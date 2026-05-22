// Tauri `#[tauri::command]` handlers — the IPC surface the Svelte
// frontend sees.
//
// Each command should:
//   - Take typed arguments (deserialised from JS).
//   - Return `Result<Dto, String>` where `Dto` is a flat,
//     `Serialize`-derived struct shaped for the UI's needs (not the
//     internal `Config` / `RuntimeState` types).
//   - Stay small — push business logic into the core lib or into
//     helper modules. Commands are glue.
//
// Phase B surface (this file):
//   - `version`            — crate version string for the header tag.
//   - `get_status`         — running / uptime / last error for the
//                             Status tab's hero indicator.
//   - `get_config`         — current `config.json` shape, flattened
//                             for the form / display.
//   - `start_proxy`        — fire up the proxy with the on-disk config.
//   - `stop_proxy`         — clean shutdown via the oneshot tx held in
//                             `AppState`.
//
// Phase C will extend this with `save_config`, profile CRUD, log
// drain, stats poll, and the discover / scan-IPs / test-relay
// operations the egui UI already exposes.

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use rahgozar::cdn_discover::{self, DiscoveredFront};
use rahgozar::cert_installer::{install_ca, is_ca_trusted_by_subject, remove_ca};
use rahgozar::config::{Config, FrontingGroup, ScriptId};
use rahgozar::data_dir;
use rahgozar::domain_fronter::DEFAULT_GOOGLE_SNI_POOL;
use rahgozar::mitm::MitmCertManager;
use rahgozar::profiles;
use rahgozar::proxy_server::ProxyServer;
use rahgozar::{scan_ips, test_cmd};

use crate::cert_ops;
use crate::runtime::RuntimeHandle;
use crate::state::AppState;

// ── Shared config-edit helpers ─────────────────────────────────────────
//
// All four edit-side commands (`save_config`, `save_fronting_groups`,
// `save_sni_pool`, `save_raw_config`) funnel through these so:
//
//   1. **Atomic writes.** Plain `std::fs::write` exposes a window where
//      a crash, disk-full condition, or partial flush leaves a
//      half-written `config.json` that subsequent loads can't parse.
//      `profiles::write_config_json_to` already implements the
//      temp-file + rename pattern with proper cleanup on failure; we
//      route every save through it.
//
//   2. **Fresh-install base.** The Tunnel form's `save_config` writes
//      every required `Config` field, so its overlay is always
//      complete. The sub-editors (`save_fronting_groups`,
//      `save_sni_pool`) only mutate one key — if the config file
//      doesn't exist yet, an overlay of just `{"fronting_groups":
//      [...]}` produces an unparseable file (`Config::mode` is
//      required). `default_config_base()` returns the same
//      minimal-valid JSON shape that `FormState::fresh_install_defaults`
//      would produce, so a fresh-install sub-save lands a valid file.

/// Minimal-valid Config JSON for a fresh install. Mirrors the field
/// values `FormState::fresh_install_defaults` used in the legacy egui
/// UI — same listen host/port/socks5 pair, same Google IP, same
/// default front. Anything not present here will be filled in by the
/// caller's overlay or stay absent (Option<…> fields).
fn default_config_base() -> serde_json::Value {
    serde_json::json!({
        "mode": "apps_script",
        "google_ip": "216.239.38.120",
        "front_domain": "www.google.com",
        "auth_key": "",
        "listen_host": "127.0.0.1",
        "listen_port": 8085,
        "socks5_port": 8086,
        "log_level": "info,hyper=warn",
    })
}

/// Read `config.json` as a JSON `Value` for in-place overlay edits.
/// Returns the minimal default base when the file doesn't exist — see
/// the rationale in the module-level comment above.
fn read_or_default_config_json() -> Result<serde_json::Value, String> {
    let path = data_dir::config_path();
    if !path.exists() {
        return Ok(default_config_base());
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))
}

/// Atomic write of an edited config `Value`. Uses the same temp-file +
/// rename helper the profile / CLI save paths use, so a partial write
/// can't corrupt the live config.
fn write_config_json(json: &serde_json::Value) -> Result<(), String> {
    let path = data_dir::config_path();
    profiles::write_config_json_to(&path, json)
        .map_err(|e| format!("write {}: {}", path.display(), e))
}

/// Crate version for the header `v2.x.y` tag. Static — the binary
/// can't change versions at runtime.
#[tauri::command]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Snapshot for the Status tab.
///
/// `uptime_secs` is `None` when stopped; `running` is the source of
/// truth for the badge colour. `last_error` lingers across a failed
/// start so the user has a chance to read it; the next successful
/// start clears it.
#[derive(Serialize)]
pub struct StatusDto {
    pub running: bool,
    pub uptime_secs: Option<u64>,
    pub last_error: Option<String>,
}

#[tauri::command]
pub fn get_status(state: State<'_, Arc<AppState>>) -> StatusDto {
    let inner = state.inner.lock().unwrap();
    StatusDto {
        running: inner.running,
        uptime_secs: inner.started_at.map(|t| t.elapsed().as_secs()),
        last_error: inner.last_error.clone(),
    }
}

/// Daily-usage snapshot for the Status tab's "Usage today" card.
///
/// Only meaningful while a fronter-backed proxy is running (i.e. mode
/// is `apps_script` or `full`). `direct` and `local_bypass` modes have
/// no `DomainFronter` and so report no stats; the frontend renders
/// nothing in that case. `Option::None` is the across-the-board "we
/// have nothing to show here" signal — no proxy, no fronter, or the
/// running state got dropped between read and unwrap.
///
/// Values:
///   - `today_calls`        — Apps Script relay invocations counted
///                            against today's PT day. Resets at
///                            00:00 PT (Google's quota cadence).
///   - `today_bytes`        — Response bytes from those invocations.
///   - `today_key`          — `YYYY-MM-DD` of the PT day the above
///                            counts refer to. Useful for cross-
///                            referencing Google's Apps Script
///                            quota dashboard, which is also PT.
///   - `today_reset_secs`   — Seconds until the next 00:00 PT
///                            rollover.
///   - `free_quota_per_day` — Free-tier Apps Script daily quota
///                            (20,000 calls). Constant — surfaced
///                            here so the frontend doesn't have to
///                            re-encode it.
#[derive(Serialize)]
pub struct UsageDto {
    pub today_calls: u64,
    pub today_bytes: u64,
    pub today_key: String,
    pub today_reset_secs: u64,
    pub free_quota_per_day: u64,
}

#[tauri::command]
pub fn get_stats(state: State<'_, Arc<AppState>>) -> Option<UsageDto> {
    let inner = state.inner.lock().unwrap();
    let rs = inner.running_state.as_ref()?;
    let fronter = rs.fronter()?;
    let snap = fronter.snapshot_stats();
    Some(UsageDto {
        today_calls: snap.today_calls,
        today_bytes: snap.today_bytes,
        today_key: snap.today_key,
        today_reset_secs: snap.today_reset_secs,
        // Free-tier Apps Script UrlFetchApp daily quota. Workspace /
        // paid tiers get 100k but most rahgozar users are on free.
        // Source value mirrored from the legacy egui UI's
        // UsageTodayCard.
        free_quota_per_day: 20_000,
    })
}

/// Frontend-facing config shape. Flat (no nested `Option<ScriptId>`)
/// so the Svelte form bindings stay shallow and the JSON the frontend
/// gets matches what the form will eventually post back. Sub-fields
/// the egui UI exposed are added here as the corresponding UI lands.
#[derive(Serialize)]
pub struct ConfigDto {
    pub mode: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub socks5_port: Option<u16>,
    pub script_ids: Vec<String>,
    pub auth_key: String,
    pub front_domain: String,
    pub google_ip: String,
    pub log_level: String,
}

#[tauri::command]
pub fn get_config() -> Result<ConfigDto, String> {
    let path = data_dir::config_path();
    if !path.exists() {
        // Mirrors the egui UI's "no config.json yet → fresh defaults"
        // path. We don't write the defaults to disk here; the Save
        // command (phase C) creates the file when the user explicitly
        // saves. `Config` itself has no `Default` impl — its
        // fields aren't all reasonable to zero (e.g. listen_port = 0
        // would be a footgun) — so we hand-roll the same shape the egui
        // `FormState::fresh_install_defaults` produces.
        return Ok(ConfigDto {
            mode: "apps_script".into(),
            listen_host: "127.0.0.1".into(),
            listen_port: 8085,
            socks5_port: Some(8086),
            script_ids: Vec::new(),
            auth_key: String::new(),
            front_domain: "www.google.com".into(),
            google_ip: "216.239.38.120".into(),
            log_level: "info,hyper=warn".into(),
        });
    }

    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let cfg: Config =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))?;

    let script_ids = match cfg.script_id.as_ref().or(cfg.script_ids.as_ref()) {
        Some(ScriptId::One(s)) => vec![s.clone()],
        Some(ScriptId::Many(v)) => v.clone(),
        None => Vec::new(),
    };

    Ok(ConfigDto {
        mode: cfg.mode,
        listen_host: cfg.listen_host,
        listen_port: cfg.listen_port,
        socks5_port: cfg.socks5_port,
        script_ids,
        auth_key: cfg.auth_key,
        front_domain: cfg.front_domain,
        google_ip: cfg.google_ip,
        log_level: cfg.log_level,
    })
}

/// Spawn the proxy in the background runtime.
///
/// Loads config from disk (no client-side config-editing surface yet
/// in phase B; phase C swaps this for an in-memory mutable model),
/// initialises the MITM CA in the user-data dir, builds a `ProxyServer`,
/// and hands its `run()` future to the Tokio runtime owned by
/// `RuntimeHandle`. The shutdown half of a `oneshot` channel is parked
/// inside `AppState::inner.shutdown_tx`; `stop_proxy` sends `()` to
/// wake the proxy's select-loop and exit cleanly.
///
/// Emits a `status` event on success so the frontend's Status tab
/// flips its badge without having to poll `get_status`.
#[tauri::command]
pub async fn start_proxy(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    runtime: State<'_, RuntimeHandle>,
) -> Result<(), String> {
    // Reject double-start before touching disk. The proxy's bind step
    // would catch it anyway (EADDRINUSE on the listen port) but the
    // error message is much clearer here.
    {
        let inner = state.inner.lock().unwrap();
        if inner.running {
            return Err("Proxy is already running".into());
        }
    }

    // Read the on-disk config. Phase B has no in-memory editor yet, so
    // "start with current config" == "load config.json now".
    let path = data_dir::config_path();
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let cfg: Config =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))?;

    // MITM cert pair lives in the user-data dir alongside the config.
    // `MitmCertManager::new_in` will mint a new CA on first run; later
    // runs reload the existing pair.
    let mitm =
        MitmCertManager::new_in(&data_dir::data_dir()).map_err(|e| format!("mitm init: {}", e))?;
    // `ProxyServer::new` takes `Arc<tokio::sync::Mutex<...>>` — the proxy
    // needs to hold the lock across `.await` points during a TLS
    // handshake, so the std mutex would force `?Send` everywhere. Using
    // tokio's mutex here keeps the future Send.
    let mitm = Arc::new(AsyncMutex::new(mitm));

    let proxy = ProxyServer::new(&cfg, mitm).map_err(|e| format!("build proxy: {}", e))?;
    // Grab the runtime-state handle BEFORE moving `proxy` into the
    // spawned future. `get_stats` reads through this to call
    // `DomainFronter::snapshot_stats()` for the Usage Today card.
    let runtime_state = proxy.state();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Spawn onto our dedicated tokio runtime. The future owns the
    // ProxyServer; when it exits (cleanly or with a panic) we emit a
    // `status` event so the UI can flip back to "stopped" even on a
    // proxy-side crash.
    let app_for_task = app.clone();
    let state_for_task: Arc<AppState> = state.inner().clone();
    runtime.rt.spawn(async move {
        let outcome = proxy.run(shutdown_rx).await;
        if let Err(e) = &outcome {
            tracing::error!(error = %e, "proxy run terminated with error");
        }
        // Drop the runtime-state handle on a self-exit. Without this
        // the AppState would hold a dangling Arc<RuntimeState> for a
        // proxy that crashed on its own (no `stop_proxy` call), and
        // `get_stats` would call into a halted fronter and report
        // stale numbers indefinitely.
        if let Ok(mut inner) = state_for_task.inner.lock() {
            inner.running = false;
            inner.started_at = None;
            inner.shutdown_tx = None;
            inner.running_state = None;
        }
        // Best-effort emit; if the app is mid-shutdown the channel may
        // already be closed.
        let _ = app_for_task.emit(
            "rahgozar:status",
            StatusEvent {
                running: false,
                last_error: outcome.err().map(|e| e.to_string()),
            },
        );
    });

    {
        let mut inner = state.inner.lock().unwrap();
        inner.running = true;
        inner.shutdown_tx = Some(shutdown_tx);
        inner.started_at = Some(Instant::now());
        inner.last_error = None;
        inner.running_state = Some(runtime_state);
    }

    let _ = app.emit(
        "rahgozar:status",
        StatusEvent {
            running: true,
            last_error: None,
        },
    );

    Ok(())
}

/// Send the shutdown signal. Idempotent — calling on a stopped proxy
/// returns Ok with no side effects so the frontend doesn't have to
/// pre-check.
#[tauri::command]
pub fn stop_proxy(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let mut inner = state.inner.lock().unwrap();
    if !inner.running {
        return Ok(());
    }
    // `Option::take` so a re-entrant `stop_proxy` (e.g. UI double-click)
    // can't double-send on a oneshot.
    if let Some(tx) = inner.shutdown_tx.take() {
        let _ = tx.send(());
    }
    inner.running = false;
    inner.started_at = None;
    inner.running_state = None;
    drop(inner);

    let _ = app.emit(
        "rahgozar:status",
        StatusEvent {
            running: false,
            last_error: None,
        },
    );

    Ok(())
}

/// Event payload mirrored by the frontend's `listen("rahgozar:status", …)`.
/// Same shape on the running-→up and crashing-→down transitions so the
/// frontend has a single handler.
#[derive(Serialize, Clone)]
struct StatusEvent {
    running: bool,
    last_error: Option<String>,
}

// ── Config edit + save ─────────────────────────────────────────────────

/// What the Tunnel form posts back. Mirrors `ConfigDto` field-for-field
/// — same wire shape both ways means a single TypeScript interface
/// covers reads + writes. The Rust side reconciles into a `Config`
/// before serialising to disk, so any field we don't list here keeps
/// whatever value was on disk previously (round-trip safe).
#[derive(Deserialize)]
pub struct ConfigUpdate {
    pub mode: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub socks5_port: Option<u16>,
    pub script_ids: Vec<String>,
    pub auth_key: String,
    pub front_domain: String,
    pub google_ip: String,
    pub log_level: String,
}

/// Persist the form to `config.json`.
///
/// Overlay strategy: we read the existing JSON document as a
/// `serde_json::Value`, mutate only the fields this form controls,
/// then write back. This preserves every key the new desktop UI
/// doesn't expose yet (fronting_groups, sni_hosts, custom params, log
/// colours, all the tuning knobs) — they round-trip untouched.
///
/// We can't go through `Config` itself because the rahgozar core type
/// only derives `Deserialize`, not `Serialize` (the legacy egui binary
/// hand-rolls a `ConfigWire<'a>` to emit the wire form). Working at
/// the JSON layer keeps the change scoped to this crate and means we
/// don't have to touch the core lib's serialization story.
///
/// Validation mirrors the egui `to_config` path: only relay-using
/// modes need at least one script ID + an auth key, ports must differ.
/// Returns the saved `ConfigDto` so the caller can update local state
/// without a separate `get_config` round-trip.
///
/// "Needs creds" is gated by `Mode::uses_apps_script_relay` from the
/// rahgozar core — the single source of truth so a future cred-free
/// mode picks the right side without another allowlist edit here.
#[tauri::command]
pub fn save_config(update: ConfigUpdate) -> Result<ConfigDto, String> {
    use rahgozar::config::Mode;
    // Parse via FromStr so unknown / typo'd modes from the UI are
    // surfaced here rather than blowing up later when the proxy
    // tries to start. The error message comes from
    // `impl FromStr for Mode` and already lists the accepted shapes.
    let mode: Mode = update.mode.parse().map_err(|e| format!("{e}"))?;
    let needs_relay_creds = mode.uses_apps_script_relay();

    // Trim + drop blank rows the same way the egui form did, so a
    // trailing-empty entry from the row editor doesn't get persisted.
    let cleaned_ids: Vec<String> = update
        .script_ids
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if needs_relay_creds {
        if cleaned_ids.is_empty() {
            return Err("At least one deployment ID is required".into());
        }
        if update.auth_key.trim().is_empty() {
            return Err("Auth key is required".into());
        }
    }
    if let Some(s) = update.socks5_port {
        if s == update.listen_port {
            return Err("HTTP and SOCKS5 ports must differ".into());
        }
    }

    // Read existing config.json (or fall back to the fresh-install
    // base — the form overlay below sets every required field anyway,
    // so even an empty base produces a complete file here).
    let mut json = read_or_default_config_json()?;
    let obj = json
        .as_object_mut()
        .ok_or_else(|| "config.json is not a JSON object".to_string())?;

    obj.insert(
        "mode".into(),
        serde_json::Value::String(update.mode.clone()),
    );
    obj.insert(
        "listen_host".into(),
        serde_json::Value::String(update.listen_host.clone()),
    );
    obj.insert("listen_port".into(), update.listen_port.into());
    match update.socks5_port {
        Some(s) => {
            obj.insert("socks5_port".into(), s.into());
        }
        None => {
            obj.remove("socks5_port");
        }
    }
    obj.insert(
        "auth_key".into(),
        serde_json::Value::String(update.auth_key.clone()),
    );
    obj.insert(
        "front_domain".into(),
        serde_json::Value::String(update.front_domain.clone()),
    );
    obj.insert(
        "google_ip".into(),
        serde_json::Value::String(update.google_ip.clone()),
    );
    obj.insert(
        "log_level".into(),
        serde_json::Value::String(update.log_level.clone()),
    );

    // Collapse the IDs into the wire shape — single id → bare string
    // (`script_id: "AKfy…"`), multiple → array, none → key absent.
    // Always drop the legacy `script_ids` alias so we don't ship a
    // file with both keys populated.
    obj.remove("script_ids");
    match cleaned_ids.as_slice() {
        [] => {
            obj.remove("script_id");
        }
        [one] => {
            obj.insert("script_id".into(), serde_json::Value::String(one.clone()));
        }
        many => {
            obj.insert(
                "script_id".into(),
                serde_json::Value::Array(
                    many.iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }

    // Atomic write via the temp-file + rename helper. See the
    // `Shared config-edit helpers` block at the top of this file
    // for the rationale.
    write_config_json(&json)?;

    Ok(ConfigDto {
        mode: update.mode,
        listen_host: update.listen_host,
        listen_port: update.listen_port,
        socks5_port: update.socks5_port,
        script_ids: cleaned_ids,
        auth_key: update.auth_key,
        front_domain: update.front_domain,
        google_ip: update.google_ip,
        log_level: update.log_level,
    })
}

// ── Diagnostics ────────────────────────────────────────────────────────

/// Outcome of `test_relay`. `pass` is what drives the toast colour
/// (green vs. red) on the Status tab; the actual probe details land
/// in the log stream so the user can inspect what went wrong.
#[derive(Serialize)]
pub struct TestResult {
    pub pass: bool,
}

/// Probe the Apps Script relay end-to-end. Spawns a one-shot test
/// (no persistent proxy) on the same runtime as `start_proxy` so
/// tracing routes through the same log bridge — the user sees each
/// step in the Logs tab as it happens, regardless of whether the
/// proxy itself is running.
///
/// The actual probe is `rahgozar::test_cmd::run` (shared with the CLI
/// `rahgozar test` subcommand), so any change to the probe heuristics
/// applies to both surfaces.
#[tauri::command]
pub async fn test_relay(runtime: State<'_, RuntimeHandle>) -> Result<TestResult, String> {
    let cfg = load_config_for_diag()?;
    let handle = runtime.rt.spawn(async move { test_cmd::run(&cfg).await });
    let pass = handle
        .await
        .map_err(|e| format!("test task panicked: {}", e))?;
    Ok(TestResult { pass })
}

/// Scan known Google frontend IPs for reachability and report each
/// candidate's latency / error via the same tracing channel that
/// feeds the Logs tab. Same shape as `test_relay`: spawn on the
/// proxy runtime, await the verdict, return a pass/fail to the
/// frontend which converts it to a toast.
///
/// The actual scan is `rahgozar::scan_ips::run` (shared with the CLI
/// `rahgozar scan-ips` subcommand), so any change to the probe
/// heuristics applies to both surfaces.
#[tauri::command]
pub async fn scan_ips(runtime: State<'_, RuntimeHandle>) -> Result<TestResult, String> {
    let cfg = load_config_for_diag()?;
    let handle = runtime.rt.spawn(async move { scan_ips::run(&cfg).await });
    let pass = handle
        .await
        .map_err(|e| format!("scan task panicked: {}", e))?;
    Ok(TestResult { pass })
}

/// Helper shared by the diagnostic commands above. Reloading config
/// from disk every invocation matters because the Tunnel tab's save
/// doesn't restart the running proxy, so "did my last edit fix it?"
/// is the most common question these diagnostics answer.
fn load_config_for_diag() -> Result<Config, String> {
    let path = data_dir::config_path();
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))
}

// ── Fronting groups ────────────────────────────────────────────────────
//
// Each `FrontingGroup` is the rahgozar concept that lets traffic for a
// configured set of `domains` be routed through `ip` while presenting
// `sni` on the outbound TLS handshake — the way you point a fronted
// connection at e.g. Fastly for python.org or Vercel for react.dev.
// The Tunnel tab's Fronting Groups section is a per-group form;
// these commands move groups in and out of `config.json::fronting_groups`
// without going through the full Tunnel form save path (which would
// require rebuilding the whole ConfigUpdate just to mutate one
// sub-array).

/// Read the current `fronting_groups` array from `config.json`.
/// Returns an empty list when no config exists yet (fresh install)
/// or when the key is simply absent — both are non-error cases for
/// the editor's "Add your first group" flow.
///
/// A malformed `fronting_groups` value (wrong type, missing required
/// sub-fields) is propagated as an error instead of silently
/// degenerating to an empty list: a quiet-empty would let the user
/// click Save and overwrite their hand-edited config with the
/// new-but-empty list, losing data.
#[tauri::command]
pub fn get_fronting_groups() -> Result<Vec<FrontingGroup>, String> {
    let path = data_dir::config_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    let Some(value) = json.get("fronting_groups") else {
        return Ok(Vec::new());
    };
    serde_json::from_value::<Vec<FrontingGroup>>(value.clone())
        .map_err(|e| format!("malformed fronting_groups: {}", e))
}

/// Replace `config.json::fronting_groups` with the supplied list.
/// Validates each entry (name, ip, sni, ≥1 domain non-blank) before
/// touching disk. Same JSON-value overlay strategy as `save_config`
/// — preserves every other key.
#[tauri::command]
pub fn save_fronting_groups(groups: Vec<FrontingGroup>) -> Result<Vec<FrontingGroup>, String> {
    // Trim + drop blank rows the same way the form would expect, so a
    // half-filled "add a new group" row left behind doesn't corrupt
    // the on-disk file.
    let cleaned: Vec<FrontingGroup> = groups
        .into_iter()
        .map(|mut g| {
            g.name = g.name.trim().to_string();
            g.ip = g.ip.trim().to_string();
            g.sni = g.sni.trim().to_string();
            g.domains = g
                .domains
                .into_iter()
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
                .collect();
            g
        })
        .filter(|g| {
            !g.name.is_empty() || !g.ip.is_empty() || !g.sni.is_empty() || !g.domains.is_empty()
        })
        .collect();

    for (i, g) in cleaned.iter().enumerate() {
        if g.name.is_empty() {
            return Err(format!("Group #{}: name is required", i + 1));
        }
        if g.ip.is_empty() {
            return Err(format!("Group '{}': IP is required", g.name));
        }
        if g.sni.is_empty() {
            return Err(format!("Group '{}': SNI is required", g.name));
        }
        if g.domains.is_empty() {
            return Err(format!(
                "Group '{}': at least one domain is required",
                g.name
            ));
        }
    }

    // Fresh-install path: `read_or_default_config_json` returns a
    // minimal-but-valid Config base (mode, listen ports, google_ip,
    // …) so an "edit fronting groups before the Tunnel form is ever
    // saved" sequence still produces a parseable config.json.
    let mut json = read_or_default_config_json()?;
    let obj = json
        .as_object_mut()
        .ok_or_else(|| "config.json is not a JSON object".to_string())?;
    obj.insert(
        "fronting_groups".into(),
        serde_json::to_value(&cleaned).map_err(|e| format!("serialize: {}", e))?,
    );
    write_config_json(&json)?;
    Ok(cleaned)
}

/// One-shot CDN edge discovery for the "Discover" button.
///
/// Resolves `hostname` to all A/AAAA records, TLS-probes each one
/// with `SNI=hostname`, returns the best (lowest-latency, cert-valid)
/// IP. Frontend uses this to populate a new `FrontingGroup`'s `ip`
/// field without the user having to look up + paste IPs manually.
///
/// `rahgozar::cdn_discover::discover_front` blocks for up to ~15s
/// worst-case (DNS + 3 waves of TLS probes); we await it on the
/// proxy runtime so the rest of the app stays responsive.
#[derive(Serialize)]
pub struct DiscoverResultDto {
    /// Echo of the input hostname so the frontend can use this as the
    /// new group's SNI without a second variable.
    pub hostname: String,
    /// Best (lowest-latency, cert-valid) reachable IP. `None` means
    /// no IP probed successfully — the frontend surfaces that as an
    /// error toast.
    pub best_ip: Option<String>,
    /// Every reachable IP, lowest-latency first. The current
    /// FrontingGroup model uses a single IP, so we surface this for
    /// future "rotate IPs per group" use AND so the frontend can
    /// optionally show "found N reachable IPs, picked X".
    pub reachable_count: usize,
}

#[tauri::command]
pub async fn discover_front_cmd(
    hostname: String,
    runtime: State<'_, RuntimeHandle>,
) -> Result<DiscoverResultDto, String> {
    let handle = runtime
        .rt
        .spawn(async move { cdn_discover::discover_front(&hostname).await });
    let res: DiscoveredFront = handle
        .await
        .map_err(|e| format!("discover task panicked: {}", e))?
        .map_err(|e| format!("discover failed: {}", e))?;
    let best_ip = res.best_ip().map(|s| s.to_string());
    let reachable_count = res.ok_ips().len();
    Ok(DiscoverResultDto {
        hostname: res.hostname,
        best_ip,
        reachable_count,
    })
}

// ── SNI pool ───────────────────────────────────────────────────────────
//
// The SNI pool is the list of host names the proxy rotates through on
// outbound TLS handshakes to the Google edge. Most users don't touch
// it — the default pool (`DEFAULT_GOOGLE_SNI_POOL`) covers
// `{www, mail, drive, docs, calendar}.google.com`. Power users in
// jurisdictions where one of those hosts is specifically blocked
// (e.g. `mail.google.com` is sometimes singled out) want to disable
// it from the rotation, and the per-host TLS-probe button below
// validates that the remaining hosts are still reachable.

/// One pool entry — what the modal renders per row.
#[derive(Serialize, Deserialize, Clone)]
pub struct SniHostDto {
    pub host: String,
    /// `true` if this host should be in the active rotation. Hosts
    /// the user wants to omit are not deleted (so they can be
    /// flipped back on) but rendered with their checkbox unchecked
    /// and excluded from the on-disk `sni_hosts` array on save.
    pub enabled: bool,
}

/// Surface the SNI pool as the modal sees it: union of the user's
/// configured pool with the default pool, with `enabled` reflecting
/// whether the entry is in the current active list.
#[tauri::command]
pub fn get_sni_pool() -> Result<Vec<SniHostDto>, String> {
    let path = data_dir::config_path();
    // A malformed `sni_hosts` value (wrong type, etc.) is surfaced
    // as an error rather than silently treated as "no configured
    // pool" — the latter would let the modal show an all-defaults
    // list and Save would overwrite the hand-edited entry.
    let configured: Vec<String> = if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse {}: {}", path.display(), e))?;
        match json.get("sni_hosts") {
            None => Vec::new(),
            Some(v) => serde_json::from_value::<Vec<String>>(v.clone())
                .map_err(|e| format!("malformed sni_hosts: {}", e))?,
        }
    } else {
        Vec::new()
    };
    // Construct the display list: enabled entries match what's on
    // disk; the default pool fills in the rest as disabled (off
    // until the user toggles). Preserve on-disk order for the
    // enabled set so a hand-edited order survives the round trip.
    let mut out: Vec<SniHostDto> = configured
        .iter()
        .map(|h| SniHostDto {
            host: h.clone(),
            enabled: true,
        })
        .collect();
    if configured.is_empty() {
        // No explicit pool → render the defaults all-enabled, since
        // that's effectively what the proxy uses.
        for &h in DEFAULT_GOOGLE_SNI_POOL {
            out.push(SniHostDto {
                host: h.to_string(),
                enabled: true,
            });
        }
    } else {
        // Show every default host the user opted out of as a
        // disabled row, so it stays one click away from re-enabling.
        for &h in DEFAULT_GOOGLE_SNI_POOL {
            if !configured.iter().any(|c| c.eq_ignore_ascii_case(h)) {
                out.push(SniHostDto {
                    host: h.to_string(),
                    enabled: false,
                });
            }
        }
    }
    Ok(out)
}

/// Persist the enabled subset of `entries` to `config.json::sni_hosts`.
/// Disabled entries don't make it to disk — re-fetching `get_sni_pool`
/// will re-surface them as disabled defaults if they happen to be in
/// `DEFAULT_GOOGLE_SNI_POOL`, otherwise they're forgotten.
#[tauri::command]
pub fn save_sni_pool(entries: Vec<SniHostDto>) -> Result<(), String> {
    let enabled: Vec<String> = entries
        .into_iter()
        .filter(|e| e.enabled)
        .map(|e| e.host.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();
    if enabled.is_empty() {
        return Err("At least one SNI host must remain enabled".into());
    }

    let mut json = read_or_default_config_json()?;
    let obj = json
        .as_object_mut()
        .ok_or_else(|| "config.json is not a JSON object".to_string())?;
    obj.insert(
        "sni_hosts".into(),
        serde_json::Value::Array(enabled.into_iter().map(serde_json::Value::String).collect()),
    );
    write_config_json(&json)?;
    Ok(())
}

/// Per-host reachability probe — the modal's "Probe" button per row.
/// Uses the same `heartbeat_probe` the running proxy uses for its
/// health checks, so a green dot here means "the proxy's heartbeat
/// would consider this SNI healthy right now".
#[derive(Serialize)]
pub struct SniProbeResult {
    pub host: String,
    pub reachable: bool,
}

#[tauri::command]
pub async fn probe_sni(
    host: String,
    runtime: State<'_, RuntimeHandle>,
) -> Result<SniProbeResult, String> {
    // We need two values out of the on-disk config: `google_ip` (the
    // IP we probe against) and `google_ip_validation` (whether the
    // cert presented at that IP has to verify as Google's). Both can
    // be defaulted if the file isn't there — we're not editing the
    // config from this command, just reading enough state to run a
    // single TLS probe.
    let path = data_dir::config_path();
    let (google_ip, google_ip_validation) = if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse {}: {}", path.display(), e))?;
        let ip = json
            .get("google_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("216.239.38.120")
            .to_string();
        let validate = json
            .get("google_ip_validation")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        (ip, validate)
    } else {
        ("216.239.38.120".to_string(), true)
    };

    // Clone the host name for the closure — we still need the
    // original to populate the returned `SniProbeResult`, and a
    // tokio::spawn future has to own its captures (`async move`).
    let probe_host = host.clone();
    let handle = runtime.rt.spawn(async move {
        // `verify_ssl=true` — strict CA-validated handshake matches
        // what the heartbeat does when `google_ip_validation` is on.
        scan_ips::heartbeat_probe(&google_ip, &probe_host, google_ip_validation, true).await
    });
    let reachable = handle
        .await
        .map_err(|e| format!("probe task panicked: {}", e))?;
    Ok(SniProbeResult { host, reachable })
}

// ── MITM CA ────────────────────────────────────────────────────────────

/// Snapshot of the MITM CA state for the Status tab card.
///
/// `exists` differs from `trusted`: the cert can live on disk (we
/// minted it on the proxy's first run) without the OS trust store
/// having admitted it yet — that's the state right before the user
/// clicks "Install CA". After install, both flip to true. After the
/// user clicks "Remove CA", the file is deleted AND the OS forgets
/// — both flip back to false.
///
/// `fingerprint` / `subject_cn` are only present when `exists`: a
/// missing on-disk PEM means there's nothing to display in the
/// confirm dialog yet (the proxy will mint one on next Start).
#[derive(Serialize)]
pub struct CaStatusDto {
    pub exists: bool,
    pub trusted: bool,
    pub path: String,
    pub fingerprint: Option<String>,
    pub subject_cn: Option<String>,
}

/// Mint the CA on demand if it doesn't exist yet, then return the
/// status snapshot. Used by both the status read AND by the install
/// flow — there's no way to install a cert that doesn't exist, so
/// "Install" clicks need to materialise the on-disk file first.
fn ensure_ca_minted() -> Result<(), String> {
    let dir = data_dir::data_dir();
    // `MitmCertManager::new_in` is the same path the running proxy
    // uses on first start — generates the key + cert pair on disk if
    // they're missing, no-op if they're already there.
    MitmCertManager::new_in(&dir).map_err(|e| format!("mitm init: {}", e))?;
    Ok(())
}

#[tauri::command]
pub fn get_ca_status() -> CaStatusDto {
    let path = cert_ops::ca_cert_path();
    let path_str = path.display().to_string();
    // Pure read — never mints from a status query. Minting is the
    // proxy start path's job (see `ensure_ca_minted` callers and
    // `MitmCertManager::new_in` in `src/main.rs`). The frontend's
    // CaCard is hidden in no-MITM modes (local_bypass / full), so
    // status reads only fire when a user is actively configuring a
    // MITM-using mode; minting on first Start there is correct
    // timing. The card shows "Will be created on first Start" until
    // then, which is accurate.
    if !path.exists() {
        return CaStatusDto {
            exists: false,
            trusted: false,
            path: path_str,
            fingerprint: None,
            subject_cn: None,
        };
    }
    let der = cert_ops::read_ca_der(&path);
    let fingerprint = der.as_deref().map(cert_ops::fingerprint_hex);
    let subject_cn = der.as_deref().and_then(cert_ops::subject_cn);
    // Trust check is scoped to THIS cert's actual Subject CN — not
    // the union of "current + legacy" names. Without that scoping,
    // a user who minted a fresh `rahgozar` cert but still has a
    // legacy `MasterHttpRelayVPN` cert hanging around in their OS
    // store would see a misleading "Trusted" badge: the badge would
    // be reflecting the LEGACY cert's trust, not the on-disk
    // `rahgozar` cert that the proxy actually mints leaves with.
    //
    // The legacy sweep still happens — `remove_ca` walks every name
    // in `known_cert_names()` so a Remove cleans up legacy entries
    // alongside the current one. This is a UI-side narrowing only.
    let trusted = subject_cn
        .as_deref()
        .map(is_ca_trusted_by_subject)
        .unwrap_or(false);
    CaStatusDto {
        exists: true,
        trusted,
        path: path_str,
        fingerprint,
        subject_cn,
    }
}

/// Install the MITM CA into the OS trust store.
///
/// The user has to have already confirmed the fingerprint in the
/// frontend dialog before calling this — there's no in-Rust prompt.
/// On most platforms this triggers an admin / sudo prompt managed by
/// the OS (Windows UAC, macOS authopen, Linux pkexec / sudo). Errors
/// (user cancels the prompt, certutil missing, etc.) come back as
/// strings the frontend can render in a toast.
#[tauri::command]
pub fn install_ca_cmd() -> Result<CaStatusDto, String> {
    ensure_ca_minted()?;
    let path = cert_ops::ca_cert_path();
    install_ca(&path).map_err(|e| format!("install failed: {}", e))?;
    Ok(get_ca_status())
}

/// Mint the CA on disk if it doesn't already exist, then return the
/// fresh status snapshot. Called from the frontend's `CaCard.onMount`
/// when the user is actively configuring a MITM-using mode, so the
/// install confirmation dialog has a fingerprint to display before
/// the user has clicked Start.
///
/// Gated by the frontend: the CaCard is hidden in no-MITM modes
/// (local_bypass / full), so this command never runs for users who
/// don't need a CA. That restores the "install before first Start"
/// UX (a relay-mode user could previously inspect + install the
/// fingerprint immediately on launch) without re-introducing the
/// surprise CA generation in no-MITM modes that the previous
/// always-eager `get_ca_status` shape produced.
#[tauri::command]
pub fn mint_ca_if_missing() -> Result<CaStatusDto, String> {
    ensure_ca_minted()?;
    Ok(get_ca_status())
}

/// Remove the MITM CA from the OS trust store + delete the on-disk
/// `ca/ca.crt` + `ca/ca.key` files. The next proxy Start regenerates
/// a fresh keypair, so the user doesn't have to redeploy Code.gs
/// or re-enter their deployment ID — the relay endpoint is
/// unaffected.
///
/// Returns the human-readable summary string from `RemovalOutcome`
/// so the frontend's toast can say e.g. "OS CA removed. NSS cleanup
/// partial: 2/3 browser stores updated." — useful diagnostic when
/// Firefox / Chromium picked up a stale copy.
#[tauri::command]
pub fn remove_ca_cmd() -> Result<String, String> {
    let dir = data_dir::data_dir();
    let outcome = remove_ca(&dir).map_err(|e| format!("remove failed: {}", e))?;
    Ok(outcome.summary())
}

// ── Log commands ───────────────────────────────────────────────────────

/// Initial scroll-back for the Logs tab. Returns the current ring
/// buffer contents (oldest first). Live tail comes from the
/// `rahgozar:log` event stream — frontend subscribes to that after
/// drain.
#[tauri::command]
pub fn drain_logs(state: State<'_, Arc<AppState>>) -> Vec<String> {
    state.log.lock().unwrap().iter().cloned().collect()
}

/// Wipe the ring buffer. UI-only — the proxy's own tracing keeps
/// going, so the next event re-populates from a clean slate.
#[tauri::command]
pub fn clear_logs(state: State<'_, Arc<AppState>>) {
    state.log.lock().unwrap().clear();
}

// ── Raw config (Advanced tab escape hatch) ─────────────────────────────
//
// The Tunnel form covers the dozen-ish fields that 95% of users
// touch. For the long tail (fronting_groups, sni_hosts, custom params,
// log colours, ~30 tuning knobs that the egui UI exposed across
// nested editors), the Advanced tab gives a raw JSON editor backed by
// these two commands. Trades hand-holding for total coverage: anyone
// who can edit JSON can configure everything without us having to
// build a dedicated UI per knob.

/// Read `config.json` as a pretty-printed string for the Advanced
/// tab's editor. Returns an empty-object JSON document when no file
/// exists yet, so the editor always has something to bind to.
#[tauri::command]
pub fn get_raw_config() -> Result<String, String> {
    let path = data_dir::config_path();
    if !path.exists() {
        return Ok("{}\n".to_string());
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    // Round-trip through `Value` so the editor always sees consistent
    // formatting (2-space indent, trailing newline) regardless of how
    // the user hand-edited the file last time. Their save will
    // re-format with the same rules — predictable diffs in git for
    // anyone tracking config.json.
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    serde_json::to_string_pretty(&value)
        .map(|mut s| {
            // `to_string_pretty` omits the trailing newline; readers
            // (vim, etc.) prefer it.
            s.push('\n');
            s
        })
        .map_err(|e| format!("serialize: {}", e))
}

/// Write the Advanced tab's editor content back to `config.json`.
/// Validates first by parsing into the typed `Config` — guarantees the
/// running proxy can load whatever we just wrote — then persists the
/// raw text the user typed (preserving their formatting / key order).
#[tauri::command]
pub fn save_raw_config(text: String) -> Result<(), String> {
    // Two-stage validation:
    //   1. Typed parse — catches misspelled fields, wrong-typed
    //      values (string where number expected, etc.).
    //   2. `Config::validate` — catches semantic problems that pass
    //      typed deserialisation but would fail at proxy startup:
    //      missing script IDs for apps_script mode, the
    //      placeholder "YOUR_APPS_SCRIPT_DEPLOYMENT_ID" sentinel,
    //      `socks5_port == listen_port`, invalid fronting-group
    //      shapes, etc. Mirrors what `proxy_server::run` does on
    //      load — fail-fast at save time so the user sees the
    //      diagnostic now, not after a Start they then have to
    //      undo.
    let parsed: Config =
        serde_json::from_str(&text).map_err(|e| format!("invalid config: {}", e))?;
    parsed
        .validate()
        .map_err(|e| format!("invalid config: {}", e))?;

    // Round-trip through the JSON value (preserving the user's
    // formatting / key order) into the atomic write helper. We could
    // bypass the helper here since the input is already a string, but
    // routing through the same path the other saves use keeps the
    // crash-safety guarantees uniform.
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("re-parse for write: {}", e))?;
    write_config_json(&value)
}
