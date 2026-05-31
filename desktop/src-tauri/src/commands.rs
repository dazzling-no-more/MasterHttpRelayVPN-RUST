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
use rahgozar::config::{Config, FrontingGroup, Mode};
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

/// True if the currently-running .exe looks like the Windows portable
/// build, false otherwise. The JS-side updater (see
/// `desktop/src/lib/updater.svelte.ts`) uses this to bypass the
/// auto-install path on portable: `latest.json` maps Windows to MSI, so
/// `tauri-plugin-updater`'s `downloadAndInstall()` on a portable user
/// would download the MSI and run the installer alongside the existing
/// portable .exe — confusing UX. The portable flow instead opens the
/// release page in the user's browser so they can grab a fresh
/// `rahgozar-portable-*.exe` manually.
///
/// Detection is intentionally narrow — we match on the .exe basename
/// rather than path heuristics:
///   - MSI default install path: `%ProgramFiles%\rahgozar\rahgozar.exe`
///   - NSIS per-user (Tauri default): `%LOCALAPPDATA%\rahgozar\rahgozar.exe`
///   - MSI per-user: `%LOCALAPPDATA%\Programs\rahgozar\rahgozar.exe`
///   - Portable: anywhere the user dropped it (Downloads, Desktop, USB)
///
/// Path-based detection has too many false positives across those four
/// install layouts. The portable archive is staged as
/// `rahgozar-portable-windows-amd64.exe` (see release.yml's "Stage
/// Windows portable exe" step), so its `file_stem()` reliably contains
/// the substring `portable`. A user who manually renames the exe to
/// `rahgozar.exe` is explicitly opting out of portable mode and will
/// fall through to the auto-update path — at which point they get the
/// MSI installer; their choice.
///
/// On non-Windows platforms there is no portable concept — `.AppImage`
/// IS portable but Tauri's updater handles AppImage replacement in
/// place; `.dmg` always installs to /Applications via drag-drop. So
/// this returns `false` everywhere except Windows.
#[tauri::command]
pub fn is_portable_install() -> bool {
    #[cfg(target_os = "windows")]
    {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(stem) = exe.file_stem().and_then(|s| s.to_str()) {
                return stem.to_lowercase().contains("portable");
            }
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
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
/// One row in the Tunnel form's deployment-IDs editor. The `enabled`
/// flag lets the user park an ID without deleting it; disabled entries
/// persist on disk but are filtered out of the runtime relay pool.
/// Mirrors `rahgozar::config::ScriptIdEntry` on the wire.
#[derive(Serialize, Deserialize, Clone)]
pub struct ScriptIdDto {
    pub id: String,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct ConfigDto {
    pub mode: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub socks5_port: Option<u16>,
    pub script_ids: Vec<ScriptIdDto>,
    pub auth_key: String,
    pub front_domain: String,
    pub google_ip: String,
    pub log_level: String,
    // ── Drive-mode (mode = "drive") ────────────────────────────────────
    //
    // Form-visible fields for the Drive transport. `oauth_refresh_token`
    // is deliberately NOT exposed in the form — it's managed by the
    // `drive_oauth_start` / `drive_oauth_complete` flow and surfaced
    // read-only via `drive_has_refresh_token` so the UI can show
    // "Signed in" without re-printing the secret. `drive_poll_interval_ms`
    // and `drive_max_concurrent_uploads` are tuning knobs in an
    // Advanced section.
    pub drive_folder_id: String,
    pub drive_relay_pubkey: String,
    pub drive_poll_interval_ms: u32,
    pub drive_max_concurrent_uploads: u8,
    /// BYO OAuth client_id, registered by the user in Google Cloud
    /// Console. See `docs/drive_oauth_setup.md`. rahgozar ships no
    /// default; every user supplies their own to sidestep the
    /// 100-user cap on unverified OAuth clients.
    pub drive_oauth_client_id: String,
    /// BYO OAuth client_secret paired with [`Self::drive_oauth_client_id`].
    pub drive_oauth_client_secret: String,
    /// True iff the on-disk `config.drive.oauth_refresh_token` is
    /// non-empty. UI uses this to decide whether to render
    /// "Sign in with Google" or "Signed in. Sign out / Re-link".
    pub drive_has_refresh_token: bool,
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
            drive_folder_id: String::new(),
            drive_relay_pubkey: String::new(),
            drive_poll_interval_ms: 300,
            drive_max_concurrent_uploads: 8,
            drive_oauth_client_id: String::new(),
            drive_oauth_client_secret: String::new(),
            drive_has_refresh_token: false,
        });
    }

    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let cfg: Config =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))?;

    // Use the canonical entry view so disabled rows round-trip into
    // the UI (legacy bare-string configs come back as enabled=true).
    let script_ids: Vec<ScriptIdDto> = cfg
        .script_id_entries()
        .into_iter()
        .map(|e| ScriptIdDto {
            id: e.id,
            enabled: e.enabled,
        })
        .collect();

    let drive_has_refresh_token = !cfg.drive.oauth_refresh_token.trim().is_empty();
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
        drive_folder_id: cfg.drive.folder_id,
        drive_relay_pubkey: cfg.drive.relay_pubkey,
        drive_poll_interval_ms: cfg.drive.poll_interval_ms,
        drive_max_concurrent_uploads: cfg.drive.max_concurrent_uploads,
        drive_oauth_client_id: cfg.drive.oauth_client_id,
        drive_oauth_client_secret: cfg.drive.oauth_client_secret,
        drive_has_refresh_token,
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

    // Read and semantically validate the on-disk config before any
    // runtime state is built. Drive setup saves can intentionally be
    // incomplete while the user is still signing in / creating a folder;
    // Start is the hard gate that must require a fully-runnable config.
    let path = data_dir::config_path();
    let cfg = Config::load(&path).map_err(|e| format!("load {}: {}", path.display(), e))?;

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
    pub script_ids: Vec<ScriptIdDto>,
    pub auth_key: String,
    pub front_domain: String,
    pub google_ip: String,
    pub log_level: String,
    // Drive-mode form fields. `oauth_refresh_token` is intentionally
    // absent — it's managed by the OAuth flow commands and the form
    // doesn't surface the secret. `save_config` preserves whatever
    // `drive.oauth_refresh_token` is already on disk.
    #[serde(default)]
    pub drive_folder_id: String,
    #[serde(default)]
    pub drive_relay_pubkey: String,
    #[serde(default = "default_drive_poll_interval_ms_form")]
    pub drive_poll_interval_ms: u32,
    #[serde(default = "default_drive_max_concurrent_uploads_form")]
    pub drive_max_concurrent_uploads: u8,
    /// BYO OAuth client_id — surfaced as a regular form field so
    /// users paste their own credentials in the Drive setup section.
    #[serde(default)]
    pub drive_oauth_client_id: String,
    /// BYO OAuth client_secret — paired with
    /// [`Self::drive_oauth_client_id`].
    #[serde(default)]
    pub drive_oauth_client_secret: String,
}

fn default_drive_poll_interval_ms_form() -> u32 {
    300
}

fn default_drive_max_concurrent_uploads_form() -> u8 {
    8
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
/// Render the cleaned deployment-ID list to the canonical `script_id`
/// wire value. Pure — call sites already trim + drop blank rows before
/// invoking. Returns `None` when the list is empty so the caller can
/// drop the key from the JSON document.
///
/// Shape rules (downgrade-compat with pre-disable-flag binaries):
///   - empty                              → `None` (caller removes key)
///   - 1 row, enabled                     → bare string `"A"`
///   - N rows, all enabled                → `["A","B",…]`
///   - any row disabled                   → `[{"id":"A","enabled":true}, …]`
///
/// The Rust reader (`Config::script_id_entries`) accepts every form,
/// so a freshly-written all-enabled config still loads on older
/// rahgozar builds that predate the object shape.
fn script_id_wire(cleaned: &[ScriptIdDto]) -> Option<serde_json::Value> {
    if cleaned.is_empty() {
        return None;
    }
    let all_enabled = cleaned.iter().all(|e| e.enabled);
    if all_enabled {
        if cleaned.len() == 1 {
            return Some(serde_json::Value::String(cleaned[0].id.clone()));
        }
        return Some(serde_json::Value::Array(
            cleaned
                .iter()
                .map(|e| serde_json::Value::String(e.id.clone()))
                .collect(),
        ));
    }
    Some(serde_json::Value::Array(
        cleaned
            .iter()
            .map(|e| {
                let mut m = serde_json::Map::new();
                m.insert("id".into(), serde_json::Value::String(e.id.clone()));
                m.insert("enabled".into(), serde_json::Value::Bool(e.enabled));
                serde_json::Value::Object(m)
            })
            .collect(),
    ))
}

/// Relay-mode credential gate. Returns Ok when either (a) the mode
/// doesn't use the Apps Script relay, or (b) the user has supplied at
/// least one enabled non-blank deployment ID and a non-blank auth key.
///
/// Direct / local_bypass modes intentionally accept any list shape
/// (including all-disabled) — they don't dispatch through the relay,
/// so the credential list is inert and we still persist it so a flip
/// back to apps_script doesn't wipe the user's settings.
fn check_relay_creds(
    needs_relay_creds: bool,
    cleaned: &[ScriptIdDto],
    auth_key: &str,
) -> Result<(), String> {
    if !needs_relay_creds {
        return Ok(());
    }
    if cleaned.is_empty() {
        return Err("At least one deployment ID is required".into());
    }
    if !cleaned.iter().any(|e| e.enabled) {
        return Err("At least one enabled deployment ID is required".into());
    }
    if auth_key.trim().is_empty() {
        return Err("Auth key is required".into());
    }
    Ok(())
}

/// Drive form validation that is safe during setup.
///
/// Full `Config::validate()` requires a refresh token, folder ID, and
/// relay key in `mode=drive`, but the desktop setup flow has to save
/// OAuth credentials before sign-in can mint that token. Keep this gate
/// to values that are either always required when present or could create
/// bad runtime behavior if persisted as zero.
fn check_drive_form(mode: Mode, update: &ConfigUpdate) -> Result<(), String> {
    if !mode.uses_drive_relay() {
        return Ok(());
    }
    if update.drive_poll_interval_ms == 0 {
        return Err("Drive poll interval must be greater than 0".into());
    }
    if update.drive_max_concurrent_uploads == 0 {
        return Err("Drive max concurrent uploads must be greater than 0".into());
    }
    let relay_pubkey = update.drive_relay_pubkey.trim();
    if !relay_pubkey.is_empty() {
        RelayPubkey::from_bech32m(relay_pubkey)
            .map_err(|e| format!("Invalid Drive relay public key: {e}"))?;
    }
    Ok(())
}

#[tauri::command]
pub fn save_config(update: ConfigUpdate) -> Result<ConfigDto, String> {
    // Parse via FromStr so unknown / typo'd modes from the UI are
    // surfaced here rather than blowing up later when the proxy
    // tries to start. The error message comes from
    // `impl FromStr for Mode` and already lists the accepted shapes.
    let mode: Mode = update.mode.parse().map_err(|e| format!("{e}"))?;
    let needs_relay_creds = mode.uses_apps_script_relay();

    // Trim + drop blank rows the same way the egui form did, so a
    // trailing-empty entry from the row editor doesn't get persisted.
    // The enabled flag rides along — disabled rows stay on disk so
    // the user can re-enable them without re-typing.
    let cleaned_ids: Vec<ScriptIdDto> = update
        .script_ids
        .iter()
        .map(|e| ScriptIdDto {
            id: e.id.trim().to_string(),
            enabled: e.enabled,
        })
        .filter(|e| !e.id.is_empty())
        .collect();

    check_relay_creds(needs_relay_creds, &cleaned_ids, &update.auth_key)?;
    check_drive_form(mode, &update)?;
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

    // Always drop the legacy `script_ids` plural alias so we don't
    // ship a file with both keys populated (the reader would merge
    // them — see `Config::script_id_entries` — but it's cleaner to
    // canonicalise on save).
    obj.remove("script_ids");
    match script_id_wire(&cleaned_ids) {
        Some(v) => {
            obj.insert("script_id".into(), v);
        }
        None => {
            obj.remove("script_id");
        }
    }

    // Drive-mode fields. Live under `config["drive"]`. The OAuth
    // refresh token in `drive.oauth_refresh_token` is preserved
    // (we don't touch it here — `drive_oauth_complete` writes it,
    // and the form never reads or echoes the secret).
    let drive_subtree = obj
        .entry("drive".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !drive_subtree.is_object() {
        return Err("config.json::drive is not an object".to_string());
    }
    let drive_obj = drive_subtree.as_object_mut().unwrap();
    drive_obj.insert(
        "folder_id".into(),
        serde_json::Value::String(update.drive_folder_id.trim().to_string()),
    );
    drive_obj.insert(
        "relay_pubkey".into(),
        serde_json::Value::String(update.drive_relay_pubkey.trim().to_string()),
    );
    drive_obj.insert(
        "poll_interval_ms".into(),
        update.drive_poll_interval_ms.into(),
    );
    drive_obj.insert(
        "max_concurrent_uploads".into(),
        update.drive_max_concurrent_uploads.into(),
    );
    let next_oauth_client_id = update.drive_oauth_client_id.trim().to_string();
    let next_oauth_client_secret = update.drive_oauth_client_secret.trim().to_string();
    if should_clear_drive_refresh_token(drive_obj, &next_oauth_client_id, &next_oauth_client_secret)
    {
        drive_obj.remove("oauth_refresh_token");
    }

    // BYO OAuth credentials — these are user-supplied per the
    // module docstring on `rahgozar::drive_oauth`. Trim because
    // paste from Google Cloud Console often picks up trailing
    // whitespace.
    drive_obj.insert(
        "oauth_client_id".into(),
        serde_json::Value::String(next_oauth_client_id.clone()),
    );
    drive_obj.insert(
        "oauth_client_secret".into(),
        serde_json::Value::String(next_oauth_client_secret.clone()),
    );
    // Snapshot the refresh-token presence for the response BEFORE the
    // atomic write — the field on disk is `oauth_refresh_token` under
    // `drive`; an absent / empty value → "not signed in".
    let drive_has_refresh_token = drive_obj
        .get("oauth_refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

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
        drive_folder_id: update.drive_folder_id.trim().to_string(),
        drive_relay_pubkey: update.drive_relay_pubkey.trim().to_string(),
        drive_poll_interval_ms: update.drive_poll_interval_ms,
        drive_max_concurrent_uploads: update.drive_max_concurrent_uploads,
        drive_oauth_client_id: next_oauth_client_id,
        drive_oauth_client_secret: next_oauth_client_secret,
        drive_has_refresh_token,
    })
}

fn should_clear_drive_refresh_token(
    drive_obj: &serde_json::Map<String, serde_json::Value>,
    next_oauth_client_id: &str,
    next_oauth_client_secret: &str,
) -> bool {
    let has_refresh_token = drive_obj
        .get("oauth_refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if !has_refresh_token {
        return false;
    }
    let current_client_id = drive_obj
        .get("oauth_client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let current_client_secret = drive_obj
        .get("oauth_client_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    current_client_id != next_oauth_client_id || current_client_secret != next_oauth_client_secret
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

/// Per-group field validation shared by `save_fronting_groups`. Pure so
/// it's unit-testable without touching disk. `ip` is required only for
/// pinned groups — camouflage (`force_ip`) groups resolve the
/// destination IP at runtime via DoH and ship with an empty `ip`,
/// mirroring the Rust `Config::validate` rule.
fn validate_fronting_group_fields(cleaned: &[FrontingGroup]) -> Result<(), String> {
    for (i, g) in cleaned.iter().enumerate() {
        if g.name.is_empty() {
            return Err(format!("Group #{}: name is required", i + 1));
        }
        if !g.force_ip && g.ip.is_empty() {
            return Err(format!(
                "Group '{}': IP is required (unless it is a camouflage/force_ip group)",
                g.name
            ));
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
    Ok(())
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

    validate_fronting_group_fields(&cleaned)?;

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

// ── Drive-mode setup (mode = "drive") ─────────────────────────────────
//
// Five commands that drive the desktop UI's Drive-mode setup flow:
//
//   - `drive_oauth_start`       — PKCE + spawn a loopback callback
//                                  listener; return the auth URL the
//                                  JS side opens in the system browser.
//   - `drive_oauth_complete`    — long-poll (up to 120 s) for the
//                                  listener task's result; on success
//                                  persists the refresh token into
//                                  `config.json::drive::oauth_refresh_token`.
//   - `drive_create_folder`     — `files.create` with the special folder
//                                  MIME type. Returns the new folder ID
//                                  the user pastes into the config UI.
//   - `drive_test_connection`   — refresh the access token + list the
//                                  configured folder; surface 401/403/404
//                                  with friendly text rather than the
//                                  raw `DriveApiError::Endpoint`.
//   - `drive_validate_relay_pubkey` — live bech32m parse echo so the
//                                  config form catches a typo before
//                                  the user clicks Save.

use rahgozar::drive_api::{build_drive_http_client, DriveApiClient, DriveApiError};
use rahgozar::drive_crypto::RelayPubkey;
use rahgozar::drive_oauth::{self, OAuthError};

use crate::state::OAuthCompletion;

/// Returned by `drive_oauth_start`. JS opens `auth_url` in the system
/// browser (via `tauri-plugin-opener`) and stashes `state_token` for
/// the subsequent `drive_oauth_complete` call.
#[derive(Serialize)]
pub struct DriveOauthStartDto {
    pub state_token: String,
    pub auth_url: String,
}

/// Result of `drive_oauth_complete`. The refresh token is persisted
/// server-side and intentionally NOT returned — the frontend only
/// needs to know the flow finished. `signed_in` reflects what the
/// next `get_config` would surface as `drive_has_refresh_token`.
#[derive(Serialize)]
pub struct DriveOauthCompleteDto {
    /// True once the refresh token has been persisted to
    /// `config.json::drive::oauth_refresh_token`. JS flips its
    /// "Signed in" indicator on this.
    pub signed_in: bool,
    /// Empty under the current `drive.file`-only scope. The UI
    /// surfaces "Signed in" without naming the account; the user
    /// already chose it in the browser. Kept as a forward-compat
    /// field so future scope upgrades can populate it.
    pub email: String,
}

/// Result of `drive_test_connection`. `files_count` is the total inside
/// the configured folder (any prefix) — a number the user can compare
/// against expectations to confirm the right folder is configured.
#[derive(Serialize)]
pub struct DriveTestDto {
    pub folder_id: String,
    pub files_count: usize,
}

/// PKCE installed-app OAuth start. Mints a `code_verifier` /
/// `code_challenge` pair + a random `state` token, binds a
/// `127.0.0.1:0` listener for the redirect callback, spawns a task
/// that will accept one connection + parse the `?code=` + exchange
/// for tokens, stashes the result-channel receiver in the
/// `oauth_pending` map keyed by `state_token`, and returns the
/// auth URL for the frontend to open.
///
/// The listener uses a 5-minute internal timeout — well above the
/// 120 s `drive_oauth_complete` long-poll window, so a slow user
/// finishing the browser flow after the JS-side poll timed out can
/// still complete the flow on the next call.
#[tauri::command]
pub async fn drive_oauth_start(
    state: State<'_, Arc<AppState>>,
    runtime: State<'_, RuntimeHandle>,
    oauth_client_id: String,
    oauth_client_secret: String,
    google_ip: String,
) -> Result<DriveOauthStartDto, String> {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    // BYO OAuth credentials come from the form, not from disk: this
    // means the user can click Sign in immediately after pasting the
    // client_id + secret, without having to click Save first
    // (previously the disk read forced Save-before-Sign-in, which
    // made the UX nonsensical given Save itself validates fields
    // the user can't fill until after sign-in like `folder_id`).
    // On successful flow completion, `drive_oauth_complete` writes
    // ALL THREE OAuth fields (client_id, client_secret, refresh_token)
    // atomically — so the on-disk state never has a refresh token
    // bound to a different client.
    let oauth_client_id = oauth_client_id.trim().to_string();
    let oauth_client_secret = oauth_client_secret.trim().to_string();
    let google_ip = google_ip.trim().to_string();
    if oauth_client_id.is_empty() {
        return Err(
            "OAuth client_id is empty — paste your Google Cloud Console Desktop-app client_id \
             into the Drive setup section first. See docs/drive_oauth_setup.md for the walkthrough."
                .to_string(),
        );
    }
    if oauth_client_secret.is_empty() {
        return Err(
            "OAuth client_secret is empty — paste the matching client_secret next to the \
             client_id. See docs/drive_oauth_setup.md for the walkthrough."
                .to_string(),
        );
    }

    // PKCE codes — verifier stays client-side (closure-captured by
    // the listener task), challenge goes in the auth URL.
    let pkce = drive_oauth::generate_pkce_codes(&mut rng);

    // 32-hex-char state token. Random per flow so a stray callback
    // from a stale flow can't replay into a fresh one — the
    // listener checks `state` parameter equality.
    let mut state_bytes = [0u8; 16];
    rng.fill_bytes(&mut state_bytes);
    let state_token: String = state_bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{:02x}", b);
            acc
        });

    // Bind the loopback listener. Port 0 → OS picks a free port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind 127.0.0.1:0: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("read bound port: {}", e))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{}/cb", port);

    let auth_url =
        drive_oauth::build_auth_url(&oauth_client_id, &redirect_uri, &pkce, &state_token);

    // Spawn the callback handler on the proxy runtime. Listener task
    // captures the verifier + expected state; on completion it
    // sends a Result into the oneshot — `drive_oauth_complete`
    // awaits the receive end.
    let (tx, rx) = oneshot::channel();
    let code_verifier = pkce.code_verifier;
    let expected_state = state_token.clone();
    let redirect_for_task = redirect_uri.clone();
    runtime.rt.spawn(async move {
        let result = run_oauth_callback_listener(
            listener,
            code_verifier,
            expected_state,
            redirect_for_task,
            oauth_client_id,
            oauth_client_secret,
            google_ip,
        )
        .await;
        let _ = tx.send(result);
    });

    {
        let mut pending = state.oauth_pending.lock().unwrap();
        pending.insert(state_token.clone(), rx);
    }

    Ok(DriveOauthStartDto {
        state_token,
        auth_url,
    })
}

/// Wait for the callback listener task to deliver a result (or fail).
/// On success, writes `refresh_token` into the on-disk config under
/// `drive.oauth_refresh_token`, preserving every other key.
///
/// Times out after 120 s; the JS side is expected to call this once
/// (with a long fetch timeout) rather than polling. A `state_token`
/// not present in the pending map is a hard error — either a
/// double-call or a stale token from a prior session.
#[tauri::command]
pub async fn drive_oauth_complete(
    state_token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<DriveOauthCompleteDto, String> {
    let mut rx = {
        let mut pending = state.oauth_pending.lock().unwrap();
        pending.remove(&state_token).ok_or_else(|| {
            "no pending OAuth flow with that state token (already completed, or expired)"
                .to_string()
        })?
    };

    // Pass `&mut rx` to `timeout` so the receiver isn't consumed if
    // the long-poll times out — the JS side may call
    // `drive_oauth_complete` again to keep waiting. On timeout, put
    // the receiver back into the pending map so the next call finds
    // it. On success / task-death the receiver is consumed.
    let outer = match tokio::time::timeout(std::time::Duration::from_secs(120), &mut rx).await {
        Ok(inner) => inner,
        Err(_) => {
            // Timeout — receiver still owned by `rx`; re-insert.
            let mut pending = state.oauth_pending.lock().unwrap();
            pending.insert(state_token, rx);
            return Err(
                "OAuth flow timed out — finish signing in within 120 seconds and call complete \
                 again"
                    .into(),
            );
        }
    };
    let completion: OAuthCompletion =
        outer.map_err(|_| "OAuth flow listener task died before completing".to_string())??;

    // Persist the THREE OAuth fields together: the client_id +
    // client_secret the user pasted into the form, and the refresh
    // token Google just minted against them. Atomic-bundle so the
    // disk never has a token bound to credentials it doesn't carry
    // — previously this function only wrote `oauth_refresh_token`
    // and required the disk's client_id/secret to match (which
    // forced Save-before-Sign-in). Every other field on disk is
    // preserved unchanged.
    let mut cfg = read_or_default_config_json()?;
    if !cfg.is_object() {
        return Err("config.json is not a JSON object — aborting save".to_string());
    }
    let drive_obj = cfg
        .as_object_mut()
        .unwrap()
        .entry("drive".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !drive_obj.is_object() {
        return Err("config.json::drive is not an object — aborting save".to_string());
    }
    let drive_map = drive_obj.as_object_mut().unwrap();
    drive_map.insert(
        "oauth_client_id".to_string(),
        serde_json::Value::String(completion.oauth_client_id),
    );
    drive_map.insert(
        "oauth_client_secret".to_string(),
        serde_json::Value::String(completion.oauth_client_secret),
    );
    drive_map.insert(
        "oauth_refresh_token".to_string(),
        serde_json::Value::String(completion.refresh_token),
    );
    write_config_json(&cfg)?;

    Ok(DriveOauthCompleteDto {
        signed_in: true,
        email: completion.email,
    })
}

/// Create a new Drive folder named `name`. Used by the first-time
/// setup UI: user clicks "Create new mailbox folder", we return the
/// new folder's ID, the UI saves it into `drive.folder_id`.
///
/// Requires a valid `drive.oauth_refresh_token` (i.e. the user must
/// have completed `drive_oauth_start` / `_complete` first). The
/// folder lands at the user's Drive root.
#[tauri::command]
pub async fn drive_create_folder(name: String) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("folder name is empty".to_string());
    }
    let (drive_api, access_token) = build_drive_api_from_config().await?;
    drive_api
        .create_folder(&access_token, name)
        .await
        .map_err(|e| drive_error_to_friendly(e, ""))
}

/// Probe the configured Drive folder. Confirms two things at once:
///   1. The saved `oauth_refresh_token` still works (a refresh is
///      issued; expired/revoked → user-friendly error).
///   2. The saved `folder_id` is reachable AND the OAuth account has
///      access (`files.list` against the folder; 404 / 403 → friendly
///      errors).
///
/// Returns the file count inside the folder — the UI displays it so
/// the user can sanity-check the folder choice ("oh, that's the
/// folder with 50 files, not the empty one I made for this").
#[tauri::command]
pub async fn drive_test_connection() -> Result<DriveTestDto, String> {
    let cfg_json = read_or_default_config_json()?;
    let drive_section = cfg_json
        .get("drive")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let folder_id = drive_section
        .get("folder_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if folder_id.is_empty() {
        return Err("no folder ID set — create or paste the shared folder ID first".to_string());
    }

    let (drive_api, access_token) = build_drive_api_from_config().await?;
    // Empty prefix → counts every file in the folder (the relay's
    // own h_*/c2r_*/r2c_* plus any extras the user has).
    let files = drive_api
        .list_files_in_folder(&access_token, &folder_id, "")
        .await
        .map_err(|e| drive_error_to_friendly(e, &folder_id))?;

    Ok(DriveTestDto {
        folder_id,
        files_count: files.len(),
    })
}

/// Live parse-validate of a bech32m relay pubkey for the config
/// form's input. Pure function — wraps
/// [`RelayPubkey::from_bech32m`] so the frontend can show a green
/// check / red error before Save is clicked, without paying the
/// full config-load round-trip every keystroke.
#[tauri::command]
pub fn drive_validate_relay_pubkey(s: String) -> Result<(), String> {
    RelayPubkey::from_bech32m(&s)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ── Internal helpers ───────────────────────────────────────────────────

/// Common path used by `drive_test_connection` and
/// `drive_create_folder`: read config, build a domain-fronted HTTP
/// client (matching the runtime path the actual Drive mux uses),
/// refresh the access token, return both.
async fn build_drive_api_from_config() -> Result<(DriveApiClient, String), String> {
    let cfg_json = read_or_default_config_json()?;
    let drive_section = cfg_json
        .get("drive")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let refresh_token = drive_section
        .get("oauth_refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if refresh_token.is_empty() {
        return Err("not signed in to Google — click 'Sign in with Google' first".to_string());
    }
    let (oauth_client_id, oauth_client_secret) =
        read_drive_oauth_credentials_from_value(&drive_section)?;
    let google_ip = cfg_json
        .get("google_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let google_ip_opt = if google_ip.is_empty() {
        None
    } else {
        Some(google_ip.as_str())
    };

    let http = build_drive_http_client(google_ip_opt)
        .map_err(|e| format!("failed to build HTTP client: {}", e))?;
    let drive_api = DriveApiClient::with_default_base_url(http.clone());

    let tokens = match drive_oauth::refresh_access_token(
        &http,
        &refresh_token,
        &oauth_client_id,
        &oauth_client_secret,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            // RFC 6749 §5.2: on `invalid_grant` / `unauthorized_client`
            // the saved refresh token is dead — clear it now so the
            // next Create/Test attempt doesn't re-send it and trip
            // Google's fraud heuristics. Best-effort: if the clear
            // fails (disk full, parse error on an externally edited
            // config), still propagate the friendly error so the user
            // knows to re-auth.
            if e.is_refresh_token_revoked() {
                if let Err(clear_err) = clear_drive_refresh_token_on_disk() {
                    tracing::warn!(
                        "could not clear revoked refresh token from config.json: {}",
                        clear_err
                    );
                }
            }
            return Err(oauth_error_to_friendly(e));
        }
    };
    Ok((drive_api, tokens.access_token))
}

/// Set `drive.oauth_refresh_token` to the empty string on disk,
/// preserving every other field. Called when Google returns
/// `invalid_grant` / `unauthorized_client`, so the next refresh
/// attempt sees an empty token and asks the user to re-sign-in
/// instead of re-sending the dead one.
fn clear_drive_refresh_token_on_disk() -> Result<(), String> {
    let path = data_dir::config_path();
    if !path.exists() {
        return Ok(());
    }
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    let Some(obj) = json.as_object_mut() else {
        return Ok(());
    };
    let Some(drive_obj) = obj.get_mut("drive").and_then(|v| v.as_object_mut()) else {
        return Ok(());
    };
    drive_obj.insert(
        "oauth_refresh_token".to_string(),
        serde_json::Value::String(String::new()),
    );
    rahgozar::profiles::write_config_json_to(&path, &json)
        .map_err(|e| format!("write {}: {}", path.display(), e))
}

/// Read the user-supplied OAuth client_id + client_secret from the
/// on-disk `config.json::drive` section. Both fields are required
/// for any Drive-mode operation (rahgozar is BYO OAuth — there are
/// no compile-time defaults). Returns a friendly error pointing at
/// the setup guide when either is empty.
fn read_drive_oauth_credentials_from_value(
    drive_section: &serde_json::Value,
) -> Result<(String, String), String> {
    let client_id = drive_section
        .get("oauth_client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if client_id.is_empty() {
        return Err(
            "no OAuth client_id configured — register your own OAuth client in Google Cloud \
             Console and paste it in the Drive setup screen. \
             See docs/drive_oauth_setup.md for the walkthrough."
                .to_string(),
        );
    }
    let client_secret = drive_section
        .get("oauth_client_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if client_secret.is_empty() {
        return Err(
            "no OAuth client_secret configured — paste it next to the client_id in the Drive \
             setup screen. See docs/drive_oauth_setup.md for the walkthrough."
                .to_string(),
        );
    }
    Ok((client_id, client_secret))
}

/// Listener task body for `drive_oauth_start`. Accepts ONE
/// connection on the bound loopback port (with a 5-minute upper
/// bound), reads the HTTP request, parses `?code=...&state=...`,
/// writes a friendly HTML response so the browser tab confirms
/// completion, then exchanges the code for tokens via
/// [`drive_oauth::exchange_authorization_code`].
async fn run_oauth_callback_listener(
    listener: tokio::net::TcpListener,
    code_verifier: String,
    expected_state: String,
    redirect_uri: String,
    oauth_client_id: String,
    oauth_client_secret: String,
    google_ip: String,
) -> Result<OAuthCompletion, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let accept_deadline = std::time::Duration::from_secs(300);
    let deadline = tokio::time::Instant::now() + accept_deadline;
    const MAX_REQ_BYTES: usize = 8 * 1024;

    let (mut stream, code) = 'accept_loop: loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(
                "OAuth callback timed out after 5 minutes (browser flow not completed)".to_string(),
            );
        }
        let (mut stream, _) = tokio::time::timeout(remaining, listener.accept())
            .await
            .map_err(|_| {
                "OAuth callback timed out after 5 minutes (browser flow not completed)".to_string()
            })?
            .map_err(|e| format!("accept callback: {}", e))?;

        // Read the HTTP request head (up to the first `\r\n\r\n`).
        // Cap at 8 KiB — Google's redirect URL is well under that.
        let mut buf = vec![0u8; MAX_REQ_BYTES];
        let mut filled = 0usize;
        let request_str = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(
                    "OAuth callback timed out after 5 minutes (browser flow not completed)"
                        .to_string(),
                );
            }
            let n = match tokio::time::timeout(remaining, stream.read(&mut buf[filled..])).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    tracing::debug!(
                        "OAuth callback read failed; waiting for next request: {}",
                        e
                    );
                    continue 'accept_loop;
                }
                Err(_) => {
                    return Err(
                        "OAuth callback timed out after 5 minutes (browser flow not completed)"
                            .to_string(),
                    );
                }
            };
            if n == 0 {
                tracing::debug!(
                    "OAuth callback connection closed before request head; waiting for next request"
                );
                continue 'accept_loop;
            }
            filled += n;
            if let Ok(s) = std::str::from_utf8(&buf[..filled]) {
                if s.contains("\r\n\r\n") {
                    break s.to_string();
                }
            }
            if filled >= MAX_REQ_BYTES {
                let _ = stream
                    .write_all(http_response(413, "OAuth callback request too large"))
                    .await;
                tracing::debug!("OAuth callback request head exceeded 8 KiB; ignoring request");
                continue 'accept_loop;
            }
        };

        let Some(request_line) = request_str.lines().next() else {
            let _ = stream
                .write_all(http_response(400, "Empty callback request"))
                .await;
            continue 'accept_loop;
        };
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            let _ = stream
                .write_all(http_response(400, "Malformed callback request"))
                .await;
            tracing::debug!("malformed callback request line: {request_line}");
            continue 'accept_loop;
        }
        let path_and_query = parts[1];
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((path_and_query, ""));
        if !path.starts_with("/cb") {
            let _ = stream
                .write_all(http_response(404, "Not the callback path"))
                .await;
            tracing::debug!("ignoring non-callback OAuth path: {path}");
            continue 'accept_loop;
        }

        let mut code: Option<String> = None;
        let mut state_param: Option<String> = None;
        let mut error_param: Option<String> = None;
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let decoded = url_decode_ascii(v);
                match k {
                    "code" => code = Some(decoded),
                    "state" => state_param = Some(decoded),
                    "error" => error_param = Some(decoded),
                    _ => {}
                }
            }
        }

        if let Some(err) = error_param {
            let html = error_response_html(&err);
            let _ = stream.write_all(html.as_bytes()).await;
            let _ = stream.shutdown().await;
            return Err(format!("OAuth flow returned error from Google: {err}"));
        }

        let Some(code) = code else {
            let _ = stream
                .write_all(error_response_html("callback URL missing code").as_bytes())
                .await;
            tracing::debug!("OAuth callback URL missing code; waiting for next request");
            continue 'accept_loop;
        };
        let Some(state_recv) = state_param else {
            let _ = stream
                .write_all(error_response_html("callback URL missing state").as_bytes())
                .await;
            tracing::debug!("OAuth callback URL missing state; waiting for next request");
            continue 'accept_loop;
        };
        if state_recv != expected_state {
            let _ = stream
                .write_all(error_response_html("state token mismatch").as_bytes())
                .await;
            tracing::debug!("OAuth state token mismatch; waiting for next request");
            continue 'accept_loop;
        }
        break (stream, code);
    };

    // Exchange the code for tokens through the same optional Google
    // edge override Drive mode uses for runtime traffic. The browser
    // authorization page itself is still opened by the system browser;
    // this covers the in-app token POST to oauth2.googleapis.com.
    let google_ip_opt = if google_ip.is_empty() {
        None
    } else {
        Some(google_ip.as_str())
    };
    let http = match build_drive_http_client(google_ip_opt) {
        Ok(http) => http,
        Err(e) => {
            let msg = format!("failed to build HTTP client: {}", e);
            let _ = stream.write_all(error_response_html(&msg).as_bytes()).await;
            let _ = stream.shutdown().await;
            return Err(msg);
        }
    };
    let tokens = match drive_oauth::exchange_authorization_code(
        &http,
        &code,
        &redirect_uri,
        &code_verifier,
        &oauth_client_id,
        &oauth_client_secret,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(e) => {
            let msg = oauth_error_to_friendly(e);
            let _ = stream.write_all(error_response_html(&msg).as_bytes()).await;
            let _ = stream.shutdown().await;
            return Err(msg);
        }
    };
    let refresh_token = match tokens.refresh_token {
        Some(t) => t,
        None => {
            let msg =
                "OAuth response did not include a refresh_token (this is unexpected — try again)"
                    .to_string();
            let _ = stream.write_all(error_response_html(&msg).as_bytes()).await;
            let _ = stream.shutdown().await;
            return Err(msg);
        }
    };

    // Friendly HTML confirmation after the token exchange succeeds, so
    // browser and app agree about the outcome.
    let _ = stream.write_all(&success_response_html()).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;

    Ok(OAuthCompletion {
        refresh_token,
        oauth_client_id,
        oauth_client_secret,
        // Empty under the current `drive.file`-only scope. See
        // `OAuthCompletion::email` for rationale.
        email: String::new(),
    })
}

/// Minimal ASCII URL-decode for OAuth callback query values. Handles
/// `+` → space and `%XX` → byte. Hand-rolled rather than pulling
/// `url` as a desktop-side dep just for this one call — OAuth codes
/// are URL-safe ASCII by construction, so the percent-decoded bytes
/// land back as valid ASCII without UTF-8 dance.
fn url_decode_ascii(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn success_response_html() -> Vec<u8> {
    let body = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
                <title>rahgozar OAuth complete</title></head>\
                <body style=\"font-family:system-ui,sans-serif;text-align:center;padding:3em;\">\
                <h1>Signed in.</h1>\
                <p>You can close this tab and return to rahgozar.</p>\
                </body></html>";
    let mut out = Vec::with_capacity(body.len() + 128);
    out.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    out.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body.as_bytes());
    out
}

fn error_response_html(reason: &str) -> String {
    let safe = reason
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>rahgozar OAuth failed</title></head>\
         <body style=\"font-family:system-ui,sans-serif;text-align:center;padding:3em;\">\
         <h1>Sign-in failed.</h1>\
         <p>Reason: <code>{}</code></p>\
         <p>You can close this tab and try again.</p>\
         </body></html>",
        safe
    );
    let mut header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    header.push_str(&body);
    header
}

/// Format a minimal HTTP response with `status` + plain-text body.
/// Used for the "wrong path" 404 in the callback listener.
fn http_response(status: u16, body: &str) -> &'static [u8] {
    // Returning `&'static` to avoid an extra allocation for the
    // small fixed cases the callback uses. Only `(404, "Not the
    // callback path")` is currently passed; extending later means
    // adding another match arm.
    match (status, body) {
        (404, "Not the callback path") => {
            b"HTTP/1.1 404 Not Found\r\n\
                                            Content-Type: text/plain; charset=utf-8\r\n\
                                            Content-Length: 21\r\n\
                                            Connection: close\r\n\r\n\
                                            Not the callback path"
        }
        _ => {
            b"HTTP/1.1 500 Internal Server Error\r\n\
              Content-Type: text/plain; charset=utf-8\r\n\
              Content-Length: 21\r\n\
              Connection: close\r\n\r\n\
              Internal server error"
        }
    }
}

/// Translate an [`OAuthError`] into a user-actionable string. The
/// raw `Display` impl already does a reasonable job; this layer
/// rewrites a few common categories into "do this, then try again"
/// shapes that map cleanly to UI toasts.
fn oauth_error_to_friendly(e: OAuthError) -> String {
    match &e {
        OAuthError::Endpoint { status, .. } if *status == 400 || *status == 401 => {
            "Google rejected the OAuth refresh — the saved token is no longer valid. \
             Sign in again to get a fresh one."
                .to_string()
        }
        OAuthError::Endpoint { status, .. } if *status == 403 => {
            "Google refused the OAuth refresh with 403. The OAuth client may have been \
             revoked, or the account is restricted from accessing Drive."
                .to_string()
        }
        OAuthError::Transport(_) => {
            format!(
                "Network error reaching Google's OAuth endpoint (check internet \
                 connectivity / `google_ip` config): {}",
                e
            )
        }
        _ => format!("OAuth error: {}", e),
    }
}

/// Translate a [`DriveApiError`] into a user-actionable string,
/// using `folder_id` to give context where relevant.
fn drive_error_to_friendly(e: DriveApiError, folder_id: &str) -> String {
    match &e {
        DriveApiError::Endpoint { status: 401, .. } => {
            "Drive rejected the access token (401). Sign in again — the saved \
             refresh token may have been revoked."
                .to_string()
        }
        DriveApiError::Endpoint {
            status: 403,
            reason,
            ..
        } => match reason.as_deref() {
            Some("userRateLimitExceeded") | Some("rateLimitExceeded") => {
                "Drive API rate limit hit. Wait a minute and try again.".to_string()
            }
            Some(r) => format!(
                "Drive forbidden (reason: {r}). The signed-in account may not have access \
                 to folder {folder_id}."
            ),
            None => "Drive forbidden — possibly Google has restricted this account from \
                    accessing Drive."
                .to_string(),
        },
        DriveApiError::Endpoint { status: 404, .. } => format!(
            "Folder {folder_id} not found. Check the folder ID — paste the bare ID from \
             Drive's URL, not the full URL."
        ),
        DriveApiError::Transport(_) => format!(
            "Network error reaching Drive (check internet / `google_ip`): {}",
            e
        ),
        _ => format!("Drive API error: {}", e),
    }
}

#[cfg(test)]
mod fronting_group_validation_tests {
    use super::*;

    fn g(name: &str, ip: &str, sni: &str, force_ip: bool) -> FrontingGroup {
        FrontingGroup {
            name: name.into(),
            ip: ip.into(),
            sni: sni.into(),
            domains: vec!["example.com".into()],
            force_ip,
            verify_names: vec![],
        }
    }

    #[test]
    fn pinned_group_requires_ip() {
        let err = validate_fronting_group_fields(&[g("vercel", "", "react.dev", false)])
            .expect_err("pinned group with empty ip must fail");
        assert!(err.contains("IP is required"), "got: {}", err);
    }

    #[test]
    fn camouflage_group_allows_empty_ip() {
        // The Critical-1 regression: a curated google-video / meta group
        // (force_ip, no ip) must save successfully through the desktop
        // command path.
        assert!(
            validate_fronting_group_fields(&[g("meta", "", "www.microsoft.com", true)]).is_ok()
        );
    }

    #[test]
    fn camouflage_group_still_requires_sni_and_name() {
        assert!(validate_fronting_group_fields(&[g("", "", "www.microsoft.com", true)]).is_err());
        assert!(validate_fronting_group_fields(&[g("meta", "", "", true)]).is_err());
    }
}

#[cfg(test)]
mod drive_helper_tests {
    use super::*;

    #[test]
    fn url_decode_ascii_passes_through_plain_text() {
        assert_eq!(url_decode_ascii("hello"), "hello");
        assert_eq!(url_decode_ascii(""), "");
    }

    #[test]
    fn url_decode_ascii_decodes_percent_escapes() {
        // Google's OAuth codes commonly contain `/` (which gets
        // percent-encoded in transit as `%2F`) and `+` (encoded as
        // `%2B`).
        assert_eq!(url_decode_ascii("a%2Fb"), "a/b");
        assert_eq!(url_decode_ascii("a%2Bb"), "a+b");
        assert_eq!(url_decode_ascii("%41%42%43"), "ABC");
    }

    #[test]
    fn url_decode_ascii_decodes_plus_to_space() {
        assert_eq!(url_decode_ascii("hello+world"), "hello world");
    }

    #[test]
    fn url_decode_ascii_leaves_malformed_percent_alone() {
        // Trailing `%` without two hex digits → keep the literal `%`.
        assert_eq!(url_decode_ascii("a%"), "a%");
        // Non-hex chars after `%` → keep the literal `%`.
        assert_eq!(url_decode_ascii("a%XX"), "a%XX");
    }

    #[test]
    fn drive_validate_relay_pubkey_accepts_round_trip() {
        // Mint a fresh keypair via the rahgozar crypto layer and
        // verify the validator accepts the resulting bech32m.
        let secret = rahgozar::drive_crypto::RelaySecret::generate(rand::rngs::OsRng);
        let s = secret.public_key().to_bech32m();
        assert!(drive_validate_relay_pubkey(s).is_ok());
    }

    #[test]
    fn drive_validate_relay_pubkey_rejects_garbage() {
        assert!(drive_validate_relay_pubkey("not bech32m".into()).is_err());
        assert!(drive_validate_relay_pubkey("".into()).is_err());
        assert!(drive_validate_relay_pubkey("rgdr1aaaaaa".into()).is_err());
    }

    #[test]
    fn drive_oauth_complete_dto_does_not_leak_refresh_token() {
        // Regression guard: the refresh_token is persisted server-
        // side; surfacing it to the renderer broadens token exposure
        // for no benefit. If a future change re-adds the field, this
        // test fails so the reviewer notices.
        let dto = DriveOauthCompleteDto {
            signed_in: true,
            email: "redacted@example.com".to_string(),
        };
        let json = serde_json::to_string(&dto).expect("serialize");
        assert!(
            !json.contains("refresh_token"),
            "DTO must not carry refresh_token; got {json}"
        );
        assert!(json.contains("\"signed_in\":true"));
    }

    #[test]
    fn oauth_error_to_friendly_rewrites_endpoint_401() {
        let e = OAuthError::Endpoint {
            endpoint: "test",
            status: 401,
            body: "{}".into(),
        };
        let msg = oauth_error_to_friendly(e);
        assert!(msg.to_lowercase().contains("sign in again"));
    }

    #[test]
    fn oauth_error_to_friendly_rewrites_endpoint_403() {
        let e = OAuthError::Endpoint {
            endpoint: "test",
            status: 403,
            body: "{}".into(),
        };
        let msg = oauth_error_to_friendly(e);
        assert!(msg.contains("403"));
    }

    #[test]
    fn drive_error_to_friendly_rewrites_404() {
        let e = DriveApiError::Endpoint {
            status: 404,
            reason: Some("notFound".into()),
            message: "File not found: BAD".into(),
        };
        let msg = drive_error_to_friendly(e, "MYFOLDER");
        assert!(msg.contains("MYFOLDER"));
        assert!(msg.to_lowercase().contains("not found") || msg.to_lowercase().contains("check"));
    }

    #[test]
    fn drive_error_to_friendly_rewrites_403_rate_limit() {
        let e = DriveApiError::Endpoint {
            status: 403,
            reason: Some("userRateLimitExceeded".into()),
            message: "Rate Limit Exceeded".into(),
        };
        let msg = drive_error_to_friendly(e, "MYFOLDER");
        assert!(msg.to_lowercase().contains("rate limit"));
    }
}

// ── Tests ──────────────────────────────────────────────────────────────
//
// Pure-function coverage for the bits of `save_config` that don't need
// disk I/O. The full `save_config` path also touches `config.json`
// (which `data_dir::config_path()` resolves to a per-user location);
// exercising that here would require either a OnceLock-set
// `set_data_dir()` (single-shot, racy across parallel tests) or
// process-isolated integration tests. Extracting `script_id_wire` and
// `check_relay_creds` as pure helpers gives us the same coverage
// without that machinery.

#[cfg(test)]
mod save_path_tests {
    use super::*;

    fn entry(id: &str, enabled: bool) -> ScriptIdDto {
        ScriptIdDto {
            id: id.into(),
            enabled,
        }
    }

    fn update(mode: &str) -> ConfigUpdate {
        ConfigUpdate {
            mode: mode.into(),
            listen_host: "127.0.0.1".into(),
            listen_port: 8085,
            socks5_port: Some(8086),
            script_ids: vec![entry("DEPLOYMENT_ID", true)],
            auth_key: "secret".into(),
            front_domain: "www.google.com".into(),
            google_ip: "216.239.38.120".into(),
            log_level: "info".into(),
            drive_folder_id: String::new(),
            drive_relay_pubkey: String::new(),
            drive_poll_interval_ms: 300,
            drive_max_concurrent_uploads: 8,
            drive_oauth_client_id: "CID.apps.googleusercontent.com".into(),
            drive_oauth_client_secret: "SECRET".into(),
        }
    }

    // ── Wire shape ─────────────────────────────────────────────────

    #[test]
    fn script_id_wire_empty_returns_none() {
        assert!(script_id_wire(&[]).is_none());
    }

    #[test]
    fn script_id_wire_single_enabled_writes_bare_string() {
        // Downgrade-compat: a one-row all-enabled list is the most
        // common shape and must remain readable by pre-disable-flag
        // binaries.
        let v = script_id_wire(&[entry("A", true)]).expect("non-empty");
        assert_eq!(v, serde_json::Value::String("A".into()));
    }

    #[test]
    fn script_id_wire_all_enabled_multi_writes_string_array() {
        let v = script_id_wire(&[entry("A", true), entry("B", true), entry("C", true)])
            .expect("non-empty");
        assert_eq!(
            v,
            serde_json::json!(["A", "B", "C"]),
            "all-enabled multi-row must remain a bare-string array for older clients",
        );
    }

    #[test]
    fn script_id_wire_mixed_disabled_writes_object_array() {
        let v = script_id_wire(&[entry("A", true), entry("B", false), entry("C", true)])
            .expect("non-empty");
        assert_eq!(
            v,
            serde_json::json!([
                {"id": "A", "enabled": true},
                {"id": "B", "enabled": false},
                {"id": "C", "enabled": true},
            ]),
            "any disabled row escalates to the object form so the flag survives",
        );
    }

    #[test]
    fn script_id_wire_all_disabled_writes_object_array() {
        // Edge case: every row disabled. Save's validation rejects
        // this in relay modes (covered separately by check_relay_creds
        // tests below); in direct / local_bypass modes it's accepted,
        // so the wire emitter must still produce a sensible shape.
        let v = script_id_wire(&[entry("A", false), entry("B", false)]).expect("non-empty");
        assert_eq!(
            v,
            serde_json::json!([
                {"id": "A", "enabled": false},
                {"id": "B", "enabled": false},
            ]),
        );
    }

    // ── Validation gate ────────────────────────────────────────────

    #[test]
    fn check_relay_creds_relay_mode_rejects_empty_list() {
        let err = check_relay_creds(true, &[], "secret").expect_err("empty list must error");
        assert!(
            err.contains("At least one deployment ID is required"),
            "got: {err}",
        );
    }

    #[test]
    fn check_relay_creds_relay_mode_rejects_all_disabled() {
        let err = check_relay_creds(true, &[entry("A", false), entry("B", false)], "secret")
            .expect_err("all-disabled must error in relay mode");
        assert!(
            err.contains("At least one enabled deployment ID is required"),
            "got: {err}",
        );
    }

    #[test]
    fn check_relay_creds_relay_mode_rejects_blank_auth_key() {
        let err = check_relay_creds(true, &[entry("A", true)], "   ")
            .expect_err("blank auth_key must error in relay mode");
        assert!(err.contains("Auth key is required"), "got: {err}");
    }

    #[test]
    fn check_relay_creds_relay_mode_accepts_one_enabled() {
        check_relay_creds(true, &[entry("A", false), entry("B", true)], "secret")
            .expect("any enabled row + auth_key satisfies the gate");
    }

    #[test]
    fn check_relay_creds_non_relay_mode_accepts_empty_list() {
        // Direct / local_bypass: no relay credentials needed, so an
        // empty list is fine.
        check_relay_creds(false, &[], "")
            .expect("direct/local_bypass must accept zero deployment IDs");
    }

    #[test]
    fn check_relay_creds_non_relay_mode_accepts_all_disabled() {
        // Direct / local_bypass: persist the (inert) list as-is so
        // flipping back to apps_script doesn't wipe what the user
        // typed previously.
        check_relay_creds(false, &[entry("A", false), entry("B", false)], "")
            .expect("direct/local_bypass must accept an all-disabled list");
    }

    #[test]
    fn check_drive_form_allows_incomplete_setup_save() {
        let u = update("drive");
        check_drive_form(Mode::Drive, &u)
            .expect("setup save must allow missing token/folder/key before OAuth completes");
    }

    #[test]
    fn check_drive_form_rejects_zero_knobs() {
        let mut u = update("drive");
        u.drive_poll_interval_ms = 0;
        let err = check_drive_form(Mode::Drive, &u).expect_err("zero poll interval must fail");
        assert!(err.contains("poll interval"), "got: {err}");

        let mut u = update("drive");
        u.drive_max_concurrent_uploads = 0;
        let err = check_drive_form(Mode::Drive, &u).expect_err("zero concurrency must fail");
        assert!(err.contains("concurrent uploads"), "got: {err}");
    }

    #[test]
    fn check_drive_form_rejects_invalid_pubkey_when_present() {
        let mut u = update("drive");
        u.drive_relay_pubkey = "not bech32m".into();
        let err = check_drive_form(Mode::Drive, &u).expect_err("invalid key must fail");
        assert!(err.contains("relay public key"), "got: {err}");
    }

    #[test]
    fn drive_refresh_token_survives_unchanged_oauth_client() {
        let drive = serde_json::json!({
            "oauth_client_id": "CID",
            "oauth_client_secret": "SECRET",
            "oauth_refresh_token": "REFRESH",
        });
        let obj = drive.as_object().unwrap();
        assert!(!should_clear_drive_refresh_token(obj, "CID", "SECRET"));
    }

    #[test]
    fn drive_refresh_token_clears_when_oauth_client_changes() {
        let drive = serde_json::json!({
            "oauth_client_id": "CID",
            "oauth_client_secret": "SECRET",
            "oauth_refresh_token": "REFRESH",
        });
        let obj = drive.as_object().unwrap();
        assert!(should_clear_drive_refresh_token(obj, "NEWCID", "SECRET"));
        assert!(should_clear_drive_refresh_token(obj, "CID", "NEWSECRET"));
    }

    // The previous `ensure_drive_oauth_credentials_unchanged` guard
    // and its tests were removed when `drive_oauth_complete` switched
    // to writing all three OAuth fields atomically (so there's
    // nothing to "compare against" — the credentials in the form
    // are the credentials the listener used, and both land on disk
    // together).
}
