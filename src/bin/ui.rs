use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use rahgozar::cdn_discover::{discover_front, DiscoveredFront};
use rahgozar::cert_installer::{install_ca, reconcile_sudo_environment, remove_ca};
use rahgozar::config::{Config, FrontingGroup, ScriptId};
use rahgozar::data_dir;
use rahgozar::domain_fronter::DEFAULT_GOOGLE_SNI_POOL;
use rahgozar::lan_utils::{advertise_proxy_host, detect_lan_ip, is_share_on_lan};
use rahgozar::mitm::{MitmCertManager, CA_CERT_FILE};
use rahgozar::profiles::{self, ProfilesFile};
use rahgozar::proxy_server::{ProxyError, ProxyServer, RuntimeState};
use rahgozar::{scan_ips, scan_sni, test_cmd};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const WIN_WIDTH: f32 = 520.0;
const WIN_HEIGHT: f32 = 680.0;
const LOG_MAX: usize = 200;

fn main() -> eframe::Result<()> {
    // Auto-updater finalize step — must run before *anything* else
    // because on Windows a staged `<exe>.new` is what got launched, and we
    // need to rename it back to the canonical exe and re-exec before
    // touching state, opening windows, etc.
    rahgozar::update_apply::finalize_pending_at_startup();

    let _ = rustls::crypto::ring::default_provider().install_default();
    // Re-point HOME at the invoking user if this binary was launched
    // under sudo (see cert_installer::reconcile_sudo_environment). Must
    // run before any data_dir / firefox_profile_dirs call.
    reconcile_sudo_environment();
    rahgozar::rlimit::raise_nofile_limit_best_effort();

    let shared = Arc::new(Shared::default());
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Cmd>();

    // Load the user's saved form first so we can seed the tracing filter
    // with their saved log level. Otherwise the form's log-level combobox
    // would only ever take effect via env var or after Save → restart, and
    // users on the UI binary (issue #401) reasonably expect the saved
    // config.json `log_level` to apply at boot like it does for the CLI.
    let (form, load_err) = load_form();
    let initial_toast = load_err.map(|e| (e, Instant::now()));

    // Hook tracing events into the Recent log panel. Without this every
    // tracing::info! / debug! / trace! the proxy emits gets swallowed and
    // the panel only ever shows our manual push_log calls, making the log
    // level selector look useless (issue #12 bug 2).
    //
    // Filter precedence (issue #401 fix in v1.8.2):
    //   1. RUST_LOG env var if set                         — explicit override
    //   2. Saved config's `log_level` (passed from form)   — what users mean
    //      when they pick a level in the UI
    //   3. "info,hyper=warn"                               — sensible default
    //
    // Save inside the running UI also installs the new filter via the
    // reload handle (see `LOG_RELOAD` below), so users don't need to
    // restart for a config change to take effect.
    install_ui_tracing(shared.clone(), &form.log_level);

    let shared_bg = shared.clone();
    std::thread::Builder::new()
        .name("mhrv-bg".into())
        .spawn(move || background_thread(shared_bg, cmd_rx))
        .expect("failed to spawn background thread");

    // Pick the renderer. Default is `glow` (OpenGL 2+) because that's
    // what we shipped through v1.0.x and it has the least binary-size
    // overhead. Users on older Windows boxes / RDP sessions / headless
    // VMs that crashed with `egui_glow requires opengl 2.0+` (issue
    // #28) can force the wgpu backend — DX12 on Windows, Vulkan on
    // Linux, Metal on macOS — by setting the env var:
    //
    //     RAHGOZAR_RENDERER=wgpu rahgozar-ui
    //
    // The launcher scripts (run.bat / run.command / run.sh) honour
    // the same variable and forward it through.
    let use_wgpu = std::env::var("RAHGOZAR_RENDERER")
        .map(|v| v.eq_ignore_ascii_case("wgpu"))
        .unwrap_or(false);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([WIN_WIDTH, WIN_HEIGHT])
            .with_min_inner_size([420.0, 400.0])
            .with_title(format!("rahgozar {}", VERSION)),
        renderer: if use_wgpu {
            eframe::Renderer::Wgpu
        } else {
            eframe::Renderer::Glow
        },
        ..Default::default()
    };

    // Load the profile store. Three outcomes:
    //   - Ok → load_ok = true.
    //   - CorruptOnDisk + backup-rename succeeded → load_ok = true
    //     (the corrupt file is now backed up; we own the live file).
    //   - CorruptOnDisk + backup-rename FAILED → load_ok = false. We
    //     start empty in memory but refuse to save, because saving
    //     would clobber the corrupt-but-recoverable bytes on disk
    //     that may be the user's only copy.
    //   - I/O read error (permission denied, locked file, etc.) →
    //     load_ok = false. The file probably still exists on disk;
    //     overwriting it with an empty store would risk losing the
    //     user's data. Surface a toast and refuse writes until the
    //     next restart.
    let (profiles, profiles_load_ok, profile_toast) = match ProfilesFile::load() {
        Ok(pf) => (pf, true, None),
        Err(rahgozar::profiles::ProfileError::CorruptOnDisk(msg)) => {
            let path = profiles::profiles_path();
            let backup = pick_corrupt_backup_path(&path);
            let renamed = std::fs::rename(&path, &backup);
            let (load_ok, detail) = match renamed {
                Ok(()) => (
                    true,
                    format!(
                        "profiles.json was unreadable ({}); backed up to {}",
                        msg,
                        backup.display()
                    ),
                ),
                Err(re) => (
                    false,
                    format!(
                        "profiles.json was unreadable ({}) and backup also failed ({}). \
                         Profile saves are disabled until you move the file aside manually.",
                        msg, re
                    ),
                ),
            };
            tracing::warn!("profiles: {}", detail);
            (ProfilesFile::default(), load_ok, Some(detail))
        }
        Err(e) => {
            // Read / I/O / permissions failure on a file that exists.
            // Treat the same as CorruptOnDisk-but-can't-back-up: the
            // bytes on disk are still there, we just can't read them
            // right now, and writing an empty store would clobber
            // them. Refuse writes until the user investigates.
            let detail = format!(
                "profiles.json could not be loaded ({}). Profile saves are \
                 disabled to avoid clobbering the on-disk file.",
                e
            );
            tracing::warn!("profiles: {}", detail);
            (ProfilesFile::default(), false, Some(detail))
        }
    };
    // If we already had a config-load toast, prefer that; otherwise
    // surface the profile-load detail on first paint.
    let initial_toast = initial_toast.or_else(|| profile_toast.map(|m| (m, Instant::now())));

    eframe::run_native(
        "rahgozar",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App {
                shared,
                cmd_tx,
                form,
                last_poll: Instant::now(),
                toast: initial_toast,
                profiles,
                profiles_load_ok,
                save_as_dialog: None,
                manage_dialog: None,
            }))
        }),
    )
}

/// Pick a non-colliding "json.corrupt-…" backup filename for a path
/// we couldn't parse at startup. Uses unix nanoseconds for entropy
/// AND a create-new probe loop, so a quick restart (or repeated
/// corrupt loads in the same nanosecond, hypothetically) doesn't
/// silently overwrite a previous backup that may itself be the
/// user's only copy of recoverable data.
fn pick_corrupt_backup_path(original: &std::path::Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut candidate = original.with_extension(format!("json.corrupt-{}", nanos));
    // If we somehow land on an existing backup, append a counter
    // until we find a fresh name. Cap iterations as a sanity belt;
    // hitting the cap would mean something pathological with the
    // filesystem, in which case we fall back to the last candidate.
    let mut n = 1u32;
    while candidate.exists() && n < 1000 {
        candidate = original.with_extension(format!("json.corrupt-{}-{}", nanos, n));
        n += 1;
    }
    candidate
}

#[derive(Default)]
struct Shared {
    state: Mutex<UiState>,
}

#[derive(Default)]
struct UiState {
    running: bool,
    started_at: Option<Instant>,
    last_stats: Option<rahgozar::domain_fronter::StatsSnapshot>,
    last_per_site: Vec<(String, rahgozar::domain_fronter::HostStat)>,
    log: VecDeque<String>,
    /// Result + timestamp for transient status banners (auto-hide after 10s).
    ca_trusted: Option<bool>,
    ca_trusted_at: Option<Instant>,
    last_test_ok: Option<bool>,
    last_test_msg: String,
    last_test_msg_at: Option<Instant>,
    /// Per-SNI probe results, populated by Cmd::TestSni / TestAllSni.
    sni_probe: HashMap<String, SniProbeState>,
    /// Most-recent "discover CDN front" result, populated by
    /// Cmd::DiscoverFront. Cleared when the user dismisses the
    /// results panel or starts a new discovery. None = idle,
    /// Some(InFlight) = probing in background, Some(Done(...)) =
    /// resolved + probed and ready for the user to Add.
    discover_state: Option<DiscoverState>,
    /// Most recent result of the Check-for-updates button (issue #15).
    /// `None` = never checked this session. `Some(InFlight)` during the
    /// probe, then the resolved outcome.
    last_update_check: Option<UpdateProbeState>,
    last_update_check_at: Option<Instant>,
    /// Set while a download of a release asset is in flight. `None` when
    /// idle or after a completed download has been acknowledged.
    download_in_progress: bool,
    /// Set while an install-or-remove cert op is in flight. Install and
    /// Remove share this single flag so they can't race each other:
    /// clicking Install → Remove back-to-back would otherwise leave the
    /// final trust/file state dependent on thread scheduling — an
    /// in-flight install could re-trust the CA after Remove had already
    /// deleted it, or vice versa. Both UI buttons disable while this
    /// is set, and both handlers gate-and-flip it.
    cert_op_in_progress: bool,
    /// Set synchronously when the Start button is clicked (UI-thread)
    /// and re-affirmed by the bg-thread when it dequeues `Cmd::Start`.
    /// Cleared synchronously on `Cmd::Stop`, on build-failure inside
    /// the bg-thread, and at the end of the spawned `server.run()`
    /// task. Broader than `running` (which is set inside the spawned
    /// task on entry, before `server.run()` binds — so there's a
    /// short scheduling-latency window where `proxy_active = true`
    /// and `running = false`). Used to block `Remove CA` and to gate
    /// live mode-switch dispatch during that startup window so a
    /// queued `Cmd::RemoveCa` can't delete `ca/` mid-load and a mode
    /// change in the same gap can't be silently dropped.
    proxy_active: bool,
    /// One-line status of the most recent download (Ok(path) or Err(msg)).
    last_download: Option<Result<std::path::PathBuf, String>>,
    last_download_at: Option<Instant>,
    /// Set while a stage-update (download + verify + extract + stage) is
    /// in flight. Used to disable the Install button so a double-click
    /// doesn't kick off two parallel downloads.
    install_in_progress: bool,
    /// Result of the most recent staging:
    ///   - Ok(StagedUpdate)  → ready, show "Restart now" button
    ///   - Err(msg)          → show the error inline
    /// Cleared on next install attempt.
    last_install: Option<Result<rahgozar::update_apply::StagedUpdate, String>>,
    last_install_at: Option<Instant>,
    /// Signal from a failed live mode switch: `(revert_to_mode_str, err_msg)`.
    /// The UI's `update()` reads this once per frame, reverts `form.mode`
    /// to the snapshot, shows a toast with the error, and clears the field.
    /// Without this round-trip the form drifts from the runtime — the
    /// dropdown would display the rejected mode while the proxy is still
    /// happily serving the previous one.
    mode_switch_revert: Option<(String, String)>,
}

#[derive(Clone, Debug)]
enum UpdateProbeState {
    InFlight,
    Done(rahgozar::update_check::UpdateCheck),
}

#[derive(Clone, Debug)]
enum SniProbeState {
    InFlight,
    Ok(u32),
    Failed(String),
}

/// State of the most-recent "Discover CDN front by hostname" run.
/// Held in `UiState::discover_state` so the result panel survives
/// repaint cycles. Cleared by the Dismiss button or by starting a
/// new discovery.
#[derive(Clone, Debug)]
enum DiscoverState {
    /// Probe is running. The hostname is kept so the UI can show
    /// "Discovering <hostname>…" without having to remember the
    /// input on its own.
    InFlight { hostname: String },
    /// DNS resolved and at least one IP was probed. May or may
    /// not have any *successful* probes — the panel renders the
    /// list either way so the user sees what failed and why.
    Done(DiscoveredFront),
    /// Top-level failure: bad input, DNS timeout, etc. Not a per-IP
    /// probe failure — those land inside `Done` with `error: Some`.
    Error { hostname: String, message: String },
}

enum Cmd {
    Start(Config),
    Stop,
    /// Hot-swap the running proxy into a new mode (and pick up any other
    /// related config changes in the snapshot) without dropping connections
    /// or rebinding listeners. Ignored when no proxy is running. See
    /// `RuntimeState::switch_mode` for what does and doesn't get applied.
    SwitchMode(Config),
    Test(Config),
    InstallCa,
    RemoveCa,
    CheckCaTrusted,
    PollStats,
    /// Probe a single SNI against the given google_ip. Result is written
    /// into UiState::sni_probe keyed by the SNI string.
    TestSni {
        google_ip: String,
        sni: String,
    },
    /// Probe a batch of SNI names. Results appear in UiState::sni_probe one
    /// by one as each probe finishes.
    TestAllSni {
        google_ip: String,
        snis: Vec<String>,
    },
    /// Hit github.com + the Releases API and compare the running version
    /// to the latest tag. Result is written to UiState::last_update_check.
    /// `route` controls whether the request goes direct or is tunnelled
    /// through our local HTTP proxy (useful when the user's ISP IP has
    /// exhausted GitHub's unauthenticated rate limit).
    CheckUpdate {
        route: rahgozar::update_check::Route,
    },
    /// Download a release asset to ~/Downloads. Fires when the user clicks
    /// the "Download update" button after a successful CheckUpdate surfaces
    /// an UpdateAvailable with a matching platform asset.
    DownloadUpdate {
        route: rahgozar::update_check::Route,
        url: String,
        name: String,
    },
    /// Resolve `hostname` to all of its A/AAAA records and TLS-probe
    /// each one with SNI=hostname, so the user can drop the best IP
    /// into a new `FrontingGroup` without hand-running `dig` and
    /// `openssl s_client`. See `rahgozar::cdn_discover`.
    DiscoverFront {
        hostname: String,
    },
    /// Download + verify + extract + stage a release asset, ready to swap
    /// in on next launch (or via restart_to_apply). Fires when the user
    /// clicks the "Install update" button after a successful CheckUpdate
    /// surfaces an UpdateAvailable with a matching platform asset.
    InstallUpdate {
        route: rahgozar::update_check::Route,
        url: String,
        name: String,
    },
    /// Perform the binary swap and re-launch. Fires when the user clicks
    /// "Restart now" after staging completed.
    RestartToApply,
}

struct App {
    shared: Arc<Shared>,
    cmd_tx: Sender<Cmd>,
    form: FormState,
    last_poll: Instant,
    toast: Option<(String, Instant)>,
    /// Profile bookkeeping for the multi-profile selector. Loaded from
    /// `profiles.json` at startup and kept in memory; mutations write
    /// through to disk immediately. See `src/profiles.rs`.
    profiles: ProfilesFile,
    /// True iff `profiles.json` either didn't exist OR loaded cleanly
    /// at startup. False means the file was corrupt AND the backup
    /// rename failed (so the corrupt file is still on disk). In that
    /// state we MUST NOT save — the current empty in-memory state
    /// would clobber the corrupt-but-recoverable bytes that may be
    /// the user's only copy of their data.
    profiles_load_ok: bool,
    /// Modal state for the "Save as new profile" dialog.
    save_as_dialog: Option<SaveAsState>,
    /// Modal state for the "Manage profiles" window.
    manage_dialog: Option<ManageState>,
}

#[derive(Default)]
struct SaveAsState {
    /// Free-form name typed by the user.
    name: String,
    /// Inline error message rendered under the text field (e.g. "name
    /// already exists"). Cleared on the next keystroke.
    error: Option<String>,
}

#[derive(Default)]
struct ManageState {
    /// Per-profile rename buffer keyed by current profile name. Lazily
    /// populated when the user clicks "Rename" on a row.
    rename_buf: HashMap<String, String>,
    /// Currently-being-renamed profile name (only one at a time). `None`
    /// when no rename is in progress.
    renaming: Option<String>,
    /// Inline error message at the top of the window (rename collision,
    /// duplicate-target collision, etc.).
    error: Option<String>,
    /// Profile name pending delete confirmation. Set when the user
    /// clicks "Delete"; cleared when they confirm or cancel. While
    /// set we render an inline "Confirm delete?" row instead of the
    /// usual action buttons, so an accidental click can't blow
    /// away the user's only saved copy of a config.
    pending_delete: Option<String>,
}

#[derive(Clone)]
struct FormState {
    /// `"apps_script"` (default), `"direct"`, or `"full"`. Controls
    /// whether the Apps Script relay is wired up at all. In `direct`,
    /// the form tolerates an empty script_id / auth_key.
    /// On load we normalize the legacy `"google_only"` string to
    /// `"direct"` so the next save rewrites the on-disk config.
    mode: String,
    script_id: String,
    auth_key: String,
    google_ip: String,
    front_domain: String,
    listen_host: String,
    listen_port: String,
    socks5_port: String,
    log_level: String,
    verify_ssl: bool,
    upstream_socks5: String,
    parallel_relay: u8,
    show_auth_key: bool,
    /// SNI rotation pool entries. Each item has a sni name + a checkbox
    /// flag indicating whether it's in the active rotation.
    sni_pool: Vec<SniRow>,
    /// Text field buffer for the "+ add custom SNI" input at the bottom of
    /// the SNI editor window.
    sni_custom_input: String,
    /// Text field buffer for the "Discover CDN front by hostname" input in
    /// the Fronting-groups editor. Ephemeral UI state — never persisted to
    /// config.json; the actual discovered group lives in `fronting_groups`.
    discover_hostname_input: String,
    /// Per-group raw text buffers for the "domains" field, indexed
    /// in lockstep with `fronting_groups` (same length, same order).
    /// Why a Vec instead of a HashMap keyed by group name: duplicate
    /// `name` values are legal in `fronting_groups` (the proxy
    /// startup logs a warning but otherwise honours them — see
    /// `proxy_server.rs::ProxyServer::new`), so name-keyed buffers
    /// would collide and silently overwrite one group's domains
    /// with another's. Position-keyed buffers don't have that bug.
    /// Add/Remove flows must touch both Vecs together to keep them
    /// in sync; helper methods enforce that.
    ///
    /// Re-joining `g.domains` every frame would strip the user's
    /// in-flight `,` / `\n` separators and break manual typing
    /// (issue: "typing a comma collapses into invalid text"), so
    /// the buffer is the source of truth while editing and we parse
    /// only at save time inside `to_config()`.
    domain_buffers: Vec<String>,
    /// Whether the floating SNI editor window is open.
    sni_editor_open: bool,
    /// Whether the Recent log panel is shown. User toggles with a checkbox.
    show_log: bool,
    fetch_ips_from_api: bool,
    max_ips_to_scan: usize,
    scan_batch_size: usize,
    google_ip_validation: bool,
    normalize_x_graphql: bool,
    youtube_via_relay: bool,
    /// See `config::Config::relay_url_patterns` for semantics + defaults.
    /// No UI control; round-tripped so a hand-edited list survives Save.
    relay_url_patterns: Vec<String>,
    /// See `config::Config::sabr_strip` for trade-off + when to flip.
    /// No UI control; round-tripped so a hand-edited `false` survives Save.
    sabr_strip: bool,
    passthrough_hosts: Vec<String>,
    block_quic: bool,
    /// Round-tripped from config.json and exposed beside QUIC blocking.
    /// Default true to push WebRTC apps toward TCP TURN instead of slow
    /// UDP ICE retries.
    block_stun: bool,
    /// Round-tripped from config.json. Not exposed as a UI control —
    /// users edit `disable_padding` directly when needed (Issue #391).
    /// Default false (padding active).
    disable_padding: bool,
    /// Round-tripped from config.json. Not exposed as a UI control —
    /// users edit `force_http1` directly when needed. Default false
    /// (HTTP/2 multiplexing on the relay leg active).
    force_http1: bool,
    /// Round-tripped from config.json. Not exposed in the UI form yet —
    /// the bypass-DoH default is the right answer for almost everyone
    /// (DoH already encrypts, the tunnel was just adding latency), so
    /// this is a config-only opt-out. See config.rs `tunnel_doh`.
    tunnel_doh: bool,
    /// User-supplied DoH hostnames added to the built-in default list,
    /// round-tripped from config.json. See config.rs `bypass_doh_hosts`.
    bypass_doh_hosts: Vec<String>,
    /// PR #763: when true, immediately reject browser DoH CONNECTs so the
    /// browser falls back to system DNS (tun2proxy virtual DNS — instant).
    /// Round-tripped from config.json. Desktop UI doesn't expose a toggle
    /// yet — Android does. See config.rs `block_doh`.
    block_doh: bool,
    /// Multi-edge fronting groups. Round-tripped from config.json so
    /// the UI's Save doesn't drop the user's hand-edited groups —
    /// there is no UI editor for these yet, only file-edited config.
    /// See config.rs `fronting_groups`.
    fronting_groups: Vec<FrontingGroup>,
    /// Auto-blacklist tuning + per-batch timeout. Config-only knobs (no UI
    /// fields yet — power-user file edit). Round-tripped through FormState
    /// so Save preserves the user's hand-edited values. See config.rs
    /// `auto_blacklist_*` and `request_timeout_secs`.
    auto_blacklist_strikes: u32,
    auto_blacklist_window_secs: u64,
    auto_blacklist_cooldown_secs: u64,
    request_timeout_secs: u64,
    /// Apps Script error-page locale (`?hl=<lang>` + paired
    /// `Accept-Language`). Config-only round-trip — power-user file
    /// edit, no UI editor yet. Default `"en"` keeps the envelope
    /// classifier matching English Apps Script error strings.
    apps_script_lang: String,
    /// Optional second-hop exit node for CF-anti-bot bypass (chatgpt.com /
    /// claude.ai / grok.com / x.com). Config-only — no UI editor yet.
    /// See `assets/exit_node/` for the generic exit-node handler.
    exit_node: rahgozar::config::ExitNodeConfig,
    /// TLS-fragmentation Direct Mode for Google-owned domains.
    /// Config-only — no UI editor yet. Round-tripped through FormState
    /// so Save preserves hand-edited `direct_mode` blocks in
    /// `config.json`.
    direct_mode: rahgozar::config::DirectModeConfig,
    // (No raw `extras` field on FormState anymore — the
    // `custom_params_buffer` below is the editor's source of truth,
    // and [`to_config`] rebuilds `Config::extras` from it on save via
    // [`build_extras_from_buffer`]. Load seeds the buffer via
    // [`extras_to_buffer`], so round-trip semantics for unknown /
    // future config.json keys are preserved.)

    // ── Carried-but-not-exposed modeled fields ──────────────────────
    // These are real fields in `Config` (so serde-deserialised at
    // load), but the desktop UI doesn't surface editors for them yet.
    // We round-trip them through FormState so Save-config and
    // Save-as-profile don't silently drop user-edited values from
    // hand-edited config.json files. ConfigWire was previously
    // missing serialize entries for some of these, which made the
    // "round-trip" comments aspirational rather than true.
    /// Hostname → IP override map. Hand-edited config field; preserve
    /// across saves so a user-defined override survives a UI save.
    hosts_passthrough: std::collections::HashMap<String, String>,
    /// Legacy batch toggle (rarely set today). Pure passthrough.
    enable_batching: bool,
    /// PR #448 — adaptive coalesce window. Android exposes sliders;
    /// desktop currently passes the compiled defaults (0/0) but a
    /// user who hand-edits config.json to non-zero values should
    /// keep them across UI saves.
    coalesce_step_ms: u16,
    coalesce_max_ms: u16,
    /// Per-level colours for the Recent log panel. Stored as `#RRGGBB`
    /// strings so they round-trip through the config file verbatim;
    /// parsed to `egui::Color32` at render time via [`parse_hex_color`].
    /// Empty string = compiled default (`DEFAULT_LOG_COLOR_*` in
    /// `config.rs`). See feature #863.
    log_color_info: String,
    log_color_warn: String,
    log_color_error: String,
    /// Whether the colour-picker expander above the Recent log panel is
    /// open. Pure UI state; never persisted.
    log_color_editor_open: bool,

    /// Live editor buffer for the "Custom parameters" key/value table.
    /// Each entry is `(key, raw_json_text)`. Seeded from [`Config::extras`]
    /// at load time and parsed back into `extras` on Save via
    /// [`build_extras_from_buffer`]. Editor is the source of truth while
    /// the form is open — `extras` on `FormState` is rebuilt from the
    /// buffer in `to_config()`, so any user edits (incl. removed rows)
    /// take effect on the next Save. Keys not present in the buffer
    /// are dropped, matching the upstream feature request that the UI
    /// be the authoritative editor for these fields.
    custom_params_buffer: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
struct SniRow {
    name: String,
    enabled: bool,
}

fn load_form() -> (FormState, Option<String>) {
    // Try the user-data config first, then the cwd fallback. Report WHY load
    // fails so the user isn't silently shown a blank form (issue: user reports
    // 'settings saved to file but not loaded back'). Without this signal the
    // failure is invisible — `.ok()` swallows it and the form looks fresh.
    let path = data_dir::config_path();
    let cwd = PathBuf::from("config.json");

    let (existing, load_err): (Option<Config>, Option<String>) = if path.exists() {
        tracing::info!("config: attempting load from {}", path.display());
        match Config::load(&path) {
            Ok(c) => {
                tracing::info!("config: loaded OK from {}", path.display());
                (Some(c), None)
            }
            Err(e) => {
                let msg = format!("Config at {} failed to load: {}", path.display(), e);
                tracing::warn!("{}", msg);
                (None, Some(msg))
            }
        }
    } else if cwd.exists() {
        tracing::info!("config: attempting fallback load from {}", cwd.display());
        match Config::load(&cwd) {
            Ok(c) => (Some(c), None),
            Err(e) => {
                let msg = format!("Config at {} failed to load: {}", cwd.display(), e);
                tracing::warn!("{}", msg);
                (None, Some(msg))
            }
        }
    } else {
        tracing::info!(
            "config: no config found at {} — starting with defaults",
            path.display()
        );
        (None, None)
    };
    let form = if let Some(c) = existing {
        let sid = match &c.script_id {
            Some(ScriptId::One(s)) => s.clone(),
            Some(ScriptId::Many(v)) => v.join("\n"),
            None => match &c.script_ids {
                Some(ScriptId::One(s)) => s.clone(),
                Some(ScriptId::Many(v)) => v.join("\n"),
                None => String::new(),
            },
        };
        let sni_pool = sni_pool_for_form(c.sni_hosts.as_deref(), &c.front_domain);
        // Normalize the legacy `google_only` mode string on load. The
        // backend's `mode_kind()` accepts the alias forever, but storing
        // it as `direct` in the form means the next Save rewrites the
        // on-disk config to the new name — one-way migration, no warn
        // on every startup.
        let mode_normalized = if c.mode == "google_only" {
            "direct".to_string()
        } else {
            c.mode.clone()
        };
        FormState {
            mode: mode_normalized,
            script_id: sid,
            auth_key: c.auth_key,
            google_ip: c.google_ip,
            front_domain: c.front_domain,
            listen_host: c.listen_host,
            listen_port: c.listen_port.to_string(),
            socks5_port: c.socks5_port.map(|p| p.to_string()).unwrap_or_default(),
            log_level: c.log_level,
            verify_ssl: c.verify_ssl,
            upstream_socks5: c.upstream_socks5.unwrap_or_default(),
            parallel_relay: c.parallel_relay,
            show_auth_key: false,
            sni_pool,
            sni_custom_input: String::new(),
            discover_hostname_input: String::new(),
            // Seed buffers from the loaded groups (newline-joined, since
            // that's the on-screen separator the editor uses). Length
            // must match `fronting_groups` length so position indexing
            // stays valid through edits.
            domain_buffers: c
                .fronting_groups
                .iter()
                .map(|g| g.domains.join("\n"))
                .collect(),
            sni_editor_open: false,
            show_log: true,
            fetch_ips_from_api: c.fetch_ips_from_api,
            max_ips_to_scan: c.max_ips_to_scan,
            google_ip_validation: c.google_ip_validation,
            scan_batch_size: c.scan_batch_size,
            normalize_x_graphql: c.normalize_x_graphql,
            youtube_via_relay: c.youtube_via_relay,
            relay_url_patterns: c.relay_url_patterns.clone(),
            sabr_strip: c.sabr_strip,
            passthrough_hosts: c.passthrough_hosts.clone(),
            block_quic: c.block_quic,
            block_stun: c.block_stun,
            disable_padding: c.disable_padding,
            force_http1: c.force_http1,
            tunnel_doh: c.tunnel_doh,
            bypass_doh_hosts: c.bypass_doh_hosts.clone(),
            block_doh: c.block_doh,
            fronting_groups: c.fronting_groups.clone(),
            auto_blacklist_strikes: c.auto_blacklist_strikes,
            auto_blacklist_window_secs: c.auto_blacklist_window_secs,
            auto_blacklist_cooldown_secs: c.auto_blacklist_cooldown_secs,
            request_timeout_secs: c.request_timeout_secs,
            apps_script_lang: c.apps_script_lang.clone(),
            exit_node: c.exit_node.clone(),
            direct_mode: c.direct_mode.clone(),
            // The editor buffer is the only persistent representation
            // of `Config::extras` on the UI side — there's no longer
            // a separate `FormState.extras` field. `to_config()` builds
            // a fresh `extras` map from this buffer on each save via
            // `build_extras_from_buffer`, so any UI edits (adds /
            // removes / value changes) take effect on next save and
            // hand-edited extras from config.json round-trip cleanly.
            custom_params_buffer: extras_to_buffer(&c.extras),
            hosts_passthrough: c.hosts.clone(),
            enable_batching: c.enable_batching,
            coalesce_step_ms: c.coalesce_step_ms,
            coalesce_max_ms: c.coalesce_max_ms,
            // Normalize on load — a malformed hex in config.json (typo,
            // hand-edit, or an old build that wrote `red` instead of
            // `#dc6e6e`) gets replaced with the compiled default so the
            // form text field shows the same colour the renderer is
            // actually using. Saving back then writes the normalized
            // value, healing the file.
            log_color_info: normalize_log_color(
                &c.log_color_info,
                rahgozar::config::DEFAULT_LOG_COLOR_INFO,
            ),
            log_color_warn: normalize_log_color(
                &c.log_color_warn,
                rahgozar::config::DEFAULT_LOG_COLOR_WARN,
            ),
            log_color_error: normalize_log_color(
                &c.log_color_error,
                rahgozar::config::DEFAULT_LOG_COLOR_ERROR,
            ),
            log_color_editor_open: false,
        }
    } else {
        FormState::fresh_install_defaults()
    };
    (form, load_err)
}

impl FormState {
    /// Build a FormState with the same hardcoded defaults shown to a
    /// first-time user (no `config.json` on disk yet). Extracted from
    /// the fresh-install branch of [`load_form`] so unit tests can
    /// construct a deterministic FormState without touching the
    /// user-data dir or CWD `config.json` — a test that calls
    /// `load_form()` would otherwise pick up a developer's real
    /// config and lose hermeticity.
    fn fresh_install_defaults() -> Self {
        FormState {
            mode: "apps_script".into(),
            script_id: String::new(),
            auth_key: String::new(),
            google_ip: "216.239.38.120".into(),
            front_domain: "www.google.com".into(),
            listen_host: "127.0.0.1".into(),
            listen_port: "8085".into(),
            socks5_port: "8086".into(),
            log_level: "info".into(),
            verify_ssl: true,
            upstream_socks5: String::new(),
            parallel_relay: 0,
            show_auth_key: false,
            sni_pool: sni_pool_for_form(None, "www.google.com"),
            sni_custom_input: String::new(),
            discover_hostname_input: String::new(),
            domain_buffers: Vec::new(),
            sni_editor_open: false,
            show_log: true,
            fetch_ips_from_api: false,
            max_ips_to_scan: 100,
            google_ip_validation: true,
            scan_batch_size: 500,
            normalize_x_graphql: false,
            youtube_via_relay: false,
            relay_url_patterns: Vec::new(),
            sabr_strip: false,
            passthrough_hosts: Vec::new(),
            block_quic: true,
            block_stun: false,
            disable_padding: false,
            force_http1: false,
            tunnel_doh: true,
            bypass_doh_hosts: Vec::new(),
            block_doh: true,
            fronting_groups: Vec::new(),
            // Defaults match `default_auto_blacklist_*` and
            // `default_request_timeout_secs` in src/config.rs.
            auto_blacklist_strikes: 3,
            auto_blacklist_window_secs: 30,
            auto_blacklist_cooldown_secs: 120,
            request_timeout_secs: 30,
            apps_script_lang: "en".into(),
            exit_node: rahgozar::config::ExitNodeConfig::default(),
            direct_mode: rahgozar::config::DirectModeConfig::default(),
            custom_params_buffer: Vec::new(),
            hosts_passthrough: std::collections::HashMap::new(),
            enable_batching: false,
            coalesce_step_ms: 0,
            coalesce_max_ms: 0,
            log_color_info: rahgozar::config::DEFAULT_LOG_COLOR_INFO.into(),
            log_color_warn: rahgozar::config::DEFAULT_LOG_COLOR_WARN.into(),
            log_color_error: rahgozar::config::DEFAULT_LOG_COLOR_ERROR.into(),
            log_color_editor_open: false,
        }
    }
}

/// Build the initial `sni_pool` list shown in the editor.
///
/// If the user has explicit `sni_hosts` configured, we show exactly those
/// rows (all enabled). Otherwise we show the default Google pool plus any
/// missing entries, all enabled, with the user's `front_domain` first.
fn sni_pool_for_form(user: Option<&[String]>, front_domain: &str) -> Vec<SniRow> {
    let user_clean: Vec<String> = user
        .unwrap_or(&[])
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !user_clean.is_empty() {
        return user_clean
            .into_iter()
            .map(|name| SniRow {
                name,
                enabled: true,
            })
            .collect();
    }
    // Default: primary + the other Google-edge subdomains, primary first,
    // all enabled.
    let primary = front_domain.trim().to_string();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    if !primary.is_empty() {
        seen.insert(primary.clone());
        out.push(SniRow {
            name: primary,
            enabled: true,
        });
    }
    for s in DEFAULT_GOOGLE_SNI_POOL {
        if seen.insert(s.to_string()) {
            out.push(SniRow {
                name: (*s).to_string(),
                enabled: true,
            });
        }
    }
    out
}

/// Wire-level keys that `Config` already models via named fields. The
/// custom-parameters editor must refuse to add a row whose key appears
/// here — `#[serde(flatten)]` would otherwise emit two top-level entries
/// for the same name during save, and the loader's behaviour with
/// duplicate keys is whatever `serde_json::Map` (last-write-wins) does,
/// which lets a custom-parameter row silently override the form's value
/// for the matching modeled field. Worse: a user who types `mode` as a
/// custom key and a non-matching string as the value can produce a
/// config file that `Config::validate()` then rejects, leaving the
/// proxy unable to start. Pinned by [`modeled_keys_list_matches_wire`]
/// against the live `ConfigWire` keyset so future Config additions
/// must be added here too.
const MODELED_CONFIG_KEYS: &[&str] = &[
    "mode",
    "google_ip",
    "front_domain",
    "script_id",
    "script_ids",
    "auth_key",
    "listen_host",
    "listen_port",
    "socks5_port",
    "log_level",
    "log_color_info",
    "log_color_warn",
    "log_color_error",
    "verify_ssl",
    "hosts",
    "enable_batching",
    "upstream_socks5",
    "parallel_relay",
    "coalesce_step_ms",
    "coalesce_max_ms",
    "sni_hosts",
    "fetch_ips_from_api",
    "max_ips_to_scan",
    "scan_batch_size",
    "google_ip_validation",
    "normalize_x_graphql",
    "youtube_via_relay",
    "relay_url_patterns",
    "sabr_strip",
    "passthrough_hosts",
    "block_quic",
    "block_stun",
    "disable_padding",
    "force_http1",
    "tunnel_doh",
    "bypass_doh_hosts",
    "block_doh",
    "fronting_groups",
    "auto_blacklist_strikes",
    "auto_blacklist_window_secs",
    "auto_blacklist_cooldown_secs",
    "request_timeout_secs",
    "apps_script_lang",
    "exit_node",
    "direct_mode",
];

/// True when `key` collides with a modeled Config field. Trimmed,
/// case-sensitive — JSON object keys are case-sensitive and so is
/// serde's flatten matcher, so we match the same.
fn is_modeled_config_key(key: &str) -> bool {
    let trimmed = key.trim();
    MODELED_CONFIG_KEYS.iter().any(|k| *k == trimmed)
}

impl FormState {
    fn to_config(&self) -> Result<Config, String> {
        // `direct` and the legacy `google_only` alias both run without
        // an Apps Script relay, so neither requires a script_id.
        let is_direct = self.mode == "direct" || self.mode == "google_only";
        if !is_direct {
            if self.script_id.trim().is_empty() {
                return Err("Apps Script ID is required".into());
            }
            if self.auth_key.trim().is_empty() {
                return Err("Auth key is required".into());
            }
        }
        let listen_port: u16 = self
            .listen_port
            .parse()
            .map_err(|_| "HTTP port must be a number".to_string())?;
        let socks5_port: Option<u16> = if self.socks5_port.trim().is_empty() {
            None
        } else {
            Some(
                self.socks5_port
                    .parse()
                    .map_err(|_| "SOCKS5 port must be a number".to_string())?,
            )
        };
        if socks5_port == Some(listen_port) {
            return Err("HTTP and SOCKS5 ports must be different".into());
        }
        // Refuse to save when a Custom-parameters row would shadow a
        // built-in form field. Caught BEFORE we build the `Config` so
        // the error message can point at the offending key by name;
        // catching it later would lose the row context.
        if let Some((k, _)) = self
            .custom_params_buffer
            .iter()
            .find(|(k, _)| is_modeled_config_key(k))
        {
            return Err(format!(
                "Custom parameter '{}' collides with a built-in field. \
                 Remove the custom row or rename it — the form above already \
                 controls this value.",
                k.trim()
            ));
        }
        let ids: Vec<String> = self
            .script_id
            .split(|c: char| c == '\n' || c == ',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let script_id = if ids.is_empty() {
            None
        } else if ids.len() == 1 {
            Some(ScriptId::One(ids[0].clone()))
        } else {
            Some(ScriptId::Many(ids))
        };
        Ok(Config {
            mode: self.mode.clone(),
            google_ip: self.google_ip.trim().to_string(),
            front_domain: self.front_domain.trim().to_string(),
            script_id,
            script_ids: None,
            auth_key: self.auth_key.clone(),
            listen_host: self.listen_host.trim().to_string(),
            listen_port,
            socks5_port,
            log_level: self.log_level.trim().to_string(),
            // Normalize on save too: if the user typed an invalid hex
            // in the editor (or never opened the editor and the loaded
            // value was already bad), write the compiled default
            // instead of a string the renderer will silently reject.
            // This keeps the on-disk config consistent with what the
            // log panel actually shows.
            log_color_info: normalize_log_color(
                &self.log_color_info,
                rahgozar::config::DEFAULT_LOG_COLOR_INFO,
            ),
            log_color_warn: normalize_log_color(
                &self.log_color_warn,
                rahgozar::config::DEFAULT_LOG_COLOR_WARN,
            ),
            log_color_error: normalize_log_color(
                &self.log_color_error,
                rahgozar::config::DEFAULT_LOG_COLOR_ERROR,
            ),
            verify_ssl: self.verify_ssl,
            // Round-tripped fields — preserve whatever was on disk
            // (or the user's hand-edits) instead of wiping to defaults.
            hosts: self.hosts_passthrough.clone(),
            enable_batching: self.enable_batching,
            upstream_socks5: {
                let v = self.upstream_socks5.trim();
                if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                }
            },
            parallel_relay: self.parallel_relay,
            sni_hosts: {
                let active: Vec<String> = self
                    .sni_pool
                    .iter()
                    .filter(|r| r.enabled)
                    .map(|r| r.name.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                // None = "use auto-expansion default", Some(list) = explicit.
                // If the user's pool is empty/all-off we still save as None so
                // the backend falls back to sensible defaults instead of dying
                // on an empty pool.
                if active.is_empty() {
                    None
                } else {
                    Some(active)
                }
            },
            fetch_ips_from_api: self.fetch_ips_from_api,
            max_ips_to_scan: self.max_ips_to_scan,
            google_ip_validation: self.google_ip_validation,
            scan_batch_size: self.scan_batch_size,
            normalize_x_graphql: self.normalize_x_graphql,
            // UI form doesn't expose youtube_via_relay yet — it's a
            // config-only flag for now. Passed through from the loaded
            // config if set, otherwise defaults to false.
            youtube_via_relay: self.youtube_via_relay,
            // Config-only round-trips. Source of truth for both fields
            // is `config::Config` (defaults, gating, trade-offs).
            relay_url_patterns: self.relay_url_patterns.clone(),
            sabr_strip: self.sabr_strip,
            // Similarly config-only for now; round-trips through the
            // file so the UI doesn't drop the user's entries on save.
            passthrough_hosts: self.passthrough_hosts.clone(),
            block_quic: self.block_quic,
            block_stun: self.block_stun,
            // Issue #391: disable_padding is config-only for now.
            // Round-trip preserves the user's choice.
            disable_padding: self.disable_padding,
            // HTTP/2 multiplexing kill switch. Config-only for now;
            // round-trip preserves the user's choice across Save.
            force_http1: self.force_http1,
            // DoH bypass is enabled-by-default with `tunnel_doh = false`.
            // Round-trip the user's choice (and any extra hostnames they
            // added) so save doesn't drop them.
            tunnel_doh: self.tunnel_doh,
            bypass_doh_hosts: self.bypass_doh_hosts.clone(),
            // PR #763: block_doh defaults to true (rejects browser DoH so
            // tun2proxy's virtual DNS handles name lookups, saving the
            // ~1.5s tunnel round-trip per DNS query). Desktop UI doesn't
            // expose a toggle yet (Android does), so this is a config-only
            // round-trip — we keep whatever the user has in config.json.
            block_doh: self.block_doh,
            // Multi-edge fronting groups. Drop draft groups (no domains
            // yet, or only blank entries) at save time — `Config::validate()`
            // in src/config.rs rejects empty `domains` lists with a hard
            // error, so passing them through would make the proxy refuse
            // to start. The editor keeps them in the live form so the user
            // can fill them in; on save we filter.
            //
            // Source-of-truth for the domains list: the position-indexed
            // `domain_buffers` Vec, parsed by
            // `build_fronting_groups_from_editor`. The editor seeds the
            // buffer from `g.domains.join("\n")` so a loaded-but-
            // untouched group round-trips identically. Empty-domain
            // groups are dropped here so `Config::validate()` doesn't
            // refuse the proxy on next start.
            fronting_groups: build_fronting_groups_from_editor(
                &self.fronting_groups,
                &self.domain_buffers,
            ),
            // PR #448 (Android): adaptive coalesce window. Desktop UI
            // doesn't expose sliders for these yet, so for fresh
            // installs they stay at the compiled defaults (0/0 → the
            // crate's built-in 10ms / 1000ms). But if a user hand-edits
            // config.json to set non-zero values, we round-trip them
            // through FormState rather than wiping on every UI save.
            coalesce_step_ms: self.coalesce_step_ms,
            coalesce_max_ms: self.coalesce_max_ms,
            // Auto-blacklist + batch timeout: config-only knobs (#391,
            // #444, #430). Round-trip through FormState so Save doesn't
            // drop hand-edited values. UI editor planned alongside the
            // v1.8.x desktop UI batch.
            auto_blacklist_strikes: self.auto_blacklist_strikes,
            auto_blacklist_window_secs: self.auto_blacklist_window_secs,
            auto_blacklist_cooldown_secs: self.auto_blacklist_cooldown_secs,
            request_timeout_secs: self.request_timeout_secs,
            // Apps Script error-page locale. Config-only round-trip
            // (no UI editor); the file-edited value flows through here
            // so a hand-edited `apps_script_lang` survives Save.
            apps_script_lang: self.apps_script_lang.clone(),
            // Exit-node config (CF-anti-bot bypass for chatgpt.com / claude.ai
            // / grok.com / x.com). Round-trip through FormState — config-only
            // editing for now, UI editor planned for v1.9.x desktop UI batch.
            exit_node: self.exit_node.clone(),
            // TLS-fragmentation Direct Mode (zyrln-style). Config-only
            // for now; preserve hand-edited blocks across UI saves the
            // same way exit_node does.
            direct_mode: self.direct_mode.clone(),
            // Custom-parameters editor: the buffer is the authoritative
            // source for `extras` on save. Rows with a blank key are
            // dropped; values that don't parse as JSON are stored as
            // plain strings so the user can type `false` and get a
            // bool, or `cool string` and get a string without learning
            // JSON quoting. See [`build_extras_from_buffer`] for the
            // precise rules.
            extras: build_extras_from_buffer(&self.custom_params_buffer),
        })
    }
}

/// Snapshot the loaded `extras` map into the editor buffer used by the
/// "Custom parameters" section. Values are JSON-stringified so they
/// round-trip cleanly through [`build_extras_from_buffer`]:
///
///   - bool / number / null / array / object → JSON form (`true`, `42`,
///     `[1,2]`) so the parser on save infers the same type.
///   - string whose inner text would NOT itself JSON-parse → bare text
///     (`foo bar`), the friendly common case (no quote-typing required).
///   - string whose inner text WOULD JSON-parse to a non-string (`"true"`,
///     `"42"`, `"[1]"`) → emitted as a JSON string literal (`"true"`)
///     so re-parsing yields a `Value::String` again instead of a
///     bool/number/array. Without this, a user who stored the literal
///     three-character string `"42"` would silently see it flip to a
///     number on the next Save.
fn extras_to_buffer(
    extras: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Vec<(String, String)> {
    extras
        .iter()
        .map(|(k, v)| {
            let text = match v {
                serde_json::Value::String(s) => {
                    // Ambiguity check: if the bare inner text would be
                    // valid JSON of any kind, parsing it back from the
                    // editor would change its type. Escape via
                    // `to_string` to force a JSON string literal.
                    if serde_json::from_str::<serde_json::Value>(s).is_ok() {
                        serde_json::to_string(s).unwrap_or_else(|_| s.clone())
                    } else {
                        s.clone()
                    }
                }
                other => other.to_string(),
            };
            (k.clone(), text)
        })
        .collect()
}

/// Parse the "Custom parameters" editor buffer back into an extras map.
///
/// Rules per row:
///   - Drop rows whose key is empty / whitespace-only.
///   - Trim leading/trailing whitespace from the key before storing.
///   - For the value, first try `serde_json::from_str` so `true`, `42`,
///     `null`, `[1,2,3]`, `{"x":1}` all become typed JSON values. If
///     that fails, store the raw text as a JSON string — this lets users
///     type plain strings (`my host`) without learning to wrap them in
///     `"..."`.
///   - Later rows with the same key win, matching insertion-order
///     intuition.
///
/// **Intentional non-fidelity vs `Config::extras`**: a JSON object key
/// like `" key "` (with leading/trailing whitespace) or `""` (empty
/// string) round-trips through `Config::extras` via serde with the
/// whitespace preserved, but this editor will trim the surrounding
/// space to `"key"` (or drop the row, for `""`). The trade-off is
/// deliberate: a hand-typed editor row almost always has stray
/// whitespace the user didn't mean to commit, and an empty-key row is
/// a draft, not a configuration directive. Users who genuinely need a
/// whitespace-padded JSON key should hand-edit `config.json` outside
/// the UI; the load path's serde flatten preserves them on disk, and
/// the next UI Save would normalise away the padding on round-trip.
fn build_extras_from_buffer(
    buffer: &[(String, String)],
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in buffer {
        let key = k.trim().to_string();
        if key.is_empty() {
            continue;
        }
        let value = serde_json::from_str::<serde_json::Value>(v.trim())
            .unwrap_or_else(|_| serde_json::Value::String(v.clone()));
        out.insert(key, value);
    }
    out
}

fn save_config(cfg: &Config) -> Result<PathBuf, String> {
    let path = data_dir::config_path();
    // Round-trip through serde_json::Value so we can hand the bytes
    // to the same atomic write helper the profile paths use. The
    // helper writes to a `.tmp` and atomic-renames into place — no
    // pre-delete window where the user could lose their previous
    // config.json to a failed write.
    let value = serde_json::to_value(ConfigWire::from(cfg)).map_err(|e| e.to_string())?;
    rahgozar::profiles::write_config_json_to(&path, &value).map_err(|e| e.to_string())?;
    Ok(path)
}

#[derive(serde::Serialize)]
struct ConfigWire<'a> {
    mode: &'a str,
    google_ip: &'a str,
    front_domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_id: Option<ScriptIdWire<'a>>,
    auth_key: &'a str,
    listen_host: &'a str,
    listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    socks5_port: Option<u16>,
    log_level: &'a str,
    /// Log colours. Skipped when matching the compiled defaults so a
    /// fresh config.json doesn't grow three extra keys most users will
    /// never touch.
    #[serde(skip_serializing_if = "is_default_log_color_info")]
    log_color_info: &'a str,
    #[serde(skip_serializing_if = "is_default_log_color_warn")]
    log_color_warn: &'a str,
    #[serde(skip_serializing_if = "is_default_log_color_error")]
    log_color_error: &'a str,
    verify_ssl: bool,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    hosts: &'a std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_socks5: Option<&'a str>,
    #[serde(skip_serializing_if = "is_zero_u8")]
    parallel_relay: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni_hosts: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "is_false")]
    normalize_x_graphql: bool,
    #[serde(skip_serializing_if = "is_false")]
    youtube_via_relay: bool,
    /// See `config::Config::relay_url_patterns`. Skipped when empty so
    /// the proxy-applied default isn't echoed into config.json.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relay_url_patterns: &'a Vec<String>,
    /// See `config::Config::sabr_strip`. Default `false` (opt-in
    /// after #977); emitted only when explicitly enabled so unchanged
    /// configs stay clean.
    #[serde(skip_serializing_if = "is_false")]
    sabr_strip: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    passthrough_hosts: &'a Vec<String>,
    // IP-scan knobs. These used to be missing from the wire struct, so
    // every Save-config silently dropped them — the user would toggle
    // "fetch from API" on, save, reopen, and find it off again. Add
    // them here and keep them in sync if Config ever grows more.
    #[serde(skip_serializing_if = "is_false")]
    fetch_ips_from_api: bool,
    max_ips_to_scan: usize,
    scan_batch_size: usize,
    google_ip_validation: bool,
    /// Default false (= bypass DoH). Only emitted when explicitly true
    /// so unchanged configs stay clean.
    #[serde(skip_serializing_if = "is_false")]
    tunnel_doh: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bypass_doh_hosts: &'a Vec<String>,
    /// PR #763: default true (= browser DoH rejected, system DNS used).
    /// Skip when matching default to keep unchanged configs clean —
    /// emit only when the user has explicitly disabled the block.
    #[serde(skip_serializing_if = "is_true")]
    block_doh: bool,
    /// Default false. Emit only when the user has explicitly enabled
    /// STUN/TURN blocking. Flipped from upstream's default-true so an
    /// existing config that omits the key keeps pre-PR semantics on
    /// upgrade — see `default_block_stun` in src/config.rs.
    #[serde(skip_serializing_if = "is_false")]
    block_stun: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fronting_groups: &'a Vec<FrontingGroup>,
    /// Auto-blacklist tuning + batch timeout (#391, #444, #430). Skip
    /// serialization when matching the historical defaults so unchanged
    /// configs stay clean — only emitted when the user has explicitly
    /// tuned them.
    #[serde(skip_serializing_if = "is_default_strikes")]
    auto_blacklist_strikes: u32,
    #[serde(skip_serializing_if = "is_default_window_secs")]
    auto_blacklist_window_secs: u64,
    #[serde(skip_serializing_if = "is_default_cooldown_secs")]
    auto_blacklist_cooldown_secs: u64,
    #[serde(skip_serializing_if = "is_default_timeout_secs")]
    request_timeout_secs: u64,
    /// Apps Script error-page locale (`?hl=<lang>`). Skip when the
    /// value matches the compiled default `"en"` so configs that
    /// haven't been hand-edited stay clean.
    #[serde(skip_serializing_if = "is_default_apps_script_lang")]
    apps_script_lang: &'a str,
    /// HTTP/2 multiplexing kill switch. Default false (h2 active); only
    /// emitted on save when the user has explicitly disabled h2, so
    /// unchanged configs stay clean.
    #[serde(skip_serializing_if = "is_false")]
    force_http1: bool,
    /// Block QUIC (UDP/443). Default true. Skip when matching default
    /// so unchanged configs stay clean — emit when user has turned
    /// the block off. Previously missing from ConfigWire, which made
    /// `Save config` silently drop a user-set `block_quic: false`.
    #[serde(skip_serializing_if = "is_true")]
    block_quic: bool,
    /// Anti-fingerprint random padding kill switch. Default false
    /// (padding active). Emit when user disabled padding.
    #[serde(skip_serializing_if = "is_false")]
    disable_padding: bool,
    /// Legacy batch toggle. Default false. Emit when explicitly set.
    #[serde(skip_serializing_if = "is_false")]
    enable_batching: bool,
    /// PR #448 adaptive coalesce window. Defaults are 0/0 (= "use
    /// the crate's compiled defaults"). Emit when the user has
    /// hand-edited non-zero values into config.json so they survive
    /// a UI save.
    #[serde(skip_serializing_if = "is_zero_u16")]
    coalesce_step_ms: u16,
    #[serde(skip_serializing_if = "is_zero_u16")]
    coalesce_max_ms: u16,
    /// Exit-node config (CF-anti-bot bypass for chatgpt.com / claude.ai /
    /// grok.com / x.com via exit-node second-hop relay). Skip when fully
    /// default (disabled with no URL/PSK/hosts) so configs without
    /// exit-node setup stay clean. Round-tripped through FormState so
    /// Save preserves user-edited values.
    #[serde(skip_serializing_if = "is_default_exit_node")]
    exit_node: &'a rahgozar::config::ExitNodeConfig,

    /// TLS-fragmentation Direct Mode for Google domains — see
    /// `src/direct_mode.rs` for the algorithm and the
    /// `DirectModeConfig` doc-comment in `src/config.rs` for the
    /// override semantics. Skip when fully default (enabled with
    /// empty override lists) so configs that use the built-in defaults
    /// stay clean. Round-tripped through FormState so Save preserves
    /// hand-edited values.
    #[serde(skip_serializing_if = "is_default_direct_mode")]
    direct_mode: &'a rahgozar::config::DirectModeConfig,

    /// Verbatim passthrough of unknown / future config.json keys
    /// captured at load time. Re-emitted via `#[serde(flatten)]`
    /// so a Save-config or Save-as-profile round-trip preserves
    /// every field — matching the Android `extrasJson` semantics.
    /// Skip when empty so unchanged configs stay clean.
    #[serde(flatten, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    extras: &'a std::collections::BTreeMap<String, serde_json::Value>,
}

fn is_default_strikes(v: &u32) -> bool {
    *v == 3
}
fn is_default_window_secs(v: &u64) -> bool {
    *v == 30
}
fn is_default_cooldown_secs(v: &u64) -> bool {
    *v == 120
}
fn is_default_timeout_secs(v: &u64) -> bool {
    *v == 30
}
fn is_default_apps_script_lang(v: &&str) -> bool {
    v.is_empty() || v.eq_ignore_ascii_case("en")
}
fn is_default_exit_node(en: &&rahgozar::config::ExitNodeConfig) -> bool {
    !en.enabled
        && en.relay_url.is_empty()
        && en.psk.is_empty()
        && en.hosts.is_empty()
        && (en.mode.is_empty() || en.mode == "selective")
}

/// Direct Mode default = `enabled: true` (compiled default) AND every
/// override list empty (so the runtime falls back to the built-in
/// defaults from `direct_mode.rs`). Skip serialization in that case so
/// configs that haven't been hand-edited stay quiet.
fn is_default_direct_mode(d: &&rahgozar::config::DirectModeConfig) -> bool {
    d.enabled
        && d.fronts.is_empty()
        && d.google_domains.is_empty()
        && d.sanctioned_domains.is_empty()
}

/// Match the log-colour defaults case-insensitively so `#5AB464` and
/// `#5ab464` both skip serialization. Empty strings are also treated as
/// default since the load path normalizes empty → compiled default.
fn is_default_log_color_info(s: &&str) -> bool {
    s.is_empty() || s.eq_ignore_ascii_case(rahgozar::config::DEFAULT_LOG_COLOR_INFO)
}
fn is_default_log_color_warn(s: &&str) -> bool {
    s.is_empty() || s.eq_ignore_ascii_case(rahgozar::config::DEFAULT_LOG_COLOR_WARN)
}
fn is_default_log_color_error(s: &&str) -> bool {
    s.is_empty() || s.eq_ignore_ascii_case(rahgozar::config::DEFAULT_LOG_COLOR_ERROR)
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum ScriptIdWire<'a> {
    One(&'a str),
    Many(Vec<&'a str>),
}

impl<'a> From<&'a Config> for ConfigWire<'a> {
    fn from(c: &'a Config) -> Self {
        let script_id = c.script_id.as_ref().map(|s| match s {
            ScriptId::One(v) => ScriptIdWire::One(v.as_str()),
            ScriptId::Many(v) => ScriptIdWire::Many(v.iter().map(String::as_str).collect()),
        });
        ConfigWire {
            mode: c.mode.as_str(),
            google_ip: c.google_ip.as_str(),
            front_domain: c.front_domain.as_str(),
            script_id,
            auth_key: c.auth_key.as_str(),
            listen_host: c.listen_host.as_str(),
            listen_port: c.listen_port,
            socks5_port: c.socks5_port,
            log_level: c.log_level.as_str(),
            log_color_info: c.log_color_info.as_str(),
            log_color_warn: c.log_color_warn.as_str(),
            log_color_error: c.log_color_error.as_str(),
            verify_ssl: c.verify_ssl,
            hosts: &c.hosts,
            upstream_socks5: c.upstream_socks5.as_deref(),
            parallel_relay: c.parallel_relay,
            sni_hosts: c
                .sni_hosts
                .as_ref()
                .map(|v| v.iter().map(String::as_str).collect()),
            normalize_x_graphql: c.normalize_x_graphql,
            youtube_via_relay: c.youtube_via_relay,
            relay_url_patterns: &c.relay_url_patterns,
            sabr_strip: c.sabr_strip,
            passthrough_hosts: &c.passthrough_hosts,
            fetch_ips_from_api: c.fetch_ips_from_api,
            max_ips_to_scan: c.max_ips_to_scan,
            scan_batch_size: c.scan_batch_size,
            google_ip_validation: c.google_ip_validation,
            tunnel_doh: c.tunnel_doh,
            bypass_doh_hosts: &c.bypass_doh_hosts,
            block_doh: c.block_doh,
            block_stun: c.block_stun,
            fronting_groups: &c.fronting_groups,
            auto_blacklist_strikes: c.auto_blacklist_strikes,
            auto_blacklist_window_secs: c.auto_blacklist_window_secs,
            auto_blacklist_cooldown_secs: c.auto_blacklist_cooldown_secs,
            request_timeout_secs: c.request_timeout_secs,
            apps_script_lang: c.apps_script_lang.as_str(),
            force_http1: c.force_http1,
            exit_node: &c.exit_node,
            direct_mode: &c.direct_mode,
            extras: &c.extras,
            block_quic: c.block_quic,
            disable_padding: c.disable_padding,
            enable_batching: c.enable_batching,
            coalesce_step_ms: c.coalesce_step_ms,
            coalesce_max_ms: c.coalesce_max_ms,
        }
    }
}

/// Accent color — same blue used throughout the UI for primary actions.
const ACCENT: egui::Color32 = egui::Color32::from_rgb(70, 120, 180);
const ACCENT_HOVER: egui::Color32 = egui::Color32::from_rgb(90, 145, 205);
const OK_GREEN: egui::Color32 = egui::Color32::from_rgb(80, 180, 100);
const ERR_RED: egui::Color32 = egui::Color32::from_rgb(220, 110, 110);

/// Default text colour for log lines whose level we couldn't classify
/// (DEBUG / TRACE / lines without a level token). Matches the panel's
/// previous monospace text colour so the default visual is unchanged.
const LOG_DEFAULT_TEXT: egui::Color32 = egui::Color32::from_gray(210);

/// Tracing levels we colour. Per-level so users can pair any subset.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum LogLevel {
    Info,
    Warn,
    Error,
}

/// Classify a log line by the level token `tracing_subscriber::fmt`
/// emits — it places the level immediately after the timestamp and
/// before the message body, e.g.:
///
/// ```text
/// 2025-05-16T10:00:00.123456Z  INFO starting up
/// ```
///
/// We pick the **leftmost** level-shaped token in the line. The
/// previous `contains(" LEVEL ")` chain checked each level in
/// priority order, which meant an INFO line whose message mentions
/// ` ERROR ` (e.g. `INFO  got ERROR response from upstream`) would be
/// misclassified as ERROR — wrong colour, wrong urgency signal. The
/// leftmost-token rule is correct because the formatter's level
/// always precedes any in-message level mention.
///
/// Returns `None` for DEBUG / TRACE / unclassified lines so they
/// render in the default colour.
fn classify_log_line(line: &str) -> Option<LogLevel> {
    let candidates: [(&str, LogLevel); 3] = [
        (" ERROR ", LogLevel::Error),
        (" WARN ", LogLevel::Warn),
        (" INFO ", LogLevel::Info),
    ];
    let mut best: Option<(usize, LogLevel)> = None;
    for (token, level) in candidates {
        if let Some(pos) = line.find(token) {
            best = match best {
                Some((bp, _)) if pos >= bp => best,
                _ => Some((pos, level)),
            };
        }
    }
    best.map(|(_, l)| l)
}

/// Parse a `#RRGGBB` / `RRGGBB` hex colour to `egui::Color32`. Returns
/// `None` on any malformed input so the caller can fall back to a
/// compiled default rather than panic on bad config.
///
/// Accepts exactly one optional leading `#` (the previous
/// `trim_start_matches('#')` would silently swallow `##abcdef`, which
/// then survives `normalize_log_color`'s round-trip with the leading
/// `#` re-attached — confusing if the user expected strict validation).
fn parse_hex_color(s: &str) -> Option<egui::Color32> {
    let trimmed = s.trim();
    let hex = match trimmed.strip_prefix('#') {
        Some(rest) => rest,
        None => trimmed,
    };
    if hex.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some(egui::Color32::from_rgb(r, g, b))
}

/// Format an `egui::Color32` back to lowercase `#RRGGBB`. Used to write
/// a colour picker's selection back into the `String` config field.
fn color_to_hex(c: egui::Color32) -> String {
    format!("#{:02x}{:02x}{:02x}", c.r(), c.g(), c.b())
}

/// Canonicalise a log-colour string to lowercase `#RRGGBB`, falling back
/// to `default` for malformed input.
///
/// Used on both sides of the form lifecycle so the on-disk config and
/// the rendered UI never disagree:
///   - At load time, malformed `config.json` values get replaced with
///     the compiled default so the form text field matches what the
///     renderer is actually using.
///   - At save time, the same normalisation runs again so a fresh Save
///     can't write a stale bad hex back to disk just because the user
///     never opened the colour editor.
///   - Valid-but-non-canonical inputs (uppercase `#ABCDEF`, no-`#`
///     `abcdef`, with-whitespace `  #abcdef  `) round-trip through
///     `parse_hex_color` → `color_to_hex`, which always emits lowercase
///     `#rrggbb`. That keeps the on-disk file stable across saves even
///     when the user types in mixed case.
fn normalize_log_color(value: &str, default: &str) -> String {
    match parse_hex_color(value) {
        Some(c) => color_to_hex(c),
        None => default.into(),
    }
}

/// One row in the per-level colour editor: a label, a swatch picker, an
/// editable hex text input, and a Reset button. The swatch and the
/// text are kept in sync — picking a colour writes the new hex back
/// into `value`, and a hex edit updates the swatch on the next frame.
fn log_color_row(ui: &mut egui::Ui, label: &str, value: &mut String, default_hex: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [54.0, 18.0],
            egui::Label::new(egui::RichText::new(label).monospace().size(11.0)),
        );
        // Swatch picker. Seed from the current text, write back on
        // change. egui's color_edit_button_srgb edits an [r,g,b] in
        // place; we mirror it from / to the hex string.
        let mut rgb: [u8; 3] = match parse_hex_color(value) {
            Some(c) => [c.r(), c.g(), c.b()],
            // Bad text → seed picker from the default so the user can
            // see a sensible starting point. The text field still
            // shows the bad value until they edit it.
            None => {
                let d = parse_hex_color(default_hex).unwrap();
                [d.r(), d.g(), d.b()]
            }
        };
        if ui.color_edit_button_srgb(&mut rgb).changed() {
            *value = color_to_hex(egui::Color32::from_rgb(rgb[0], rgb[1], rgb[2]));
        }
        ui.add_sized(
            [110.0, 20.0],
            egui::TextEdit::singleline(value).hint_text("#rrggbb"),
        );
        if ui
            .small_button("reset")
            .on_hover_text("Restore the compiled default for this level.")
            .clicked()
        {
            *value = default_hex.into();
        }
        // Live preview of how a log line of this level would render.
        if let Some(c) = parse_hex_color(value) {
            ui.label(
                egui::RichText::new("sample log line")
                    .monospace()
                    .size(11.0)
                    .color(c),
            );
        } else {
            ui.label(
                egui::RichText::new("bad hex — reverts to default")
                    .small()
                    .italics()
                    .color(egui::Color32::from_gray(150)),
            );
        }
    });
}

/// Build the on-disk `fronting_groups` Vec from the live editor state.
///
/// `groups[i]` and `buffers[i]` are paired by position — the editor in
/// `FormState` maintains this invariant. For each row:
///
///   - parse the raw edit buffer into a list of domains (split on
///     `,` and `\n`, trim, drop empty entries),
///   - if the parsed list is empty, drop the row entirely (so a draft
///     row with no domains doesn't survive into a saved config —
///     `Config::validate()` would otherwise reject it),
///   - otherwise emit a `FrontingGroup` with the cleaned domains.
///
/// `buffers` shorter than `groups` is tolerated: the missing tail
/// reads from each group's existing `domains` field. The editor
/// loop tops the buffer Vec up before rendering, but `to_config()`
/// can also be called from non-editor sites (Test handler, etc.).
///
/// Critically: rows are *position-keyed*, not name-keyed. Duplicate
/// `name` values are legal in `fronting_groups` (the proxy
/// startup warns about them but honours them — see
/// `proxy_server.rs::ProxyServer::new`), and a previous version of
/// this code keyed buffers by name in a HashMap, which silently
/// collapsed two same-named groups' domain lists into one. The
/// indexed shape eliminates that data-loss bug. See the
/// `duplicate_group_names_get_distinct_buffers` test below.
fn build_fronting_groups_from_editor(
    groups: &[FrontingGroup],
    buffers: &[String],
) -> Vec<FrontingGroup> {
    // Dedup preserving insertion order. The Android
    // `ConfigStore.toJson()` applies the same `.distinct()` pass, so
    // this keeps saved configs consistent across the two clients — a
    // user who hand-pastes a duplicate-laden list ends up with the
    // same on-disk representation regardless of which UI they used.
    fn dedup_preserve_order(items: impl Iterator<Item = String>) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for s in items {
            if seen.insert(s.clone()) {
                out.push(s);
            }
        }
        out
    }

    groups
        .iter()
        .enumerate()
        .filter_map(|(i, g)| {
            let cleaned: Vec<String> = match buffers.get(i) {
                Some(buf) => dedup_preserve_order(
                    buf.split(|c: char| c == ',' || c == '\n')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                ),
                None => dedup_preserve_order(
                    g.domains
                        .iter()
                        .map(|d| d.trim().to_string())
                        .filter(|d| !d.is_empty()),
                ),
            };
            if cleaned.is_empty() {
                None
            } else {
                Some(FrontingGroup {
                    name: g.name.clone(),
                    ip: g.ip.clone(),
                    sni: g.sni.clone(),
                    domains: cleaned,
                })
            }
        })
        .collect()
}

/// Draw a "section card" — a rounded frame with a faint fill and a small
/// heading above it. Used to visually group related form rows.
fn section(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(6.0);
    ui.label(
        egui::RichText::new(title)
            .size(12.0)
            .color(egui::Color32::from_gray(180))
            .strong(),
    );
    ui.add_space(2.0);
    let frame = egui::Frame::none()
        .fill(egui::Color32::from_rgb(28, 30, 34))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 54, 60)))
        .rounding(6.0)
        .inner_margin(egui::Margin::same(10.0));
    frame.show(ui, body);
}

/// A primary accent-filled button. Used for the headline action in a row
/// (Start / Stop / SNI pool).
fn primary_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(egui::Color32::WHITE)
            .strong(),
    )
    .fill(ACCENT)
    .min_size(egui::vec2(120.0, 28.0))
    .rounding(4.0)
}

/// A compact form row: label on the left (fixed width for vertical alignment),
/// widget on the right filling the remaining space.
fn form_row(
    ui: &mut egui::Ui,
    label: &str,
    hover: Option<&str>,
    widget: impl FnOnce(&mut egui::Ui, egui::Id),
) {
    ui.horizontal(|ui| {
        let resp = ui.add_sized(
            [120.0, 20.0],
            egui::Label::new(egui::RichText::new(label).color(egui::Color32::from_gray(200))),
        );
        let label_id = resp.id;
        if let Some(h) = hover {
            resp.on_hover_text(h);
        }
        widget(ui, label_id);
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if self.last_poll.elapsed() > Duration::from_millis(700) {
            let _ = self.cmd_tx.send(Cmd::PollStats);
            self.last_poll = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(500));

        // Drain a pending mode-switch revert signal. The background
        // thread sets this when `switch_mode` rejects the new config
        // (typically build_mode_state failing, e.g. DomainFronter::new
        // refusing a missing script_id). We roll the dropdown back to
        // the runtime's actual mode and surface the error as a toast,
        // so the user sees a clear "tried → failed → still on previous
        // mode" rather than a silently-out-of-sync UI.
        {
            let revert = self.shared.state.lock().unwrap().mode_switch_revert.take();
            if let Some((revert_to, err_msg)) = revert {
                self.form.mode = revert_to;
                self.toast = Some((err_msg, Instant::now()));
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.style_mut().spacing.item_spacing = egui::vec2(8.0, 6.0);

            // Wrap the whole central panel in a vertical scroll area so the
            // form + stats + log panel stay accessible on short screens
            // (~13" laptops at default scaling). Nested scroll areas still
            // work fine within this outer scroller.
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {

            // ── Header row: project name, version (→ github), status pill ─
            let running = self.shared.state.lock().unwrap().running;
            ui.horizontal(|ui| {
                ui.hyperlink_to(
                    egui::RichText::new("rahgozar").size(20.0).strong(),
                    "https://github.com/dazzling-no-more/rahgozar",
                );
                ui.hyperlink_to(
                    egui::RichText::new(format!("v{}", VERSION))
                        .color(egui::Color32::from_gray(140))
                        .monospace(),
                    format!(
                        "https://github.com/dazzling-no-more/rahgozar/releases/tag/v{}",
                        VERSION
                    ),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (fill, dot, label) = if running {
                        (
                            egui::Color32::from_rgb(30, 60, 40),
                            OK_GREEN,
                            "running",
                        )
                    } else {
                        (
                            egui::Color32::from_rgb(60, 35, 35),
                            ERR_RED,
                            "stopped",
                        )
                    };
                    egui::Frame::none()
                        .fill(fill)
                        .rounding(12.0)
                        .inner_margin(egui::Margin::symmetric(10.0, 3.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(8.0, 8.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(rect.center(), 4.0, dot);
                                ui.label(
                                    egui::RichText::new(label)
                                        .color(dot)
                                        .monospace()
                                        .strong(),
                                );
                            });
                        });
                });
            });

            ui.add_space(2.0);

            // ── Profile bar ──────────────────────────────────────────────
            // Lets the user keep several configs (e.g. one Apps Script setup
            // and one Full tunnel setup) side by side and switch between
            // them without re-typing deployment IDs / auth keys / tuning
            // knobs. See `src/profiles.rs` for the storage model.
            self.show_profile_bar(ui);

            // ── Section: Mode ─────────────────────────────────────────────
            // Surfacing the mode at the top of the form because it changes
            // which of the sections below are actually used. `direct` runs
            // without the Apps Script relay (Google edge + any configured
            // fronting_groups via the SNI-rewrite tunnel only) — useful as
            // a bootstrap to deploy Code.gs, or as a standalone mode for
            // users who only need access to fronting-group targets.
            // Snapshot the mode before the dropdown so we can detect a
            // change after the closure returns. When the proxy is running
            // and the user picks a different mode, we fire `Cmd::SwitchMode`
            // and let `RuntimeState::switch_mode` hot-swap the bundle
            // (fronter + TunnelMux + RewriteCtx) without rebinding the
            // listeners. See `src/proxy_server.rs::switch_mode`.
            let mode_before = self.form.mode.clone();
            section(ui, "Mode", |ui| {
                form_row(ui, "Mode", Some(
                    "apps_script: DPI bypass via Apps Script relay (needs cert).\n\
                     full: tunnel ALL traffic through Apps Script + tunnel node (no cert needed).\n\
                     direct: SNI-rewrite tunnel only — no relay (Google edge + any fronting_groups).\n\
                     \n\
                     While the proxy is running, switching mode here hot-swaps the routing live — no Stop/Start needed."
                ), |ui, _label_id| {
                    egui::ComboBox::from_id_source("mode")
                        .selected_text(match self.form.mode.as_str() {
                            "direct" | "google_only" => "Direct (no relay)",
                            "full" => "Full tunnel (no cert)",
                            _ => "Apps Script (MITM)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.form.mode,
                                "apps_script".into(),
                                "Apps Script (MITM)",
                            );
                            ui.selectable_value(
                                &mut self.form.mode,
                                "full".into(),
                                "Full tunnel (no cert)",
                            );
                            ui.selectable_value(
                                &mut self.form.mode,
                                "direct".into(),
                                "Direct (no relay)",
                            );
                        });
                });
                if self.form.mode == "direct" || self.form.mode == "google_only" {
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.small(egui::RichText::new(
                            "Direct mode — SNI-rewrite tunnel only. Reach the Google edge (and any configured fronting_groups) without an Apps Script relay.",
                        )
                        .color(OK_GREEN));
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.small(egui::RichText::new(
                            "Also works as upstream proxy for Psiphon / xray — unfronted hosts pass through as raw TCP. Setup: docs/use-as-upstream.md (FA: docs/use-as-upstream.fa.md).",
                        )
                        .color(egui::Color32::from_gray(150)));
                    });
                }
                if self.form.mode == "full" {
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.small(egui::RichText::new(
                            "Full tunnel — all traffic tunneled end-to-end via Apps Script + remote tunnel node. No certificate needed.",
                        )
                        .color(OK_GREEN));
                    });
                }
            });

            // Live mode-switch dispatch. Compares against the snapshot taken
            // before the section closure; only fires while the proxy is
            // running so a stopped proxy still picks up the new mode on the
            // next Start (no behavior change for the Start/Stop flow).
            //
            // If `to_config()` rejects the form (e.g. apps_script picked
            // without a script_id), we revert `self.form.mode` and toast
            // the error so the user isn't left with a UI state the runtime
            // never accepted.
            if mode_before != self.form.mode {
                // Use `proxy_active`, not `running`. The Start button
                // flips `proxy_active = true` synchronously on click,
                // while `running` only flips on the entry of the
                // spawned `server.run()` task — which sits behind a
                // bg-thread → tokio-spawn → scheduler hop. A mode
                // change inside that latency window would otherwise be
                // silently dropped (gate sees `running = false`),
                // leaving the form on the new mode while the proxy
                // serves the original. The bg-thread orders commands
                // as it dequeues, so a SwitchMode landing in this
                // window is processed strictly after Cmd::Start
                // finishes its synchronous setup (`active = Some`),
                // and the `state.switch_mode` call then races
                // correctly with the spawned `server.run()`'s init
                // block under `switch_lock`.
                let proxy_active_now = self.shared.state.lock().unwrap().proxy_active;
                if proxy_active_now {
                    match self.form.to_config() {
                        Ok(cfg) => {
                            let _ = self.cmd_tx.send(Cmd::SwitchMode(cfg));
                            self.toast = Some((
                                format!("Switching mode → {}", self.form.mode),
                                Instant::now(),
                            ));
                        }
                        Err(e) => {
                            self.toast = Some((
                                format!("Cannot switch mode: {}", e),
                                Instant::now(),
                            ));
                            self.form.mode = mode_before;
                        }
                    }
                }
            }

            let direct_mode = self.form.mode == "direct" || self.form.mode == "google_only";

            // ── Section: Fronting groups (CDN edge MITM targets) ───────────
            // Lets users add Vercel / Fastly / Akamai / Netlify edges (or any
            // multi-tenant CDN) by typing a known-hosted hostname; we resolve
            // it via DNS + TLS-probe each IP and let the user add the best
            // one as a new `FrontingGroup`. See `rahgozar::cdn_discover` for
            // the probe logic. The editor lives outside `direct_mode` gating
            // because fronting groups also fire in `apps_script` mode — only
            // `full` mode short-circuits them (warned at proxy startup).
            section(ui, "Fronting groups (CDN edges)", |ui| {
                ui.small(egui::RichText::new(
                    "Route specific domains through a CDN edge instead of the Apps Script relay. \
                     Pick a hostname known to live on the CDN (e.g. python.org → Fastly, react.dev → Vercel) \
                     and click Discover — we'll resolve it and pick the best IP.",
                )
                .color(egui::Color32::from_gray(150)));
                ui.add_space(4.0);

                // ─ Existing groups list ────────────────────────────────────
                // Defensive: keep `domain_buffers` in sync with
                // `fronting_groups` in case anything else mutated the
                // groups Vec without going through this editor (a
                // future code path, or a load that bypassed the
                // constructor). Out of sync would silently mis-key
                // every domain edit; bring them back to par before
                // we render.
                while self.form.domain_buffers.len() < self.form.fronting_groups.len() {
                    let idx = self.form.domain_buffers.len();
                    self.form.domain_buffers
                        .push(self.form.fronting_groups[idx].domains.join("\n"));
                }
                self.form.domain_buffers.truncate(self.form.fronting_groups.len());

                let mut remove_idx: Option<usize> = None;
                for i in 0..self.form.fronting_groups.len() {
                    // Snapshot draft state from the buffer (source of
                    // truth for in-flight edits); `g.domains` is only
                    // a fallback for groups loaded from disk that the
                    // user hasn't touched, but the constructor already
                    // primed the buffer with `g.domains.join("\n")`
                    // so reads off the buffer cover both paths.
                    let has_domains = self.form.domain_buffers[i]
                        .split(|c: char| c == ',' || c == '\n')
                        .any(|s| !s.trim().is_empty());
                    let g = &self.form.fronting_groups[i];
                    let g_name = g.name.clone();
                    let g_ip = g.ip.clone();
                    let g_sni = g.sni.clone();
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&g_name).strong());
                        ui.label(egui::RichText::new(format!(
                            "→ {}  via {}",
                            g_ip, g_sni,
                        ))
                        .monospace()
                        .color(egui::Color32::from_gray(170)));
                        // Draft warning: surface that Save will drop this
                        // group so the user doesn't think they configured
                        // something that quietly disappears. Matches the
                        // filter in `to_config()`.
                        if !has_domains {
                            ui.small(egui::RichText::new("(draft — won't save until you list domains)")
                                .color(ERR_RED));
                        }
                        if ui.small_button("remove")
                            .on_hover_text("Delete this fronting group. Takes effect on the next Save config + restart.")
                            .clicked()
                        {
                            remove_idx = Some(i);
                        }
                    });
                    // Domains list edited via the position-indexed buffer
                    // (see FormState::domain_buffers). Splitting on every
                    // keystroke would strip a freshly typed `, ` or `\n`
                    // separator the moment the user hit the key, which
                    // makes adding a second domain manually impossible.
                    // The buffer is the source of truth while editing;
                    // parsing happens once at save time inside
                    // `to_config()`.
                    ui.add(
                        egui::TextEdit::multiline(&mut self.form.domain_buffers[i])
                            .hint_text("domains to front, one per line (or comma-separated)")
                            .desired_width(f32::INFINITY)
                            .desired_rows(2),
                    );
                    // CDN-edge mismatch warning. Domains here are routed
                    // to `g.ip` with `SNI=g.sni` — they must be served
                    // by the same edge as `sni`, otherwise the inner
                    // Host header leaks to the wrong CDN backend and
                    // the request fails (wrong cert, 404, or a returned
                    // page that isn't what the user asked for). See
                    // docs/fronting-groups.md.
                    ui.small(egui::RichText::new(
                        "⚠ Only list domains you know are served by the same edge as the SNI above — \
                         a mismatch returns wrong-cert errors or a default page.",
                    )
                    .color(egui::Color32::from_rgb(220, 180, 100)));
                    ui.add_space(4.0);
                }
                if let Some(idx) = remove_idx {
                    // Both Vecs must be touched together — they are
                    // length-locked. Removing only from one would
                    // shift the alignment for every subsequent group
                    // and the buffer-for-group-N rendering would point
                    // at the wrong row.
                    self.form.fronting_groups.remove(idx);
                    if idx < self.form.domain_buffers.len() {
                        self.form.domain_buffers.remove(idx);
                    }
                }

                // ─ Discover-by-hostname row ────────────────────────────────
                ui.separator();
                ui.add_space(4.0);
                // Snapshot the discovery state so we can read+render it
                // without holding the lock through the closure (the Add
                // button mutates fronting_groups, which is on self.form,
                // and we want the UI thread free to do that without
                // contending with the background thread.)
                let discover_state = self.shared.state.lock().unwrap().discover_state.clone();
                let in_flight = matches!(discover_state, Some(DiscoverState::InFlight { .. }));
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::Label::new(egui::RichText::new("Discover front")
                            .color(egui::Color32::from_gray(200))),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.form.discover_hostname_input)
                            .hint_text("hostname (e.g. python.org)")
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add_space(120.0 + 8.0);
                    let btn_label = if in_flight { "Discovering…" } else { "Discover" };
                    let btn = egui::Button::new(btn_label)
                        .min_size(egui::vec2(100.0, 22.0))
                        .rounding(4.0);
                    let enabled = !in_flight
                        && !self.form.discover_hostname_input.trim().is_empty();
                    if ui.add_enabled(enabled, btn)
                        .on_hover_text(
                            "DNS-resolve the hostname and TLS-probe each returned IP \
                             with SNI=hostname. Successful IPs can be added below as a \
                             new fronting group."
                        )
                        .clicked()
                    {
                        let hostname = self.form.discover_hostname_input.trim().to_string();
                        let _ = self.cmd_tx.send(Cmd::DiscoverFront { hostname });
                    }
                });

                // ─ Discover results panel ──────────────────────────────────
                match &discover_state {
                    Some(DiscoverState::InFlight { hostname }) => {
                        ui.add_space(4.0);
                        ui.small(egui::RichText::new(format!(
                            "Discovering {} — resolving DNS and probing IPs…",
                            hostname,
                        ))
                        .color(egui::Color32::from_gray(170)));
                    }
                    Some(DiscoverState::Error { hostname, message }) => {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.small(egui::RichText::new(format!("✗ {}: {}", hostname, message))
                                .color(ERR_RED));
                            if ui.small_button("dismiss").clicked() {
                                self.shared.state.lock().unwrap().discover_state = None;
                            }
                        });
                    }
                    Some(DiscoverState::Done(df)) => {
                        let hostname = df.hostname.clone();
                        let n_ok = df.ips.iter().filter(|r| r.is_ok()).count();
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            let header = if n_ok > 0 {
                                format!("{} — {} of {} IPs reachable", hostname, n_ok, df.ips.len())
                            } else {
                                format!("{} — no IPs reachable", hostname)
                            };
                            ui.small(egui::RichText::new(header)
                                .color(if n_ok > 0 { OK_GREEN } else { ERR_RED }));
                            if ui.small_button("dismiss").clicked() {
                                self.shared.state.lock().unwrap().discover_state = None;
                            }
                        });
                        // Per-IP rows. Successful entries get an Add button
                        // that appends a new FrontingGroup pointing at that
                        // IP, with hostname as the SNI and an empty domains
                        // list (user fills in what to front via this edge).
                        let mut to_add: Option<String> = None;
                        for r in &df.ips {
                            ui.horizontal(|ui| {
                                let (marker, color, detail) = match (&r.latency_ms, &r.error) {
                                    (Some(ms), _) => ("✓", OK_GREEN, format!("{} ms", ms)),
                                    (None, Some(e)) => ("✗", ERR_RED, e.clone()),
                                    (None, None) => ("?", egui::Color32::from_gray(160), "unknown".into()),
                                };
                                ui.small(egui::RichText::new(marker).color(color));
                                ui.small(egui::RichText::new(&r.ip).monospace());
                                ui.small(egui::RichText::new(detail)
                                    .color(egui::Color32::from_gray(150)));
                                if r.is_ok() {
                                    if ui.small_button("add as fronting group")
                                        .on_hover_text(
                                            "Append a new fronting group with this IP and SNI=hostname. \
                                             You then list the domains you want fronted through this edge."
                                        )
                                        .clicked()
                                    {
                                        to_add = Some(r.ip.clone());
                                    }
                                }
                            });
                        }
                        if let Some(ip) = to_add {
                            // Pick a unique name to avoid log-line ambiguity
                            // (proxy_server warns on duplicate group names).
                            let base_name = hostname.clone();
                            let name = if self.form.fronting_groups.iter()
                                .any(|g| g.name == base_name)
                            {
                                let mut n = 2;
                                loop {
                                    let candidate = format!("{}-{}", base_name, n);
                                    if !self.form.fronting_groups.iter()
                                        .any(|g| g.name == candidate)
                                    {
                                        break candidate;
                                    }
                                    n += 1;
                                }
                            } else {
                                base_name
                            };
                            self.form.fronting_groups.push(FrontingGroup {
                                name,
                                ip,
                                sni: hostname.clone(),
                                domains: Vec::new(),
                            });
                            // Position-locked buffer: must push in lockstep
                            // with `fronting_groups` so index-keyed reads
                            // (editor render, to_config) stay valid.
                            self.form.domain_buffers.push(String::new());
                            // Clear the input + result so the next discovery
                            // doesn't re-trigger an Add on stale state.
                            self.form.discover_hostname_input.clear();
                            self.shared.state.lock().unwrap().discover_state = None;
                            self.toast = Some((
                                format!("Added fronting group for {} — fill in domains and Save config.",
                                    hostname),
                                Instant::now(),
                            ));
                        }
                    }
                    None => {}
                }
            });

            // ── Section: Apps Script relay ────────────────────────────────
            section(ui, "Apps Script relay", |ui| {
                ui.add_enabled_ui(!direct_mode, |ui| {
                    form_row(ui, "Deployment IDs", Some(
                        "One deployment ID per line. Proxy round-robins between them and sidelines \
                         any ID that hits its daily quota for 10 minutes before retrying."
                    ), |ui, label_id| {
                        ui.add(egui::TextEdit::multiline(&mut self.form.script_id)
                            .hint_text("one deployment ID per line")
                            .desired_width(f32::INFINITY)
                            .desired_rows(3))
                        .labelled_by(label_id);
                    });

                    let id_count = self.form.script_id
                        .split(|c: char| c == '\n' || c == ',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .count();
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        if id_count <= 1 {
                            ui.small(egui::RichText::new("Tip: add more IDs for round-robin with auto-failover.")
                                .color(egui::Color32::from_gray(140)));
                        } else {
                            ui.small(egui::RichText::new(format!(
                                "{} IDs — round-robin with auto-failover on quota.", id_count
                            )).color(OK_GREEN));
                        }
                    });

                    form_row(ui, "Auth key", Some(
                        "Same value as AUTH_KEY inside your Code.gs."
                    ), |ui, label_id| {
                        ui.add(egui::TextEdit::singleline(&mut self.form.auth_key)
                            .password(!self.form.show_auth_key)
                            .desired_width(f32::INFINITY))
                        .labelled_by(label_id);
                    });
                });
            });

            // ── Section: Network ──────────────────────────────────────────
            section(ui, "Network", |ui| {
                form_row(ui, "Google IP", None, |ui, label_id| {
                    ui.add(egui::TextEdit::singleline(&mut self.form.google_ip)
                        .desired_width(f32::INFINITY))
                    .labelled_by(label_id);
                });
                ui.horizontal(|ui| {
                    ui.add_space(120.0 + 8.0);
                    if ui.small_button("scan IPs")
                        .on_hover_text(
                            "Probe known Google frontend IPs; report which are reachable \
                             (results go to the log panel)."
                        )
                        .clicked()
                    {
                        if let Ok(cfg) = self.form.to_config() {
                            let _ = self.cmd_tx.send(Cmd::Test(cfg.clone()));
                            self.toast = Some((
                                "Scan started — check the Recent log below.".into(),
                                Instant::now(),
                            ));
                        }
                    }
                    let active_sni = self.form.sni_pool.iter().filter(|r| r.enabled).count();
                    let total_sni = self.form.sni_pool.len();
                    let sni_btn = egui::Button::new(
                        egui::RichText::new(format!("SNI pool… ({}/{})", active_sni, total_sni))
                            .color(egui::Color32::WHITE),
                    )
                    .fill(ACCENT)
                    .rounding(4.0);
                    if ui.add(sni_btn)
                        .on_hover_text(
                            "Open the SNI rotation pool editor. Test which front-domain \
                             names get through your network's DPI."
                        )
                        .clicked()
                    {
                        self.form.sni_editor_open = true;
                    }
                });

                form_row(ui, "Front domain", None, |ui, label_id| {
                    ui.add(egui::TextEdit::singleline(&mut self.form.front_domain)
                        .desired_width(f32::INFINITY))
                    .labelled_by(label_id);
                });

                // Network sharing: phones, tablets, other laptops on the
                // same Wi-Fi can use this proxy when the bind address is
                // 0.0.0.0 instead of 127.0.0.1. We expose this as a
                // single-checkbox UI rather than the raw `listen_host`
                // text field — typing `0.0.0.0` from memory is enough of
                // a friction point that almost no one does it. Power
                // users with a custom bind IP (specific NIC) can still
                // edit `listen_host` directly in `config.json`; we
                // detect that case and show a "Custom bind" badge so
                // the checkbox doesn't silently overwrite their setting
                // on the next Save.
                //
                // Snapshot the relevant flags before entering form_row's
                // closure — we need to mutate `self.form.listen_host`
                // inside the closure when the checkbox toggles, so we
                // can't hold a borrow on it through the closure.
                let listen_host_snapshot = self.form.listen_host.trim().to_string();
                let listen_port_snapshot = self.form.listen_port.trim().to_string();
                let socks5_port_snapshot = self.form.socks5_port.trim().to_string();
                let was_share_on_lan = is_share_on_lan(&listen_host_snapshot);
                let lower_snapshot = listen_host_snapshot.to_ascii_lowercase();
                let is_custom_bind = !listen_host_snapshot.is_empty()
                    && !was_share_on_lan
                    && lower_snapshot != "127.0.0.1"
                    && lower_snapshot != "localhost";
                let mut new_listen_host: Option<String> = None;
                // Listener fields (bind host + HTTP/SOCKS5 ports) need
                // a Stop+Start to take effect — `RuntimeState::switch_mode`
                // explicitly ignores changes to them since rebinding a
                // socket is observable to clients. Disable the
                // widgets while the proxy is running (or starting) so
                // the user isn't surprised when they edit a port and
                // the form does nothing live.
                let proxy_active_for_listeners =
                    self.shared.state.lock().unwrap().proxy_active;
                let listener_hover = if proxy_active_for_listeners {
                    Some(
                        "Stop the proxy first — listen host and ports are bound at \
                         Start and aren't part of the live mode-switch contract.",
                    )
                } else {
                    None
                };
                ui.add_enabled_ui(!proxy_active_for_listeners, |ui| {
                form_row(ui, "Network", Some(
                    "By default the proxy is reachable only from this computer. \
                     Turn this on to let phones, tablets, and other laptops on the \
                     same Wi-Fi (or a hotspot you're sharing) use it too. The \
                     other devices then point their HTTP / SOCKS5 proxy at the \
                     LAN IP shown below. Make sure your firewall lets in the proxy \
                     port — macOS pops up a Firewall prompt the first time."
                ), |ui, _label_id| {
                    if is_custom_bind {
                        // The user manually wrote a specific bind IP —
                        // don't let the checkbox stomp on it. Show what
                        // they have and tell them to edit config.json
                        // if they want to change it.
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(format!(
                                "Custom bind: {}",
                                listen_host_snapshot
                            )).color(egui::Color32::from_rgb(220, 180, 100)));
                            ui.small("Edit `listen_host` in config.json to change.");
                        });
                    } else {
                        let mut share = was_share_on_lan;
                        if ui.checkbox(&mut share, "Share with other devices on my Wi-Fi / network").changed() {
                            new_listen_host = Some(if share {
                                "0.0.0.0".to_string()
                            } else {
                                "127.0.0.1".to_string()
                            });
                        }
                        if share {
                            // detect_lan_ip() opens a UDP socket and
                            // asks the kernel which interface a packet
                            // to a public IP would use. Cheap (no
                            // syscall does network I/O) and accurate
                            // (it's the same selection any outbound
                            // connection would make).
                            match detect_lan_ip() {
                                Some(ip) => {
                                    let port = if listen_port_snapshot.is_empty() {
                                        "8085"
                                    } else {
                                        listen_port_snapshot.as_str()
                                    };
                                    let socks_port = if socks5_port_snapshot.is_empty() {
                                        "8086"
                                    } else {
                                        socks5_port_snapshot.as_str()
                                    };
                                    ui.small(egui::RichText::new(format!(
                                        "Other devices: HTTP {}:{}  ·  SOCKS5 {}:{}",
                                        ip, port, ip, socks_port,
                                    )).color(egui::Color32::from_rgb(120, 200, 140)));
                                }
                                None => {
                                    ui.small(egui::RichText::new(
                                        "Couldn't detect your LAN IP. Find it in System Settings \
                                         → Network → Wi-Fi → Details (macOS) or `ipconfig` (Windows)."
                                    ).color(egui::Color32::from_rgb(220, 180, 100)));
                                }
                            }
                        }
                    }
                });
                if let Some(updated) = new_listen_host {
                    self.form.listen_host = updated;
                }

                ui.horizontal(|ui| {
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::Label::new(egui::RichText::new("Ports")
                            .color(egui::Color32::from_gray(200))),
                    );
                    let http_label = ui.label(egui::RichText::new("HTTP").small());
                    let http_resp = ui.add(egui::TextEdit::singleline(&mut self.form.listen_port)
                        .desired_width(70.0))
                    .labelled_by(http_label.id);
                    if let Some(h) = listener_hover { http_resp.on_hover_text(h); }
                    ui.add_space(10.0);
                    let socks_label = ui.label(egui::RichText::new("SOCKS5").small());
                    let socks_resp = ui.add(egui::TextEdit::singleline(&mut self.form.socks5_port)
                        .desired_width(70.0))
                    .labelled_by(socks_label.id);
                    if let Some(h) = listener_hover { socks_resp.on_hover_text(h); }
                });
                if proxy_active_for_listeners {
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.small(
                            egui::RichText::new(
                                "Listen host / ports are bound at Start — Stop the proxy to change them.",
                            )
                            .color(egui::Color32::from_gray(150)),
                        );
                    });
                }
                });
            });

            // ── Section: Advanced (collapsed by default) ──────────────────
            ui.add_space(6.0);
            egui::CollapsingHeader::new(
                egui::RichText::new("Advanced")
                    .size(12.0)
                    .color(egui::Color32::from_gray(180))
                    .strong(),
            )
            .default_open(false)
            .show(ui, |ui| {
                let frame = egui::Frame::none()
                    .fill(egui::Color32::from_rgb(28, 30, 34))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 54, 60)))
                    .rounding(6.0)
                    .inner_margin(egui::Margin::same(10.0));
                frame.show(ui, |ui| {
                    form_row(ui, "Upstream SOCKS5", Some(
                        "Optional. host:port of a local xray / v2ray / sing-box SOCKS5 inbound. \
                         When set, non-HTTP / raw-TCP traffic (Telegram MTProto, IMAP, SSH, …) \
                         is chained through it instead of direct. HTTP/HTTPS still go through \
                         the Apps Script relay."
                    ), |ui, label_id| {
                        ui.add(egui::TextEdit::singleline(&mut self.form.upstream_socks5)
                            .hint_text("empty = direct; 127.0.0.1:50529 for local xray")
                            .desired_width(f32::INFINITY))
                        .labelled_by(label_id);
                    });

                    form_row(ui, "Parallel dispatch", Some(
                        "Fire N Apps Script IDs in parallel per request and take the first \
                         response. 0/1 = off. 2-3 kills long-tail latency at N× quota cost. \
                         Only effective with multiple IDs configured."
                    ), |ui, _label_id| {
                        ui.add(egui::DragValue::new(&mut self.form.parallel_relay)
                            .speed(1)
                            .range(0..=8));
                    });

                    form_row(ui, "Log level", None, |ui, _label_id| {
                        egui::ComboBox::from_id_source("loglevel")
                            .selected_text(&self.form.log_level)
                            .show_ui(ui, |ui| {
                                for lvl in ["warn", "info", "debug", "trace"] {
                                    ui.selectable_value(&mut self.form.log_level, lvl.into(), lvl);
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.verify_ssl, "Verify TLS server certificate (recommended)");
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.show_auth_key, "Show auth key");
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.normalize_x_graphql, "Normalize X/Twitter GraphQL URLs")
                            .on_hover_text(
                                "Trim the `features` / `fieldToggles` query params from x.com/i/api/graphql/… \
                                 requests before relaying. Massively improves cache hit rate when browsing \
                                 Twitter/X. Off by default — some endpoints may reject trimmed requests. \
                                 Credit: seramo_ir + Persian Python community (issue #16).",
                            );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(
                            &mut self.form.youtube_via_relay,
                            "Send YouTube through relay (no SNI rewrite)",
                        )
                        .on_hover_text(
                            "YouTube normally uses the same direct Google-edge tunnel as google.com (TLS SNI is \
                             the front domain, not youtube.com). That can trigger restricted mode or sign-out \
                             prompts. Enable this to route youtube.com / youtu.be / ytimg.com through the Apps \
                             Script relay instead — slower for video, but the visible SNI matches the site.",
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.block_quic, "Block QUIC (UDP/443)")
                            .on_hover_text(
                                "Drop QUIC (UDP port 443) so browsers fall back to TCP/HTTPS. \
                                 QUIC over the TCP-based tunnel causes TCP-over-TCP meltdown \
                                 (<1 Mbps). Browsers detect the drop and switch to TCP within seconds. \
                                 Issue #213, #793.",
                            );
                    });

                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.block_stun, "Block STUN/TURN UDP")
                            .on_hover_text(
                                "Opt-in: drop WebRTC STUN/TURN UDP ports 3478, 5349, and 19302 \
                                 so apps such as Meet, Discord, and WhatsApp move to TCP TURN \
                                 instead of waiting on UDP ICE retries. Off by default so existing \
                                 configs behave the same after upgrade.",
                            );
                    });

                    // Curated fronting-group loader. The full list shipped
                    // in `assets/fronting-groups/curated.json` covers
                    // Vercel, Fastly (reddit/cnn/python/github-content),
                    // AWS CloudFront (netlify), and direct-to-GitHub for
                    // gist + objects-origin. There's no editor for the
                    // groups in the UI yet — this button is the no-typing
                    // path to install the full set; hand-edited entries
                    // are preserved (collision is by group `name`).
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        let count = self.form.fronting_groups.len();
                        let label = format!(
                            "Load curated fronting groups (vercel, fastly, …)  ·  current: {}",
                            count
                        );
                        if ui.button(label)
                            .on_hover_text(
                                "Append the bundled curated fronting groups to your config. \
                                 Existing groups are preserved — entries with the same `name` \
                                 are skipped, never overwritten. Press Save config afterwards \
                                 to persist. Edge IPs may need refresh; see docs/fronting-groups.md."
                            )
                            .clicked()
                        {
                            match rahgozar::curated_groups::merge_into(&mut self.form.fronting_groups) {
                                Ok(report) => {
                                    self.toast = Some((
                                        format!(
                                            "Loaded curated groups: {} added, {} already present. \
                                             Press Save config to persist.",
                                            report.added, report.skipped,
                                        ),
                                        Instant::now(),
                                    ));
                                }
                                Err(e) => {
                                    self.toast = Some((
                                        format!("Could not load curated groups: {}", e),
                                        Instant::now(),
                                    ));
                                }
                            }
                        }
                    });
                });
            });

            // ── Custom parameters (advanced) ─────────────────────────────
            // Editable key-value table backed by `Config::extras`. Lets
            // power users add config.json fields the UI form doesn't
            // model (e.g. flags shipped by a newer build, hand-edited
            // tuning) and have them survive Save instead of being
            // silently dropped. Collapsed by default so the form stays
            // simple for the majority who don't need it. Feature #876.
            ui.add_space(6.0);
            egui::CollapsingHeader::new(format!(
                "Custom parameters ({})",
                self.form.custom_params_buffer.len(),
            ))
            .default_open(false)
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Extra config.json keys not covered by the form above. Values are \
                         parsed as JSON when possible (`true`, `42`, `[1,2]`, `{\"a\":1}`) \
                         and treated as plain strings otherwise. Save config persists them.",
                    )
                    .small()
                    .color(egui::Color32::from_gray(150)),
                );
                ui.add_space(4.0);
                let mut remove_idx: Option<usize> = None;
                egui::Grid::new("custom_params_grid")
                    .num_columns(3)
                    .spacing([6.0, 4.0])
                    .min_col_width(120.0)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("key").strong().small());
                        ui.label(egui::RichText::new("value (JSON or text)").strong().small());
                        ui.label("");
                        ui.end_row();
                        for (idx, (k, v)) in
                            self.form.custom_params_buffer.iter_mut().enumerate()
                        {
                            // Highlight rows whose key collides with a
                            // modeled field — `to_config()` will refuse
                            // to save them, so surface the conflict in
                            // the editor before the user hits Save.
                            let collides = !k.trim().is_empty()
                                && is_modeled_config_key(k);
                            let mut key_edit = egui::TextEdit::singleline(k)
                                // Hint must NOT name a modeled field
                                // (the collision check below would
                                // then reject the suggested example
                                // on save). Use a generic future-key
                                // shape instead.
                                .hint_text("my_future_field")
                                .desired_width(160.0);
                            if collides {
                                key_edit = key_edit.text_color(ERR_RED);
                            }
                            let key_resp = ui.add(key_edit);
                            if collides {
                                key_resp.on_hover_text(
                                    "This name is already controlled by the form above. \
                                     Save will fail until you rename or remove the row.",
                                );
                            }
                            ui.add(
                                egui::TextEdit::singleline(v)
                                    .hint_text("true / 42 / hello / [1,2]")
                                    .desired_width(f32::INFINITY),
                            );
                            if ui
                                .small_button("✕")
                                .on_hover_text("Remove this row.")
                                .clicked()
                            {
                                remove_idx = Some(idx);
                            }
                            ui.end_row();
                        }
                    });
                if let Some(i) = remove_idx {
                    self.form.custom_params_buffer.remove(i);
                }
                ui.add_space(2.0);
                if ui
                    .small_button("+ add parameter")
                    .on_hover_text(
                        "Add a new key/value row. Empty rows are dropped on save.",
                    )
                    .clicked()
                {
                    self.form
                        .custom_params_buffer
                        .push((String::new(), String::new()));
                }
            });

            // ── Bottom of form: Save + config-path hint ───────────────────
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add(primary_button("Save config")).clicked() {
                    match self.form.to_config().and_then(|c| save_config(&c)) {
                        Ok(p) => {
                            // Apply the new log level live so users don't have to
                            // restart for the combobox to take effect (#401).
                            apply_log_level(&self.form.log_level);
                            // Pull the just-normalized log colours back
                            // into the form so the colour-picker text
                            // fields show exactly what we wrote to disk.
                            // Without this, a bad hex entered by the
                            // user persists in the editor (and reverts
                            // to default at the renderer) — the file
                            // is healed but the UI still claims it
                            // isn't, which is confusing.
                            self.form.log_color_info = normalize_log_color(
                                &self.form.log_color_info,
                                rahgozar::config::DEFAULT_LOG_COLOR_INFO,
                            );
                            self.form.log_color_warn = normalize_log_color(
                                &self.form.log_color_warn,
                                rahgozar::config::DEFAULT_LOG_COLOR_WARN,
                            );
                            self.form.log_color_error = normalize_log_color(
                                &self.form.log_color_error,
                                rahgozar::config::DEFAULT_LOG_COLOR_ERROR,
                            );
                            // Invariant 2: `active = "name"` means the
                            // named profile's snapshot equals
                            // config.json. A regular Save config writes
                            // user-edited bytes that almost certainly
                            // diverge from any saved profile, so clear
                            // active. The user can re-bind via "Save as
                            // profile" if they want the live config
                            // tracked under a name again.
                            let mut pointer_warning: Option<String> = None;
                            if !self.profiles.active.is_empty() && self.profiles_load_ok {
                                let mut next = self.profiles.clone();
                                next.active = String::new();
                                match next.save() {
                                    Ok(()) => {
                                        self.profiles = next;
                                    }
                                    Err(e) => {
                                        // The config write succeeded but
                                        // we couldn't clear the stale
                                        // active marker. Surface that to
                                        // the user — the dropdown will
                                        // still claim the previous
                                        // profile matches the live
                                        // config when it no longer does.
                                        tracing::warn!(
                                            "profiles: clearing active on Save config failed: {}",
                                            e
                                        );
                                        pointer_warning = Some(format!("{}", e));
                                    }
                                }
                            }
                            self.toast = Some((
                                match pointer_warning {
                                    Some(w) => format!(
                                        "Saved to {}, but the active profile marker still points at '{}' (clearing it failed: {}). The dropdown will misclaim until you switch profiles or restart.",
                                        p.display(), self.profiles.active, w
                                    ),
                                    None => format!("Saved to {}", p.display()),
                                },
                                Instant::now(),
                            ));
                        }
                        Err(e) => self.toast = Some((format!("Save failed: {}", e), Instant::now())),
                    }
                }
                ui.small(egui::RichText::new(format!("→ {}", data_dir::config_path().display()))
                    .color(egui::Color32::from_gray(130)));
            });

            // Floating SNI editor window. Rendered here so it's inside the
            // same egui context but visually pops out with its own title bar.
            self.show_sni_editor(ctx);
            // Profile dialogs (Save as / Manage). Same pop-out treatment.
            self.show_save_as_dialog(ctx);
            self.show_manage_dialog(ctx);

            ui.add_space(8.0);

            // ── Status + stats card ────────────────────────────────────────
            let (running, started_at, stats, ca_trusted, last_test_msg, per_site) = {
                let s = self.shared.state.lock().unwrap();
                (
                    s.running,
                    s.started_at,
                    s.last_stats.clone(),
                    s.ca_trusted,
                    s.last_test_msg.clone(),
                    s.last_per_site.clone(),
                )
            };

            let status_title = if running {
                let up = started_at.map(|t| t.elapsed()).unwrap_or_default();
                format!("Traffic  ·  uptime {}", fmt_duration(up))
            } else {
                "Traffic  ·  (not running)".to_string()
            };
            section(ui, &status_title, |ui| {
                if let Some(s) = &stats {
                    // Compact two-column layout so 7 metrics fit in ~4 rows
                    // instead of a tall vertical strip.
                    let mut rows: Vec<(&str, String)> = vec![
                        ("relay calls", s.relay_calls.to_string()),
                        ("failures", s.relay_failures.to_string()),
                        ("coalesced", s.coalesced.to_string()),
                        (
                            "cache hits",
                            format!(
                                "{} / {}  ({:.0}%)",
                                s.cache_hits,
                                s.cache_hits + s.cache_misses,
                                s.hit_rate()
                            ),
                        ),
                        ("cache size", format!("{} KB", s.cache_bytes / 1024)),
                        ("bytes relayed", fmt_bytes(s.bytes_relayed)),
                        (
                            "active scripts",
                            format!(
                                "{} / {}",
                                s.total_scripts - s.blacklisted_scripts,
                                s.total_scripts
                            ),
                        ),
                    ];
                    // Forwarder rows only appear once the path filter
                    // has fired at least once — otherwise the typical
                    // (no-pattern-hit / non-AppsScript) user sees an
                    // empty pair of "0" rows that adds noise without
                    // signal. `err` is fast-path-miss count; combine
                    // with `relay_failures` to gauge end-to-end health.
                    if s.forwarder_calls + s.forwarder_errors > 0 {
                        rows.push((
                            "fwd calls",
                            format!(
                                "{} (err {})",
                                s.forwarder_calls, s.forwarder_errors
                            ),
                        ));
                        rows.push(("fwd bytes", fmt_bytes(s.forwarder_bytes)));
                    }
                    egui::Grid::new("stats")
                        .num_columns(4)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for chunk in rows.chunks(2) {
                                for (label, value) in chunk.iter() {
                                    ui.add_sized(
                                        [110.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(*label)
                                                .color(egui::Color32::from_gray(150)),
                                        ),
                                    );
                                    ui.add_sized(
                                        [140.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(value).monospace(),
                                        ),
                                    );
                                }
                                // Pad the final short row so grid columns stay aligned.
                                if chunk.len() == 1 {
                                    ui.label("");
                                    ui.label("");
                                }
                                ui.end_row();
                            }
                        });
                } else {
                    ui.label(
                        egui::RichText::new("No traffic yet — click Start and send a request.")
                            .color(egui::Color32::from_gray(150))
                            .italics(),
                    );
                }
            });

            // ── Usage today (estimated) — daily budget tracker ───────────────
            // Client-side estimate from our own atomic counters. Counts only
            // successful relay calls this process saw since 00:00 UTC. Google's
            // actual quota bucket is per-Apps-Script-project and per-Google
            // account — if multiple devices share the same deployment, each
            // client only sees its own share. We link to the Google dashboard
            // for the authoritative number.
            if let Some(s) = &stats {
                ui.add_space(2.0);
                section(ui, "Usage today (estimated)", |ui| {
                    // Free-tier Apps Script UrlFetchApp quota. Workspace /
                    // paid accounts get 100k but most users are on free.
                    const FREE_QUOTA_PER_DAY: u64 = 20_000;
                    let pct = if FREE_QUOTA_PER_DAY > 0 {
                        (s.today_calls as f64 / FREE_QUOTA_PER_DAY as f64) * 100.0
                    } else { 0.0 };
                    let reset = s.today_reset_secs;
                    let reset_str = format!(
                        "{}h {}m",
                        reset / 3600,
                        (reset / 60) % 60,
                    );
                    let rows: Vec<(&str, String)> = vec![
                        (
                            "calls today",
                            format!(
                                "{} / {}  ({:.1}%)",
                                s.today_calls, FREE_QUOTA_PER_DAY, pct
                            ),
                        ),
                        ("bytes today", fmt_bytes(s.today_bytes)),
                        ("PT day", s.today_key.clone()),
                        ("resets in", reset_str),
                    ];
                    egui::Grid::new("usage_today")
                        .num_columns(4)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for chunk in rows.chunks(2) {
                                for (label, value) in chunk.iter() {
                                    ui.add_sized(
                                        [110.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(*label)
                                                .color(egui::Color32::from_gray(150)),
                                        ),
                                    );
                                    ui.add_sized(
                                        [140.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(value).monospace(),
                                        ),
                                    );
                                }
                                if chunk.len() == 1 {
                                    ui.label("");
                                    ui.label("");
                                }
                                ui.end_row();
                            }
                        });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.hyperlink_to(
                            egui::RichText::new("View quota on Google →"),
                            "https://script.google.com/home/usage",
                        );
                        ui.label(
                            egui::RichText::new(
                                "  (authoritative — estimate is what this device relayed)",
                            )
                            .color(egui::Color32::from_gray(130))
                            .italics()
                            .small(),
                        );
                    });
                });
            }

            if !per_site.is_empty() {
                ui.add_space(2.0);
                egui::CollapsingHeader::new(format!("Per-site ({} hosts)", per_site.len()))
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(140.0)
                            .show(ui, |ui| {
                                egui::Grid::new("per_site")
                                    .num_columns(5)
                                    .spacing([8.0, 2.0])
                                    .striped(true)
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("host").strong());
                                        ui.label(egui::RichText::new("req").strong());
                                        ui.label(egui::RichText::new("hit%").strong());
                                        ui.label(egui::RichText::new("bytes").strong());
                                        ui.label(egui::RichText::new("avg ms").strong());
                                        ui.end_row();
                                        for (host, st) in per_site.iter().take(60) {
                                            let hit_pct = if st.requests > 0 {
                                                (st.cache_hits as f64 / st.requests as f64) * 100.0
                                            } else { 0.0 };
                                            ui.label(egui::RichText::new(host).monospace());
                                            ui.label(egui::RichText::new(st.requests.to_string()).monospace());
                                            ui.label(egui::RichText::new(format!("{:.0}%", hit_pct)).monospace());
                                            ui.label(egui::RichText::new(fmt_bytes(st.bytes)).monospace());
                                            ui.label(egui::RichText::new(format!("{:.0}", st.avg_latency_ms())).monospace());
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
            }

            ui.add_space(8.0);

            // ── Primary action: Start / Stop is the headline; others smaller ──
            // Gate on `proxy_active`, not `running`, so the in-between
            // "starting but not yet bound" window already shows Stop and
            // not Start. Without this:
            //   * a double-click would queue two `Cmd::Start`s — the
            //     bg-thread's `if active.is_some()` guard catches it but
            //     only because the first Start completed synchronously
            //     enough to set `active`; before this change the second
            //     click would silently send a second Start cmd.
            //   * a mode change in the gap between click and bg-thread
            //     processing reads `proxy_active = false`, doesn't send
            //     SwitchMode, and the runtime ends up serving the old
            //     mode while the form shows the new one.
            // Flipping proxy_active synchronously on click closes both.
            let proxy_active_now = self.shared.state.lock().unwrap().proxy_active;
            ui.horizontal(|ui| {
                if !proxy_active_now {
                    let btn = egui::Button::new(
                        egui::RichText::new("▶  Start").color(egui::Color32::WHITE).strong(),
                    )
                    .fill(OK_GREEN)
                    .min_size(egui::vec2(120.0, 32.0))
                    .rounding(4.0);
                    if ui.add(btn).clicked() {
                        match self.form.to_config() {
                            Ok(cfg) => {
                                // Flip BEFORE send so a same-frame mode
                                // change sees `proxy_active = true` and
                                // dispatches `Cmd::SwitchMode` correctly.
                                // The bg-thread will re-affirm this when
                                // it dequeues `Cmd::Start`, and will
                                // clear it on build-failure / self-exit /
                                // Cmd::Stop.
                                self.shared.state.lock().unwrap().proxy_active = true;
                                let _ = self.cmd_tx.send(Cmd::Start(cfg));
                            }
                            Err(e) => {
                                self.toast = Some((format!("Cannot start: {}", e), Instant::now()));
                            }
                        }
                    }
                } else {
                    let btn = egui::Button::new(
                        egui::RichText::new("■  Stop").color(egui::Color32::WHITE).strong(),
                    )
                    .fill(ERR_RED)
                    .min_size(egui::vec2(120.0, 32.0))
                    .rounding(4.0);
                    if ui.add(btn).clicked() {
                        let _ = self.cmd_tx.send(Cmd::Stop);
                    }
                }

                if ui.add(
                    egui::Button::new("Test relay")
                        .min_size(egui::vec2(0.0, 32.0))
                        .rounding(4.0),
                ).on_hover_text("Send one request through the Apps Script relay end-to-end and report the result.").clicked() {
                    match self.form.to_config() {
                        Ok(cfg) => {
                            let _ = self.cmd_tx.send(Cmd::Test(cfg));
                        }
                        Err(e) => {
                            self.toast = Some((format!("Cannot test: {}", e), Instant::now()));
                        }
                    }
                }
            });

            // Upstream-proxy hint: when running in direct mode, surface the
            // listen address with a one-click copy so users wiring this up as
            // Psiphon/xray's upstream don't have to read the config to find
            // the port. Direct mode is the only sane mode for that use case
            // — apps_script and full try to relay everything through Apps
            // Script, which breaks Psiphon's binary protocol. See
            // docs/use-as-upstream.md.
            //
            // The copied address is normalized via `advertise_proxy_host` so
            // a wildcard bind (`0.0.0.0`, `[::]`) becomes `127.0.0.1` for
            // same-device pasting — Winsock rejects `0.0.0.0` as a connect
            // target on Windows, so leaking the raw bind would break the
            // most common Psiphon-on-Windows setup. The LAN IP (for *other*
            // devices) is shown on a second line when the bind is wildcard.
            if running
                && (self.form.mode == "direct" || self.form.mode == "google_only")
            {
                ui.add_space(4.0);
                let port = if self.form.listen_port.trim().is_empty() {
                    "8085".to_string()
                } else {
                    self.form.listen_port.trim().to_string()
                };
                let same_device_host = advertise_proxy_host(&self.form.listen_host);
                let upstream = format!("{}:{}", same_device_host, port);
                ui.horizontal(|ui| {
                    ui.small(egui::RichText::new("Upstream for Psiphon / xray:")
                        .color(egui::Color32::from_gray(150)));
                    ui.small(egui::RichText::new(&upstream)
                        .monospace()
                        .color(OK_GREEN));
                    if ui.small_button("copy")
                        .on_hover_text("Paste into Psiphon → Options → Upstream Proxy (or xray's outbound HTTP).")
                        .clicked()
                    {
                        ui.output_mut(|o| o.copied_text = upstream.clone());
                        self.toast = Some((format!("Copied {}", upstream), Instant::now()));
                    }
                });
                // Second line: if the proxy is bound on all interfaces, show
                // the LAN IP so the user can also paste it on a phone or
                // second machine. Skipped when bound to loopback only —
                // there's no other-device address to advertise.
                if is_share_on_lan(&self.form.listen_host) {
                    if let Some(lan) = detect_lan_ip() {
                        let lan_upstream = format!("{}:{}", lan, port);
                        ui.horizontal(|ui| {
                            ui.small(egui::RichText::new("From another device on your network:")
                                .color(egui::Color32::from_gray(150)));
                            ui.small(egui::RichText::new(&lan_upstream)
                                .monospace()
                                .color(OK_GREEN));
                            if ui.small_button("copy")
                                .on_hover_text("Use this when Psiphon (or any client) runs on a different device on the same Wi-Fi.")
                                .clicked()
                            {
                                ui.output_mut(|o| o.copied_text = lan_upstream.clone());
                                self.toast = Some((format!("Copied {}", lan_upstream), Instant::now()));
                            }
                        });
                    }
                }
            }

            // Secondary actions — smaller, grouped together on their own line.
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                // Install CA and Remove CA share a single in-flight flag
                // so back-to-back clicks can't race — an in-flight
                // install would otherwise re-trust the CA after Remove
                // deleted it (or vice versa). Both buttons disable when
                // either op is running.
                let (cert_op_in_flight, proxy_active) = {
                    let s = self.shared.state.lock().unwrap();
                    (s.cert_op_in_progress, s.proxy_active)
                };

                let install_hover = if cert_op_in_flight {
                    "A cert install/remove is already in progress."
                } else {
                    "Install the MITM CA into the OS trust store (and NSS if certutil \
                     is available)."
                };
                ui.add_enabled_ui(!cert_op_in_flight, |ui| {
                    if ui
                        .small_button("Install CA")
                        .on_hover_text(install_hover)
                        .clicked()
                    {
                        let _ = self.cmd_tx.send(Cmd::InstallCa);
                    }
                });

                let remove_hover = if proxy_active || running {
                    "Stop the proxy first — the CA keypair is held in memory by the \
                     running MITM engine, and removing it now would break HTTPS for \
                     every site until restart."
                } else if cert_op_in_flight {
                    "A cert install/remove is already in progress."
                } else {
                    "Remove the MITM CA from the OS trust store (verified by name) \
                     and delete the on-disk ca/ directory. NSS cleanup (Firefox/Chrome) \
                     is best-effort and logs a hint if certutil is missing or a browser \
                     has the DB locked. A fresh CA is generated the next time you start \
                     the proxy. Your config.json and the Apps Script deployment are NOT \
                     touched — no need to redeploy Code.gs."
                };
                ui.add_enabled_ui(!proxy_active && !running && !cert_op_in_flight, |ui| {
                    if ui.small_button("Remove CA")
                        .on_hover_text(remove_hover)
                        .clicked()
                    {
                        let _ = self.cmd_tx.send(Cmd::RemoveCa);
                    }
                });
                if ui.small_button("Check CA").clicked() {
                    let _ = self.cmd_tx.send(Cmd::CheckCaTrusted);
                }
                if ui.small_button("Check for updates")
                    .on_hover_text(
                        "Ask GitHub's Releases API for the latest tag and compare against this \
                         running version. When the proxy is running, the request is tunnelled \
                         through it — so GitHub sees an Apps Script IP instead of your ISP IP \
                         (different rate-limit bucket, and works even if GitHub is blocked on \
                         your network). No background polling — only fires when you click."
                    )
                    .clicked()
                {
                    let route = self.update_check_route();
                    let _ = self.cmd_tx.send(Cmd::CheckUpdate { route });
                }
                let _ = ACCENT_HOVER; // silence unused const warning if it occurs
            });

            // ── Transient status line ─────────────────────────────────────
            // One compact line at most. Everything auto-hides after 10s so
            // stale messages don't keep pushing the log panel off-screen.
            // Priority: update-check in flight > fresh test msg > fresh CA
            // result > update-check result. Old/expired entries are dropped.
            const TRANSIENT_TTL: Duration = Duration::from_secs(10);
            let (test_msg_fresh, ca_trusted_fresh, update_check_fresh, download_fresh, install_fresh) = {
                let s = self.shared.state.lock().unwrap();
                (
                    s.last_test_msg_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                    s.ca_trusted_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                    s.last_update_check_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                    s.last_download_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                    // Install state stays "fresh" for as long as a successful
                    // staging is parked — TTL only applies to errors. We need
                    // the "Restart now" button to remain visible until the
                    // user acts on it.
                    s.install_in_progress
                        || matches!(s.last_install, Some(Ok(_)))
                        || s.last_install_at.map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                )
            };

            let mut shown_any = false;
            let update_is_inflight = matches!(
                self.shared.state.lock().unwrap().last_update_check,
                Some(UpdateProbeState::InFlight)
            );
            if update_is_inflight {
                ui.small(
                    egui::RichText::new("Checking for updates…")
                        .color(egui::Color32::GRAY),
                );
                shown_any = true;
            } else if update_check_fresh {
                let done = self.shared.state.lock().unwrap().last_update_check.clone();
                if let Some(UpdateProbeState::Done(r)) = done {
                    use rahgozar::update_check::UpdateCheck;
                    let color = match &r {
                        UpdateCheck::UpToDate { .. } => OK_GREEN,
                        UpdateCheck::UpdateAvailable { .. } => {
                            egui::Color32::from_rgb(220, 170, 80)
                        }
                        _ => ERR_RED,
                    };
                    ui.horizontal(|ui| {
                        ui.small(egui::RichText::new(r.summary()).color(color));
                        if let UpdateCheck::UpdateAvailable {
                            release_url, asset, ..
                        } = &r
                        {
                            ui.hyperlink_to("open release", release_url);
                            if let Some(a) = asset {
                                let (dl_in_flight, install_in_flight) = {
                                    let s = self.shared.state.lock().unwrap();
                                    (s.download_in_progress, s.install_in_progress)
                                };
                                if dl_in_flight {
                                    ui.small(
                                        egui::RichText::new("downloading…")
                                            .color(egui::Color32::GRAY),
                                    );
                                } else if install_in_flight {
                                    ui.small(
                                        egui::RichText::new("installing…")
                                            .color(egui::Color32::GRAY),
                                    );
                                } else {
                                    // Primary action: Install (download + verify
                                    // + extract + stage + restart). Secondary:
                                    // plain download, for users who'd rather
                                    // place the asset in Downloads and apply it
                                    // by hand.
                                    let install_btn = egui::Button::new(
                                        egui::RichText::new(format!(
                                            "⟳ Install update ({:.1} MB)",
                                            a.size_bytes as f64 / 1_048_576.0
                                        ))
                                        .color(egui::Color32::WHITE),
                                    )
                                    .fill(ACCENT)
                                    .rounding(4.0);
                                    if ui.add(install_btn).clicked() {
                                        let route = self.update_check_route();
                                        let _ = self.cmd_tx.send(Cmd::InstallUpdate {
                                            route,
                                            url: a.download_url.clone(),
                                            name: a.name.clone(),
                                        });
                                    }
                                    if ui.small_button(format!(
                                        "download only ({:.1} MB)",
                                        a.size_bytes as f64 / 1_048_576.0
                                    ))
                                    .clicked()
                                    {
                                        let route = self.update_check_route();
                                        let _ = self.cmd_tx.send(Cmd::DownloadUpdate {
                                            route,
                                            url: a.download_url.clone(),
                                            name: a.name.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    });
                    shown_any = true;
                }
            } else if test_msg_fresh && !last_test_msg.is_empty() {
                let color = if last_test_msg.starts_with("Test passed") {
                    OK_GREEN
                } else {
                    ERR_RED
                };
                ui.small(egui::RichText::new(last_test_msg).color(color));
                shown_any = true;
            } else if install_fresh {
                let install_state = {
                    let s = self.shared.state.lock().unwrap();
                    (s.install_in_progress, s.last_install.clone())
                };
                match install_state {
                    (true, _) => {
                        ui.small(
                            egui::RichText::new("Installing update… (downloading + verifying)")
                                .color(egui::Color32::GRAY),
                        );
                    }
                    (false, Some(Ok(staged))) => {
                        ui.horizontal(|ui| {
                            ui.small(
                                egui::RichText::new(format!(
                                    "Update staged → {}",
                                    staged.staged_path.display()
                                ))
                                .color(OK_GREEN),
                            );
                            let restart_btn = egui::Button::new(
                                egui::RichText::new("⟳ Restart now to apply")
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(ACCENT)
                            .rounding(4.0);
                            if ui.add(restart_btn).clicked() {
                                let _ = self.cmd_tx.send(Cmd::RestartToApply);
                            }
                        });
                    }
                    (false, Some(Err(msg))) => {
                        ui.small(
                            egui::RichText::new(format!("Install failed: {}", msg))
                                .color(ERR_RED),
                        );
                    }
                    (false, None) => {}
                }
                shown_any = true;
            } else if download_fresh {
                let dl = self.shared.state.lock().unwrap().last_download.clone();
                match dl {
                    Some(Ok(path)) => {
                        ui.horizontal(|ui| {
                            ui.small(
                                egui::RichText::new(format!("Downloaded → {}", path.display()))
                                    .color(OK_GREEN),
                            );
                            if ui.small_button("show in folder").clicked() {
                                reveal_in_file_manager(&path);
                            }
                        });
                    }
                    Some(Err(msg)) => {
                        ui.small(
                            egui::RichText::new(format!("Download failed: {}", msg))
                                .color(ERR_RED),
                        );
                    }
                    None => {
                        ui.small(
                            egui::RichText::new("Downloading…")
                                .color(egui::Color32::GRAY),
                        );
                    }
                }
                shown_any = true;
            } else if ca_trusted_fresh {
                match ca_trusted {
                    Some(true) => {
                        ui.small(
                            egui::RichText::new("CA appears trusted on this machine.")
                                .color(OK_GREEN),
                        );
                    }
                    Some(false) => {
                        ui.small(
                            egui::RichText::new(
                                "CA is NOT trusted in the system store. Click Install CA.",
                            )
                            .color(ERR_RED),
                        );
                    }
                    None => {}
                }
                shown_any = true;
            }
            // Reserve a line of space even when empty so the log below doesn't
            // jump when a transient message appears / disappears.
            if !shown_any {
                ui.small(" ");
            }

            ui.add_space(4.0);

            // ── Recent log ────────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Recent log").strong());
                ui.checkbox(&mut self.form.show_log, "show");
                let colors_label = if self.form.log_color_editor_open {
                    "colors ▾"
                } else {
                    "colors ▸"
                };
                if ui
                    .small_button(colors_label)
                    .on_hover_text("Customise the per-level log colours.")
                    .clicked()
                {
                    self.form.log_color_editor_open = !self.form.log_color_editor_open;
                }
                if ui.small_button("save…")
                    .on_hover_text(
                        "Write every line in the log panel to a timestamped file in the \
                         user-data dir. Useful for filing bug reports."
                    )
                    .clicked()
                {
                    let log = self.shared.state.lock().unwrap().log.clone();
                    let fname = format!(
                        "log-{}.txt",
                        time::OffsetDateTime::now_utc()
                            .format(&time::macros::format_description!(
                                "[year][month][day]-[hour][minute][second]"
                            ))
                            .unwrap_or_default(),
                    );
                    let path = data_dir::data_dir().join(&fname);
                    let body: String = log.iter().cloned().collect::<Vec<_>>().join("\n");
                    match std::fs::write(&path, body) {
                        Ok(_) => self.toast = Some((
                            format!("Log saved to {}", path.display()),
                            Instant::now(),
                        )),
                        Err(e) => self.toast = Some((
                            format!("Log save failed: {}", e),
                            Instant::now(),
                        )),
                    }
                }
                if ui.small_button("clear").clicked() {
                    self.shared.state.lock().unwrap().log.clear();
                }
            });
            if self.form.log_color_editor_open {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(28, 30, 34))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 54, 60)))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::same(6.0))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Per-level colours. Pick a swatch or type a hex code \
                                 (#RRGGBB). Save config to persist.",
                            )
                            .small()
                            .color(egui::Color32::from_gray(150)),
                        );
                        ui.add_space(2.0);
                        log_color_row(
                            ui,
                            "INFO",
                            &mut self.form.log_color_info,
                            rahgozar::config::DEFAULT_LOG_COLOR_INFO,
                        );
                        log_color_row(
                            ui,
                            "WARN",
                            &mut self.form.log_color_warn,
                            rahgozar::config::DEFAULT_LOG_COLOR_WARN,
                        );
                        log_color_row(
                            ui,
                            "ERROR",
                            &mut self.form.log_color_error,
                            rahgozar::config::DEFAULT_LOG_COLOR_ERROR,
                        );
                    });
                ui.add_space(2.0);
            }
            if self.form.show_log {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(22, 23, 26))
                    .stroke(egui::Stroke::new(
                        1.0,
                        egui::Color32::from_rgb(45, 48, 52),
                    ))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::same(6.0))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(220.0)
                            .min_scrolled_height(220.0)
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                let log = self.shared.state.lock().unwrap().log.clone();
                                if log.is_empty() {
                                    ui.small(
                                        egui::RichText::new("(empty — run some traffic or click Test)")
                                            .color(egui::Color32::from_gray(120))
                                            .italics(),
                                    );
                                }
                                // Resolve the user's colour preferences once
                                // outside the line loop. `parse_hex_color`
                                // falls back to the compiled default on bad
                                // input so a typo in config.json doesn't
                                // crash the UI — colours just revert.
                                let c_info = parse_hex_color(&self.form.log_color_info)
                                    .unwrap_or_else(|| {
                                        parse_hex_color(
                                            rahgozar::config::DEFAULT_LOG_COLOR_INFO,
                                        )
                                        .unwrap()
                                    });
                                let c_warn = parse_hex_color(&self.form.log_color_warn)
                                    .unwrap_or_else(|| {
                                        parse_hex_color(
                                            rahgozar::config::DEFAULT_LOG_COLOR_WARN,
                                        )
                                        .unwrap()
                                    });
                                let c_err = parse_hex_color(&self.form.log_color_error)
                                    .unwrap_or_else(|| {
                                        parse_hex_color(
                                            rahgozar::config::DEFAULT_LOG_COLOR_ERROR,
                                        )
                                        .unwrap()
                                    });
                                for line in log.iter() {
                                    let color = match classify_log_line(line) {
                                        Some(LogLevel::Info) => c_info,
                                        Some(LogLevel::Warn) => c_warn,
                                        Some(LogLevel::Error) => c_err,
                                        None => LOG_DEFAULT_TEXT,
                                    };
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(line)
                                                .monospace()
                                                .size(11.0)
                                                .color(color),
                                        )
                                        .wrap(),
                                    );
                                }
                            });
                    });
            }

            // Transient toast at the bottom. Config-load failures stick for
            // 30s instead of 5 because they explain why the form looks empty.
            if let Some((msg, t)) = &self.toast {
                let ttl = if msg.contains("failed to load") {
                    Duration::from_secs(30)
                } else {
                    Duration::from_secs(5)
                };
                if t.elapsed() < ttl {
                    ui.add_space(4.0);
                    ui.colored_label(egui::Color32::from_rgb(200, 170, 80), msg);
                } else {
                    self.toast = None;
                }
            }
                }); // end ScrollArea
        });
    }
}

impl App {
    /// Pick the route for an update-check or download request: if the
    /// proxy is running and we have a local HTTP listen_port, tunnel
    /// through it (GitHub sees Apps Script's IP instead of the user's
    /// rate-limited ISP IP). Otherwise go direct.
    fn update_check_route(&self) -> rahgozar::update_check::Route {
        let running = self.shared.state.lock().unwrap().running;
        if running {
            if let Ok(port) = self.form.listen_port.trim().parse::<u16>() {
                let host = if self.form.listen_host.trim().is_empty() {
                    "127.0.0.1".to_string()
                } else {
                    self.form.listen_host.trim().to_string()
                };
                return rahgozar::update_check::Route::Proxy { host, port };
            }
        }
        rahgozar::update_check::Route::Direct
    }

    /// Top-of-form profile bar: dropdown selector + "Save as profile" +
    /// "Manage" buttons. Switching a profile writes its stored config
    /// snapshot to `config.json` and reloads the form from there, so the
    /// runtime path (read `config.json`) stays unchanged.
    fn show_profile_bar(&mut self, ui: &mut egui::Ui) {
        let active = self.profiles.active.clone();
        let names = self.profiles.names();
        // Disable profile switching AND Save-as while the proxy is
        // running. The running ProxyServer task holds a Config that
        // was cloned at Cmd::Start time and won't pick up a new
        // config.json, so any write here would create a UI/runtime
        // drift. Save-as currently rewrites config.json (so the
        // active marker can truthfully claim "matches live config"),
        // which means it has the same drift problem as switching.
        // Manage stays enabled — rename / duplicate / delete don't
        // touch config.json.
        let running = self.shared.state.lock().unwrap().running;

        // Declared outside the horizontal closure so we can read it back
        // after the click handlers have run and the borrow on `ui` is
        // released — switching profile mutates self, which collides with
        // any borrow held inside the closure.
        let mut chosen: Option<String> = None;
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Profile")
                    .size(12.0)
                    .color(egui::Color32::from_gray(180))
                    .strong(),
            );
            let selected_label = if active.is_empty() {
                "(none)".to_string()
            } else {
                active.clone()
            };
            let combo =
                egui::ComboBox::from_id_source("profile_picker").selected_text(selected_label);
            ui.add_enabled_ui(!running, |ui| {
                let resp = combo.show_ui(ui, |ui| {
                    if names.is_empty() {
                        ui.label(
                            egui::RichText::new("no profiles saved yet")
                                .color(egui::Color32::from_gray(140))
                                .italics(),
                        );
                    } else {
                        for name in &names {
                            if ui.selectable_label(active == *name, name.clone()).clicked() {
                                chosen = Some(name.clone());
                            }
                        }
                    }
                });
                if running {
                    resp.response.on_hover_text(
                        "Stop the proxy first — profile switching takes effect on \
                         the next Start, and swapping the live config underneath \
                         a running proxy would only confuse things.",
                    );
                }
            });

            // Gate Save-as on (a) profiles.json being loadable AND
            // (b) the proxy not running. The corrupt-on-disk case
            // would clobber the recoverable bytes; the running case
            // would put config.json out of sync with the cloned
            // Config inside the running ProxyServer task.
            let save_as_enabled = self.profiles_load_ok && !running;
            ui.add_enabled_ui(save_as_enabled, |ui| {
                let resp = ui.button("Save as profile…").on_hover_text(
                    "Capture the current form (deployment IDs, mode, auth key, \
                         and all tuning knobs) under a name so you can switch back \
                         to it later.",
                );
                if resp.clicked() {
                    self.save_as_dialog = Some(SaveAsState::default());
                }
                if !self.profiles_load_ok {
                    resp.on_hover_text(
                        "Profiles disabled: profiles.json on disk is unreadable. \
                         Move it aside manually, then restart.",
                    );
                } else if running {
                    resp.on_hover_text(
                        "Stop the proxy first — Save as profile rewrites config.json \
                         to make the active marker truthful, which would put the live \
                         config out of sync with the running proxy's cloned config.",
                    );
                }
            });

            ui.add_enabled_ui(self.profiles_load_ok && !names.is_empty(), |ui| {
                if ui
                    .button("Manage…")
                    .on_hover_text("Rename, duplicate, or delete saved profiles.")
                    .clicked()
                {
                    self.manage_dialog = Some(ManageState::default());
                }
            });
        });

        if let Some(name) = chosen {
            self.switch_to_profile(&name);
        }
    }

    /// Switch the live config to a stored profile: write the profile's
    /// snapshot to `config.json`, reload the form from disk, update the
    /// profiles file's active pointer. Toasts on either outcome.
    ///
    /// The snapshot is applied RAW (invariant 1 in `src/profiles.rs`) —
    /// any config fields this build doesn't model still survive in the
    /// live config.
    fn switch_to_profile(&mut self, name: &str) {
        // Three distinct outcomes from apply_profile:
        //   - Err — nothing changed on disk. Toast the error verbatim.
        //   - Ok(ApplyOutcome::Ok) — both writes succeeded.
        //   - Ok(ApplyOutcome::PartialConfigOnly(e)) — config.json IS
        //     the new profile but the active pointer didn't save.
        //     Treat as "switched" for the form reload, but surface the
        //     carried error so the user knows the dropdown's marker is
        //     stale.
        let pointer_warning = match profiles::apply_profile(name) {
            Err(e) => {
                self.toast = Some((format!("Switch failed: {}", e), Instant::now()));
                return;
            }
            Ok(profiles::ApplyOutcome::Ok) => None,
            Ok(profiles::ApplyOutcome::PartialConfigOnly(e)) => Some(format!("{}", e)),
        };
        // Reload the profile store so the active pointer reflects the
        // switch (apply_profile updated it on disk — unless we got
        // PartialConfigOnly, in which case the on-disk pointer is
        // stale; we still reload so any other concurrent changes show
        // up correctly).
        match ProfilesFile::load() {
            Ok(pf) => self.profiles = pf,
            Err(e) => {
                tracing::warn!("profiles: reload after switch failed: {}", e);
            }
        }
        // Reload the form from the new config.json. A warning load_err is
        // surfaced as a toast — the user notices but doesn't get stuck.
        let (new_form, load_err) = load_form();
        self.form = new_form;
        apply_log_level(&self.form.log_level);
        let msg = match (pointer_warning, load_err) {
            (Some(ptr), Some(le)) => format!(
                "Switched to '{}' (live config updated) but pointer save failed: {}; also: {}",
                name, ptr, le
            ),
            (Some(ptr), None) => format!(
                "Switched to '{}' (live config updated) but profile pointer save failed: {}",
                name, ptr
            ),
            (None, Some(le)) => format!("Switched to '{}' but: {}", name, le),
            (None, None) => format!("Switched to profile '{}'", name),
        };
        self.toast = Some((msg, Instant::now()));
    }

    /// Modal: "Save as new profile" name prompt. Validates non-empty and
    /// non-duplicate (offers an "overwrite existing" path when the name
    /// already exists).
    fn show_save_as_dialog(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let Some(state) = self.save_as_dialog.as_mut() else {
            return;
        };
        // Snapshot what we need so we can mutate self after the window closes.
        let mut commit: Option<(String, bool)> = None; // (name, overwrite)
        egui::Window::new("Save as profile")
            .collapsible(false)
            .resizable(false)
            .default_width(360.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, -40.0))
            .show(ctx, |ui| {
                ui.label("Profile name:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.name)
                        .desired_width(f32::INFINITY)
                        .hint_text("e.g. Apps Script (home) or Full tunnel (work)"),
                );
                if resp.changed() {
                    state.error = None;
                }
                if let Some(err) = &state.error {
                    ui.colored_label(ERR_RED, err);
                }
                let trimmed = state.name.trim().to_string();
                let exists = !trimmed.is_empty() && self.profiles.find(&trimmed).is_some();
                if exists {
                    ui.small(
                        egui::RichText::new(format!(
                            "A profile named '{}' already exists.",
                            trimmed
                        ))
                        .color(egui::Color32::from_rgb(220, 180, 100)),
                    );
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let save_label = if exists { "Overwrite" } else { "Save" };
                    let save_enabled = !trimmed.is_empty();
                    if ui
                        .add_enabled(save_enabled, egui::Button::new(save_label))
                        .clicked()
                    {
                        commit = Some((trimmed.clone(), exists));
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });

        if let Some((name, overwrite)) = commit {
            match self.save_form_as_profile(&name, overwrite) {
                Ok(()) => {
                    self.toast = Some((format!("Saved profile '{}'", name), Instant::now()));
                    close = true;
                }
                Err(msg) => {
                    if let Some(state) = self.save_as_dialog.as_mut() {
                        state.error = Some(msg);
                    }
                }
            }
        }

        if close {
            self.save_as_dialog = None;
        }
    }

    /// Save the current form as a named profile.
    ///
    /// Write order: **`config.json` FIRST, then `profiles.json`**.
    /// This is the safe order because:
    ///   - If `config.json` fails, neither file changes; nothing to
    ///     roll back (invariant 3).
    ///   - If `profiles.json` fails after `config.json` succeeded, the
    ///     live config now reflects the form — equivalent to the user
    ///     having clicked Save config — but no profile entry was
    ///     added/updated. Invariant 2 holds: we never wrote an
    ///     `active` claim we couldn't back up.
    ///
    /// The previous order (profiles.json first) had a corruption bug:
    /// on overwrite, the profile's snapshot was already replaced
    /// before we knew whether config.json would land, so a failed
    /// config write left profile "name" pointing at bytes that
    /// nothing on disk matched.
    fn save_form_as_profile(&mut self, name: &str, overwrite: bool) -> Result<(), String> {
        if !self.profiles_load_ok {
            return Err(
                "profiles.json on disk is unreadable; refusing to overwrite. \
                 Move it aside manually, then restart."
                    .into(),
            );
        }
        let cfg = self
            .form
            .to_config()
            .map_err(|e| format!("Form is invalid: {}", e))?;
        let wire = ConfigWire::from(&cfg);
        let value = serde_json::to_value(&wire).map_err(|e| format!("serialize failed: {}", e))?;

        // Pre-validate the profile mutation would succeed (collision /
        // empty-name checks) BEFORE touching config.json, so we don't
        // commit the live config and then discover the profile
        // operation is rejected.
        let mut next = self.profiles.clone();
        if overwrite {
            next.upsert(name, value.clone())
                .map_err(|e| format!("{}", e))?;
        } else {
            next.insert_new(name, value.clone())
                .map_err(|e| format!("{}", e))?;
        }

        // Step 1: write the snapshot to config.json. On failure,
        // neither file has changed.
        profiles::write_config_json(&value)
            .map_err(|e| format!("write config.json failed: {}", e))?;

        // Step 2: write profiles.json with the new entry + active=name.
        // On failure here, config.json is already the new bytes but no
        // profile entry exists. We surface this as "PartialConfigOnly"
        // text so the user understands the live config DID change but
        // the profile didn't save.
        match next.save() {
            Ok(()) => {
                self.profiles = next;
                let (new_form, _) = load_form();
                self.form = new_form;
                apply_log_level(&self.form.log_level);
                Ok(())
            }
            Err(e) => {
                // config.json IS the new bytes — refresh the form so
                // the UI reflects that — but report the profile save
                // failure honestly.
                let (new_form, _) = load_form();
                self.form = new_form;
                apply_log_level(&self.form.log_level);
                Err(format!(
                    "Live config saved, but writing the profile entry failed: {}. \
                     Retry to save the profile.",
                    e
                ))
            }
        }
    }

    /// Modal: "Manage profiles". Lists every saved profile with rename,
    /// duplicate, and delete actions. All mutations write through to disk
    /// immediately.
    fn show_manage_dialog(&mut self, ctx: &egui::Context) {
        if self.manage_dialog.is_none() {
            return;
        }
        // Use a local "close" sentinel and only mutate self.manage_dialog
        // at the very end — egui's Window::open borrow conflicts with
        // mid-frame mutations.
        let mut close = false;
        let names = self.profiles.names();
        let active = self.profiles.active.clone();
        // Collected actions to apply after the closure (mutating
        // self.profiles inside would tangle with the &mut borrow on
        // self.manage_dialog).
        enum Action {
            CommitRename { from: String, to: String },
            Duplicate(String),
            Delete(String),
        }
        let mut pending: Option<Action> = None;

        egui::Window::new("Manage profiles")
            .collapsible(false)
            .resizable(true)
            .default_size(egui::vec2(460.0, 360.0))
            .show(ctx, |ui| {
                let state = self.manage_dialog.as_mut().unwrap();
                if let Some(err) = &state.error {
                    ui.colored_label(ERR_RED, err);
                    ui.add_space(4.0);
                }
                if names.is_empty() {
                    ui.label(
                        egui::RichText::new("No profiles saved yet.")
                            .italics()
                            .color(egui::Color32::from_gray(160)),
                    );
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        for name in &names {
                            ui.horizontal(|ui| {
                                let is_active = *name == active;
                                if is_active {
                                    ui.label(egui::RichText::new("●").color(OK_GREEN).strong())
                                        .on_hover_text("Active profile");
                                } else {
                                    ui.label("  ");
                                }
                                if state.renaming.as_deref() == Some(name.as_str()) {
                                    let buf = state
                                        .rename_buf
                                        .entry(name.clone())
                                        .or_insert_with(|| name.clone());
                                    ui.add(egui::TextEdit::singleline(buf).desired_width(180.0));
                                    if ui.button("OK").clicked() {
                                        let to = buf.clone();
                                        pending = Some(Action::CommitRename {
                                            from: name.clone(),
                                            to,
                                        });
                                    }
                                    if ui.button("Cancel").clicked() {
                                        state.renaming = None;
                                        state.rename_buf.remove(name);
                                        state.error = None;
                                    }
                                } else if state.pending_delete.as_deref() == Some(name.as_str()) {
                                    // Confirm-delete row: replaces the
                                    // usual action buttons with an
                                    // explicit "Confirm delete?" prompt.
                                    // Profile data may be the user's
                                    // only copy, so we don't want a
                                    // single accidental click to take
                                    // it out.
                                    ui.label(
                                        egui::RichText::new(format!("Delete '{}'?", name))
                                            .color(ERR_RED)
                                            .strong(),
                                    );
                                    let confirm = egui::Button::new(
                                        egui::RichText::new("Confirm delete")
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(ERR_RED)
                                    .rounding(4.0);
                                    if ui.add(confirm).clicked() {
                                        pending = Some(Action::Delete(name.clone()));
                                    }
                                    if ui.small_button("Cancel").clicked() {
                                        state.pending_delete = None;
                                        state.error = None;
                                    }
                                } else {
                                    ui.label(egui::RichText::new(name.clone()).monospace());
                                    if ui.small_button("Rename").clicked() {
                                        state.renaming = Some(name.clone());
                                        state.error = None;
                                    }
                                    if ui.small_button("Duplicate").clicked() {
                                        pending = Some(Action::Duplicate(name.clone()));
                                    }
                                    if ui.small_button("Delete").clicked() {
                                        state.pending_delete = Some(name.clone());
                                        state.error = None;
                                    }
                                }
                            });
                            ui.add_space(2.0);
                        }
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
            });

        if let Some(action) = pending {
            if !self.profiles_load_ok {
                let state = self.manage_dialog.as_mut().unwrap();
                state.error = Some(
                    "profiles.json on disk is unreadable; refusing to overwrite. \
                     Move it aside manually, then restart."
                        .into(),
                );
                if close {
                    self.manage_dialog = None;
                }
                return;
            }
            // Transactional: mutate a clone, save, only assign back on
            // success. A failed disk write thus leaves both the
            // in-memory state and the on-disk file unchanged
            // (invariant 3 in src/profiles.rs).
            let mut next = self.profiles.clone();
            let outcome: Result<(), String> = match &action {
                Action::CommitRename { from, to } => {
                    next.rename(from, to).map_err(|e| format!("{}", e))
                }
                Action::Duplicate(name) => {
                    // Pick a unique copy name: "name (copy)", "name (copy 2)", …
                    let mut candidate = format!("{} (copy)", name);
                    let mut n = 2;
                    while next.find(&candidate).is_some() {
                        candidate = format!("{} (copy {})", name, n);
                        n += 1;
                    }
                    next.duplicate(name, &candidate)
                        .map_err(|e| format!("{}", e))
                }
                Action::Delete(name) => next.delete(name).map_err(|e| format!("{}", e)),
            };
            let state = self.manage_dialog.as_mut().unwrap();
            match outcome.and_then(|_| next.save().map_err(|e| format!("save failed: {}", e))) {
                Ok(()) => {
                    // Disk write succeeded — now commit the new state.
                    self.profiles = next;
                    state.error = None;
                    match &action {
                        Action::CommitRename { from, .. } => {
                            state.renaming = None;
                            state.rename_buf.remove(from);
                        }
                        Action::Delete(_) => {
                            state.pending_delete = None;
                        }
                        Action::Duplicate(_) => {}
                    }
                }
                Err(e) => state.error = Some(e),
            }
        }

        if close {
            self.manage_dialog = None;
        }
    }

    /// Floating editor window for the SNI rotation pool. Opens from the
    /// **SNI pool…** button in the main form. The list is live-editable
    /// (reorder / toggle / add / remove); changes only persist when the user
    /// hits **Save config** in the main window. Probe results are cached in
    /// `UiState::sni_probe` so they survive opening and closing the editor.
    fn show_sni_editor(&mut self, ctx: &egui::Context) {
        if !self.form.sni_editor_open {
            return;
        }
        let mut keep_open = true;
        egui::Window::new("SNI rotation pool")
            .open(&mut keep_open)
            .resizable(true)
            .default_size(egui::vec2(520.0, 420.0))
            .min_width(460.0)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Which SNI names to rotate through when opening TLS connections \
                         to your Google IP. Some names may be locally blocked (Iran has \
                         dropped mail.google.com at times, for example); use the Test \
                         buttons to check — TLS handshake + HTTP HEAD against the \
                         configured google_ip, per name.",
                    )
                    .small(),
                );
                ui.add_space(4.0);

                // Action row.
                let google_ip = self.form.google_ip.trim().to_string();
                let probe_map = self.shared.state.lock().unwrap().sni_probe.clone();
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Test all").on_hover_text(
                        "Probe every SNI in the list against the configured google_ip in parallel."
                    ).clicked() {
                        let snis: Vec<String> = self
                            .form
                            .sni_pool
                            .iter()
                            .map(|r| r.name.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if !snis.is_empty() && !google_ip.is_empty() {
                            let _ = self.cmd_tx.send(Cmd::TestAllSni {
                                google_ip: google_ip.clone(),
                                snis,
                            });
                        }
                    }
                    if ui
                        .button("Keep working only")
                        .on_hover_text("Uncheck every SNI that didn't pass the last probe.")
                        .clicked()
                    {
                        for row in &mut self.form.sni_pool {
                            let ok = matches!(probe_map.get(&row.name), Some(SniProbeState::Ok(_)));
                            row.enabled = ok;
                        }
                    }
                    if ui.button("Enable all").clicked() {
                        for row in &mut self.form.sni_pool {
                            row.enabled = true;
                        }
                    }
                    if ui.button("Clear status").clicked() {
                        self.shared.state.lock().unwrap().sni_probe.clear();
                    }
                    if ui
                        .button("Reset to defaults")
                        .on_hover_text(
                            "Replace the list with the built-in Google SNI pool. Custom entries \
                         are dropped.",
                        )
                        .clicked()
                    {
                        self.form.sni_pool = DEFAULT_GOOGLE_SNI_POOL
                            .iter()
                            .map(|s| SniRow {
                                name: (*s).to_string(),
                                enabled: true,
                            })
                            .collect();
                        self.shared.state.lock().unwrap().sni_probe.clear();
                    }
                });
                ui.separator();

                // Main list — one horizontal row per SNI, explicit widths so
                // the domain text field gets the room it needs.
                let mut to_remove: Option<usize> = None;
                let mut test_name: Option<String> = None;
                const STATUS_W: f32 = 150.0;
                const NAME_W: f32 = 230.0;
                egui::ScrollArea::vertical()
                    .max_height(280.0)
                    .show(ui, |ui| {
                        for (i, row) in self.form.sni_pool.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut row.enabled, "");
                                let sni_label = ui.add_sized(
                                    [0.0, 0.0],
                                    egui::Label::new(
                                        egui::RichText::new(format!("SNI name {}", i))
                                            .color(egui::Color32::TRANSPARENT),
                                    ),
                                );
                                ui.add(
                                    egui::TextEdit::singleline(&mut row.name)
                                        .desired_width(NAME_W)
                                        .font(egui::TextStyle::Monospace),
                                )
                                .labelled_by(sni_label.id);
                                let status_txt = match probe_map.get(&row.name) {
                                    Some(SniProbeState::Ok(ms)) => {
                                        egui::RichText::new(format!("ok  {} ms", ms))
                                            .color(egui::Color32::from_rgb(80, 180, 100))
                                            .monospace()
                                    }
                                    Some(SniProbeState::Failed(e)) => {
                                        let short = if e.len() > 22 { &e[..22] } else { e };
                                        egui::RichText::new(format!("fail {}", short))
                                            .color(egui::Color32::from_rgb(220, 110, 110))
                                            .monospace()
                                    }
                                    Some(SniProbeState::InFlight) => {
                                        egui::RichText::new("testing…")
                                            .color(egui::Color32::GRAY)
                                            .monospace()
                                    }
                                    None => egui::RichText::new("untested")
                                        .color(egui::Color32::GRAY)
                                        .monospace(),
                                };
                                ui.add_sized(
                                    [STATUS_W, 18.0],
                                    egui::Label::new(status_txt).truncate(),
                                );
                                if ui.small_button("Test").clicked() {
                                    test_name = Some(row.name.clone());
                                }
                                if ui
                                    .small_button("remove")
                                    .on_hover_text("Remove this row")
                                    .clicked()
                                {
                                    to_remove = Some(i);
                                }
                            });
                        }
                    });

                if let Some(name) = test_name {
                    let name = name.trim().to_string();
                    if !name.is_empty() && !google_ip.is_empty() {
                        let _ = self.cmd_tx.send(Cmd::TestSni {
                            google_ip: google_ip.clone(),
                            sni: name,
                        });
                    }
                }
                if let Some(i) = to_remove {
                    self.form.sni_pool.remove(i);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    let custom_label = ui.add_sized(
                        [0.0, 0.0],
                        egui::Label::new(
                            egui::RichText::new("Custom SNI").color(egui::Color32::TRANSPARENT),
                        ),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.form.sni_custom_input)
                            .hint_text("add a custom SNI (e.g. translate.google.com)")
                            .desired_width(280.0),
                    )
                    .labelled_by(custom_label.id);
                    let add_clicked = ui.button("+ Add").clicked();
                    if add_clicked {
                        let new_name = self.form.sni_custom_input.trim().to_string();
                        if !new_name.is_empty()
                            && !self.form.sni_pool.iter().any(|r| r.name == new_name)
                        {
                            self.form.sni_pool.push(SniRow {
                                name: new_name.clone(),
                                enabled: true,
                            });
                            self.form.sni_custom_input.clear();
                            // Auto-probe the freshly added name so the user gets
                            // immediate feedback instead of a silent "untested"
                            // row. Needs a non-empty google_ip to have meaning.
                            if !google_ip.is_empty() {
                                let _ = self.cmd_tx.send(Cmd::TestSni {
                                    google_ip: google_ip.clone(),
                                    sni: new_name,
                                });
                            }
                        }
                    }
                });

                ui.add_space(6.0);
                ui.separator();
                ui.small(
                    "Changes take effect on the next Start of the proxy. \
                     Don't forget to press Save config in the main window to persist.",
                );
            });
        self.form.sni_editor_open = keep_open;
    }
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn fmt_bytes(b: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = K * K;
    const G: u64 = M * K;
    if b >= G {
        format!("{:.2} GB", b as f64 / G as f64)
    } else if b >= M {
        format!("{:.2} MB", b as f64 / M as f64)
    } else if b >= K {
        format!("{:.1} KB", b as f64 / K as f64)
    } else {
        format!("{} B", b)
    }
}

// ---------- Background thread: owns the tokio runtime + proxy lifecycle ----------

fn background_thread(shared: Arc<Shared>, rx: Receiver<Cmd>) {
    let rt = Runtime::new().expect("failed to create tokio runtime");

    let mut active: Option<(
        JoinHandle<()>,
        Arc<RuntimeState>,
        tokio::sync::oneshot::Sender<()>,
    )> = None;

    loop {
        // Reap a self-exited proxy task. Without this, a bind failure
        // (or any path where `server.run()` returns without going
        // through `Cmd::Stop`) leaves `active = Some(...)` pinning a
        // finished JoinHandle, and `Cmd::Start` rejects every future
        // start attempt with "already running" — even though the UI
        // shows "stopped" because the task body itself cleared
        // `running`/`proxy_active`. Polling `is_finished` each loop
        // iteration is cheap and matches the existing recv_timeout
        // cadence (~250 ms), which is well below human-perceptible
        // delay between a Stop and the next Start.
        //
        // Consolidates ALL finished-task cleanup in one place: the
        // previous shape had a footer at the bottom of the loop that
        // dropped `active` without `block_on`-ing the handle (so panics
        // disappeared into the runtime drop path) and only cleared
        // `running`/`started_at` (so an abnormally-ended task that
        // didn't reach its own cleanup block left `proxy_active` stuck
        // true — UI permanently in "starting"). Doing block_on +
        // defensive flag-clearing once here covers both gaps.
        if let Some((handle, _, _)) = &active {
            if handle.is_finished() {
                if let Some((handle, _, _)) = active.take() {
                    // Await the handle so a panic inside the task
                    // surfaces in the log instead of silently going to
                    // the runtime drop path. Best-effort: a successful
                    // join is the normal exit, JoinError covers panic
                    // and cancellation alike.
                    if let Err(e) = rt.block_on(handle) {
                        push_log(
                            &shared,
                            &format!("[ui] proxy task ended unexpectedly: {}", e),
                        );
                    }
                    // Defensive flag reset. The task body's cleanup
                    // block normally clears all three before exit, but
                    // a panic or external abort can bypass it. Clearing
                    // here is idempotent for the normal-exit case and
                    // load-bearing for the abnormal one.
                    let mut st = shared.state.lock().unwrap();
                    st.running = false;
                    st.started_at = None;
                    st.proxy_active = false;
                }
            }
        }

        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Cmd::PollStats) => {
                if let Some((_, state, _)) = &active {
                    // Read the *current* fronter from the live bundle —
                    // after a live mode switch this may be a different
                    // `Arc<DomainFronter>` than the one Start handed us,
                    // or `None` if the user switched to direct mode.
                    if let Some(fronter) = state.fronter() {
                        let shared = shared.clone();
                        rt.spawn(async move {
                            let s = fronter.snapshot_stats();
                            let per_site = fronter.snapshot_per_site();
                            let mut st = shared.state.lock().unwrap();
                            st.last_stats = Some(s);
                            st.last_per_site = per_site;
                        });
                    } else {
                        // No fronter in the current mode (direct). Clear
                        // any cached stats from a previous apps_script /
                        // full mode session so the UI doesn't show stale
                        // numbers next to a "Direct" badge.
                        let mut st = shared.state.lock().unwrap();
                        if st.last_stats.is_some() || !st.last_per_site.is_empty() {
                            st.last_stats = None;
                            st.last_per_site.clear();
                        }
                    }
                }
            }
            Ok(Cmd::Start(cfg)) => {
                if active.is_some() {
                    push_log(&shared, "[ui] already running");
                    continue;
                }
                push_log(&shared, "[ui] starting proxy...");
                // Flip proxy_active synchronously so a `Remove CA` click
                // queued in the same frame as Start is rejected before
                // the MITM manager begins loading.
                shared.state.lock().unwrap().proxy_active = true;

                // Build the proxy synchronously on this thread so we can
                // capture the `Arc<RuntimeState>` BEFORE spawning the run
                // future. The previous shape constructed inside the spawn
                // and stashed the fronter into an outer AsyncMutex slot;
                // with a swappable bundle we just hand the state out
                // directly. The MITM cert manager initialisation is also
                // sync and lives here so build failures abort cleanly.
                let base = data_dir::data_dir();
                let mitm = match MitmCertManager::new_in(&base) {
                    Ok(m) => m,
                    Err(e) => {
                        push_log(&shared, &format!("[ui] MITM init failed: {}", e));
                        let mut s = shared.state.lock().unwrap();
                        s.running = false;
                        s.proxy_active = false;
                        continue;
                    }
                };
                let mitm = Arc::new(AsyncMutex::new(mitm));
                let server = match ProxyServer::new(&cfg, mitm) {
                    Ok(s) => s,
                    Err(e) => {
                        push_log(&shared, &format!("[ui] proxy build failed: {}", e));
                        let mut st = shared.state.lock().unwrap();
                        st.running = false;
                        st.proxy_active = false;
                        continue;
                    }
                };
                let state = server.state();

                let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
                let shared2 = shared.clone();
                let cfg_for_log = cfg.clone();
                let handle = rt.spawn(async move {
                    {
                        let mut s = shared2.state.lock().unwrap();
                        s.running = true;
                        s.started_at = Some(Instant::now());
                    }
                    push_log(
                        &shared2,
                        &format!(
                            "[ui] listening HTTP {}:{} SOCKS5 {}:{}",
                            cfg_for_log.listen_host,
                            cfg_for_log.listen_port,
                            cfg_for_log.listen_host,
                            cfg_for_log
                                .socks5_port
                                .unwrap_or(cfg_for_log.listen_port + 1)
                        ),
                    );

                    if let Err(e) = server.run(shutdown_rx).await {
                        push_log(&shared2, &format!("[ui] proxy error: {}", e));
                    }

                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.running = false;
                        st.started_at = None;
                        // Self-exit path (e.g. bind error after startup,
                        // or normal shutdown without Cmd::Stop). The
                        // Stop handler clears this too — either is fine.
                        st.proxy_active = false;
                    }
                    push_log(&shared2, "[ui] proxy stopped");
                });

                active = Some((handle, state, shutdown_tx));
            }

            Ok(Cmd::SwitchMode(cfg)) => {
                if let Some((_, state, _)) = &active {
                    // Serial dispatch: `rt.block_on` waits for this
                    // switch to finish before the background thread
                    // services the next `Cmd::*`. Detached `rt.spawn`
                    // was the wrong shape — two rapid mode changes
                    // could spawn two switch tasks contending on
                    // `switch_lock` in arbitrary order, so the later
                    // dropdown choice could commit BEFORE the earlier
                    // one and end up overwritten. Serial dispatch
                    // makes "latest click wins" trivially true.
                    //
                    // switch_mode is sub-millisecond when the new
                    // mode is direct, low-millisecond when it has to
                    // build a fresh `DomainFronter` — no IO involved,
                    // so blocking the bg-thread loop briefly is fine
                    // and matches what `Cmd::Stop` already does.
                    push_log(&shared, "[ui] switching mode live...");
                    let result = rt.block_on(state.switch_mode(&cfg));
                    match result {
                        Ok(()) => {
                            push_log(
                                &shared,
                                &format!("[ui] mode switched live to '{}'", cfg.mode),
                            );
                            // Discard any pending revert left by a
                            // prior failed switch. Without this, a
                            // sequence (fail-A, succeed-B) could let
                            // the UI revert the form back from B to
                            // A's stale target on the next frame even
                            // though B is what's actually serving
                            // traffic. Clearing here makes "latest
                            // success wins" hold for the form too.
                            shared.state.lock().unwrap().mode_switch_revert = None;
                        }
                        // Stop racing with a queued SwitchMode is a
                        // designed no-op, not a failure. Don't toast
                        // it — the user just sees their click took
                        // effect ("proxy stopped") without a confusing
                        // "switch failed" pop-up. Debug log only.
                        Err(ProxyError::ShuttingDown) => {
                            push_log(&shared, "[ui] mode switch skipped (proxy stopping)");
                        }
                        Err(e) => {
                            let msg = format!("Live mode switch failed: {}", e);
                            push_log(&shared, &format!("[ui] {}", msg));
                            // Re-read the live mode AFTER the failed
                            // switch returns so the revert target is
                            // the runtime's actual current mode, not
                            // whatever was live at dispatch time.
                            let revert_to = state.current_mode().as_str().to_string();
                            let mut st = shared.state.lock().unwrap();
                            st.mode_switch_revert = Some((revert_to, msg));
                        }
                    }
                } else {
                    push_log(&shared, "[ui] not running; ignoring SwitchMode");
                }
            }

            Ok(Cmd::Stop) => {
                if let Some((mut handle, _, shutdown_tx)) = active.take() {
                    push_log(&shared, "[ui] stop requested");
                    let _ = shutdown_tx.send(());

                    // Give the proxy 2 seconds to shut down gracefully
                    rt.block_on(async {
                        tokio::select! {
                            _ = &mut handle => {
                                push_log(&shared, "[ui] proxy stopped gracefully");
                            }
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                                handle.abort();
                                let _ = handle.await;
                                push_log(&shared, "[ui] shutdown timeout, forced abort");
                            }
                        }
                    });

                    let mut st = shared.state.lock().unwrap();
                    st.running = false;
                    st.started_at = None;
                    st.proxy_active = false;
                }
            }

            Ok(Cmd::Test(cfg)) => {
                let shared2 = shared.clone();
                // Short-circuit modes where `test_cmd::run` deliberately
                // refuses (full mode, direct mode). Those return false
                // even when the proxy is healthy, which surfaced as
                // "Test failed" + alarming red status — see #665. Show
                // a friendly notice instead and skip the test path.
                let mode_kind = cfg.mode_kind().ok();
                let mode_explainer = match mode_kind {
                    Some(rahgozar::config::Mode::Full) => Some(
                        "Test Relay is wired only for apps_script mode. \
                         In full mode the data plane is the tunnel-node — \
                         to verify it end-to-end, start the proxy and load \
                         https://whatismyipaddress.com in your browser \
                         via 127.0.0.1:8085. The IP shown should be your \
                         tunnel-node's VPS IP. Tracking a real Full-mode \
                         test in #160.",
                    ),
                    Some(rahgozar::config::Mode::Direct) => Some(
                        "Test Relay is wired only for apps_script mode. \
                         In direct mode there is no Apps Script relay — \
                         every request goes through the SNI-rewrite tunnel \
                         straight to Google's edge. Verify by loading \
                         https://www.google.com via the proxy.",
                    ),
                    _ => None,
                };
                if let Some(msg) = mode_explainer {
                    {
                        let mut st = shared.state.lock().unwrap();
                        st.last_test_ok = None;
                        st.last_test_msg = msg.into();
                        st.last_test_msg_at = Some(Instant::now());
                    }
                    push_log(&shared, &format!("[ui] test skipped: {}", msg));
                    continue;
                }
                push_log(&shared, "[ui] running test...");
                rt.spawn(async move {
                    let ok = test_cmd::run(&cfg).await;
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.last_test_ok = Some(ok);
                        st.last_test_msg = if ok {
                            "Test passed — relay is working.".into()
                        } else {
                            "Test failed — see Recent log below for details.".into()
                        };
                        st.last_test_msg_at = Some(Instant::now());
                    }
                    push_log(
                        &shared2,
                        &format!("[ui] test result: {}", if ok { "pass" } else { "fail" }),
                    );
                    // Also run ip scan on demand (cheap).
                    let _ = scan_ips::run(&cfg).await;
                });
            }
            Ok(Cmd::InstallCa) => {
                // Share the cert-op flag with Remove CA so the two
                // can't race. Gate and flip before spawning; the worker
                // clears on exit.
                {
                    let mut st = shared.state.lock().unwrap();
                    if st.cert_op_in_progress {
                        push_log(
                            &shared,
                            "[ui] cert op already in progress — ignoring duplicate install",
                        );
                        continue;
                    }
                    st.cert_op_in_progress = true;
                }
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    push_log(&shared2, "[ui] installing CA...");
                    let base = data_dir::data_dir();
                    let result = (|| -> Result<(), String> {
                        if let Err(e) = MitmCertManager::new_in(&base) {
                            return Err(format!("CA init failed: {}", e));
                        }
                        let ca = base.join(CA_CERT_FILE);
                        install_ca(&ca).map_err(|e| format!("CA install failed: {}", e))
                    })();
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.cert_op_in_progress = false;
                        if result.is_ok() {
                            st.ca_trusted = Some(true);
                            st.ca_trusted_at = Some(Instant::now());
                        }
                    }
                    match result {
                        Ok(()) => push_log(&shared2, "[ui] CA install ok"),
                        Err(msg) => {
                            push_log(&shared2, &format!("[ui] {}", msg));
                            push_log(&shared2, "[ui] hint: run the terminal binary with sudo/admin: rahgozar --install-cert");
                        }
                    }
                });
            }
            Ok(Cmd::RemoveCa) => {
                // Authoritative proxy-active guard: the UI button is
                // disabled when proxy_active/running is set, but a
                // Cmd::RemoveCa may already be queued by the time the
                // Start handler flips the flag. `active` is owned by
                // this thread so its state is the real source of truth
                // — reject removal any time a proxy handle is alive,
                // whether it's still starting or fully running.
                if active.is_some() {
                    push_log(
                        &shared,
                        "[ui] cannot remove CA: proxy is running or starting — stop it first",
                    );
                    continue;
                }
                // Shared cert-op gate: covers Install CA too, so back-
                // to-back Install → Remove clicks can't race. The
                // button is already disabled while this is set, but a
                // queued command can still arrive here.
                {
                    let mut st = shared.state.lock().unwrap();
                    if st.cert_op_in_progress {
                        push_log(
                            &shared,
                            "[ui] cert op already in progress — ignoring duplicate remove",
                        );
                        continue;
                    }
                    st.cert_op_in_progress = true;
                }
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    push_log(&shared2, "[ui] removing CA (trust store + files)...");
                    let base = data_dir::data_dir();
                    let result = remove_ca(&base);
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.cert_op_in_progress = false;
                        if result.is_ok() {
                            st.ca_trusted = Some(false);
                            st.ca_trusted_at = Some(Instant::now());
                        }
                    }
                    match result {
                        Ok(outcome) => {
                            push_log(&shared2, &format!("[ui] {}", outcome.summary()));
                            push_log(
                                &shared2,
                                "[ui] config.json and Apps Script deployment untouched",
                            );
                        }
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] CA remove failed: {}", e));
                            push_log(&shared2, "[ui] hint: run the terminal binary with sudo/admin: rahgozar --remove-cert");
                        }
                    }
                });
            }
            Ok(Cmd::DiscoverFront { hostname }) => {
                // Mark in-flight synchronously so the UI's "Discover"
                // button can disable on the next frame instead of
                // letting the user double-tap. The background tokio
                // task fires off the DNS resolve + TLS probes and
                // writes the Done/Error variant when it completes.
                {
                    let mut st = shared.state.lock().unwrap();
                    st.discover_state = Some(DiscoverState::InFlight {
                        hostname: hostname.clone(),
                    });
                }
                let shared2 = shared.clone();
                rt.spawn(async move {
                    let result = discover_front(&hostname).await;
                    let new_state = match result {
                        Ok(df) => DiscoverState::Done(df),
                        Err(msg) => DiscoverState::Error {
                            hostname,
                            message: msg,
                        },
                    };
                    shared2.state.lock().unwrap().discover_state = Some(new_state);
                });
            }
            Ok(Cmd::TestSni { google_ip, sni }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    st.sni_probe.insert(sni.clone(), SniProbeState::InFlight);
                }
                rt.spawn(async move {
                    let result = scan_sni::probe_one(&google_ip, &sni).await;
                    let state = match result.latency_ms {
                        Some(ms) => SniProbeState::Ok(ms),
                        None => {
                            SniProbeState::Failed(result.error.unwrap_or_else(|| "failed".into()))
                        }
                    };
                    shared2.state.lock().unwrap().sni_probe.insert(sni, state);
                });
            }
            Ok(Cmd::TestAllSni { google_ip, snis }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    for s in &snis {
                        st.sni_probe.insert(s.clone(), SniProbeState::InFlight);
                    }
                }
                rt.spawn(async move {
                    let results = scan_sni::probe_all(&google_ip, snis).await;
                    let mut st = shared2.state.lock().unwrap();
                    for (sni, r) in results {
                        let state = match r.latency_ms {
                            Some(ms) => SniProbeState::Ok(ms),
                            None => {
                                SniProbeState::Failed(r.error.unwrap_or_else(|| "failed".into()))
                            }
                        };
                        st.sni_probe.insert(sni, state);
                    }
                });
            }
            Ok(Cmd::CheckCaTrusted) => {
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    let base = data_dir::data_dir();
                    let ca = base.join(CA_CERT_FILE);
                    let file_exists = ca.exists();
                    // Probe the trust store by name — independent of
                    // whether the on-disk ca.crt happens to be there.
                    // The file and the trust-store entry can be out of
                    // sync (e.g. after a partial removal), and that
                    // mismatch is exactly what Check CA must surface.
                    let trusted = rahgozar::cert_installer::is_ca_trusted_by_name();
                    push_log(
                        &shared2,
                        &format!(
                            "[ui] check CA: file={} trust_store={}",
                            if file_exists { "present" } else { "missing" },
                            if trusted { "trusted" } else { "not trusted" },
                        ),
                    );
                    let mut st = shared2.state.lock().unwrap();
                    st.ca_trusted = Some(trusted);
                    st.ca_trusted_at = Some(Instant::now());
                });
            }
            Ok(Cmd::CheckUpdate { route }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    st.last_update_check = Some(UpdateProbeState::InFlight);
                    st.last_update_check_at = Some(Instant::now());
                }
                rt.spawn(async move {
                    let result = rahgozar::update_check::check(route).await;
                    push_log(
                        &shared2,
                        &format!("[ui] update check: {}", result.summary()),
                    );
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.last_update_check = Some(UpdateProbeState::Done(result));
                        st.last_update_check_at = Some(Instant::now());
                    }
                });
            }
            Ok(Cmd::DownloadUpdate { route, url, name }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    st.download_in_progress = true;
                    st.last_download = None;
                }
                push_log(&shared, &format!("[ui] downloading {}", name));
                rt.spawn(async move {
                    let dir = downloads_dir();
                    let out = dir.join(&name);
                    let result = rahgozar::update_check::download_asset(route, &url, &out).await;
                    let log_msg = match result {
                        Ok(bytes) => {
                            let log_msg = format!(
                                "[ui] download ok: {} ({} bytes) -> {}",
                                name,
                                bytes,
                                out.display()
                            );
                            let mut st = shared2.state.lock().unwrap();
                            st.download_in_progress = false;
                            st.last_download_at = Some(Instant::now());
                            st.last_download = Some(Ok(out));
                            log_msg
                        }
                        Err(e) => {
                            let log_msg = format!("[ui] download failed: {}", e);
                            let mut st = shared2.state.lock().unwrap();
                            st.download_in_progress = false;
                            st.last_download_at = Some(Instant::now());
                            st.last_download = Some(Err(e));
                            log_msg
                        }
                    };
                    push_log(&shared2, &log_msg);
                });
            }
            Ok(Cmd::InstallUpdate { route, url, name }) => {
                let shared2 = shared.clone();
                let already_in_progress = {
                    let mut st = shared2.state.lock().unwrap();
                    if st.install_in_progress {
                        true
                    } else {
                        st.install_in_progress = true;
                        st.last_install = None;
                        st.last_install_at = Some(Instant::now());
                        false
                    }
                };
                if already_in_progress {
                    push_log(
                        &shared,
                        "[ui] install already in progress; ignoring duplicate request",
                    );
                    continue;
                }
                push_log(&shared, &format!("[ui] installing {}", name));
                rt.spawn(async move {
                    let result =
                        rahgozar::update_apply::download_and_stage(route, &url, &name).await;
                    let log_msg = match result {
                        Ok(staged) => {
                            let log_msg = format!(
                                "[ui] update staged → {} (restart to apply)",
                                staged.staged_path.display()
                            );
                            let mut st = shared2.state.lock().unwrap();
                            st.install_in_progress = false;
                            st.last_install_at = Some(Instant::now());
                            st.last_install = Some(Ok(staged));
                            log_msg
                        }
                        Err(e) => {
                            let log_msg = format!("[ui] install failed: {}", e);
                            let mut st = shared2.state.lock().unwrap();
                            st.install_in_progress = false;
                            st.last_install_at = Some(Instant::now());
                            st.last_install = Some(Err(e.to_string()));
                            log_msg
                        }
                    };
                    push_log(&shared2, &log_msg);
                });
            }
            Ok(Cmd::RestartToApply) => {
                // Pull the staged update out of UiState. If it's missing
                // we have nothing to do — the user shouldn't have been able
                // to click Restart in that case, but a UI race could let it
                // through. Also need to do the swap on this thread so the
                // process can exec/exit cleanly without the egui loop
                // continuing afterwards.
                let staged = shared
                    .state
                    .lock()
                    .unwrap()
                    .last_install
                    .as_ref()
                    .and_then(|r| r.as_ref().ok().cloned());
                if let Some(staged) = staged {
                    push_log(&shared, "[ui] restarting to apply update");
                    if let Err(e) = rahgozar::update_apply::restart_to_apply(&staged) {
                        push_log(&shared, &format!("[ui] restart failed: {}", e));
                        let mut st = shared.state.lock().unwrap();
                        st.last_install = Some(Err(format!("restart failed: {}", e)));
                        st.last_install_at = Some(Instant::now());
                    }
                    // restart_to_apply doesn't return on success — control
                    // never reaches here in the happy path.
                } else {
                    push_log(
                        &shared,
                        "[ui] restart requested but no staged update is available",
                    );
                }
            }
            Err(_) => {}
        }
    }
}

/// Install a tracing subscriber that mirrors every log event into the UI's
/// Recent log panel.
///
/// Filter precedence (issue #401, v1.8.2):
///   1. `RUST_LOG` env var, if set
///   2. The saved form's `log_level` (passed in from the loaded config)
///   3. `info,hyper=warn` as a sensible default
///
/// The constructed filter is wrapped in a `reload::Layer` and the handle
/// is stashed in `LOG_RELOAD` so that a Save inside the running UI can
/// reinstall the filter without a restart. See `apply_log_level`.
fn install_ui_tracing(shared: Arc<Shared>, config_level: &str) {
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{reload, EnvFilter};

    /// A MakeWriter that pushes each line into the shared log panel.
    struct UiLogWriter {
        shared: Arc<Shared>,
    }

    struct UiWriterInst {
        shared: Arc<Shared>,
        buf: Vec<u8>,
    }

    impl<'a> MakeWriter<'a> for UiLogWriter {
        type Writer = UiWriterInst;
        fn make_writer(&'a self) -> Self::Writer {
            UiWriterInst {
                shared: self.shared.clone(),
                buf: Vec::with_capacity(128),
            }
        }
    }

    impl std::io::Write for UiWriterInst {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.buf.is_empty() {
                return Ok(());
            }
            let text = String::from_utf8_lossy(&self.buf).trim_end().to_string();
            self.buf.clear();
            // Split on newlines in case multiple events got buffered.
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                let mut s = self.shared.state.lock().unwrap();
                s.log.push_back(line.to_string());
                while s.log.len() > LOG_MAX {
                    s.log.pop_front();
                }
            }
            Ok(())
        }
    }

    impl Drop for UiWriterInst {
        fn drop(&mut self) {
            let _ = std::io::Write::flush(self);
        }
    }

    // RUST_LOG > config.log_level > "info,hyper=warn"
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let trimmed = config_level.trim();
        if trimmed.is_empty() {
            EnvFilter::new("info,hyper=warn")
        } else {
            EnvFilter::try_new(trimmed).unwrap_or_else(|_| EnvFilter::new("info,hyper=warn"))
        }
    });

    let (filter_layer, reload_handle) = reload::Layer::new(filter);
    if LOG_RELOAD.set(reload_handle).is_err() {
        // Already initialized — install_ui_tracing got called twice. Bail
        // silently rather than panic; the existing subscriber stays live.
        return;
    }

    let writer = UiLogWriter { shared };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(writer);

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}

/// Reload handle for the UI's tracing EnvFilter — populated once at startup
/// by `install_ui_tracing`. `apply_log_level` uses it to swap in a new
/// filter when the user clicks Save with a different log level (#401).
static LOG_RELOAD: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>,
> = std::sync::OnceLock::new();

/// Reinstall the tracing filter at runtime. Called from the Save handler
/// so the user's new `log_level` takes effect without a restart. RUST_LOG
/// still wins if it was set at process start — explicit override beats
/// config in both directions.
fn apply_log_level(level: &str) {
    use tracing_subscriber::EnvFilter;
    let Some(handle) = LOG_RELOAD.get() else {
        return;
    };
    if std::env::var_os("RUST_LOG").is_some() {
        // RUST_LOG was set explicitly at boot — don't silently override.
        return;
    }
    let trimmed = level.trim();
    let new = if trimmed.is_empty() {
        EnvFilter::new("info,hyper=warn")
    } else {
        match EnvFilter::try_new(trimmed) {
            Ok(f) => f,
            Err(_) => return,
        }
    };
    let _ = handle.modify(|f| *f = new);
}

/// Where we drop downloaded release assets. Prefer the OS user Downloads
/// dir (via the directories crate that's already in our tree), fall back
/// to the user-data dir for platforms that don't expose one (edge case).
fn downloads_dir() -> std::path::PathBuf {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
        .unwrap_or_else(data_dir::data_dir)
}

/// Open the OS file manager with the given file highlighted/selected.
/// Best-effort: fires the platform-specific command and swallows errors.
fn reveal_in_file_manager(p: &std::path::Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg("-R").arg(p).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let arg = format!("/select,\"{}\"", p.display());
        let _ = std::process::Command::new("explorer").arg(arg).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // No universal "select this file" primitive on Linux; just open
        // the containing folder.
        if let Some(parent) = p.parent() {
            let _ = std::process::Command::new("xdg-open").arg(parent).spawn();
        }
    }
}

fn push_log(shared: &Shared, msg: &str) {
    let line = format!(
        "{}  {}",
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Iso8601::DEFAULT)
            .unwrap_or_default(),
        msg
    );
    let mut s = shared.state.lock().unwrap();
    s.log.push_back(line);
    while s.log.len() > LOG_MAX {
        s.log.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rahgozar::config::Config;

    fn mk_group(name: &str, ip: &str, sni: &str, domains: &[&str]) -> FrontingGroup {
        FrontingGroup {
            name: name.into(),
            ip: ip.into(),
            sni: sni.into(),
            domains: domains.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn duplicate_group_names_get_distinct_buffers() {
        // Regression guard for the buffer-keyed-by-name bug.
        //
        // `Config::validate()` and `ProxyServer::new()` accept two
        // fronting groups with the same `name` (warning-only; see
        // `proxy_server.rs`). An earlier version of this UI keyed
        // the per-group domain edit buffer by `group.name` in a
        // HashMap, which silently collapsed the two same-named
        // groups into one buffer entry — editing the second group
        // would overwrite the first's domains, and on Save one
        // group's domain list would disappear into the other.
        //
        // The position-indexed Vec design here makes that
        // impossible: two distinct rows have two distinct buffer
        // slots regardless of name. This test pins that behaviour
        // by exercising the save path with two same-named groups
        // and checking both keep their own domains.
        let groups = vec![
            mk_group("akamai", "2.22.151.143", "www.bbc.com", &[]),
            mk_group("akamai", "2.22.151.150", "www.akamai.com", &[]),
        ];
        // Each buffer carries different domains. Pre-fix, the
        // HashMap would have collapsed these into one entry —
        // whichever group rendered last would have won.
        let buffers = vec![
            "reddit.com\ngithub.com".to_string(),
            "microsoft.com\nicloud.com".to_string(),
        ];
        let out = build_fronting_groups_from_editor(&groups, &buffers);
        assert_eq!(out.len(), 2, "both same-named groups must survive");
        assert_eq!(out[0].name, "akamai");
        assert_eq!(out[0].ip, "2.22.151.143");
        assert_eq!(out[0].domains, vec!["reddit.com", "github.com"]);
        assert_eq!(out[1].name, "akamai");
        assert_eq!(out[1].ip, "2.22.151.150");
        assert_eq!(out[1].domains, vec!["microsoft.com", "icloud.com"]);
    }

    #[test]
    fn empty_buffer_drops_group_before_save() {
        // `Config::validate()` rejects `fronting_groups[i].domains`
        // being empty. The editor keeps draft groups (no domains
        // entered yet) visible so the user can fill them in, but
        // the save path filters them out so the persisted config
        // is always valid. Pre-fix the draft entry would survive
        // into `to_config()` with `domains: []` and the next proxy
        // start would error out.
        let groups = vec![
            mk_group("draft-only", "1.2.3.4", "example.com", &[]),
            mk_group("real", "5.6.7.8", "real.example", &[]),
        ];
        let buffers = vec![
            // First group: only whitespace and empty separators —
            // simulates the user clicking "add as fronting group"
            // from a Discover result but not typing any domains yet.
            "  \n , \n".to_string(),
            // Second group: legit content.
            "site.test".to_string(),
        ];
        let out = build_fronting_groups_from_editor(&groups, &buffers);
        assert_eq!(out.len(), 1, "draft group should be dropped");
        assert_eq!(out[0].name, "real");
        assert_eq!(out[0].domains, vec!["site.test"]);
    }

    #[test]
    fn buffer_separators_trim_and_dedup_blanks() {
        // Mixed separators (`,`, `\n`) + whitespace + blanks all
        // get normalized into a clean Vec<String>. This is what
        // the user gets when pasting from a Telegram channel that
        // formatted the list with mixed delimiters.
        let groups = vec![mk_group("g", "1.1.1.1", "sni.test", &[])];
        let buffers = vec!["  a.com , b.com\n\n c.com,  ,\nd.com  ".to_string()];
        let out = build_fronting_groups_from_editor(&groups, &buffers);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].domains, vec!["a.com", "b.com", "c.com", "d.com"]);
    }

    #[test]
    fn buffer_dedups_domains_preserving_first_seen_order() {
        // Aligns with the Android `ConfigStore.toJson()` `.distinct()`
        // pass — a user pasting a list with duplicates ends up with
        // the same on-disk shape regardless of which UI they used.
        // Order of first appearance is preserved so a curated list
        // (Telegram channel paste) keeps its meaningful ordering.
        let groups = vec![mk_group("g", "1.1.1.1", "sni.test", &[])];
        let buffers = vec!["a.com\nb.com\na.com\nc.com\n  B.COM  \nb.com".to_string()];
        let out = build_fronting_groups_from_editor(&groups, &buffers);
        assert_eq!(out.len(), 1);
        // `B.COM` and `b.com` differ in case — domain matching on
        // the proxy side is case-insensitive but the dedup here is
        // byte-exact, matching the Android `.distinct()` behaviour.
        // That's intentional: aggressive case-collapsing here would
        // surprise a user who deliberately typed varied casing.
        assert_eq!(out[0].domains, vec!["a.com", "b.com", "c.com", "B.COM"],);
    }

    #[test]
    fn missing_buffer_falls_back_to_existing_domains() {
        // `to_config()` can be called from non-editor sites
        // (Test, Start handlers) where the buffer Vec might be
        // shorter than the groups Vec — for instance right at
        // first launch before the editor has rendered. In that
        // case the existing `g.domains` is the source of truth.
        let groups = vec![mk_group(
            "loaded",
            "9.9.9.9",
            "x.test",
            &["alpha.test", "beta.test"],
        )];
        let buffers: Vec<String> = vec![]; // no buffers — should fall back
        let out = build_fronting_groups_from_editor(&groups, &buffers);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].domains, vec!["alpha.test", "beta.test"]);
    }

    /// Regression for the desktop write-side extras passthrough.
    /// `config.rs::unknown_fields_captured_into_extras` proves the
    /// LOAD side stashes unknown keys into `Config::extras`. This
    /// test pins the WRITE side: building a `ConfigWire` from a
    /// `Config` with extras must re-emit those keys verbatim in the
    /// serialized JSON. Otherwise Save-config and Save-as-profile
    /// would still silently drop future / hand-edited fields even
    /// though `Config` carried them through.
    #[test]
    fn config_wire_serializes_extras() {
        let json = r#"{
            "mode": "apps_script",
            "auth_key": "MY_REAL_SECRET",
            "script_id": "X",
            "future_field_xyz": [1, 2, 3],
            "another_future_field": {"nested": true, "n": 42}
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        // Sanity check on the load side.
        assert!(cfg.extras.contains_key("future_field_xyz"));

        // The write path: build a ConfigWire and serialize.
        let wire = ConfigWire::from(&cfg);
        let out = serde_json::to_value(&wire).expect("ConfigWire serialize");

        // Unknown keys must appear in the output, with their values
        // preserved exactly.
        assert_eq!(
            out.get("future_field_xyz"),
            Some(&serde_json::json!([1, 2, 3])),
            "ConfigWire must re-emit unknown scalar/array fields verbatim"
        );
        assert_eq!(
            out.get("another_future_field"),
            Some(&serde_json::json!({"nested": true, "n": 42})),
            "ConfigWire must re-emit unknown object fields verbatim"
        );
        // Modelled fields must NOT be duplicated by the extras flatten
        // (would happen if Config also stuck them in `extras`).
        assert_eq!(out.get("mode"), Some(&serde_json::json!("apps_script")));
        assert_eq!(
            out.get("auth_key"),
            Some(&serde_json::json!("MY_REAL_SECRET"))
        );
    }

    /// Carry-through of `block_quic` / `disable_padding` / `enable_batching`
    /// / `coalesce_*` through ConfigWire. These were the modelled fields
    /// that the previous ConfigWire was silently dropping.
    #[test]
    fn config_wire_serializes_previously_dropped_modeled_fields() {
        let json = r#"{
            "mode": "direct",
            "block_quic": false,
            "block_stun": true,
            "disable_padding": true,
            "enable_batching": true,
            "coalesce_step_ms": 25,
            "coalesce_max_ms": 750
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let wire = ConfigWire::from(&cfg);
        let out = serde_json::to_value(&wire).unwrap();
        // block_quic: default true → emit when false.
        assert_eq!(out.get("block_quic"), Some(&serde_json::json!(false)));
        // block_stun: default false → emit when true.
        assert_eq!(out.get("block_stun"), Some(&serde_json::json!(true)));
        // disable_padding: default false → emit when true.
        assert_eq!(out.get("disable_padding"), Some(&serde_json::json!(true)));
        // enable_batching: default false → emit when true.
        assert_eq!(out.get("enable_batching"), Some(&serde_json::json!(true)));
        // coalesce_*: default 0 → emit when non-zero.
        assert_eq!(out.get("coalesce_step_ms"), Some(&serde_json::json!(25)));
        assert_eq!(out.get("coalesce_max_ms"), Some(&serde_json::json!(750)));
    }

    /// Defaults must NOT be emitted, so unchanged configs stay clean
    /// on disk — symmetric to the round-trip test above. This catches
    /// the failure mode where `skip_serializing_if` is wired to the
    /// wrong predicate (e.g. `is_false` instead of `is_true`).
    #[test]
    fn config_wire_omits_default_values() {
        let json = r#"{
            "mode": "direct"
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let wire = ConfigWire::from(&cfg);
        let out = serde_json::to_value(&wire).unwrap();
        // block_quic defaults true / block_stun defaults false → both
        // omitted from the wire on a fresh "mode: direct" config.
        assert!(
            out.get("block_quic").is_none(),
            "default block_quic must be omitted"
        );
        assert!(
            out.get("block_stun").is_none(),
            "default block_stun must be omitted"
        );
        assert!(out.get("disable_padding").is_none());
        assert!(out.get("enable_batching").is_none());
        assert!(out.get("coalesce_step_ms").is_none());
        assert!(out.get("coalesce_max_ms").is_none());
        // Log colours default — not emitted into the file unless changed.
        assert!(out.get("log_color_info").is_none());
        assert!(out.get("log_color_warn").is_none());
        assert!(out.get("log_color_error").is_none());
    }

    /// Custom-parameters editor must round-trip every extras value type
    /// across load → buffer → save without changing the JSON type. This
    /// is the contract the feature request asks for: parameters added
    /// to the UI table survive Save without flipping types.
    #[test]
    fn custom_params_buffer_round_trips_all_value_kinds() {
        let mut extras = std::collections::BTreeMap::new();
        extras.insert("force_http1".into(), serde_json::Value::Bool(true));
        extras.insert(
            "max_retries".into(),
            serde_json::Value::Number(serde_json::Number::from(7)),
        );
        extras.insert(
            "label".into(),
            serde_json::Value::String("home network".into()),
        );
        // Ambiguous string: `"42"` looks like a number when bare. The
        // buffer must escape it so re-parsing keeps it a string.
        extras.insert(
            "ambig_number".into(),
            serde_json::Value::String("42".into()),
        );
        extras.insert(
            "ambig_bool".into(),
            serde_json::Value::String("true".into()),
        );
        extras.insert("list".into(), serde_json::json!([1, 2, 3]));
        extras.insert("obj".into(), serde_json::json!({"a": 1, "b": "x"}));

        let buf = extras_to_buffer(&extras);
        let round = build_extras_from_buffer(&buf);
        assert_eq!(
            round, extras,
            "round-trip must preserve every value verbatim"
        );
    }

    /// Blank-key rows are dropped on save, matching the editor UX where
    /// an empty row is treated as "draft, not yet committed". Without
    /// this, hitting Add then Save would write a phantom `""` key.
    #[test]
    fn custom_params_blank_key_rows_dropped() {
        let buf = vec![
            ("".into(), "true".into()),
            ("   ".into(), "ignored".into()),
            ("real_key".into(), "5".into()),
        ];
        let out = build_extras_from_buffer(&buf);
        assert_eq!(out.len(), 1);
        assert_eq!(out.get("real_key"), Some(&serde_json::json!(5)));
    }

    /// Default log colours must survive a Config-load → ConfigWire
    /// serialize round-trip cleanly (skipped from output as defaults).
    /// And non-default colours must appear so the user's preference
    /// persists. Mirrors the `block_quic` / `coalesce_*` round-trip
    /// pattern above.
    #[test]
    fn log_color_fields_emit_only_when_non_default() {
        let json = r##"{
            "mode": "direct",
            "log_color_info": "#00ff00",
            "log_color_warn": "#e0a83a",
            "log_color_error": "#ff0000"
        }"##;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let wire = ConfigWire::from(&cfg);
        let out = serde_json::to_value(&wire).unwrap();
        // Non-default info / error → emitted verbatim.
        assert_eq!(
            out.get("log_color_info"),
            Some(&serde_json::json!("#00ff00"))
        );
        assert_eq!(
            out.get("log_color_error"),
            Some(&serde_json::json!("#ff0000"))
        );
        // Warn matches the compiled default → skipped from the wire output.
        assert!(out.get("log_color_warn").is_none());
    }

    /// `normalize_log_color` must replace bad input with the supplied
    /// default, canonicalise valid input to lowercase `#rrggbb`, and
    /// reject double-`#` prefixes. Pins the contract before the
    /// wire-side healing behaviour below.
    #[test]
    fn normalize_log_color_canonicalizes_and_heals() {
        // Canonical input → unchanged.
        assert_eq!(normalize_log_color("#abcdef", "#dc6e6e"), "#abcdef");
        // Empty / nonsense → default.
        assert_eq!(normalize_log_color("", "#dc6e6e"), "#dc6e6e");
        assert_eq!(normalize_log_color("red", "#dc6e6e"), "#dc6e6e");
        assert_eq!(normalize_log_color("#12345", "#dc6e6e"), "#dc6e6e");
        // Uppercase → lowercased so the file is stable across saves.
        assert_eq!(normalize_log_color("#ABCDEF", "#dc6e6e"), "#abcdef");
        // Surrounding whitespace tolerated.
        assert_eq!(normalize_log_color("  #abcdef  ", "#dc6e6e"), "#abcdef",);
        // No-`#` form → canonicalised with the `#` re-attached.
        assert_eq!(normalize_log_color("abcdef", "#dc6e6e"), "#abcdef");
        // Double-`#` was previously silently accepted (the old
        // `trim_start_matches('#')` stripped both). It must now
        // fail validation and fall back to the default.
        assert_eq!(normalize_log_color("##abcdef", "#dc6e6e"), "#dc6e6e");
        // Junk after a valid prefix → reject (length check covers it).
        assert_eq!(normalize_log_color("#abcdefXX", "#dc6e6e"), "#dc6e6e");
    }

    /// Bad hex codes in config.json must not crash the UI — they should
    /// silently fall back to the compiled defaults at render time.
    /// `parse_hex_color` returns `None` on garbage; the render path
    /// uses `unwrap_or_else(default)` so this can't panic.
    #[test]
    fn parse_hex_color_rejects_garbage() {
        assert!(parse_hex_color("").is_none());
        assert!(parse_hex_color("not a color").is_none());
        assert!(parse_hex_color("#12345").is_none()); // 5 chars
        assert!(parse_hex_color("#1234567").is_none()); // 7 chars
        assert!(parse_hex_color("#gghhii").is_none()); // non-hex digits
                                                       // Tightened from the previous `trim_start_matches('#')` impl:
                                                       // double-`#` must NOT be silently accepted. This was the
                                                       // review's `##abcdef` case.
        assert!(parse_hex_color("##abcdef").is_none());
        assert!(parse_hex_color("###abcdef").is_none());
        // No-`#` short form is still accepted (matches what HTML
        // `<input type=color>` produces and what color_to_hex emits
        // without the `#` when passed unprefixed strings elsewhere).
        assert!(parse_hex_color("abcdef").is_some());
        // Sanity: the compiled defaults must themselves parse, otherwise
        // the fallback `.unwrap()` in the render path would crash.
        assert!(parse_hex_color(rahgozar::config::DEFAULT_LOG_COLOR_INFO).is_some());
        assert!(parse_hex_color(rahgozar::config::DEFAULT_LOG_COLOR_WARN).is_some());
        assert!(parse_hex_color(rahgozar::config::DEFAULT_LOG_COLOR_ERROR).is_some());
    }

    /// Modeled-key collision must be rejected at save time. Without
    /// this gate a user could add `mode` (or any modeled field) as a
    /// custom parameter and the flatten emit would shadow the form's
    /// value during save → reload, silently overriding form state.
    /// Pin every modeled key plus a known-non-modeled one to make
    /// sure the rejection works AND legitimate extras still pass.
    #[test]
    fn custom_params_rejects_modeled_key_collisions() {
        // Hermetic FormState — uses the same compiled defaults as a
        // fresh install, rather than `load_form()` which would read
        // the developer's real config.json from the user-data dir.
        // We only care about `custom_params_buffer` here; `mode =
        // "direct"` skips the script_id / auth_key requirement so the
        // collision check is what fails the save, not missing creds.
        let mut form = FormState::fresh_install_defaults();
        form.mode = "direct".into();
        // Sanity: a real custom key saves fine.
        form.custom_params_buffer = vec![("my_future_field".into(), "true".into())];
        form.to_config().expect("non-colliding key must save");

        // Modeled-key collision → Err with a message naming the key.
        for &key in MODELED_CONFIG_KEYS {
            form.custom_params_buffer = vec![(key.into(), "anything".into())];
            let err = form
                .to_config()
                .err()
                .unwrap_or_else(|| panic!("expected save to fail for modeled key '{}'", key));
            assert!(
                err.contains(key),
                "error must name the colliding key '{}', got: {}",
                key,
                err,
            );
        }

        // Whitespace around a modeled key must still be caught — the
        // editor trims on save so leading/trailing space cannot be a
        // workaround.
        form.custom_params_buffer = vec![("  mode  ".into(), "x".into())];
        assert!(form.to_config().is_err());
    }

    /// MODELED_CONFIG_KEYS must stay in sync with the actual ConfigWire
    /// keyset. The collision check uses this list, so a new field added
    /// to Config without a corresponding MODELED_CONFIG_KEYS entry
    /// would silently allow that field to be shadowed via the custom-
    /// parameters editor. We extract the live key set from a fully-
    /// populated ConfigWire serialization and assert it's a subset of
    /// the constant — plus the constant has no entries that ConfigWire
    /// can't actually emit.
    #[test]
    fn modeled_keys_list_matches_wire() {
        // Populate every field with a non-default value so
        // `skip_serializing_if` doesn't hide modeled keys from the
        // emitted JSON.
        let json = r##"{
            "mode": "apps_script",
            "google_ip": "1.2.3.4",
            "front_domain": "x.example",
            "script_id": "ID",
            "script_ids": ["A","B"],
            "auth_key": "K",
            "listen_host": "127.0.0.1",
            "listen_port": 8085,
            "socks5_port": 8086,
            "log_level": "debug",
            "log_color_info": "#010203",
            "log_color_warn": "#040506",
            "log_color_error": "#070809",
            "verify_ssl": false,
            "hosts": {"h": "1.1.1.1"},
            "enable_batching": true,
            "upstream_socks5": "127.0.0.1:1",
            "parallel_relay": 2,
            "coalesce_step_ms": 25,
            "coalesce_max_ms": 750,
            "sni_hosts": ["a.example"],
            "fetch_ips_from_api": true,
            "max_ips_to_scan": 1,
            "scan_batch_size": 1,
            "google_ip_validation": false,
            "normalize_x_graphql": true,
            "youtube_via_relay": true,
            "relay_url_patterns": ["a.example/p"],
            "sabr_strip": true,
            "passthrough_hosts": ["a.example"],
            "block_quic": false,
            "block_stun": true,
            "disable_padding": true,
            "force_http1": true,
            "tunnel_doh": true,
            "bypass_doh_hosts": ["a.example"],
            "block_doh": false,
            "fronting_groups": [
              {"name":"g","ip":"1.2.3.4","sni":"x.example","domains":["y.example"]}
            ],
            "auto_blacklist_strikes": 10,
            "auto_blacklist_window_secs": 99,
            "auto_blacklist_cooldown_secs": 999,
            "request_timeout_secs": 31,
            "apps_script_lang": "fa",
            "exit_node": {
              "enabled": true,
              "relay_url": "https://a.example",
              "psk": "K",
              "hosts": ["b.example"],
              "mode": "selective"
            },
            "direct_mode": {
              "enabled": true,
              "fronts": ["www.example.com"]
            }
        }"##;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let wire = ConfigWire::from(&cfg);
        let out = serde_json::to_value(&wire).unwrap();
        let wire_keys: std::collections::BTreeSet<&str> = out
            .as_object()
            .expect("wire serializes to object")
            .keys()
            .map(|s| s.as_str())
            .collect();
        let modeled: std::collections::BTreeSet<&str> =
            MODELED_CONFIG_KEYS.iter().copied().collect();

        // Every wire key must appear in MODELED_CONFIG_KEYS — otherwise
        // the collision check silently allows shadowing.
        for k in &wire_keys {
            assert!(
                modeled.contains(k),
                "wire emits '{}' but MODELED_CONFIG_KEYS is missing it — \
                 add the field to the constant in src/bin/ui.rs",
                k,
            );
        }
        // And every MODELED_CONFIG_KEYS entry must correspond to a real
        // wire key (script_ids is an alias deserialise-only but it's
        // here for the editor's collision check, so we allow it to be
        // missing from the wire output).
        for k in &modeled {
            if *k == "script_ids" {
                continue;
            }
            assert!(
                wire_keys.contains(k),
                "MODELED_CONFIG_KEYS lists '{}' but the wire never emits it — \
                 the constant is stale",
                k,
            );
        }
    }

    /// Line-classifier must (a) only match the level tokens at word
    /// boundaries, not arbitrary substrings, AND (b) pick the
    /// **leftmost** level-shaped token so an INFO line whose message
    /// happens to mention ERROR / WARN doesn't get recoloured by the
    /// later occurrence.
    #[test]
    fn log_level_classifier_matches_leftmost_word_boundary() {
        assert_eq!(
            classify_log_line("2025-05-16T10:00:00Z  INFO  starting up"),
            Some(LogLevel::Info),
        );
        assert_eq!(
            classify_log_line("2025-05-16T10:00:00Z  WARN  rate limit"),
            Some(LogLevel::Warn),
        );
        assert_eq!(
            classify_log_line("2025-05-16T10:00:00Z ERROR  fatal"),
            Some(LogLevel::Error),
        );
        // Substring without the space-padded token = not a level.
        assert_eq!(classify_log_line("debug: INFOrmation logged"), None);
        // DEBUG / TRACE / unclassified → no recolour.
        assert_eq!(classify_log_line("DEBUG step"), None);

        // Leftmost wins — INFO line that mentions ERROR/WARN in the
        // message body must stay green, not flip to red/yellow. This
        // was the original review's regression: ` INFO  got ERROR
        // response`.
        assert_eq!(
            classify_log_line("2025-05-16T10:00:00Z  INFO  got ERROR response from upstream"),
            Some(LogLevel::Info),
            "INFO line mentioning ' ERROR ' must stay INFO",
        );
        assert_eq!(
            classify_log_line("2025-05-16T10:00:00Z  WARN  prior INFO event was suspicious"),
            Some(LogLevel::Warn),
            "WARN line mentioning ' INFO ' must stay WARN",
        );
        assert_eq!(
            classify_log_line("2025-05-16T10:00:00Z ERROR  saw earlier WARN and INFO too"),
            Some(LogLevel::Error),
            "ERROR line mentioning ' WARN ' / ' INFO ' must stay ERROR",
        );
    }
}
