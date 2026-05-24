// Process-wide mutable state for the Tauri backend.
//
// Mirrors the role that `Shared`/`State` plays in the legacy egui binary
// (`src/bin/ui/main.rs`): a single Mutex-guarded blob that the running
// proxy and the command handlers both poke at. We deliberately keep it
// small here — anything that isn't *needed* to satisfy a frontend
// command stays out, so the lifetime of a held lock is short.
//
// Why a `std::sync::Mutex` (not `tokio::sync::Mutex`):
//   - All access is from synchronous code paths: Tauri command bodies
//     and the spawned proxy task only touch this on success/failure of
//     a `oneshot` send. Holding it across an `.await` would be wrong
//     anyway because the proxy itself doesn't need the lock during its
//     run loop — the shutdown channel is the only handoff.
//   - Avoids pulling tokio's mutex semantics into command bodies that
//     would otherwise be plain sync functions, which keeps the
//     `#[tauri::command]` signatures readable.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rahgozar::proxy_server::RuntimeState;
use tokio::sync::oneshot;

/// Maximum number of log lines retained in the ring buffer. Mirrors the
/// `LOG_MAX = 200` cap used by the legacy egui UI — small enough to
/// keep memory bounded, large enough that a user inspecting a recent
/// failure can scroll back through the relevant context.
pub const LOG_MAX: usize = 500;

/// Tauri-managed app state.
///
/// Wrapped in `Arc<AppState>` at startup (in `lib.rs::run`) so the
/// background tracing writer can hold one clone independently of the
/// command-handler view. Tauri's `.manage()` is fine with `Arc<T>` —
/// `State<'_, Arc<AppState>>` derefs through both layers.
pub struct AppState {
    pub inner: Mutex<Inner>,
    /// Ring buffer of recent log lines. Pushed to from the tracing
    /// `MakeWriter` installed at startup, drained by `drain_logs`
    /// (frontend's initial scroll-back fetch) and tailed via
    /// `rahgozar:log` events for the live stream.
    pub log: Mutex<VecDeque<String>>,
    /// In-flight Drive-mode OAuth flows, keyed by the `state` token
    /// returned by `drive_oauth_start`. Each entry holds the
    /// `oneshot::Receiver` half of the channel the loopback listener
    /// task will fire when the user completes (or aborts) the
    /// browser flow.
    ///
    /// `drive_oauth_start` inserts; `drive_oauth_complete` removes
    /// (takes ownership of the Receiver) and awaits it with a
    /// timeout. Held in a separate `Mutex` from `inner` because
    /// OAuth flow lifecycle is orthogonal to proxy lifecycle —
    /// signing in / out doesn't affect a running proxy and vice
    /// versa.
    pub oauth_pending: Mutex<HashMap<String, oneshot::Receiver<Result<OAuthCompletion, String>>>>,
}

/// Successful outcome of a Drive-mode OAuth flow. Returned by
/// `drive_oauth_complete` to the frontend.
///
/// `email` is intentionally empty under the current `drive.file`
/// scope — Google's `/userinfo` endpoint requires the `email` /
/// `openid` scope to populate it. Adding those scopes just for a
/// display string would broaden the OAuth grant beyond what the
/// transport actually needs, so v1 leaves the field unpopulated.
/// The frontend can surface "Signed in" without naming the
/// account; the user already saw which Google account they picked
/// during the browser flow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OAuthCompletion {
    pub refresh_token: String,
    /// OAuth client_id used to mint `refresh_token`. Kept server-side so
    /// completion can refuse to save a token under a different saved client.
    #[serde(skip_serializing)]
    pub oauth_client_id: String,
    /// OAuth client_secret paired with [`Self::oauth_client_id`].
    #[serde(skip_serializing)]
    pub oauth_client_secret: String,
    #[serde(default)]
    pub email: String,
}

/// Mutable bits, all under one mutex so reading `running` + `started_at`
/// in `get_status` is atomic from the frontend's point of view (no
/// chance of seeing "still running but started_at = None").
pub struct Inner {
    /// True between `start_proxy` returning Ok and either `stop_proxy`
    /// firing or the spawned task panicking/exiting on its own.
    pub running: bool,

    /// Shutdown handle owned while the proxy is up. `stop_proxy()` takes
    /// it via `Option::take` and sends `()` — the proxy's `run()` future
    /// is awaiting on the rx end and exits cleanly on receipt. `None`
    /// when nothing is running (or as a transient state during shutdown).
    pub shutdown_tx: Option<oneshot::Sender<()>>,

    /// Wall-clock-ish anchor for uptime display in the Status tab. Wraps
    /// `Instant` (monotonic) rather than `SystemTime` because the user
    /// cares about "how long has it been up", not "what was the wall
    /// time it started" — uptime is what's shown on screen.
    pub started_at: Option<Instant>,

    /// Last fatal error reported by `start_proxy` or by the spawned
    /// proxy task. Surfaced in the Status tab so a build / bind /
    /// MITM-init failure doesn't disappear silently after the toast
    /// fades. Cleared when the user successfully starts again.
    pub last_error: Option<String>,

    /// Handle on the currently-running proxy. Populated by
    /// `start_proxy` after a successful `ProxyServer::new`, cleared
    /// by `stop_proxy` and by the spawned task's exit path. Read by
    /// `get_stats` to reach `DomainFronter::snapshot_stats()` for
    /// the Usage Today card. None when no proxy is running.
    pub running_state: Option<Arc<RuntimeState>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                running: false,
                shutdown_tx: None,
                started_at: None,
                last_error: None,
                running_state: None,
            }),
            log: Mutex::new(VecDeque::with_capacity(LOG_MAX)),
            oauth_pending: Mutex::new(HashMap::new()),
        }
    }

    /// Append a log line, evicting from the front when the ring is
    /// full. Called from the tracing `MakeWriter` impl in `tracing.rs`.
    pub fn push_log(&self, line: String) {
        let mut log = self.log.lock().unwrap();
        log.push_back(line);
        while log.len() > LOG_MAX {
            log.pop_front();
        }
    }
}
