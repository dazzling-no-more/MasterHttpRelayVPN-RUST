// Owns the Tokio runtime that the rahgozar proxy server runs on top of.
//
// We can't use Tauri's own internal runtime for the proxy task because
// the proxy holds tokio-rustls / hyper / our domain-fronter machinery
// — a substantial workload that needs its own thread pool independent
// of the GUI's tick frequency. A dedicated `Runtime` keeps proxy I/O
// from contending with whatever housekeeping Tauri does on its own
// reactor.
//
// The runtime is created once at app startup and lives for the entire
// process. Spawning a proxy task is `state.rt.spawn(...)`; the task
// owns its own shutdown signalling (oneshot rx). When the app exits,
// the runtime drops, all background tasks abort, and we're done — no
// explicit teardown plumbing required.

use std::sync::Arc;

use tokio::runtime::Runtime;

/// Tauri-managed handle to the long-lived Tokio runtime.
pub struct RuntimeHandle {
    pub rt: Arc<Runtime>,
}

impl RuntimeHandle {
    /// Build a multi-thread Tokio runtime suitable for the proxy. Uses
    /// the standard worker count (one per CPU) — the rahgozar core was
    /// designed against this default and any tuning we'd want lives
    /// inside the proxy itself, not at the runtime layer.
    pub fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("rahgozar-tokio")
            .build()
            .expect("build tokio runtime");
        Self { rt: Arc::new(rt) }
    }
}

impl Default for RuntimeHandle {
    fn default() -> Self {
        Self::new()
    }
}
