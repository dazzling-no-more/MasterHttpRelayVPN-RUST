// Tracing → Tauri event bridge.
//
// Single tracing `MakeWriter` impl that:
//   1. Splits the byte stream from `tracing-subscriber` into newline-
//      terminated lines.
//   2. Pushes each line into `AppState::log` (the bounded ring buffer
//      the Logs tab's initial scroll-back reads from).
//   3. Forwards each line through an unbounded mpsc to a small drain
//      task on the Tokio runtime, which emits `rahgozar:log` events
//      to the frontend.
//
// Why an mpsc + drain task instead of emitting straight from the
// writer:
//   - `AppHandle::emit` needs the live Tauri runtime; the writer
//     would have to hold either a clone of the AppHandle or pull it
//     from a global. The mpsc lets us thread `AppHandle` through
//     `tauri::Builder::setup` (where we naturally have it) without
//     touching the writer at all.
//   - The writer runs on whatever thread tracing happens to emit on
//     (the proxy's tokio worker, the UI thread, etc.); emitting from
//     arbitrary contexts is fine but wrapping the JSON payload + going
//     through Tauri's event bus is a hot-path overhead we'd rather
//     batch off the tracing thread.

use std::sync::Arc;

use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc::UnboundedSender;
use tracing_subscriber::fmt::MakeWriter;

use crate::state::AppState;

/// Install the tracing subscriber. Two layers:
///   - filter:  `RUST_LOG` if set, else "info,hyper=warn" — same default
///              as the egui binary so the proxy emits the same volume.
///   - format:  our custom writer below, which fans out to the ring
///              buffer + the mpsc.
///
/// Idempotent via `try_init` so a duplicated call (tests, hot-reload)
/// doesn't panic.
pub fn install(state: Arc<AppState>, tx: UnboundedSender<String>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,hyper=warn"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(BridgeWriter { state, tx });

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();
}

/// Spawn the drain task that turns mpsc receives into Tauri events.
/// Owns the rx end of the channel; runs forever (until the runtime is
/// dropped at process exit).
pub fn spawn_drain(
    rt: &tokio::runtime::Runtime,
    handle: AppHandle,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    rt.spawn(async move {
        while let Some(line) = rx.recv().await {
            // Best-effort — if a listener has gone away or the app is
            // mid-shutdown, dropping the event is fine.
            let _ = handle.emit("rahgozar:log", &line);
        }
    });
}

// ── Internals ──────────────────────────────────────────────────────────

/// `MakeWriter` factory. Cloned per tracing event by the subscriber.
struct BridgeWriter {
    state: Arc<AppState>,
    tx: UnboundedSender<String>,
}

/// Per-event writer instance. Buffers bytes inside one event (a tracing
/// formatted line can arrive across multiple `write()` calls before the
/// terminating `flush()`), then split on newlines so multi-line events
/// (rare, but happens for `Display` impls that embed `\n`) each become
/// their own log entry.
struct BridgeWriterInst {
    state: Arc<AppState>,
    tx: UnboundedSender<String>,
    buf: Vec<u8>,
}

impl<'a> MakeWriter<'a> for BridgeWriter {
    type Writer = BridgeWriterInst;
    fn make_writer(&'a self) -> Self::Writer {
        BridgeWriterInst {
            state: self.state.clone(),
            tx: self.tx.clone(),
            buf: Vec::with_capacity(192),
        }
    }
}

impl std::io::Write for BridgeWriterInst {
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
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            // Two-step: push into ring buffer first so `drain_logs`
            // sees a consistent tail, then fan out via mpsc for the
            // live event stream. Order matters: if the drain task
            // crashes the events stop but the ring keeps growing,
            // which is the right failure mode.
            self.state.push_log(line.to_string());
            let _ = self.tx.send(line.to_string());
        }
        Ok(())
    }
}

impl Drop for BridgeWriterInst {
    fn drop(&mut self) {
        // tracing's subscriber relies on Drop-time flush for the final
        // bytes of an event. Forwarding here ensures we don't lose the
        // last write of every emission.
        let _ = std::io::Write::flush(self);
    }
}
