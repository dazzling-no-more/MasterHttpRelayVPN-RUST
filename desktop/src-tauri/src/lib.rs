// Tauri backend for the rahgozar desktop UI.
//
// Top-level wiring only — actual command bodies live in `commands.rs`,
// shared state in `state.rs`, tokio runtime in `runtime.rs`, and the
// tracing→event bridge in `logbridge.rs`. Keep this file structurally
// simple so a future contributor can see, in one screen, what the
// app's IPC surface is and where each command's implementation lives.
//
// Phase progression so far:
//   - Phase A: scaffold (just `version`).
//   - Phase B: status + config readers + proxy start/stop.
//   - Phase C: tab nav + log streaming + Tunnel config editor ← we are here.

mod cert_ops;
mod commands;
mod logbridge;
mod runtime;
mod state;

use std::sync::Arc;

use crate::runtime::RuntimeHandle;
use crate::state::AppState;

/// Tauri app entry. Builds the runtime, installs the opener plugin so
/// `<a href="https://github.com/...">` clicks open the system browser
/// instead of trying to navigate inside the embedded webview, registers
/// the long-lived app state + tokio runtime, and hands control to the
/// OS event loop.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = Arc::new(AppState::new());
    let runtime = RuntimeHandle::new();

    // Tracing → state ring buffer → Tauri event mpsc. Install BEFORE
    // the app builds so log lines emitted during Tauri's own startup
    // (plugin init, webview spawn) end up in the ring just like proxy
    // logs would.
    let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    logbridge::install(app_state.clone(), log_tx);

    // Hold the rx in a slot the setup hook can take. We can't spawn
    // the drain task here because we don't have the AppHandle yet —
    // that only exists inside `setup`. Wrapping in `Mutex<Option>`
    // lets the closure take ownership exactly once.
    let log_rx_slot = Arc::new(std::sync::Mutex::new(Some(log_rx)));
    let rt_for_setup = runtime.rt.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Updater plugin: silent on success, exposes JS-side helpers
        // (`check()`, `downloadAndInstall()`) for the Status tab's
        // "Update available" affordance. Endpoint URL + public key
        // live in `tauri.conf.json::plugins.updater`.
        .plugin(tauri_plugin_updater::Builder::new().build())
        // Process plugin: `relaunch()` after an update install on
        // Windows + Linux. macOS doesn't need it (auto-restart) but
        // having the JS surface available cross-platform keeps the
        // updater code simple.
        .plugin(tauri_plugin_process::init())
        .manage(app_state)
        .manage(runtime)
        .setup(move |app| {
            // Spawn the drain task now that we have a real AppHandle
            // to emit events through. Receiver is `take`d from the
            // slot so a double-setup (shouldn't happen, but…) won't
            // try to spawn twice.
            if let Some(rx) = log_rx_slot.lock().unwrap().take() {
                logbridge::spawn_drain(&rt_for_setup, app.handle().clone(), rx);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::version,
            commands::is_portable_install,
            commands::get_status,
            commands::get_stats,
            commands::get_config,
            commands::save_config,
            commands::start_proxy,
            commands::stop_proxy,
            commands::test_relay,
            commands::scan_ips,
            commands::get_ca_status,
            commands::install_ca_cmd,
            commands::mint_ca_if_missing,
            commands::remove_ca_cmd,
            commands::get_fronting_groups,
            commands::save_fronting_groups,
            commands::discover_front_cmd,
            commands::get_sni_pool,
            commands::save_sni_pool,
            commands::probe_sni,
            commands::drain_logs,
            commands::clear_logs,
            commands::get_raw_config,
            commands::save_raw_config,
            // Drive-mode setup: OAuth flow + folder + relay-pubkey
            // validation. See the "Drive-mode setup" section in
            // `commands.rs` for the per-command contract.
            commands::drive_oauth_start,
            commands::drive_oauth_complete,
            commands::drive_create_folder,
            commands::drive_test_connection,
            commands::drive_validate_relay_pubkey,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
