// Tauri's build script. Generates the `tauri::generate_context!()`
// metadata (icon, identifier, config) at compile time from
// `tauri.conf.json`. Required for every Tauri 2 binary; one-liner.
fn main() {
    tauri_build::build();
}
