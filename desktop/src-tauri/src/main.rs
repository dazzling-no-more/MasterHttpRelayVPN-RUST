// Phase A entry point — just delegates to the lib crate's `run()`.
// The `windows_subsystem = "windows"` attribute keeps a console window
// from popping up alongside the GUI on Windows release builds; debug
// builds still get the console so `println!` / tracing output stays
// visible during development.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    rahgozar_desktop_lib::run();
}
