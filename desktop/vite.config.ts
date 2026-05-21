// Vite config tuned for Tauri 2.
//
// Two things this file does differently from a vanilla web app:
//   1. Pins the dev port to 1420 (Tauri's default expectation in
//      tauri.conf.json -> build.devUrl). If the dev server randomly
//      picked a free port, `cargo tauri dev` would launch a webview
//      pointed at the wrong URL.
//   2. Ignores writes inside `src-tauri/` for HMR so the Rust side
//      rebuilding doesn't trigger a JS reload — the Tauri CLI handles
//      Rust hot-reload separately.
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

// `TAURI_DEV_HOST` is set by `tauri dev` when running on a real device
// (mobile) so the webview can reach the host machine. Desktop dev just
// binds to localhost.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [svelte(), tailwindcss()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host ?? false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
});
