// Thin wrapper around @tauri-apps/plugin-updater.
//
// The plugin already has a typed JS API; this module exists so:
//   1. The Svelte side has a single reactive store the UI binds to,
//      instead of every component handling promise state itself.
//   2. The Tauri-specific imports stay isolated — components import
//      `updater` (the store) and don't need to know about the plugin
//      surface.
//   3. Auto-check-on-startup state (in-flight / found / none / error)
//      is shared between the always-visible header banner and the
//      manual "Check for updates" button on the About tab.
//
// The actual update flow is opinionated:
//   - `checkOnStartup()` runs once when App.svelte mounts. Silent on
//     "no update" — we don't bother the user with a toast they didn't
//     ask for. Network errors are also silent on startup (Iran users
//     run with intermittent connectivity; surfacing every failed
//     auto-check is noise).
//   - `installAndRestart()` triggers the download + relaunch. The
//     plugin replaces the binary in place; the OS restarts it.

import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

/** Discriminated union of UI states for the update banner. */
export type UpdateState =
  | { kind: "idle" }
  | { kind: "checking" }
  | {
      kind: "available";
      version: string;
      notes: string | null;
      update: Update;
      /**
       * True if the running binary is the Windows portable .exe — in
       * that case the install action opens the release page in the
       * browser instead of running `update.downloadAndInstall()`, since
       * `latest.json` only ships an MSI for Windows and running it from
       * a portable would leave the user with two side-by-side installs.
       * Components MUST check this and re-label the action button
       * accordingly ("Open release page" vs "Install & restart").
       */
      portable: boolean;
    }
  | { kind: "downloading"; version: string; downloaded: number; total: number | null }
  | { kind: "installed"; version: string }
  | { kind: "error"; message: string };

let _state = $state<UpdateState>({ kind: "idle" });

/**
 * Cached result of the `is_portable_install` Rust-side check — see
 * `desktop/src-tauri/src/commands.rs::is_portable_install`. Resolved
 * lazily on first call so module import stays synchronous. Returns
 * `false` on the IPC failing (which would happen on a non-Tauri
 * surface like `vite dev` previewing the bundle in a plain browser),
 * which is the safer default: false → standard auto-update path runs
 * → it'll just fail with a clear "no updater available" error if the
 * plugin isn't there, instead of silently disabling updates everywhere.
 */
let _portableCache: Promise<boolean> | null = null;
function detectPortable(): Promise<boolean> {
  if (!_portableCache) {
    _portableCache = invoke<boolean>("is_portable_install").catch(() => false);
  }
  return _portableCache;
}

/** Release-page URL the portable flow redirects to. Hardcoded rather
 * than read from `update.body` / the manifest because the user is
 * about to leave the app — we want a stable, well-known landing page
 * (the `latest` redirect always resolves to the newest release), not
 * a tag-pinned URL that goes stale if a v(n+1) ships between the
 * check and the user clicking. */
const RELEASE_PAGE_URL =
  "https://github.com/dazzling-no-more/rahgozar/releases/latest";

export const updater = {
  get state(): UpdateState {
    return _state;
  },

  /**
   * One-shot startup check. Quiet on "up to date" / network failure
   * because the user didn't actively ask. If an update IS available,
   * the banner above the tab content surfaces it.
   */
  async checkOnStartup(): Promise<void> {
    _state = { kind: "checking" };
    try {
      const [update, portable] = await Promise.all([check(), detectPortable()]);
      if (update) {
        _state = {
          kind: "available",
          version: update.version,
          notes: update.body ?? null,
          update,
          portable,
        };
      } else {
        _state = { kind: "idle" };
      }
    } catch {
      // Quiet on startup — the user didn't ask for this check, and a
      // "couldn't reach update server" log line on every cold start
      // (common on intermittent networks the rahgozar audience runs
      // on) is just noise. Manual checks via the About tab surface
      // errors via toast for the cases the user explicitly opted into.
      _state = { kind: "idle" };
    }
  },

  /**
   * Manual "check for updates" invocation. Same call as
   * `checkOnStartup` but flips state to `error` on failure so the
   * caller can surface a toast — the user is actively waiting on a
   * result and "nothing happened" is worse than an error message.
   */
  async checkNow(): Promise<UpdateState> {
    _state = { kind: "checking" };
    try {
      const [update, portable] = await Promise.all([check(), detectPortable()]);
      if (update) {
        _state = {
          kind: "available",
          version: update.version,
          notes: update.body ?? null,
          update,
          portable,
        };
      } else {
        _state = { kind: "idle" };
      }
    } catch (e) {
      _state = { kind: "error", message: String(e) };
    }
    return _state;
  },

  /**
   * Download the available update + verify its ed25519 signature +
   * install (the plugin handles all three). On success, restart the
   * app — the new binary is what comes back up.
   *
   * On the Windows portable build this would instead download the MSI
   * and run the installer (the only Windows entry in `latest.json`),
   * stranding the user with two side-by-side installs. The portable
   * branch redirects to the GitHub release page so they can download a
   * fresh portable .exe manually — the only update path that keeps
   * portable users portable.
   */
  async installAndRestart(): Promise<void> {
    if (_state.kind !== "available") return;
    if (_state.portable) {
      try {
        await openUrl(RELEASE_PAGE_URL);
      } catch (e) {
        _state = { kind: "error", message: String(e) };
      }
      return;
    }
    const { update, version } = _state;
    _state = { kind: "downloading", version, downloaded: 0, total: null };
    try {
      let total: number | null = null;
      let downloaded = 0;
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            total = event.data.contentLength ?? null;
            _state = { kind: "downloading", version, downloaded: 0, total };
            break;
          case "Progress":
            downloaded += event.data.chunkLength;
            _state = { kind: "downloading", version, downloaded, total };
            break;
          case "Finished":
            _state = { kind: "installed", version };
            break;
        }
      });
      // `downloadAndInstall` on Windows + Linux requires an explicit
      // relaunch — the plugin replaces the binary but doesn't bounce
      // the process. macOS auto-relaunches; calling relaunch() on
      // macOS is a no-op so this is safe everywhere.
      await relaunch();
    } catch (e) {
      _state = { kind: "error", message: String(e) };
    }
  },

  /** Dismiss the banner without installing — until next startup. */
  dismiss(): void {
    if (_state.kind === "available" || _state.kind === "error") {
      _state = { kind: "idle" };
    }
  },
};
