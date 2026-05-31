// Typed wrappers around the Tauri IPC surface.
//
// One module owns "how do we talk to the Rust backend" so call sites
// stay readable (no inline `invoke<…>("snake_case_name", { … })`) and
// renaming a command on the Rust side is a one-file change here.
//
// DTO shapes here MUST match the `#[derive(Serialize)]` structs in
// `desktop/src-tauri/src/commands.rs`. When you add a field on the
// Rust side, mirror it here — TypeScript will flag stale usages at
// compile time via the `tsc`/`svelte-check` pass.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ── Read-only commands ───────────────────────────────────────────────

export interface StatusDto {
  running: boolean;
  uptime_secs: number | null;
  last_error: string | null;
}

/**
 * One row in the deployment-IDs editor. `enabled === false` parks the
 * ID without deleting it — disabled rows stay in config.json so the
 * user can flip them back on without re-typing. Mirrors
 * `ScriptIdDto` on the Rust side.
 */
export interface ScriptIdDto {
  id: string;
  enabled: boolean;
}

export interface ConfigDto {
  mode: string;
  listen_host: string;
  listen_port: number;
  socks5_port: number | null;
  script_ids: ScriptIdDto[];
  auth_key: string;
  front_domain: string;
  google_ip: string;
  log_level: string;
  // ── Drive-mode (mode === "drive") ────────────────────────────────
  // The OAuth refresh token isn't exposed in the form — it's managed
  // by `driveOauthStart` / `driveOauthComplete` and reflected here
  // only as the boolean `drive_has_refresh_token`. Everything else
  // is a regular form field bound to its own input.
  drive_folder_id: string;
  drive_relay_pubkey: string;
  drive_poll_interval_ms: number;
  drive_max_concurrent_uploads: number;
  /** BYO OAuth client_id from Google Cloud Console — see
   *  `docs/drive_oauth_setup.md`. Required for Drive mode; no
   *  embedded default. */
  drive_oauth_client_id: string;
  /** BYO OAuth client_secret paired with `drive_oauth_client_id`.
   *  Per RFC 8252 §8.6 not actually secret for installed apps, but
   *  Google's token endpoint requires it. */
  drive_oauth_client_secret: string;
  /** Read-only: true iff the on-disk `drive.oauth_refresh_token` is
   *  non-empty. UI uses this to swap "Sign in with Google" for
   *  "Signed in. Re-link" without round-tripping the secret. */
  drive_has_refresh_token: boolean;
}

/** Write side of the Tunnel form — same fields as `ConfigDto`. */
export type ConfigUpdate = ConfigDto;

// ── Drive-mode setup ─────────────────────────────────────────────────

export interface DriveOauthStartDto {
  state_token: string;
  auth_url: string;
}

export interface DriveOauthCompleteDto {
  /** True once the refresh token has been persisted server-side.
   *  The refresh token itself is deliberately NOT returned to the
   *  renderer — it never has to cross the IPC boundary. */
  signed_in: boolean;
  /** Empty under the current `drive.file`-only OAuth scope. The UI
   *  surfaces "Signed in" without naming the account; the user
   *  already chose it in the browser. */
  email: string;
}

export interface DriveTestDto {
  folder_id: string;
  files_count: number;
}

export interface TestResult {
  pass: boolean;
}

/**
 * Daily-usage stats for the "Usage today" card. `null` means there's
 * nothing to show — either no proxy running, or the running mode
 * (`direct`) doesn't use a `DomainFronter` and so has no quota stats.
 */
export interface UsageDto {
  today_calls: number;
  today_bytes: number;
  today_key: string;
  today_reset_secs: number;
  free_quota_per_day: number;
}

export interface CaStatusDto {
  exists: boolean;
  trusted: boolean;
  path: string;
  fingerprint: string | null;
  subject_cn: string | null;
}

/**
 * One fronting group — mirrors `rahgozar::config::FrontingGroup`.
 * Routes `domains` (case-insensitive, dot-anchored suffix match)
 * through `ip` with `sni` on the outbound TLS handshake.
 *
 * Camouflage mode (`force_ip`): dial the destination's own DoH-resolved
 * IP instead of `ip` (which may be empty), send `sni` only to blind DPI,
 * and verify the cert against the real host (or `verify_names`). Used by
 * the curated `google-video` / `meta` groups. Both fields are optional
 * and omitted by the backend when unset (force_ip=false / empty list).
 */
export interface FrontingGroup {
  name: string;
  ip: string;
  sni: string;
  domains: string[];
  force_ip?: boolean;
  verify_names?: string[];
}

export interface DiscoverResultDto {
  hostname: string;
  best_ip: string | null;
  reachable_count: number;
}

export interface SniHostDto {
  host: string;
  enabled: boolean;
}

export interface SniProbeResult {
  host: string;
  reachable: boolean;
}

export const api = {
  version(): Promise<string> {
    return invoke<string>("version");
  },
  getStatus(): Promise<StatusDto> {
    return invoke<StatusDto>("get_status");
  },
  getStats(): Promise<UsageDto | null> {
    return invoke<UsageDto | null>("get_stats");
  },
  getConfig(): Promise<ConfigDto> {
    return invoke<ConfigDto>("get_config");
  },
  saveConfig(update: ConfigUpdate): Promise<ConfigDto> {
    return invoke<ConfigDto>("save_config", { update });
  },
  startProxy(): Promise<void> {
    return invoke<void>("start_proxy");
  },
  stopProxy(): Promise<void> {
    return invoke<void>("stop_proxy");
  },
  testRelay(): Promise<TestResult> {
    return invoke<TestResult>("test_relay");
  },
  scanIps(): Promise<TestResult> {
    return invoke<TestResult>("scan_ips");
  },
  getCaStatus(): Promise<CaStatusDto> {
    return invoke<CaStatusDto>("get_ca_status");
  },
  /** Mint the CA on disk if it doesn't exist yet, then return the
   *  fresh status. Called by CaCard.onMount in MITM-using modes so
   *  the user can inspect the fingerprint + install the cert
   *  before clicking Start. Idempotent — no-ops if the file is
   *  already on disk. */
  mintCaIfMissing(): Promise<CaStatusDto> {
    return invoke<CaStatusDto>("mint_ca_if_missing");
  },
  installCa(): Promise<CaStatusDto> {
    return invoke<CaStatusDto>("install_ca_cmd");
  },
  removeCa(): Promise<string> {
    return invoke<string>("remove_ca_cmd");
  },
  getFrontingGroups(): Promise<FrontingGroup[]> {
    return invoke<FrontingGroup[]>("get_fronting_groups");
  },
  saveFrontingGroups(groups: FrontingGroup[]): Promise<FrontingGroup[]> {
    return invoke<FrontingGroup[]>("save_fronting_groups", { groups });
  },
  discoverFront(hostname: string): Promise<DiscoverResultDto> {
    return invoke<DiscoverResultDto>("discover_front_cmd", { hostname });
  },
  getSniPool(): Promise<SniHostDto[]> {
    return invoke<SniHostDto[]>("get_sni_pool");
  },
  saveSniPool(entries: SniHostDto[]): Promise<void> {
    return invoke<void>("save_sni_pool", { entries });
  },
  probeSni(host: string): Promise<SniProbeResult> {
    return invoke<SniProbeResult>("probe_sni", { host });
  },
  drainLogs(): Promise<string[]> {
    return invoke<string[]>("drain_logs");
  },
  clearLogs(): Promise<void> {
    return invoke<void>("clear_logs");
  },
  getRawConfig(): Promise<string> {
    return invoke<string>("get_raw_config");
  },
  saveRawConfig(text: string): Promise<void> {
    return invoke<void>("save_raw_config", { text });
  },
  // ── Drive-mode setup ──────────────────────────────────────────────
  //
  // Sequence:
  //   1. `driveOauthStart` takes the user-pasted OAuth client_id +
  //      secret + google_ip from the FORM (not disk), returns an
  //      auth URL + state token. UI shows the URL with Copy + Open
  //      buttons so the user can paste it into whichever browser
  //      they're signed into Google with.
  //   2. User signs in, Google redirects to a 127.0.0.1 loopback URL
  //      the Rust side bound — the listener task captures the code
  //      and exchanges it for a refresh token.
  //   3. JS calls `driveOauthComplete(state_token)` which long-polls
  //      (up to 120s) for the listener's result and atomically
  //      persists all three OAuth fields (client_id, client_secret,
  //      refresh_token) into config.json.
  //   4. `driveCreateFolder(name)` / `driveTestConnection()` /
  //      `driveValidateRelayPubkey(s)` are independent setup
  //      affordances the UI surfaces as buttons.
  driveOauthStart(args: {
    oauthClientId: string;
    oauthClientSecret: string;
    googleIp: string;
  }): Promise<DriveOauthStartDto> {
    return invoke<DriveOauthStartDto>("drive_oauth_start", args);
  },
  driveOauthComplete(stateToken: string): Promise<DriveOauthCompleteDto> {
    return invoke<DriveOauthCompleteDto>("drive_oauth_complete", {
      stateToken,
    });
  },
  driveCreateFolder(name: string): Promise<string> {
    return invoke<string>("drive_create_folder", { name });
  },
  driveTestConnection(): Promise<DriveTestDto> {
    return invoke<DriveTestDto>("drive_test_connection");
  },
  driveValidateRelayPubkey(s: string): Promise<void> {
    return invoke<void>("drive_validate_relay_pubkey", { s });
  },
};

// ── Event stream ─────────────────────────────────────────────────────

export interface StatusEvent {
  running: boolean;
  last_error: string | null;
}

/**
 * Subscribe to `rahgozar:status` events emitted by the Rust backend on
 * proxy start / stop / crash. The handler fires once per transition;
 * call the returned function to unsubscribe (typically in an `onMount`
 * cleanup).
 */
export function onStatusChange(
  handler: (e: StatusEvent) => void,
): Promise<UnlistenFn> {
  return listen<StatusEvent>("rahgozar:status", (event) => {
    handler(event.payload);
  });
}

/**
 * Subscribe to `rahgozar:log` events — one event per log line emitted
 * by the running proxy (and by Tauri's own startup). The Logs tab
 * uses this to tail in real time after fetching the initial snapshot
 * via `api.drainLogs()`.
 */
export function onLogLine(
  handler: (line: string) => void,
): Promise<UnlistenFn> {
  return listen<string>("rahgozar:log", (event) => {
    handler(event.payload);
  });
}
