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

export interface ConfigDto {
  mode: string;
  listen_host: string;
  listen_port: number;
  socks5_port: number | null;
  script_ids: string[];
  auth_key: string;
  front_domain: string;
  google_ip: string;
  log_level: string;
}

/** Write side of the Tunnel form — same fields as `ConfigDto`. */
export type ConfigUpdate = ConfigDto;

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
 */
export interface FrontingGroup {
  name: string;
  ip: string;
  sni: string;
  domains: string[];
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
