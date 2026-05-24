<script lang="ts">
  // Status tab: runtime state at a glance.
  //
  // Hero card: large coloured dot + Running/Stopped label + uptime
  // tick. Primary action button on the right (Start/Stop). Inline
  // error rows pin failures so the user can read them after a toast
  // would have faded. Read-only config preview sits below as a sanity
  // check ("is this the config I'd start?").
  //
  // Editing lives in the Tunnel tab; this screen is intentionally
  // light so it stays glanceable.

  import { onDestroy, onMount } from "svelte";
  import type { UnlistenFn } from "@tauri-apps/api/event";

  import {
    api,
    onStatusChange,
    type ConfigDto,
    type StatusDto,
  } from "../api";
  import { t, tn } from "../i18n.svelte";
  import { toast } from "../toast.svelte";
  import CaCard from "./CaCard.svelte";
  import UsageTodayCard from "./UsageTodayCard.svelte";

  // ── Reactive state ───────────────────────────────────────────────
  let status = $state<StatusDto | null>(null);
  let config = $state<ConfigDto | null>(null);

  // Uptime display: the backend hands us `uptime_secs` (an integer
  // second count) along with each status snapshot. Between snapshots
  // we tick the displayed value forward locally so the badge counts
  // smoothly without a backend round-trip per second.
  //
  // Anchor = the wall-clock millisecond when we last received a
  // status snapshot. The derived `uptimeLabel` below adds
  // `(now - anchorMs)` to `status.uptime_secs` to get a smoothly
  // advancing value. Updated whenever we mutate `status`, so:
  //   - mount: anchor = mount time, uptime stays continuous with the
  //            backend's value
  //   - Start event: anchor = event time, uptime restarts from 0
  //   - Stop event: status.running = false, label hides entirely
  //
  // Bug fix history: anchor was previously a `const` set once at
  // mount, which made the displayed uptime drift forward by the
  // age of the window itself — a Start clicked five minutes after
  // launch showed "5m 12s" immediately.
  let now = $state(Date.now());
  let anchorMs = $state(Date.now());
  let tick: ReturnType<typeof setInterval> | undefined;

  let pending = $state(false);
  let testing = $state(false);
  let scanning = $state(false);
  let actionError = $state<string | null>(null);
  let unlistenStatus: UnlistenFn | null = null;

  function modeUsesMitmCa(mode: string | null | undefined): boolean {
    return mode === "apps_script" || mode === "direct";
  }

  onMount(async () => {
    [status, config] = await Promise.all([
      api.getStatus(),
      api.getConfig().catch((e) => {
        // A corrupt config.json shouldn't blank the Status tab — keep
        // the runtime indicator usable and surface the read failure
        // inline instead.
        actionError = tn("status.read_config_error", { error: String(e) });
        return null;
      }),
    ]);
    // Re-anchor on the initial snapshot — until this point the anchor
    // was the mount time, which is fine if the backend was already
    // running when we mounted (uptime stays continuous), but for a
    // future Start event we'll re-anchor below.
    anchorMs = Date.now();

    unlistenStatus = await onStatusChange((event) => {
      // Merge in place: Rust already mutated its AppState before
      // emitting, so we can skip a follow-up get_status round-trip.
      // Re-anchor every transition so the displayed uptime restarts
      // from 0 on Start (instead of carrying the window-age forward)
      // and disappears immediately on Stop.
      if (status) {
        status = {
          running: event.running,
          uptime_secs: event.running ? 0 : null,
          last_error: event.last_error ?? status.last_error,
        };
        anchorMs = Date.now();
      }
    });

    tick = setInterval(() => {
      now = Date.now();
    }, 1000);
  });

  onDestroy(() => {
    if (unlistenStatus) unlistenStatus();
    if (tick) clearInterval(tick);
  });

  const uptimeLabel = $derived.by(() => {
    if (!status?.running || status.uptime_secs == null) return null;
    const elapsedSinceAnchor = Math.max(0, Math.floor((now - anchorMs) / 1000));
    return formatDuration(status.uptime_secs + elapsedSinceAnchor);
  });

  function formatDuration(secs: number): string {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
    if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
    return `${s}s`;
  }

  async function onStart() {
    pending = true;
    actionError = null;
    try {
      await api.startProxy();
    } catch (e) {
      actionError = String(e);
    } finally {
      pending = false;
    }
  }

  async function onStop() {
    pending = true;
    actionError = null;
    try {
      await api.stopProxy();
    } catch (e) {
      actionError = String(e);
    } finally {
      pending = false;
    }
  }

  async function onTestRelay() {
    testing = true;
    toast.info(t("status.test_running"));
    try {
      const result = await api.testRelay();
      if (result.pass) {
        toast.success(t("status.test_passed"));
      } else {
        toast.error(t("status.test_failed"));
      }
    } catch (e) {
      toast.error(String(e));
    } finally {
      testing = false;
    }
  }

  async function onScanIps() {
    scanning = true;
    toast.info(t("status.scan_running"));
    try {
      const result = await api.scanIps();
      // The scan reports per-IP details via tracing → Logs tab. The
      // top-level pass/fail just signals "did at least one IP probe
      // succeed?"; either way the user wants the Logs tab to inspect
      // the specifics.
      if (result.pass) {
        toast.success(t("status.scan_done"));
      } else {
        toast.error(t("status.scan_failed"));
      }
    } catch (e) {
      toast.error(String(e));
    } finally {
      scanning = false;
    }
  }
</script>

<div class="space-y-6">
  <!-- Hero card. -->
  <section
    class="bg-surface border-border-subtle rounded-lg border p-6 shadow-sm"
  >
    <div class="flex items-center gap-4">
      <span
        class="inline-block h-3 w-3 rounded-full {status?.running
          ? 'bg-success animate-pulse'
          : 'bg-muted'}"
        aria-hidden="true"
      ></span>
      <div class="flex-1">
        <p class="text-2xl font-semibold tracking-tight">
          {status == null
            ? t("status.loading")
            : status.running
              ? t("status.running")
              : t("status.stopped")}
        </p>
        {#if uptimeLabel}
          <p class="text-secondary mt-1 text-sm">
            {t("status.uptime")} <span class="font-mono">{uptimeLabel}</span>
          </p>
        {/if}
      </div>

      {#if status}
        <div class="flex flex-col items-end gap-2">
          {#if status.running}
            <button
              type="button"
              disabled={pending}
              onclick={onStop}
              class="bg-error/90 hover:bg-error inline-flex items-center gap-2 rounded-md px-5 py-2.5 font-semibold text-white shadow-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span aria-hidden="true">■</span> {t("status.stop")}
            </button>
          {:else}
            <button
              type="button"
              disabled={pending}
              onclick={onStart}
              class="bg-accent hover:bg-accent-hover inline-flex items-center gap-2 rounded-md px-5 py-2.5 font-semibold text-black shadow-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span aria-hidden="true">▶</span> {t("status.start")}
            </button>
          {/if}
          <!-- Diagnostic secondary actions. Both run independently of
               the persistent proxy (one-shot probes), share the same
               tracing channel that feeds the Logs tab, and surface
               their verdict via toasts. Stacked vertically under the
               primary so the hero action isn't visually competing
               with maintenance buttons. -->
          <div class="flex flex-col items-end gap-1">
            <button
              type="button"
              disabled={testing}
              onclick={onTestRelay}
              title={t("status.test_relay_hover")}
              class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              {testing ? t("status.test_running") : t("status.test_relay")}
            </button>
            <button
              type="button"
              disabled={scanning}
              onclick={onScanIps}
              title={t("status.scan_ips_hover")}
              class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              {scanning ? t("status.scan_running") : t("status.scan_ips")}
            </button>
          </div>
        </div>
      {/if}
    </div>

    {#if actionError}
      <p class="text-error mt-4 text-sm">
        <strong>{t("status.action_failed")}</strong>
        {actionError}
      </p>
    {/if}
    {#if status?.last_error && !actionError}
      <p class="text-warn mt-4 text-sm">
        <strong>{t("status.last_run_ended")}</strong>
        {status.last_error}
      </p>
    {/if}
  </section>

  <!-- Usage Today card. Only renders while the proxy is running AND
       the running mode has a fronter (apps_script / full). Owns its
       own poll + lifecycle. -->
  <UsageTodayCard />

  <!-- MITM CA card. Sits between the hero (does the proxy run?) and
       the config preview (what would it run with?). Its own data
       lifecycle, no props from this component.
       Hidden in no-MITM modes: those paths never touch the CA, so
       advertising "install this root cert"
       there is misleading and adds avoidable trust-store risk.
       The card itself triggers a lazy mint in onMount when the file
       is missing (via `mint_ca_if_missing`), so gating render here
       is also what stops CA generation in no-MITM modes. Matches
       the Android-side gate in HomeScreen. -->
  {#if config && modeUsesMitmCa(config.mode)}
    <CaCard />
  {/if}

  <!-- Read-only config preview. Real editor lives on the Tunnel tab. -->
  {#if config}
    <section class="bg-surface border-border-subtle rounded-lg border p-6">
      <div class="mb-4 flex items-center justify-between">
        <h2 class="text-secondary text-xs font-semibold tracking-wider uppercase">
          {t("status.current_config")}
        </h2>
        <span class="text-muted text-xs">{t("status.read_only_hint")}</span>
      </div>

      <dl class="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <dt class="text-secondary">{t("status.config_field.mode")}</dt>
        <dd class="font-mono">{config.mode}</dd>

        <dt class="text-secondary">{t("status.config_field.listen")}</dt>
        <dd class="font-mono">
          {config.listen_host}:{config.listen_port}{#if config.socks5_port}
            <span class="text-muted">
              {tn("status.socks5_chip", { port: config.socks5_port })}
            </span>
          {/if}
        </dd>

        <dt class="text-secondary">{t("status.config_field.front_domain")}</dt>
        <dd class="font-mono">{config.front_domain}</dd>

        <dt class="text-secondary">{t("status.config_field.google_ip")}</dt>
        <dd class="font-mono">{config.google_ip}</dd>

        <dt class="text-secondary">
          {t("status.config_field.deployment_ids")}
        </dt>
        <dd class="font-mono">
          {#if config.script_ids.length === 0}
            <span class="text-muted">{t("status.deployment_ids.none")}</span>
          {:else}
            {tn("status.deployment_ids.count", {
              enabled: config.script_ids.filter((e) => e.enabled).length,
              total: config.script_ids.length,
            })}
          {/if}
        </dd>

        <dt class="text-secondary">{t("status.config_field.log_level")}</dt>
        <dd class="font-mono">{config.log_level}</dd>
      </dl>
    </section>
  {/if}
</div>
