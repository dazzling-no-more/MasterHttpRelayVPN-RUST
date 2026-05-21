<script lang="ts">
  // "Usage today (estimated)" card — Status tab.
  //
  // Polls `get_stats` once a second while the proxy is running and
  // renders today's Apps Script relay calls + transferred bytes
  // against the free-tier 20k/day quota, plus a countdown to the
  // next 00:00 Pacific Time reset.
  //
  // Why polling instead of an event stream:
  //   - The numbers change on every relay call; an event-per-call
  //     would flood the UI thread under load.
  //   - 1 Hz is plenty for human-readable progress (the legacy
  //     egui UI used the same cadence).
  //   - `get_stats` is cheap on the Rust side — just reads a
  //     handful of atomics.
  //
  // Hides itself entirely when no proxy is running OR when the
  // running mode (`direct`) has no fronter and so reports no usage
  // — better to disappear than to show all-zeros that the user has
  // to learn to interpret as "n/a".

  import { onDestroy, onMount } from "svelte";
  import type { UnlistenFn } from "@tauri-apps/api/event";
  import { openUrl } from "@tauri-apps/plugin-opener";

  import { api, onStatusChange, type UsageDto } from "../api";
  import { t, tn } from "../i18n.svelte";

  let usage = $state<UsageDto | null>(null);
  let running = $state(false);
  let poll: ReturnType<typeof setInterval> | undefined;
  let unlistenStatus: UnlistenFn | null = null;

  // ── Lifecycle ────────────────────────────────────────────────────
  onMount(async () => {
    // Read the current running state once so a card that mounts
    // while the proxy is already up starts polling immediately.
    const s = await api.getStatus();
    running = s.running;
    if (running) {
      await refresh();
      startPolling();
    }

    unlistenStatus = await onStatusChange((event) => {
      running = event.running;
      if (event.running) {
        void refresh();
        startPolling();
      } else {
        stopPolling();
        // Clear the snapshot so the card hides immediately on Stop
        // instead of lingering with stale numbers until the user
        // navigates away.
        usage = null;
      }
    });
  });

  onDestroy(() => {
    stopPolling();
    if (unlistenStatus) unlistenStatus();
  });

  function startPolling() {
    if (poll) return;
    poll = setInterval(() => {
      void refresh();
    }, 1000);
  }
  function stopPolling() {
    if (poll) {
      clearInterval(poll);
      poll = undefined;
    }
  }

  async function refresh() {
    try {
      usage = await api.getStats();
    } catch {
      usage = null;
    }
  }

  // ── Derived display ──────────────────────────────────────────────
  const pct = $derived.by(() => {
    if (!usage || usage.free_quota_per_day === 0) return 0;
    const v = (usage.today_calls / usage.free_quota_per_day) * 100;
    return Math.min(100, Math.max(0, v));
  });

  // Progress-bar colour bands: green well under quota, amber as we
  // approach the limit, red when over. Same hue choices as the level
  // chips on the Logs tab so the brand language stays consistent.
  const barClass = $derived.by(() => {
    if (pct >= 90) return "bg-error";
    if (pct >= 70) return "bg-warn";
    return "bg-success";
  });

  /** Format a byte count as "N.NN MB" / "N.NN GB". */
  function formatBytes(b: number): string {
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(2)} MB`;
    return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  /** Format a duration in seconds as "Xh Ym Zs" / "Xm Ys" / "Xs". */
  function formatDuration(secs: number): string {
    if (secs <= 0) return "0s";
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
    if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
    return `${s}s`;
  }

  async function openQuotaDashboard() {
    // Google Apps Script's quota dashboard. Opens in the user's
    // default browser via the opener plugin (not inside the
    // embedded webview, which Tauri blocks by default for off-
    // origin navigation anyway).
    try {
      await openUrl("https://script.google.com/home/usage");
    } catch {
      /* swallow — best-effort */
    }
  }
</script>

{#if running && usage}
  <section
    class="bg-surface border-border-subtle rounded-lg border p-6"
  >
    <header class="mb-3 flex items-center justify-between">
      <h2 class="text-secondary text-xs font-semibold tracking-wider uppercase">
        {t("usage.heading")}
      </h2>
      <span class="text-muted text-xs">
        {tn("usage.day_key", { date: usage.today_key })}
      </span>
    </header>

    <p class="text-secondary mb-4 text-sm">{t("usage.help")}</p>

    <!-- Main progress: calls / quota. The bar's colour shifts amber
         and then red as you approach the daily cap so the visual
         alarm matches the actual risk. -->
    <div class="space-y-2">
      <div class="flex items-baseline justify-between">
        <span class="text-primary text-lg font-semibold tabular-nums">
          {tn("usage.calls", {
            calls: usage.today_calls.toLocaleString(),
            quota: usage.free_quota_per_day.toLocaleString(),
          })}
        </span>
        <span class="text-secondary font-mono text-xs">
          {pct.toFixed(1)}%
        </span>
      </div>
      <div class="bg-input h-2 w-full overflow-hidden rounded-full">
        <div
          class="{barClass} h-full transition-all duration-500"
          style="width: {pct}%"
          aria-hidden="true"
        ></div>
      </div>
    </div>

    <!-- Secondary stats: bytes + reset countdown + link. The bytes
         figure helps users on metered connections (mobile hotspot,
         etc.) decide whether to keep the proxy up. -->
    <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-1 text-xs">
      <span class="text-secondary">
        {tn("usage.bytes", { bytes: formatBytes(usage.today_bytes) })}
      </span>
      <span class="text-secondary">
        {tn("usage.reset_in", {
          duration: formatDuration(usage.today_reset_secs),
        })}
      </span>
      <button
        type="button"
        onclick={openQuotaDashboard}
        class="text-accent hover:text-accent-hover ms-auto transition-colors"
      >
        {t("usage.dashboard_link")} ↗
      </button>
    </div>
  </section>
{/if}
