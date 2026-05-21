<script lang="ts">
  // Logs tab: tailing the proxy's tracing output in real time.
  //
  // Two data paths: a one-shot `drainLogs()` on mount populates the
  // scroll-back from the backend's ring buffer, then a
  // `rahgozar:log` event listener appends each new line as it
  // arrives. Same lines, same order — the ring buffer is just the
  // "what would the event have been if you'd been listening" record.
  //
  // Filter chips run on the *classified* level (see classifyLine),
  // mirroring the egui binary's INFO/WARN/ERROR/other split. Lines
  // are still appended to the underlying array regardless of filter
  // state so toggling a chip back on re-reveals them without a
  // round-trip.
  //
  // Auto-scroll: a checkbox lets the user pause auto-follow when they
  // scroll up to inspect history. Manual scroll-up unpins; manual
  // scroll-down to the bottom re-pins. Matches what every console UI
  // does.

  import { onDestroy, onMount, tick } from "svelte";
  import type { UnlistenFn } from "@tauri-apps/api/event";

  import { api, onLogLine } from "../api";
  import { t, tn } from "../i18n.svelte";
  import { toast } from "../toast.svelte";

  // ── State ────────────────────────────────────────────────────────
  let lines = $state<string[]>([]);
  let filterInfo = $state(true);
  let filterWarn = $state(true);
  let filterError = $state(true);
  let filterOther = $state(true);
  let autoScroll = $state(true);

  let viewport: HTMLDivElement | null = null;
  let unlisten: UnlistenFn | null = null;

  // ── Level classifier — same word-boundary rules as the egui side.
  type Level = "info" | "warn" | "error" | "other";
  function classifyLine(line: string): Level {
    // Match the egui `classify_log_line` heuristic: look for " INFO ",
    // " WARN ", " ERROR " in that priority order. Padding with spaces
    // avoids matching tokens that happen to appear inside payloads
    // (e.g. "INFO" inside a hex string or URL).
    if (line.includes(" ERROR ")) return "error";
    if (line.includes(" WARN ")) return "warn";
    if (line.includes(" INFO ")) return "info";
    return "other";
  }

  function passes(line: string): boolean {
    switch (classifyLine(line)) {
      case "info":
        return filterInfo;
      case "warn":
        return filterWarn;
      case "error":
        return filterError;
      case "other":
        return filterOther;
    }
  }

  function colorFor(level: Level): string {
    switch (level) {
      case "info":
        return "text-success";
      case "warn":
        return "text-warn";
      case "error":
        return "text-error";
      case "other":
        return "text-secondary";
    }
  }

  // ── Lifecycle ────────────────────────────────────────────────────
  onMount(async () => {
    lines = await api.drainLogs();
    await tick();
    scrollToBottom();

    unlisten = await onLogLine((line) => {
      // Append-only — the ring on the Rust side enforces a cap, so
      // this array won't grow unbounded once it reaches LOG_MAX.
      // (We could also slice on the client; the cap is enforced
      // server-side so a slow listener doesn't OOM the renderer.)
      lines = [...lines, line];
      if (autoScroll) {
        // Defer to after the DOM updates so scrollTop hits the new
        // last row, not the old one.
        tick().then(scrollToBottom);
      }
    });
  });

  onDestroy(() => {
    if (unlisten) unlisten();
  });

  function scrollToBottom() {
    if (viewport) viewport.scrollTop = viewport.scrollHeight;
  }

  function onScroll() {
    if (!viewport) return;
    // 4-px slop so a fractional scroll-back at the bottom doesn't
    // unpin auto-scroll on devices with sub-pixel scrolling.
    const atBottom =
      viewport.scrollTop + viewport.clientHeight >=
      viewport.scrollHeight - 4;
    autoScroll = atBottom;
  }

  // ── Actions ──────────────────────────────────────────────────────
  async function onCopy() {
    const body = visible.join("\n");
    try {
      await navigator.clipboard.writeText(body);
      toast.success(tn("logs.copy_success", { n: visible.length }));
    } catch {
      toast.error(t("logs.copy_failed"));
    }
  }

  async function onClear() {
    await api.clearLogs();
    lines = [];
  }

  // ── Derived ──────────────────────────────────────────────────────
  const visible = $derived(lines.filter(passes));
</script>

<div class="flex h-full flex-col gap-3">
  <!-- Action row: filter chips + auto-scroll + actions. -->
  <div class="flex flex-wrap items-center gap-3">
    <span class="text-secondary text-xs">{t("logs.filter")}</span>
    {#each [
      { id: "info" as const, label: t("logs.level.info"), model: () => filterInfo, set: (v: boolean) => (filterInfo = v), color: "border-success/40 text-success bg-success/15" },
      { id: "warn" as const, label: t("logs.level.warn"), model: () => filterWarn, set: (v: boolean) => (filterWarn = v), color: "border-warn/40 text-warn bg-warn/15" },
      { id: "error" as const, label: t("logs.level.error"), model: () => filterError, set: (v: boolean) => (filterError = v), color: "border-error/40 text-error bg-error/15" },
      { id: "other" as const, label: t("logs.level.other"), model: () => filterOther, set: (v: boolean) => (filterOther = v), color: "border-border-subtle text-muted" },
    ] as const as chip}
      <button
        type="button"
        onclick={() => chip.set(!chip.model())}
        class="rounded-md border px-3 py-1 text-xs font-semibold transition-colors {chip.model()
          ? chip.color
          : 'border-border-subtle text-muted hover:text-secondary'}"
      >
        {chip.label}
      </button>
    {/each}

    <label class="text-secondary ms-2 flex items-center gap-2 text-xs">
      <input
        type="checkbox"
        bind:checked={autoScroll}
        class="accent-accent h-3.5 w-3.5"
      />
      {t("logs.auto_scroll")}
    </label>

    <div class="ms-auto flex items-center gap-2">
      <button
        type="button"
        onclick={onCopy}
        class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1 text-xs transition-colors"
      >
        {t("logs.copy")}
      </button>
      <button
        type="button"
        onclick={onClear}
        class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1 text-xs transition-colors"
      >
        {t("logs.clear")}
      </button>
    </div>
  </div>

  <!-- Viewport. Monospace, dim line numbers via CSS counter so we
       don't have to render per-row indices. -->
  <div
    bind:this={viewport}
    onscroll={onScroll}
    class="bg-input border-border-subtle font-mono min-h-0 flex-1 overflow-auto rounded-lg border p-3 text-xs leading-relaxed"
  >
    {#if visible.length === 0}
      <p class="text-muted italic">
        {#if lines.length === 0}
          {t("logs.empty")}
        {:else}
          {t("logs.all_filtered")}
        {/if}
      </p>
    {:else}
      {#each visible as line, i (i + ":" + line.length)}
        <div class="whitespace-pre-wrap break-all {colorFor(classifyLine(line))}">
          {line}
        </div>
      {/each}
    {/if}
  </div>

  <p class="text-muted text-xs">
    {tn("logs.count", { shown: visible.length, total: lines.length })}
  </p>
</div>
