<script lang="ts">
  // Floating "update available" banner. Mounted in the App shell above
  // the tab content so it's visible regardless of which tab the user
  // is on — surfacing an update offer only on the Status tab would
  // bury it for anyone who lives in Logs or Tunnel.
  //
  // Three visible states:
  //   - `available`: green-ish banner with "Install & restart" + "Later"
  //   - `downloading`: progress with the new version number
  //   - `installed`: brief flash before the relaunch fires (the OS
  //                  takes over before the user can act on it)
  //
  // `idle`, `checking`, and `error` render nothing — those are
  // handled by Toaster (for manual checks) or by silent no-op (for
  // the auto-check on startup).

  import { fly } from "svelte/transition";
  import { quintOut } from "svelte/easing";

  import { t, tn } from "../i18n.svelte";
  import { updater } from "../updater.svelte";

  function flyY() {
    return { y: -16, duration: 220, easing: quintOut };
  }

  // Human-friendly download progress. Returns null when we don't yet
  // know the total content length (early in the download).
  function progressLabel(downloaded: number, total: number | null): string {
    const mb = (n: number) => (n / (1024 * 1024)).toFixed(1);
    if (total == null) return `${mb(downloaded)} MB`;
    const pct = total > 0 ? Math.round((downloaded / total) * 100) : 0;
    return `${pct}%  (${mb(downloaded)} / ${mb(total)} MB)`;
  }
</script>

{#if updater.state.kind === "available"}
  <div
    in:fly={flyY()}
    out:fly={{ ...flyY(), duration: 160 }}
    class="bg-success/12 border-success/40 text-success flex items-center gap-4 border-b px-6 py-3"
    role="status"
  >
    <div class="flex-1">
      <p class="text-sm font-semibold">
        {t("update.available_title")}
      </p>
      <p class="text-success/80 text-xs">
        {#if updater.state.portable}
          {tn("update.available_body_portable", { version: updater.state.version })}
        {:else}
          {tn("update.available_body", { version: updater.state.version })}
        {/if}
      </p>
    </div>
    <div class="flex items-center gap-2">
      <button
        type="button"
        onclick={() => updater.dismiss()}
        class="text-secondary hover:text-primary rounded-md px-3 py-1.5 text-xs transition-colors"
      >
        {t("update.dismiss")}
      </button>
      <button
        type="button"
        onclick={() => updater.installAndRestart()}
        class="bg-success hover:bg-success/90 rounded-md px-4 py-1.5 text-xs font-semibold text-black transition-colors"
      >
        {#if updater.state.portable}
          {t("update.open_release_page")}
        {:else}
          {t("update.install")}
        {/if}
      </button>
    </div>
  </div>
{:else if updater.state.kind === "downloading"}
  <div
    in:fly={flyY()}
    class="bg-accent/12 border-accent/40 text-accent flex items-center gap-4 border-b px-6 py-3"
    role="status"
  >
    <div class="flex-1">
      <p class="text-sm font-semibold">
        {tn("update.downloading", { version: updater.state.version })}
      </p>
      <p class="text-accent/80 font-mono text-xs">
        {progressLabel(updater.state.downloaded, updater.state.total)}
      </p>
    </div>
  </div>
{:else if updater.state.kind === "installed"}
  <div
    in:fly={flyY()}
    class="bg-success/12 border-success/40 text-success flex items-center gap-4 border-b px-6 py-3"
    role="status"
  >
    <p class="text-sm font-semibold">
      {tn("update.installed", { version: updater.state.version })}
    </p>
  </div>
{/if}
