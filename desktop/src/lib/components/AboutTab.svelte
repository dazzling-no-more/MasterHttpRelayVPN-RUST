<script lang="ts">
  // About tab: version, project links, credits, licence.
  //
  // Strings here go through `t()` so the FA toggle in the header
  // flips them along with the rest of the surface. The proper noun
  // "rahgozar" stays Latin in English mode and switches to "رهگذر"
  // in Persian, matching what the Android release notes do.

  import { onMount } from "svelte";
  import { openUrl } from "@tauri-apps/plugin-opener";

  import { api } from "../api";
  import { t } from "../i18n.svelte";
  import { toast } from "../toast.svelte";
  import { updater } from "../updater.svelte";

  let version = $state<string | null>(null);

  onMount(async () => {
    version = await api.version();
  });

  async function open(url: string) {
    try {
      await openUrl(url);
    } catch {
      await navigator.clipboard.writeText(url).catch(() => {
        /* no fallback path beyond clipboard — swallow */
      });
    }
  }

  // Manual update check. Unlike the startup probe in App.svelte
  // (which is silent on "no update" + on errors), this one surfaces
  // every outcome via toast — the user clicked a button and expects
  // feedback.
  async function onCheckUpdates() {
    toast.info(t("update.checking"));
    const result = await updater.checkNow();
    switch (result.kind) {
      case "available":
        // Banner in App.svelte already surfaces the offer; no toast
        // needed here — would be redundant.
        break;
      case "idle":
        toast.success(t("update.up_to_date"));
        break;
      case "error":
        toast.error(
          t("update.error").replace("{error}", result.message),
        );
        break;
    }
  }
</script>

<div class="mx-auto max-w-xl space-y-8">
  <section class="space-y-2">
    <h2 class="text-3xl font-bold tracking-tight">{t("app.name")}</h2>
    <p class="text-secondary">{t("app.tagline")}</p>
    {#if version}
      <div class="flex items-center gap-3">
        <p class="text-muted font-mono text-sm">v{version}</p>
        <button
          type="button"
          onclick={onCheckUpdates}
          disabled={updater.state.kind === "checking"}
          class="text-accent hover:text-accent-hover text-xs underline transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {updater.state.kind === "checking"
            ? t("update.checking")
            : t("update.check_now")}
        </button>
      </div>
    {/if}
  </section>

  <section class="space-y-3">
    <h3 class="text-secondary text-xs font-semibold tracking-wider uppercase">
      {t("about.heading_project")}
    </h3>
    <ul class="space-y-2 text-sm">
      <li>
        <button
          type="button"
          onclick={() => open("https://github.com/dazzling-no-more/rahgozar")}
          class="text-accent hover:text-accent-hover transition-colors"
        >
          {t("about.link.source")} &nbsp;<span class="text-muted text-xs">
            {t("about.link.suffix_github")}
          </span>
        </button>
      </li>
      <li>
        <button
          type="button"
          onclick={() =>
            open("https://github.com/dazzling-no-more/rahgozar/releases")}
          class="text-accent hover:text-accent-hover transition-colors"
        >
          {t("about.link.releases")} &nbsp;<span class="text-muted text-xs">
            {t("about.link.suffix_github")}
          </span>
        </button>
      </li>
      <li>
        <button
          type="button"
          onclick={() =>
            open("https://github.com/dazzling-no-more/rahgozar/issues/new")}
          class="text-accent hover:text-accent-hover transition-colors"
        >
          {t("about.link.report_bug")} &nbsp;<span class="text-muted text-xs">
            {t("about.link.suffix_github")}
          </span>
        </button>
      </li>
    </ul>
  </section>

  <section class="text-muted space-y-2 text-sm">
    <p>{t("about.license")}</p>
    <p>{t("about.font_credit")}</p>
  </section>
</div>
