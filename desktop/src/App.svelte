<script lang="ts">
  // App shell: header (with lang + theme toggles) + tab nav + dispatcher.
  //
  // Side effect of importing `i18n` / `theme`: an `$effect` below syncs
  // their reactive values onto the <html> element's `lang`, `dir`, and
  // `data-theme` attributes. That way:
  //   - Persian flips the whole document RTL (form controls, scroll
  //     bar position, etc.) — not just the strings.
  //   - Light/dark cascades through every `var(--color-*)` reference
  //     (Tailwind utility classes, custom CSS) via the data-theme
  //     override block in app.css.

  import { onMount } from "svelte";
  import { fade } from "svelte/transition";
  import { cubicOut } from "svelte/easing";

  import { api } from "./lib/api";
  import { i18n, t } from "./lib/i18n.svelte";
  import { theme } from "./lib/theme.svelte";
  import { DEFAULT_TAB, TABS, type TabId } from "./lib/tabs";
  import { updater } from "./lib/updater.svelte";

  import AboutTab from "./lib/components/AboutTab.svelte";
  import AdvancedTab from "./lib/components/AdvancedTab.svelte";
  import LogsTab from "./lib/components/LogsTab.svelte";
  import StatusTab from "./lib/components/StatusTab.svelte";
  import Toaster from "./lib/components/Toaster.svelte";
  import TunnelTab from "./lib/components/TunnelTab.svelte";
  import UpdateBanner from "./lib/components/UpdateBanner.svelte";

  let active = $state<TabId>(DEFAULT_TAB);
  let version = $state<string | null>(null);

  onMount(async () => {
    version = await api.version();
    // Quiet one-shot updater probe at startup. Surfaces the
    // `<UpdateBanner />` below if a newer release is published; silent
    // on "up to date" + on network errors (the user didn't ask, so
    // a "couldn't reach update server" toast would just be noise).
    void updater.checkOnStartup();
  });

  // Sync UI prefs onto <html>. This runs once on mount + on every
  // change to `i18n.lang` / `theme.current` thanks to the rune deps
  // tracking — no manual subscribe/unsubscribe.
  $effect(() => {
    const root = document.documentElement;
    root.lang = i18n.lang;
    root.dir = i18n.isRtl ? "rtl" : "ltr";
    root.dataset.theme = theme.current;
  });
</script>

<div class="flex h-screen flex-col">
  <!-- Header strip: title, language chips, theme chip, version tag. -->
  <header
    class="bg-surface border-border-subtle flex items-center gap-4 border-b px-6 py-3"
  >
    <h1 class="text-xl font-bold tracking-tight">{t("app.name")}</h1>

    <!-- Spacer pushes the chips + version to the trailing edge. With
         `dir="rtl"` set on <html>, ms-auto becomes physical leading,
         so the chips stay on the leading edge in both directions. -->
    <div class="ms-auto flex items-center gap-3">
      <!-- Language chip pair: tap-active is no-op so a fat-fingered
           click doesn't surprise. Same pattern as the egui binary. -->
      <div
        class="bg-raised border-border-subtle inline-flex overflow-hidden rounded-md border text-xs font-semibold"
      >
        {#each ["en", "fa"] as const as code (code)}
          <button
            type="button"
            onclick={() => i18n.set(code)}
            class="px-2.5 py-1 transition-colors {i18n.lang === code
              ? 'bg-accent text-black'
              : 'text-secondary hover:text-primary'}"
            aria-pressed={i18n.lang === code}
          >
            {code.toUpperCase()}
          </button>
        {/each}
      </div>

      <!-- Theme toggle. Single button (not a pair) — fewer pixels,
           still unambiguous because the glyph + tooltip describe the
           *destination* state ("Switch to light"). -->
      <button
        type="button"
        onclick={() => theme.toggle()}
        title={theme.current === "dark"
          ? t("header.theme.toggle_to_light")
          : t("header.theme.toggle_to_dark")}
        aria-label={theme.current === "dark"
          ? t("header.theme.toggle_to_light")
          : t("header.theme.toggle_to_dark")}
        class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong grid h-7 w-7 place-items-center rounded-md border transition-colors"
      >
        {#if theme.current === "dark"}
          <!-- Sun glyph: clicking switches to light. -->
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2" />
            <path d="M12 20v2" />
            <path d="m4.93 4.93 1.41 1.41" />
            <path d="m17.66 17.66 1.41 1.41" />
            <path d="M2 12h2" />
            <path d="M20 12h2" />
            <path d="m4.93 19.07 1.41-1.41" />
            <path d="m17.66 6.34 1.41-1.41" />
          </svg>
        {:else}
          <!-- Moon glyph: clicking switches to dark. -->
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
        {/if}
      </button>

      {#if version}
        <a
          href="https://github.com/dazzling-no-more/rahgozar/releases/tag/v{version}"
          target="_blank"
          rel="noopener noreferrer"
          class="text-secondary hover:text-accent font-mono text-sm transition-colors"
        >
          v{version}
        </a>
      {/if}
    </div>
  </header>

  <!-- Update banner — sits between the chrome header and the tab
       nav so it's always visible (regardless of which tab is active)
       but doesn't displace the language / theme controls in the header
       or push tab content off-screen. Renders nothing when no update
       is available. -->
  <UpdateBanner />

  <!-- Top tab nav. Accent underline on the active tab. -->
  <nav
    class="bg-surface border-border-subtle flex border-b px-6"
    aria-label="Main"
  >
    {#each TABS as tabDef (tabDef.id)}
      <button
        type="button"
        onclick={() => (active = tabDef.id)}
        class="relative px-4 py-3 text-sm font-medium transition-colors {active ===
        tabDef.id
          ? 'text-accent'
          : 'text-secondary hover:text-primary'}"
        aria-current={active === tabDef.id ? "page" : undefined}
      >
        {t(`tab.${tabDef.id}`)}
        {#if active === tabDef.id}
          <span
            class="bg-accent absolute inset-x-2 -bottom-px h-0.5 rounded-t"
            aria-hidden="true"
          ></span>
        {/if}
      </button>
    {/each}
  </nav>

  <!-- Tab content. Each component owns its own scroll + lifecycle.
       A keyed `#key active` block forces re-mount on tab switch so the
       in/out fade transitions cleanly. Without the key, Svelte would
       just patch the existing nodes and the transition wouldn't fire. -->
  <main class="bg-base flex-1 overflow-auto px-6 py-6">
    {#key active}
      <div
        in:fade={{ duration: 140, easing: cubicOut }}
        class="h-full"
      >
        {#if active === "status"}
          <div class="mx-auto max-w-2xl">
            <StatusTab />
          </div>
        {:else if active === "tunnel"}
          <div class="mx-auto max-w-3xl">
            <TunnelTab />
          </div>
        {:else if active === "logs"}
          <div class="mx-auto h-full max-w-5xl">
            <LogsTab />
          </div>
        {:else if active === "advanced"}
          <div class="mx-auto max-w-4xl">
            <AdvancedTab />
          </div>
        {:else if active === "about"}
          <AboutTab />
        {/if}
      </div>
    {/key}
  </main>

  <!-- Global toast stack. Rendered once at the app root so any
       feature module's `toast.success(...)` shows up regardless of
       which tab the user is on. -->
  <Toaster />
</div>
