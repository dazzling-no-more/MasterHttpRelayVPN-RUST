<script lang="ts">
  // Advanced tab: raw JSON editor for `config.json`.
  //
  // Purpose: cover the long tail of fields the Tunnel form doesn't
  // expose — fronting_groups, sni_hosts, custom tuning knobs, log
  // colour overrides, the dozen-ish fields most users never touch.
  // The backend validates by attempting a full typed parse before
  // writing, so a syntactically valid but field-typed-wrong JSON
  // doesn't clobber the disk file with something the proxy can't
  // load. Save errors surface via toast.
  //
  // Why a plain `<textarea>` instead of CodeMirror / Monaco:
  //   - Zero extra dep. The Tauri bundle stays compact.
  //   - The most common edit is "paste a few keys" or "tweak a
  //     value", not multi-thousand-line refactoring.
  //   - Browser-side `tab` insertion + line-numbering would be nice
  //     polish but isn't load-bearing.

  import { onMount } from "svelte";

  import { api } from "../api";
  import { t } from "../i18n.svelte";
  import { toast } from "../toast.svelte";

  let text = $state<string | null>(null);
  let pristine = $state<string | null>(null);
  let saving = $state(false);

  onMount(async () => {
    await load();
  });

  async function load() {
    try {
      const raw = await api.getRawConfig();
      text = raw;
      pristine = raw;
    } catch (e) {
      toast.error(String(e));
    }
  }

  async function onSave() {
    if (text == null) return;
    saving = true;
    try {
      await api.saveRawConfig(text);
      pristine = text;
      toast.success(t("advanced.saved"));
    } catch (e) {
      // Backend rejects with a `serde_json` / typed-parse error
      // message — pass it through verbatim so the user sees exactly
      // which line / field is wrong.
      toast.error(String(e));
    } finally {
      saving = false;
    }
  }

  const dirty = $derived(text != null && pristine != null && text !== pristine);
</script>

<div class="space-y-4">
  <header class="space-y-2">
    <h2 class="text-xl font-semibold tracking-tight">
      {t("advanced.heading")}
    </h2>
    <p class="text-secondary text-sm">{t("advanced.help")}</p>
  </header>

  {#if text == null}
    <p class="text-muted">{t("advanced.loading")}</p>
  {:else}
    <!-- `spellcheck="false"` + `dir="ltr"` so an FA-mode session
         doesn't try to spell-check JSON or right-align it. JSON is
         English-syntax regardless of UI language. -->
    <textarea
      bind:value={text}
      spellcheck="false"
      dir="ltr"
      class="bg-input border-border-subtle focus:border-accent h-[60vh] w-full resize-none rounded-md border p-4 font-mono text-xs leading-relaxed outline-none transition-colors"
    ></textarea>

    <div class="flex items-center justify-between gap-3">
      <div class="text-secondary text-xs">
        {#if dirty}
          <span class="text-warn">{t("tunnel.dirty")}</span>
        {:else}
          <span class="text-muted">{t("tunnel.in_sync")}</span>
        {/if}
      </div>
      <div class="flex items-center gap-2">
        <button
          type="button"
          onclick={load}
          disabled={saving}
          class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-4 py-2 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {t("advanced.reset")}
        </button>
        <button
          type="button"
          onclick={onSave}
          disabled={!dirty || saving}
          class="bg-accent hover:bg-accent-hover rounded-md px-5 py-2 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving ? t("tunnel.saving") : t("advanced.save")}
        </button>
      </div>
    </div>
  {/if}
</div>
