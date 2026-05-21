<script lang="ts">
  // Tunnel tab: the config editor.
  //
  // Loads the on-disk config on mount, binds form fields to a local
  // mutable copy, and POSTs the whole shape back via `save_config`
  // on Save. The backend overlays our fields onto the on-disk JSON so
  // any keys this UI doesn't expose (fronting_groups, sni_hosts,
  // custom params, tuning knobs) survive untouched — see the round-
  // trip comment in `commands.rs::save_config`.
  //
  // Deployment IDs use the Android-style row editor: one input + ×
  // delete button per ID, plus a bulk-paste textarea + "+ Add" button
  // that splits on whitespace / newline / comma. Matches what the
  // Android UI does in `HomeScreen.kt::DeploymentIdsField` so a user
  // moving between platforms doesn't have to relearn it.

  import { onMount } from "svelte";
  import { api, type ConfigDto, type SniHostDto } from "../api";
  import { t, tn } from "../i18n.svelte";
  import { toast } from "../toast.svelte";
  import FrontingGroupsSection from "./FrontingGroupsSection.svelte";
  import SniPoolModal from "./SniPoolModal.svelte";

  // ── State ────────────────────────────────────────────────────────
  let config = $state<ConfigDto | null>(null);
  // Pristine snapshot so we can compute "is the form dirty?" without
  // shipping every field through a `dirty` flag.
  let pristine = $state<ConfigDto | null>(null);

  let addBuffer = $state("");
  let saving = $state(false);

  // SNI pool modal visibility + summary chip ("SNI pool (5/8)").
  // The summary counts come from a lazy load on mount; the modal
  // refreshes its own data on each open so the count getting stale
  // (e.g. user edited the pool, never re-saved the Tunnel form) is
  // only ever briefly wrong.
  let sniModalOpen = $state(false);
  let sniSummary = $state<{ active: number; total: number }>({
    active: 0,
    total: 0,
  });
  async function refreshSniSummary() {
    try {
      const pool: SniHostDto[] = await api.getSniPool();
      sniSummary = {
        active: pool.filter((p) => p.enabled).length,
        total: pool.length,
      };
    } catch {
      /* swallow — chip falls back to "0/0" until refresh succeeds */
    }
  }

  onMount(async () => {
    try {
      const c = await api.getConfig();
      config = c;
      pristine = structuredClone(c);
    } catch (e) {
      toast.error(`Couldn't load config: ${e}`);
    }
    void refreshSniSummary();
  });

  // ── Mode ─────────────────────────────────────────────────────────
  // Translation lookup happens at render time (via `t()` below) rather
  // than at module-eval time so the label / help text re-render when
  // the user toggles language. The wire `value` is always English —
  // it's the on-disk Config field.
  const MODES = ["apps_script", "full", "direct"] as const;

  const isDirect = $derived(
    config?.mode === "direct" || config?.mode === "google_only",
  );

  const dirty = $derived(
    config != null &&
      pristine != null &&
      JSON.stringify(config) !== JSON.stringify(pristine),
  );

  // ── Deployment IDs row editor ────────────────────────────────────
  function removeIdAt(i: number) {
    if (!config) return;
    config.script_ids = config.script_ids.filter((_, idx) => idx !== i);
  }

  function addFromBuffer() {
    if (!config) return;
    const parsed = addBuffer
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (parsed.length === 0) return;
    config.script_ids = [...config.script_ids, ...parsed];
    addBuffer = "";
  }

  // ── Save ─────────────────────────────────────────────────────────
  async function onSave() {
    if (!config) return;
    saving = true;
    try {
      const saved = await api.saveConfig(config);
      config = saved;
      pristine = structuredClone(saved);
      toast.success(t("tunnel.saved"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      saving = false;
    }
  }

  async function onRevert() {
    if (!pristine) return;
    config = structuredClone(pristine);
  }
</script>

{#if !config}
  <!-- Load errors land in the global toast stack (see `onMount`) so
       we don't need an inline error slot here; the empty loading
       state is the only thing left. -->
  <p class="text-muted">{t("tunnel.loading_config")}</p>
{:else}
  <div class="space-y-6">
    <!-- ── Mode ─────────────────────────────────────────────────── -->
    <section class="bg-surface border-border-subtle rounded-lg border p-5">
      <h2 class="text-secondary mb-3 text-xs font-semibold tracking-wider uppercase">
        {t("tunnel.section.mode")}
      </h2>
      <div class="space-y-2">
        {#each MODES as value (value)}
          <label
            class="border-border-subtle hover:border-border-strong flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors {config.mode ===
            value
              ? 'border-accent/60 bg-accent/5'
              : ''}"
          >
            <input
              type="radio"
              name="mode"
              {value}
              bind:group={config.mode}
              class="accent-accent mt-0.5 h-4 w-4"
            />
            <div class="flex-1">
              <div class="font-semibold">{t(`tunnel.mode.${value}.label`)}</div>
              <div class="text-secondary mt-0.5 text-xs">
                {t(`tunnel.mode.${value}.help`)}
              </div>
            </div>
          </label>
        {/each}
      </div>
    </section>

    <!-- ── Fronting groups ────────────────────────────────────────
         Owns its own data lifecycle (loads / saves independent of
         this form's Save button) — see `FrontingGroupsSection.svelte`
         for the reasoning. -->
    <FrontingGroupsSection />

    <!-- ── Apps Script relay ─────────────────────────────────────── -->
    <section
      class="bg-surface border-border-subtle rounded-lg border p-5 {isDirect
        ? 'opacity-50'
        : ''}"
    >
      <h2 class="text-secondary mb-3 text-xs font-semibold tracking-wider uppercase">
        {t("tunnel.section.apps_script")}
      </h2>

      <!-- Deployment IDs row editor. -->
      <div class="space-y-2">
        <div class="text-primary text-sm font-semibold">
          {t("tunnel.deployment_ids.label")}
        </div>
        <p class="text-muted text-xs">{t("tunnel.deployment_ids.help")}</p>

        <div class="space-y-1.5">
          {#each config.script_ids as _id, i (i)}
            <div class="flex items-center gap-2">
              <span class="text-muted w-7 text-end font-mono text-xs">
                {String(i + 1).padStart(2, "0")}.
              </span>
              <input
                type="text"
                bind:value={config.script_ids[i]}
                disabled={isDirect}
                class="bg-input border-border-subtle focus:border-accent flex-1 rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors disabled:cursor-not-allowed"
              />
              <button
                type="button"
                onclick={() => removeIdAt(i)}
                disabled={isDirect}
                aria-label={tn("tunnel.deployment_ids.remove_aria", {
                  n: i + 1,
                })}
                class="text-error/80 hover:text-error hover:bg-error/10 grid h-7 w-7 place-items-center rounded-md text-lg font-bold transition-colors disabled:cursor-not-allowed disabled:opacity-50"
              >
                ×
              </button>
            </div>
          {/each}
        </div>

        <!-- Bulk-paste / add row. -->
        <div class="mt-2 flex items-start gap-2">
          <textarea
            bind:value={addBuffer}
            disabled={isDirect}
            rows="2"
            placeholder={t("tunnel.deployment_ids.placeholder")}
            class="bg-input border-border-subtle focus:border-accent placeholder:text-muted flex-1 rounded-md border px-3 py-2 font-mono text-xs outline-none transition-colors disabled:cursor-not-allowed"
          ></textarea>
          <button
            type="button"
            onclick={addFromBuffer}
            disabled={isDirect || addBuffer.trim().length === 0}
            class="bg-accent hover:bg-accent-hover rounded-md px-4 py-2 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
          >
            {t("tunnel.add")}
          </button>
        </div>

        <!-- Count summary. -->
        {#if config.script_ids.length === 0}
          <p class="text-muted text-xs">{t("tunnel.deployment_ids.tip_more")}</p>
        {:else if config.script_ids.length === 1}
          <p class="text-muted text-xs">
            {t("tunnel.deployment_ids.one_configured")}
          </p>
        {:else}
          <p class="text-success text-xs">
            {tn("tunnel.deployment_ids.many_configured", {
              n: config.script_ids.length,
            })}
          </p>
        {/if}
      </div>

      <!-- Auth key. -->
      <div class="mt-5">
        <label class="text-primary text-sm font-semibold" for="auth-key">
          {t("tunnel.auth_key.label")}
        </label>
        <p class="text-muted text-xs">{t("tunnel.auth_key.help")}</p>
        <input
          id="auth-key"
          type="password"
          autocomplete="off"
          bind:value={config.auth_key}
          disabled={isDirect}
          class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors disabled:cursor-not-allowed"
        />
      </div>
    </section>

    <!-- ── Network ───────────────────────────────────────────────── -->
    <section class="bg-surface border-border-subtle rounded-lg border p-5">
      <h2 class="text-secondary mb-3 text-xs font-semibold tracking-wider uppercase">
        {t("tunnel.section.network")}
      </h2>

      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="text-primary text-sm font-semibold" for="listen-host">
            {t("tunnel.network.listen_host")}
          </label>
          <input
            id="listen-host"
            type="text"
            bind:value={config.listen_host}
            class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
        </div>
        <div>
          <label class="text-primary text-sm font-semibold" for="listen-port">
            {t("tunnel.network.http_port")}
          </label>
          <input
            id="listen-port"
            type="number"
            min="1"
            max="65535"
            bind:value={config.listen_port}
            class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
        </div>
        <div>
          <label class="text-primary text-sm font-semibold" for="socks5-port">
            {t("tunnel.network.socks5_port")}
            <span class="text-muted text-xs font-normal">
              {t("tunnel.network.socks5_optional")}
            </span>
          </label>
          <input
            id="socks5-port"
            type="number"
            min="0"
            max="65535"
            value={config.socks5_port ?? ""}
            oninput={(e) => {
              if (!config) return;
              const v = (e.currentTarget as HTMLInputElement).value;
              config.socks5_port = v === "" ? null : Number(v);
            }}
            class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
        </div>
        <div>
          <label class="text-primary text-sm font-semibold" for="log-level">
            {t("tunnel.network.log_level")}
          </label>
          <input
            id="log-level"
            type="text"
            bind:value={config.log_level}
            placeholder="info,hyper=warn"
            class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
        </div>
        <div class="col-span-2">
          <label class="text-primary text-sm font-semibold" for="front-domain">
            {t("tunnel.network.front_domain")}
          </label>
          <input
            id="front-domain"
            type="text"
            bind:value={config.front_domain}
            class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
        </div>
        <div class="col-span-2">
          <label class="text-primary text-sm font-semibold" for="google-ip">
            {t("tunnel.network.google_ip")}
          </label>
          <input
            id="google-ip"
            type="text"
            bind:value={config.google_ip}
            class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
          <!-- SNI pool affordance. The active/total chip surfaces
               "how many of the rotation hosts are currently
               enabled" so a misconfiguration (everything disabled,
               proxy can't handshake) is visible at a glance even
               before opening the modal. -->
          <button
            type="button"
            onclick={() => (sniModalOpen = true)}
            class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong mt-2 rounded-md border px-3 py-1 text-xs transition-colors"
          >
            {tn("tunnel.network.sni_pool_btn", {
              active: sniSummary.active,
              total: sniSummary.total,
            })}
          </button>
        </div>
      </div>
    </section>

    <!-- SNI pool modal. Visibility owned here so the chip above
         drives it; modal calls back via `onclose` to flip it off. -->
    <SniPoolModal
      bind:open={sniModalOpen}
      onclose={() => {
        sniModalOpen = false;
        void refreshSniSummary();
      }}
    />

    <!-- ── Save / Revert footer ────────────────────────────────────
         Save / error feedback now goes through the global toast stack
         (see `lib/toast.svelte.ts`); the inline status line on the
         left only reports the *persistent* form state ("dirty / in
         sync"), so users don't have a stale "Saved" line sitting on
         screen after they've already started making new edits. -->
    <div class="flex items-center justify-between gap-3">
      <div class="text-secondary text-xs">
        {#if dirty}
          <span class="text-warn">{t("tunnel.dirty")}</span>
        {:else}
          <span class="text-muted">{t("tunnel.in_sync")}</span>
        {/if}
      </div>

      <div class="flex items-center gap-2">
        {#if dirty}
          <button
            type="button"
            onclick={onRevert}
            disabled={saving}
            class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-4 py-2 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
          >
            {t("tunnel.revert")}
          </button>
        {/if}
        <button
          type="button"
          onclick={onSave}
          disabled={!dirty || saving}
          class="bg-accent hover:bg-accent-hover rounded-md px-5 py-2 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving ? t("tunnel.saving") : t("tunnel.save")}
        </button>
      </div>
    </div>
  </div>
{/if}
