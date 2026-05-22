<script lang="ts">
  // MITM CA card for the Status tab.
  //
  // Three render paths driven by the same status snapshot:
  //   - exists=false:           transient state — the CA isn't on
  //                             disk yet. `onMount` calls
  //                             `mint_ca_if_missing` (which only
  //                             runs because StatusTab renders
  //                             this card in MITM-using modes
  //                             only), then refreshes status so
  //                             we land on the next path. The
  //                             card stays in a brief loading
  //                             state until the mint returns.
  //   - exists=true, trusted=false:  show fingerprint + "Install CA"
  //                                  button. Install opens the
  //                                  confirm dialog below.
  //   - exists=true, trusted=true:   show "Trusted" badge + "Remove CA"
  //                                  button. Remove deletes the on-
  //                                  disk PEM + un-trusts.
  //
  // `get_ca_status` itself is a pure read — minting only happens via
  // `mint_ca_if_missing` from `onMount` here and via `install_ca_cmd`
  // when the user clicks Install. No-MITM modes (local_bypass /
  // full) hide this card at the StatusTab level, so neither mint
  // path runs for them.
  //
  // The confirm dialog is intentionally inline (own state in this
  // component) rather than a global modal stack — it's the only
  // confirm we currently need, and bringing in a Modal component
  // for one use-site would be over-engineering.

  import { onDestroy, onMount } from "svelte";
  import type { UnlistenFn } from "@tauri-apps/api/event";

  import { api, onStatusChange, type CaStatusDto } from "../api";
  import { t, tn } from "../i18n.svelte";
  import { toast } from "../toast.svelte";

  let status = $state<CaStatusDto | null>(null);
  let pending = $state(false);
  let confirmOpen = $state(false);
  let unlistenStatus: UnlistenFn | null = null;

  onMount(async () => {
    await refresh();
    // Restore the "install before first Start" UX. CaCard is only
    // rendered in MITM-using modes (apps_script / direct), so
    // calling mint here is the right place to trigger CA
    // generation lazily — no-MITM modes never reach this code.
    // `get_ca_status` is a pure read now (it used to mint
    // eagerly), so without this call a fresh install would show
    // "Will be created on first Start" with no fingerprint and a
    // disabled Install button. Idempotent: a no-op when the CA
    // already exists.
    if (status && !status.exists) {
      try {
        status = await api.mintCaIfMissing();
      } catch (e) {
        // Mint failures (permission denied, disk full) leave the
        // card in the "not minted" state — the proxy will mint
        // on next Start as a fallback. Log + don't toast (the
        // Status tab keeps working).
        // eslint-disable-next-line no-console
        console.warn("mint_ca_if_missing failed:", e);
      }
    }
    // If the proxy starts later and mints the file itself
    // (e.g. mint here failed transiently), the status-change
    // event will pick that up.
    unlistenStatus = await onStatusChange(() => {
      void refresh();
    });
  });

  onDestroy(() => {
    if (unlistenStatus) unlistenStatus();
  });

  async function refresh() {
    try {
      status = await api.getCaStatus();
    } catch (e) {
      // Read should be infallible — log + swallow, don't toast (the
      // card just stays in the loading state, the rest of the
      // Status tab works fine).
      // eslint-disable-next-line no-console
      console.warn("get_ca_status failed:", e);
    }
  }

  async function onInstall() {
    confirmOpen = false;
    pending = true;
    try {
      const next = await api.installCa();
      status = next;
      toast.success(t("ca.toast.installed"));
    } catch (e) {
      toast.error(tn("ca.toast.install_failed", { error: String(e) }));
    } finally {
      pending = false;
    }
  }

  async function onRemove() {
    pending = true;
    try {
      const summary = await api.removeCa();
      toast.success(tn("ca.toast.removed", { summary }));
      await refresh();
    } catch (e) {
      toast.error(tn("ca.toast.remove_failed", { error: String(e) }));
    } finally {
      pending = false;
    }
  }

  // Chunk a long colon-hex fingerprint onto two lines so it doesn't
  // overflow a narrow card. SHA-256 is 32 bytes = 95 chars with
  // colons; we break after byte 16 (the colon between byte 15 and 16
  // is the visible separator).
  function splitFingerprint(fp: string): [string, string] {
    const parts = fp.split(":");
    const mid = Math.ceil(parts.length / 2);
    return [parts.slice(0, mid).join(":"), parts.slice(mid).join(":")];
  }
</script>

<section class="bg-surface border-border-subtle rounded-lg border p-6">
  <header class="mb-3 flex items-center justify-between">
    <h2 class="text-secondary text-xs font-semibold tracking-wider uppercase">
      {t("ca.heading")}
    </h2>
    {#if status}
      {#if !status.exists}
        <span class="text-muted text-xs">{t("ca.state.not_yet_minted")}</span>
      {:else if status.trusted}
        <span class="bg-success/15 text-success rounded-full px-2.5 py-0.5 text-xs font-semibold">
          ● {t("ca.state.trusted")}
        </span>
      {:else}
        <span class="bg-warn/15 text-warn rounded-full px-2.5 py-0.5 text-xs font-semibold">
          ● {t("ca.state.not_trusted")}
        </span>
      {/if}
    {/if}
  </header>

  <p class="text-secondary text-sm">{t("ca.help")}</p>

  {#if status?.exists && status.fingerprint}
    <dl class="mt-4 space-y-1.5 text-xs">
      {#if status.subject_cn}
        <div class="flex gap-2">
          <dt class="text-muted w-20">{t("ca.subject_label")}</dt>
          <dd class="font-mono">{status.subject_cn}</dd>
        </div>
      {/if}
      <div class="flex gap-2">
        <dt class="text-muted w-20">{t("ca.fingerprint_label")}</dt>
        <dd class="font-mono break-all">
          {#each splitFingerprint(status.fingerprint) as line (line)}
            <div>{line}</div>
          {/each}
        </dd>
      </div>
    </dl>
  {/if}

  {#if status?.exists}
    <div class="mt-4 flex justify-end gap-2">
      {#if status.trusted}
        <button
          type="button"
          disabled={pending}
          onclick={onRemove}
          class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-4 py-1.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {pending ? t("ca.removing") : t("ca.remove")}
        </button>
      {:else}
        <button
          type="button"
          disabled={pending}
          onclick={() => (confirmOpen = true)}
          class="bg-accent hover:bg-accent-hover rounded-md px-5 py-1.5 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {pending ? t("ca.installing") : t("ca.install")}
        </button>
      {/if}
    </div>
  {/if}
</section>

<!-- Confirm-install modal. Rendered as a portal-style overlay
     ("portal-style" = fixed positioning + high z-index, no actual
     Svelte portal because that requires a dep we don't have).
     Closed by the Cancel button OR by clicking the dimmer backdrop. -->
{#if confirmOpen && status?.exists && status.fingerprint}
  <div
    class="fixed inset-0 z-50 grid place-items-center"
    role="dialog"
    aria-modal="true"
    aria-labelledby="ca-confirm-title"
  >
    <button
      type="button"
      aria-label={t("ca.confirm_cancel")}
      onclick={() => (confirmOpen = false)}
      class="absolute inset-0 bg-black/60 backdrop-blur-sm"
    ></button>
    <div
      class="bg-surface border-border-subtle relative max-w-lg rounded-lg border p-6 shadow-xl"
    >
      <h3 id="ca-confirm-title" class="text-lg font-semibold tracking-tight">
        {t("ca.install_confirm_title")}
      </h3>
      <p class="text-secondary mt-2 text-sm">
        {t("ca.install_confirm_body")}
      </p>
      <dl class="bg-input border-border-subtle mt-4 space-y-1.5 rounded-md border p-3 text-xs">
        {#if status.subject_cn}
          <div class="flex gap-2">
            <dt class="text-muted w-20">{t("ca.subject_label")}</dt>
            <dd class="font-mono">{status.subject_cn}</dd>
          </div>
        {/if}
        <div class="flex gap-2">
          <dt class="text-muted w-20">{t("ca.fingerprint_label")}</dt>
          <dd class="font-mono break-all">
            {#each splitFingerprint(status.fingerprint) as line (line)}
              <div>{line}</div>
            {/each}
          </dd>
        </div>
      </dl>
      <div class="mt-5 flex justify-end gap-2">
        <button
          type="button"
          onclick={() => (confirmOpen = false)}
          class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-4 py-2 text-sm transition-colors"
        >
          {t("ca.confirm_cancel")}
        </button>
        <button
          type="button"
          onclick={onInstall}
          class="bg-accent hover:bg-accent-hover rounded-md px-5 py-2 text-sm font-semibold text-black transition-colors"
        >
          {t("ca.confirm_install")}
        </button>
      </div>
    </div>
  </div>
{/if}
