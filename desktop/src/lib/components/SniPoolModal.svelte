<script lang="ts">
  // SNI pool editor modal — opened from a "SNI pool (n/m)" button in
  // the Tunnel tab's Network section.
  //
  // Each row is one host + a checkbox (in-rotation yes/no) + a Probe
  // button (per-host TLS reachability test against the configured
  // `google_ip` with `SNI=host`). Probe results are local state
  // (idle / ok / fail) that doesn't persist — re-opening the modal
  // resets every row to idle, intentionally: a stale "reachable"
  // mark from yesterday is misleading.

  import { onMount } from "svelte";

  import { api, type SniHostDto } from "../api";
  import { t, tn } from "../i18n.svelte";
  import { toast } from "../toast.svelte";

  // Parent owns visibility via prop binding.
  type Props = { open: boolean; onclose: () => void };
  let { open = $bindable(), onclose }: Props = $props();

  type ProbeStatus = "idle" | "probing" | "ok" | "fail";

  // Display rows. `enabled` mirrors the backend's notion of "in
  // rotation"; `probe` is per-session UI state.
  type Row = SniHostDto & {
    probe: ProbeStatus;
  };

  let rows = $state<Row[]>([]);
  let pristine = $state<Row[]>([]);
  let loading = $state(false);
  let saving = $state(false);
  let addBuffer = $state("");

  // Reload pool every time the modal opens — picks up changes that
  // happened while it was closed (e.g. via the Advanced raw-JSON
  // editor).
  $effect(() => {
    if (open) {
      loadPool();
    }
  });

  async function loadPool() {
    loading = true;
    try {
      const pool = await api.getSniPool();
      const fresh: Row[] = pool.map((e) => ({ ...e, probe: "idle" as ProbeStatus }));
      rows = fresh;
      // Clone the plain array, not the reactive `rows` proxy.
      // `structuredClone` on a Svelte 5 $state proxy throws DataCloneError.
      pristine = fresh.map((r) => ({ ...r }));
    } catch (e) {
      toast.error(String(e));
    } finally {
      loading = false;
    }
  }

  const dirty = $derived(
    JSON.stringify(rows.map((r) => ({ host: r.host, enabled: r.enabled }))) !==
      JSON.stringify(
        pristine.map((r) => ({ host: r.host, enabled: r.enabled })),
      ),
  );

  function toggleRow(i: number) {
    rows[i].enabled = !rows[i].enabled;
  }

  function removeRow(i: number) {
    rows = rows.filter((_, idx) => idx !== i);
  }

  function addFromBuffer() {
    const host = addBuffer.trim();
    if (!host) return;
    if (rows.some((r) => r.host.toLowerCase() === host.toLowerCase())) {
      // No duplicates — focus the existing row's intent (toggling it
      // back on) rather than appending a second copy.
      toast.info(`${host} already in the list`);
      addBuffer = "";
      return;
    }
    rows = [...rows, { host, enabled: true, probe: "idle" }];
    addBuffer = "";
  }

  async function probeRow(i: number) {
    rows[i].probe = "probing";
    try {
      const res = await api.probeSni(rows[i].host);
      rows[i].probe = res.reachable ? "ok" : "fail";
    } catch (e) {
      rows[i].probe = "fail";
      toast.error(String(e));
    }
  }

  async function onSave() {
    saving = true;
    try {
      // Strip the `probe` UI state before sending — backend only
      // wants `{host, enabled}`.
      await api.saveSniPool(
        rows.map((r) => ({ host: r.host, enabled: r.enabled })),
      );
      // Snapshot the rows by shallow-copying each entry — `structuredClone`
      // on the reactive `rows` proxy throws DataCloneError (Svelte 5).
      pristine = rows.map((r) => ({ ...r }));
      toast.success(t("sni.saved"));
      onclose();
    } catch (e) {
      toast.error(String(e));
    } finally {
      saving = false;
    }
  }
</script>

{#if open}
  <div
    class="fixed inset-0 z-50 grid place-items-center"
    role="dialog"
    aria-modal="true"
    aria-labelledby="sni-modal-title"
  >
    <button
      type="button"
      aria-label={t("sni.close")}
      onclick={onclose}
      class="absolute inset-0 bg-black/60 backdrop-blur-sm"
    ></button>
    <div
      class="bg-surface border-border-subtle relative flex max-h-[80vh] w-160 max-w-[92vw] flex-col rounded-lg border shadow-xl"
    >
      <header class="border-border-subtle border-b p-5">
        <h3 id="sni-modal-title" class="text-lg font-semibold tracking-tight">
          {t("sni.title")}
        </h3>
        <p class="text-secondary mt-2 text-sm">{t("sni.help")}</p>
      </header>

      <div class="min-h-0 flex-1 overflow-y-auto p-5">
        {#if loading}
          <p class="text-muted text-sm">…</p>
        {:else}
          <ul class="space-y-1.5">
            {#each rows as _r, i (rows[i].host + i)}
              <li
                class="bg-input border-border-subtle flex items-center gap-3 rounded-md border px-3 py-2"
              >
                <input
                  type="checkbox"
                  checked={rows[i].enabled}
                  onchange={() => toggleRow(i)}
                  class="accent-accent h-4 w-4"
                  aria-label={t("sni.col_enabled")}
                />
                <span class="flex-1 font-mono text-xs">{rows[i].host}</span>

                <!-- Per-host probe status pill. Idle/ok/fail get
                     distinct colours so a quick scan tells you which
                     row needs attention. -->
                <span class="text-xs">
                  {#if rows[i].probe === "ok"}
                    <span class="text-success">✓ {t("sni.probe_ok")}</span>
                  {:else if rows[i].probe === "fail"}
                    <span class="text-error">✕ {t("sni.probe_fail")}</span>
                  {:else if rows[i].probe === "probing"}
                    <span class="text-accent">{t("sni.probing")}</span>
                  {:else}
                    <span class="text-muted">—</span>
                  {/if}
                </span>

                <button
                  type="button"
                  onclick={() => probeRow(i)}
                  disabled={rows[i].probe === "probing"}
                  class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-2.5 py-1 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {t("sni.probe")}
                </button>

                <button
                  type="button"
                  onclick={() => removeRow(i)}
                  aria-label={tn("sni.remove_aria", { host: rows[i].host })}
                  class="text-error/70 hover:text-error hover:bg-error/10 grid h-7 w-7 place-items-center rounded-md text-lg font-bold transition-colors"
                >
                  ×
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>

      <footer class="border-border-subtle border-t p-5">
        <div class="flex items-center gap-2">
          <input
            type="text"
            bind:value={addBuffer}
            placeholder={t("sni.add_placeholder")}
            onkeydown={(e) => {
              if (e.key === "Enter") addFromBuffer();
            }}
            class="bg-input border-border-subtle focus:border-accent placeholder:text-muted flex-1 rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
          <button
            type="button"
            onclick={addFromBuffer}
            disabled={addBuffer.trim().length === 0}
            class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1.5 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50"
          >
            {t("sni.add")}
          </button>
        </div>
        <div class="mt-3 flex items-center justify-end gap-2">
          <button
            type="button"
            onclick={onclose}
            class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-4 py-2 text-sm transition-colors"
          >
            {t("sni.close")}
          </button>
          <button
            type="button"
            onclick={onSave}
            disabled={!dirty || saving}
            class="bg-accent hover:bg-accent-hover rounded-md px-5 py-2 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving ? t("sni.saving") : t("sni.save")}
          </button>
        </div>
      </footer>
    </div>
  </div>
{/if}
