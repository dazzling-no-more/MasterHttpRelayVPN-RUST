<script lang="ts">
  // Fronting groups editor — sits on the Tunnel tab between Mode and
  // Apps Script relay.
  //
  // Data lifecycle: independent of the rest of the Tunnel form. Loads
  // on mount via `get_fronting_groups`, lets the user mutate a local
  // copy, posts back via `save_fronting_groups` (which writes only
  // `config.json::fronting_groups`, preserving every other key). The
  // Tunnel form's main Save button doesn't touch this list — they're
  // independent saves. Avoids one big Save that has to know about
  // every sub-array.
  //
  // Discover button: takes a hostname, calls
  // `discover_front_cmd` (resolves DNS → TLS-probes each IP → picks
  // best), then appends a new group with that IP + SNI=hostname and
  // an empty domain list ready for the user to fill in.

  import { onMount } from "svelte";

  import { api, type FrontingGroup } from "../api";
  import { t, tn } from "../i18n.svelte";
  import { toast } from "../toast.svelte";

  let groups = $state<FrontingGroup[]>([]);
  let pristine = $state<FrontingGroup[]>([]);
  let loading = $state(true);
  let saving = $state(false);

  // Discover form
  let discoverHostname = $state("");
  let discovering = $state(false);

  onMount(async () => {
    try {
      const g = await api.getFrontingGroups();
      groups = g;
      pristine = structuredClone(g);
    } catch (e) {
      toast.error(String(e));
    } finally {
      loading = false;
    }
  });

  const dirty = $derived(
    JSON.stringify(groups) !== JSON.stringify(pristine),
  );

  function addEmptyGroup() {
    groups = [
      ...groups,
      {
        name: "",
        ip: "",
        sni: "",
        domains: [""],
      },
    ];
  }

  function removeGroup(i: number) {
    groups = groups.filter((_, idx) => idx !== i);
  }

  function addDomain(i: number) {
    groups[i].domains = [...groups[i].domains, ""];
  }

  function removeDomain(groupIdx: number, domainIdx: number) {
    groups[groupIdx].domains = groups[groupIdx].domains.filter(
      (_, idx) => idx !== domainIdx,
    );
  }

  async function onDiscover() {
    const hostname = discoverHostname.trim();
    if (!hostname) return;
    discovering = true;
    try {
      const res = await api.discoverFront(hostname);
      if (res.best_ip == null) {
        toast.error(
          tn("tunnel.fronting.discover_none_reachable", {
            hostname: res.hostname,
          }),
        );
      } else {
        // Append a new group prefilled with the discovered IP + SNI.
        // Name defaults to the hostname for legibility; user can
        // rename. Empty domain list invites them to fill in the
        // actual member domains they want fronted.
        groups = [
          ...groups,
          {
            name: res.hostname,
            ip: res.best_ip,
            sni: res.hostname,
            domains: [""],
          },
        ];
        toast.success(
          tn("tunnel.fronting.discover_found", {
            ip: res.best_ip,
            n: res.reachable_count,
          }),
        );
        discoverHostname = "";
      }
    } catch (e) {
      toast.error(
        tn("tunnel.fronting.discover_failed", { error: String(e) }),
      );
    } finally {
      discovering = false;
    }
  }

  async function onSave() {
    saving = true;
    try {
      const saved = await api.saveFrontingGroups(groups);
      groups = saved;
      pristine = structuredClone(saved);
      toast.success(t("tunnel.fronting.saved"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      saving = false;
    }
  }
</script>

<section class="bg-surface border-border-subtle rounded-lg border p-5">
  <h2 class="text-secondary mb-3 text-xs font-semibold tracking-wider uppercase">
    {t("tunnel.section.fronting_groups")}
  </h2>
  <p class="text-secondary text-sm">{t("tunnel.fronting.help")}</p>

  <!-- Discover row. Single input + button; resolved IP + SNI auto-fill
       a fresh group below. -->
  <div class="mt-4 space-y-2">
    <div class="text-primary text-sm font-semibold">
      {t("tunnel.fronting.discover_label")}
    </div>
    <div class="flex items-center gap-2">
      <input
        type="text"
        bind:value={discoverHostname}
        placeholder={t("tunnel.fronting.discover_placeholder")}
        class="bg-input border-border-subtle focus:border-accent placeholder:text-muted flex-1 rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
      />
      <button
        type="button"
        onclick={onDiscover}
        disabled={discovering || discoverHostname.trim().length === 0}
        class="bg-accent hover:bg-accent-hover rounded-md px-4 py-1.5 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
      >
        {discovering
          ? t("tunnel.fronting.discovering")
          : t("tunnel.fronting.discover_btn")}
      </button>
    </div>
  </div>

  <!-- Group cards. One card per FrontingGroup; per-card delete on the
       right, per-domain × inside the domains list. -->
  <div class="mt-5 space-y-3">
    {#if loading}
      <p class="text-muted text-sm">…</p>
    {:else if groups.length === 0}
      <p class="text-muted text-sm italic">
        {t("tunnel.fronting.no_groups")}
      </p>
    {:else}
      {#each groups as g, gi (gi)}
        <div class="bg-input border-border-subtle rounded-md border p-4">
          {#if g.force_ip}
            <!-- Camouflage (force_ip) group: no edge IP to set — the
                 destination IP is DoH-resolved at runtime and the SNI is
                 a decoy. Surface that as a read-only badge + hint so
                 users don't try to fill in an IP. -->
            <div class="mb-3 flex items-center gap-2">
              <span
                class="bg-accent/15 text-accent rounded px-2 py-0.5 text-[10px] font-semibold tracking-wider uppercase"
              >
                {t("tunnel.fronting.camouflage_badge")}
              </span>
              <span class="text-muted text-xs">{t("tunnel.fronting.camouflage_hint")}</span>
            </div>
          {/if}
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-muted text-xs" for={`fg-name-${gi}`}>
                {t("tunnel.fronting.group_name")}
              </label>
              <input
                id={`fg-name-${gi}`}
                type="text"
                bind:value={groups[gi].name}
                class="bg-base border-border-subtle focus:border-accent mt-1 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
              />
            </div>
            <div>
              <label class="text-muted text-xs" for={`fg-ip-${gi}`}>
                {t("tunnel.fronting.group_ip")}
              </label>
              <input
                id={`fg-ip-${gi}`}
                type="text"
                bind:value={groups[gi].ip}
                readonly={g.force_ip}
                placeholder={g.force_ip ? t("tunnel.fronting.group_ip_auto") : ""}
                class="bg-base border-border-subtle focus:border-accent placeholder:text-muted mt-1 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors read-only:opacity-50"
              />
            </div>
            <div class="col-span-2">
              <label class="text-muted text-xs" for={`fg-sni-${gi}`}>
                {t("tunnel.fronting.group_sni")}
              </label>
              <input
                id={`fg-sni-${gi}`}
                type="text"
                bind:value={groups[gi].sni}
                class="bg-base border-border-subtle focus:border-accent mt-1 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
              />
            </div>
          </div>

          <div class="mt-3">
            <div class="text-muted text-xs">
              {t("tunnel.fronting.group_domains")}
            </div>
            <div class="mt-1 space-y-1.5">
              {#each groups[gi].domains as _d, di (di)}
                <div class="flex items-center gap-2">
                  <input
                    type="text"
                    bind:value={groups[gi].domains[di]}
                    placeholder={t("tunnel.fronting.domain_placeholder")}
                    class="bg-base border-border-subtle focus:border-accent flex-1 rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
                  />
                  <button
                    type="button"
                    onclick={() => removeDomain(gi, di)}
                    aria-label={tn("tunnel.fronting.remove_domain_aria", {
                      n: di + 1,
                      name: g.name || `#${gi + 1}`,
                    })}
                    class="text-error/80 hover:text-error hover:bg-error/10 grid h-7 w-7 place-items-center rounded-md text-lg font-bold transition-colors"
                  >
                    ×
                  </button>
                </div>
              {/each}
              <button
                type="button"
                onclick={() => addDomain(gi)}
                class="text-accent hover:text-accent-hover text-xs font-semibold transition-colors"
              >
                {t("tunnel.fronting.add_domain")}
              </button>
            </div>
          </div>

          <div class="mt-3 flex justify-end">
            <button
              type="button"
              onclick={() => removeGroup(gi)}
              aria-label={tn("tunnel.fronting.remove_group_aria", {
                name: g.name || `#${gi + 1}`,
              })}
              class="text-error/80 hover:text-error hover:bg-error/10 rounded-md px-3 py-1 text-xs transition-colors"
            >
              ×
            </button>
          </div>
        </div>
      {/each}
    {/if}

    <button
      type="button"
      onclick={addEmptyGroup}
      class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong w-full rounded-md border border-dashed px-3 py-2 text-sm transition-colors"
    >
      {t("tunnel.fronting.add_group")}
    </button>
  </div>

  {#if dirty}
    <div class="mt-4 flex justify-end">
      <button
        type="button"
        onclick={onSave}
        disabled={saving}
        class="bg-accent hover:bg-accent-hover rounded-md px-5 py-2 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
      >
        {saving
          ? t("tunnel.fronting.saving")
          : t("tunnel.fronting.save")}
      </button>
    </div>
  {/if}
</section>
