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
  import { openUrl } from "@tauri-apps/plugin-opener";
  import {
    api,
    type ConfigDto,
    type DriveOauthCompleteDto,
    type SniHostDto,
  } from "../api";
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
  const MODES = [
    "apps_script",
    "full",
    "direct",
    "local_bypass",
    "drive",
  ] as const;

  // direct / google_only (legacy alias) / local_bypass / drive all
  // skip the Apps Script relay, so the deployment-IDs + auth-key
  // form is hidden under any of them — switching back to
  // apps_script or full restores it. (apps_script + full are the
  // only modes that consult `script_ids` / `auth_key`, mirroring
  // the Rust-side `Mode::uses_apps_script_relay`.)
  const noRelay = $derived(
    config?.mode === "direct" ||
      config?.mode === "google_only" ||
      config?.mode === "local_bypass" ||
      config?.mode === "drive",
  );

  // LocalBypass goes a step further than "noRelay": it ignores
  // front_domain, google_ip, the SNI pool, and fronting_groups.
  // Drive also skips the Apps Script relay knobs, but it still uses
  // google_ip for Drive/OAuth endpoint resolution, so the network
  // editor keeps that field visible in Drive mode.
  const isLocalBypass = $derived(config?.mode === "local_bypass");
  const isDrive = $derived(config?.mode === "drive");

  const dirty = $derived(
    config != null &&
      pristine != null &&
      JSON.stringify(config) !== JSON.stringify(pristine),
  );

  // ── Deployment IDs row editor ────────────────────────────────────
  // Rows are objects (id + enabled). Newly-added rows default to
  // enabled; the checkbox in the row lets the user park an ID without
  // deleting it (saved as `enabled: false` on disk so they can flip it
  // back on later without re-typing). Same pattern the SNI pool modal
  // uses for disabling probe targets.
  function removeIdAt(i: number) {
    if (!config) return;
    config.script_ids = config.script_ids.filter((_, idx) => idx !== i);
  }

  function addFromBuffer() {
    if (!config) return;
    const parsed = addBuffer
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .map((id) => ({ id, enabled: true }));
    if (parsed.length === 0) return;
    config.script_ids = [...config.script_ids, ...parsed];
    addBuffer = "";
  }

  // Match `save_config`'s validation: blank IDs are dropped on save,
  // so the inline summary must count the same population — otherwise
  // a row that's checked but still empty inflates the chip into
  // "1 of 1 enabled" while save would error with "all disabled".
  // `nonBlankTotal` is the population we report; `enabledIdCount` is
  // the enabled subset within it.
  const nonBlankTotal = $derived(
    config?.script_ids.filter((e) => e.id.trim() !== "").length ?? 0,
  );
  const enabledIdCount = $derived(
    config?.script_ids.filter((e) => e.enabled && e.id.trim() !== "").length ?? 0,
  );

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
    // `pristine` is reactive ($state); `structuredClone` on a Svelte 5
    // proxy throws DataCloneError. Round-trip through JSON to deep-copy
    // the plain shape.
    config = JSON.parse(JSON.stringify(pristine));
  }

  // ── Drive-mode setup ─────────────────────────────────────────────
  //
  // OAuth flow: clicking "Sign in" calls `driveOauthStart` which
  // returns a state token + auth URL. We open the URL in the system
  // browser (via tauri-plugin-opener), then long-poll
  // `driveOauthComplete` — the Rust side blocks up to 120s waiting
  // on the loopback listener task. Success persists the refresh
  // token into config.json server-side; we re-read the config so
  // `drive_has_refresh_token` flips to true in the form.

  let signingIn = $state(false);
  // The auth URL is surfaced in a dialog with Copy + Open buttons
  // so the user can paste it into whichever browser they're signed
  // into Google with — auto-opening the system-default browser
  // forces a sign-in in the wrong account if their default isn't
  // their Google-signed-in one. `null` means no flow is in
  // progress.
  let pendingAuthUrl = $state<string | null>(null);
  // `drive_oauth_start` now takes the OAuth client_id/secret +
  // google_ip directly from the form (no Save first). So the only
  // gate is "the three required fields have content".
  let signInReady = $derived(
    !!config &&
      !!config.drive_oauth_client_id.trim() &&
      !!config.drive_oauth_client_secret.trim(),
  );
  async function onSignInDrive() {
    if (!config) return;
    if (!signInReady) return;
    signingIn = true;
    pendingAuthUrl = null;
    try {
      const start = await api.driveOauthStart({
        oauthClientId: config.drive_oauth_client_id,
        oauthClientSecret: config.drive_oauth_client_secret,
        googleIp: config.google_ip,
      });
      // Show the URL — the user decides which browser to use.
      pendingAuthUrl = start.auth_url;
      // Long-poll. The Rust command waits up to 120s per call, while
      // the loopback listener stays alive for 5 minutes; keep calling
      // on timeout so a slow browser approval still persists.
      let complete: DriveOauthCompleteDto | null = null;
      const oauthDeadline = Date.now() + 5 * 60 * 1000;
      while (!complete) {
        try {
          complete = await api.driveOauthComplete(start.state_token);
        } catch (e) {
          const message = String(e);
          if (
            message.includes("OAuth flow timed out") &&
            Date.now() < oauthDeadline
          ) {
            continue;
          }
          throw e;
        }
      }
      // Refresh the form state so `drive_has_refresh_token`
      // reflects the just-saved token. The server-side
      // `drive_oauth_complete` already wrote all three OAuth
      // fields (client_id, client_secret, refresh_token) to disk.
      const fresh = await api.getConfig();
      config = fresh;
      pristine = structuredClone(fresh);
      toast.success(
        complete.email
          ? tn("tunnel.drive.signed_in_as", { email: complete.email })
          : t("tunnel.drive.signed_in"),
      );
    } catch (e) {
      toast.error(tn("tunnel.drive.oauth_failed", { error: String(e) }));
    } finally {
      signingIn = false;
      pendingAuthUrl = null;
    }
  }

  async function onOpenAuthUrl() {
    if (!pendingAuthUrl) return;
    try {
      await openUrl(pendingAuthUrl);
    } catch (e) {
      toast.error(`Couldn't open browser: ${String(e)}. Copy the URL manually.`);
    }
  }

  async function onCopyAuthUrl() {
    if (!pendingAuthUrl) return;
    try {
      await navigator.clipboard.writeText(pendingAuthUrl);
      toast.success(t("tunnel.drive.oauth_url_copied"));
    } catch (e) {
      toast.error(`Copy failed: ${String(e)}`);
    }
  }

  // Create-folder modal state. Stays local to this component because
  // it's a one-shot interaction — once we have a folder ID we paste
  // it into the regular folder_id field and the form's normal
  // dirty-tracking kicks in.
  let showCreateFolderModal = $state(false);
  let newFolderName = $state("rahgozar mailbox");
  let creatingFolder = $state(false);
  async function onCreateFolder() {
    if (!config) return;
    if (dirty) {
      toast.error(t("tunnel.drive.save_before_create_folder"));
      return;
    }
    if (signingIn) return;
    creatingFolder = true;
    try {
      const folderId = await api.driveCreateFolder(newFolderName);
      config.drive_folder_id = folderId;
      showCreateFolderModal = false;
      toast.success(t("tunnel.drive.folder_created"));
    } catch (e) {
      toast.error(tn("tunnel.drive.create_folder_failed", { error: String(e) }));
    } finally {
      creatingFolder = false;
    }
  }

  // Relay-pubkey live validation. Fires on input change; cached so
  // an unchanged value doesn't re-call the Rust side every keystroke.
  // The validator is pure (bech32m parse) so latency is negligible,
  // but caching keeps the IPC volume sane.
  let pubkeyValidation = $state<
    { ok: true } | { ok: false; error: string } | null
  >(null);
  let pubkeyLastValidated = $state("");
  async function validateRelayPubkey() {
    if (!config) return;
    const s = config.drive_relay_pubkey.trim();
    if (s === "") {
      pubkeyValidation = null;
      pubkeyLastValidated = "";
      return;
    }
    if (s === pubkeyLastValidated) return;
    pubkeyLastValidated = s;
    try {
      await api.driveValidateRelayPubkey(s);
      pubkeyValidation = { ok: true };
    } catch (e) {
      pubkeyValidation = { ok: false, error: String(e) };
    }
  }

  // Test-connection. Reads from on-disk config (not the in-memory
  // form), so the user must Save before clicking — surface that as
  // a guard rather than silently testing stale settings.
  let testingConnection = $state(false);
  let lastTestResult = $state<{ folder: string; count: number } | null>(null);
  async function onTestDriveConnection() {
    if (!config) return;
    if (dirty) {
      toast.error(t("tunnel.drive.save_before_test"));
      return;
    }
    testingConnection = true;
    lastTestResult = null;
    try {
      const r = await api.driveTestConnection();
      lastTestResult = { folder: r.folder_id, count: r.files_count };
    } catch (e) {
      toast.error(tn("tunnel.drive.test_failed", { error: String(e) }));
    } finally {
      testingConnection = false;
    }
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
         for the reasoning. Inert in LocalBypass and Drive (neither
         dispatch path consults `fronting_groups`), so the editor is
         hidden in those modes. -->
    {#if !isLocalBypass && !isDrive}
      <FrontingGroupsSection />
    {/if}

    <!-- ── Apps Script relay ───────────────────────────────────────
         Mode-gated: only renders for apps_script / full. Other modes
         don't read script_ids / auth_key, so showing the editor just
         implies the values matter when they don't. -->
    {#if !noRelay}
      <section class="bg-surface border-border-subtle rounded-lg border p-5">
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
            {#each config.script_ids as entry, i (i)}
              <div class="flex items-center gap-2">
                <input
                  type="checkbox"
                  bind:checked={config.script_ids[i].enabled}
                  aria-label={tn("tunnel.deployment_ids.enable_aria", {
                    n: i + 1,
                  })}
                  class="accent-accent h-4 w-4 cursor-pointer"
                />
                <span class="text-muted w-7 text-end font-mono text-xs">
                  {String(i + 1).padStart(2, "0")}.
                </span>
                <input
                  type="text"
                  bind:value={config.script_ids[i].id}
                  class="bg-input border-border-subtle focus:border-accent flex-1 rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors {entry.enabled
                    ? ''
                    : 'text-muted line-through opacity-60'}"
                />
                <button
                  type="button"
                  onclick={() => removeIdAt(i)}
                  aria-label={tn("tunnel.deployment_ids.remove_aria", {
                    n: i + 1,
                  })}
                  class="text-error/80 hover:text-error hover:bg-error/10 grid h-7 w-7 place-items-center rounded-md text-lg font-bold transition-colors"
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
              rows="2"
              placeholder={t("tunnel.deployment_ids.placeholder")}
              class="bg-input border-border-subtle focus:border-accent placeholder:text-muted flex-1 rounded-md border px-3 py-2 font-mono text-xs outline-none transition-colors"
            ></textarea>
            <button
              type="button"
              onclick={addFromBuffer}
              disabled={addBuffer.trim().length === 0}
              class="bg-accent hover:bg-accent-hover rounded-md px-4 py-2 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              {t("tunnel.add")}
            </button>
          </div>

          <!-- Count summary: enabled / total. All rows blank → render
               the "tip" copy (functionally the same state as zero
               rows, even though there are blank placeholders the
               user typed and emptied again). -->
          {#if nonBlankTotal === 0}
            <p class="text-muted text-xs">{t("tunnel.deployment_ids.tip_more")}</p>
          {:else if enabledIdCount === 0}
            <p class="text-error text-xs">
              {tn("tunnel.deployment_ids.all_disabled", {
                total: nonBlankTotal,
              })}
            </p>
          {:else}
            <p class="text-success text-xs">
              {tn("tunnel.deployment_ids.summary", {
                enabled: enabledIdCount,
                total: nonBlankTotal,
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
            class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
        </div>
      </section>
    {/if}

    <!-- ── Drive setup ──────────────────────────────────────────────
         Mode-gated: only renders when `mode === "drive"`. The Save
         button at the bottom of the form persists every field
         (including these) via `save_config`'s overlay. The OAuth
         refresh token is NOT a form field — `Sign in with Google`
         triggers the loopback-listener flow which writes the token
         server-side and we re-read the config to flip the
         `drive_has_refresh_token` indicator. -->
    {#if isDrive}
      <section class="bg-surface border-border-subtle rounded-lg border p-5">
        <h2 class="text-secondary mb-3 text-xs font-semibold tracking-wider uppercase">
          {t("tunnel.section.drive")}
        </h2>
        <p class="text-secondary mb-4 text-xs">{t("tunnel.drive.help")}</p>

        <!-- 0. BYO OAuth client credentials. rahgozar ships no
             default OAuth client — every user registers their own
             in Google Cloud Console (see docs/drive_oauth_setup.md
             for the walkthrough) and pastes the values here. This
             section comes BEFORE Sign in so users see the
             prerequisite first; the Sign-in button is disabled
             until both fields are non-empty AND saved. -->
        <div class="border-border-subtle mb-5 rounded-md border p-3">
          <h3 class="text-primary mb-1 text-sm font-semibold">
            {t("tunnel.drive.oauth_client_section")}
          </h3>
          <p class="text-muted mb-3 text-xs">{t("tunnel.drive.oauth_client_help")}</p>
          <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label
                class="text-secondary text-xs font-semibold"
                for="drive-oauth-client-id"
              >
                {t("tunnel.drive.oauth_client_id_label")}
              </label>
              <input
                id="drive-oauth-client-id"
                type="text"
                bind:value={config.drive_oauth_client_id}
                disabled={signingIn}
                placeholder={t("tunnel.drive.oauth_client_id_placeholder")}
                class="bg-input border-border-subtle focus:border-accent placeholder:text-muted mt-1 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              />
            </div>
            <div>
              <label
                class="text-secondary text-xs font-semibold"
                for="drive-oauth-client-secret"
              >
                {t("tunnel.drive.oauth_client_secret_label")}
              </label>
              <input
                id="drive-oauth-client-secret"
                type="password"
                bind:value={config.drive_oauth_client_secret}
                disabled={signingIn}
                placeholder={t("tunnel.drive.oauth_client_secret_placeholder")}
                class="bg-input border-border-subtle focus:border-accent placeholder:text-muted mt-1 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              />
            </div>
          </div>
        </div>

        <!-- 1. OAuth sign-in. The "Signed in" indicator reads from
             `drive_has_refresh_token` which is set by `get_config`
             based on whether `config.drive.oauth_refresh_token` is
             non-empty on disk — i.e. the OAuth flow already
             persisted a token.

             Sign-in needs the BYO OAuth credentials present on
             disk (the Rust side reads them from config.json at
             flow start). Disable the button when the form values
             are missing or dirty: `dirty` means in-memory form
             differs from on-disk → save first. -->
        <div class="mb-5 flex flex-wrap items-center gap-3">
          {#if config.drive_has_refresh_token}
            <span class="text-success text-sm">
              ✓ {t("tunnel.drive.signed_in")}
            </span>
            <button
              type="button"
              onclick={onSignInDrive}
              disabled={signingIn || !signInReady}
              class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              {signingIn ? t("tunnel.drive.signing_in") : t("tunnel.drive.relink_btn")}
            </button>
          {:else}
            <span class="text-warn text-sm">
              {t("tunnel.drive.signed_out")}
            </span>
            <button
              type="button"
              onclick={onSignInDrive}
              disabled={signingIn || !signInReady}
              class="bg-accent hover:bg-accent-hover rounded-md px-4 py-1.5 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              {signingIn ? t("tunnel.drive.signing_in") : t("tunnel.drive.sign_in_btn")}
            </button>
          {/if}
          {#if !signInReady}
            <span class="text-warn text-xs">
              {t("tunnel.drive.oauth_creds_required")}
            </span>
          {/if}
        </div>

        <!-- Auth-URL dialog. Visible only while a Sign-in flow is in
             flight (pendingAuthUrl != null). The user picks which
             browser to use: Copy → paste anywhere; Open → system
             default. Either way the loopback listener catches the
             redirect when the user finishes sign-in. -->
        {#if pendingAuthUrl}
          <div
            class="border-border-subtle bg-surface-2 mb-5 rounded-md border p-3 text-sm"
          >
            <div class="text-primary mb-2 font-semibold">
              {t("tunnel.drive.oauth_url_dialog_title")}
            </div>
            <p class="text-secondary mb-2 text-xs">
              {t("tunnel.drive.oauth_url_dialog_help")}
            </p>
            <input
              type="text"
              readonly
              value={pendingAuthUrl}
              class="border-border-subtle bg-surface-1 text-primary mb-2 w-full rounded-md border px-2 py-1 font-mono text-xs"
            />
            <div class="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onclick={onCopyAuthUrl}
                class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1 text-xs transition-colors"
              >
                {t("tunnel.drive.oauth_url_copy")}
              </button>
              <button
                type="button"
                onclick={onOpenAuthUrl}
                class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 py-1 text-xs transition-colors"
              >
                {t("tunnel.drive.oauth_url_open")}
              </button>
              <span class="text-muted ml-auto text-xs">
                {t("tunnel.drive.oauth_url_waiting")}
              </span>
            </div>
          </div>
        {/if}

        <!-- 2. Folder ID. Set manually OR via Create-new modal. -->
        <div class="mb-5">
          <label class="text-primary text-sm font-semibold" for="drive-folder-id">
            {t("tunnel.drive.folder_id_label")}
          </label>
          <p class="text-muted text-xs">{t("tunnel.drive.folder_id_help")}</p>
          <div class="mt-1.5 flex items-stretch gap-2">
            <input
              id="drive-folder-id"
              type="text"
              bind:value={config.drive_folder_id}
              placeholder={t("tunnel.drive.folder_id_placeholder")}
              class="bg-input border-border-subtle focus:border-accent placeholder:text-muted flex-1 rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
            />
            <button
              type="button"
              onclick={() => (showCreateFolderModal = true)}
              disabled={!config.drive_has_refresh_token || dirty || signingIn}
              class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-3 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              {t("tunnel.drive.create_folder_btn")}
            </button>
          </div>
        </div>

        <!-- 3. Relay pubkey. Live-validated via the
             `drive_validate_relay_pubkey` Tauri command — pure
             bech32m parse, so the IPC cost is negligible. The
             cached-last-validated value in the script block prevents
             re-calling for an unchanged input. -->
        <div class="mb-5">
          <label class="text-primary text-sm font-semibold" for="drive-relay-pubkey">
            {t("tunnel.drive.relay_pubkey_label")}
          </label>
          <p class="text-muted text-xs">{t("tunnel.drive.relay_pubkey_help")}</p>
          <input
            id="drive-relay-pubkey"
            type="text"
            bind:value={config.drive_relay_pubkey}
            oninput={validateRelayPubkey}
            placeholder={t("tunnel.drive.relay_pubkey_placeholder")}
            class="bg-input border-border-subtle focus:border-accent placeholder:text-muted mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
          />
          {#if pubkeyValidation && pubkeyValidation.ok}
            <p class="text-success mt-1 text-xs">✓ {t("tunnel.drive.relay_pubkey_valid")}</p>
          {:else if pubkeyValidation && !pubkeyValidation.ok}
            <p class="text-error mt-1 text-xs">
              {tn("tunnel.drive.relay_pubkey_invalid", {
                error: pubkeyValidation.error,
              })}
            </p>
          {/if}
        </div>

        <!-- 4. Test connection. Guarded by `dirty` so the user
             saves their changes before testing (the test reads
             from on-disk config). -->
        <div class="mb-5 flex items-center gap-3">
            <button
              type="button"
              onclick={onTestDriveConnection}
              disabled={testingConnection || !config.drive_has_refresh_token || dirty}
              class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-4 py-1.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
            {testingConnection ? t("tunnel.drive.testing") : t("tunnel.drive.test_btn")}
          </button>
          {#if lastTestResult}
            <span class="text-success text-xs">
              ✓ {tn("tunnel.drive.test_ok", {
                folder: lastTestResult.folder,
                count: lastTestResult.count,
              })}
            </span>
          {/if}
        </div>

        <!-- 5. Advanced: poll interval + max concurrent uploads. -->
        <details class="border-border-subtle border-t pt-3">
          <summary class="text-secondary cursor-pointer text-xs">
            {t("tunnel.drive.advanced")}
          </summary>
          <div class="mt-3 grid grid-cols-2 gap-4">
            <div>
              <label class="text-primary text-sm font-semibold" for="drive-poll-interval">
                {t("tunnel.drive.poll_interval_label")}
              </label>
              <p class="text-muted text-xs">{t("tunnel.drive.poll_interval_help")}</p>
              <input
                id="drive-poll-interval"
                type="number"
                min="50"
                max="60000"
                bind:value={config.drive_poll_interval_ms}
                class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
              />
            </div>
            <div>
              <label class="text-primary text-sm font-semibold" for="drive-max-concurrent">
                {t("tunnel.drive.max_concurrent_label")}
              </label>
              <p class="text-muted text-xs">{t("tunnel.drive.max_concurrent_help")}</p>
              <input
                id="drive-max-concurrent"
                type="number"
                min="1"
                max="64"
                bind:value={config.drive_max_concurrent_uploads}
                class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 font-mono text-xs outline-none transition-colors"
              />
            </div>
          </div>
        </details>
      </section>

      <!-- Create-folder mini-modal. Inline rather than a separate
           component because it has zero shared state with anything
           else — name input + create + cancel. -->
      {#if showCreateFolderModal}
        <div
          class="fixed inset-0 z-50 grid place-items-center bg-black/50 backdrop-blur-sm"
          onclick={(e) => {
            if (e.target === e.currentTarget) showCreateFolderModal = false;
          }}
          role="presentation"
        >
          <div
            class="bg-surface border-border-subtle w-[24rem] rounded-lg border p-5 shadow-xl"
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-folder-title"
          >
            <h3 id="create-folder-title" class="mb-3 text-base font-semibold">
              {t("tunnel.drive.create_folder_btn")}
            </h3>
            <label class="text-primary text-sm font-semibold" for="new-folder-name">
              {t("tunnel.drive.create_folder_name_label")}
            </label>
            <input
              id="new-folder-name"
              type="text"
              bind:value={newFolderName}
              placeholder={t("tunnel.drive.create_folder_name_placeholder")}
              class="bg-input border-border-subtle focus:border-accent mt-1.5 w-full rounded-md border px-3 py-1.5 text-sm outline-none transition-colors"
            />
            <div class="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onclick={() => (showCreateFolderModal = false)}
                disabled={creatingFolder}
                class="border-border-subtle text-secondary hover:text-primary hover:border-border-strong rounded-md border px-4 py-1.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50"
              >
                {t("tunnel.drive.create_folder_cancel")}
              </button>
              <button
                type="button"
                onclick={onCreateFolder}
                disabled={creatingFolder || newFolderName.trim() === ""}
                class="bg-accent hover:bg-accent-hover rounded-md px-4 py-1.5 text-sm font-semibold text-black transition-colors disabled:cursor-not-allowed disabled:opacity-50"
              >
                {creatingFolder
                  ? t("tunnel.drive.creating_folder")
                  : t("tunnel.drive.create_folder_confirm")}
              </button>
            </div>
          </div>
        </div>
      {/if}
    {/if}

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
        <!-- front_domain / SNI pool feed the Apps Script relay path.
             google_ip also feeds Drive/OAuth endpoint resolution, so
             keep it visible in Drive mode while hiding the relay-only
             knobs. LocalBypass ignores all three. -->
        {#if !isLocalBypass && !isDrive}
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
        {/if}
        {#if !isLocalBypass}
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
            {#if !isDrive}
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
            {/if}
          </div>
        {/if}
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
