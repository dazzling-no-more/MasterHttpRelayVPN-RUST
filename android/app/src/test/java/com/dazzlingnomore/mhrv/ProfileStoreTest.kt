package com.dazzlingnomore.mhrv

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * Unit coverage for [ProfileStore] and the [ConfigStore]/[RahgozarConfig]
 * surfaces it touches. These tests pin the invariants documented in
 * the class headers — drift here means desktop and Android can
 * diverge silently on the same profile data, which is the whole
 * point of the test matrix.
 *
 * Mirror of the Rust-side tests in `src/profiles.rs` — each invariant
 * has a counterpart so a behavioural delta between Rust and Kotlin
 * shows up as a test failure on at least one side.
 */
@RunWith(RobolectricTestRunner::class)
class ProfileStoreTest {
    private val validRelayPubkey =
        "rgdr1jxtcw0wklzug0kxfsegwh2cc4kt6y50a5ac7vwmlln0emd30sq4sd7x0sx"

    private lateinit var ctx: Context
    private lateinit var profilesFile: File
    private lateinit var configFile: File

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        profilesFile = File(ctx.filesDir, "profiles.json")
        configFile = File(ctx.filesDir, "config.json")
        clearAll()
    }

    @After
    fun tearDown() {
        clearAll()
    }

    /**
     * Wrap bare IDs/URLs into [DeploymentEntry]s with `enabled = true`.
     * Most ProfileStore tests use `appsScriptUrls` as throwaway content
     * to make configs distinguishable — they don't care about the
     * enabled flag, so this keeps fixture lines short and readable.
     * Tests that care about disabled rows construct
     * [DeploymentEntry] inline with `enabled = false`.
     */
    private fun depEntries(vararg ids: String): List<DeploymentEntry> = ids.map { DeploymentEntry(it, true) }

    /**
     * Recursive cleanup so a test that mid-flight created a directory
     * at a file path (the injected-write-failure trick) doesn't leak
     * into the next test. Plain [File.delete] won't remove a non-empty
     * directory.
     */
    private fun clearAll() {
        listOf(
            profilesFile,
            configFile,
            File(ctx.filesDir, "profiles.json.tmp"),
            File(ctx.filesDir, "profiles.json.bak"),
            File(ctx.filesDir, "config.json.tmp"),
            File(ctx.filesDir, "config.json.bak"),
        ).forEach { deleteRecursively(it) }
    }

    private fun deleteRecursively(f: File) {
        if (!f.exists()) return
        if (f.isDirectory) {
            f.listFiles()?.forEach { deleteRecursively(it) }
        }
        f.delete()
    }

    // ---- Invariant 1: raw snapshot preservation ----

    /**
     * The whole point of storing snapshots as raw JSON: a profile
     * written by a desktop build (or a future Android build) with
     * config fields this build doesn't model must round-trip
     * losslessly through Save → Switch.
     */
    @Test
    fun applyProfile_preserves_unknown_fields_in_config_json() {
        val futureSnapshot =
            """
            {
              "mode": "apps_script",
              "script_ids": ["A"],
              "auth_key": "secret",
              "fronting_groups": [
                {"name": "vercel", "ip": "76.76.21.21", "sni": "react.dev",
                 "domains": ["vercel.com"]}
              ],
              "exit_node": {"enabled": true, "relay_url": "https://e.example",
                            "psk": "p", "mode": "selective",
                            "hosts": ["chatgpt.com"]},
              "request_timeout_secs": 45,
              "future_field_xyz": [1, 2, 3]
            }
            """.trimIndent()
        val written =
            """
            {"active":"future","profiles":[{"name":"future","config":$futureSnapshot}]}
            """.trimIndent()
        profilesFile.writeText(written)

        val applied = ProfileStore.applyProfile(ctx, "future")
        assertTrue(
            "apply should succeed on a valid future-shape snapshot, got ${applied::class.simpleName}",
            applied is ProfileStore.ApplyResult.Ok,
        )

        assertTrue("config.json should have been written", configFile.exists())
        val onDisk = JSONObject(configFile.readText())
        assertEquals("apps_script", onDisk.optString("mode"))
        assertEquals("secret", onDisk.optString("auth_key"))
        assertTrue("fronting_groups must survive", onDisk.has("fronting_groups"))
        assertEquals(1, onDisk.optJSONArray("fronting_groups")?.length() ?: 0)
        assertTrue("exit_node must survive", onDisk.has("exit_node"))
        assertEquals(45, onDisk.optInt("request_timeout_secs", -1))
        assertTrue(
            "completely unknown future field must survive",
            onDisk.has("future_field_xyz"),
        )
    }

    /**
     * The data-loss bug we fixed: unknown fields used to be dropped
     * the moment the user edited any form field (because persist()
     * runs cfg.toJson() which only emits modelled keys). The fix
     * was to capture unknown keys into RahgozarConfig.extrasJson and
     * re-emit them. This test asserts: load → toJson round-trips
     * unknown fields.
     */
    @Test
    fun rahgozarconfig_toJson_preserves_unknown_fields() {
        val originalJson =
            """
            {
              "mode": "apps_script",
              "script_ids": ["A"],
              "auth_key": "secret",
              "fronting_groups": [{"name":"x","ip":"1.2.3.4","sni":"a.b","domains":["c.com"]}],
              "request_timeout_secs": 99,
              "disable_padding": true
            }
            """.trimIndent()
        configFile.writeText(originalJson)
        val cfg = ConfigStore.load(ctx)
        // Round-trip via toJson — the path persist() takes on every edit.
        val roundTripped = JSONObject(cfg.toJson())
        assertEquals(99, roundTripped.optInt("request_timeout_secs"))
        assertTrue(roundTripped.optBoolean("disable_padding"))
        assertTrue(roundTripped.has("fronting_groups"))
    }

    /**
     * Critical: Rust writes `script_id` (singular, can be string or
     * array). Before this fix, Android only read `script_ids` (plural,
     * array only), so a desktop-saved profile applied on Android with
     * zero deployment IDs and the proxy would refuse to start.
     */
    @Test
    fun configstore_reads_rust_shaped_script_id_scalar() {
        val rustScalar =
            """
            {"mode":"apps_script","script_id":"DESKTOP_ID","auth_key":"k"}
            """.trimIndent()
        configFile.writeText(rustScalar)
        val cfg = ConfigStore.load(ctx)
        assertEquals(1, cfg.appsScriptUrls.size)
        assertTrue(
            cfg.appsScriptUrls
                .first()
                .url
                .contains("DESKTOP_ID"),
        )
        assertTrue("hasDeploymentId must be true", cfg.hasDeploymentId)
    }

    @Test
    fun configstore_reads_rust_shaped_script_id_array() {
        val rustArray =
            """
            {"mode":"apps_script","script_id":["A","B","C"],"auth_key":"k"}
            """.trimIndent()
        configFile.writeText(rustArray)
        val cfg = ConfigStore.load(ctx)
        assertEquals(3, cfg.appsScriptUrls.size)
    }

    @Test
    fun configstore_reads_both_script_id_and_script_ids_combined() {
        // Hand-edited config where someone added a key via "script_id"
        // and another via "script_ids". The union must be exposed.
        val combined =
            """
            {"mode":"apps_script","script_id":"X","script_ids":["Y","Z"],"auth_key":"k"}
            """.trimIndent()
        configFile.writeText(combined)
        val cfg = ConfigStore.load(ctx)
        assertEquals(3, cfg.appsScriptUrls.size)
    }

    /**
     * Object form parses, the enabled flag is preserved through
     * [ConfigStore.load], and the disabled row is invisible to the
     * "do we have credentials?" gate but still present on the model
     * so the user can flip it back on.
     */
    @Test
    fun configstore_reads_script_id_object_form_with_disabled_row() {
        val objForm =
            """
            {
              "mode": "apps_script",
              "auth_key": "k",
              "script_id": [
                {"id": "A", "enabled": true},
                {"id": "B", "enabled": false},
                {"id": "C", "enabled": true}
              ]
            }
            """.trimIndent()
        configFile.writeText(objForm)
        val cfg = ConfigStore.load(ctx)
        assertEquals(3, cfg.appsScriptUrls.size)
        assertTrue("A must be enabled", cfg.appsScriptUrls[0].enabled)
        assertFalse("B must be disabled", cfg.appsScriptUrls[1].enabled)
        assertTrue("C must be enabled", cfg.appsScriptUrls[2].enabled)
        assertTrue("at least one usable row → hasDeploymentId true", cfg.hasDeploymentId)
    }

    /**
     * Disabled rows survive a load → save round-trip. Without this
     * a user toggling a row off would only have it parked until the
     * next save — at which point [toJson] would silently drop it
     * and we'd regress to "disable = delete".
     */
    @Test
    fun configstore_round_trip_preserves_disabled_row() {
        val cfg =
            RahgozarConfig(
                mode = Mode.APPS_SCRIPT,
                appsScriptUrls =
                    listOf(
                        DeploymentEntry("https://script.google.com/macros/s/A/exec", true),
                        DeploymentEntry("https://script.google.com/macros/s/B/exec", false),
                    ),
                authKey = "k",
            )
        ConfigStore.save(ctx, cfg)
        // Confirm the on-disk shape carries the enabled flag — a
        // build that downgraded to bare strings would lose the flag.
        val onDisk = JSONObject(configFile.readText())
        val arr = onDisk.getJSONArray("script_id")
        assertEquals(2, arr.length())
        val first = arr.getJSONObject(0)
        val second = arr.getJSONObject(1)
        assertEquals("A", first.optString("id"))
        assertTrue(first.optBoolean("enabled", false))
        assertEquals("B", second.optString("id"))
        assertFalse(second.optBoolean("enabled", true))

        val reloaded = ConfigStore.load(ctx)
        assertEquals(2, reloaded.appsScriptUrls.size)
        assertTrue(reloaded.appsScriptUrls[0].enabled)
        assertFalse(reloaded.appsScriptUrls[1].enabled)
    }

    /**
     * Downgrade-compat: when no row is disabled, [toJson] must keep
     * the legacy bare-string array shape so an older rahgozar build
     * (one that doesn't know the `{id, enabled}` form) can still
     * parse a config written by this build.
     */
    @Test
    fun configstore_writes_legacy_string_array_when_all_enabled() {
        val cfg =
            RahgozarConfig(
                mode = Mode.APPS_SCRIPT,
                appsScriptUrls =
                    listOf(
                        DeploymentEntry("https://script.google.com/macros/s/A/exec", true),
                        DeploymentEntry("https://script.google.com/macros/s/B/exec", true),
                    ),
                authKey = "k",
            )
        ConfigStore.save(ctx, cfg)
        val onDisk = JSONObject(configFile.readText())
        val arr = onDisk.getJSONArray("script_id")
        assertEquals(2, arr.length())
        // Bare strings, NOT objects — an older parser would crash on
        // `{id,enabled}` shapes here.
        assertEquals("A", arr.getString(0))
        assertEquals("B", arr.getString(1))
    }

    /**
     * `hasDeploymentId` must require an *enabled* row — the relay
     * round-robin filters out disabled IDs, so a profile with every
     * row parked is functionally credential-less. The HomeScreen
     * "Connect" gate and the section-expand logic both lean on this.
     */
    @Test
    fun hasDeploymentId_false_when_all_rows_disabled() {
        val cfg =
            RahgozarConfig(
                mode = Mode.APPS_SCRIPT,
                appsScriptUrls =
                    listOf(
                        DeploymentEntry("https://script.google.com/macros/s/A/exec", false),
                        DeploymentEntry("https://script.google.com/macros/s/B/exec", false),
                    ),
                authKey = "k",
            )
        assertFalse(
            "all rows disabled → hasDeploymentId must be false",
            cfg.hasDeploymentId,
        )
        // And: flipping one back on flips the gate.
        val flipped =
            cfg.copy(
                appsScriptUrls =
                    cfg.appsScriptUrls.mapIndexed { i, e ->
                        if (i == 0) e.copy(enabled = true) else e
                    },
            )
        assertTrue(flipped.hasDeploymentId)
    }

    /**
     * ApplyProfile must refuse a snapshot whose every script_id row
     * is disabled, in the same way it refuses a missing key. The
     * Rust validator backs this — `script_ids_resolved()` filters to
     * enabled-only, so an all-disabled `script_id` looks like an
     * empty list to `Config::validate`, and ApplyProfile sniffs that
     * via `validateRuntimeShape`.
     */
    @Test
    fun applyProfile_refuses_all_disabled_apps_script_snapshot() {
        val bad =
            """
            {
              "active": "bad",
              "profiles": [{
                "name": "bad",
                "config": {
                  "mode": "apps_script",
                  "auth_key": "k",
                  "script_id": [
                    {"id": "A", "enabled": false},
                    {"id": "B", "enabled": false}
                  ]
                }
              }]
            }
            """.trimIndent()
        profilesFile.writeText(bad)
        // Plant a known-good live config to confirm it's untouched.
        ConfigStore.save(ctx, RahgozarConfig(authKey = "preserve-me"))
        val before = configFile.readText()

        val r = ProfileStore.applyProfile(ctx, "bad")
        assertTrue(
            "expected Failed, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Failed,
        )
        assertEquals(before, configFile.readText())
    }

    // ---- Invariant 2: active == "matches the live config" ----

    @Test
    fun delete_active_clears_pointer() {
        ProfileStore.upsert(ctx, "a", RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "x"))
        ProfileStore.upsert(ctx, "b", RahgozarConfig(appsScriptUrls = depEntries("B"), authKey = "y"))
        ProfileStore.upsert(ctx, "c", RahgozarConfig(appsScriptUrls = depEntries("C"), authKey = "z"))
        assertEquals(ProfileStore.MutationResult.Ok, ProfileStore.delete(ctx, "c"))
        val state = ProfileStore.load(ctx)
        assertEquals("", state.active)
        assertNotNull(state.find("a"))
        assertNotNull(state.find("b"))
    }

    @Test
    fun delete_non_active_keeps_pointer() {
        ProfileStore.upsert(ctx, "a", RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "x"))
        ProfileStore.upsert(ctx, "b", RahgozarConfig(appsScriptUrls = depEntries("B"), authKey = "y"))
        ProfileStore.delete(ctx, "a")
        assertEquals("b", ProfileStore.load(ctx).active)
    }

    @Test
    fun upsert_writes_snapshot_to_live_config_json() {
        val cfg =
            RahgozarConfig(
                mode = Mode.APPS_SCRIPT,
                appsScriptUrls = depEntries("A"),
                authKey = "secret",
                googleIp = "1.2.3.4",
            )
        val r = ProfileStore.upsert(ctx, "home", cfg)
        assertEquals(ProfileStore.MutationResult.Ok, r)
        assertTrue("config.json must be written by upsert", configFile.exists())
        val onDisk = JSONObject(configFile.readText())
        assertEquals("apps_script", onDisk.optString("mode"))
        assertEquals("secret", onDisk.optString("auth_key"))
        assertEquals("1.2.3.4", onDisk.optString("google_ip"))
        assertEquals("home", ProfileStore.load(ctx).active)
    }

    @Test
    fun insertNew_writes_snapshot_to_live_config_json() {
        val cfg = RahgozarConfig(appsScriptUrls = depEntries("X"), authKey = "k")
        val r = ProfileStore.insertNew(ctx, "first", cfg)
        assertEquals(ProfileStore.MutationResult.Ok, r)
        assertTrue(configFile.exists())
        assertEquals("first", ProfileStore.load(ctx).active)
    }

    /**
     * Invariant 2 follow-up: clearActiveIfAny clears active when set,
     * is a no-op otherwise. Called on every persist() in HomeScreen.
     */
    @Test
    fun clearActiveIfAny_clears_when_set() {
        ProfileStore.upsert(ctx, "p", RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "k"))
        assertEquals("p", ProfileStore.load(ctx).active)
        ProfileStore.clearActiveIfAny(ctx)
        val state = ProfileStore.load(ctx)
        assertEquals("", state.active)
        // Profile entry should still be there — we cleared the marker,
        // not the data.
        assertNotNull(state.find("p"))
    }

    @Test
    fun clearActiveIfAny_no_op_on_missing_file() {
        // Should not create profiles.json out of thin air.
        ProfileStore.clearActiveIfAny(ctx)
        assertFalse(profilesFile.exists())
    }

    @Test
    fun clearActiveIfAny_no_op_on_already_empty_active() {
        // Write a profiles.json with no active pointer.
        profilesFile.writeText("""{"active":"","profiles":[]}""")
        ProfileStore.clearActiveIfAny(ctx)
        // No write should have happened, but to be lenient we allow
        // a rewrite as long as content is the same on reload.
        assertEquals("", ProfileStore.load(ctx).active)
    }

    // ---- Invariant 3: persist before in-memory state changes ----

    @Test
    fun rename_collision_does_not_mutate_state() {
        ProfileStore.upsert(ctx, "a", RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "x"))
        ProfileStore.upsert(ctx, "b", RahgozarConfig(appsScriptUrls = depEntries("B"), authKey = "y"))
        val r = ProfileStore.rename(ctx, "a", "b")
        assertEquals(ProfileStore.MutationResult.Duplicate, r)
        val state = ProfileStore.load(ctx)
        assertNotNull(state.find("a"))
        assertNotNull(state.find("b"))
    }

    @Test
    fun upsert_empty_name_is_rejected() {
        val r = ProfileStore.upsert(ctx, "   ", RahgozarConfig())
        assertEquals(ProfileStore.MutationResult.EmptyName, r)
        assertFalse("nothing should be written for empty name", profilesFile.exists())
    }

    @Test
    fun insertNew_duplicate_returns_Duplicate_not_overwrite() {
        ProfileStore.insertNew(
            ctx,
            "p",
            RahgozarConfig(appsScriptUrls = depEntries("first"), authKey = "k"),
        )
        val r =
            ProfileStore.insertNew(
                ctx,
                "p",
                RahgozarConfig(appsScriptUrls = depEntries("second"), authKey = "k"),
            )
        assertEquals(ProfileStore.MutationResult.Duplicate, r)
        val applied = ProfileStore.applyProfile(ctx, "p")
        assertTrue(applied is ProfileStore.ApplyResult.Ok)
        val cfg = (applied as ProfileStore.ApplyResult.Ok).cfg
        assertEquals(
            listOf(DeploymentEntry("https://script.google.com/macros/s/first/exec", true)),
            cfg.appsScriptUrls,
        )
    }

    // ---- Invariant 4: load failure is loud ----

    @Test
    fun corrupt_file_is_surfaced_via_loadStrict() {
        profilesFile.writeText("{ not valid json")
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(r is ProfileStore.LoadResult.Corrupt)
    }

    @Test
    fun missing_file_is_surfaced_as_Missing() {
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(r is ProfileStore.LoadResult.Missing)
    }

    /**
     * Partial-malformation strictness: a file where the top-level
     * shape is valid but one profile entry is broken must surface
     * as Corrupt, NOT a lenient "skip the bad entry and silently
     * drop it on next save". Before this was strict, the next save
     * would have permanently lost the broken entry.
     */
    @Test
    fun partial_malformed_profile_entry_surfaces_as_corrupt() {
        val partial =
            """
            {
              "active": "good",
              "profiles": [
                {"name": "good", "config": {"mode": "apps_script"}},
                {"name": "broken"}
              ]
            }
            """.trimIndent()
        profilesFile.writeText(partial)
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(
            "expected Corrupt for missing config, got ${r::class.simpleName}",
            r is ProfileStore.LoadResult.Corrupt,
        )
    }

    @Test
    fun partial_malformed_profile_name_surfaces_as_corrupt() {
        val partial =
            """
            {
              "active": "good",
              "profiles": [
                {"name": "", "config": {"mode": "apps_script"}}
              ]
            }
            """.trimIndent()
        profilesFile.writeText(partial)
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(r is ProfileStore.LoadResult.Corrupt)
    }

    /**
     * Duplicate names make every by-name operation (apply / rename /
     * delete) ambiguous, so we reject on load. Matches the Rust-side
     * test of the same name.
     */
    @Test
    fun duplicate_names_surface_as_corrupt() {
        val dup =
            """
            {
              "active": "p",
              "profiles": [
                {"name": "p", "config": {"mode": "apps_script"}},
                {"name": "p", "config": {"mode": "full"}}
              ]
            }
            """.trimIndent()
        profilesFile.writeText(dup)
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(
            "expected Corrupt for duplicate names, got ${r::class.simpleName}",
            r is ProfileStore.LoadResult.Corrupt,
        )
        val msg = (r as ProfileStore.LoadResult.Corrupt).cause.message.orEmpty()
        assertTrue(
            "error should mention duplicate explicitly: $msg",
            msg.contains("duplicate", ignoreCase = true),
        )
    }

    @Test
    fun mutations_refuse_to_overwrite_corrupt_profiles_file() {
        profilesFile.writeText("{ corrupt")
        val before = profilesFile.readText()
        val r =
            ProfileStore.upsert(
                ctx,
                "p",
                RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "k"),
            )
        assertTrue(r is ProfileStore.MutationResult.CorruptOnDisk)
        assertEquals(before, profilesFile.readText())
    }

    @Test
    fun corrupt_then_delete_corrupt_then_save_works() {
        profilesFile.writeText("{ corrupt")
        profilesFile.delete()
        val r =
            ProfileStore.upsert(
                ctx,
                "p",
                RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "k"),
            )
        assertEquals(ProfileStore.MutationResult.Ok, r)
        assertEquals("p", ProfileStore.load(ctx).active)
    }

    // ---- Atomic-replace data-loss regression guard ----

    /**
     * Regression for the pre-delete data-loss bug: if [ProfileStore.save]
     * succeeds, the previous file's bytes are gone (replaced) — but
     * if it FAILED (which we can't easily simulate cleanly), the
     * previous file must still exist. We can at least verify the
     * happy path leaves no leftover temp/backup files.
     */
    @Test
    fun save_leaves_no_tmp_or_bak_behind_on_success() {
        ProfileStore.upsert(ctx, "p", RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "k"))
        assertFalse(File(ctx.filesDir, "profiles.json.tmp").exists())
        assertFalse(File(ctx.filesDir, "profiles.json.bak").exists())
    }

    // ---- Cross-platform parity: applyProfile + decoded view ----

    @Test
    fun applyProfile_decoded_view_matches_snapshot_subset() {
        val cfg =
            RahgozarConfig(
                mode = Mode.FULL,
                appsScriptUrls = depEntries("Z"),
                authKey = "topsecret",
                parallelRelay = 3,
            )
        ProfileStore.upsert(ctx, "fullmode", cfg)
        ConfigStore.save(ctx, RahgozarConfig(mode = Mode.DIRECT))
        val applied = ProfileStore.applyProfile(ctx, "fullmode")
        assertTrue(applied is ProfileStore.ApplyResult.Ok)
        val out = (applied as ProfileStore.ApplyResult.Ok).cfg
        assertEquals(Mode.FULL, out.mode)
        assertEquals("topsecret", out.authKey)
        assertEquals(3, out.parallelRelay)
    }

    /**
     * Snapshot with apps_script mode but no script_id/script_ids and
     * no auth_key would fail Rust's `Config::validate`. Apply must
     * refuse instead of clobbering config.json with bytes the runtime
     * rejects on its next start.
     */
    @Test
    fun applyProfile_refuses_runtime_invalid_snapshot() {
        val bad =
            """
            {
              "active": "bad",
              "profiles": [{"name": "bad", "config": {"mode": "apps_script"}}]
            }
            """.trimIndent()
        profilesFile.writeText(bad)
        // Plant a known-good live config so we can assert it's unchanged.
        ConfigStore.save(ctx, RahgozarConfig(authKey = "preserve-me"))
        val before = configFile.readText()

        val r = ProfileStore.applyProfile(ctx, "bad")
        assertTrue(
            "expected Failed, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Failed,
        )
        // config.json must not have been touched.
        assertEquals(before, configFile.readText())
    }

    /**
     * A direct-mode snapshot doesn't need script_id or auth_key — the
     * runtime tolerates both being absent for direct. Apply must
     * succeed.
     */
    @Test
    fun applyProfile_accepts_minimal_direct_snapshot() {
        val ok =
            """
            {
              "active": "",
              "profiles": [{"name": "d", "config": {"mode": "direct"}}]
            }
            """.trimIndent()
        profilesFile.writeText(ok)
        val r = ProfileStore.applyProfile(ctx, "d")
        assertTrue(
            "minimal direct snapshot must apply, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Ok,
        )
    }

    /**
     * Mirror of [applyProfile_accepts_minimal_direct_snapshot] for
     * the `local_bypass` mode. Pins the invariant that
     * `validateRuntimeShape` gates the credential check on
     * [Mode.usesAppsScriptRelay] rather than a hard-coded allowlist
     * of mode strings — adding a future cred-free mode means
     * flipping that one predicate, not chasing four allowlists.
     */
    @Test
    fun applyProfile_accepts_minimal_local_bypass_snapshot() {
        val ok =
            """
            {
              "active": "",
              "profiles": [{"name": "lb", "config": {"mode": "local_bypass"}}]
            }
            """.trimIndent()
        profilesFile.writeText(ok)
        val r = ProfileStore.applyProfile(ctx, "lb")
        assertTrue(
            "minimal local_bypass snapshot must apply, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Ok,
        )
        // The applied config.json should round-trip back into a
        // RahgozarConfig with mode = LOCAL_BYPASS. Without this
        // assertion we could regress to the parser silently
        // downgrading to APPS_SCRIPT (the `else -> Mode.APPS_SCRIPT`
        // fallback in `loadFromJson`).
        val applied = ConfigStore.load(ctx)
        assertEquals(Mode.LOCAL_BYPASS, applied.mode)
        assertFalse(
            "local_bypass must not require Apps Script creds",
            applied.mode.usesAppsScriptRelay(),
        )
    }

    /**
     * Drive-mode snapshot acceptance gate. Before this slice
     * `validateRuntimeShape` didn't know about `Mode.DRIVE` and
     * `applyProfile` would reject a valid Drive profile as
     * "unknown mode 'drive'", silently losing the user's setup.
     */
    @Test
    fun applyProfile_accepts_well_formed_drive_snapshot() {
        val ok =
            """
            {
              "active": "",
              "profiles": [{"name": "d", "config": {
                "mode": "drive",
                "drive": {
                  "oauth_client_id": "CID.apps.googleusercontent.com",
                  "oauth_client_secret": "SECRET",
                  "folder_id": "FOLDER_ID",
                  "relay_pubkey": "$validRelayPubkey",
                  "oauth_refresh_token": "1//04xxxx"
                }
              }}]
            }
            """.trimIndent()
        profilesFile.writeText(ok)
        val r = ProfileStore.applyProfile(ctx, "d")
        assertTrue(
            "well-formed drive snapshot must apply, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Ok,
        )
        val applied = ConfigStore.load(ctx)
        assertEquals(Mode.DRIVE, applied.mode)
        assertEquals("FOLDER_ID", applied.driveFolderId)
        assertEquals("CID.apps.googleusercontent.com", applied.driveOauthClientId)
    }

    /**
     * Drive snapshot missing the BYO OAuth credentials must be
     * rejected up front — Rust's `Config::validate` would fail at
     * proxy-start with the same message, but applyProfile catches
     * it first so config.json isn't clobbered by bytes the runtime
     * will refuse on its next start.
     */
    @Test
    fun applyProfile_refuses_drive_snapshot_missing_oauth_client_id() {
        val bad =
            """
            {
              "active": "bad",
              "profiles": [{"name": "bad", "config": {
                "mode": "drive",
                "drive": {
                  "oauth_client_secret": "SECRET",
                  "folder_id": "FOLDER_ID",
                  "relay_pubkey": "$validRelayPubkey"
                }
              }}]
            }
            """.trimIndent()
        profilesFile.writeText(bad)
        ConfigStore.save(ctx, RahgozarConfig(authKey = "preserve-me"))
        val before = configFile.readText()

        val r = ProfileStore.applyProfile(ctx, "bad")
        assertTrue(
            "expected Failed for missing oauth_client_id, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Failed,
        )
        assertEquals(before, configFile.readText())
    }

    @Test
    fun applyProfile_refuses_drive_snapshot_missing_refresh_token() {
        val bad =
            """
            {
              "active": "bad",
              "profiles": [{"name": "bad", "config": {
                "mode": "drive",
                "drive": {
                  "oauth_client_id": "CID.apps.googleusercontent.com",
                  "oauth_client_secret": "SECRET",
                  "folder_id": "FOLDER_ID",
                  "relay_pubkey": "$validRelayPubkey"
                }
              }}]
            }
            """.trimIndent()
        profilesFile.writeText(bad)
        ConfigStore.save(ctx, RahgozarConfig(authKey = "preserve-me"))
        val before = configFile.readText()

        val r = ProfileStore.applyProfile(ctx, "bad")
        assertTrue(
            "expected Failed for missing oauth_refresh_token, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Failed,
        )
        assertEquals(before, configFile.readText())
    }

    @Test
    fun applyProfile_refuses_drive_snapshot_with_bad_relay_pubkey() {
        val bad =
            """
            {
              "active": "bad",
              "profiles": [{"name": "bad", "config": {
                "mode": "drive",
                "drive": {
                  "oauth_client_id": "CID.apps.googleusercontent.com",
                  "oauth_client_secret": "SECRET",
                  "folder_id": "FOLDER_ID",
                  "relay_pubkey": "rgdr1qqqq",
                  "oauth_refresh_token": "1//04xxxx"
                }
              }}]
            }
            """.trimIndent()
        profilesFile.writeText(bad)
        ConfigStore.save(ctx, RahgozarConfig(authKey = "preserve-me"))
        val before = configFile.readText()

        val r = ProfileStore.applyProfile(ctx, "bad")
        assertTrue(
            "expected Failed for malformed relay_pubkey, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Failed,
        )
        assertEquals(before, configFile.readText())
    }

    @Test
    fun applyProfile_refuses_drive_snapshot_with_invalid_tuning() {
        val bad =
            """
            {
              "active": "bad",
              "profiles": [{"name": "bad", "config": {
                "mode": "drive",
                "drive": {
                  "oauth_client_id": "CID.apps.googleusercontent.com",
                  "oauth_client_secret": "SECRET",
                  "folder_id": "FOLDER_ID",
                  "relay_pubkey": "$validRelayPubkey",
                  "oauth_refresh_token": "1//04xxxx",
                  "poll_interval_ms": 0
                }
              }}]
            }
            """.trimIndent()
        profilesFile.writeText(bad)
        ConfigStore.save(ctx, RahgozarConfig(authKey = "preserve-me"))
        val before = configFile.readText()

        val r = ProfileStore.applyProfile(ctx, "bad")
        assertTrue(
            "expected Failed for poll_interval_ms=0, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Failed,
        )
        assertEquals(before, configFile.readText())
    }

    @Test
    fun configSave_clears_refresh_token_when_oauth_client_changes() {
        ConfigStore.save(
            ctx,
            RahgozarConfig(
                mode = Mode.DRIVE,
                driveOauthClientId = "OLD.apps.googleusercontent.com",
                driveOauthClientSecret = "OLDSECRET",
                driveFolderId = "FOLDER_ID",
                driveRelayPubkey = validRelayPubkey,
                driveOauthRefreshTokenSnapshot = "1//04old-token",
            ),
        )
        val loaded = ConfigStore.load(ctx)
        assertTrue(loaded.driveHasRefreshToken)

        assertTrue(
            ConfigStore.save(
                ctx,
                loaded.copy(driveOauthClientId = "NEW.apps.googleusercontent.com"),
            ),
        )

        val drive = JSONObject(configFile.readText()).getJSONObject("drive")
        assertTrue(
            "refresh token must be cleared when OAuth client_id changes",
            !drive.has("oauth_refresh_token") || drive.optString("oauth_refresh_token").isBlank(),
        )

        assertTrue(
            ConfigStore.save(
                ctx,
                loaded.copy(
                    driveOauthClientId = "NEW.apps.googleusercontent.com",
                    driveFolderId = "FOLDER_ID_2",
                ),
            ),
        )
        val afterSecondSave = JSONObject(configFile.readText()).getJSONObject("drive")
        assertTrue(
            "stale in-memory snapshots must not resurrect a cleared refresh token",
            !afterSecondSave.has("oauth_refresh_token") ||
                afterSecondSave.optString("oauth_refresh_token").isBlank(),
        )
    }

    @Test
    fun applyProfile_missing_returns_NotFound_without_side_effects() {
        ConfigStore.save(ctx, RahgozarConfig(authKey = "preserve-me"))
        val before = configFile.readText()
        val applied = ProfileStore.applyProfile(ctx, "does-not-exist")
        assertTrue(applied is ProfileStore.ApplyResult.NotFound)
        assertEquals(before, configFile.readText())
    }

    @Test
    fun unique_copy_name_increments_on_collision() {
        ProfileStore.upsert(ctx, "p", RahgozarConfig(appsScriptUrls = depEntries("A"), authKey = "k"))
        ProfileStore.duplicate(ctx, "p", "p (copy)")
        val state = ProfileStore.load(ctx)
        val unique = ProfileStore.uniqueCopyName(state, "p")
        assertNotEquals("p (copy)", unique)
        assertEquals("p (copy 2)", unique)
    }

    // ---- Injected write-failure tests ----
    //
    // Trick: make a file path a *directory* on disk before the call.
    // The atomic-replace step (NIO Files.move or File.renameTo)
    // then fails because we can't overwrite a directory with a
    // file. This is portable across the Robolectric backing FS and
    // doesn't require mocking.

    /**
     * Step 1 (config.json) fails → upsert returns SaveFailed and
     * neither file is modified. Specifically guards against the
     * old order (profiles.json first), where an overwrite would
     * clobber an existing profile's snapshot before discovering
     * the live-config write would fail.
     */
    @Test
    fun upsert_config_write_failure_leaves_profiles_unchanged() {
        ProfileStore.upsert(
            ctx,
            "home",
            RahgozarConfig(appsScriptUrls = depEntries("OLD"), authKey = "old"),
        )
        val profilesBefore = profilesFile.readText()

        // Block config.json write by making the path a directory.
        // atomicReplace refuses to overwrite a directory target,
        // so the save fails — exactly what we want to test.
        configFile.delete()
        configFile.mkdirs()
        File(configFile, "sentinel").writeText("x")

        try {
            val r =
                ProfileStore.upsert(
                    ctx,
                    "home",
                    RahgozarConfig(appsScriptUrls = depEntries("NEW"), authKey = "new"),
                )
            assertEquals(ProfileStore.MutationResult.SaveFailed, r)
            // profiles.json must be UNCHANGED — the bug guard.
            assertEquals(profilesBefore, profilesFile.readText())
        } finally {
            // Even if an assertion fires, leave a clean filesystem
            // for the next test. clearAll() in tearDown is recursive
            // but cheap insurance never hurts.
            deleteRecursively(configFile)
        }
    }

    /**
     * Step 2 (profiles.json) fails AFTER step 1 succeeded → returns
     * PartialConfigOnly. config.json is the new bytes, profiles.json
     * is unchanged.
     */
    @Test
    fun upsert_profiles_write_failure_returns_partial_config_only() {
        ProfileStore.upsert(
            ctx,
            "home",
            RahgozarConfig(appsScriptUrls = depEntries("OLD"), authKey = "old"),
        )
        val profilesBefore = profilesFile.readText()

        // Block profiles.json write by making profiles.json.tmp
        // a directory. The tmp.writeText() call inside save() then
        // throws (can't write a regular file at a directory path).
        val tmp = File(ctx.filesDir, "profiles.json.tmp")
        tmp.delete()
        tmp.mkdirs()
        File(tmp, "sentinel").writeText("x")

        try {
            val r =
                ProfileStore.upsert(
                    ctx,
                    "home",
                    RahgozarConfig(appsScriptUrls = depEntries("NEW"), authKey = "new"),
                )
            assertEquals(ProfileStore.MutationResult.PartialConfigOnly, r)

            // config.json IS the new bytes — equivalent to a regular Save.
            val onDisk = JSONObject(configFile.readText())
            assertEquals("new", onDisk.optString("auth_key"))

            // profiles.json is byte-identical to before the call —
            // profile "home" still has its OLD snapshot.
            assertEquals(profilesBefore, profilesFile.readText())
        } finally {
            deleteRecursively(tmp)
        }
    }

    /**
     * Same injected failure on applyProfile (switch path): step 2
     * fails AFTER step 1 succeeds → ApplyResult.PartialConfigOnly,
     * config.json updated, profiles.json unchanged.
     */
    @Test
    fun applyProfile_profiles_write_failure_returns_partial() {
        // Snapshots must pass `validateRuntimeShape` — apps_script
        // mode (the default) requires a deployment ID + auth_key,
        // otherwise applyProfile short-circuits with Failed before
        // ever reaching the step-1 write we're trying to verify here.
        ProfileStore.upsert(
            ctx,
            "home",
            RahgozarConfig(appsScriptUrls = depEntries("HOME_ID"), authKey = "homekey"),
        )
        ProfileStore.upsert(
            ctx,
            "other",
            RahgozarConfig(appsScriptUrls = depEntries("OTHER_ID"), authKey = "otherkey"),
        )
        val profilesBefore = profilesFile.readText()
        assertEquals("other", ProfileStore.load(ctx).active)

        val tmp = File(ctx.filesDir, "profiles.json.tmp")
        tmp.delete()
        tmp.mkdirs()
        File(tmp, "sentinel").writeText("x")

        try {
            val r = ProfileStore.applyProfile(ctx, "home")
            assertTrue(
                "expected PartialConfigOnly, got ${r::class.simpleName}",
                r is ProfileStore.ApplyResult.PartialConfigOnly,
            )

            val onDisk = JSONObject(configFile.readText())
            assertEquals("homekey", onDisk.optString("auth_key"))

            assertEquals(profilesBefore, profilesFile.readText())
        } finally {
            deleteRecursively(tmp)
        }
    }
}
