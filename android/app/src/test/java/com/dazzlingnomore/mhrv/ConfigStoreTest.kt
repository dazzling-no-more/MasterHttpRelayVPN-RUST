package com.dazzlingnomore.mhrv

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the [ConfigStore.toJson] / [ConfigStore.loadFromJson]
 * round trip, with a focus on `fronting_groups` — which the Android UI
 * silently dropped on Save before this round of work. These tests exist
 * specifically to catch regressions of that data-loss path.
 *
 * The encode/decode (Base64 + DEFLATE) wrapper around the same JSON is
 * not tested here because `android.util.Base64` is stubbed in JVM unit
 * tests; the JSON payload it wraps is the same code path covered below.
 */
class ConfigStoreTest {
    private val validRelayPubkey =
        "rgdr1jxtcw0wklzug0kxfsegwh2cc4kt6y50a5ac7vwmlln0emd30sq4sd7x0sx"

    private val sampleGroups =
        listOf(
            FrontingGroup(
                name = "github-direct",
                ip = "140.82.121.4",
                sni = "github.com",
                domains = listOf("gist.github.com"),
            ),
            FrontingGroup(
                name = "vercel",
                ip = "76.76.21.21",
                sni = "react.dev",
                domains = listOf("vercel.com", "vercel.app", "nextjs.org"),
            ),
        )

    @Test
    fun frontingGroups_roundTripsThroughJson() {
        val cfg =
            RahgozarConfig(
                mode = Mode.DIRECT,
                frontingGroups = sampleGroups,
            )

        val json = cfg.toJson()
        val parsed = ConfigStore.loadFromJson(JSONObject(json))

        assertEquals(
            "fronting_groups must round-trip exactly — order, fields, and all",
            sampleGroups,
            parsed.frontingGroups,
        )
    }

    @Test
    fun frontingGroups_emptyListProducesNoKey() {
        val cfg = RahgozarConfig(frontingGroups = emptyList())
        val json = JSONObject(cfg.toJson())
        // Skipping the key when empty matches the pattern used for the
        // other optional list fields (passthrough_hosts, sni_hosts) and
        // keeps the saved file tidy for users who don't use the feature.
        assertTrue(
            "fronting_groups should be omitted when the list is empty",
            !json.has("fronting_groups"),
        )
    }

    @Test
    fun frontingGroups_loadIgnoresMalformedEntries() {
        // Half-empty entries (missing ip / sni / domains) used to leak
        // through if the user hand-edited config.json. The Rust validator
        // would reject them at startup; the Kotlin loader skips them on
        // read so the UI never sees broken state.
        val raw =
            """
            {
              "mode": "direct",
              "fronting_groups": [
                {"name": "ok", "ip": "1.2.3.4", "sni": "example.com",
                 "domains": ["example.com"]},
                {"name": "no-ip", "ip": "", "sni": "x.com",
                 "domains": ["x.com"]},
                {"name": "no-domains", "ip": "1.2.3.4", "sni": "x.com",
                 "domains": []},
                {"name": "missing-fields"}
              ]
            }
            """.trimIndent()

        val parsed = ConfigStore.loadFromJson(JSONObject(raw))

        assertEquals(1, parsed.frontingGroups.size)
        assertEquals("ok", parsed.frontingGroups[0].name)
    }

    // ---- Drive-mode encode/decode (regression guard for the
    //      missing-drive-subobject bug in encode()) -------------------

    @Test
    fun driveConfig_roundTripsThroughToJson() {
        // Every modelled Drive field survives a toJson → loadFromJson
        // round-trip. The bug fixed in this slice was that toJson
        // emitted `mode=drive` but no `drive` block, so a shared
        // QR-encoded Drive config decoded to an unusable
        // half-populated state.
        val cfg =
            RahgozarConfig(
                mode = Mode.DRIVE,
                driveOauthClientId = "1234-cid.apps.googleusercontent.com",
                driveOauthClientSecret = "GOCSPX-test-secret",
                driveFolderId = "0AABBccDDeeFFgg",
                driveRelayPubkey = "rgdr1qqqq",
                drivePollIntervalMs = 500,
                driveMaxConcurrentUploads = 4,
                driveOauthRefreshTokenSnapshot = "1//04test-refresh-token",
            )

        val parsed = ConfigStore.loadFromJson(JSONObject(cfg.toJson()))

        assertEquals(Mode.DRIVE, parsed.mode)
        assertEquals(cfg.driveOauthClientId, parsed.driveOauthClientId)
        assertEquals(cfg.driveOauthClientSecret, parsed.driveOauthClientSecret)
        assertEquals(cfg.driveFolderId, parsed.driveFolderId)
        assertEquals(cfg.driveRelayPubkey, parsed.driveRelayPubkey)
        assertEquals(cfg.drivePollIntervalMs, parsed.drivePollIntervalMs)
        assertEquals(cfg.driveMaxConcurrentUploads, parsed.driveMaxConcurrentUploads)
        assertEquals(cfg.driveOauthRefreshTokenSnapshot, parsed.driveOauthRefreshTokenSnapshot)
        assertTrue("snapshot non-empty → driveHasRefreshToken", parsed.driveHasRefreshToken)
    }

    @Test
    fun driveConfig_encodeProducesDriveSubobject() {
        // QR-share path (ConfigStore.encode → decode) was the second
        // half of the same bug: encode() built a JSON for the share
        // payload that included `mode=drive` but no `drive` block.
        // Verify the share-side path emits the non-secret drive
        // subobject too by inspecting the JSON shape encode() builds
        // before compression.
        val cfg =
            RahgozarConfig(
                mode = Mode.DRIVE,
                driveOauthClientId = "CID",
                driveOauthClientSecret = "SECRET",
                driveFolderId = "FOLDER",
                driveRelayPubkey = "rgdr1...",
                driveOauthRefreshTokenSnapshot = "1//04test-refresh-token",
            )
        val json = ConfigStore.toShareJson(cfg)
        assertTrue("share JSON must emit a `drive` block in DRIVE mode", json.has("drive"))
        val drive = json.getJSONObject("drive")
        assertEquals("CID", drive.optString("oauth_client_id"))
        assertEquals("FOLDER", drive.optString("folder_id"))
        assertEquals("rgdr1...", drive.optString("relay_pubkey"))
        assertTrue("share JSON must not export OAuth client_secret", !drive.has("oauth_client_secret"))
        assertTrue("share JSON must not export OAuth refresh_token", !drive.has("oauth_refresh_token"))
    }

    @Test
    fun driveModeStartGateRequiresValidRelayPubkey() {
        val base =
            RahgozarConfig(
                mode = Mode.DRIVE,
                driveOauthClientId = "CID",
                driveOauthClientSecret = "SECRET",
                driveHasRefreshToken = true,
                driveFolderId = "FOLDER",
            )

        assertTrue(
            "invalid relay pubkey should block Drive start",
            !base.copy(driveRelayPubkey = "rgdr1qqqq").canStartCurrentMode,
        )
        assertTrue(
            "valid Drive setup should allow start",
            base.copy(driveRelayPubkey = validRelayPubkey).canStartCurrentMode,
        )
    }

    @Test
    fun driveRelayPubkeyValidatorRejectsLowOrderIdentity() {
        val zeroPubkey =
            "rgdr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlnncl2"

        assertEquals(
            "relay pubkey is a low-order X25519 point",
            validateDriveRelayPubkey(zeroPubkey),
        )
    }

    @Test
    fun driveModeStartGateRejectsInvalidTuningKnobs() {
        val base =
            RahgozarConfig(
                mode = Mode.DRIVE,
                driveOauthClientId = "CID",
                driveOauthClientSecret = "SECRET",
                driveHasRefreshToken = true,
                driveFolderId = "FOLDER",
                driveRelayPubkey = validRelayPubkey,
            )

        assertTrue(
            "poll_interval_ms=0 would be rejected by Rust config validation",
            !base.copy(drivePollIntervalMs = 0).canStartCurrentMode,
        )
        assertTrue(
            "max_concurrent_uploads=0 would be rejected by Rust config validation",
            !base.copy(driveMaxConcurrentUploads = 0).canStartCurrentMode,
        )
        assertTrue(
            "positive tuning knobs should allow an otherwise valid Drive config",
            base.canStartCurrentMode,
        )
    }

    @Test
    fun frontingGroups_unknownConfigKeysIgnored() {
        // Curated.json carries a `_comment` array that JSONObject would
        // happily round-trip if the loader weren't selective. This test
        // pins that the loader only reads fields it knows about — same
        // defense the Rust serde layer gives us automatically.
        val raw =
            """
            {
              "mode": "direct",
              "_comment": ["a", "b"],
              "fronting_groups": [
                {"name": "g", "ip": "1.2.3.4", "sni": "s.example",
                 "domains": ["d.example"]}
              ]
            }
            """.trimIndent()

        val parsed = ConfigStore.loadFromJson(JSONObject(raw))

        assertEquals(1, parsed.frontingGroups.size)
        assertEquals(Mode.DIRECT, parsed.mode)
    }
}
