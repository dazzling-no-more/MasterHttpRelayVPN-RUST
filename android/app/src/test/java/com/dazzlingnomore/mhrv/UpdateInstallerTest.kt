package com.dazzlingnomore.mhrv

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Coverage for the singleton state machine that drives the version-button
 * badge and the in-flight install guard. The Compose-side `offerInstall`
 * itself needs an Activity to exercise (snackbars, FileProvider), so it
 * isn't tested here — but its preconditions (acquire-once semantics) and
 * its hand-off to the badge state ARE asserted, which is where the bugs
 * showed up in review.
 *
 * `UpdateInstaller` is an `object` so the state survives across tests in
 * the same JVM. `@Before`/`@After` reset both flows so test ordering
 * doesn't bleed.
 */
class UpdateInstallerTest {
    private fun sampleAvailable(latest: String = "2.0.5"): UpdateInstaller.State.Available =
        UpdateInstaller.State.Available(
            current = "2.0.3",
            latest = latest,
            releaseUrl = "https://example.invalid/release",
            asset =
                UpdateInstaller.ApkAsset(
                    name = "rahgozar-android-arm64-v8a.apk",
                    url = "https://example.invalid/rahgozar-android-arm64-v8a.apk",
                    sizeBytes = 12_345_678L,
                ),
        )

    @Before
    fun reset() {
        UpdateInstaller.clearPendingUpdate()
        UpdateInstaller.releaseOffer()
    }

    @After
    fun tearDown() {
        UpdateInstaller.clearPendingUpdate()
        UpdateInstaller.releaseOffer()
    }

    @Test
    fun pendingUpdate_startsNull() {
        assertNull(UpdateInstaller.pendingUpdate.value)
    }

    @Test
    fun markPendingUpdate_setsFlowValue() {
        val state = sampleAvailable()
        UpdateInstaller.markPendingUpdate(state)
        assertSame(state, UpdateInstaller.pendingUpdate.value)
    }

    @Test
    fun markPendingUpdate_overwritesPriorValue() {
        UpdateInstaller.markPendingUpdate(sampleAvailable("2.0.4"))
        val newer = sampleAvailable("2.0.5")
        UpdateInstaller.markPendingUpdate(newer)
        assertSame(newer, UpdateInstaller.pendingUpdate.value)
    }

    @Test
    fun clearPendingUpdate_resetsFlowValue() {
        UpdateInstaller.markPendingUpdate(sampleAvailable())
        assertNotNull(UpdateInstaller.pendingUpdate.value)
        UpdateInstaller.clearPendingUpdate()
        assertNull(UpdateInstaller.pendingUpdate.value)
    }

    @Test
    fun tryAcquireOffer_firstCallerWins() {
        assertTrue(UpdateInstaller.tryAcquireOffer())
        assertTrue(UpdateInstaller.offerInFlight.value)
    }

    @Test
    fun tryAcquireOffer_secondCallerLosesUntilReleased() {
        assertTrue("first acquire should win", UpdateInstaller.tryAcquireOffer())
        // This is the duplicate-tap scenario flagged in review: a second
        // offerInstall call while the first is still alive must not be
        // able to start its own download/install flow.
        assertFalse("second acquire must fail while first is in flight", UpdateInstaller.tryAcquireOffer())
        assertFalse(
            "third acquire must also fail",
            UpdateInstaller.tryAcquireOffer(),
        )
        UpdateInstaller.releaseOffer()
        assertFalse(UpdateInstaller.offerInFlight.value)
        assertTrue("acquire must succeed again once released", UpdateInstaller.tryAcquireOffer())
    }

    @Test
    fun releaseOffer_isIdempotent() {
        UpdateInstaller.releaseOffer()
        UpdateInstaller.releaseOffer()
        assertFalse(UpdateInstaller.offerInFlight.value)
        assertTrue(UpdateInstaller.tryAcquireOffer())
    }

    @Test
    fun parseCheckResult_upToDate_doesNotTouchPendingState() {
        // Lifecycle invariant: only the caller (HomeScreen's
        // LaunchedEffect) mutates pendingUpdate, not the parser. Pin
        // that so a future refactor doesn't smuggle a side effect in.
        UpdateInstaller.markPendingUpdate(sampleAvailable())
        val before = UpdateInstaller.pendingUpdate.value
        val parsed = UpdateInstaller.parseCheckResult("""{"kind":"upToDate"}""")
        assertEquals(UpdateInstaller.State.UpToDate, parsed)
        assertSame(before, UpdateInstaller.pendingUpdate.value)
    }

    @Test
    fun parseCheckResult_available_returnsStateButLeavesFlowsAlone() {
        // Same invariant: parsing returns the state, but plumbing it into
        // the badge state is HomeScreen's responsibility.
        val parsed =
            UpdateInstaller.parseCheckResult(
                """
                {
                  "kind": "updateAvailable",
                  "current": "2.0.3",
                  "latest": "2.0.5",
                  "url": "https://example.invalid/r",
                  "assetUrl": "https://example.invalid/a.apk",
                  "assetName": "a.apk",
                  "assetSize": 42
                }
                """.trimIndent(),
            )
        assertTrue(parsed is UpdateInstaller.State.Available)
        assertNull(UpdateInstaller.pendingUpdate.value)
        assertFalse(UpdateInstaller.offerInFlight.value)
    }
}
