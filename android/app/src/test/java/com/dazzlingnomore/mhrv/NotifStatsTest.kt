package com.dazzlingnomore.mhrv

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/**
 * Unit tests for the notification stats parser + byte formatter.
 *
 * These two functions are pulled out as top-level `internal` helpers
 * specifically so the JVM unit-test suite can exercise them without
 * spinning up the service. The rest of RahgozarVpnService is Android-only
 * (Notification, Handler, JNI) and would require Robolectric or
 * instrumentation tests.
 *
 * What we care about here:
 *   - empty / blank / null JSON → null (caller falls back to ports line)
 *   - malformed JSON → null
 *   - missing `today_calls` → null (the documented signal for non-relay
 *     modes from Native.statsJson)
 *   - valid blob → populated NotifStatsView
 *   - zero counters are NOT confused with "missing" — a fresh-boot
 *     `today_calls=0` should still render as a real stats line.
 */
class NotifStatsTest {
    @Test
    fun parseNotifStats_blankAndNull_returnNull() {
        assertNull(parseNotifStats(null))
        assertNull(parseNotifStats(""))
        assertNull(parseNotifStats("   \t\n"))
    }

    @Test
    fun parseNotifStats_malformedJson_returnsNull() {
        assertNull(parseNotifStats("not json"))
        assertNull(parseNotifStats("{"))
        // Valid JSON but not an object (parser would throw)
        assertNull(parseNotifStats("[1,2,3]"))
    }

    @Test
    fun parseNotifStats_missingTodayCalls_returnsNull() {
        // A handle from a direct / full-only mode emits an empty string
        // per Native.statsJson docs, but a defensive caller might also
        // see "{}" or partial blobs. Either way, no today_calls → null.
        assertNull(parseNotifStats("{}"))
        assertNull(parseNotifStats("""{"today_bytes": 100, "today_reset_secs": 3600}"""))
    }

    @Test
    fun parseNotifStats_validBlob_populatesAllFields() {
        val json =
            """
            {
              "today_calls": 1234,
              "today_bytes": 5678901,
              "today_key": "2026-05-17",
              "today_reset_secs": 19800,
              "relay_calls": 5000
            }
            """.trimIndent()
        val stats = parseNotifStats(json)
        assertTrue("expected non-null parse", stats != null)
        assertEquals(1234L, stats!!.todayCalls)
        assertEquals(5678901L, stats.todayBytes)
        assertEquals(19800L, stats.resetSecs)
    }

    @Test
    fun parseNotifStats_zeroCounters_treatedAsValid() {
        // Fresh service start: today_calls is 0 but the field IS present —
        // this is meaningfully different from "stats unavailable" and the
        // notification should render "0 calls today" rather than falling
        // back to the ports line.
        val stats = parseNotifStats("""{"today_calls": 0, "today_bytes": 0, "today_reset_secs": 0}""")
        assertTrue(stats != null)
        assertEquals(0L, stats!!.todayCalls)
        assertEquals(0L, stats.todayBytes)
        assertEquals(0L, stats.resetSecs)
    }

    @Test
    fun parseNotifStats_missingOptionalFields_defaultToZero() {
        // today_calls present but today_bytes / today_reset_secs absent —
        // they default to 0 rather than disqualifying the whole parse.
        val stats = parseNotifStats("""{"today_calls": 42}""")
        assertTrue(stats != null)
        assertEquals(42L, stats!!.todayCalls)
        assertEquals(0L, stats.todayBytes)
        assertEquals(0L, stats.resetSecs)
    }

    @Test
    fun formatNotifBytes_acrossUnits() {
        // Small (B)
        assertEquals("0 B", formatNotifBytes(0L))
        assertEquals("1023 B", formatNotifBytes(1023L))
        // KB
        assertEquals("1.0 KB", formatNotifBytes(1024L))
        assertEquals("1.5 KB", formatNotifBytes(1536L))
        // MB (one decimal for compactness)
        assertEquals("1.0 MB", formatNotifBytes(1024L * 1024))
        // GB
        assertEquals("1.00 GB", formatNotifBytes(1024L * 1024 * 1024))
    }

    /**
     * Pins the decimal separator to "." across device locales. A
     * German-locale device used to render "1,5 KB" via default-locale
     * String.format, which looks inconsistent next to the English
     * "KB"/"MB"/"GB" unit suffix. Locale.US in the formatter keeps the
     * whole string consistently English-formatted.
     */
    @Test
    fun formatNotifBytes_usesUSDecimalSeparator_regardlessOfDefaultLocale() {
        val saved = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("de-DE"))
            assertEquals("1.5 KB", formatNotifBytes(1536L))
            Locale.setDefault(Locale.forLanguageTag("fa-IR"))
            assertEquals("1.5 KB", formatNotifBytes(1536L))
        } finally {
            Locale.setDefault(saved)
        }
    }
}
