package com.dazzlingnomore.mhrv

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.math.BigInteger

/*
 * Config I/O. The source of truth is a JSON file in the app's files dir —
 * the Rust side parses the same file, so we don't maintain two schemas.
 *
 * What the Android UI exposes is a pragmatic subset of the full rahgozar
 * config, but we now track parity with the desktop UI on the dimensions
 * that actually matter on a phone:
 *   - multiple deployment IDs (round-robin)
 *   - an SNI rotation pool
 *   - log level / verify_ssl / parallel_relay knobs
 * Anything else gets phone-appropriate defaults.
 */

/**
 * How the foreground service exposes the proxy to the rest of the device.
 *
 * - [VPN_TUN] — the default; `VpnService` claims a TUN interface and every
 *   app's traffic goes through `tun2proxy` → our SOCKS5 → Apps Script.
 *   Requires the user to accept the system "VPN connection request"
 *   dialog on first Start.
 *
 * - [PROXY_ONLY] — just runs the HTTP (`127.0.0.1:8080`) and SOCKS5
 *   (`127.0.0.1:1081`) listeners; no VpnService, no TUN. The user sets
 *   their Wi-Fi proxy (or a per-app proxy setting) to those addresses.
 *   Useful when the device already has another VPN up, or the user
 *   specifically wants per-app opt-in, or on rooted/specialized devices
 *   where VpnService is unwelcome. Closes issue #37.
 */
enum class ConnectionMode { VPN_TUN, PROXY_ONLY }

/**
 * App-splitting policy when in VPN_TUN mode.
 *
 * - [ALL]  — tunnel every app (default; the package list is ignored).
 * - [ONLY] — allow-list: tunnel ONLY the apps in `splitApps`. Everything
 *   else bypasses the VPN. Useful when you want rahgozar for a specific
 *   browser / messenger and nothing else.
 * - [EXCEPT] — deny-list: tunnel everything EXCEPT the apps in
 *   `splitApps`. Useful for excluding a banking app that would break
 *   under MITM anyway, or a self-updater you don't want going through
 *   the quota-limited relay.
 *
 * Our own package (`packageName`) is always excluded regardless of mode
 * — that's the loop-avoidance rule from day one, not a user toggle.
 */
enum class SplitMode { ALL, ONLY, EXCEPT }

/**
 * UI language preference. AUTO respects the device locale; FA / EN
 * force the app into Persian / English with proper RTL / LTR layout
 * on next app launch (AppCompatDelegate.setApplicationLocales is
 * applied at Application.onCreate).
 */
enum class UiLang { AUTO, FA, EN }

/**
 * Operating mode. Mirrors the Rust-side `Mode` enum.
 *
 * - [APPS_SCRIPT] (default) — full DPI bypass through the user's deployed
 *   Apps Script relay. Requires a Deployment ID + Auth key.
 * - [DIRECT] — no Apps Script relay. Only the SNI-rewrite tunnel is
 *   active: Google edge by default, plus any user-configured
 *   `fronting_groups` (Vercel, Fastly, …). Useful as a bootstrap to
 *   reach `script.google.com` and deploy Code.gs, or as a standalone
 *   mode for users who only need fronting-group targets. No Deployment
 *   ID / Auth key needed. Non-matching traffic goes raw (no relay).
 *   Was named `GOOGLE_ONLY` before fronting_groups was added — the
 *   string `"google_only"` is still accepted on parse for back-compat.
 * - [FULL] — full tunnel mode. ALL traffic is tunneled end-to-end through
 *   Apps Script + a remote tunnel node. No certificate installation needed.
 * - [LOCAL_BYPASS] — local-only DPI bypass. Every TLS CONNECT (from any
 *   app, courtesy of the VpnService TUN) gets its real ClientHello split
 *   across TCP segments and sent directly to the real destination IP.
 *   No Apps Script, no VPS, no MITM CA. Defeats DPI only — IP-blocked
 *   destinations remain unreachable (so this won't help with sites Iran
 *   blocks at the IP level like claude.ai / x.ai; use Apps Script or
 *   Full for those).
 */
enum class Mode {
    APPS_SCRIPT,
    DIRECT,
    FULL,
    LOCAL_BYPASS,

    /**
     * Drive-mailbox transport. Every TCP session
     * is sealed and uploaded as files to a shared Google Drive
     * folder; a separate `rahgozar-drive-relay` binary on a VPS
     * abroad polls the folder, dials the destination, and writes
     * response frames back. The ISP only sees TLS to *.google.com.
     * Requires OAuth refresh token + Drive folder ID + relay
     * public key in the `drive` sub-object.
     */
    DRIVE,
    ;

    /**
     * True iff this mode talks to the user's Apps Script deployment
     * and therefore needs a deployment ID + auth_key. Mirrors the
     * Rust-side [`Mode::uses_apps_script_relay`](../../../../../../src/config.rs).
     * Single source of truth — UI gates, profile-shape validators,
     * and the service-side credential check all defer here rather
     * than open-coding the `APPS_SCRIPT || FULL` match, which is
     * the kind of allowlist that silently drifts when a new mode
     * lands.
     */
    fun usesAppsScriptRelay(): Boolean = this == APPS_SCRIPT || this == FULL

    /**
     * True iff this mode terminates inbound TLS with rahgozar's local
     * MITM CA. Mirrors Rust-side `Mode::uses_mitm_ca`.
     */
    fun usesMitmCa(): Boolean = this == APPS_SCRIPT || this == DIRECT

    /**
     * True iff this mode uses the Drive-mailbox transport. The UI
     * shows the Drive setup section only when this is true; the
     * service-side credential check requires `drive.oauth_refresh_token`
     * + `drive.folder_id` + `drive.relay_pubkey` before allowing
     * Start.
     */
    fun usesDriveRelay(): Boolean = this == DRIVE
}

internal fun validateDriveRelayPubkey(value: String): String? {
    val s = value.trim()
    if (s.isEmpty()) return "relay pubkey is empty"
    if (s.any { it.code < 33 || it.code > 126 }) {
        return "relay pubkey contains invalid bech32 characters"
    }
    val lower = s.lowercase()
    if (s != lower && s != s.uppercase()) {
        return "relay pubkey mixes uppercase and lowercase"
    }
    val sep = lower.lastIndexOf('1')
    if (sep <= 0 || sep + 7 > lower.length) {
        return "relay pubkey is not valid bech32m"
    }
    val hrp = lower.substring(0, sep)
    if (hrp != "rgdr") {
        return "relay pubkey has HRP '$hrp' but expected 'rgdr'"
    }
    val dataPart = lower.substring(sep + 1)
    val values = ArrayList<Int>(dataPart.length)
    for (ch in dataPart) {
        val idx = DRIVE_RELAY_BECH32_CHARSET.indexOf(ch)
        if (idx < 0) return "relay pubkey is not valid bech32m"
        values.add(idx)
    }
    if (!driveRelayBech32mChecksumValid(hrp, values)) {
        return "relay pubkey checksum is invalid"
    }
    val payload =
        driveRelayConvertBits(values.dropLast(6), fromBits = 5, toBits = 8, pad = false)
            ?: return "relay pubkey payload has invalid padding"
    if (payload.size != 32) {
        return "relay pubkey decodes to ${payload.size} bytes but X25519 keys are exactly 32 bytes"
    }
    if (!driveRelayX25519ProbeIsContributory(payload)) {
        return "relay pubkey is a low-order X25519 point"
    }
    return null
}

private const val DRIVE_RELAY_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
private val DRIVE_X25519_P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
private val DRIVE_X25519_A24 = BigInteger.valueOf(121665)
private val DRIVE_X25519_PROBE_SCALAR = ByteArray(32) { 0x42.toByte() }

private fun driveRelayBech32mChecksumValid(
    hrp: String,
    values: List<Int>,
): Boolean {
    val expanded = ArrayList<Int>(hrp.length * 2 + values.size + 1)
    for (ch in hrp) expanded.add(ch.code shr 5)
    expanded.add(0)
    for (ch in hrp) expanded.add(ch.code and 31)
    expanded.addAll(values)
    val polymod = driveRelayBech32Polymod(expanded)
    return polymod == 0x2bc830a3
}

private fun driveRelayBech32Polymod(values: List<Int>): Int {
    val generators = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    var chk = 1
    for (v in values) {
        val top = chk ushr 25
        chk = (chk and 0x1ffffff) shl 5 xor v
        for (i in 0 until 5) {
            if (((top ushr i) and 1) != 0) chk = chk xor generators[i]
        }
    }
    return chk
}

private fun driveRelayConvertBits(
    data: List<Int>,
    fromBits: Int,
    toBits: Int,
    pad: Boolean,
): List<Int>? {
    var acc = 0
    var bits = 0
    val maxv = (1 shl toBits) - 1
    val maxAcc = (1 shl (fromBits + toBits - 1)) - 1
    val out = ArrayList<Int>()
    for (value in data) {
        if (value < 0 || (value ushr fromBits) != 0) return null
        acc = ((acc shl fromBits) or value) and maxAcc
        bits += fromBits
        while (bits >= toBits) {
            bits -= toBits
            out.add((acc ushr bits) and maxv)
        }
    }
    if (pad) {
        if (bits > 0) out.add((acc shl (toBits - bits)) and maxv)
    } else if (bits >= fromBits || ((acc shl (toBits - bits)) and maxv) != 0) {
        return null
    }
    return out
}

private fun driveRelayX25519ProbeIsContributory(payload: List<Int>): Boolean {
    if (payload.size != 32) return false
    val publicKey = ByteArray(32) { i -> payload[i].toByte() }
    val shared = driveRelayX25519(DRIVE_X25519_PROBE_SCALAR, publicKey)
    return shared.any { it.toInt() != 0 }
}

private fun driveRelayX25519(
    scalarInput: ByteArray,
    publicKeyInput: ByteArray,
): ByteArray {
    val scalar = scalarInput.copyOf(32)
    scalar[0] = (scalar[0].toInt() and 248).toByte()
    scalar[31] = ((scalar[31].toInt() and 127) or 64).toByte()

    val publicKey = publicKeyInput.copyOf(32)
    publicKey[31] = (publicKey[31].toInt() and 127).toByte()
    val x1 = driveRelayLittleEndianToBigInteger(publicKey)

    var x2 = BigInteger.ONE
    var z2 = BigInteger.ZERO
    var x3 = x1
    var z3 = BigInteger.ONE
    var swap = 0

    for (t in 254 downTo 0) {
        val kt = driveRelayScalarBit(scalar, t)
        if ((swap xor kt) != 0) {
            val tx = x2
            x2 = x3
            x3 = tx
            val tz = z2
            z2 = z3
            z3 = tz
        }
        swap = kt

        val a = driveRelayMod(x2 + z2)
        val aa = driveRelaySquare(a)
        val b = driveRelayMod(x2 - z2)
        val bb = driveRelaySquare(b)
        val e = driveRelayMod(aa - bb)
        val c = driveRelayMod(x3 + z3)
        val d = driveRelayMod(x3 - z3)
        val da = driveRelayMod(d * a)
        val cb = driveRelayMod(c * b)
        x3 = driveRelaySquare(da + cb)
        z3 = driveRelayMod(x1 * driveRelaySquare(da - cb))
        x2 = driveRelayMod(aa * bb)
        z2 = driveRelayMod(e * driveRelayMod(aa + DRIVE_X25519_A24 * e))
    }

    if (swap != 0) {
        val tx = x2
        x2 = x3
        x3 = tx
        val tz = z2
        z2 = z3
        z3 = tz
    }

    val result =
        if (z2 == BigInteger.ZERO) {
            BigInteger.ZERO
        } else {
            driveRelayMod(x2 * z2.modInverse(DRIVE_X25519_P))
        }
    return driveRelayBigIntegerToLittleEndian(result)
}

private fun driveRelayScalarBit(
    scalar: ByteArray,
    bit: Int,
): Int {
    val byte = scalar[bit / 8].toInt() and 0xff
    return (byte ushr (bit % 8)) and 1
}

private fun driveRelayMod(v: BigInteger): BigInteger = v.mod(DRIVE_X25519_P)

private fun driveRelaySquare(v: BigInteger): BigInteger = driveRelayMod(v * v)

private fun driveRelayLittleEndianToBigInteger(bytes: ByteArray): BigInteger {
    val be = ByteArray(bytes.size)
    for (i in bytes.indices) {
        be[bytes.size - 1 - i] = bytes[i]
    }
    return BigInteger(1, be)
}

private fun driveRelayBigIntegerToLittleEndian(v: BigInteger): ByteArray {
    val be = v.toByteArray()
    val out = ByteArray(32)
    for (i in out.indices) {
        val src = be.size - 1 - i
        out[i] = if (src >= 0) be[src] else 0
    }
    return out
}

/**
 * One multi-edge fronting group. Mirrors the Rust-side `FrontingGroup`
 * in [`src/config.rs`](../../../../../../src/config.rs).
 *
 * Tells the proxy: when a CONNECT to one of [domains] arrives, dial
 * [ip]:443, send the TLS handshake with `SNI=`[sni], then forward the
 * inner HTTP `Host` to that edge. Picking a benign edge-hosted [sni]
 * lets DPI see only that hostname while the real target stays inside
 * the encrypted tunnel.
 */
data class FrontingGroup(
    /** Human-readable label used in log lines. Free-form. */
    val name: String,
    /**
     * Edge IP to dial in the pinned-front model. Ignored (and may be
     * empty) when [forceIp] is true — the destination's own IP is then
     * resolved per-connection via DoH on the Rust side.
     */
    val ip: String,
    /**
     * SNI on the outbound TLS handshake. Must be served by the same
     * edge as [domains] or the edge will refuse / 404. Auto-populated
     * from the hostname the user typed when discovering via
     * `Native.discoverFront`. In camouflage mode ([forceIp] true) this
     * is a *fake* benign SNI used only to blind DPI.
     */
    val sni: String,
    /**
     * Domains routed through this edge. Case-insensitive; an entry
     * matches the host exactly OR as a dot-anchored suffix (entry
     * `vercel.com` matches `app.vercel.com` too).
     */
    val domains: List<String>,
    /**
     * Camouflage mode (patterniha `ForceIP`): dial the destination's own
     * DoH-resolved IP, send the fake [sni] to blind DPI, verify the cert
     * against the real host (or [verifyNames]). Used by the curated
     * `google-video` / `meta` groups. Default false. Round-tripped here
     * so Save doesn't drop it — the field is interpreted entirely on the
     * Rust side.
     */
    val forceIp: Boolean = false,
    /**
     * Optional explicit cert-name allow-list for camouflage mode. Empty
     * = verify against the real per-request host (the usual case).
     */
    val verifyNames: List<String> = emptyList(),
)

/**
 * One row in the Apps Script deployment-IDs list. [url] may be a bare
 * Deployment ID OR the full `/macros/s/.../exec` URL — `extractId()`
 * normalises both. [enabled] lets the user park an ID without deleting
 * it: disabled rows persist on disk (saved as `{id, enabled: false}`
 * under `script_id`) and skip the runtime round-robin. Mirrors the Rust
 * `ScriptIdEntry` shape.
 */
data class DeploymentEntry(
    val url: String,
    val enabled: Boolean = true,
)

data class RahgozarConfig(
    val mode: Mode = Mode.APPS_SCRIPT,
    val listenHost: String = "0.0.0.0",
    val listenPort: Int = 8080,
    val socks5Port: Int? = 1081,
    /** One Apps Script ID or deployment URL per entry, with per-row enabled flag. */
    val appsScriptUrls: List<DeploymentEntry> = emptyList(),
    val authKey: String = "",
    val frontDomain: String = "www.google.com",
    /** Rotation pool of SNI hostnames; empty means "let Rust auto-expand". */
    val sniHosts: List<String> = emptyList(),
    val googleIp: String = "142.251.36.68",
    val verifySsl: Boolean = true,
    val logLevel: String = "info",
    val parallelRelay: Int = 1,
    /**
     * Disable the HTTP/2 multiplexing on the Apps Script relay leg.
     * Default false (h2 active); flip to true to force the legacy
     * HTTP/1.1 keep-alive pool. Round-tripped from config.json so a
     * hand-edited kill switch survives a save round trip from the
     * Android UI. See `src/config.rs` `force_http1`.
     */
    val forceHttp1: Boolean = false,
    val coalesceStepMs: Int = 10,
    val coalesceMaxMs: Int = 1000,
    /** Block QUIC (UDP/443). QUIC over TCP tunnel causes meltdown. */
    val blockQuic: Boolean = true,
    /**
     * Block STUN/TURN ports (3478/5349/19302) over UDP. Forces WebRTC TCP
     * fallback. Defaults to `false` so an existing install upgrading to a
     * build that knows the key gets the pre-pipelining semantics until
     * the user opts in. See `default_block_stun` in src/config.rs for
     * the rationale.
     */
    val blockStun: Boolean = false,
    val upstreamSocks5: String = "",
    /**
     * User-configured hostnames that bypass Apps Script relay entirely
     * and plain-TCP passthrough (via upstreamSocks5 if set). Each entry
     * is either an exact hostname ("example.com") or a leading-dot
     * suffix (".example.com" → matches example.com + any subdomain).
     * See `src/config.rs` `passthrough_hosts` for semantics.
     * Issues #39, #127.
     */
    val passthroughHosts: List<String> = emptyList(),
    /**
     * Opt-out for the DoH bypass. The Rust default is to bypass DoH
     * traffic (chrome.cloudflare-dns.com, dns.google, etc.) directly
     * instead of routing it through the Apps Script tunnel — DoH
     * already encrypts queries, so the tunnel was just adding ~2 s
     * per name lookup with no real privacy gain. Set this to true to
     * keep DoH inside the tunnel. See `src/config.rs` `tunnel_doh`.
     */
    val tunnelDoh: Boolean = true,
    /**
     * Extra hostnames added to the built-in DoH default list. Same
     * matching shape as `passthroughHosts` (exact or leading-dot
     * suffix). Use to cover private / enterprise DoH endpoints.
     */
    val bypassDohHosts: List<String> = emptyList(),
    /**
     * When true, reject all connections to known DoH endpoints.
     * Browsers fall back to system DNS (tun2proxy virtual DNS — instant).
     * Takes priority over tunnel_doh / bypass_doh.
     */
    val blockDoh: Boolean = true,
    /** VPN_TUN (everything routed) vs PROXY_ONLY (user configures per-app). */
    val connectionMode: ConnectionMode = ConnectionMode.VPN_TUN,
    /** ALL / ONLY / EXCEPT — scope of app splitting inside VPN_TUN mode. */
    val splitMode: SplitMode = SplitMode.ALL,
    /** Package names used by ONLY and EXCEPT. Empty under ALL. */
    val splitApps: List<String> = emptyList(),
    /**
     * Route YouTube traffic through Apps Script relay instead of the
     * SNI-rewrite tunnel. Avoids Google SafeSearch-on-SNI / restricted
     * mode, but slower for video. Maps to Rust `youtube_via_relay`.
     */
    val youtubeViaRelay: Boolean = false,
    /**
     * SABR quality-track strip — opt-in (Rust `sabr_strip`, default
     * false after #977 testing). See `src/config.rs` `sabr_strip` for
     * the full reasoning and when to flip on. Android-side is just
     * round-trip plumbing.
     */
    val sabrStrip: Boolean = false,
    /**
     * Path-pinned relay routing (Rust `relay_url_patterns`).
     * See `src/config.rs` `relay_url_patterns` for the full semantics —
     * suppression gates, default pattern, host-overlap rules. This
     * Android-side field is for *additional* user entries only,
     * round-tripped so a hand-edited list survives Save.
     */
    val relayUrlPatterns: List<String> = emptyList(),
    /** UI language toggle. Non-Rust; honoured only by the Android wrapper. */
    val uiLang: UiLang = UiLang.AUTO,
    /**
     * Drive-mode (mode == DRIVE) — bare Drive folder ID (no URL). Used as
     * the shared mailbox folder. Below this point until [driveOauthClientSecret]
     * are the form-visible fields for the Drive transport. `oauth_refresh_token`
     * is intentionally NOT modelled as an editable field — the JNI device-code
     * flow writes it after a successful sign-in and the UI sees only
     * [driveHasRefreshToken] (computed at load time). The other fields are
     * normal form fields the user enters and Save persists.
     */
    val driveFolderId: String = "",
    /** Bech32m public key the relay printed at `rahgozar-drive-relay keygen` time. */
    val driveRelayPubkey: String = "",
    /** Baseline poll interval (ms) for the client-side r2c poller. */
    val drivePollIntervalMs: Int = 300,
    /** Max concurrent Drive uploads in flight from this client. */
    val driveMaxConcurrentUploads: Int = 8,
    /**
     * BYO OAuth client_id from the user's own Google Cloud project.
     * rahgozar ships no embedded OAuth client — every user registers
     * their own to sidestep the 100-user cap on unverified clients.
     * Required for Drive mode; the JNI surface refuses
     * `driveOauthStart` until both this and [driveOauthClientSecret]
     * are non-empty in `config.json`. See `docs/drive_oauth_setup.md`
     * for the Google Cloud Console walkthrough.
     */
    val driveOauthClientId: String = "",
    /**
     * BYO OAuth client_secret paired with [driveOauthClientId]. Per
     * RFC 8252 §8.6 not actually secret for installed apps, but
     * Google's token endpoint still requires it.
     */
    val driveOauthClientSecret: String = "",
    /** Read-only: true iff config.drive.oauth_refresh_token is non-empty on disk. */
    val driveHasRefreshToken: Boolean = false,
    /**
     * OAuth refresh-token snapshot captured at load time. The UI must
     * NEVER surface or echo this string — its only purpose is to
     * survive a UI Save round-trip so a token written by the JNI
     * device-code flow isn't wiped when the user subsequently saves
     * the Drive form. Internally re-emitted in
     * `toJson`'s `drive` sub-object alongside the user-facing fields.
     *
     * `driveHasRefreshToken` is the public read-only flag the UI
     * uses; this field exists purely for the load → save → write
     * preservation invariant.
     */
    val driveOauthRefreshTokenSnapshot: String = "",
    /**
     * Multi-edge fronting groups (Vercel, Fastly, AWS CloudFront, …).
     * Until v1.9.x the Android Save path silently dropped this field
     * because it wasn't modelled here; round-tripping fixes that and
     * unlocks the curated bundle loader. There's no in-app editor for
     * the entries — users either load the curated bundle or import a
     * config that contains them. See `assets/fronting-groups/curated.json`.
     */
    val frontingGroups: List<FrontingGroup> = emptyList(),
    /**
     * Verbatim JSON for any config.json key this build doesn't model
     * (e.g. desktop-only `exit_node`, `request_timeout_secs`,
     * `disable_padding`, `auto_blacklist_*`, `hosts`,
     * `normalize_x_graphql`, and any future Rust-side field added
     * before Android catches up).
     *
     * Captured by [ConfigStore.loadFromJson] and re-emitted by
     * [toJson] so a Rust-shaped or future-shaped config survives a
     * round-trip through the Android UI **without losing fields the
     * native runtime still needs**. The whole point of the Profile
     * "raw snapshot preservation" invariant is that the Rust side
     * sees those fields — and the Rust side reads `config.json`,
     * which is what we write here.
     *
     * Stored as a JSON object string (not Map) so we can splice it
     * back in via [JSONObject.put] without retyping every key.
     * Default empty = no passthrough fields.
     *
     * Excluded from [toJson]'s output when blank.
     */
    val extrasJson: String = "",
) {
    /**
     * Extract just the deployment ID from either a full
     * `https://script.google.com/macros/s/<ID>/exec` URL or a bare ID.
     *
     * Implementation note (this used to be buggy): never use the chained
     * `substringBefore(delim, missingDelimiterValue)` form passing the
     * original input as the fallback. Example of what that caused:
     *   "https://.../macros/s/X/exec"
     *     .substringAfter("/macros/s/", s)  -> "X/exec"
     *     .substringBefore("/", s)          -> "X"
     *     .substringBefore("?", s)          -> FALLBACK fires because
     *                                           "?" isn't in "X",
     *                                           returning the ORIGINAL URL
     * → we'd then save the full URL as the "ID", and on reload the UI
     * would build `https://.../macros/s/<full-URL>/exec`, producing the
     * "extra https:// and extra /exec" symptom users reported. Keep the
     * extraction linear and don't reach for a fallback.
     */
    private fun extractId(input: String): String {
        var s = input.trim()
        if (s.isEmpty()) return s
        val marker = "/macros/s/"
        val i = s.indexOf(marker)
        if (i >= 0) s = s.substring(i + marker.length)
        // Strip /exec or /dev suffix (or any path after the ID).
        val slash = s.indexOf('/')
        if (slash >= 0) s = s.substring(0, slash)
        // Strip query string.
        val q = s.indexOf('?')
        if (q >= 0) s = s.substring(0, q)
        return s.trim()
    }

    fun toJson(): String {
        // Normalise each row to a bare ID (entries may be full deployment
        // URLs from old configs or fresh paste) and drop blanks. The
        // enabled flag rides along — disabled rows persist so the user
        // can re-enable without re-typing.
        val entries =
            appsScriptUrls
                .map { DeploymentEntry(url = extractId(it.url), enabled = it.enabled) }
                .filter { it.url.isNotEmpty() }

        val obj =
            JSONObject().apply {
                // `mode` is required — without it serde errors with
                // "missing field `mode`" and startProxy silently returns 0.
                put(
                    "mode",
                    when (mode) {
                        Mode.APPS_SCRIPT -> "apps_script"
                        Mode.DIRECT -> "direct"
                        Mode.FULL -> "full"
                        Mode.LOCAL_BYPASS -> "local_bypass"
                        Mode.DRIVE -> "drive"
                    },
                )
                put("listen_host", listenHost)
                put("listen_port", listenPort)
                socks5Port?.let { put("socks5_port", it) }

                // In direct mode these are unused by the Rust side, but we
                // still persist whatever the user typed so flipping back to
                // apps_script mode doesn't wipe their settings.
                //
                // Prefer the legacy bare-string shape when no row is
                // disabled — older rahgozar / Android builds (pre-disable
                // flag) only know how to read strings, and a config
                // written here may be sideloaded onto one of them via
                // QR / clipboard. Only escalate to `[{id, enabled}]`
                // when a row actually needs the flag. The Rust reader
                // accepts both shapes via the `untagged` enum.
                if (entries.isNotEmpty()) {
                    val allEnabled = entries.all { it.enabled }
                    if (allEnabled) {
                        put(
                            "script_id",
                            JSONArray().apply { entries.forEach { put(it.url) } },
                        )
                    } else {
                        put(
                            "script_id",
                            JSONArray().apply {
                                entries.forEach { e ->
                                    put(
                                        JSONObject().apply {
                                            put("id", e.url)
                                            put("enabled", e.enabled)
                                        },
                                    )
                                }
                            },
                        )
                    }
                }
                put("auth_key", authKey)

                put("front_domain", frontDomain)
                if (sniHosts.isNotEmpty()) {
                    put("sni_hosts", JSONArray().apply { sniHosts.forEach { put(it) } })
                }
                put("google_ip", googleIp)

                put("verify_ssl", verifySsl)
                put("log_level", logLevel)
                put("parallel_relay", parallelRelay)
                if (forceHttp1) put("force_http1", true)
                if (coalesceStepMs != 10) put("coalesce_step_ms", coalesceStepMs)
                if (coalesceMaxMs != 1000) put("coalesce_max_ms", coalesceMaxMs)
                put("block_quic", blockQuic)
                put("block_stun", blockStun)
                if (upstreamSocks5.isNotBlank()) {
                    put("upstream_socks5", upstreamSocks5.trim())
                }
                if (passthroughHosts.isNotEmpty()) {
                    put("passthrough_hosts", JSONArray().apply { passthroughHosts.forEach { put(it) } })
                }
                put("tunnel_doh", tunnelDoh)
                put("block_doh", blockDoh)
                if (youtubeViaRelay) put("youtube_via_relay", true)
                // sabr_strip default is false on the Rust side (opt-in
                // after #977); emit only when the user has explicitly
                // enabled it so unchanged configs stay clean.
                if (sabrStrip) put("sabr_strip", true)
                // Trim/drop-empty/dedupe before serializing — same pattern
                // as bypass_doh_hosts. Skip the key entirely when the user
                // hasn't added any extras so we don't leak an empty array
                // into otherwise-clean configs.
                val cleanRelayUrlPatterns =
                    relayUrlPatterns
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                        .distinct()
                if (cleanRelayUrlPatterns.isNotEmpty()) {
                    put("relay_url_patterns", JSONArray().apply { cleanRelayUrlPatterns.forEach { put(it) } })
                }
                // Trim/drop-empty/dedupe before serializing — symmetric with the
                // read-side normalization in loadFromJson(), so a user typing
                // " doh.foo " or accidentally adding a duplicate doesn't end up
                // in the saved JSON.
                val cleanBypassDohHosts =
                    bypassDohHosts
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                        .distinct()
                if (cleanBypassDohHosts.isNotEmpty()) {
                    put("bypass_doh_hosts", JSONArray().apply { cleanBypassDohHosts.forEach { put(it) } })
                }

                // Phone-scoped scan defaults. We don't expose these in the UI
                // because a phone isn't where you'd run a full /16 scan; users
                // who need it can do that on the desktop UI and paste the IP.
                put("fetch_ips_from_api", false)
                put("max_ips_to_scan", 20)

                // Fronting groups: the snake_case JSON shape must match the
                // Rust-side `FrontingGroup` serde format exactly, otherwise
                // the proxy will refuse to start with "missing field". The
                // `domains` array is trimmed/de-duped at write time so a
                // user pasting messy input doesn't poison the persisted
                // form.
                //
                // Drop draft groups (no domains yet) at save time:
                // `Config::validate()` in src/config.rs rejects empty
                // `domains` lists with a hard error, so persisting them
                // would make Native.startProxy() return 0. The UI keeps
                // them visible so the user can still fill in domains;
                // they survive into the saved file only once non-empty.
                val savableGroups =
                    frontingGroups.mapNotNull { g ->
                        val cleaned =
                            g.domains
                                .map { it.trim() }
                                .filter { it.isNotEmpty() }
                                .distinct()
                        if (cleaned.isEmpty()) null else g.copy(domains = cleaned)
                    }
                if (savableGroups.isNotEmpty()) {
                    put(
                        "fronting_groups",
                        JSONArray().apply {
                            savableGroups.forEach { g ->
                                put(
                                    JSONObject().apply {
                                        put("name", g.name)
                                        put("ip", g.ip)
                                        put("sni", g.sni)
                                        put(
                                            "domains",
                                            JSONArray().apply {
                                                g.domains.forEach { put(it) }
                                            },
                                        )
                                        if (g.forceIp) put("force_ip", true)
                                        if (g.verifyNames.isNotEmpty()) {
                                            put(
                                                "verify_names",
                                                JSONArray().apply {
                                                    g.verifyNames.forEach { put(it) }
                                                },
                                            )
                                        }
                                    },
                                )
                            }
                        },
                    )
                }

                // Android-only: surfaced in the UI dropdown. The Rust side
                // doesn't read this key (serde ignores unknown fields), which
                // is intentional — proxy-vs-TUN is a service-layer decision
                // that belongs to the Android wrapper, not the crate.
                put(
                    "connection_mode",
                    when (connectionMode) {
                        ConnectionMode.VPN_TUN -> "vpn_tun"
                        ConnectionMode.PROXY_ONLY -> "proxy_only"
                    },
                )
                put(
                    "split_mode",
                    when (splitMode) {
                        SplitMode.ALL -> "all"
                        SplitMode.ONLY -> "only"
                        SplitMode.EXCEPT -> "except"
                    },
                )
                if (splitApps.isNotEmpty()) {
                    put("split_apps", JSONArray().apply { splitApps.forEach { put(it) } })
                }
                // Drive-mode sub-object. The OAuth refresh token is
                // re-emitted from the load-time snapshot so a UI Save
                // doesn't wipe a token that the JNI device-code flow
                // wrote out directly. The UI never surfaces the snapshot
                // and never lets the user edit it — the OAuth flow is
                // the only legitimate source for that value.
                val driveObj = JSONObject()
                if (driveOauthRefreshTokenSnapshot.isNotEmpty()) {
                    driveObj.put("oauth_refresh_token", driveOauthRefreshTokenSnapshot)
                }
                if (driveFolderId.isNotBlank()) {
                    driveObj.put("folder_id", driveFolderId.trim())
                }
                if (driveRelayPubkey.isNotBlank()) {
                    driveObj.put("relay_pubkey", driveRelayPubkey.trim())
                }
                // BYO OAuth credentials — emit only when non-empty so
                // a fresh-install config doesn't ship a half-empty
                // `drive` block. The Rust validator only requires them
                // when mode == drive, so leaving them out for users
                // running other modes is fine.
                if (driveOauthClientId.isNotBlank()) {
                    driveObj.put("oauth_client_id", driveOauthClientId.trim())
                }
                if (driveOauthClientSecret.isNotBlank()) {
                    driveObj.put("oauth_client_secret", driveOauthClientSecret.trim())
                }
                driveObj.put("poll_interval_ms", drivePollIntervalMs)
                driveObj.put("max_concurrent_uploads", driveMaxConcurrentUploads)
                put("drive", driveObj)

                put(
                    "ui_lang",
                    when (uiLang) {
                        UiLang.AUTO -> "auto"
                        UiLang.FA -> "fa"
                        UiLang.EN -> "en"
                    },
                )

                // Splice back any keys this build doesn't model (so they
                // survive a load → edit → save round-trip and reach the
                // native runtime, which IS the source of truth for them).
                // We deliberately don't overwrite our modelled keys — if a
                // future build models a field that's currently in extras,
                // the new modelled value wins on the next save.
                if (extrasJson.isNotBlank()) {
                    try {
                        val ex = JSONObject(extrasJson)
                        val it = ex.keys()
                        while (it.hasNext()) {
                            val k = it.next()
                            if (!has(k)) put(k, ex.get(k))
                        }
                    } catch (_: Throwable) {
                        // Malformed extras — drop. Captured-at-parse-time
                        // extras should never be malformed; this guard is
                        // for the synthetic-cfg path (decode()).
                    }
                }
            }
        return obj.toString(2)
    }

    /**
     * Convenience: is there at least one enabled, usable deployment ID?
     * Disabled rows are filtered out — the relay can't dispatch through
     * them, so they don't satisfy the "do we have credentials?" gate
     * the UI uses to decide whether to disable the start button.
     */
    val hasDeploymentId: Boolean get() =
        appsScriptUrls.any { it.enabled && extractId(it.url).isNotEmpty() }

    // Keep this predicate cheap: Compose reads it on every recomposition
    // (Start button enable state, called per keystroke). Strong pubkey
    // validation runs (a) live in the Drive-setup section's
    // `Native.driveValidateRelayPubkey` LaunchedEffect on Dispatchers.IO,
    // (b) in ProfileStore.applyProfile on import, and (c) in Rust's
    // Config::validate on proxy start — so weakening this to "field is
    // filled" doesn't change the overall safety story, it just keeps
    // the BigInteger Curve25519 ladder off the main thread.
    val hasDriveRelayConfig: Boolean get() =
        driveOauthClientId.isNotBlank() &&
            driveOauthClientSecret.isNotBlank() &&
            driveHasRefreshToken &&
            driveFolderId.isNotBlank() &&
            driveRelayPubkey.isNotBlank() &&
            drivePollIntervalMs > 0 &&
            driveMaxConcurrentUploads > 0

    val canStartCurrentMode: Boolean get() =
        when {
            mode.usesAppsScriptRelay() -> hasDeploymentId && authKey.isNotBlank()
            mode.usesDriveRelay() -> hasDriveRelayConfig
            else -> true
        }
}

object ConfigStore {
    private const val FILE = "config.json"

    fun load(ctx: Context): RahgozarConfig {
        val f = File(ctx.filesDir, FILE)
        if (!f.exists()) return RahgozarConfig()
        return try {
            loadFromJson(JSONObject(f.readText()))
        } catch (_: Throwable) {
            RahgozarConfig()
        }
    }

    /**
     * Return the exact config shape that should be written for a UI save.
     *
     * Refresh tokens are preserved only while the token is still present
     * on disk and still bound to the same OAuth client credentials. This
     * keeps a loaded UI snapshot from resurrecting a token that was cleared
     * by credential rotation or by another writer.
     */
    fun prepareForSave(
        ctx: Context,
        cfg: RahgozarConfig,
    ): RahgozarConfig {
        val f = File(ctx.filesDir, FILE)
        return prepareForSave(f, cfg)
    }

    /**
     * Persist [cfg] to `config.json`. Returns true on success.
     *
     * Atomicity: writes to `config.json.tmp` and replaces via the same
     * NIO/backup pattern as [ProfileStore.save] — never deletes the
     * existing file without a backup. On failure the previous
     * `config.json` is preserved untouched (or restored from `.bak`).
     */
    fun save(
        ctx: Context,
        cfg: RahgozarConfig,
    ): Boolean {
        val f = File(ctx.filesDir, FILE)
        val tmp = File(ctx.filesDir, "$FILE.tmp")
        return try {
            val cfgToWrite = prepareForSave(f, cfg)
            tmp.writeText(cfgToWrite.toJson())
            ProfileStore.atomicReplacePublic(tmp, f)
        } catch (_: Throwable) {
            tmp.delete()
            false
        }
    }

    private fun prepareForSave(
        existingFile: File,
        next: RahgozarConfig,
    ): RahgozarConfig {
        fun withoutRefreshToken() =
            next.copy(
                driveHasRefreshToken = false,
                driveOauthRefreshTokenSnapshot = "",
            )

        if (!existingFile.exists()) {
            return next.copy(
                driveHasRefreshToken = next.driveOauthRefreshTokenSnapshot.isNotBlank(),
            )
        }
        return try {
            val root = JSONObject(existingFile.readText())
            val drive = root.optJSONObject("drive") ?: return withoutRefreshToken()
            val refreshToken = drive.optString("oauth_refresh_token", "").trim()
            if (refreshToken.isEmpty()) return withoutRefreshToken()
            val oldClientId = drive.optString("oauth_client_id", "").trim()
            val oldClientSecret = drive.optString("oauth_client_secret", "").trim()
            if (
                oldClientId != next.driveOauthClientId.trim() ||
                oldClientSecret != next.driveOauthClientSecret.trim()
            ) {
                withoutRefreshToken()
            } else {
                next.copy(
                    driveHasRefreshToken = true,
                    driveOauthRefreshTokenSnapshot =
                        next.driveOauthRefreshTokenSnapshot.ifBlank { refreshToken },
                )
            }
        } catch (_: Throwable) {
            // If the existing file is malformed, let the normal save
            // path decide whether it can replace it; don't preserve a
            // token whose credential binding we cannot verify.
            withoutRefreshToken()
        }
    }

    /** Prefix for encoded config strings so we can detect them in clipboard. */
    private const val HASH_PREFIX = "rahgozar://"

    /**
     * JSON payload used by QR/clipboard export. Deliberately omits
     * Drive OAuth bearer material; persistence uses [RahgozarConfig.toJson]
     * instead so Save still preserves the refresh token on disk.
     */
    internal fun toShareJson(cfg: RahgozarConfig): JSONObject {
        val defaults = RahgozarConfig()
        val obj = JSONObject()

        // Always include essential fields.
        obj.put(
            "mode",
            when (cfg.mode) {
                Mode.APPS_SCRIPT -> "apps_script"
                Mode.DIRECT -> "direct"
                Mode.FULL -> "full"
                Mode.LOCAL_BYPASS -> "local_bypass"
                Mode.DRIVE -> "drive"
            },
        )
        // Normalise each entry to a bare ID and keep its enabled flag —
        // sharing carries disabled rows so the receiver doesn't have to
        // re-disable IDs they've already chosen to park.
        val entries =
            cfg.appsScriptUrls.mapNotNull { entry ->
                val marker = "/macros/s/"
                val raw = entry.url
                val normalised =
                    if (raw.indexOf(marker) >= 0) {
                        var s = raw.substring(raw.indexOf(marker) + marker.length)
                        val slash = s.indexOf('/')
                        if (slash >= 0) s = s.substring(0, slash)
                        s.trim()
                    } else {
                        raw.trim()
                    }
                if (normalised.isEmpty()) null else DeploymentEntry(normalised, entry.enabled)
            }
        if (entries.isNotEmpty()) {
            // Mirror `toJson()`: prefer the legacy bare-string shape when
            // no row is disabled, so a QR share into an older client
            // still parses. Escalate to objects only when needed.
            val allEnabled = entries.all { it.enabled }
            if (allEnabled) {
                obj.put(
                    "script_id",
                    JSONArray().apply { entries.forEach { put(it.url) } },
                )
            } else {
                obj.put(
                    "script_id",
                    JSONArray().apply {
                        entries.forEach { e ->
                            put(
                                JSONObject().apply {
                                    put("id", e.url)
                                    put("enabled", e.enabled)
                                },
                            )
                        }
                    },
                )
            }
        }
        if (cfg.authKey.isNotBlank()) obj.put("auth_key", cfg.authKey)

        // Only include non-default values.
        if (cfg.googleIp != defaults.googleIp) obj.put("google_ip", cfg.googleIp)
        if (cfg.frontDomain != defaults.frontDomain) obj.put("front_domain", cfg.frontDomain)
        if (cfg.sniHosts.isNotEmpty()) obj.put("sni_hosts", JSONArray().apply { cfg.sniHosts.forEach { put(it) } })
        if (cfg.verifySsl != defaults.verifySsl) obj.put("verify_ssl", cfg.verifySsl)
        if (cfg.logLevel != defaults.logLevel) obj.put("log_level", cfg.logLevel)
        if (cfg.parallelRelay != defaults.parallelRelay) obj.put("parallel_relay", cfg.parallelRelay)
        if (cfg.forceHttp1 != defaults.forceHttp1) obj.put("force_http1", cfg.forceHttp1)
        if (cfg.coalesceStepMs != defaults.coalesceStepMs) obj.put("coalesce_step_ms", cfg.coalesceStepMs)
        if (cfg.coalesceMaxMs != defaults.coalesceMaxMs) obj.put("coalesce_max_ms", cfg.coalesceMaxMs)
        if (cfg.blockQuic != defaults.blockQuic) obj.put("block_quic", cfg.blockQuic)
        if (cfg.blockStun != defaults.blockStun) obj.put("block_stun", cfg.blockStun)
        if (cfg.upstreamSocks5.isNotBlank()) obj.put("upstream_socks5", cfg.upstreamSocks5)
        if (cfg.passthroughHosts.isNotEmpty()) obj.put("passthrough_hosts", JSONArray().apply { cfg.passthroughHosts.forEach { put(it) } })
        if (cfg.tunnelDoh != defaults.tunnelDoh) obj.put("tunnel_doh", cfg.tunnelDoh)
        if (cfg.blockDoh != defaults.blockDoh) obj.put("block_doh", cfg.blockDoh)
        if (cfg.youtubeViaRelay != defaults.youtubeViaRelay) obj.put("youtube_via_relay", cfg.youtubeViaRelay)
        if (cfg.sabrStrip != defaults.sabrStrip) obj.put("sabr_strip", cfg.sabrStrip)
        val cleanBypassDohHosts =
            cfg.bypassDohHosts
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
        if (cleanBypassDohHosts.isNotEmpty()) {
            obj.put("bypass_doh_hosts", JSONArray().apply { cleanBypassDohHosts.forEach { put(it) } })
        }
        val cleanRelayUrlPatterns =
            cfg.relayUrlPatterns
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
        if (cleanRelayUrlPatterns.isNotEmpty()) {
            obj.put("relay_url_patterns", JSONArray().apply { cleanRelayUrlPatterns.forEach { put(it) } })
        }
        // Fronting groups: include only fully-populated entries so the QR
        // receiver doesn't import drafts that the proxy would refuse to
        // load. Same drop-empty-domains rule as toJson(). Domains are
        // trimmed + de-duped here so a sharer with messy input doesn't
        // push that mess across devices.
        val savableGroups =
            cfg.frontingGroups.mapNotNull { g ->
                val cleaned =
                    g.domains
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                        .distinct()
                if (cleaned.isEmpty()) null else g.copy(domains = cleaned)
            }
        if (savableGroups.isNotEmpty()) {
            obj.put(
                "fronting_groups",
                JSONArray().apply {
                    savableGroups.forEach { g ->
                        put(
                            JSONObject().apply {
                                put("name", g.name)
                                put("ip", g.ip)
                                put("sni", g.sni)
                                put("domains", JSONArray().apply { g.domains.forEach { put(it) } })
                                if (g.forceIp) put("force_ip", true)
                                if (g.verifyNames.isNotEmpty()) {
                                    put(
                                        "verify_names",
                                        JSONArray().apply { g.verifyNames.forEach { put(it) } },
                                    )
                                }
                            },
                        )
                    }
                },
            )
        }
        // Drive-mode sub-object. Only emit fields the user has
        // populated — a QR share of a non-Drive config shouldn't
        // include an empty `drive` block. Never export
        // oauth_refresh_token or oauth_client_secret: sharing should
        // not silently grant Drive access or leak a BYO OAuth client
        // secret. Recipients can paste their own secret and sign in.
        val driveObj = JSONObject()
        if (cfg.driveFolderId.isNotBlank()) driveObj.put("folder_id", cfg.driveFolderId.trim())
        if (cfg.driveRelayPubkey.isNotBlank()) driveObj.put("relay_pubkey", cfg.driveRelayPubkey.trim())
        if (cfg.driveOauthClientId.isNotBlank()) driveObj.put("oauth_client_id", cfg.driveOauthClientId.trim())
        if (cfg.drivePollIntervalMs != defaults.drivePollIntervalMs) {
            driveObj.put("poll_interval_ms", cfg.drivePollIntervalMs)
        }
        if (cfg.driveMaxConcurrentUploads != defaults.driveMaxConcurrentUploads) {
            driveObj.put("max_concurrent_uploads", cfg.driveMaxConcurrentUploads)
        }
        if (driveObj.length() > 0) {
            obj.put("drive", driveObj)
        }
        return obj
    }

    /** Encode config as a shareable base64 string with prefix.
     *  Only includes non-default fields to keep the hash short. */
    fun encode(cfg: RahgozarConfig): String {
        val obj = toShareJson(cfg)
        // Compress with DEFLATE then base64.
        val jsonBytes = obj.toString().toByteArray(Charsets.UTF_8)
        val compressed =
            java.io
                .ByteArrayOutputStream()
                .also { bos ->
                    java.util.zip
                        .DeflaterOutputStream(bos)
                        .use { it.write(jsonBytes) }
                }.toByteArray()

        val b64 =
            android.util.Base64.encodeToString(
                compressed,
                android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE,
            )
        return "$HASH_PREFIX$b64"
    }

    /** Try DEFLATE inflate; fall back to treating bytes as raw UTF-8
     *  (for backward compat with uncompressed exports). */
    private fun inflateOrRaw(raw: ByteArray): String =
        try {
            java.util.zip
                .InflaterInputStream(raw.inputStream())
                .bufferedReader()
                .readText()
        } catch (_: Throwable) {
            String(raw, Charsets.UTF_8)
        }

    /** Try to decode an encoded config string or raw JSON. Returns null on failure. */
    fun decode(encoded: String): RahgozarConfig? {
        val trimmed = encoded.trim()
        // Try raw JSON first.
        if (trimmed.startsWith("{")) {
            return try {
                val obj = JSONObject(trimmed)
                if (!hasConfigShape(obj)) null else loadFromJson(obj)
            } catch (_: Throwable) {
                null
            }
        }
        // Try rahgozar:// base64 encoded (possibly DEFLATE-compressed).
        val payload = if (trimmed.startsWith(HASH_PREFIX)) trimmed.removePrefix(HASH_PREFIX) else trimmed
        return try {
            val raw = android.util.Base64.decode(payload, android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE)
            val text = inflateOrRaw(raw)
            val obj = JSONObject(text)
            if (!hasConfigShape(obj)) return null
            loadFromJson(obj)
        } catch (_: Throwable) {
            null
        }
    }

    /** Check if a string looks like an encoded rahgozar config. */
    fun looksLikeConfig(text: String): Boolean {
        val t = text.trim()
        if (t.startsWith(HASH_PREFIX)) return true
        if (t.startsWith("{")) {
            return try {
                hasConfigShape(JSONObject(t))
            } catch (_: Throwable) {
                false
            }
        }
        return false
    }

    /**
     * Acceptance gate for "is this JSON shaped like a rahgozar config?".
     * Accepts any of `mode`, `auth_key`, `script_id` (Rust output),
     * or `script_ids` (legacy Android output). `script_id` was added
     * after the parser was taught to read both shapes — without it,
     * a Rust-shaped config with only `script_id` would be rejected
     * here even though [loadFromJson] could read it fine.
     */
    private fun hasConfigShape(obj: JSONObject): Boolean =
        obj.has("mode") ||
            obj.has("auth_key") ||
            obj.has("script_id") ||
            obj.has("script_ids")

    /**
     * Keys this build models. Anything outside this set is captured
     * into [RahgozarConfig.extrasJson] at parse time and re-emitted by
     * [RahgozarConfig.toJson] so the native runtime keeps seeing
     * desktop-only / future Rust-side fields (`exit_node`,
     * `request_timeout_secs`, `disable_padding`, `auto_blacklist_*`,
     * `hosts`, `normalize_x_graphql`, `google_ip_validation`,
     * `scan_batch_size`, etc.).
     *
     * Updating this set is a deliberate act — add a key here only
     * when [RahgozarConfig] gains a real field for it.
     */
    private val MODELLED_KEYS: Set<String> =
        setOf(
            "mode",
            "listen_host",
            "listen_port",
            "socks5_port",
            // Both script_id (Rust output) and script_ids (legacy Android
            // output) are read by us, so both belong in the "modelled" set
            // — otherwise a Rust-shaped config would have its IDs end up
            // in extras AND in the parsed appsScriptUrls, getting written
            // out twice (once as the unmodelled passthrough, once as
            // script_ids).
            "script_id",
            "script_ids",
            "auth_key",
            "front_domain",
            "sni_hosts",
            "google_ip",
            "verify_ssl",
            "log_level",
            "parallel_relay",
            "force_http1",
            "coalesce_step_ms",
            "coalesce_max_ms",
            "block_quic",
            "block_stun",
            "upstream_socks5",
            "passthrough_hosts",
            "tunnel_doh",
            "bypass_doh_hosts",
            "block_doh",
            "youtube_via_relay",
            "sabr_strip",
            "relay_url_patterns",
            "fronting_groups",
            "connection_mode",
            "split_mode",
            "split_apps",
            "ui_lang",
            // Phone-scoped scan defaults toJson() emits. Modelled so they
            // don't round-trip into extras then collide with toJson's
            // explicit puts.
            "fetch_ips_from_api",
            "max_ips_to_scan",
            // Drive-mode setup. The whole `drive` sub-object is modelled
            // (broken out into 5 fields in RahgozarConfig — folder_id,
            // relay_pubkey, poll_interval_ms, max_concurrent_uploads, and
            // the oauth_refresh_token snapshot for round-trip
            // preservation). Keeping `drive` here prevents the unmodelled
            // extras-passthrough from re-emitting the same sub-object
            // and colliding with toJson's explicit `put("drive", ...)`.
            "drive",
        )

    /**
     * Parse config from a JSON object — shared by [load] and [decode].
     * `internal` rather than `private` so the JVM unit tests in
     * `src/test/` can drive a JSON-only round-trip without going
     * through the disk path.
     */
    internal fun loadFromJson(obj: JSONObject): RahgozarConfig {
        // Read deployment IDs from both `script_id` (current canonical
        // key, written by Rust and by recent Android builds) and
        // `script_ids` (legacy Android plural). Each can be a scalar
        // string, an array of strings, or an array of `{id, enabled}`
        // objects (the new shape that carries the disable flag).
        //
        // Dedupe by ID. When the same ID appears under both keys, the
        // first occurrence wins — so the row order from `script_id`
        // (the modern key) is preserved over `script_ids`.
        val rawEntries =
            buildList<DeploymentEntry> {
                addAll(readScriptIdList(obj, "script_id"))
                addAll(readScriptIdList(obj, "script_ids"))
            }.filter { it.url.isNotBlank() }
        val seen = mutableSetOf<String>()
        val entries =
            rawEntries.mapNotNull { e ->
                if (seen.add(e.url)) {
                    DeploymentEntry(
                        url = "https://script.google.com/macros/s/${e.url}/exec",
                        enabled = e.enabled,
                    )
                } else {
                    null
                }
            }
        val sni =
            obj
                .optJSONArray("sni_hosts")
                ?.let { arr ->
                    buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
                }?.filter { it.isNotBlank() }
                .orEmpty()

        // Capture anything we don't model into extras for passthrough
        // (raw-snapshot preservation invariant — the native runtime
        // reads config.json directly and needs every field).
        val extras = JSONObject()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            if (k !in MODELLED_KEYS) extras.put(k, obj.get(k))
        }
        val extrasStr = if (extras.length() > 0) extras.toString() else ""

        // Drive-mode sub-object. Parsed once so the modelled fields +
        // the snapshot of the OAuth refresh token (for round-trip
        // preservation) both flow into the returned RahgozarConfig.
        val driveObj = obj.optJSONObject("drive")
        val driveFolderId = driveObj?.optString("folder_id", "")?.trim().orEmpty()
        val driveRelayPubkey = driveObj?.optString("relay_pubkey", "")?.trim().orEmpty()
        val drivePollIntervalMs = driveObj?.optInt("poll_interval_ms", 300) ?: 300
        val driveMaxConcurrentUploads = driveObj?.optInt("max_concurrent_uploads", 8) ?: 8
        val driveOauthClientId = driveObj?.optString("oauth_client_id", "")?.trim().orEmpty()
        val driveOauthClientSecret = driveObj?.optString("oauth_client_secret", "")?.trim().orEmpty()
        val driveOauthRefreshTokenSnapshot =
            driveObj?.optString("oauth_refresh_token", "")?.trim().orEmpty()
        val driveHasRefreshToken = driveOauthRefreshTokenSnapshot.isNotEmpty()

        return RahgozarConfig(
            mode =
                when (obj.optString("mode", "apps_script")) {
                    "direct" -> Mode.DIRECT

                    // Deprecated alias kept forever for back-compat with
                    // configs written before the rename.
                    "google_only" -> Mode.DIRECT

                    "full" -> Mode.FULL

                    "local_bypass" -> Mode.LOCAL_BYPASS

                    "drive" -> Mode.DRIVE

                    else -> Mode.APPS_SCRIPT
                },
            listenHost = obj.optString("listen_host", "0.0.0.0"),
            listenPort = obj.optInt("listen_port", 8080),
            socks5Port = obj.optInt("socks5_port", 1081).takeIf { it > 0 },
            appsScriptUrls = entries,
            authKey = obj.optString("auth_key", ""),
            frontDomain = obj.optString("front_domain", "www.google.com"),
            sniHosts = sni,
            googleIp = obj.optString("google_ip", "142.251.36.68"),
            verifySsl = obj.optBoolean("verify_ssl", true),
            logLevel = obj.optString("log_level", "info"),
            parallelRelay = obj.optInt("parallel_relay", 1),
            forceHttp1 = obj.optBoolean("force_http1", false),
            coalesceStepMs = obj.optInt("coalesce_step_ms", 10),
            coalesceMaxMs = obj.optInt("coalesce_max_ms", 1000),
            blockQuic = obj.optBoolean("block_quic", true),
            blockStun = obj.optBoolean("block_stun", false),
            upstreamSocks5 = obj.optString("upstream_socks5", ""),
            passthroughHosts =
                obj
                    .optJSONArray("passthrough_hosts")
                    ?.let { arr ->
                        buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
                    }?.filter { it.isNotBlank() }
                    .orEmpty(),
            tunnelDoh = obj.optBoolean("tunnel_doh", true),
            blockDoh = obj.optBoolean("block_doh", true),
            youtubeViaRelay = obj.optBoolean("youtube_via_relay", false),
            sabrStrip = obj.optBoolean("sabr_strip", false),
            bypassDohHosts =
                obj
                    .optJSONArray("bypass_doh_hosts")
                    ?.let { arr ->
                        buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
                    }?.filter { it.isNotBlank() }
                    .orEmpty(),
            relayUrlPatterns =
                obj
                    .optJSONArray("relay_url_patterns")
                    ?.let { arr ->
                        buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
                    }?.filter { it.isNotBlank() }
                    .orEmpty(),
            connectionMode =
                when (obj.optString("connection_mode", "vpn_tun")) {
                    "proxy_only" -> ConnectionMode.PROXY_ONLY
                    else -> ConnectionMode.VPN_TUN
                },
            splitMode =
                when (obj.optString("split_mode", "all")) {
                    "only" -> SplitMode.ONLY
                    "except" -> SplitMode.EXCEPT
                    else -> SplitMode.ALL
                },
            splitApps =
                obj
                    .optJSONArray("split_apps")
                    ?.let { arr ->
                        buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
                    }?.filter { it.isNotBlank() }
                    .orEmpty(),
            uiLang =
                when (obj.optString("ui_lang", "auto")) {
                    "fa" -> UiLang.FA
                    "en" -> UiLang.EN
                    else -> UiLang.AUTO
                },
            frontingGroups =
                obj
                    .optJSONArray("fronting_groups")
                    ?.let { arr ->
                        buildList {
                            for (i in 0 until arr.length()) {
                                val g = arr.optJSONObject(i) ?: continue
                                val name = g.optString("name").trim()
                                val ip = g.optString("ip").trim()
                                val sni = g.optString("sni").trim()
                                val domArr = g.optJSONArray("domains")
                                val domains =
                                    if (domArr != null) {
                                        buildList {
                                            for (j in 0 until domArr.length()) {
                                                val d = domArr.optString(j).trim()
                                                if (d.isNotEmpty()) add(d)
                                            }
                                        }
                                    } else {
                                        emptyList()
                                    }
                                val forceIp = g.optBoolean("force_ip", false)
                                val verifyArr = g.optJSONArray("verify_names")
                                val verifyNames =
                                    if (verifyArr != null) {
                                        buildList {
                                            for (j in 0 until verifyArr.length()) {
                                                val v = verifyArr.optString(j).trim()
                                                if (v.isNotEmpty()) add(v)
                                            }
                                        }
                                    } else {
                                        emptyList()
                                    }
                                // Skip half-empty entries — same shape as the
                                // Rust validator in src/config.rs would reject.
                                // `ip` is required only for pinned groups; in
                                // camouflage mode (force_ip) the destination IP
                                // is resolved at runtime, so an empty ip is fine.
                                if (name.isEmpty() ||
                                    (!forceIp && ip.isEmpty()) ||
                                    sni.isEmpty() ||
                                    domains.isEmpty()
                                ) {
                                    continue
                                }
                                add(FrontingGroup(name, ip, sni, domains, forceIp, verifyNames))
                            }
                        }
                    }.orEmpty(),
            driveFolderId = driveFolderId,
            driveRelayPubkey = driveRelayPubkey,
            drivePollIntervalMs = drivePollIntervalMs,
            driveMaxConcurrentUploads = driveMaxConcurrentUploads,
            driveOauthClientId = driveOauthClientId,
            driveOauthClientSecret = driveOauthClientSecret,
            driveHasRefreshToken = driveHasRefreshToken,
            driveOauthRefreshTokenSnapshot = driveOauthRefreshTokenSnapshot,
            extrasJson = extrasStr,
        )
    }

    /**
     * Read a list of deployment-ID entries from `key`. Accepts:
     *   - a JSON string scalar ("abc") — legacy, enabled = true
     *   - a JSON array of strings (["abc","def"]) — legacy, all enabled
     *   - a JSON array of objects ([{"id":"abc","enabled":true}, ...]) — new
     *   - mixed arrays (a bare string inside an array defaults to enabled)
     *
     * Mirrors the Rust [ScriptId] enum's `untagged` deserialize so all
     * shapes interop. Returns an empty list when the key is absent or
     * shaped wrong.
     */
    private fun readScriptIdList(
        obj: JSONObject,
        key: String,
    ): List<DeploymentEntry> {
        if (!obj.has(key)) return emptyList()
        // Array form first.
        obj.optJSONArray(key)?.let { arr ->
            return buildList {
                for (i in 0 until arr.length()) {
                    when (val elem = arr.opt(i)) {
                        is String -> {
                            if (elem.isNotBlank()) add(DeploymentEntry(elem, true))
                        }

                        is JSONObject -> {
                            val id = elem.optString("id", "")
                            if (id.isNotBlank()) {
                                add(DeploymentEntry(id, elem.optBoolean("enabled", true)))
                            }
                        }

                        // Numbers/null/booleans inside the array are silently skipped —
                        // hand-edited junk shouldn't crash the load path.
                        else -> {}
                    }
                }
            }
        }
        // Scalar form.
        val s = obj.optString(key, "")
        return if (s.isNotBlank()) listOf(DeploymentEntry(s, true)) else emptyList()
    }
}

/**
 * Default SNI rotation pool. Mirrors `DEFAULT_GOOGLE_SNI_POOL` from the
 * Rust `domain_fronter` module — keep the lists in sync, or leave the
 * user's sniHosts empty and let Rust auto-expand.
 */
val DEFAULT_SNI_POOL: List<String> =
    listOf(
        "www.google.com",
        "mail.google.com",
        "drive.google.com",
        "docs.google.com",
        "calendar.google.com",
        // accounts.google.com — originally listed as accounts.googl.com per
        // issue #42, but googl.com is NOT in Google's GFE cert SAN so TLS
        // validation fails with verify_ssl=true (PR #92). Replaced with
        // accounts.google.com which is covered by the *.google.com wildcard.
        "accounts.google.com",
        // Issue #47: same DPI-passing behaviour on MCI / Samantel.
        "scholar.google.com",
        // Ported from upstream Python FRONT_SNI_POOL_GOOGLE (commit 57738ec);
        // more rotation material for DPI-fingerprint spread and a couple of
        // SNIs (maps/play) that pass DPI where shorter *.google.com names don't.
        "maps.google.com",
        "chat.google.com",
        "translate.google.com",
        "play.google.com",
        "lens.google.com",
        // Issue #75.
        "chromewebstore.google.com",
    )
