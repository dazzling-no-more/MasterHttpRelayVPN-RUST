package com.dazzlingnomore.mhrv

/**
 * JNI bindings for the rahgozar Rust crate. The crate is compiled to
 * librahgozar.so and loaded at app start.
 *
 * All methods are blocking on a short-lived native call — the proxy itself
 * runs on a Rust-side tokio runtime, not on the JVM thread that calls in.
 * The returned handles are opaque to Kotlin; pass them back to stop() /
 * statsJson() / etc.
 *
 * Thread-safe: the underlying Rust side guards its state with a mutex.
 */
object Native {
    init {
        System.loadLibrary("rahgozar")
    }

    /**
     * Initialise rustls-platform-verifier with an Android Context.
     * MUST be called once per process before any TLS-touching code runs
     * — reqwest 0.13's cert verifier reaches into Android's KeyStore
     * via JNI to walk the device's trust anchors, and without this
     * init the very first TLS handshake aborts the process with
     * "Expect rustls-platform-verifier to be initialized".
     * Invoked from RahgozarApp.onCreate so all subsequent code paths
     * (Drive OAuth, proxy start, update check, etc.) are covered.
     * Idempotent: subsequent calls are no-ops.
     */
    external fun initAndroidTls(context: android.content.Context)

    /**
     * Tell the Rust side where to put config + CA + cache. Must be called
     * once before any other call. The path we hand over is our app's
     * private filesDir — guaranteed writable, auto-cleaned on uninstall.
     */
    external fun setDataDir(path: String)

    /**
     * Spin up the proxy. `configJson` is the full config.json contents as
     * a String. Returns the handle (positive) on success, or 0 on failure
     * (inspect logcat for the failure reason).
     */
    external fun startProxy(configJson: String): Long

    /**
     * Stop a running proxy. Idempotent: returns false if the handle is
     * unknown (e.g. already stopped).
     */
    external fun stopProxy(handle: Long): Boolean

    /**
     * Copy the MITM CA cert to a destination path. Used by the UI to
     * surface ca.crt in Downloads so the user can feed it to Android's
     * system "Install certificate" picker.
     */
    external fun exportCa(destPath: String): Boolean

    /** rahgozar crate version. Smoke test for JNI linkage. */
    external fun version(): String

    /**
     * Drain the in-memory log ring buffer (populated by the same tracing
     * subscriber that feeds logcat). Returns a `\n`-joined blob of any
     * events the UI hasn't seen yet, or an empty string.
     *
     * Cheap to call — the Kotlin side polls this on a timer. Single blob
     * instead of `String[]` because one JNI crossing is much faster than N.
     */
    external fun drainLogs(): String

    /**
     * Probe a single SNI against `googleIp`. Returns a JSON string of the
     * form `{"ok":true,"latencyMs":123}` on success or
     * `{"ok":false,"error":"..."}` on failure.
     *
     * BLOCKS (does a TLS handshake); call from a background dispatcher.
     */
    external fun testSni(
        googleIp: String,
        sni: String,
    ): String

    /**
     * Ask GitHub's Releases API whether a newer version of rahgozar is
     * out. Returns a JSON blob, one of:
     *   - `{"kind":"upToDate","current":"1.0.0","latest":"1.0.0"}`
     *   - `{"kind":"updateAvailable","current":"1.0.0","latest":"1.1.0","url":"https://...",`
     *     `"assetName":"...apk","assetUrl":"https://...","assetSize":12345}`
     *   - `{"kind":"offline","reason":"..."}`
     *   - `{"kind":"error","reason":"..."}`
     *
     * The `assetName/Url/Size` fields appear on `updateAvailable` when the
     * Rust-side picker matched a per-ABI APK in the release. The auto-
     * updater (UpdateInstaller.kt) uses these to fetch the right APK.
     *
     * BLOCKS (HTTPS round-trip); call from a background dispatcher.
     * Same check the desktop UI runs — same result format.
     */
    external fun checkUpdate(): String

    /**
     * Download a release asset (typically an APK) to `destPath` using the
     * Rust-side rustls client. Signed release builds also fetch and verify
     * the sibling `.minisig` before returning success. Returns a JSON blob:
     *   - `{"ok":true,"bytes":12345678}`
     *   - `{"ok":false,"error":"..."}`
     *
     * BLOCKS (large download); call from `Dispatchers.IO`.
     */
    external fun downloadAsset(
        url: String,
        destPath: String,
    ): String

    /**
     * Live traffic/usage counters for a running proxy handle. Returns a
     * JSON blob with the StatsSnapshot fields — or an empty string if the
     * handle is unknown or the proxy isn't using the Apps Script relay
     * (direct / full-only modes).
     *
     * Schema (all integer fields unless noted):
     *   relay_calls, relay_failures, coalesced, bytes_relayed,
     *   cache_hits, cache_misses, cache_bytes,
     *   blacklisted_scripts, total_scripts,
     *   today_calls, today_bytes, today_key (string "YYYY-MM-DD" in
     *     Pacific Time — matches Apps Script's actual quota reset),
     *   today_reset_secs (seconds until the next 00:00 Pacific Time
     *     rollover; ~7-8 h offset from UTC depending on DST),
     *   h2_calls (calls served by the HTTP/2 multiplexed transport,
     *     across all entry points — Apps-Script direct, exit-node
     *     outer call, full-mode tunnel single op, full-mode tunnel
     *     batch. NOT comparable to relay_calls, which only sees the
     *     Apps-Script-direct path),
     *   h2_fallbacks (calls that attempted h2 but had to fall back
     *     to h1 — handshake failure, open backoff, sticky ALPN
     *     refusal, post-send error retried on h1; same all-entry-
     *     points scope as h2_calls. Compute h2 health as
     *     h2_calls / (h2_calls + h2_fallbacks)),
     *   h2_disabled (boolean: true when h2 fast path is permanently
     *     off — config force_http1 set, or peer refused h2 via ALPN),
     *   forwarder_calls (successful upstream fetches via the
     *     SNI-rewrite forwarder — fast path for non-/youtubei/
     *     paths on `force_mitm_hosts`. Counted at upstream-success,
     *     before the downstream write to the browser, so a client
     *     disconnect mid-write still counts. Zero in non-AppsScript
     *     modes / when no `relay_url_patterns` host is in play),
     *   forwarder_bytes (response bytes successfully fetched by the
     *     forwarder; same upstream-fetch-success semantic as
     *     forwarder_calls),
     *   forwarder_errors (forwarder dispatch errors — connect failure,
     *     TLS error, read timeout, response cap exceeded. Distinct
     *     from relay_failures: this counts fast-path-only misses
     *     regardless of whether the relay-fallback then recovered the
     *     request. Combine with relay_failures to distinguish "fast
     *     path missed but request served" from "request failed
     *     end-to-end")
     *
     * Cheap — just reads atomics. Safe to poll on a second-scale timer.
     */
    external fun statsJson(handle: Long): String

    /**
     * Resolve `hostname` to its A/AAAA records and TLS-probe each
     * resolved IP with `SNI=hostname`. Returns a JSON blob the UI
     * can hand into a new fronting group without further parsing.
     *
     * Success shape:
     * ```
     * {"hostname":"python.org","ips":[
     *   {"ip":"151.101.0.223","ok":true,"latencyMs":45},
     *   {"ip":"...","ok":false,"error":"connect timeout"}
     * ]}
     * ```
     *
     * Failure shape (bad input, DNS timeout, etc.):
     * ```
     * {"hostname":"python.org","error":"dns: ..."}
     * ```
     *
     * BLOCKS for up to ~15s in the worst case (3s DNS timeout +
     * 3 probe waves of 4s each at 8-way concurrency over the
     * 24-IP cap). Typical case for a healthy CDN is well under 1s.
     * Always call from a background dispatcher.
     */
    external fun discoverFront(hostname: String): String

    /**
     * Pipeline debug overlay snapshot. Returns a JSON blob with elevated
     * session count, batch semaphore usage, and recent ramp/drop events.
     * Temporary — for debugging pipeline behavior on-device.
     */
    external fun pipelineDebugJson(): String

    /**
     * Start tun2proxy via its CLI args C API (`tun2proxy_run_with_cli_args`).
     * Resolved at runtime via dlsym from libtun2proxy.so — no fork needed.
     *
     * @param cliArgs full CLI string, e.g. "tun2proxy --proxy socks5://... --tun-fd 42 --udpgw-server 192.0.2.1:7300"
     * @param tunMtu TUN MTU (typically 1500)
     * @return 0 on normal shutdown, negative on error. BLOCKS.
     */
    external fun runTun2proxy(
        cliArgs: String,
        tunMtu: Int,
    ): Int

    /**
     * Stop tun2proxy by calling the plain-C `tun2proxy_stop` entry point
     * via dlsym (same `libtun2proxy.so` already mapped by `runTun2proxy`).
     *
     * Substitutes for the Kotlin-side `Tun2proxy.stop()` JNI shim that
     * the tun2proxy crate also exports. The Kotlin shim's first
     * reference triggers `Tun2proxy`'s `init { System.loadLibrary("tun2proxy") }`,
     * and on Samsung Android 16+ that load-during-teardown raced
     * libhwui's render-thread shutdown — `hwuiTask0` would FORTIFY-abort
     * ~1.8 s after disconnect on a destroyed mutex inside `libhwui.so`'s
     * BSS. Going through dlsym from native code skips the JVM-side
     * library load entirely.
     *
     * MUST be called on disconnect — without clearing tun2proxy's
     * global `TUN_QUIT` token, the next `runTun2proxy` returns -1
     * ("tun2proxy already started") immediately, the TUN fd leaks, and
     * Android keeps the VPN slot active (visible: VPN key icon stays
     * in status bar; `Service.onDestroy` is delayed ~18 s).
     *
     * @return 0 on a clean clear, -1 when no run was outstanding,
     *         -10 on dlopen failure, -11 on dlsym failure.
     */
    external fun stopTun2proxy(): Int

    // ── Drive-mode setup ──────────────────────────────────────────────
    //
    // Six entries that the Drive setup UI in HomeScreen.kt drives.
    // OAuth uses the device-code flow (RFC 8628) on Android because
    // Google's Desktop-app OAuth client type — which is what users
    // register per docs/drive_oauth_setup.md — does NOT permit custom
    // scheme redirects (`rahgozar://oauth/cb` would 400 with
    // `redirect_uri_mismatch`). The device-code flow has no inbound
    // URI to handle: the user opens the verification URL on any device,
    // enters the user_code, and Android polls until Google reports
    // approval.

    /**
     * Start an RFC 8628 device-code OAuth flow. Reads
     * `oauth_client_id` from `config.json::drive` (the BYO credential
     * the user pasted in the Drive setup screen) and POSTs
     * `oauth2.googleapis.com/device/code`. Returns:
     *
     *   `{"ok":true, "flow_token":"...", "user_code":"ABCD-EFGH",`
     *    `"verification_url":"https://www.google.com/device",`
     *    `"expires_in_secs":1800, "interval_secs":5}`
     *   `{"ok":false, "error":"..."}`
     *
     * The UI displays `user_code` + `verification_url` to the user
     * (with Open / Copy buttons), then polls `driveOauthPollFlow` at
     * `interval_secs` until completion. `flow_token` is the opaque
     * handle that identifies this in-flight flow on subsequent calls.
     *
     * BLOCKS for the device/code HTTP round-trip (~500 ms typical).
     * Call from a background dispatcher.
     */
    external fun driveOauthDeviceCodeStart(): String

    /**
     * Poll one iteration of the device-code flow. Hits Google's
     * `/token` endpoint with the device_code stashed against
     * `flowToken`. Outcomes:
     *
     *   `{"status":"pending"}`        — user hasn't entered code yet
     *   `{"status":"slow_down","interval_secs":N}` — back off & retry
     *   `{"status":"ok"}`             — refresh token persisted to config
     *   `{"status":"denied"}`         — user clicked Cancel on consent
     *   `{"status":"expired"}`        — device_code TTL exhausted
     *   `{"status":"transient_error","error":"..."}` — retry next tick
     *   `{"status":"error","error":"..."}`
     *   `{"status":"unknown"}`        — flow_token not in registry
     *
     * On `ok` the refresh token has already been written into
     * `config.json::drive::oauth_refresh_token`; the UI just needs to
     * re-read the config to flip its "Signed in" indicator.
     *
     * BLOCKS for one /token round-trip (~200 ms typical). Call from a
     * background dispatcher on the timer interval the previous response
     * returned.
     */
    external fun driveOauthPollFlow(flowToken: String): String

    /**
     * Drop an in-flight device-code flow. Called when the user taps
     * Cancel in the device-code dialog. No-op if the flow is already
     * complete or unknown. Returns `{"ok":true}` either way.
     *
     * NON-BLOCKING — just removes the entry from the in-memory registry.
     */
    external fun driveOauthCancelFlow(flowToken: String): String

    /**
     * `files.create` with the Drive folder MIME type, against the
     * OAuth account currently persisted in config.json. The UI
     * surfaces the returned folder ID by pasting it into the Drive
     * form's folder_id field. Result shape:
     *
     *   `{"ok": true,  "folder_id": "..."}`
     *   `{"ok": false, "error": "..."}`
     *
     * BLOCKS for the duration of the OAuth refresh + files.create
     * HTTP round-trips (~1 s typical). Call from a background thread.
     */
    external fun driveCreateFolder(name: String): String

    /**
     * OAuth refresh + `files.list` against the configured folder.
     * Confirms both that the saved refresh token still works AND
     * that the saved folder ID is reachable. Result shape:
     *
     *   `{"ok": true,  "folder_id": "...", "files_count": 42}`
     *   `{"ok": false, "error": "..."}`
     *
     * BLOCKS (~1 s typical). Call from a background thread.
     */
    external fun driveTestConnection(): String

    /**
     * Pure bech32m parse of the relay public key. Empty string on
     * success; human-readable error message on failure. The Drive
     * form calls this on every keystroke for live validation — the
     * IPC cost is negligible (pure compute, no I/O).
     */
    external fun driveValidateRelayPubkey(relayPubkey: String): String
}
