package com.dazzlingnomore.mhrv

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.github.shadowsocks.bg.Tun2proxy
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground VpnService that:
 *   1. Runs the rahgozar Rust proxy (HTTP + SOCKS5 on 127.0.0.1).
 *   2. Establishes a VPN TUN interface capturing all device traffic.
 *   3. Spawns tun2proxy in a background thread — it reads IP packets from
 *      the TUN fd, runs a userspace TCP/IP stack, and funnels every TCP/UDP
 *      flow through our local SOCKS5. Without step 3 the TUN captures
 *      traffic but nothing reads it → DNS_PROBE_STARTED in Chrome (the
 *      symptom that bit us on the first run).
 *
 * Loop-avoidance note: our own proxy's OUTBOUND connections to
 * google_ip:443 would normally be re-captured by the TUN ("traffic goes in
 * circles"). We break the loop by excluding this app's UID from the VPN
 * via `addDisallowedApplication(packageName)`. Everything else on the
 * device still gets routed through us.
 */
class RahgozarVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var proxyHandle: Long = 0L
    private var tun2proxyThread: Thread? = null

    // Per-generation worker-running flag. Each spawn assigns a FRESH
    // AtomicBoolean and the worker captures that same instance in its
    // finally — so a zombie worker from a previous generation (e.g. a
    // teardown's join() timed out, but the native code finally returns
    // many seconds later) clearing ITS captured flag does not poison
    // the field that a newer generation's teardown relies on. The
    // field itself is only read/written under lifecycleLock; the
    // workers only touch their captured local reference.
    private var tun2proxyRunning: AtomicBoolean = AtomicBoolean(false)
    private var debugOverlay: PipelineDebugOverlay? = null

    // Serialises startEverything() and runTeardown(). Without this, a
    // pause-then-stop or onDestroy-races-ACTION_STOP scenario could race
    // two threads through Tun2proxy.stop() / fd.close() / Native.stopProxy()
    // on a not-yet-nulled handle — the same SIGSEGV-or-zombie source #700
    // hit historically. Inside the lock the field-nulling pattern is
    // idempotent: second caller reads already-cleared state and no-ops.
    private val lifecycleLock = Any()

    // All three lifecycle flags (paused / starting / stop-requested) live
    // on a small extracted helper so the decision matrix is unit-testable
    // end-to-end (see VpnLifecycleGuardsTest) without spinning up the
    // Service. See VpnLifecycleGuards' kdoc for the rationale.
    private val guards = VpnLifecycleGuards()

    // CAS-claimed by the first runTeardown caller so subsequent
    // concurrent callers (onDestroy racing ACTION_STOP, a stop racing a
    // pause's own teardown) skip immediately instead of blocking on
    // lifecycleLock. Reset in finally so the next genuine teardown
    // cycle works. NOT a replacement for lifecycleLock — start↔teardown
    // still synchronizes there.
    private val teardownInProgress = AtomicBoolean(false)

    // Ports remembered from the last startEverything so we can rebuild
    // the notification (paused state / non-Apps-Script fallback line)
    // without re-loading ConfigStore.
    private var lastHttpPort: Int = 0
    private var lastSocks5Port: Int = 0

    // 2-second poll that refreshes the running-state notification with
    // live `today_calls` / `today_bytes` from Native.statsJson. Posted on
    // the main looper — Native.statsJson is documented as cheap (atomic
    // reads only). Stopped on pause and on teardown.
    //
    // notifTickerActive is AtomicBoolean (not plain Boolean) because
    // stop is called from worker threads (rahgozar-pause, rahgozar-teardown)
    // while the runnable executes on the main thread — without atomic
    // visibility, an in-flight tick could read a stale `true` and
    // reschedule itself even after stop has run. The runnable double-
    // checks the flag at entry (before notify) AND before its own
    // postDelayed self-reschedule.
    private val notifHandler = Handler(Looper.getMainLooper())
    private val notifTickerActive = AtomicBoolean(false)
    private val notifTicker =
        object : Runnable {
            override fun run() {
                if (!notifTickerActive.get()) return
                if (guards.isPaused || proxyHandle == 0L) return
                try {
                    val statsBlob = Native.statsJson(proxyHandle)
                    // Pipeline debug JSON is cheap (atomics + a small
                    // HashMap snapshot) and only changes shape based on
                    // the cargo `pipeline-debug` feature flag — release
                    // builds get a stable empty payload. Poll it on the
                    // same cadence so the UI's PipelineDebugCard can
                    // observe it via VpnStateSync without a second
                    // ticker.
                    val pipelineBlob = runCatching { Native.pipelineDebugJson() }.getOrDefault("")
                    // Mirror the latest snapshot to the UI process. The
                    // `:vpn` service can't share a singleton StateFlow
                    // with the UI process, so each tick rebroadcasts.
                    // 2 s cadence matches the notification refresh — the
                    // UI cards observe the same data without polling
                    // Native themselves (Native.statsJson called from
                    // the UI process would have no live proxy handle to
                    // read against anyway).
                    broadcastVpnState(
                        running = true,
                        handle = proxyHandle,
                        statsJson = statsBlob,
                        pipelineJson = pipelineBlob,
                    )
                    if (statsBlob.isBlank()) {
                        // Native.statsJson returns blank in any mode
                        // that doesn't run the Apps Script relay —
                        // DIRECT and LOCAL_BYPASS today, plus any
                        // future cred-free mode — and so has no
                        // today_calls / today_bytes to show. The
                        // blank state is permanent for the lifetime
                        // of the handle, so polling every 2s is pure
                        // waste (JNI + PendingIntent rebuild +
                        // notify). The static ports notification
                        // posted at startForeground is the right
                        // thing for those modes; stop the ticker.
                        Log.i(TAG, "notifTicker: blank stats (non-relay mode), stopping ticker")
                        stopNotifTicker()
                        return
                    }
                    val notif = buildNotif(NotifState.RUNNING, statsBlob)
                    getSystemService(NotificationManager::class.java)?.notify(NOTIF_ID, notif)
                } catch (t: Throwable) {
                    Log.w(TAG, "notif tick: ${t.message}")
                }
                // Re-check before reposting: a stop() that races us
                // between entry and now should not get a fresh tick on
                // the queue that removeCallbacks already missed.
                if (notifTickerActive.get()) {
                    notifHandler.postDelayed(this, NOTIF_REFRESH_MS)
                }
            }
        }

    private enum class NotifState { RUNNING, PAUSED }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action ?: "<null>"} startId=$startId")
        return when (intent?.action) {
            ACTION_STOP -> {
                // Sticky-true the stop flag IMMEDIATELY. Any in-flight
                // rahgozar-pause thread that's still inside runTeardown
                // will see this when it reaches its post-teardown
                // "paint paused notif" gate, and skip the notify ---
                // without it, pause+stop arriving in quick succession
                // could let pause's notify resurrect an "ongoing
                // paused" notification AFTER stopForeground removed
                // the foreground one (same NOTIF_ID, but now untied
                // to a service => persists past stopSelf).
                guards.requestStop()
                // Halt the 2-second stats ticker FIRST. If we did
                // stopForeground first and a tick fired in the window
                // before runTeardown reached its own stopNotifTicker
                // call, notify(NOTIF_ID, ...) would resurrect the
                // ongoing notification right after Stop. Tearing down
                // the ticker before dropping foreground closes that
                // window. (The runTeardown call below stops the
                // ticker again --- that's a no-op on the AtomicBoolean.)
                stopNotifTicker()
                // Drop foreground SECOND — that's what makes the status-bar
                // key icon disappear and lets the user see "Stop worked"
                // even if the native teardown below takes a few seconds
                // (e.g. a dozen in-flight Apps Script requests stuck in
                // their 30s timeout). The service itself stays alive until
                // stopSelf + the background thread below finish.
                try {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } catch (t: Throwable) {
                    Log.w(TAG, "stopForeground: ${t.message}")
                }
                // Teardown can block on native shutdown (rt.shutdown_timeout
                // is 5s max, plus 2s for the tun2proxy join). Do it off the
                // main thread so we don't ANR.
                Thread({
                    runTeardown()
                    // Belt-and-suspenders cancel: if any path (a racing
                    // rahgozar-pause whose teardown overlapped with us, a
                    // straggler tick, an upstream side-channel) managed
                    // to post NOTIF_ID after stopForeground removed it,
                    // explicitly cancel here so the user doesn't see a
                    // dangling notification on a dead service.
                    try {
                        getSystemService(NotificationManager::class.java)?.cancel(NOTIF_ID)
                    } catch (t: Throwable) {
                        Log.w(TAG, "post-stop cancel: ${t.message}")
                    }
                    stopSelf()
                    Log.i(TAG, "teardown done, service stopping")
                }, "rahgozar-teardown").start()
                START_NOT_STICKY
            }

            ACTION_PAUSE -> {
                // Decision matrix lives in VpnLifecycleGuards so the
                // race outcomes (pause-while-stopping, double-pause) are
                // exercised by VpnLifecycleGuardsTest rather than only
                // manually verified.
                when (guards.tryPause()) {
                    VpnLifecycleGuards.PauseDecision.STOPPING -> {
                        Log.i(TAG, "Pause: stop already requested, ignoring")
                        return START_NOT_STICKY
                    }

                    VpnLifecycleGuards.PauseDecision.ALREADY_PAUSED -> {
                        Log.i(TAG, "Pause: already paused, ignoring")
                        return START_NOT_STICKY
                    }

                    VpnLifecycleGuards.PauseDecision.PROCEED -> {}
                }
                // Tear native down (proxy + tun2proxy + TUN fd) but leave
                // the foreground service alive so the notification with
                // the Resume action stays in the status bar. The whole
                // body holds lifecycleLock --- JVM monitors are reentrant
                // so the inner synchronized in runTeardown re-enters
                // fine. The lock spans the PAUSED notify so a racing
                // Resume can't slip in between teardown and paint and
                // leave the user staring at a "Paused" notification on
                // a service that's actually running. The stopRequested
                // gate inside the lock makes sure a racing Stop wins
                // outright --- pause won't repaint an ongoing notif
                // after stopForeground has removed it.
                Thread({
                    synchronized(lifecycleLock) {
                        val tornDownAnything = runTeardown()
                        // Three gates on the paused-notif post. Each
                        // closes a real race seen in review:
                        //   1. Stop was requested during teardown:
                        //      ACTION_STOP's rahgozar-teardown is queued
                        //      behind us and will cancel(NOTIF_ID)
                        //      next; we must not paint a "Paused"
                        //      that out-lives the service.
                        //   2. pausedFlag was cleared (concurrent
                        //      Resume / Connect-from-app called
                        //      tryStart, which atomically clears it
                        //      as part of claiming the starting
                        //      slot): a paint here would lie about
                        //      state and dead the Resume button.
                        //   3. No native state was actually present:
                        //      a stale PAUSE intent or a Pause
                        //      arriving on a service that failed
                        //      startup. A "Paused" claim would
                        //      strand the user on a service that's
                        //      not even running.
                        if (guards.isStopRequested) {
                            Log.i(TAG, "Pause: stop requested mid-teardown, skipping paused notif")
                            return@synchronized
                        }
                        if (!guards.isPaused) {
                            Log.i(TAG, "Pause: paused flag cleared mid-teardown (resume in flight), skipping paused notif")
                            return@synchronized
                        }
                        if (!tornDownAnything) {
                            Log.i(TAG, "Pause: no native state to tear down, skipping paused notif")
                            // Also reset pausedFlag — we accepted the
                            // intent but did nothing with it, so a
                            // future Resume tap would otherwise see
                            // PROCEED on a service with nothing to
                            // resume. Treat it as if Pause was a
                            // no-op.
                            guards.cancelPausedIntent()
                            // Stale PAUSE PendingIntent on a fresh /
                            // idle service: release the started claim
                            // so the service can die instead of
                            // sticking around invisibly. No-ops if a
                            // run/start is in flight.
                            stopSelfIfIdle()
                            return@synchronized
                        }
                        try {
                            val notif = buildNotif(NotifState.PAUSED)
                            getSystemService(NotificationManager::class.java)?.notify(NOTIF_ID, notif)
                        } catch (t: Throwable) {
                            Log.w(TAG, "paused notif: ${t.message}")
                        }
                    }
                    Log.i(TAG, "Pause complete")
                }, "rahgozar-pause").start()
                // START_NOT_STICKY (not STICKY) — if Android kills a
                // paused service for memory, we do NOT want a sticky
                // restart that fires onStartCommand with a null intent,
                // because that would fall through to the connect/else
                // branch and reconnect the proxy without the user asking.
                // Paused means paused; resurrection requires an explicit
                // user action.
                START_NOT_STICKY
            }

            ACTION_RESUME -> {
                when (guards.tryResume()) {
                    VpnLifecycleGuards.ResumeDecision.STOPPING -> {
                        Log.i(TAG, "Resume: stop already requested, ignoring")
                        return START_NOT_STICKY
                    }

                    VpnLifecycleGuards.ResumeDecision.NOT_PAUSED -> {
                        Log.i(TAG, "Resume: not paused, ignoring")
                        // Stale RESUME PendingIntent on a fresh / idle
                        // service: release the started claim so we
                        // don't strand an invisible sticky service.
                        // No-ops if a real run/start/pause is in
                        // flight.
                        stopSelfIfIdle()
                        return START_NOT_STICKY
                    }

                    VpnLifecycleGuards.ResumeDecision.PROCEED -> {}
                }
                spawnStart("rahgozar-resume")
                START_STICKY
            }

            else -> {
                // Connect from app. spawnStart's tryStart figures out
                // the paused→running transition atomically when it
                // claims the starting slot (wasPaused captured at
                // entry, pausedFlag cleared on claim). No explicit
                // clearPaused call here --- doing so up-front races a
                // concurrent ACTION_RESUME and causes the second
                // tryStart to misread ALREADY_RUNNING. The
                // startForeground call inside startEverything still
                // fires well within Android's 5s budget --- the
                // worker thread reaches it in milliseconds.
                spawnStart("rahgozar-start")
                START_STICKY
            }
        }
    }

    /**
     * Release the "started" claim on the service when an action turned
     * out to be a no-op AND nothing is preserving the service's reason
     * to live. Without this, a stale Pause/Resume PendingIntent that
     * happens to land on a fresh service instance (process respawn,
     * stale notification surviving an uninstall+reinstall, etc.) leaves
     * the service "started" with no foreground notification, no native
     * work, and a sticky restart flag — an invisible zombie.
     */
    private fun stopSelfIfIdle() {
        if (guards.shouldStopSelfIfIdle(isRunning = VpnState.isRunning.value)) {
            Log.i(TAG, "stopSelfIfIdle: no live work, stopping service")
            stopSelf()
        }
    }

    /**
     * Spawn startEverything on a worker thread, coalescing double-taps.
     * Returns immediately. The full decision matrix (stop-already-
     * requested / already-running / start-in-flight / proceed) lives in
     * [VpnLifecycleGuards.tryStart] so the four-way outcome is unit-
     * testable in isolation.
     */
    private fun spawnStart(threadName: String) {
        when (guards.tryStart(isRunning = VpnState.isRunning.value)) {
            VpnLifecycleGuards.StartDecision.STOPPING -> {
                Log.i(TAG, "$threadName: stop already requested, ignoring")
                return
            }

            VpnLifecycleGuards.StartDecision.ALREADY_RUNNING -> {
                Log.i(TAG, "$threadName: already running, ignoring")
                return
            }

            VpnLifecycleGuards.StartDecision.ALREADY_STARTING -> {
                Log.i(TAG, "$threadName: start already in flight, ignoring")
                return
            }

            VpnLifecycleGuards.StartDecision.PROCEED -> {}
        }
        Thread({
            try {
                startEverything()
            } finally {
                // Reset regardless of success/failure so the next genuine
                // Connect (e.g. after a stop or pause) is allowed through.
                guards.finishStart()
            }
        }, threadName).start()
    }

    private fun startEverything() =
        synchronized(lifecycleLock) {
            // Post-launch stop check. spawnStart() checked stopRequested
            // before launching us, but the OS can delay the worker thread's
            // first instruction long enough for an ACTION_STOP / onDestroy
            // to slip in between the spawn and now. If teardown already
            // ran (saw empty state, returned quickly) and released the
            // lock before we got it, we MUST NOT proceed --- otherwise
            // startForeground + Native.startProxy below would resurrect
            // a service the user already Stopped.
            if (guards.isStopRequested) {
                Log.i(TAG, "startEverything: stop requested before startup, skipping")
                return
            }

            // 1) Seed native with our app's private dir and boot the proxy.
            Native.setDataDir(filesDir.absolutePath)

            val cfg = ConfigStore.load(this)

            // Android 8+ requires every service started via
            // `startForegroundService()` to call `startForeground()` within a
            // short window or the system crashes the app with
            // `ForegroundServiceDidNotStartInTimeException`. Every `stopSelf()`
            // path below MUST therefore happen after a `startForeground()`
            // call — otherwise the user-visible symptom is "the app crashes
            // the instant I tap Start". See issue #73.
            // Issue #211: notification used to display
            // `127.0.0.1:${listenPort + 1}` for the SOCKS5 port, which is
            // wrong whenever socks5Port doesn't equal listenPort+1. With the
            // default Android config (listenPort=8080, socks5Port=1081)
            // users saw "Routing via SOCKS5 127.0.0.1:8081" but the real
            // listener was on 1081 — so per-app SOCKS5 setup against the
            // notification value silently failed. Pass the actual socks5Port
            // (after the same elvis fallback used elsewhere) so the
            // notification matches reality.
            val notifSocks5Port = cfg.socks5Port ?: (cfg.listenPort + 1)
            // Remember the ports so a later pause / non-Apps-Script-mode
            // notification rebuild can render the fallback ports line
            // without re-loading the config.
            lastHttpPort = cfg.listenPort
            lastSocks5Port = notifSocks5Port
            // Empty statsJson on first paint — the 2s ticker overwrites with
            // live counters as soon as the proxy is up. For non-Apps-Script
            // modes (direct / full-only) the statsJson stays "" forever and
            // the notification keeps showing the ports line.
            startForeground(NOTIF_ID, buildNotif(NotifState.RUNNING, statsJson = ""))

            // Preflight the mode-specific requirements before handing
            // control to Rust. This mirrors the Connect button gate and
            // keeps foreground-service startup failures explicit.
            if (!cfg.canStartCurrentMode) {
                Log.e(TAG, "Config is incomplete for ${cfg.mode}")
                try {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } catch (_: Throwable) {
                }
                stopSelf()
                return
            }

            // Defensive teardown: if a previous startEverything left state
            // behind (handle, tun2proxy worker, or open TUN fd), tear it ALL
            // down before re-starting. Releasing only proxyHandle here used
            // to leak the tun2proxy worker thread and corrupt tun2proxyRunning
            // for the fresh worker; runTeardown's serialised sequence drops
            // every field together. Reentrant on lifecycleLock — JVM monitors
            // allow nested entries by the same thread, so this works while
            // we already hold the lock at the top of startEverything.
            if (proxyHandle != 0L || tun != null || tun2proxyThread != null) {
                Log.w(
                    TAG,
                    "startEverything: stale state " +
                        "(handle=$proxyHandle, tun=${tun != null}, t2p=${tun2proxyThread != null}); " +
                        "tearing down before restart",
                )
                runTeardown()
                // Re-check stop AFTER the stale-state teardown. An
                // ACTION_STOP arriving DURING this teardown would have
                // hit teardownInProgress, skipped its own runTeardown,
                // and still called cancel(NOTIF_ID) + stopSelf. Without
                // this recheck, we'd happily continue into Native.startProxy
                // / startForeground and bring the VPN back up on a service
                // the user already Stopped.
                if (guards.isStopRequested) {
                    Log.i(TAG, "startEverything: stop requested during stale-state teardown, aborting")
                    return
                }
            }

            proxyHandle = Native.startProxy(cfg.toJson())
            if (proxyHandle == 0L) {
                Log.e(TAG, "Native.startProxy returned 0 — see logcat tag rahgozar")
                try {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } catch (_: Throwable) {
                }
                stopSelf()
                return
            }

            val socks5Port = cfg.socks5Port ?: (cfg.listenPort + 1)

            // PROXY_ONLY mode: the user wants just the 127.0.0.1 HTTP + SOCKS5
            // listeners up, with no VpnService / no TUN. Typical reasons:
            // another VPN app already owns the system VPN slot, the user
            // wants per-app opt-in via Wi-Fi proxy settings, or the device
            // is a sandboxed/rooted setup where VpnService is unwelcome.
            // We already called startForeground() at the top of this method,
            // which is all PROXY_ONLY needs for the listener thread to survive
            // backgrounding. Issue #37.
            if (cfg.connectionMode == ConnectionMode.PROXY_ONLY) {
                Log.i(TAG, "PROXY_ONLY mode: listeners up, skipping VpnService/TUN")
                VpnState.setProxyHandle(proxyHandle)
                VpnState.setRunning(true)
                broadcastVpnState(running = true, handle = proxyHandle)
                showDebugOverlay()
                startNotifTicker()
                return
            }

            // 2) Establish the TUN. Key Builder calls:
            //    - addAddress(10.0.0.2/32): our local IP inside the tunnel.
            //    - addRoute(0.0.0.0/0): capture ALL IPv4 traffic. IPv6 isn't added,
            //      so v6 leaks stay up the normal route — fine for this app.
            //    - addDnsServer(1.1.1.1): DNS queries go to this IP, which ALSO
            //      hits our TUN — tun2proxy intercepts in Virtual DNS mode.
            //    - addDisallowedApplication(packageName): our OWN outbound
            //      connections bypass the TUN. Without this, the proxy's
            //      outbound to google_ip loops back through the TUN forever.
            //    - setBlocking(false): we're going to hand the fd to tun2proxy,
            //      which does its own async I/O.
            val builder =
                Builder()
                    .setSession("rahgozar")
                    .setMtu(MTU)
                    .addAddress("10.0.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1")
                    .setBlocking(false)

            // Apply user-chosen app splitting. The VpnService API treats
            // addAllowedApplication and addDisallowedApplication as mutually
            // exclusive — calling both on one Builder throws
            // IllegalArgumentException at establish() time, which is the bug
            // that manifested as "ONLY mode tunnels everything" (establish()
            // failed silently and the fallback never routed correctly).
            //
            // ALL / EXCEPT: add the mandatory self-exclude (packageName) via
            // addDisallowedApplication so our own proxy's outbound to
            // google_ip doesn't loop through the TUN.
            // ONLY: self-exclusion is implicit — we're not in the allow-list.
            //
            // Packages that are not installed (leftover selections from a
            // previous device) throw PackageManager.NameNotFoundException —
            // we log and skip rather than aborting the whole VPN start.
            when (cfg.splitMode) {
                SplitMode.ALL -> {
                    try {
                        builder.addDisallowedApplication(packageName)
                    } catch (e: Throwable) {
                        Log.w(TAG, "addDisallowedApplication(self) failed: ${e.message}")
                    }
                }

                SplitMode.ONLY -> {
                    if (cfg.splitApps.isEmpty()) {
                        Log.w(TAG, "ONLY mode with empty splitApps list — no app would get the VPN; falling back to ALL")
                        try {
                            builder.addDisallowedApplication(packageName)
                        } catch (_: Throwable) {
                        }
                    } else {
                        var allowed = 0
                        for (pkg in cfg.splitApps) {
                            if (pkg == packageName) continue // can't tunnel ourselves
                            try {
                                builder.addAllowedApplication(pkg)
                                allowed++
                            } catch (e: Throwable) {
                                Log.w(TAG, "addAllowedApplication($pkg) failed: ${e.message}")
                            }
                        }
                        if (allowed == 0) {
                            Log.w(TAG, "ONLY mode had no usable apps — falling back to ALL")
                            try {
                                builder.addDisallowedApplication(packageName)
                            } catch (_: Throwable) {
                            }
                        }
                    }
                }

                SplitMode.EXCEPT -> {
                    try {
                        builder.addDisallowedApplication(packageName)
                    } catch (e: Throwable) {
                        Log.w(TAG, "addDisallowedApplication(self) failed: ${e.message}")
                    }
                    for (pkg in cfg.splitApps) {
                        if (pkg == packageName) continue // already self-excluded above
                        try {
                            builder.addDisallowedApplication(pkg)
                        } catch (e: Throwable) {
                            Log.w(TAG, "addDisallowedApplication($pkg) failed: ${e.message}")
                        }
                    }
                }
            }

            val parcelFd =
                try {
                    builder.establish()
                } catch (t: Throwable) {
                    Log.e(TAG, "VpnService.establish() failed: ${t.message}")
                    null
                }

            if (parcelFd == null) {
                Log.e(TAG, "establish() returned null — is VPN permission granted?")
                Native.stopProxy(proxyHandle)
                proxyHandle = 0L
                try {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } catch (_: Throwable) {
                }
                stopSelf()
                return
            }
            tun = parcelFd

            // 3) Start tun2proxy on a worker thread. It blocks until stop() or
            //    shutdown. We detach the fd so ownership transfers cleanly to
            //    tun2proxy (closeFdOnDrop = true closes it on return from run()).
            //    The ParcelFileDescriptor (`tun`) we keep is post-detach — its
            //    own close() is a no-op for the underlying fd, so the worker is
            //    the sole owner once it's running.
            val detachedFd = parcelFd.detachFd()
            // Fresh per-generation running flag. The worker captures THIS
            // instance and only mutates it in its finally; field-level
            // tun2proxyRunning is reassigned so older generations'
            // zombie workers can't write through it.
            val workerRunning = AtomicBoolean(true)
            tun2proxyRunning = workerRunning
            // Use tun2proxy_run_with_cli_args C API via dlsym — gives full
            // CLI flexibility including --udpgw-server, no fork needed.
            val cliArgs =
                buildString {
                    append("tun2proxy")
                    append(" --proxy socks5://127.0.0.1:$socks5Port")
                    append(" --tun-fd $detachedFd")
                    append(" --dns virtual")
                    append(" --verbosity info")
                    append(" --close-fd-on-drop true")
                    if (cfg.mode == Mode.FULL) append(" --udpgw-server $UDPGW_MAGIC_DEST")
                }
            val worker =
                Thread({
                    try {
                        val rc = Native.runTun2proxy(cliArgs, MTU)
                        Log.i(TAG, "tun2proxy exited rc=$rc")
                    } catch (t: Throwable) {
                        Log.e(TAG, "tun2proxy crashed: ${t.message}", t)
                    } finally {
                        // Touch only OUR captured AtomicBoolean. The field
                        // tun2proxyRunning may point to a newer generation
                        // by the time we get here (teardown's join timed
                        // out, then a Resume/Connect spawned a fresh
                        // worker); writing through it would silently fool
                        // that generation's teardown into skipping
                        // Tun2proxy.stop().
                        workerRunning.set(false)
                    }
                }, "tun2proxy")
            try {
                worker.start()
                tun2proxyThread = worker
            } catch (t: Throwable) {
                // Thread.start can throw OutOfMemoryError under extreme memory
                // pressure. The fd we just detached has no owner — without an
                // explicit close it leaks for the life of the process. Adopt
                // it into a fresh ParcelFileDescriptor purely so we can call
                // close() on it.
                Log.e(TAG, "tun2proxy thread start failed: ${t.message}", t)
                workerRunning.set(false)
                try {
                    ParcelFileDescriptor.adoptFd(detachedFd).close()
                } catch (closeErr: Throwable) {
                    Log.w(TAG, "adoptFd($detachedFd).close failed: ${closeErr.message}")
                }
                Native.stopProxy(proxyHandle)
                proxyHandle = 0L
                try {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } catch (_: Throwable) {
                }
                stopSelf()
                return
            }

            // (startForeground was already called at the top of this method
            // to satisfy Android 8+'s foreground-service contract — see the
            // comment at the start of startEverything. Calling it here again
            // would be a no-op but wasteful.)

            // Publish "running" state for the UI's Connect/Disconnect button
            // to observe. Only flipped true once everything above succeeded —
            // if we'd flipped it earlier the button would light up green for
            // a failed-to-establish run.
            VpnState.setProxyHandle(proxyHandle)
            VpnState.setRunning(true)
            broadcastVpnState(running = true, handle = proxyHandle)
            showDebugOverlay()
            startNotifTicker()
        }

    private fun showDebugOverlay() {
        // Pipelining-debug overlay is a development affordance only.
        // Release builds skip it entirely so end-users never hit the
        // SYSTEM_ALERT_WINDOW prompt (no user benefit, and Play Console
        // flags the permission as sensitive). Strip via BuildConfig.DEBUG
        // — the JIT/R8 elides the rest of the body in release.
        if (!BuildConfig.DEBUG) return
        if (debugOverlay != null) return
        if (!android.provider.Settings.canDrawOverlays(this)) {
            Log.w(TAG, "overlay permission not granted — skipping debug overlay")
            return
        }
        // wm.addView must run on the main looper (Looper.getMainLooper()):
        // WindowManager rejects view ops from arbitrary threads on most
        // OEM builds. startEverything() runs on a worker thread because
        // it does blocking JNI, so we post here.
        //
        // Store the overlay reference *before* posting show(): teardown
        // (cleanupEverything) may run on the worker thread between the
        // post and its execution, and it needs to be able to call hide()
        // on whatever overlay instance we constructed — even if show()
        // hasn't attached the view yet. PipelineDebugOverlay's `torn`
        // flag handles the late-show case (a hide() before show() makes
        // the subsequent show() a no-op + tears down the poll thread).
        // We also drop the reference if show() failed, so a one-time
        // addView failure doesn't suppress a future retry attempt.
        val overlay = PipelineDebugOverlay(this)
        debugOverlay = overlay
        Handler(Looper.getMainLooper()).post {
            if (!overlay.show() && debugOverlay === overlay) {
                debugOverlay = null
            }
        }
    }

    /**
     * Tear down the native side of this service (Rust proxy, tun2proxy
     * worker, TUN fd) and return whether anything was actually freed.
     *
     * Two safety mechanisms layered here:
     *   - A `teardownInProgress` CAS makes a second concurrent caller
     *     bail FAST instead of blocking. onDestroy specifically uses
     *     this: it runs on the main thread, and the OS expects it to
     *     return quickly — without the fast path it could wait many
     *     seconds for a worker's Native.stopProxy / Tun2proxy.stop /
     *     thread-join budget to drain.
     *   - The `synchronized(lifecycleLock)` inside [runTeardownLocked]
     *     is the start↔teardown mutex: startEverything MUST wait for
     *     an in-flight teardown before doing native work, even if a
     *     second teardown-caller is skipping.
     *
     * Does NOT call stopSelf — the caller decides whether this is a
     * transient teardown (ACTION_PAUSE: service stays alive in
     * foreground for a later Resume) or a final stop (ACTION_STOP /
     * onDestroy: caller follows up with stopSelf).
     *
     * Returns true if this call actually freed native state (proxy
     * handle, TUN fd, or tun2proxy thread); false if it short-circuited
     * (concurrent teardown in progress) OR found nothing to free (stale
     * PAUSE intent on a service that never reached running, no-op
     * second pass on already-cleared state). Callers use this to skip
     * posting state-claiming notifications (e.g. paused-state notif)
     * when nothing was actually paused.
     */
    private fun runTeardown(): Boolean {
        if (!teardownInProgress.compareAndSet(false, true)) {
            Log.i(
                TAG,
                "teardown: already in progress on another thread, skipping " +
                    "(caller=${Thread.currentThread().name})",
            )
            return false
        }
        try {
            return runTeardownLocked()
        } finally {
            teardownInProgress.set(false)
        }
    }

    /**
     * Body of the teardown sequence, run while holding [lifecycleLock]
     * so startEverything cannot interleave native work with us.
     *
     * Shutdown order matters. Doing it wrong (we did originally) leaves
     * tun2proxy still forwarding packets into a half-dead Rust runtime
     * while the runtime is force-aborting its tasks — that's the scenario
     * that manifested as "Stop crashes the app" (issue #700) when there
     * were in-flight relay requests piled up against a dead Apps Script
     * deployment.
     *
     * Steps, with the bound on each one called out so a hung native
     * call cannot stall the whole teardown thread:
     *   1. Shut down the Rust proxy FIRST. Closing the listening
     *      SOCKS5 socket is what makes tun2proxy's worker thread's
     *      blocking read return — we have no other lever to wake it.
     *      Bounded by `rt.shutdown_timeout(3s)` Rust-side.
     *   2. Signal tun2proxy to stop (cooperative). Mostly redundant
     *      after step 1, covers any future code path where the worker
     *      is blocked on something other than its upstream socket
     *      (e.g. a smoltcp internal queue waiting on a wake). Bounded
     *      by a 2s side-thread join.
     *   3. Drop our ParcelFileDescriptor reference. Because we already
     *      called detachFd() at startup, this is a no-op for the
     *      underlying fd — the worker (closeFdOnDrop=true) owns it.
     *      Kept only so PROXY_ONLY / failed-establish paths null the
     *      field cleanly.
     *   4. Join the tun2proxy thread, bounded at 4s. With step 1
     *      having already closed its upstream socket, the join almost
     *      always completes well under deadline.
     *
     * History (#700 from @ilok67): the original order was
     * tun2proxy → tun.close → join → stopProxy. That ordering
     * SIGSEGV'd ~2s after Disconnect because Native.stopProxy() freed
     * the Rust runtime (including the SOCKS5 listener) while
     * tun2proxy's worker was still in a blocking native read against
     * it — classic use-after-free. Native.stopProxy cannot forcibly
     * terminate a separate native thread; it only frees memory the
     * other thread is still using. Reversing the order makes the
     * worker's blocking read return EOF, the worker exits through its
     * own error path, and the join just confirms a clean shutdown.
     */
    private fun runTeardownLocked(): Boolean =
        synchronized(lifecycleLock) {
            // Capture whether any native state actually exists BEFORE we
            // start nulling fields. The pause body uses this to skip the
            // "Paused" notification when teardown was a no-op (stale PAUSE
            // intent, pause arriving after a failed startup, etc.).
            val hadNativeState = proxyHandle != 0L || tun != null || tun2proxyThread != null
            // Inside lifecycleLock a concurrent caller sees fully-cleared
            // state (proxyHandle=0, tun=null, tun2proxyThread=null) and
            // every step below short-circuits on null/zero checks. That's
            // the protection against the #700 double-free: without
            // serialisation two threads could each read proxyHandle=X
            // before either nulled it and both call Native.stopProxy(X).
            Log.i(
                TAG,
                "teardown: begin caller=${Thread.currentThread().name} " +
                    "(tun2proxy running=${tun2proxyRunning.get()}, proxyHandle=$proxyHandle)",
            )

            // Halt the notification stats poll first so it doesn't try to call
            // Native.statsJson() on a handle we're about to free.
            stopNotifTicker()

            // 1. Stop the Rust proxy FIRST. Closing the SOCKS5 listener is
            //    what makes tun2proxy's worker thread's blocking read return
            //    — without this the worker stays in native code and a later
            //    Native.stopProxy would race it into use-after-free (#700).
            val handle = proxyHandle
            proxyHandle = 0L
            if (handle != 0L) {
                Log.i(TAG, "teardown: stopping proxy handle=$handle")
                try {
                    Native.stopProxy(handle)
                } catch (t: Throwable) {
                    Log.e(TAG, "Native.stopProxy threw: ${t.message}", t)
                }
            }

            // 2. Cooperative stop signal — REQUIRED to clear tun2proxy's
            //    process-global `TUN_QUIT` cancellation token. Without it,
            //    the next `runTun2proxy` short-circuits with rc=-1
            //    ("tun2proxy already started"), the TUN fd leaks, Android
            //    holds the VPN slot, and the status-bar VPN key icon
            //    stays visible after disconnect.
            //
            //    We deliberately DO NOT call `Tun2proxy.stop()` here —
            //    that Kotlin object's first reference triggers its
            //    `init { System.loadLibrary("tun2proxy") }`, and on
            //    Samsung Android 16+ that load-during-teardown races
            //    libhwui's render-thread shutdown: ~1.8 s after
            //    disconnect, `hwuiTask0` FORTIFY-aborts on a destroyed
            //    mutex inside libhwui.so's BSS. We confirmed via
            //    /proc/self/maps that the mutex address is owned by
            //    libhwui, not by us — the trigger is some interaction
            //    between the JVM-side library load and libhwui's static
            //    teardown.
            //
            //    `Native.stopTun2proxy()` reaches the same
            //    `general_api::tun2proxy_stop_internal` via dlsym from
            //    inside librahgozar.so (libtun2proxy.so is already mapped
            //    by `runTun2proxy`'s dlsym path), so there's no JVM-side
            //    library load and no `Tun2proxy` class init. The libhwui
            //    abort does not fire on this path. Bounded on a side
            //    thread so a hung native call can't stall teardown.
            if (tun2proxyRunning.get()) {
                val stopper =
                    Thread({
                        try {
                            val rc = Native.stopTun2proxy()
                            Log.i(TAG, "Native.stopTun2proxy: rc=$rc")
                        } catch (t: Throwable) {
                            Log.w(TAG, "Native.stopTun2proxy: ${t.message}")
                        }
                    }, "rahgozar-tun2proxy-stop").apply { start() }
                try {
                    stopper.join(2_000)
                } catch (_: InterruptedException) {
                }
                if (stopper.isAlive) {
                    Log.w(TAG, "Native.stopTun2proxy did not return within 2s — proceeding")
                }
            }

            // 3. Drop our PFD reference. detachFd at startup means this
            //    close() is a no-op for the underlying fd — tun2proxy owns
            //    it (closeFdOnDrop = true) and closes it on return from
            //    run(). The call is kept only to null the field cleanly on
            //    paths that never reached detachFd (PROXY_ONLY, or an
            //    establish() that failed mid-builder).
            try {
                tun?.close()
            } catch (t: Throwable) {
                Log.w(TAG, "tun.close: ${t.message}")
            }
            tun = null

            // 4. Join the worker. With step 1 having killed its upstream this
            //    almost always completes immediately; the 4s budget is just
            //    headroom for tun2proxy's internal close path to drain.
            try {
                tun2proxyThread?.join(4_000)
            } catch (_: InterruptedException) {
            }
            val stillAlive = tun2proxyThread?.isAlive == true
            tun2proxyThread = null
            if (stillAlive) {
                Log.w(TAG, "tun2proxy thread still alive after join timeout — proceeding anyway")
            }

            // Hide debug overlay before flipping UI state. Like show(),
            // hide() ultimately touches WindowManager and must run on the
            // main looper — teardown runs on the worker thread that owned
            // the VPN run loop, so we post.
            val overlayToHide = debugOverlay
            debugOverlay = null
            if (overlayToHide != null) {
                Handler(Looper.getMainLooper()).post { overlayToHide.hide() }
            }

            // Flip UI state last — the button reverts to Connect only after
            // the native-side cleanup actually happened, not optimistically.
            VpnState.setProxyHandle(0L)
            VpnState.setRunning(false)
            broadcastVpnState(running = false, handle = 0L)
            Log.i(TAG, "teardown: done (hadNativeState=$hadNativeState)")
            hadNativeState
        }

    /**
     * Send a [VpnStateSync.ACTION_STATE] broadcast so the UI process (which
     * lives in a different Android process and cannot see this service's
     * in-memory [VpnState]) picks up the change. Called on every transition
     * — start / teardown — and from the 2-second notification ticker so the
     * UI's stats cards stay current without polling Native from the UI
     * process. Stats / pipeline JSON are empty strings on transition
     * events (the ticker fills them in on its next tick).
     */
    private fun broadcastVpnState(
        running: Boolean,
        handle: Long,
        statsJson: String = "",
        pipelineJson: String = "",
    ) {
        try {
            VpnStateSync.broadcastFromService(
                context = this,
                running = running,
                handle = handle,
                statsJson = statsJson,
                pipelineJson = pipelineJson,
            )
        } catch (t: Throwable) {
            Log.w(TAG, "VpnStateSync broadcast: ${t.message}")
        }
    }

    override fun onCreate() {
        super.onCreate()
        // Create the notification channel exactly once per service
        // instance. It used to be created inside buildNotif, which the
        // 2-second stats tick calls every refresh — createNotificationChannel
        // is documented as idempotent (no-op when the channel already
        // exists with the same ID) but it's still a system-call cycle
        // we don't need to spend per tick.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch =
                NotificationChannel(
                    CHANNEL_ID,
                    "rahgozar",
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = "Status of the rahgozar VPN"
                    setShowBadge(false)
                }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(ch)
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy entered")
        // Same gate as ACTION_STOP: prevent any racing rahgozar-pause thread
        // from posting an ongoing "Paused" notification AFTER the service
        // is destroyed (e.g. VPN revoke fires onDestroy while pause is
        // still inside its synchronized block).
        guards.requestStop()
        try {
            runTeardown()
        } catch (t: Throwable) {
            // Belt-and-suspenders. Crashing out of onDestroy takes the
            // whole process with it — user-visible as the app closing
            // right when they tap Stop, which is exactly the symptom we
            // are trying to fix. Anything that gets here is logged and
            // swallowed.
            Log.e(TAG, "onDestroy teardown threw: ${t.message}", t)
        }
        super.onDestroy()
        Log.i(TAG, "onDestroy done")
    }

    private fun buildNotif(
        state: NotifState,
        statsJson: String? = null,
    ): Notification {
        // Channel is created once in onCreate — building a notification
        // never recreates it.
        val openIntent =
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        val stopIntent =
            PendingIntent.getService(
                this,
                1,
                Intent(this, RahgozarVpnService::class.java).setAction(ACTION_STOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        val pauseIntent =
            PendingIntent.getService(
                this,
                2,
                Intent(this, RahgozarVpnService::class.java).setAction(ACTION_PAUSE),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        val resumeIntent =
            PendingIntent.getService(
                this,
                3,
                Intent(this, RahgozarVpnService::class.java).setAction(ACTION_RESUME),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )

        val title =
            when (state) {
                NotifState.PAUSED -> getString(R.string.notif_title_paused)
                NotifState.RUNNING -> getString(R.string.notif_title_active)
            }
        val text =
            when (state) {
                NotifState.PAUSED -> getString(R.string.notif_paused_body)
                NotifState.RUNNING -> renderRunningText(statsJson)
            }

        val builder =
            NotificationCompat
                .Builder(this, CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.presence_online)
                .setContentIntent(openIntent)
                .setOngoing(true)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                // setOnlyAlertOnce so the 2s stats poll doesn't re-buzz the
                // status bar every refresh — title/text update silently.
                .setOnlyAlertOnce(true)

        when (state) {
            NotifState.RUNNING -> {
                builder.addAction(
                    android.R.drawable.ic_media_pause,
                    getString(R.string.notif_action_pause),
                    pauseIntent,
                )
            }

            NotifState.PAUSED -> {
                builder.addAction(
                    android.R.drawable.ic_media_play,
                    getString(R.string.notif_action_resume),
                    resumeIntent,
                )
            }
        }
        builder.addAction(
            android.R.drawable.ic_menu_close_clear_cancel,
            getString(R.string.notif_action_stop),
            stopIntent,
        )

        return builder.build()
    }

    /**
     * Render the body text for a running-state notification. When
     * `statsJson` is a populated StatsSnapshot (Apps Script relay modes)
     * we show today's call count / bytes / countdown to the Pacific-time
     * quota reset — the trio the user actually cares about for daily
     * Google quota tracking. For modes that don't use the Apps
     * Script relay (direct / local_bypass / drive — see
     * [Mode.usesAppsScriptRelay])
     * statsJson is "" and we fall back to the local-listener port info
     * that's been in the notification historically.
     */
    private fun renderRunningText(statsJson: String?): String {
        val stats = parseNotifStats(statsJson)
        return if (stats != null) {
            val hours = (stats.resetSecs / 3600).toInt().coerceAtLeast(0)
            val minutes = ((stats.resetSecs / 60) % 60).toInt().coerceAtLeast(0)
            getString(
                R.string.notif_running_stats,
                stats.todayCalls,
                formatNotifBytes(stats.todayBytes),
                hours,
                minutes,
            )
        } else {
            getString(R.string.notif_running_ports, lastHttpPort, lastSocks5Port)
        }
    }

    private fun startNotifTicker() {
        if (!notifTickerActive.compareAndSet(false, true)) return
        notifHandler.postDelayed(notifTicker, NOTIF_REFRESH_MS)
    }

    private fun stopNotifTicker() {
        if (!notifTickerActive.compareAndSet(true, false)) return
        // Removes only pending invocations. An already-executing tick on
        // the main thread won't be cancelled by this call, but it sees
        // the freshly-cleared notifTickerActive in its repost guard and
        // skips its self-reschedule.
        notifHandler.removeCallbacks(notifTicker)
    }

    companion object {
        private const val TAG = "RahgozarVpnService"
        private const val CHANNEL_ID = "mhrv.vpn.status"
        private const val NOTIF_ID = 0x1001
        private const val MTU = 1500

        // Live-stats notification refresh interval. 2s is conservative —
        // some OEMs throttle notification updates faster than ~1Hz, and
        // the user-visible reset countdown only moves in 1-minute steps.
        private const val NOTIF_REFRESH_MS = 2_000L
        const val ACTION_STOP = "com.dazzlingnomore.mhrv.STOP"
        const val ACTION_PAUSE = "com.dazzlingnomore.mhrv.PAUSE"
        const val ACTION_RESUME = "com.dazzlingnomore.mhrv.RESUME"

        // Magic udpgw destination passed to tun2proxy in Full mode. MUST stay
        // outside tun2proxy's --dns virtual range (198.18.0.0/15) — otherwise
        // virtual DNS can synthesise the magic IP for a real hostname and
        // silently mis-route its traffic into the udpgw path. See issue #251
        // and `UDPGW_MAGIC_IP` / `UDPGW_MAGIC_PORT` in tunnel-node/src/udpgw.rs.
        // Wire-protocol convention: both sides must agree. v1.9.25+ tunnel-nodes
        // also accept the legacy 198.18.0.1:7300 for one deprecation cycle.
        private const val UDPGW_MAGIC_DEST = "192.0.2.1:7300"
    }
}

/**
 * Three fields rendered in the notification's running-state body.
 * Top-level + `internal` so unit tests in the same package can call
 * [parseNotifStats] without reflection.
 */
internal data class NotifStatsView(
    val todayCalls: Long,
    val todayBytes: Long,
    val resetSecs: Long,
)

/**
 * Parse `Native.statsJson(handle)` output into a [NotifStatsView]. Returns
 * null when:
 *   - the blob is null / blank (handle unknown, or non-Apps-Script mode
 *     where the Rust side documents an empty return),
 *   - the JSON is malformed,
 *   - the `today_calls` field is missing (sentinel -1L) — same signal
 *     that this snapshot isn't from a relay-using config.
 *
 * Callers in this file use the null return to fall back to the
 * port-info notification body.
 */
internal fun parseNotifStats(statsJson: String?): NotifStatsView? {
    if (statsJson.isNullOrBlank()) return null
    return runCatching {
        val o = JSONObject(statsJson)
        // optLong with a sentinel default lets us distinguish "field
        // absent" from "value is 0" — the latter is a legitimate
        // pre-traffic state we still want to render.
        val calls = o.optLong("today_calls", -1L)
        if (calls < 0L) return@runCatching null
        NotifStatsView(
            todayCalls = calls,
            todayBytes = o.optLong("today_bytes", 0L),
            resetSecs = o.optLong("today_reset_secs", 0L),
        )
    }.getOrNull()
}

/**
 * Format a byte count with two-decimal GB, one-decimal MB/KB, or a raw
 * byte count. Locale.US is pinned so the decimal separator stays "."
 * regardless of device locale --- the unit suffix is English-only
 * ("GB"/"MB"/"KB"/"B"), and rendering "1,5 KB" or eastern-arabic
 * digits next to an English suffix looks inconsistent.
 */
internal fun formatNotifBytes(b: Long): String {
    val k = 1024L
    val m = k * k
    val g = m * k
    return when {
        b >= g -> String.format(java.util.Locale.US, "%.2f GB", b.toDouble() / g)
        b >= m -> String.format(java.util.Locale.US, "%.1f MB", b.toDouble() / m)
        b >= k -> String.format(java.util.Locale.US, "%.1f KB", b.toDouble() / k)
        else -> "$b B"
    }
}

/**
 * Lifecycle decision matrix for the rahgozar VPN service.
 *
 * The service has four user-facing transitions --- Connect (start), Pause,
 * Resume, Stop --- and Stop wins over everything. The three sticky/edge
 * flags (`isPaused`, `isStarting`, `stopRequested`) encode the
 * intermediate states; each `tryXxx` method here is the atomic CAS that
 * decides whether the corresponding handler should run or no-op.
 *
 * Lives top-level + `internal` so the decision matrix is unit-testable
 * without spinning up the Service (see VpnLifecycleGuardsTest). The
 * service holds exactly one instance; if you find yourself constructing
 * one anywhere else, you're probably racing the real lifecycle.
 */
internal class VpnLifecycleGuards {
    /** Result of [tryStart]. PROCEED means the caller spawned a worker. */
    internal enum class StartDecision { PROCEED, ALREADY_RUNNING, ALREADY_STARTING, STOPPING }

    /** Result of [tryPause]. PROCEED means the caller runs runTeardown + paint. */
    internal enum class PauseDecision { PROCEED, ALREADY_PAUSED, STOPPING }

    /** Result of [tryResume]. PROCEED means the caller spawns startEverything. */
    internal enum class ResumeDecision { PROCEED, NOT_PAUSED, STOPPING }

    private val pausedFlag = AtomicBoolean(false)
    private val startingFlag = AtomicBoolean(false)

    // Sticky-true on first ACTION_STOP / onDestroy. Never reset --- the
    // service instance is destroyed afterwards, so the next user Connect
    // gets a fresh service with a fresh guards instance.
    private val stopRequestedFlag = AtomicBoolean(false)

    val isPaused: Boolean get() = pausedFlag.get()
    val isStarting: Boolean get() = startingFlag.get()
    val isStopRequested: Boolean get() = stopRequestedFlag.get()

    /**
     * True if the service has no in-flight or persistent work and can
     * safely call stopSelf. Used by no-op action handlers (stale
     * Pause/Resume PendingIntents reaching a fresh service instance)
     * to release the "started" claim instead of leaving a stranded
     * sticky service with no foreground notification.
     *
     * `isRunning` is taken as a parameter (singleton truth lives in
     * VpnState).
     */
    fun shouldStopSelfIfIdle(isRunning: Boolean): Boolean =
        !isRunning &&
            !pausedFlag.get() &&
            !startingFlag.get() &&
            !stopRequestedFlag.get()

    /**
     * Try to claim the "starting" slot. `isRunning` is taken as a
     * parameter (not a flag we own) because the source of truth is
     * VpnState.isRunning, set by startEverything's success path ---
     * threading that through here would couple us to the singleton.
     *
     * Atomically clears pausedFlag if it was set on entry. That clear
     * is the SINGLE boundary at which a paused→running transition
     * happens: it makes a sibling tryResume see NOT_PAUSED (so a
     * Resume that arrived a beat later doesn't queue a second
     * startEverything) and lets the queued rahgozar-pause body's
     * post-teardown notify gate see isPaused=false (so it skips
     * posting "Paused" over a service that's about to come back up).
     *
     * Critical: ALREADY_RUNNING is keyed off `wasPaused`, not the
     * live `isPaused`. Without that, the bug is: tryResume signals
     * intent and tryStart sees pausedFlag still true → PROCEED. But
     * if a tap sequence is Pause→Resume→Connect-from-app on different
     * threads, the resume's tryStart could clear pausedFlag before
     * the connect's tryStart reads it, and the connect would then
     * incorrectly bail with ALREADY_RUNNING (since VpnState.isRunning
     * is still stale-true). Capturing wasPaused at entry pins the
     * decision against this race.
     *
     * Caller calls [finishStart] from a finally block once
     * startEverything returns (success OR failure) so the next
     * genuine Connect can claim the slot.
     */
    fun tryStart(isRunning: Boolean): StartDecision {
        if (stopRequestedFlag.get()) return StartDecision.STOPPING
        val wasPaused = pausedFlag.get()
        if (isRunning && !wasPaused) return StartDecision.ALREADY_RUNNING
        if (!startingFlag.compareAndSet(false, true)) return StartDecision.ALREADY_STARTING
        if (wasPaused) pausedFlag.set(false)
        return StartDecision.PROCEED
    }

    fun finishStart() {
        startingFlag.set(false)
    }

    fun tryPause(): PauseDecision {
        if (stopRequestedFlag.get()) return PauseDecision.STOPPING
        if (!pausedFlag.compareAndSet(false, true)) return PauseDecision.ALREADY_PAUSED
        return PauseDecision.PROCEED
    }

    /**
     * Signals user-intent resume. Does NOT flip pausedFlag --- the
     * atomic paused→running transition happens inside [tryStart]
     * when it claims the starting slot. Splitting the steps means a
     * resume that races a sibling Connect-from-app can't accidentally
     * have one consume the other's transition.
     */
    fun tryResume(): ResumeDecision {
        if (stopRequestedFlag.get()) return ResumeDecision.STOPPING
        if (!pausedFlag.get()) return ResumeDecision.NOT_PAUSED
        return ResumeDecision.PROCEED
    }

    fun requestStop() {
        stopRequestedFlag.set(true)
    }

    /**
     * Clear pausedFlag from the pause body when the teardown turned
     * out to be a no-op (stale PAUSE intent, pause after failed
     * startup). Without this, a subsequent Resume tap would see
     * PROCEED and try to start a service whose paused-state we never
     * actually committed to. Distinct from the clear inside
     * [tryStart] which fires on a real resume.
     */
    fun cancelPausedIntent() {
        pausedFlag.set(false)
    }
}
