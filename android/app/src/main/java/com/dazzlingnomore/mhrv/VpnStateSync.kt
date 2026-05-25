package com.dazzlingnomore.mhrv

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Cross-process state sync between the VPN service (hosted in the
 * `:vpn` Android process — see the comment on `<service>` in the
 * manifest) and the UI process (where Compose runs).
 *
 * Same observable shape as the in-service [VpnState] singleton (a
 * StateFlow per field), but populated from broadcasts the service
 * sends when its state changes. Two reasons to use a broadcast rather
 * than something heavier (AIDL service binding, ContentProvider, etc.):
 *  - State changes are infrequent (start, stop, occasional stats tick),
 *    so the per-broadcast IPC overhead is irrelevant in the steady
 *    state.
 *  - Broadcasts give the UI a fire-and-forget subscription model that
 *    survives Activity recreation without any bookkeeping on either
 *    end. AIDL would have us managing onServiceConnected /
 *    onServiceDisconnected lifecycle gates that don't add value here.
 *
 * The UI process registers a receiver once in [RahgozarApp.onCreate]
 * (which Android instantiates per-process — we gate the receiver on
 * the UI process specifically). The service publishes via
 * [broadcastFromService] on each state transition + on every stats
 * tick. Polling APIs ([Native.statsJson], [Native.pipelineDebugJson])
 * only function inside the service process (that's where the proxy
 * runtime lives), so we surface their results to the UI through the
 * same broadcast — UI cards observe [statsJson] / [pipelineJson] here
 * instead of calling Native directly.
 *
 * Initial-state semantics: the receiver only fires when the service
 * broadcasts, which it does on its next stats tick (within ~2 s of
 * service start). On a cold UI launch with a service already running
 * the UI shows "not running" for that ~2 s window, then catches up.
 * Acceptable trade-off — the same race exists with any IPC scheme,
 * and the alternative (UI-side query at launch) needs the service to
 * be bound, which races with service start anyway.
 */
object VpnStateSync {
    /** Mirrors [VpnState.isRunning] from the service process. */
    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

    /** Mirrors [VpnState.proxyHandle] from the service process. */
    private val _proxyHandle = MutableStateFlow(0L)
    val proxyHandle: StateFlow<Long> = _proxyHandle.asStateFlow()

    /**
     * Latest `Native.statsJson(handle)` snapshot from the service. The
     * service polls this on the same 2 s cadence as the notification
     * ticker and rebroadcasts here so the UI's UsageTodayCard doesn't
     * have to call Native from the UI process (which has no live
     * proxy handle in its own copy of the lib).
     */
    private val _statsJson = MutableStateFlow("")
    val statsJson: StateFlow<String> = _statsJson.asStateFlow()

    /**
     * Latest `Native.pipelineDebugJson()` snapshot from the service.
     * Same broadcast cadence as [statsJson]; the debug card in
     * HomeScreen observes this instead of polling Native directly.
     */
    private val _pipelineJson = MutableStateFlow("")
    val pipelineJson: StateFlow<String> = _pipelineJson.asStateFlow()

    const val ACTION_STATE = "com.dazzlingnomore.mhrv.STATE"
    private const val EXTRA_RUNNING = "running"
    private const val EXTRA_HANDLE = "handle"
    private const val EXTRA_STATS = "stats"
    private const val EXTRA_PIPELINE = "pipeline"

    /**
     * Called once in the UI process (from [RahgozarApp.onCreate]) to
     * keep the StateFlows above synced with broadcasts the service
     * sends. The receiver is registered with [ContextCompat.RECEIVER_NOT_EXPORTED]
     * so only our own package can deliver to it — Android 14+ requires
     * the export flag explicitly, and we don't want any other app to
     * be able to spoof state into our UI.
     */
    fun registerInUiProcess(context: Context) {
        val filter = IntentFilter(ACTION_STATE)
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(
                    c: Context,
                    intent: Intent,
                ) {
                    if (intent.action != ACTION_STATE) return
                    _isRunning.value = intent.getBooleanExtra(EXTRA_RUNNING, false)
                    _proxyHandle.value = intent.getLongExtra(EXTRA_HANDLE, 0L)
                    // Empty string means "no stats this tick" (e.g. service
                    // is stopping); we still publish it so observers can
                    // clear the card body cleanly instead of holding the
                    // last successful snapshot forever.
                    _statsJson.value = intent.getStringExtra(EXTRA_STATS) ?: ""
                    _pipelineJson.value = intent.getStringExtra(EXTRA_PIPELINE) ?: ""
                }
            }
        ContextCompat.registerReceiver(
            context.applicationContext,
            receiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    /**
     * Called by the service (in the `:vpn` process) whenever its
     * VpnState changes or a stats tick fires. Scoped to our package
     * via `setPackage(packageName)` so the broadcast is explicit
     * (Android requires this for non-system broadcasts targeting
     * background-restricted receivers) AND so it never leaves the
     * app — there's no scenario where a third-party listener
     * benefits from our VPN state.
     */
    fun broadcastFromService(
        context: Context,
        running: Boolean,
        handle: Long,
        statsJson: String = "",
        pipelineJson: String = "",
    ) {
        val intent =
            Intent(ACTION_STATE).apply {
                setPackage(context.packageName)
                putExtra(EXTRA_RUNNING, running)
                putExtra(EXTRA_HANDLE, handle)
                putExtra(EXTRA_STATS, statsJson)
                putExtra(EXTRA_PIPELINE, pipelineJson)
            }
        context.sendBroadcast(intent)
    }
}
