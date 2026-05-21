package com.dazzlingnomore.mhrv

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject

/**
 * Transparent system overlay showing pipeline debug stats.
 * Draggable, semi-transparent, shown on top of all apps.
 * Temporary — remove when pipelining is validated.
 */
class PipelineDebugOverlay(
    private val context: Context,
) {
    private val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private var root: View? = null

    private lateinit var tvElevated: TextView
    private lateinit var tvBatches: TextView
    private lateinit var tvEvents: TextView

    private val pollInterval = 500L

    // Background HandlerThread for the JNI poll. Previously each tick
    // spawned a fresh `Thread { … }.start()`, which burned a TID per
    // poll and built up zombie threads if native polling ever stalled.
    // A single HandlerThread reuses one OS thread for the whole overlay
    // lifetime and is torn down deterministically by `hide()`.
    private val pollThread = android.os.HandlerThread("PipelineDebugOverlay-poll").apply { start() }
    private val pollHandler = Handler(pollThread.looper)

    // One-way state: `false` after construction, flips to `true` the
    // first time `hide()` runs (or `show()` fails). Once true, every
    // subsequent show()/hide() is a no-op except for thread-quit safety.
    // This closes two races:
    //   1. RahgozarVpnService posts `show()` on the main looper, but
    //      service teardown runs first and calls `hide()` before the
    //      posted show executes. Without this flag, the late show()
    //      would add the view after stop and orphan it.
    //   2. `wm.addView` throws inside show(): the previous shape
    //      returned `false` but left `pollThread` running forever.
    @Volatile
    private var torn: Boolean = false

    /**
     * Add the overlay to the WindowManager. Returns true on success,
     * false if the OS refused (BadTokenException, SecurityException,
     * etc.). The caller (RahgozarVpnService) uses the return value to
     * decide whether to keep the overlay reference live — without it,
     * a one-time addView failure would stick a non-null but-not-shown
     * overlay onto the service, silently swallowing every later retry.
     */
    fun show(): Boolean {
        // Race-late guard: if hide() ran before this posted show()
        // arrived on the main looper, do not attach the view. The
        // HandlerThread is already quit in that case.
        if (torn) return false
        if (root != null) return true

        val dp = { px: Int ->
            TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, px.toFloat(), context.resources.displayMetrics).toInt()
        }

        val layout =
            LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundColor(Color.argb(160, 0, 0, 0))
                setPadding(dp(8), dp(6), dp(8), dp(6))
            }

        val titleTv =
            TextView(context).apply {
                text = context.getString(R.string.debug_pipeline_title)
                setTextColor(Color.argb(220, 100, 255, 100))
                textSize = 11f
            }
        layout.addView(titleTv)

        tvElevated =
            TextView(context).apply {
                setTextColor(Color.WHITE)
                textSize = 10f
            }
        layout.addView(tvElevated)

        tvBatches =
            TextView(context).apply {
                setTextColor(Color.WHITE)
                textSize = 10f
            }
        layout.addView(tvBatches)

        tvEvents =
            TextView(context).apply {
                setTextColor(Color.argb(200, 200, 200, 200))
                textSize = 9f
                maxLines = 8
            }
        layout.addView(tvEvents)

        // TYPE_APPLICATION_OVERLAY was introduced in API 26 (O). On
        // API 24-25 (Android 7.x) it's not a valid constant — even
        // with overlay permission, the addView would throw. Fall back
        // to the pre-O TYPE_PHONE so the debug overlay also works on
        // Android 7. Both types are gated by SYSTEM_ALERT_WINDOW; the
        // semantics for our purposes are equivalent.
        @Suppress("DEPRECATION")
        val overlayType =
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                WindowManager.LayoutParams.TYPE_PHONE
            }
        val params =
            WindowManager
                .LayoutParams(
                    WindowManager.LayoutParams.WRAP_CONTENT,
                    WindowManager.LayoutParams.WRAP_CONTENT,
                    overlayType,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                        WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                    PixelFormat.TRANSLUCENT,
                ).apply {
                    gravity = Gravity.TOP or Gravity.START
                    x = dp(8)
                    y = dp(80)
                }

        // Draggable
        var startX = 0
        var startY = 0
        var startTouchX = 0f
        var startTouchY = 0f
        layout.setOnTouchListener { _, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    startX = params.x
                    startY = params.y
                    startTouchX = event.rawX
                    startTouchY = event.rawY
                    true
                }

                MotionEvent.ACTION_MOVE -> {
                    params.x = startX + (event.rawX - startTouchX).toInt()
                    params.y = startY + (event.rawY - startTouchY).toInt()
                    wm.updateViewLayout(layout, params)
                    true
                }

                else -> {
                    false
                }
            }
        }

        // Guard addView: a stale permission, OEM quirk, or transient
        // WindowManager state can throw (BadTokenException, SecurityException,
        // etc.). The overlay is a debug affordance — its failure must never
        // take the VPN service down with it. On failure, flip `torn` and
        // tear the poll thread down so this instance doesn't leak a
        // running OS thread for the rest of the process.
        return try {
            wm.addView(layout, params)
            root = layout
            schedulePoll()
            true
        } catch (t: Throwable) {
            android.util.Log.w("PipelineDebugOverlay", "addView failed; skipping overlay", t)
            torn = true
            pollHandler.removeCallbacksAndMessages(null)
            pollThread.quitSafely()
            false
        }
    }

    fun hide() {
        // Idempotent: also short-circuits a late `show()` posted before
        // teardown ran (the `torn` flag is read at the top of show()).
        if (torn) return
        torn = true
        // Cancel any in-flight poll on the background thread *and* any
        // pending applyJson on the main thread, then quit the background
        // looper so the OS thread terminates instead of leaking until
        // process death.
        pollHandler.removeCallbacksAndMessages(null)
        handler.removeCallbacksAndMessages(null)
        pollThread.quitSafely()
        root?.let {
            try {
                wm.removeView(it)
            } catch (_: Throwable) {
            }
        }
        root = null
    }

    private fun schedulePoll() {
        pollHandler.postDelayed(::poll, pollInterval)
    }

    private fun poll() {
        if (root == null) return
        try {
            val json = Native.pipelineDebugJson()
            handler.post { applyJson(json) }
        } catch (_: Throwable) {
        }
        schedulePoll()
    }

    private fun applyJson(json: String) {
        if (root == null) return
        try {
            if (json.isNotBlank()) {
                val obj = JSONObject(json)
                val elevated = obj.optInt("elevated", 0)
                val maxElev = obj.optInt("max_elevated", 0)
                val batches = obj.optInt("active_batches", 0)
                val maxBatch = obj.optInt("max_batch_slots", 0)

                val sessions = obj.optInt("active_sessions", 0)
                tvElevated.text =
                    context.getString(R.string.debug_overlay_sessions_fmt, sessions, elevated, maxElev)
                tvBatches.text =
                    context.getString(R.string.debug_overlay_batches_fmt, batches, maxBatch)

                val sessArr = obj.optJSONArray("sessions")
                val sessLines =
                    if (sessArr != null && sessArr.length() > 0) {
                        (0 until sessArr.length()).joinToString("\n") { i ->
                            val s = sessArr.getJSONObject(i)
                            val sid = s.optString("sid", "?")
                            val d = s.optInt("depth", 0)
                            val inf = s.optInt("inflight", 0)
                            val e = if (s.optBoolean("elevated", false)) " E" else ""
                            "$sid d=$d f=$inf$e"
                        }
                    } else {
                        ""
                    }

                val arr = obj.optJSONArray("events")
                val evtLines =
                    if (arr != null && arr.length() > 0) {
                        val start = maxOf(0, arr.length() - 5)
                        (start until arr.length()).joinToString("\n") { arr.getString(it) }
                    } else {
                        ""
                    }

                tvEvents.text = listOf(sessLines, evtLines).filter { it.isNotEmpty() }.joinToString("\n---\n")
            }
        } catch (_: Throwable) {
        }
    }
}
