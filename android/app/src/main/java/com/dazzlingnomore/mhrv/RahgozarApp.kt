package com.dazzlingnomore.mhrv

import android.app.Application
import android.util.Log
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat

/**
 * Application-level setup. The only job here right now is to catch
 * uncaught JVM exceptions and route them through logcat under the
 * `rahgozar-crash` tag BEFORE the process dies. Without this the crashes
 * appear as opaque "App closed unexpectedly" with no line number in
 * `adb logcat` — we re-raise the exception afterwards so the default
 * handler still prints its stack trace and Android still shows the
 * dialog, but at least the chain-of-events is searchable.
 *
 * Registering the handler in `Application.onCreate()` (rather than
 * `Activity.onCreate()`) catches crashes on ALL process threads,
 * including the tun2proxy worker and the log-drain coroutine —
 * important because those don't have an activity in scope.
 */
class RahgozarApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // Initialise rustls-platform-verifier with the Android Context
        // BEFORE anything that might touch TLS. The very first HTTPS
        // call out of the app (Drive OAuth device-code POST, update
        // check, etc.) panics-and-aborts with "Expect
        // rustls-platform-verifier to be initialized" without this.
        // Safe to call from onCreate: System.loadLibrary("rahgozar")
        // already ran via the Native.init block at first reference.
        Native.initAndroidTls(this)

        // Apply the saved UI-language preference before any UI class
        // loads. AppCompatDelegate propagates locale changes to the whole
        // process, including Compose text rendering and
        // LocalLayoutDirection (which becomes RTL when Persian is
        // selected), without us having to thread it through every
        // composable.
        val cfg = ConfigStore.load(this)
        val tag =
            when (cfg.uiLang) {
                UiLang.FA -> "fa"
                UiLang.EN -> "en"
                UiLang.AUTO -> "" // empty list = follow system locale
            }
        Log.i(APP_TAG, "applying ui_lang=${cfg.uiLang} (tag='$tag')")
        AppCompatDelegate.setApplicationLocales(
            if (tag.isEmpty()) {
                LocaleListCompat.getEmptyLocaleList()
            } else {
                LocaleListCompat.forLanguageTags(tag)
            },
        )
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            // Log.e itself can throw on extreme conditions (logd dead,
            // OOM allocating the formatted message). If we let that
            // bubble up, we'd recurse into our own handler with a
            // half-handled original exception; swallow it so the
            // previous handler still fires with the real failure.
            try {
                Log.e(
                    CRASH_TAG,
                    "uncaught on thread=${thread.name} (id=${thread.id}): ${throwable.message}",
                    throwable,
                )
            } catch (_: Throwable) {
            }
            // Let the default handler still terminate the process and
            // show the system "app closed" dialog — we just wanted to
            // get a log line out the door first.
            previous?.uncaughtException(thread, throwable)
        }
    }

    companion object {
        private const val CRASH_TAG = "rahgozar-crash"
        private const val APP_TAG = "RahgozarApp"
    }
}
