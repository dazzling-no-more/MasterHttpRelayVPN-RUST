//! JNI entry points for the Android app.
//!
//! The app (Kotlin) calls `Native.setDataDir()` once, then `Native.startProxy()`
//! with the full config.json payload and gets back a handle (u64). Later the
//! app calls `stopProxy(handle)` to stop, `statsJson(handle)` to poll, or
//! `exportCa(dest)` to copy the MITM CA cert to a path the app can hand to
//! Android's system "install certificate" dialog.
//!
//! The proxy runs on an internal tokio runtime that we own (1 worker thread
//! minimum) — we don't piggyback on the JVM thread that calls in.
//!
//! SAFETY: every `extern "system"` entry point catches panics so they never
//! unwind across the JNI boundary (UB otherwise).

#![cfg(target_os = "android")]

use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::{Env, EnvUnowned};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use crate::config::Config;
use crate::mitm::{MitmCertManager, CA_CERT_FILE};
use crate::proxy_server::ProxyServer;

/// Running-proxy record. The JNI handle is the index into a slot map we
/// keep in a lazy-initialized global — we can't round-trip a Rust pointer
/// through `jlong` safely if the JVM compacts, but we can hand out an
/// integer key.
struct Running {
    /// Dropping this sends the shutdown signal. Optional so we can `take()`
    /// it in stop().
    shutdown: Option<oneshot::Sender<()>>,
    /// Own the runtime so it outlives the server. Dropped last.
    rt: Option<Runtime>,
    /// Keep an Arc to the DomainFronter so `statsJson(handle)` can read the
    /// live stats without going through the async server. `None` for
    /// direct / full-only configs where the fronter isn't used.
    fronter: Option<Arc<crate::domain_fronter::DomainFronter>>,
}

static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn slot_map() -> &'static Mutex<std::collections::HashMap<u64, Running>> {
    static SLOTS: OnceLock<Mutex<std::collections::HashMap<u64, Running>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

// ---------------------------------------------------------------------------
// Logging bridge.
//
// We fan each tracing event out two ways:
//   1. `__android_log_write` — lands in `adb logcat` under tag `rahgozar`.
//   2. An in-memory ring buffer the Kotlin UI drains via `Native.drainLogs()`.
// The first path was enough to get past "startProxy returned 0 — silent
// failure"; the second path gives the user a live log panel without making
// them attach a debugger.
// ---------------------------------------------------------------------------

extern "C" {
    fn __android_log_write(
        prio: i32,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> i32;
}

const ANDROID_LOG_INFO: i32 = 4;
const LOG_RING_CAP: usize = 500;

fn log_ring() -> &'static Mutex<VecDeque<String>> {
    static RING: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(LOG_RING_CAP)))
}

/// MakeWriter that forwards each write to `__android_log_write` AND to the
/// in-memory ring buffer. One line per write call; we trim the trailing
/// newline that tracing-subscriber appends so logcat doesn't show blank
/// rows between every event.
struct LogcatWriter;

impl std::io::Write for LogcatWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Skip empty writes — tracing occasionally flushes a bare "\n".
        if buf.is_empty() {
            return Ok(0);
        }
        let trimmed = if buf.ends_with(b"\n") {
            &buf[..buf.len() - 1]
        } else {
            buf
        };

        // logcat side.
        let mut cstr = Vec::with_capacity(trimmed.len() + 1);
        cstr.extend_from_slice(trimmed);
        cstr.push(0);
        static TAG: &[u8] = b"rahgozar\0";
        unsafe {
            __android_log_write(
                ANDROID_LOG_INFO,
                TAG.as_ptr() as *const std::os::raw::c_char,
                cstr.as_ptr() as *const std::os::raw::c_char,
            );
        }

        // ring-buffer side. Best-effort UTF-8; if there are invalid bytes
        // we'd rather show replacement chars than drop the line entirely.
        if let Ok(mut g) = log_ring().lock() {
            if g.len() >= LOG_RING_CAP {
                g.pop_front();
            }
            let line = String::from_utf8_lossy(trimmed).into_owned();
            g.push_back(line);
        }

        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogcatWriter {
    type Writer = LogcatWriter;
    fn make_writer(&'a self) -> Self::Writer {
        LogcatWriter
    }
}

fn install_logging_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(LogcatWriter)
            .try_init();

        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Helper: JString -> String, defaulting to "" on any failure.
fn jstring_to_string(env: &Env, s: &JString) -> String {
    // Use `mutf8_chars(env)` directly: `JString::to_string(env)` would
    // resolve to `std::string::ToString::to_string` first (JString
    // implements Display) and call the std method with an arg, which is
    // an arity mismatch. mutf8_chars yields a `MUTF8Chars` whose `Into<String>`
    // impl does the MUTF-8 → UTF-8 conversion.
    s.mutf8_chars(env)
        .map(|c| c.into())
        .unwrap_or_else(|_| String::new())
}

/// Helper: collapse the jni 0.22 entry-point boilerplate for `jstring`-
/// returning native methods. The closure receives the owned `Env`,
/// computes a `String`, and we materialise it as a `JString` and surface
/// the raw `jstring` pointer the JVM expects. Errors during conversion
/// are logged via `LogErrorAndDefault` and the JVM gets a null jstring
/// back (the `Default` for `jstring`), which is what the equivalent
/// jni 0.21 paths returned before.
fn jstring_return<'local, F>(env: &mut EnvUnowned<'local>, f: F) -> jstring
where
    F: FnOnce(&mut Env<'local>) -> String,
{
    env.with_env(|env| -> jni::errors::Result<jstring> {
        let s = f(env);
        Ok(env.new_string(s)?.into_raw())
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

/// Build a throwaway tokio runtime for one-shot blocking calls from JNI.
/// One worker thread (not current_thread), with an explicitly bumped
/// 4 MiB stack — the default ~2 MiB worker stack is fine for most
/// reqwest calls, but the Drive OAuth device-code flow does a full
/// rustls TLS 1.3 handshake which is stack-hungry, and the JNI
/// caller's thread (Kotlin's Dispatchers.IO worker) has a tighter
/// stack budget than desktop processes. Running on `new_current_thread`
/// would borrow that same tight stack and crash mid-handshake with
/// SIGSEGV — observed pre-fix on driveOauthDeviceCodeStart against
/// oauth2.googleapis.com. Bumping the worker stack here costs ~2 MiB
/// of address space per JNI call, which is negligible.
fn one_shot_runtime() -> Option<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_stack_size(4 * 1024 * 1024)
        .enable_all()
        .build()
        .ok()
}

/// `Native.initAndroidTls(Context)` — call ONCE per process, before
/// any TLS-touching code runs. Reqwest 0.13 with rustls delegates
/// cert-chain verification to `rustls-platform-verifier`; on Linux/
/// macOS/Windows that crate auto-bootstraps off the system cert store,
/// but on Android it needs an explicit JNIEnv + Application context
/// handed to it (the verifier reaches into Android's KeyStore via JNI
/// to walk the device trust anchors). Without this init, the very
/// first TLS handshake — typically the Drive OAuth device-code POST
/// to `oauth2.googleapis.com` — panics with "Expect
/// rustls-platform-verifier to be initialized" and aborts the
/// process. Kotlin calls this from `RahgozarApp.onCreate`.
///
/// Idempotent: `rustls_platform_verifier::android::init_with_env`
/// uses a `OnceCell` internally, so a second call is a no-op.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_initAndroidTls<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    context: JObject<'local>,
) {
    env.with_env(|env| {
        install_logging_once();
        rustls_platform_verifier::android::init_with_env(env, context)
    })
    .resolve::<jni::errors::LogErrorAndDefault>();
    tracing::info!("rustls-platform-verifier init attempted for Android");
}

/// `Native.setDataDir(String)` — must be called once, before `startProxy`.
/// The Kotlin side passes `context.filesDir.absolutePath`.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_setDataDir<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        install_logging_once();
        let p = jstring_to_string(env, &path);
        if !p.is_empty() {
            crate::data_dir::set_data_dir(PathBuf::from(p));
        }
        Ok(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>();
}

/// `Native.startProxy(String configJson)` -> `long` handle (0 on failure).
/// The config is parsed and validated; on success the proxy server is
/// spawned on its own tokio runtime and a non-zero handle returned.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_startProxy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jlong {
    env.with_env(|env| -> jni::errors::Result<jlong> {
        install_logging_once();

        let json = jstring_to_string(env, &config_json);
        let config: Config = match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("android: invalid config json: {}", e);
                return Ok(0i64);
            }
        };

        // Try to build the runtime first — if allocation fails we want to
        // know before spinning up anything stateful.
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name("rahgozar-worker")
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("android: tokio runtime build failed: {}", e);
                return Ok(0i64);
            }
        };

        let base = crate::data_dir::data_dir();
        let mitm = match MitmCertManager::new_in(&base) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("android: MITM CA init failed: {}", e);
                return Ok(0i64);
            }
        };
        let mitm = Arc::new(AsyncMutex::new(mitm));

        let server = match ProxyServer::new(&config, mitm) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("android: ProxyServer::new failed: {}", e);
                return Ok(0i64);
            }
        };

        // Grab the fronter Arc BEFORE we move `server` into the async task —
        // so `statsJson(handle)` can read counters without cross-task plumbing.
        let fronter = server.fronter();

        let (tx, rx) = oneshot::channel::<()>();

        rt.spawn(async move {
            if let Err(e) = server.run(rx).await {
                tracing::error!("android: proxy server exited: {}", e);
            }
        });

        let handle = HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        slot_map().lock().unwrap().insert(
            handle,
            Running {
                shutdown: Some(tx),
                rt: Some(rt),
                fronter,
            },
        );
        Ok(handle as jlong)
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

/// `Native.stopProxy(long handle)` -> boolean. Idempotent: calling on an
/// unknown handle returns false quietly.
///
/// Uses `Runtime::shutdown_timeout` instead of letting `drop(rt)` block
/// synchronously. `drop(rt)` waits forever for tokio tasks to finish, and
/// if ANY task is stuck (in-flight TLS handshake, retrying HTTP request,
/// blocked read) the whole thing deadlocks — which is exactly what caused
/// the reported "Stop doesn't disconnect; subsequent Start fails with
/// Address already in use" bug. 3s is enough for a cooperative server to
/// unwind; anything slower, we force-kill (the listener socket is released
/// as part of the forced shutdown).
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_stopProxy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    env.with_env(|_env| -> jni::errors::Result<jboolean> {
        let mut map = slot_map().lock().unwrap();
        let Some(mut running) = map.remove(&(handle as u64)) else {
            return Ok(JNI_FALSE);
        };
        if let Some(tx) = running.shutdown.take() {
            let _ = tx.send(());
        }
        // Release the map lock BEFORE shutting the runtime down so concurrent
        // JNI callers (stats queries, etc.) don't stall behind us.
        drop(map);
        if let Some(rt) = running.rt.take() {
            tracing::info!(
                "android: stopProxy handle={} — shutting runtime down",
                handle
            );
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
            tracing::info!(
                "android: stopProxy handle={} — runtime shutdown complete",
                handle
            );
        }
        Ok(JNI_TRUE)
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

/// `Native.exportCa(String destPath)` -> boolean. Writes the MITM CA's
/// public cert to the given path. Init-safe: creates the CA on first call
/// if it doesn't exist yet.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_exportCa<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    dest: JString<'local>,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<jboolean> {
        install_logging_once();
        let dest_path = jstring_to_string(env, &dest);
        if dest_path.is_empty() {
            return Ok(JNI_FALSE);
        }
        let base = crate::data_dir::data_dir();
        if MitmCertManager::new_in(&base).is_err() {
            return Ok(JNI_FALSE);
        }
        let src = base.join(CA_CERT_FILE);
        Ok(match std::fs::copy(&src, &dest_path) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                tracing::error!("android: CA export to {} failed: {}", dest_path, e);
                JNI_FALSE
            }
        })
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

/// `Native.version()` -> String. Trivial smoke test for the JNI linkage.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_version<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    jstring_return(&mut env, |_env| env!("CARGO_PKG_VERSION").to_string())
}

/// `Native.drainLogs()` -> String. Returns the full ring buffer as a single
/// `\n`-joined blob, then clears it. We return one String rather than an
/// array because it's one JNI call vs. N — the Kotlin side splits on `\n`
/// for display. Empty string when there's nothing to read.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_drainLogs<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    jstring_return(&mut env, |_env| {
        let Ok(mut g) = log_ring().lock() else {
            return String::new();
        };
        let lines: Vec<String> = g.drain(..).collect();
        lines.join("\n")
    })
}

/// `Native.checkUpdate()` -> String. Runs the same `update_check::check`
/// the desktop UI uses, serializes the outcome as JSON so Kotlin can
/// pattern-match without needing its own GitHub client.
///
/// Returned shape, one of:
///   {"kind":"upToDate","current":"1.0.0","latest":"1.0.0"}
///   {"kind":"updateAvailable","current":"1.0.0","latest":"1.1.0","url":"https://...",
///    "assetName":"rahgozar-android-arm64-v8a-v1.1.0.apk",
///    "assetUrl":"https://...","assetSize":12345678}
///   {"kind":"offline","reason":"..."}
///   {"kind":"error","reason":"..."}
///
/// `assetName/Url/Size` are only present on `updateAvailable` and only when
/// the picker matched a per-ABI APK in the release. The Kotlin updater
/// uses these fields to fetch the right APK and hand it to PackageInstaller.
///
/// Blocking — hit from a background dispatcher.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_checkUpdate<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    jstring_return(&mut env, |_env| {
        install_logging_once();
        let Some(rt) = one_shot_runtime() else {
            return r#"{"kind":"error","reason":"tokio init failed"}"#.to_string();
        };
        let outcome = rt.block_on(crate::update_check::check(
            crate::update_check::Route::Direct,
        ));
        update_check_to_json(&outcome)
    })
}

fn update_check_to_json(u: &crate::update_check::UpdateCheck) -> String {
    // Hand-serialized to keep the JNI side free of serde derive noise on
    // the inner enum (which would need `#[derive(Serialize)]`). Short
    // enough that the hand-rolled version is simpler than pulling
    // serde_json in here for one call.
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    match u {
        crate::update_check::UpdateCheck::UpToDate { current, latest } => format!(
            r#"{{"kind":"upToDate","current":"{}","latest":"{}"}}"#,
            esc(current),
            esc(latest),
        ),
        crate::update_check::UpdateCheck::UpdateAvailable {
            current,
            latest,
            release_url,
            asset,
        } => {
            let asset_fields = match asset {
                Some(a) => format!(
                    r#","assetName":"{}","assetUrl":"{}","assetSize":{}"#,
                    esc(&a.name),
                    esc(&a.download_url),
                    a.size_bytes,
                ),
                None => String::new(),
            };
            format!(
                r#"{{"kind":"updateAvailable","current":"{}","latest":"{}","url":"{}"{}}}"#,
                esc(current),
                esc(latest),
                esc(release_url),
                asset_fields,
            )
        }
        crate::update_check::UpdateCheck::Offline(reason) => {
            format!(r#"{{"kind":"offline","reason":"{}"}}"#, esc(reason),)
        }
        crate::update_check::UpdateCheck::Error(reason) => {
            format!(r#"{{"kind":"error","reason":"{}"}}"#, esc(reason),)
        }
    }
}

/// `Native.downloadAsset(url, destPath)` -> String. Downloads a release
/// asset to `destPath` using the same rustls + redirect-following client
/// the desktop UI uses (so we go through CA-pinned TLS, no Java/OkHttp
/// dependency on the Kotlin side). When this build embeds
/// `RAHGOZAR_UPDATE_PUBKEY`, also downloads `<url>.minisig` and verifies the
/// asset before returning success. BLOCKS — call from IO dispatcher.
///
/// Returns a JSON blob:
///   {"ok":true,"bytes":12345678}
///   {"ok":false,"error":"..."}
///
/// Always uses Route::Direct on Android — the proxy-route trick that
/// helps shared-NAT desktop users isn't needed here (Android users
/// generally have working clear-net to GitHub for the asset CDN, which
/// `objects.githubusercontent.com` redirects to). Can be revisited if
/// users on Iranian networks report the asset host blocked.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_downloadAsset<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    url: JString<'local>,
    dest: JString<'local>,
) -> jstring {
    jstring_return(&mut env, |env| {
        install_logging_once();
        let url_s = jstring_to_string(env, &url);
        let dest_s = jstring_to_string(env, &dest);
        if url_s.is_empty() || dest_s.is_empty() {
            return r#"{"ok":false,"error":"empty url or dest"}"#.to_string();
        }
        let Some(rt) = one_shot_runtime() else {
            return r#"{"ok":false,"error":"tokio init failed"}"#.to_string();
        };
        let dest_path = std::path::PathBuf::from(&dest_s);
        let res = rt.block_on(async {
            let bytes = crate::update_check::download_asset(
                crate::update_check::Route::Direct,
                &url_s,
                &dest_path,
            )
            .await?;

            if let Some(pubkey) = crate::update_apply::embedded_update_pubkey() {
                let sig_url = crate::update_apply::signature_url_for_asset(&url_s);
                let sig_path = {
                    let Some(file_name) = dest_path.file_name() else {
                        return Err("dest path has no filename".to_string());
                    };
                    let mut sig_name = file_name.to_os_string();
                    sig_name.push(".minisig");
                    dest_path.with_file_name(sig_name)
                };
                crate::update_check::download_asset(
                    crate::update_check::Route::Direct,
                    &sig_url,
                    &sig_path,
                )
                .await
                .map_err(|e| format!("signature missing: {}", e))?;
                let sig_text = tokio::fs::read_to_string(&sig_path)
                    .await
                    .map_err(|e| format!("read signature: {}", e))?;
                crate::update_apply::verify_minisign_signature(pubkey, &dest_path, &sig_text)
                    .map_err(|e| format!("signature invalid: {}", e))?;
                let _ = tokio::fs::remove_file(&sig_path).await;
                tracing::info!("android: minisign signature verified for {}", dest_s);
            } else {
                tracing::warn!(
                    "android: RAHGOZAR_UPDATE_PUBKEY was not set at build time — \
                         installing update without minisign check (rollout mode)."
                );
            }

            Ok::<u64, String>(bytes)
        });
        match res {
            Ok(bytes) => {
                tracing::info!(
                    "android: downloadAsset {} -> {} ({} bytes)",
                    url_s,
                    dest_s,
                    bytes
                );
                format!(r#"{{"ok":true,"bytes":{}}}"#, bytes)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&dest_path);
                tracing::warn!("android: downloadAsset failed: {}", e);
                let cleaned = e.replace('\\', "\\\\").replace('"', "\\\"");
                format!(r#"{{"ok":false,"error":"{}"}}"#, cleaned)
            }
        }
    })
}

/// `Native.testSni(googleIp, sni)` -> String. Returns a small JSON blob
/// like `{"ok":true,"latencyMs":123}` or `{"ok":false,"error":"..."}`.
/// Blocking call — Kotlin side should invoke on a background coroutine.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_testSni<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    google_ip: JString<'local>,
    sni: JString<'local>,
) -> jstring {
    jstring_return(&mut env, |env| {
        install_logging_once();
        let ip = jstring_to_string(env, &google_ip);
        let s = jstring_to_string(env, &sni);
        if ip.is_empty() || s.is_empty() {
            return r#"{"ok":false,"error":"empty google_ip or sni"}"#.to_string();
        }
        let Some(rt) = one_shot_runtime() else {
            return r#"{"ok":false,"error":"tokio init failed"}"#.to_string();
        };
        let probe = rt.block_on(crate::scan_sni::probe_one(&ip, &s));
        match (probe.latency_ms, probe.error) {
            (Some(ms), _) => {
                tracing::info!("sni_probe: {} via {} ok in {}ms", s, ip, ms);
                format!(r#"{{"ok":true,"latencyMs":{}}}"#, ms)
            }
            (None, Some(e)) => {
                tracing::warn!("sni_probe: {} via {} FAIL: {}", s, ip, e);
                let cleaned = e.replace('\\', "\\\\").replace('"', "\\\"");
                format!(r#"{{"ok":false,"error":"{}"}}"#, cleaned)
            }
            _ => r#"{"ok":false,"error":"unknown"}"#.to_string(),
        }
    })
}

/// `Native.statsJson(long handle)` -> String. Returns a JSON blob with the
/// live `StatsSnapshot` for a running proxy, or an empty string if the
/// handle is unknown or the proxy has no fronter (direct / full modes).
///
/// Cheap — just reads a handful of atomics. The Kotlin UI polls this on a
/// timer to render the "Usage today (estimated)" card.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_statsJson<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    jstring_return(&mut env, |_env| {
        let Ok(map) = slot_map().lock() else {
            return String::new();
        };
        let Some(running) = map.get(&(handle as u64)) else {
            return String::new();
        };
        let Some(f) = running.fronter.as_ref() else {
            return String::new();
        };
        f.snapshot_stats().to_json()
    })
}

/// `Native.pipelineDebugJson()` -> String. Snapshot of pipeline debug
/// state: elevated session count, batch semaphore usage, recent ramp /
/// drop events. The Kotlin caller (the debug overlay) is gated to
/// `BuildConfig.DEBUG`, and the underlying `pipeline_debug::to_json`
/// is gated to the `pipeline-debug` cargo feature — without the feature,
/// this returns a stable empty-snapshot JSON instead of doing any work.
/// The JNI symbol itself is kept unconditionally so Android can load
/// the library cleanly regardless of which variant the Rust side was
/// built with.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_pipelineDebugJson<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    jstring_return(&mut env, |_env| {
        crate::tunnel_client::pipeline_debug::to_json()
    })
}

// ---------------------------------------------------------------------------
// tun2proxy CLI API wrapper (dlsym — no fork or patch needed)
// ---------------------------------------------------------------------------

/// `Native.discoverFront(hostname)` -> String JSON.
///
/// Resolves `hostname` to its A/AAAA records and TLS-probes each one
/// with `SNI=hostname` so the Kotlin UI can populate a new
/// `FrontingGroup` from one click instead of asking the user to dig
/// + openssl s_client by hand. See `crate::cdn_discover`.
///
/// JSON shape on success:
/// `{"hostname":"python.org","ips":[{"ip":"151.101.0.223","ok":true,"latencyMs":45}, ...]}`
///
/// On top-level failure (bad input, DNS timeout, etc.):
/// `{"hostname":"python.org","error":"dns: ..."}`
///
/// Worst-case wall time is ~15s (3s DNS timeout + 3 probe waves of
/// 4s each at 8-way concurrency over the 24-IP cap, both TCP and
/// TLS handshakes bounded). Typical case for a healthy CDN is well
/// under 1s. Always call from a background dispatcher.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_discoverFront<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    hostname: JString<'local>,
) -> jstring {
    jstring_return(&mut env, |env| {
        install_logging_once();
        let host = jstring_to_string(env, &hostname);
        if host.trim().is_empty() {
            return r#"{"hostname":"","error":"hostname is empty"}"#.to_string();
        }
        let Some(rt) = one_shot_runtime() else {
            return r#"{"hostname":"","error":"tokio init failed"}"#.to_string();
        };
        // Use serde_json::json! here (unlike `update_check_to_json`
        // above, which is fixed-shape and ASCII-only). Probe `error`
        // strings come from OS / TLS / DNS layers and routinely
        // contain non-ASCII bytes, control chars, or both — the
        // hand-rolled `replace('"').replace('\\')` pattern would
        // miss `\n` / `\t` / `\x00` and produce malformed JSON the
        // Kotlin side rejects.
        match rt.block_on(crate::cdn_discover::discover_front(&host)) {
            Ok(df) => {
                let ips: Vec<serde_json::Value> = df
                    .ips
                    .iter()
                    .map(|r| match (&r.latency_ms, &r.error) {
                        (Some(ms), _) => serde_json::json!({
                            "ip": r.ip,
                            "ok": true,
                            "latencyMs": ms,
                        }),
                        (None, Some(e)) => serde_json::json!({
                            "ip": r.ip,
                            "ok": false,
                            "error": e,
                        }),
                        (None, None) => serde_json::json!({
                            "ip": r.ip,
                            "ok": false,
                            "error": "unknown",
                        }),
                    })
                    .collect();
                tracing::info!(
                    "discover_front: {} -> {} ips, {} ok",
                    df.hostname,
                    df.ips.len(),
                    df.ips.iter().filter(|r| r.is_ok()).count(),
                );
                serde_json::json!({
                    "hostname": df.hostname,
                    "ips": ips,
                })
                .to_string()
            }
            Err(e) => {
                tracing::warn!("discover_front: {} FAIL: {}", host, e);
                serde_json::json!({
                    "hostname": host,
                    "error": e,
                })
                .to_string()
            }
        }
    })
}

/// `Native.runTun2proxy(cliArgs, tunMtu)` -> int
///
/// Calls `tun2proxy_run_with_cli_args` from libtun2proxy.so via dlsym.
/// This is the C API the tun2proxy maintainer recommends for callers that
/// need full CLI flexibility (e.g. --udpgw-server). BLOCKS until shutdown.
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_runTun2proxy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    cli_args: JString<'local>,
    tun_mtu: jni::sys::jint,
) -> jni::sys::jint {
    env.with_env(|env| -> jni::errors::Result<jni::sys::jint> {
        let args_str = jstring_to_string(env, &cli_args);
        tracing::info!("runTun2proxy: cli={}", args_str);

        let rc = unsafe {
            use std::ffi::{CStr, CString};

            let lib = CString::new("libtun2proxy.so").unwrap();
            let handle = libc::dlopen(lib.as_ptr(), libc::RTLD_NOW);
            if handle.is_null() {
                let err = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlopen libtun2proxy.so failed: {:?}", err);
                return Ok(-10);
            }

            let sym = CString::new("tun2proxy_run_with_cli_args").unwrap();
            let func = libc::dlsym(handle, sym.as_ptr());
            if func.is_null() {
                let err = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlsym tun2proxy_run_with_cli_args: {:?}", err);
                libc::dlclose(handle);
                return Ok(-11);
            }

            type RunFn = unsafe extern "C" fn(*const std::ffi::c_char, u16, bool) -> i32;
            let run: RunFn = std::mem::transmute(func);
            let c_args = CString::new(args_str).unwrap();
            let rc = run(c_args.as_ptr(), tun_mtu as u16, false);
            libc::dlclose(handle);
            rc
        };
        Ok(rc)
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

/// `Native.stopTun2proxy()` — clears tun2proxy's process-global TUN_QUIT
/// shutdown token via the plain `tun2proxy_stop` C entry point in
/// libtun2proxy.so, resolved via dlsym (same path as
/// [`Java_..._runTun2proxy`]).
///
/// Why dlsym a C symbol instead of calling the Kotlin `Tun2proxy.stop()`
/// JNI shim that the tun2proxy crate also exports:
///
/// On Samsung Android 16+, calling `Tun2proxy.stop()` from the
/// Kotlin-side `object Tun2proxy` triggers a FORTIFY abort about 1.8s
/// later — `pthread_mutex_lock called on a destroyed mutex` inside
/// `libhwui.so`'s static-data section, fatal on `hwuiTask0`. The
/// likely chain is `Tun2proxy`'s lazy `init { System.loadLibrary }`
/// firing for the first time during teardown, intersecting whatever
/// libhwui does during render-thread shutdown. Going through dlsym
/// against the SAME `.so` already loaded by `runTun2proxy`'s dlsym
/// path avoids the JVM-side class init and System.loadLibrary entirely
/// — the lookup is just a pointer table query, no library load.
///
/// `tun2proxy_stop()` is what releases tun2proxy's global `TUN_QUIT`
/// `Mutex<Option<CancellationToken>>`; without that, the next
/// `tun2proxy_run_with_cli_args` short-circuits with rc=-1
/// ("tun2proxy already started"), the TUN fd leaks, and Android keeps
/// the VPN slot held — symptom: VPN key icon stays in status bar after
/// disconnect, and an 18+ s gap between `stopSelf()` and `onDestroy`.
///
/// Returns the underlying `tun2proxy_stop` rc (0 on a clean clear, -1
/// when no run was outstanding) or a negative wrapper code:
///   -10  dlopen of libtun2proxy.so failed
///   -11  dlsym of `tun2proxy_stop` failed
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_stopTun2proxy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jint {
    env.with_env(|_env| -> jni::errors::Result<jni::sys::jint> {
        let rc = unsafe {
            use std::ffi::{CStr, CString};

            let lib = CString::new("libtun2proxy.so").unwrap();
            let handle = libc::dlopen(lib.as_ptr(), libc::RTLD_NOW);
            if handle.is_null() {
                let err = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlopen libtun2proxy.so failed: {:?}", err);
                return Ok(-10);
            }

            let sym = CString::new("tun2proxy_stop").unwrap();
            let func = libc::dlsym(handle, sym.as_ptr());
            if func.is_null() {
                let err = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlsym tun2proxy_stop: {:?}", err);
                // No dlclose here — see comment after the stop() call below.
                return Ok(-11);
            }

            type StopFn = unsafe extern "C" fn() -> i32;
            let stop: StopFn = std::mem::transmute(func);
            let rc = stop();
            // DELIBERATELY DO NOT dlclose(handle): `tun2proxy_stop` only
            // SIGNALS the worker thread to begin shutdown via a
            // CancellationToken — the thread is still alive when we
            // return here, and will exit milliseconds later through
            // `pthread_exit`, which walks `pthread_key_clean_all` to
            // invoke registered TLS destructors. Those destructor
            // function pointers live inside libtun2proxy.so's `.text`.
            // If we drop our refcount here and we're the last holder,
            // bionic's linker unmaps the library; the worker's pthread
            // teardown then jumps to a now-invalid PC → SIGSEGV in
            // `pthread_key_clean_all`. Holding the handle indefinitely
            // costs one extra refcount + ~3 MB of mapped memory; both
            // are exactly what we want since the .so was going to stay
            // mapped anyway for any subsequent `runTun2proxy`.
            //
            // Same reasoning applied historically to the JVM-side
            // `Tun2proxy.stop()` path — `System.loadLibrary` bumped the
            // refcount, the Kotlin object's class init dropped it the
            // moment its reference scope closed, racing libhwui's
            // render-thread teardown with libtun2proxy unmapping.
            // (Manifested as a FORTIFY abort on `hwuiTask0` ~1.8 s
            // after disconnect on Samsung Android 16+.)
            let _ = handle; // keep the binding alive in case of future edits
            rc
        };
        tracing::info!("stopTun2proxy: rc={}", rc);
        Ok(rc)
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

// ---------------------------------------------------------------------------
// Drive-mode OAuth + helpers.
//
// Drive Mode setup on Android uses the **device-code flow (RFC 8628)**.
// Pair it with a Google OAuth client whose application type is
// "TVs and Limited Input devices". Desktop loopback PKCE uses a
// Desktop app client instead.
//
// User taps "Sign in"; Android calls `driveOauthDeviceCodeStart`,
// which POSTs `/device/code` and returns `user_code` +
// `verification_url`. The UI shows both; the user opens the URL on
// any device (often the same phone, in another browser tab), enters
// the code, signs in. Android polls `driveOauthPollFlow` at the
// returned `interval_secs` until Google reports success / denial /
// expiry — same shape the relay's CLI uses.
//
// Per-flow state (device_code + OAuth credentials snapshot) lives in
// a process-wide `Mutex<HashMap<flow_token, PendingDeviceFlow>>` so
// the polling JNI export can look it up by handle.
//
// Five JNI exports:
//   - `driveOauthDeviceCodeStart` — mint a flow, POST /device/code,
//                                   return user_code + URL + handle
//   - `driveOauthPollFlow`        — one /token poll; persists
//                                   refresh_token on success
//   - `driveOauthCancelFlow`      — drop the in-flight flow handle
//   - `driveCreateFolder`         — files.create with the folder MIME
//   - `driveTestConnection`       — list the configured folder
//   - `driveValidateRelayPubkey`  — pure bech32m parse echo
// ---------------------------------------------------------------------------

/// Per-flow state for an RFC 8628 device-code OAuth flow. Held in the
/// `pending_device_flows` registry until either the polling resolves
/// (`status` flips to a terminal variant) or the UI explicitly
/// cancels.
struct PendingDeviceFlow {
    /// Opaque device_code Google returned at start. Goes into every
    /// poll request body.
    device_code: String,
    /// User-supplied OAuth client_id snapshotted at flow-start.
    /// Captured here rather than re-read on every poll so a config
    /// edit mid-flow can't cause `invalid_client` mid-handshake.
    oauth_client_id: String,
    /// Same rationale as [`Self::oauth_client_id`].
    oauth_client_secret: String,
    /// Local deadline after which the in-memory registry entry is
    /// useless even if Compose never calls cancel.
    expires_at: Instant,
}

const MAX_PENDING_DEVICE_FLOWS: usize = 8;
const DEVICE_FLOW_EXPIRY_GRACE_SECS: u64 = 60;

fn pending_device_flows() -> &'static Mutex<std::collections::HashMap<String, PendingDeviceFlow>> {
    static FLOWS: OnceLock<Mutex<std::collections::HashMap<String, PendingDeviceFlow>>> =
        OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn prune_expired_device_flows(flows: &mut std::collections::HashMap<String, PendingDeviceFlow>) {
    let now = Instant::now();
    flows.retain(|_, flow| flow.expires_at > now);
}

/// Start an RFC 8628 device-code OAuth flow. POSTs `/device/code`
/// with the user-supplied OAuth client_id, stashes the device_code +
/// BYO credentials in the in-memory registry, and returns the
/// `user_code` + `verification_url` for the UI to display. JSON
/// shape:
///
/// ```json
/// {"ok":true, "flow_token":"...", "user_code":"ABCD-EFGH",
///  "verification_url":"https://www.google.com/device",
///  "expires_in_secs":1800, "interval_secs":5}
/// {"ok":false, "error":"..."}
/// ```
///
/// `flow_token` is a 32-hex random string the UI passes back to
/// `driveOauthPollFlow` on each polling tick. Distinct from
/// `device_code` (which never leaves the Rust side — leaking it
/// to JS wouldn't be useful, the call to `/token` requires
/// client_secret too).
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_driveOauthDeviceCodeStart<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    jstring_return(&mut env, |_env| {
        install_logging_once();
        // Fail fast on missing BYO credentials so the user gets
        // a clear "set OAuth client first" error instead of a
        // generic Google-side `invalid_client` after the round-trip.
        let fields = match load_drive_config_fields() {
            Ok(f) => f,
            Err(e) => return drive_error_json(&e),
        };
        if fields.oauth_client_id.is_empty() || fields.oauth_client_secret.is_empty() {
            return drive_error_json(
                "OAuth client credentials missing — paste your client_id + client_secret \
                     from Google Cloud Console first (see docs/drive_oauth_setup.md)",
            );
        }
        let google_ip_opt = if fields.google_ip.is_empty() {
            None
        } else {
            Some(fields.google_ip.as_str())
        };
        let http = match crate::drive_api::build_drive_http_client(google_ip_opt) {
            Ok(c) => c,
            Err(e) => return drive_error_json(&format!("build http client: {e}")),
        };
        let oauth_client_id = fields.oauth_client_id;
        let oauth_client_secret = fields.oauth_client_secret;
        let Some(rt) = one_shot_runtime() else {
            return drive_error_json("tokio init failed");
        };
        let flow = match rt.block_on(crate::drive_oauth::device_code_start(
            &http,
            &oauth_client_id,
        )) {
            Ok(f) => f,
            Err(e) => {
                // Log via tracing so the error surfaces in `adb
                // logcat -s rahgozar:V` and the in-app Logs ring,
                // not just in the toast (which truncates after
                // ~80 chars and loses the OAuth response body).
                tracing::warn!("device_code_start failed: {}", e);
                return drive_error_json(&format!("device_code_start: {e}"));
            }
        };

        // 32-hex random flow_token. The actual device_code is
        // an opaque Google value; we mint our own handle so the
        // JS / Kotlin side has a stable identifier even if the
        // device_code shape ever changes.
        use rand::RngCore;
        let mut tok_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut tok_bytes);
        let flow_token: String = tok_bytes
            .iter()
            .fold(String::with_capacity(32), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{:02x}", b);
                acc
            });

        let expires_at = Instant::now()
            .checked_add(flow.expires_in + Duration::from_secs(DEVICE_FLOW_EXPIRY_GRACE_SECS))
            .unwrap_or_else(Instant::now);
        {
            let mut flows = pending_device_flows().lock().unwrap();
            prune_expired_device_flows(&mut flows);
            if flows.len() >= MAX_PENDING_DEVICE_FLOWS {
                return drive_error_json(
                    "too many pending OAuth device-code flows — cancel or wait for one to expire",
                );
            }
            flows.insert(
                flow_token.clone(),
                PendingDeviceFlow {
                    device_code: flow.device_code.clone(),
                    oauth_client_id,
                    oauth_client_secret,
                    expires_at,
                },
            );
        }

        format!(
            r#"{{"ok":true,"flow_token":"{}","user_code":"{}","verification_url":"{}","expires_in_secs":{},"interval_secs":{}}}"#,
            json_escape(&flow_token),
            json_escape(&flow.user_code),
            json_escape(&flow.verification_url),
            flow.expires_in.as_secs(),
            flow.interval.as_secs().max(1),
        )
    })
}

/// Poll one iteration of an in-flight device-code flow. Status
/// shape mirrors the device-code outcomes the relay's CLI handles
/// (RFC 8628 §3.5). On `ok`, the refresh token has already been
/// persisted into `config.json::drive::oauth_refresh_token`; the
/// UI just re-reads the config to flip its indicator.
///
/// ```json
/// {"status":"pending"}
/// {"status":"slow_down","interval_secs":N}
/// {"status":"ok"}
/// {"status":"denied"}
/// {"status":"expired"}
/// {"status":"error","error":"..."}
/// {"status":"unknown"}
/// ```
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_driveOauthPollFlow<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    flow_token: JString<'local>,
) -> jstring {
    jstring_return(&mut env, |env| {
        install_logging_once();
        let tok = jstring_to_string(env, &flow_token);
        if tok.is_empty() {
            return r#"{"status":"unknown"}"#.to_string();
        }
        // Snapshot the flow's state without removing it — a
        // `pending` / `slow_down` outcome means the UI is going
        // to poll again, so we leave the entry alive.
        let (device_code, oauth_client_id, oauth_client_secret) = {
            let mut guard = pending_device_flows().lock().unwrap();
            prune_expired_device_flows(&mut guard);
            match guard.get(&tok) {
                Some(p) => (
                    p.device_code.clone(),
                    p.oauth_client_id.clone(),
                    p.oauth_client_secret.clone(),
                ),
                None => return r#"{"status":"unknown"}"#.to_string(),
            }
        };

        let fields = match load_drive_config_fields() {
            Ok(f) => f,
            Err(e) => {
                return format!(
                    r#"{{"status":"transient_error","error":"{}"}}"#,
                    json_escape(&e),
                );
            }
        };
        let google_ip_opt = if fields.google_ip.is_empty() {
            None
        } else {
            Some(fields.google_ip.as_str())
        };
        let http = match crate::drive_api::build_drive_http_client(google_ip_opt) {
            Ok(c) => c,
            Err(e) => {
                return format!(
                    r#"{{"status":"transient_error","error":"{}"}}"#,
                    json_escape(&format!("build http client: {e}")),
                );
            }
        };
        let Some(rt) = one_shot_runtime() else {
            return r#"{"status":"error","error":"tokio init failed"}"#.to_string();
        };
        match rt.block_on(crate::drive_oauth::device_code_poll(
            &http,
            &device_code,
            &oauth_client_id,
            &oauth_client_secret,
        )) {
            Ok(crate::drive_oauth::DevicePollOutcome::Pending) => {
                r#"{"status":"pending"}"#.to_string()
            }
            Ok(crate::drive_oauth::DevicePollOutcome::SlowDown) => {
                // Per RFC 8628 §3.5 the next poll interval MUST
                // increase by at least 5 s. The Android-side
                // poller is responsible for honouring this — we
                // report it as a hint here.
                r#"{"status":"slow_down","interval_secs":5}"#.to_string()
            }
            Ok(crate::drive_oauth::DevicePollOutcome::AccessDenied) => {
                pending_device_flows().lock().unwrap().remove(&tok);
                r#"{"status":"denied"}"#.to_string()
            }
            Ok(crate::drive_oauth::DevicePollOutcome::ExpiredToken) => {
                pending_device_flows().lock().unwrap().remove(&tok);
                r#"{"status":"expired"}"#.to_string()
            }
            Ok(crate::drive_oauth::DevicePollOutcome::Tokens(tokens)) => {
                let refresh = match tokens.refresh_token {
                    Some(t) if !t.is_empty() => t,
                    _ => {
                        pending_device_flows().lock().unwrap().remove(&tok);
                        return r#"{"status":"error","error":"OAuth response did not include a refresh_token"}"#.to_string();
                    }
                };
                if let Err(e) =
                    persist_drive_refresh_token(&refresh, &oauth_client_id, &oauth_client_secret)
                {
                    pending_device_flows().lock().unwrap().remove(&tok);
                    return format!(
                        r#"{{"status":"error","error":"{}"}}"#,
                        json_escape(&format!("save refresh token: {e}")),
                    );
                }
                pending_device_flows().lock().unwrap().remove(&tok);
                r#"{"status":"ok"}"#.to_string()
            }
            Err(e) => {
                let transient = matches!(
                    &e,
                    crate::drive_oauth::OAuthError::Transport(_)
                        | crate::drive_oauth::OAuthError::BadResponse(_)
                );
                if !transient {
                    pending_device_flows().lock().unwrap().remove(&tok);
                }
                // Network / parse errors leave the flow alive so
                // the next poll can retry. OAuth endpoint errors
                // such as invalid_client are terminal.
                format!(
                    r#"{{"status":"{}","error":"{}"}}"#,
                    if transient {
                        "transient_error"
                    } else {
                        "error"
                    },
                    json_escape(&format!("device_code_poll: {e}")),
                )
            }
        }
    })
}

/// Drop an in-flight device-code flow. Called when the user taps
/// Cancel in the Compose dialog. Idempotent: returns `{"ok":true}`
/// whether the flow existed or not. The OAuth-side device_code is
/// left to expire naturally on Google's side (Google's
/// `/device/code/cancel` endpoint exists but isn't worth the extra
/// round-trip — the user has already abandoned the flow).
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_driveOauthCancelFlow<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    flow_token: JString<'local>,
) -> jstring {
    jstring_return(&mut env, |env| {
        let tok = jstring_to_string(env, &flow_token);
        pending_device_flows().lock().unwrap().remove(&tok);
        r#"{"ok":true}"#.to_string()
    })
}

/// `files.create` with the folder MIME type. Returns the new
/// folder's Drive ID — the UI pastes it into the Drive form's
/// folder_id field. JSON shape:
///
/// ```json
/// {"ok": true,  "folder_id": "..."}
/// {"ok": false, "error": "..."}
/// ```
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_driveCreateFolder<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    name: JString<'local>,
) -> jstring {
    jstring_return(&mut env, |env| {
        install_logging_once();
        let n = jstring_to_string(env, &name);
        let n = n.trim();
        if n.is_empty() {
            return drive_error_json("folder name is empty");
        }
        let fields = match load_drive_config_fields() {
            Ok(t) => t,
            Err(e) => return drive_error_json(&e),
        };
        if fields.refresh_token.is_empty() {
            return drive_error_json("not signed in to Google — sign in first, then try again");
        }
        if fields.oauth_client_id.is_empty() || fields.oauth_client_secret.is_empty() {
            return drive_error_json(
                "OAuth client credentials missing — paste your client_id + client_secret \
                     from Google Cloud Console first (see docs/drive_oauth_setup.md)",
            );
        }
        let Some(rt) = one_shot_runtime() else {
            return drive_error_json("tokio init failed");
        };
        let google_ip_opt = if fields.google_ip.is_empty() {
            None
        } else {
            Some(fields.google_ip.as_str())
        };
        let http = match crate::drive_api::build_drive_http_client(google_ip_opt) {
            Ok(c) => c,
            Err(e) => return drive_error_json(&format!("build http: {e}")),
        };
        let api = crate::drive_api::DriveApiClient::with_default_base_url(http.clone());
        let access = match rt.block_on(crate::drive_oauth::refresh_access_token(
            &http,
            &fields.refresh_token,
            &fields.oauth_client_id,
            &fields.oauth_client_secret,
        )) {
            Ok(t) => t.access_token,
            Err(e) if e.is_refresh_token_revoked() => {
                let _ = clear_drive_refresh_token();
                return drive_reauth_required_json(&format!(
                    "Your Google access has been revoked or the session expired \
                         (Google returned: {e}). Sign in with Google again."
                ));
            }
            Err(e) => return drive_error_json(&format!("refresh failed: {e}")),
        };
        let folder_id = match rt.block_on(api.create_folder(&access, n)) {
            Ok(id) => id,
            Err(e) => return drive_error_json(&format!("create folder: {e}")),
        };
        format!(r#"{{"ok":true,"folder_id":"{}"}}"#, json_escape(&folder_id))
    })
}

/// Refresh + `files.list` against the configured folder. Confirms
/// both that the saved OAuth refresh token still works and that the
/// saved folder ID is reachable. JSON shape:
///
/// ```json
/// {"ok": true,  "folder_id": "...", "files_count": 42}
/// {"ok": false, "error": "..."}
/// ```
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_driveTestConnection<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    jstring_return(&mut env, |_env| {
        install_logging_once();
        let fields = match load_drive_config_fields() {
            Ok(t) => t,
            Err(e) => return drive_error_json(&e),
        };
        if fields.refresh_token.is_empty() {
            return drive_error_json("not signed in to Google — sign in first, then try again");
        }
        if fields.folder_id.is_empty() {
            return drive_error_json(
                "no folder ID set — create or paste the shared folder ID first",
            );
        }
        if fields.oauth_client_id.is_empty() || fields.oauth_client_secret.is_empty() {
            return drive_error_json(
                "OAuth client credentials missing — paste your client_id + client_secret \
                     from Google Cloud Console first (see docs/drive_oauth_setup.md)",
            );
        }
        let Some(rt) = one_shot_runtime() else {
            return drive_error_json("tokio init failed");
        };
        let google_ip_opt = if fields.google_ip.is_empty() {
            None
        } else {
            Some(fields.google_ip.as_str())
        };
        let http = match crate::drive_api::build_drive_http_client(google_ip_opt) {
            Ok(c) => c,
            Err(e) => return drive_error_json(&format!("build http: {e}")),
        };
        let api = crate::drive_api::DriveApiClient::with_default_base_url(http.clone());
        let access = match rt.block_on(crate::drive_oauth::refresh_access_token(
            &http,
            &fields.refresh_token,
            &fields.oauth_client_id,
            &fields.oauth_client_secret,
        )) {
            Ok(t) => t.access_token,
            Err(e) if e.is_refresh_token_revoked() => {
                let _ = clear_drive_refresh_token();
                return drive_reauth_required_json(&format!(
                    "Your Google access has been revoked or the session expired \
                         (Google returned: {e}). Sign in with Google again."
                ));
            }
            Err(e) => return drive_error_json(&format!("refresh failed: {e}")),
        };
        let files = match rt.block_on(api.list_files_in_folder(&access, &fields.folder_id, "")) {
            Ok(f) => f,
            Err(e) => return drive_error_json(&format!("list folder: {e}")),
        };
        format!(
            r#"{{"ok":true,"folder_id":"{}","files_count":{}}}"#,
            json_escape(&fields.folder_id),
            files.len()
        )
    })
}

/// Pure bech32m parse echo — live-validate the relay public key
/// from the Drive setup form. Returns an empty string on OK, the
/// human-readable error otherwise. (No JSON wrapper because the UI
/// just needs a yes/no + reason.)
#[no_mangle]
pub extern "system" fn Java_com_dazzlingnomore_mhrv_Native_driveValidateRelayPubkey<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    relay_pubkey: JString<'local>,
) -> jstring {
    jstring_return(&mut env, |env| {
        let s = jstring_to_string(env, &relay_pubkey);
        match crate::drive_crypto::RelayPubkey::from_bech32m(&s) {
            Ok(_) => String::new(),
            Err(e) => e.to_string(),
        }
    })
}

// ---------------------------------------------------------------------------
// Drive helpers — config IO + JSON escaping
// ---------------------------------------------------------------------------

/// Drive-related fields rahgozar's `Config` exposes to the JNI
/// surface: the OAuth refresh token + folder ID + the existing
/// `google_ip` + the user-supplied BYO OAuth client_id/secret.
/// Returns empty strings when fields are absent (a fresh config
/// with no Drive setup yet) rather than erroring — the caller
/// decides which fields are preconditions for its specific
/// operation. Individual JNI exports decide which fields are required
/// and return user-facing setup errors for missing prerequisites.
struct DriveJniConfigFields {
    refresh_token: String,
    folder_id: String,
    google_ip: String,
    oauth_client_id: String,
    oauth_client_secret: String,
}

fn load_drive_config_fields() -> Result<DriveJniConfigFields, String> {
    let path = crate::data_dir::config_path();
    if !path.exists() {
        return Ok(DriveJniConfigFields {
            refresh_token: String::new(),
            folder_id: String::new(),
            google_ip: String::new(),
            oauth_client_id: String::new(),
            oauth_client_secret: String::new(),
        });
    }
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    let drive = json
        .get("drive")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let refresh_token = drive
        .get("oauth_refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let folder_id = drive
        .get("folder_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let oauth_client_id = drive
        .get("oauth_client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let oauth_client_secret = drive
        .get("oauth_client_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let google_ip = json
        .get("google_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    Ok(DriveJniConfigFields {
        refresh_token,
        folder_id,
        google_ip,
        oauth_client_id,
        oauth_client_secret,
    })
}

/// Write `refresh_token` into `config.json::drive::oauth_refresh_token`,
/// preserving every other field. Refuses to save if the OAuth client
/// credentials on disk changed after the device-code flow started.
fn persist_drive_refresh_token(
    refresh_token: &str,
    expected_client_id: &str,
    expected_client_secret: &str,
) -> Result<(), String> {
    let path = crate::data_dir::config_path();
    let mut json: serde_json::Value = if path.exists() {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {}", path.display(), e))?
    } else {
        return Err(
            "config.json no longer exists — save your OAuth client credentials and sign in again"
                .to_string(),
        );
    };
    let obj = json
        .as_object_mut()
        .ok_or_else(|| "config.json is not a JSON object".to_string())?;
    let drive_obj = obj
        .get_mut("drive")
        .ok_or_else(|| "config.json::drive is missing".to_string())?
        .as_object_mut()
        .ok_or_else(|| "config.json::drive is not an object".to_string())?;
    let current_client_id = drive_obj
        .get("oauth_client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let current_client_secret = drive_obj
        .get("oauth_client_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if current_client_id != expected_client_id.trim()
        || current_client_secret != expected_client_secret.trim()
    {
        return Err(
            "OAuth credentials changed during sign-in — save the intended credentials and sign in \
             again"
                .to_string(),
        );
    }
    drive_obj.insert(
        "oauth_refresh_token".to_string(),
        serde_json::Value::String(refresh_token.to_string()),
    );
    crate::profiles::write_config_json_to(&path, &json)
        .map_err(|e| format!("write {}: {}", path.display(), e))
}

/// Atomically clear `drive.oauth_refresh_token` in `config.json`. Used
/// by the Drive JNI surface when Google returns `invalid_grant` (token
/// revoked / user signed out / sanctions hit) — per RFC 6749 §5.2 the
/// client MUST stop using the dead token and force re-auth. Repeatedly
/// re-sending an invalid_grant can trip Google's fraud heuristics and
/// lock the account.
///
/// No-op if config.json doesn't exist or already has an empty token.
/// Errors only on JSON parse / disk write failure.
fn clear_drive_refresh_token() -> Result<(), String> {
    let path = crate::data_dir::config_path();
    if !path.exists() {
        return Ok(());
    }
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    let Some(obj) = json.as_object_mut() else {
        return Ok(());
    };
    let Some(drive_obj) = obj.get_mut("drive").and_then(|v| v.as_object_mut()) else {
        return Ok(());
    };
    drive_obj.insert(
        "oauth_refresh_token".to_string(),
        serde_json::Value::String(String::new()),
    );
    crate::profiles::write_config_json_to(&path, &json)
        .map_err(|e| format!("write {}: {}", path.display(), e))
}

/// Format a small error JSON for the Drive JNI surface.
fn drive_error_json(reason: &str) -> String {
    format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(reason))
}

/// Format an error JSON the UI can recognize as "the saved refresh
/// token is dead, prompt re-auth". Carries the `reauth_required` flag
/// so DriveSetupSection.kt can switch the indicator back to "Not
/// signed in" and disable Create Folder / Test Connection.
fn drive_reauth_required_json(reason: &str) -> String {
    format!(
        r#"{{"ok":false,"reauth_required":true,"error":"{}"}}"#,
        json_escape(reason)
    )
}

/// Minimal JSON string-escape — only the characters that must be
/// escaped per RFC 8259 §7. Sufficient for the short strings the
/// Drive JNI surface emits (OAuth URLs, folder IDs, error messages).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
