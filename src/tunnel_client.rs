//! Full-mode tunnel client with pipelined batch multiplexer.
//!
//! A central multiplexer collects pending data from ALL active sessions
//! and fires batch requests without waiting for the previous one to return.
//! Each Apps Script deployment (account) gets its own concurrency pool of
//! 30 in-flight requests — matching the per-account Apps Script limit.

use std::collections::{BTreeMap, HashMap};
// `AtomicU64` from `std::sync::atomic` requires hardware-backed 64-bit
// atomics, which 32-bit MIPS (`mipsel-unknown-linux-musl` — our OpenWRT
// router target) does not provide — the std type isn't even defined
// there, so the build fails with `no AtomicU64 in sync::atomic`. We
// already pull `portable-atomic` for `domain_fronter.rs` for the same
// reason; reuse it here. `AtomicBool` works fine in std on every target.
use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::domain_fronter::{BatchOp, DomainFronter, FronterError, TunnelResponse};

/// Apps Script allows 30 concurrent executions per account / deployment.
const CONCURRENCY_PER_DEPLOYMENT: usize = 30;

/// Idle long-polls are useful for push latency, but letting them occupy all
/// 30 Apps Script executions makes real connect/upload batches wait behind
/// empty polls. Cap pure-idle batches below the account limit so active
/// traffic always has a few reserved slots.
const RESERVED_ACTIVE_PER_DEPLOYMENT: usize = 6;
const IDLE_CONCURRENCY_PER_DEPLOYMENT: usize =
    CONCURRENCY_PER_DEPLOYMENT - RESERVED_ACTIVE_PER_DEPLOYMENT;

/// Low-priority idle batches never queue on the total semaphore. They hold
/// only their idle permit and periodically try the total pool, which keeps
/// Tokio's fair semaphore queue available for active batches.
///
/// Trade-off: under sustained heavy active load that holds all 30 total
/// permits for longer than `DomainFronter::batch_timeout()`, idle batches
/// in this spin-loop will see their session-side `reply_rx` time out and
/// reset the session. We accept that — the alternative (queuing idle
/// batches on the fair semaphore queue) blocks active connect/upload work
/// behind empty long-polls and is the bug this two-tier setup exists to
/// avoid.
const IDLE_BATCH_PERMIT_RETRY_MS: u64 = 25;

/// Maximum total base64-encoded payload bytes in a single batch request.
/// Apps Script accepts up to 50 MB per fetch, but the tunnel-node must
/// parse and fan-out every op — keeping batches under ~4 MB avoids
/// hitting the 6-minute execution cap on the Apps Script side.
const MAX_BATCH_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Maximum number of ops in a single batch. Prevents one mega-batch from
/// serializing too many sessions behind a single HTTP round-trip.
const MAX_BATCH_OPS: usize = 50;

// Per-batch HTTP round-trip timeout is now read from
// `DomainFronter::batch_timeout()`, sourced from `Config::request_timeout_secs`
// (#430, masterking32 PR #25). The historical default — 30 s, matching Apps
// Script's typical response cliff — lives in `default_request_timeout_secs`
// in `config.rs`.

/// Slack added to the reply-timeout budget on top of `batch_timeout`.
/// Covers spawn/encode overhead and a small margin for clock skew, so
/// the session-side `reply_rx` doesn't fire just before `fire_batch`'s
/// HTTP round-trip would have completed. No retry budget here — each
/// batch makes exactly one attempt (see `fire_batch` docs).
const REPLY_TIMEOUT_SLACK: Duration = Duration::from_secs(5);

/// How long we'll briefly hold the client socket after the local
/// CONNECT/SOCKS5 handshake, waiting for the client's first bytes (the
/// TLS ClientHello for HTTPS). Bundling those bytes with the tunnel-node
/// connect saves one Apps Script round-trip per new flow.
const CLIENT_FIRST_DATA_WAIT: Duration = Duration::from_millis(50);

/// Retry budget for `connect_data` when the Apps Script transport fails
/// before we get any tunnel-node response. Kept to one retry and gated to
/// TLS-looking first bytes so cleartext HTTP requests are not replayed.
const CONNECT_DATA_TRANSPORT_RETRIES: usize = 1;

/// Floor depth after a drop (first empty reply).
const INFLIGHT_IDLE: usize = 1;

/// Optimistic starting depth. A fresh HTTPS flow often has one empty
/// prefill poll plus two small client upload records ready immediately
/// after `connect_data` returns (TLS Finished + encrypted request). With
/// only two slots, that second upload waits a full Apps Script batch RTT;
/// three slots let it ride the first post-connect batch without needing
/// an elevated-session permit. This does not make fresh HTTPS one-cycle:
/// `connect_data` still has to return the server handshake bytes before
/// the client can send Finished/request bytes, so first response data is
/// normally the second Apps Script cycle. A fourth optimistic slot mostly
/// becomes an extra empty poll on short HTTPS flows and can delay in-order
/// delivery if it grabs data before older empty replies return. Drops to
/// IDLE after consecutive empties.
const INFLIGHT_OPTIMIST: usize = 3;

/// Maximum pipeline depth when data is actively flowing. Ramps up on
/// data-bearing replies, drops back to IDLE after consecutive empties.
const INFLIGHT_ACTIVE: usize = 6;

/// Max sessions that can run at elevated pipeline depth per deployment.
const MAX_ELEVATED_PER_DEPLOYMENT: u64 = 30;

/// Delay between poll refills while a session is active / optimistic.
const ACTIVE_REFILL_DELAY_MS: u64 = 1000;

/// After this many consecutive empty responses at idle depth, start leaving
/// a gap with no outstanding long-poll. This trades server-push latency for
/// Apps Script quota on sockets that have gone quiet.
///
/// Below this threshold `refill_delay` returns `Duration::ZERO`, so a
/// returning empty long-poll is immediately replaced by another. The
/// tunnel-node's 4s long-poll provides the natural cadence — zero-delay
/// refill keeps freshly-idle sessions back-to-back-polled (good push
/// latency for sessions likely to receive data soon) without spamming
/// because the long-poll itself doesn't return for ~4 s. The pre-rewrite
/// behavior added a 1 s gap here; we drop that gap until the ramp kicks
/// in at `IDLE_REFILL_DELAY_START_EMPTY` empties.
const IDLE_REFILL_DELAY_START_EMPTY: u32 = 4;

/// Idle refill delay ramps by this amount every few empty responses.
const IDLE_REFILL_DELAY_STEP_MS: u64 = 1000;

/// Cap for the client-side no-poll gap on long-idle TCP sessions. With the
/// tunnel-node's 4s long-poll, this cuts idle poll rate by more than half
/// without making push-only sockets feel completely dead.
const IDLE_REFILL_DELAY_MAX_MS: u64 = 7000;

/// Capacity of the bounded MuxMsg channel between `TunnelMux::send_sync`
/// and `mux_loop`. Sized for ~256 active-sending sessions at the per-
/// session in-flight cap (`INFLIGHT_ACTIVE + 4` = 8). When full,
/// `send_sync`'s `try_send` drops the message and logs once per session;
/// the affected session's `reply_rx` will then hit `reply_timeout` and
/// close terminally. This is the global back-pressure boundary —
/// without it, a local/LAN client could open many sessions and queue
/// raw payloads + pending batch tasks until OOM. Tune up for high-fan-
/// in relay operators.
const MUX_CHANNEL_DEPTH: usize = 2048;

/// Adaptive coalesce defaults: after each new op arrives, wait another
/// step for more ops. Resets on every arrival, up to max from the first
/// op. Overridable via config `coalesce_step_ms` / `coalesce_max_ms`.
///
/// 200 ms balances latency against batching efficiency. The dominant
/// bottleneck is the Apps Script round-trip (~1.5 s), so the extra
/// 200 ms wait is negligible to the user but lets significantly more
/// ops land in each batch — a page load that would fire 10 separate
/// 1-op batches at 10 ms now packs 3–5 ops per batch, cutting the
/// number of round-trips roughly in half. On idle sessions the step
/// timer fires once with nothing queued (no cost); under load each
/// arriving op resets the timer, so rapid bursts still coalesce up to
/// `DEFAULT_COALESCE_MAX_MS` naturally.
const DEFAULT_COALESCE_STEP_MS: u64 = 200;
const DEFAULT_COALESCE_MAX_MS: u64 = 1000;

/// Per-batch coalesce cap when a handshake-stage op is in flight.
/// Effective cap is `min(coalesce_max, HANDSHAKE_COALESCE_MAX_MS)` so
/// a tighter operator setting wins. See `is_handshake_priority`.
const HANDSHAKE_COALESCE_MAX_MS: u64 = 50;

/// Structured error code the tunnel-node returns when it doesn't know the
/// op (version mismatch). Must match `tunnel-node/src/main.rs`.
const CODE_UNSUPPORTED_OP: &str = "UNSUPPORTED_OP";

/// Empty poll round-trip latency below which we conclude the tunnel-node
/// is *not* long-polling (legacy fixed-sleep drain instead). On a
/// long-poll-capable server an empty poll with no upstream push either
/// returns near `LONGPOLL_DEADLINE` (currently 4 s, see tunnel-node)
/// or comes back early *with* pushed bytes — neither matches a fast
/// empty reply. Threshold sits well above the legacy `~350 ms` drain
/// and well below the long-poll floor, so network jitter on either
/// side won't false-trigger. Keep this in sync with the tunnel-node
/// constant; if `LONGPOLL_DEADLINE` ever drops below ~1.6 s this
/// threshold needs to come down with it.
const LEGACY_DETECT_THRESHOLD: Duration = Duration::from_millis(1500);

/// How long a deployment stays in "legacy / no long-poll" mode after the
/// last detection. Must be much longer than `LEGACY_DETECT_THRESHOLD` so a
/// freshly-marked deployment doesn't immediately self-recover, but short
/// enough that a redeployed / recovered tunnel-node gets re-probed without
/// requiring a process restart. 60 s lets one stuck deployment widen its
/// own poll cadence without poisoning the others, and self-resets so an
/// upgraded tunnel-node returns to the long-poll fast path on its own.
const LEGACY_RECOVER_AFTER: Duration = Duration::from_secs(60);

/// How long to remember a `Network is unreachable` / `No route to host`
/// failure for a given `(host, port)`. While cached, the proxy short-circuits
/// repeat CONNECTs with an immediate "host unreachable" reply instead of
/// burning a 1.5–2s tunnel batch round-trip on a target that just failed.
/// Real motivator: IPv6-only probe hostnames (e.g. `ds6.probe.*`) on devices
/// without IPv6 — the OS retries the probe every ~1.5s for 10s+, generating
/// 5–10 wasted tunnel sessions per probe.
const UNREACHABLE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Hard cap on negative-cache size. Browsing pulls in dozens of distinct
/// hosts; we don't want a runaway map. Pruned opportunistically on insert.
const UNREACHABLE_CACHE_MAX: usize = 256;

// ---------------------------------------------------------------------------
// Pipeline debug overlay state — gated behind the `pipeline-debug` cargo
// feature. Off by default: the Android overlay that consumes this lives
// behind `BuildConfig.DEBUG` on the Kotlin side and is not surfaced by
// any desktop UI, so paying the atomic-fetch / HashMap-insert cost on
// the upload/reply hot path in release builds buys nothing. Production
// builds use the no-op stubs below; diagnostic builds pass
// `--features pipeline-debug` to get real counters.
// ---------------------------------------------------------------------------
#[cfg(feature = "pipeline-debug")]
pub(crate) mod pipeline_debug {
    use portable_atomic::AtomicU64;
    use std::collections::VecDeque;
    use std::sync::atomic::Ordering;
    use std::sync::{Mutex, OnceLock};

    const EVENT_CAP: usize = 30;

    struct SessionInfo {
        depth: usize,
        inflight: usize,
        elevated: bool,
    }

    struct State {
        events: Mutex<VecDeque<String>>,
        elevated: AtomicU64,
        max_elevated: AtomicU64,
        active_batches: AtomicU64,
        max_batch_slots: AtomicU64,
        active_sessions: AtomicU64,
        sessions: Mutex<std::collections::HashMap<String, SessionInfo>>,
    }

    fn state() -> &'static State {
        static S: OnceLock<State> = OnceLock::new();
        S.get_or_init(|| State {
            events: Mutex::new(VecDeque::with_capacity(EVENT_CAP)),
            elevated: AtomicU64::new(0),
            max_elevated: AtomicU64::new(0),
            active_batches: AtomicU64::new(0),
            max_batch_slots: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            sessions: Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn push_event(msg: String) {
        if let Ok(mut g) = state().events.lock() {
            if g.len() >= EVENT_CAP {
                g.pop_front();
            }
            g.push_back(msg);
        }
    }

    pub fn set_limits(max_elev: u64, max_batches: u64) {
        let s = state();
        s.max_elevated.store(max_elev, Ordering::Relaxed);
        s.max_batch_slots.store(max_batches, Ordering::Relaxed);
    }

    pub fn set_elevated(n: u64) {
        state().elevated.store(n, Ordering::Relaxed);
    }

    pub fn batch_acquire() {
        state().active_batches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn batch_release() {
        // saturating decrement — never wrap past zero.
        let s = state();
        let mut cur = s.active_batches.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return;
            }
            match s.active_batches.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(v) => cur = v,
            }
        }
    }

    pub fn session_start(sid: &str) {
        let s = state();
        if let Ok(mut g) = s.sessions.lock() {
            // Only count the session if this is the first insertion —
            // a reconnect/re-init under the same sid mustn't double-count.
            if g.insert(
                sid.to_string(),
                SessionInfo {
                    depth: 0,
                    inflight: 0,
                    elevated: false,
                },
            )
            .is_none()
            {
                s.active_sessions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn session_end(sid: &str) {
        let s = state();
        if let Ok(mut g) = s.sessions.lock() {
            if g.remove(sid).is_some() {
                let mut cur = s.active_sessions.load(Ordering::Relaxed);
                loop {
                    if cur == 0 {
                        break;
                    }
                    match s.active_sessions.compare_exchange_weak(
                        cur,
                        cur - 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(v) => cur = v,
                    }
                }
            }
        }
    }

    pub fn session_update(sid: &str, depth: usize, inflight: usize, elevated: bool) {
        if let Ok(mut g) = state().sessions.lock() {
            if let Some(info) = g.get_mut(sid) {
                info.depth = depth;
                info.inflight = inflight;
                info.elevated = elevated;
            }
        }
    }

    pub fn to_json() -> String {
        let s = state();
        let events: Vec<String> = s
            .events
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default();
        let sessions: Vec<serde_json::Value> = s
            .sessions
            .lock()
            .map(|g| {
                g.iter()
                    .map(|(sid, info)| {
                        serde_json::json!({
                            "sid": sid,
                            "depth": info.depth,
                            "inflight": info.inflight,
                            "elevated": info.elevated,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let payload = serde_json::json!({
            "elevated": s.elevated.load(Ordering::Relaxed),
            "max_elevated": s.max_elevated.load(Ordering::Relaxed),
            "active_batches": s.active_batches.load(Ordering::Relaxed),
            "max_batch_slots": s.max_batch_slots.load(Ordering::Relaxed),
            "active_sessions": s.active_sessions.load(Ordering::Relaxed),
            "sessions": sessions,
            "events": events,
        });
        payload.to_string()
    }
}

#[cfg(not(feature = "pipeline-debug"))]
pub(crate) mod pipeline_debug {
    // No-op stubs. With the feature off, the compiler inlines every
    // call site to nothing (each function body is empty) so the hot
    // path pays no cost. `to_json` returns a stable empty-snapshot
    // shape so any JNI consumer that calls it on a release build still
    // gets parseable JSON rather than an error.
    #[inline]
    pub fn push_event(_msg: String) {}
    #[inline]
    pub fn set_limits(_max_elev: u64, _max_batches: u64) {}
    #[inline]
    pub fn set_elevated(_n: u64) {}
    #[inline]
    pub fn batch_acquire() {}
    #[inline]
    pub fn batch_release() {}
    #[inline]
    pub fn session_start(_sid: &str) {}
    #[inline]
    pub fn session_end(_sid: &str) {}
    #[inline]
    pub fn session_update(_sid: &str, _depth: usize, _inflight: usize, _elevated: bool) {}

    pub fn to_json() -> String {
        // Stable empty snapshot — same key set as the feature-on path
        // so consumers don't need to handle two shapes.
        r#"{"elevated":0,"max_elevated":0,"active_batches":0,"max_batch_slots":0,"active_sessions":0,"sessions":[],"events":[]}"#
            .to_string()
    }
}

/// Ports where the *server* speaks first (SMTP banner, SSH identification,
/// POP3/IMAP greeting, FTP banner). On these, waiting for client bytes
/// gains nothing and just adds handshake latency — skip the pre-read.
/// HTTP on 80 is intentionally not listed: normal HTTP clients speak
/// first, and bundling the request line into `connect_data` can save a
/// whole Apps Script batch RTT.
fn is_server_speaks_first(port: u16) -> bool {
    matches!(port, 21 | 22 | 25 | 110 | 143 | 587)
}

/// Recognize the tunnel-node's connect-error strings that mean
/// "this destination is fundamentally unreachable from the tunnel-node's
/// network right now" — distinct from refused/reset/timeout, which can be
/// transient. These come through as the inner `e` of a `TunnelResponse`
/// after the tunnel-node's std::io::Error is stringified, so we match on
/// substrings rather than `ErrorKind`. Linux: errno 101 (ENETUNREACH),
/// errno 113 (EHOSTUNREACH). Format varies a bit across libc/Tokio
/// versions, so cover both the human text and the os-error tag.
fn is_unreachable_error_str(s: &str) -> bool {
    let lc = s.to_ascii_lowercase();
    lc.contains("network is unreachable")
        || lc.contains("no route to host")
        || lc.contains("os error 101")
        || lc.contains("os error 113")
}

/// Canonicalize a host string for use as a negative-cache key. DNS names
/// are case-insensitive and may carry a trailing root-label dot, so
/// `Example.COM:443`, `example.com:443`, and `example.com.:443` are all the
/// same destination. IPv4 / IPv6 literals are unaffected — IPv4 has no
/// letters, and `Ipv6Addr::to_string()` already emits lowercase.
fn normalize_cache_host(host: &str) -> String {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    trimmed.to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Multiplexer
// ---------------------------------------------------------------------------

/// Reply payload for ops that go through `fire_batch` — which is now
/// every non-close op, including plain `Connect`. The `String` is the
/// `script_id` of the deployment that processed the batch, needed by
/// `tunnel_loop`'s legacy-detection and per-deployment skip-when-idle
/// decisions which can't reach `fire_batch`'s local `script_id` any
/// other way. `connect_plain` ignores the script_id (`_script_id` in
/// the destructure at `connect_plain`) since legacy detection happens
/// only after the first data reply.
type BatchedReplyResult = Result<(TunnelResponse, String), String>;
type BatchedReply = oneshot::Sender<BatchedReplyResult>;
type BatchedReplyRx = oneshot::Receiver<BatchedReplyResult>;

enum MuxMsg {
    Connect {
        host: String,
        port: u16,
        reply: BatchedReply,
    },
    ConnectData {
        host: String,
        port: u16,
        // `Bytes` is internally Arc-backed, so the caller can cheaply
        // clone() to keep its own reference for the unsupported-fallback
        // replay path without an extra 64 KB copy per session.
        data: Bytes,
        reply: BatchedReply,
    },
    Data {
        sid: String,
        data: Bytes,
        seq: Option<u64>,
        wseq: Option<u64>,
        reply: BatchedReply,
    },
    UdpOpen {
        host: String,
        port: u16,
        data: Bytes,
        reply: BatchedReply,
    },
    UdpData {
        sid: String,
        data: Bytes,
        reply: BatchedReply,
    },
    Close {
        sid: String,
    },
}

/// Raw, not-yet-encoded form of a batch operation. Lives only inside
/// `mux_loop` and gets converted to `BatchOp` (with base64-encoded `d`)
/// inside `fire_batch`'s spawned task — keeping the encoding work off
/// the single mux thread, which previously had to base64 every op
/// inline before it could move on to the next message.
struct PendingOp {
    op: &'static str,
    sid: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    /// Raw payload. `None` for empty polls / opless ops; `Some` even
    /// when empty preserves the connect_data shape (always emits `d`).
    data: Option<Bytes>,
    /// True for ops that must serialize `d` even when empty (currently
    /// only `connect_data`, which uses presence of `d` as the signal
    /// that the caller is opting into the bundled-first-bytes flow).
    encode_empty: bool,
    seq: Option<u64>,
    wseq: Option<u64>,
}

#[derive(Clone)]
struct DeploymentSemaphores {
    total: Arc<Semaphore>,
    idle: Arc<Semaphore>,
}

impl DeploymentSemaphores {
    fn new(total_permits: usize, idle_permits: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total_permits)),
            idle: Arc::new(Semaphore::new(idle_permits)),
        }
    }
}

pub struct TunnelMux {
    // Bounded channel — global back-pressure boundary. Per-session
    // pipeline depth caps each session at ~8 in-flight MuxMsgs, but
    // active_sessions itself isn't capped, so an unbounded channel
    // would let a local/LAN client open many sessions and queue raw
    // payloads + pending batch tasks until OOM. Bounded `channel(N)`
    // means `tx.send` is async — incompatible with `send_sync`, which
    // is called from `tunnel_loop`'s sync select arms — so the sync
    // path uses `try_send` and drops on full. The dropped op's
    // `reply_rx` then hits `reply_timeout` and the session closes
    // terminally (clean error path). See `MUX_CHANNEL_DEPTH`.
    tx: mpsc::Sender<MuxMsg>,
    /// Set to `true` after the first time the tunnel-node rejects
    /// `connect_data` as unsupported. Subsequent sessions skip the
    /// optimistic path entirely and go straight to plain connect + data.
    connect_data_unsupported: Arc<AtomicBool>,
    /// Per-deployment legacy state: `script_id` → time it was last
    /// observed serving an empty poll faster than `LEGACY_DETECT_THRESHOLD`.
    /// Absence means "long-poll capable, or untested." Entries expire after
    /// `LEGACY_RECOVER_AFTER` so a redeployed / recovered tunnel-node
    /// rejoins the long-poll fast path without requiring a process restart.
    ///
    /// Note: the per-deployment marks here do *not* drive a per-deployment
    /// poll cadence — the `tunnel_loop` cadence (read-timeout backoff and
    /// skip-empty-when-idle) is gated on the aggregate `all_legacy`,
    /// because the next op's deployment is chosen later by
    /// `next_script_id()` round-robin and the loop can't pre-select. What
    /// the per-deployment design *does* fix vs the old single AtomicBool:
    ///   * one slow / legacy deployment can no longer flip the aggregate
    ///     true on its own — every deployment has to be marked first;
    ///   * deployments recover individually on the TTL, so an upgraded
    ///     tunnel-node lifts the aggregate without needing the others to
    ///     also recover or the process to restart;
    ///   * the warn log fires once per (deployment, recovery cycle), so
    ///     re-detection after recovery is a real signal in the logs.
    ///
    /// The cost: legacy deployments still receive fast empty polls in
    /// mixed mode (round-robin doesn't know to avoid them). Worth it to
    /// keep pushed bytes flowing through the long-poll-capable peers.
    legacy_deployments: Mutex<HashMap<String, Instant>>,
    /// Lock-free hot-path snapshot of "every known deployment is currently
    /// in legacy mode." Recomputed under `legacy_deployments`'s mutex on
    /// every mark/expire and read with a relaxed load from `tunnel_loop`.
    /// True only when this process has fast-empty observations for *all*
    /// `num_scripts` deployments simultaneously — that's when the per-
    /// session 30 s read-timeout backoff (the only setting where there is
    /// no per-deployment alternative) is still appropriate. Invariant: the
    /// atomic is always written *after* the map insert, under the same
    /// lock, so any reader that sees `true` was preceded by a complete
    /// map update.
    all_legacy: Arc<AtomicBool>,
    /// Count of *unique* configured deployment IDs at start time.
    /// Snapshotted from `fronter.script_id_list()` deduped, since the
    /// aggregate gate compares this against `legacy_deployments.len()`
    /// (a HashMap, so unique-keyed) — using the raw configured count
    /// would make the gate unreachable whenever a user lists the same
    /// script_id twice. Blacklisted-but-configured deployments still
    /// count here; see `all_servers_legacy` for why.
    num_scripts: usize,
    /// Pre-read observability. Lets an operator see whether the 50 ms
    /// wait-for-first-bytes is pulling its weight:
    ///   * `preread_win` — client sent bytes in time, bundled with connect
    ///   * `preread_loss` — timed out empty; paid 50 ms for nothing
    ///   * `preread_skip_port` — port was server-speaks-first; skipped wait
    ///   * `preread_skip_unsupported` — tunnel-node said no; skipped wait
    ///
    /// A rolling sum of win-time (µs) drives a `mean_win_time` readout so
    /// you can tune `CLIENT_FIRST_DATA_WAIT` against real client flush
    /// timing. A summary line is logged every 100 preread events.
    preread_win: AtomicU64,
    preread_loss: AtomicU64,
    preread_skip_port: AtomicU64,
    preread_skip_unsupported: AtomicU64,
    preread_win_total_us: AtomicU64,
    /// Separate monotonic counter used only to trigger the summary log
    /// (avoids a race where two threads both see `total % 100 == 0`).
    preread_total_events: AtomicU64,
    /// Short-lived negative cache for targets the tunnel-node reported as
    /// unreachable (`Network is unreachable` / `No route to host`). Keyed by
    /// `(host, port)`, value is the expiry instant. Plain Mutex<HashMap> is
    /// fine: it's touched once per CONNECT (cheap) and once per failure.
    unreachable_cache: Mutex<HashMap<(String, u16), Instant>>,
    /// How long a session waits for its batch reply before giving up and
    /// retry-polling on the next tick. Computed at construction from
    /// `fronter.batch_timeout() + REPLY_TIMEOUT_SLACK` so the session-
    /// side `reply_rx` always outlives `fire_batch`'s single HTTP
    /// round-trip. Without runtime derivation, an operator who raises
    /// `request_timeout_secs` would see sessions abandon replies just
    /// before the batch would have completed.
    reply_timeout: Duration,
    /// How many sessions are currently at elevated pipeline depth (>= 3).
    elevated_sessions: AtomicU64,
    max_elevated: u64,
}

impl TunnelMux {
    pub fn start(
        fronter: Arc<DomainFronter>,
        coalesce_step_ms: u64,
        coalesce_max_ms: u64,
    ) -> Arc<Self> {
        // Dedupe before snapshotting: the aggregate `all_legacy` gate
        // compares `legacy_deployments.len()` (a HashMap, so unique
        // keys) against this count, so using the raw `num_scripts()`
        // would make the gate unreachable whenever a user lists the
        // same script_id twice in config.
        let unique: std::collections::HashSet<&str> = fronter
            .script_id_list()
            .iter()
            .map(String::as_str)
            .collect();
        let unique_n = unique.len();
        let raw_n = fronter.num_scripts();
        if unique_n != raw_n {
            tracing::warn!(
                "tunnel mux: {} deployments configured but only {} unique script_id(s) — duplicate entries ignored for legacy detection",
                raw_n,
                unique_n,
            );
        }
        tracing::info!(
            "tunnel mux: {} deployment(s), {} concurrent per deployment ({} idle long-poll slots, {} active-reserved)",
            unique_n,
            CONCURRENCY_PER_DEPLOYMENT,
            IDLE_CONCURRENCY_PER_DEPLOYMENT,
            RESERVED_ACTIVE_PER_DEPLOYMENT,
        );
        let step = if coalesce_step_ms > 0 {
            coalesce_step_ms
        } else {
            DEFAULT_COALESCE_STEP_MS
        };
        let max = if coalesce_max_ms > 0 {
            coalesce_max_ms
        } else {
            DEFAULT_COALESCE_MAX_MS
        };
        tracing::info!(
            "batch coalesce: step={}ms max={}ms, pipeline max depth: {}, optimist: {}",
            step,
            max,
            INFLIGHT_ACTIVE,
            INFLIGHT_OPTIMIST,
        );
        // Reply timeout co-varies with `request_timeout_secs` so an
        // operator who raises the batch budget doesn't have sessions
        // abandoning replies just before the HTTP round-trip would
        // have completed. See the `reply_timeout` field comment for
        // the invariant.
        let reply_timeout = fronter.batch_timeout().saturating_add(REPLY_TIMEOUT_SLACK);
        pipeline_debug::set_limits(
            MAX_ELEVATED_PER_DEPLOYMENT * unique_n as u64,
            (CONCURRENCY_PER_DEPLOYMENT * unique_n) as u64,
        );
        let (tx, rx) = mpsc::channel(MUX_CHANNEL_DEPTH);
        tokio::spawn(mux_loop(rx, fronter, step, max));
        Arc::new(Self {
            tx,
            connect_data_unsupported: Arc::new(AtomicBool::new(false)),
            legacy_deployments: Mutex::new(HashMap::new()),
            all_legacy: Arc::new(AtomicBool::new(false)),
            num_scripts: unique_n,
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
            unreachable_cache: Mutex::new(HashMap::new()),
            reply_timeout,
            elevated_sessions: AtomicU64::new(0),
            max_elevated: MAX_ELEVATED_PER_DEPLOYMENT * unique_n as u64,
        })
    }

    /// How long a session waits for its batch reply before retry-polling.
    /// Co-varies with `Config::request_timeout_secs` so `fire_batch`'s
    /// single HTTP round-trip is always covered.
    pub fn reply_timeout(&self) -> Duration {
        self.reply_timeout
    }

    fn send_sync(&self, msg: MuxMsg) {
        // Bounded `try_send` — drops on full instead of awaiting (this
        // path is called from `tunnel_loop`'s sync select arms and can't
        // .await). The dropped op's reply_rx never resolves, so the
        // session hits `reply_timeout` and closes terminally — clean
        // error path. Tokio's tracing handles dedupe; we don't try to
        // log per-drop here because under saturation that's its own
        // hot-path tax.
        if let Err(e) = self.tx.try_send(msg) {
            tracing::warn!(
                "mux channel full ({} cap) — dropping MuxMsg, session will close via reply_timeout",
                MUX_CHANNEL_DEPTH,
            );
            // Explicitly drop the un-sent MuxMsg so any held `reply_tx`
            // inside it is closed; this surfaces the failure to the
            // waiting session as `oneshot::Canceled` immediately instead
            // of forcing a wait for reply_timeout.
            drop(e);
        }
    }

    async fn send(&self, msg: MuxMsg) {
        // Async path — does await, providing real back-pressure to
        // callers like `udp_open` that already run in an async context.
        let _ = self.tx.send(msg).await;
    }

    pub async fn udp_open(
        &self,
        host: &str,
        port: u16,
        data: impl Into<Bytes>,
    ) -> Result<TunnelResponse, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MuxMsg::UdpOpen {
            host: host.to_string(),
            port,
            data: data.into(),
            reply: reply_tx,
        })
        .await;
        match reply_rx.await {
            Ok(Ok((resp, _script_id))) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("mux channel closed".into()),
        }
    }

    pub async fn udp_data(
        &self,
        sid: &str,
        data: impl Into<Bytes>,
    ) -> Result<TunnelResponse, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MuxMsg::UdpData {
            sid: sid.to_string(),
            data: data.into(),
            reply: reply_tx,
        })
        .await;
        match reply_rx.await {
            Ok(Ok((resp, _script_id))) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("mux channel closed".into()),
        }
    }

    pub async fn close_session(&self, sid: &str) {
        self.send(MuxMsg::Close {
            sid: sid.to_string(),
        })
        .await;
    }

    fn connect_data_unsupported(&self) -> bool {
        self.connect_data_unsupported.load(Ordering::Relaxed)
    }

    fn mark_connect_data_unsupported(&self) {
        if !self.connect_data_unsupported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "tunnel-node doesn't support connect_data (pre-v1.x); falling back to plain connect + data for all future sessions"
            );
        }
    }

    /// True only when *every* known deployment is currently in legacy
    /// mode. Both per-session decisions in `tunnel_loop` (the 30 s
    /// read-timeout backoff and the skip-empty-when-idle short-circuit)
    /// gate on this aggregate — they can't pick a per-deployment answer
    /// ahead of time because the next op's deployment is chosen by
    /// `next_script_id()` only when the batch fires. With one
    /// long-poll-capable peer still around, the loop must keep emitting
    /// empty polls so round-robin lands some on that peer (where the
    /// server can hold them open and deliver pushed bytes).
    ///
    /// Known limitation: the comparison is against *all configured*
    /// deployments (`num_scripts`), not currently-selectable ones. A
    /// fleet where most deployments are blacklisted in `DomainFronter`
    /// (10 min cooldown) and the only selectable deployment(s) are
    /// legacy will keep the fast cadence for up to that cooldown, even
    /// though every reachable peer is legacy. Accepted because
    /// integrating the blacklist would require a hot-path query on the
    /// fronter's mutex once per `tunnel_loop` iteration; a heavily-
    /// blacklisted fleet has bigger problems than quota optimization,
    /// and the worst-case quota cost is bounded by the cooldown.
    ///
    /// Hot path: lock-free relaxed load. If the cached value is `true`,
    /// double-check under the mutex with a sweep for expired entries —
    /// otherwise stale legacy marks would keep us in the slow path forever
    /// after every deployment recovers (the `mark_server_no_longpoll` sweep
    /// only fires on the next mark, which may never come).
    fn all_servers_legacy(&self) -> bool {
        if !self.all_legacy.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        let mut deps = match self.legacy_deployments.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        deps.retain(|_, marked_at| now.duration_since(*marked_at) < LEGACY_RECOVER_AFTER);
        let still_all = deps.len() == self.num_scripts;
        if !still_all {
            self.all_legacy.store(false, Ordering::Relaxed);
        }
        still_all
    }

    fn mark_server_no_longpoll(&self, script_id: &str) {
        let now = Instant::now();
        let mut deps = match self.legacy_deployments.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Inline expiry sweep: if any entry has aged past
        // LEGACY_RECOVER_AFTER, drop it before recomputing `all_legacy`.
        // Without this, an entry that should have recovered would still
        // count toward the aggregate.
        deps.retain(|_, marked_at| now.duration_since(*marked_at) < LEGACY_RECOVER_AFTER);
        let was_present = deps.contains_key(script_id);
        deps.insert(script_id.to_string(), now);
        let all = deps.len() == self.num_scripts;
        // Atomic written under the lock and *after* the map insert. Any
        // reader that observes `all_legacy = true` has seen a complete
        // map state where every deployment is marked.
        self.all_legacy.store(all, Ordering::Relaxed);
        drop(deps);
        // Only log on first-mark-for-this-cycle: after `LEGACY_RECOVER_AFTER`
        // expiry + re-detection we re-log, which is intentional — that's
        // a real signal that the deployment regressed back to legacy mode.
        if !was_present {
            let short = &script_id[..script_id.len().min(8)];
            tracing::warn!(
                "tunnel-node deployment {}... returned an empty poll faster than {:?}; assuming legacy (no long-poll) drain — this deployment will skip empty polls when idle for the next {:?}",
                short,
                LEGACY_DETECT_THRESHOLD,
                LEGACY_RECOVER_AFTER,
            );
        }
    }

    /// Returns true if `(host, port)` has a non-expired unreachable entry.
    /// The proxy front-end uses this to skip the tunnel and reply
    /// "host unreachable" immediately on follow-up CONNECTs.
    pub fn is_unreachable(&self, host: &str, port: u16) -> bool {
        let now = Instant::now();
        let mut cache = match self.unreachable_cache.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let key = (normalize_cache_host(host), port);
        match cache.get(&key) {
            Some(expiry) if *expiry > now => true,
            Some(_) => {
                cache.remove(&key);
                false
            }
            None => false,
        }
    }

    /// If `err` looks like a network-unreachable / no-route-to-host error
    /// from the tunnel-node, remember the target for `UNREACHABLE_CACHE_TTL`.
    /// No-op for any other error (timeouts, refused, EOF, etc.) — those can
    /// be transient and we don't want to lock out a host on a flaky moment.
    fn record_unreachable_if_match(&self, host: &str, port: u16, err: &str) {
        if !is_unreachable_error_str(err) {
            return;
        }
        let mut cache = match self.unreachable_cache.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Cap enforcement is two-stage: first drop anything already expired,
        // then if we're STILL at/above the cap (i.e. an unbounded burst of
        // unique unreachable hosts within the TTL), evict the entry that
        // would expire soonest. This bounds the map size at all times — a
        // pure `retain` on expiry alone would let the map grow unbounded
        // until the first entry's TTL elapses.
        if cache.len() >= UNREACHABLE_CACHE_MAX {
            let now = Instant::now();
            cache.retain(|_, expiry| *expiry > now);
            while cache.len() >= UNREACHABLE_CACHE_MAX {
                let victim = cache
                    .iter()
                    .min_by_key(|(_, expiry)| **expiry)
                    .map(|(k, _)| k.clone());
                match victim {
                    Some(k) => {
                        cache.remove(&k);
                    }
                    None => break,
                }
            }
        }
        let key = (normalize_cache_host(host), port);
        cache.insert(key, Instant::now() + UNREACHABLE_CACHE_TTL);
        tracing::debug!(
            "negative-cached {}:{} for {:?} ({})",
            host,
            port,
            UNREACHABLE_CACHE_TTL,
            err
        );
    }

    fn record_preread_win(&self, port: u16, elapsed: Duration) {
        self.preread_win.fetch_add(1, Ordering::Relaxed);
        self.preread_win_total_us
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        tracing::debug!("preread win: port={} took={:?}", port, elapsed);
        self.maybe_log_preread_summary();
    }

    fn record_preread_loss(&self, port: u16) {
        self.preread_loss.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            "preread loss: port={} (empty within {:?})",
            port,
            CLIENT_FIRST_DATA_WAIT
        );
        self.maybe_log_preread_summary();
    }

    fn record_preread_skip_port(&self, port: u16) {
        self.preread_skip_port.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("preread skip: port={} (server-speaks-first)", port);
        self.maybe_log_preread_summary();
    }

    fn record_preread_skip_unsupported(&self, port: u16) {
        self.preread_skip_unsupported
            .fetch_add(1, Ordering::Relaxed);
        tracing::debug!("preread skip: port={} (connect_data unsupported)", port);
        self.maybe_log_preread_summary();
    }

    /// Emit an aggregate summary exactly once per 100 preread events.
    /// Using a dedicated counter for the trigger avoids a race where two
    /// threads both observe the win/loss/skip totals summing to a
    /// multiple of 100 — here, exactly one thread gets the boundary.
    fn maybe_log_preread_summary(&self) {
        let new_count = self.preread_total_events.fetch_add(1, Ordering::Relaxed) + 1;
        if !new_count.is_multiple_of(100) {
            return;
        }
        let win = self.preread_win.load(Ordering::Relaxed);
        let loss = self.preread_loss.load(Ordering::Relaxed);
        let skip_port = self.preread_skip_port.load(Ordering::Relaxed);
        let skip_unsup = self.preread_skip_unsupported.load(Ordering::Relaxed);
        let total_us = self.preread_win_total_us.load(Ordering::Relaxed);
        let mean_us = total_us.checked_div(win).unwrap_or(0);
        tracing::info!(
            "connect_data preread: {} win / {} loss / {} skip(port) / {} skip(unsup), mean win time {}µs (ceiling {}µs)",
            win,
            loss,
            skip_port,
            skip_unsup,
            mean_us,
            CLIENT_FIRST_DATA_WAIT.as_micros(),
        );
    }
}

async fn mux_loop(
    mut rx: mpsc::Receiver<MuxMsg>,
    fronter: Arc<DomainFronter>,
    coalesce_step_ms: u64,
    coalesce_max_ms: u64,
) {
    let coalesce_step = Duration::from_millis(coalesce_step_ms);
    let coalesce_max = Duration::from_millis(coalesce_max_ms);
    // Honor an operator-configured `coalesce_max` tighter than the
    // handshake floor — `min` keeps that intent. See
    // `HANDSHAKE_COALESCE_MAX_MS` for the reasoning behind the cap.
    let coalesce_max_handshake = Duration::from_millis(HANDSHAKE_COALESCE_MAX_MS).min(coalesce_max);
    // One total semaphore per deployment ID (30 concurrent requests), plus
    // one smaller idle-poll semaphore so pure empty long-polls cannot occupy
    // every Apps Script execution slot for that account.
    let sems: Arc<HashMap<String, DeploymentSemaphores>> = Arc::new(
        fronter
            .script_id_list()
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    DeploymentSemaphores::new(
                        CONCURRENCY_PER_DEPLOYMENT,
                        IDLE_CONCURRENCY_PER_DEPLOYMENT,
                    ),
                )
            })
            .collect(),
    );

    loop {
        let mut msgs = Vec::new();
        // Block on the first message — no point waking up to find an empty
        // queue. Once the first op lands, the adaptive coalesce loop waits
        // in `coalesce_step` increments (resetting on each new arrival, up
        // to `coalesce_max`) so concurrent ops land in the same batch.
        match rx.recv().await {
            Some(msg) => msgs.push(msg),
            None => break,
        }
        // Anchor deadlines to the first-op instant so a late priority op
        // can only shrink `hard_deadline`, never extend it. Initial
        // priority is taken from msgs[0]; `upgrade_handshake_deadline`
        // applies the sticky flip + clamp on every new arrival.
        let batch_start = tokio::time::Instant::now();
        let mut priority = is_handshake_priority(&msgs[0]);
        let mut hard_deadline = batch_start
            + if priority {
                coalesce_max_handshake
            } else {
                coalesce_max
            };
        let mut soft_deadline = batch_start + coalesce_step;
        loop {
            // Drain anything that's already queued without waiting.
            while let Ok(msg) = rx.try_recv() {
                (priority, hard_deadline) = upgrade_handshake_deadline(
                    priority,
                    is_handshake_priority(&msg),
                    hard_deadline,
                    batch_start,
                    coalesce_max_handshake,
                );
                msgs.push(msg);
                // Reset the soft deadline — more ops are arriving.
                soft_deadline = tokio::time::Instant::now() + coalesce_step;
            }
            let now = tokio::time::Instant::now();
            let wait_until = soft_deadline.min(hard_deadline);
            if now >= wait_until {
                break;
            }
            match tokio::time::timeout(wait_until - now, rx.recv()).await {
                Ok(Some(msg)) => {
                    (priority, hard_deadline) = upgrade_handshake_deadline(
                        priority,
                        is_handshake_priority(&msg),
                        hard_deadline,
                        batch_start,
                        coalesce_max_handshake,
                    );
                    msgs.push(msg);
                    // New op arrived — extend the soft deadline.
                    soft_deadline = tokio::time::Instant::now() + coalesce_step;
                }
                Ok(None) => return,
                Err(_) => break, // soft or hard deadline hit, no more ops
            }
        }

        // All non-close ops (Connect, ConnectData, Data, UdpOpen, UdpData)
        // share the batch accumulator and the per-deployment permit pool.
        // Close ops have no reply channel — they're collected separately
        // and appended to the trailing batch so they ride the same fetch.
        let mut accum = BatchAccum::new();
        let mut close_sids: Vec<String> = Vec::new();

        for msg in msgs {
            match msg {
                MuxMsg::Connect { host, port, reply } => {
                    // Plain connect (no first-payload data) is batched
                    // alongside data ops. This adds up to `coalesce_max_ms`
                    // of latency per new TCP, in exchange for sharing the
                    // per-deployment permit pool with data ops instead of
                    // spawning a free-floating fetch that bypassed the
                    // semaphore entirely. `connect_data` (the bundled-
                    // first-bytes variant SOCKS5+HTTPS callers prefer) was
                    // always batched; only plain CONNECT is affected.
                    // `encode_empty: false` is fine here — `encode_pending`
                    // only honors that flag when `data.is_some()`, and a
                    // connect op always carries `data: None`.
                    let op = PendingOp {
                        op: "connect",
                        sid: None,
                        host: Some(host),
                        port: Some(port),
                        data: None,
                        encode_empty: false,
                        seq: None,
                        wseq: None,
                    };
                    accum.push_or_fire(op, 0, reply, &sems, &fronter).await;
                }
                MuxMsg::ConnectData {
                    host,
                    port,
                    data,
                    reply,
                } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "connect_data",
                        sid: None,
                        host: Some(host),
                        port: Some(port),
                        data: Some(data),
                        encode_empty: true,
                        seq: None,
                        wseq: None,
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
                }
                MuxMsg::Data {
                    sid,
                    data,
                    seq,
                    wseq,
                    reply,
                } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "data",
                        sid: Some(sid),
                        host: None,
                        port: None,
                        data: if data.is_empty() { None } else { Some(data) },
                        encode_empty: false,
                        seq,
                        wseq,
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
                }
                MuxMsg::UdpOpen {
                    host,
                    port,
                    data,
                    reply,
                } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "udp_open",
                        sid: None,
                        host: Some(host),
                        port: Some(port),
                        data: if data.is_empty() { None } else { Some(data) },
                        encode_empty: false,
                        seq: None,
                        wseq: None,
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
                }
                MuxMsg::UdpData { sid, data, reply } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "udp_data",
                        sid: Some(sid),
                        host: None,
                        port: None,
                        data: if data.is_empty() { None } else { Some(data) },
                        encode_empty: false,
                        seq: None,
                        wseq: None,
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
                }
                MuxMsg::Close { sid } => {
                    close_sids.push(sid);
                }
            }
        }

        // `close` ops piggyback on whatever batch we're about to fire — no
        // reply channel, no payload, just tell tunnel-node to drop the sid.
        for sid in close_sids {
            accum.pending_ops.push(PendingOp {
                op: "close",
                sid: Some(sid),
                host: None,
                port: None,
                data: None,
                encode_empty: false,
                seq: None,
                wseq: None,
            });
        }

        if accum.pending_ops.is_empty() {
            continue;
        }

        fire_batch(&sems, &fronter, accum.pending_ops, accum.data_replies).await;
    }
}

/// Per-iteration accumulator for `mux_loop`. Owns the three fields that
/// the data-bearing arms used to mutate in lockstep, with a single
/// `push_or_fire` entry point so the cap-then-push pattern lives in one
/// place instead of being copy-pasted into every arm.
struct BatchAccum {
    pending_ops: Vec<PendingOp>,
    data_replies: Vec<(usize, BatchedReply)>,
    payload_bytes: usize,
}

impl BatchAccum {
    fn new() -> Self {
        Self {
            pending_ops: Vec::new(),
            data_replies: Vec::new(),
            payload_bytes: 0,
        }
    }

    /// Append `op` (with its `reply` channel and pre-computed `op_bytes`),
    /// firing the current accumulator first if `op` would push us past
    /// `MAX_BATCH_OPS` or `MAX_BATCH_PAYLOAD_BYTES`. After a fire the
    /// accumulator is fresh for the new op.
    async fn push_or_fire(
        &mut self,
        op: PendingOp,
        op_bytes: usize,
        reply: BatchedReply,
        sems: &Arc<HashMap<String, DeploymentSemaphores>>,
        fronter: &Arc<DomainFronter>,
    ) {
        if should_fire(self.pending_ops.len(), self.payload_bytes, op_bytes) {
            fire_batch(
                sems,
                fronter,
                std::mem::take(&mut self.pending_ops),
                std::mem::take(&mut self.data_replies),
            )
            .await;
            self.payload_bytes = 0;
        }
        let idx = self.pending_ops.len();
        self.pending_ops.push(op);
        self.data_replies.push((idx, reply));
        self.payload_bytes += op_bytes;
    }
}

/// Threshold predicate for `BatchAccum::push_or_fire`: would adding an
/// op of `op_bytes` to a batch already holding `pending_len` ops and
/// `payload_bytes` of base64 cross either the per-batch op cap or
/// the payload-size cap?
///
/// Extracted from the inline `if` so the tunable boundary — including
/// the "first op never fires" rule (`pending_len == 0`) — has direct
/// unit-test coverage without spinning up a real `fire_batch`.
///
/// `saturating_add` keeps the helper's contract self-contained: a
/// pathological `op_bytes` near `usize::MAX` clamps to "yes, fire"
/// rather than wrapping around and silently letting an oversized op
/// slip past the cap. Today's callers only feed `encoded_len(n)` on
/// reasonable buffer sizes, but the predicate is the wrong place to
/// rely on caller bounds.
fn should_fire(pending_len: usize, payload_bytes: usize, op_bytes: usize) -> bool {
    pending_len > 0
        && (pending_len >= MAX_BATCH_OPS
            || payload_bytes.saturating_add(op_bytes) > MAX_BATCH_PAYLOAD_BYTES)
}

/// Heuristic — true if `msg` is plausibly a TLS handshake op.
///
/// `Connect`/`ConnectData` are always priority. `Data` is matched on
/// the leading TLS record header `[0x16, 0x03, ..]` (Handshake content
/// type + TLS major version 3, used by every TLS 1.0–1.3 record). The
/// version check makes a false positive on an unaligned mid-stream
/// ApplicationData chunk vanishingly unlikely (1/65536 vs 1/256).
/// Still: this is a heuristic that fires on legitimate post-handshake
/// renegotiations and session-ticket refreshes too, which is the
/// intended behavior — those compound the same per-RTT cost.
fn is_handshake_priority(msg: &MuxMsg) -> bool {
    match msg {
        MuxMsg::Connect { .. } | MuxMsg::ConnectData { .. } => true,
        MuxMsg::Data { data, .. } => is_tls_record_handshake(data),
        MuxMsg::UdpOpen { .. } | MuxMsg::UdpData { .. } | MuxMsg::Close { .. } => false,
    }
}

/// Sticky deadline upgrade: if `new_is_priority` and the batch wasn't
/// already priority, flip the flag and clamp the hard deadline to the
/// handshake floor anchored at `batch_start`. Pure function so the
/// shrink-only / can't-extend invariant lives in one place and is
/// directly unit-testable without standing up the async mux loop.
fn upgrade_handshake_deadline(
    priority: bool,
    new_is_priority: bool,
    hard_deadline: tokio::time::Instant,
    batch_start: tokio::time::Instant,
    coalesce_max_handshake: Duration,
) -> (bool, tokio::time::Instant) {
    if !priority && new_is_priority {
        (
            true,
            hard_deadline.min(batch_start + coalesce_max_handshake),
        )
    } else {
        (priority, hard_deadline)
    }
}

fn is_idle_poll_batch(ops: &[PendingOp]) -> bool {
    !ops.is_empty()
        && ops
            .iter()
            .all(|op| matches!(op.op, "data" | "udp_data") && op.data.is_none())
}

/// True for the IDLE pipeline depth. Centralized so every site that
/// branches on "is this session idle?" uses the same predicate — earlier
/// drafts had `> INFLIGHT_IDLE` and `== INFLIGHT_IDLE` in adjacent blocks,
/// which is correct today but silently diverges if `INFLIGHT_IDLE` ever
/// stops being the smallest depth.
fn is_idle_depth(max_inflight: usize) -> bool {
    max_inflight == INFLIGHT_IDLE
}

/// Should an empty-poll refill be suppressed? Used in two refill arms in
/// `tunnel_loop` — extracted so the predicate (and its threshold,
/// `IDLE_REFILL_DELAY_START_EMPTY`) cannot drift between sites.
///
/// We suppress the refill on legacy-only deployments once an idle-depth
/// session has accumulated `IDLE_REFILL_DELAY_START_EMPTY` empty replies,
/// provided there's nothing else to send and the client socket is still
/// open. On a legacy server the empty poll returns immediately and burns
/// quota; on long-poll deployments it costs nothing, so the gate is
/// scoped to `all_servers_legacy`.
fn should_suppress_empty_refill(
    has_buffered_upload: bool,
    client_closed: bool,
    max_inflight: usize,
    consecutive_empty: u32,
    all_servers_legacy: bool,
) -> bool {
    !has_buffered_upload
        && !client_closed
        && is_idle_depth(max_inflight)
        && consecutive_empty >= IDLE_REFILL_DELAY_START_EMPTY
        && all_servers_legacy
}

async fn acquire_total_permit(
    sem: Arc<Semaphore>,
    idle_batch: bool,
) -> Result<OwnedSemaphorePermit, String> {
    if !idle_batch {
        return sem
            .acquire_owned()
            .await
            .map_err(|_| "batch semaphore closed".to_string());
    }

    // Spin-poll instead of queuing on the fair semaphore queue. Each
    // iteration clones the Arc so `try_acquire_owned` can consume it on
    // success; the atomic bump at 25 ms cadence is negligible compared to
    // any per-batch HTTP work and lets us reuse tokio's `Closed` detection
    // instead of reimplementing it via `is_closed`. (We *must* call
    // `try_acquire_owned` every iteration — short-circuiting on
    // `available_permits() == 0` silently swallows `Closed` for a
    // closed-but-empty semaphore and the loop sleeps forever.)
    loop {
        match Arc::clone(&sem).try_acquire_owned() {
            Ok(p) => return Ok(p),
            Err(TryAcquireError::NoPermits) => {
                tokio::time::sleep(Duration::from_millis(IDLE_BATCH_PERMIT_RETRY_MS)).await;
            }
            Err(TryAcquireError::Closed) => return Err("batch semaphore closed".into()),
        }
    }
}

fn refill_delay(max_inflight: usize, consecutive_empty: u32) -> Duration {
    if !is_idle_depth(max_inflight) {
        return Duration::from_millis(ACTIVE_REFILL_DELAY_MS);
    }
    if consecutive_empty < IDLE_REFILL_DELAY_START_EMPTY {
        return Duration::ZERO;
    }
    let empty_over = consecutive_empty - IDLE_REFILL_DELAY_START_EMPTY;
    let ramp_steps = (empty_over / 4) as u64 + 1;
    Duration::from_millis((ramp_steps * IDLE_REFILL_DELAY_STEP_MS).min(IDLE_REFILL_DELAY_MAX_MS))
}

/// Exact base64-encoded length of `n` raw bytes (standard padding):
/// `((n + 2) / 3) * 4`. Used by `mux_loop` to enforce
/// `MAX_BATCH_PAYLOAD_BYTES` without doing the actual encoding inline —
/// that work now happens in `fire_batch`'s spawned task.
fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Build the wire-shape `BatchOp` from an internal `PendingOp`. Free
/// function so the encoding contract — non-empty data → encoded,
/// empty connect_data → `Some("")`, anything else empty → `None` — is
/// directly testable without spinning up the mux loop.
fn encode_pending(p: PendingOp) -> BatchOp {
    let d = match (&p.data, p.encode_empty) {
        (Some(b), _) if !b.is_empty() => Some(B64.encode(b)),
        (Some(_), true) => Some(String::new()),
        _ => None,
    };
    BatchOp {
        op: p.op.into(),
        sid: p.sid,
        host: p.host,
        port: p.port,
        d,
        seq: p.seq,
        wseq: p.wseq,
    }
}

/// Pick a deployment, acquire its per-account concurrency slot, and spawn
/// a batch request task.
///
/// The batch HTTP round-trip is bounded by `DomainFronter::batch_timeout()`
/// so a slow or dead tunnel-node target cannot hold a pipeline slot (and
/// block waiting sessions) forever. Each batch makes a single attempt —
/// no client-side retry against a different deployment, because
/// tunnel-node's `drain_now` mutates the per-session buffer when building
/// a response, so a lost response means lost bytes (silent gap on the
/// client side). Without server-side ack / sequence support a replay
/// would either duplicate writes (payload ops) or silently skip bytes
/// (empty polls). Sessions whose batch times out re-poll on the next
/// tick — same recovery surface as pre-#1088.
async fn fire_batch(
    sems: &Arc<HashMap<String, DeploymentSemaphores>>,
    fronter: &Arc<DomainFronter>,
    pending_ops: Vec<PendingOp>,
    data_replies: Vec<(usize, BatchedReply)>,
) {
    // Choose deployment + look up its semaphore on the mux task (cheap;
    // no awaits). The actual `acquire_owned().await` lives inside the
    // spawned batch task below so mux_loop never blocks here. Previously
    // a saturated per-deployment semaphore stalled mux_loop's `rx.recv`
    // consumer while `send_sync` kept dumping into the unbounded
    // channel — memory grew and per-op `reply_timeout` started firing
    // before ops even got a permit. Now mux_loop drains continuously;
    // back-pressure on the upstream HTTP path comes from the spawned
    // tasks queuing on the semaphore, each holding only its own ops.
    let script_id = fronter.next_script_id();
    // `sems` is built from the exact list `next_script_id` rotates over
    // (see `mux_loop`), so a miss here means the fronter's script-id set
    // drifted out of sync with the semaphore map — a real bug, not a
    // recoverable state. Falling back to a fresh isolated semaphore would
    // silently drop per-deployment back-pressure.
    let slots = sems
        .get(&script_id)
        .cloned()
        .expect("script_id from fronter must be present in per-deployment semaphore map");
    let f = fronter.clone();
    let idle_batch = is_idle_poll_batch(&pending_ops);

    tokio::spawn(async move {
        let idle_permit = if idle_batch {
            match slots.idle.clone().acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => {
                    for (_, reply) in data_replies {
                        let _ = reply.send(Err("idle semaphore closed".into()));
                    }
                    return;
                }
            }
        } else {
            None
        };
        let permit = match acquire_total_permit(slots.total.clone(), idle_batch).await {
            Ok(p) => p,
            Err(e) => {
                for (_, reply) in data_replies {
                    let _ = reply.send(Err(e.clone()));
                }
                return;
            }
        };
        pipeline_debug::batch_acquire();
        struct BatchGuard;
        impl Drop for BatchGuard {
            fn drop(&mut self) {
                pipeline_debug::batch_release();
            }
        }
        // Hold both permits (and the metrics guard) alive until this task
        // ends so the deployment slots stay reserved for the entire batch
        // round-trip. `_idle_permit` shadows an `Option`; for active
        // batches it is `None` and a no-op at drop.
        let _batch_guard = BatchGuard;
        let _permit = permit;
        let _idle_permit = idle_permit;
        let t0 = std::time::Instant::now();
        let n_ops = pending_ops.len();

        // Encode payloads to base64 here, off the single mux thread.
        // With 50 ops × 64 KB this is up to ~3 MB of work; doing it on
        // the mux task previously serialized every op behind whichever
        // batch was currently encoding.
        let data_ops: Vec<BatchOp> = pending_ops.into_iter().map(encode_pending).collect();

        // Bounded-wait: if the batch takes longer than the configured
        // batch timeout (Config::request_timeout_secs), all sessions in
        // this batch get an error and can retry-poll on the next tick.
        let batch_timeout = f.batch_timeout();
        let result = tokio::time::timeout(
            batch_timeout,
            f.tunnel_batch_request_to(&script_id, &data_ops),
        )
        .await;
        let sid_short = &script_id[..script_id.len().min(8)];
        tracing::info!(
            "batch: {} ops → {}, rtt={:?}",
            n_ops,
            sid_short,
            t0.elapsed()
        );

        match result {
            Ok(Ok(batch_resp)) => {
                f.record_batch_success(&script_id);
                // Wire the Full-mode usage counter that #230 / #362 flagged
                // as stuck-at-zero. Each successful batch is one
                // `UrlFetchApp.fetch()` call against the deploying Google
                // account's daily quota — bytes-counted is the inbound JSON
                // response which is the closest analogue to the apps_script
                // path's `record_today(bytes_received)` (we don't have the
                // exact response byte count post-deserialize, so we use a
                // proxy: sum of per-session response payload bytes the
                // batch carried back). Underestimates by JSON envelope
                // overhead but is in the right order of magnitude.
                let response_bytes: u64 = batch_resp
                    .r
                    .iter()
                    .map(|r| {
                        // `d` carries TCP payload (base64 string len ≈
                        // 4/3 of decoded bytes; close enough); `pkts`
                        // carries UDP datagrams (each base64); plus any
                        // error string. Sum gives a stable proxy for
                        // "how much did this batch move."
                        let d = r.d.as_ref().map(|s| s.len() as u64).unwrap_or(0);
                        let pkts = r
                            .pkts
                            .as_ref()
                            .map(|v| v.iter().map(|p| p.len() as u64).sum::<u64>())
                            .unwrap_or(0);
                        d + pkts
                    })
                    .sum();
                f.record_today(response_bytes);
                for (idx, reply) in data_replies {
                    if let Some(resp) = batch_resp.r.get(idx) {
                        let _ = reply.send(Ok((resp.clone(), script_id.clone())));
                    } else {
                        tracing::error!(
                            "batch response mismatch: idx={} but r.len()={} (sent {} ops) from script {}",
                            idx, batch_resp.r.len(), n_ops, sid_short,
                        );
                        let _ = reply.send(Err(format!(
                            "missing response in batch from script {}",
                            sid_short
                        )));
                    }
                }
            }
            Ok(Err(e)) => {
                // Read-side timeout from `domain_fronter`: Apps Script didn't
                // start streaming response bytes within the per-read deadline.
                // Common cause: deployment's `TUNNEL_SERVER_URL` points at a
                // dead host, so UrlFetchApp inside Apps Script hangs until its
                // own internal connect timeout. Strike-counter blacklists the
                // deployment after a sustained pattern.
                if matches!(e, FronterError::Timeout) {
                    f.record_timeout_strike(&script_id);
                }
                let err_msg = format!("{}", e);
                // Decoy / Apps-Script-flake detection. This body string can
                // mean any of 4 unrelated things (AUTH_KEY mismatch, Apps
                // Script execution timeout, Google-side flake, ISP-side
                // truncation #313), so surface all candidates rather than
                // asserting one. Operators can flip DIAGNOSTIC_MODE in
                // Code.gs to disambiguate (#404).
                if err_msg.contains("The script completed but did not return anything") {
                    tracing::error!(
                        "batch failed (script {}): got the v1.8.0 decoy/placeholder body — \
                         could be (1) AUTH_KEY mismatch between rahgozar config and Code.gs \
                         (run a direct curl probe against the deployment to verify), \
                         (2) Apps Script execution timeout or per-100s quota tear (try \
                         lowering parallel_concurrency in config), (3) Apps Script \
                         internal hiccup (transient, retry next batch), or (4) ISP-side \
                         response truncation (#313 pattern, try a different google_ip). \
                         To distinguish (1) from the rest: set DIAGNOSTIC_MODE=true at \
                         the top of Code.gs + redeploy as new version — only AUTH_KEY \
                         mismatch returns this body in diagnostic mode.",
                        sid_short
                    );
                } else {
                    tracing::warn!("batch failed (script {}): {}", sid_short, err_msg);
                }
                for (_, reply) in data_replies {
                    let _ = reply.send(Err(err_msg.clone()));
                }
            }
            Err(_) => {
                // Whole-batch budget elapsed. Even stronger signal than a
                // per-read timeout — count it the same way so a truly-stuck
                // deployment exits round-robin fast.
                f.record_timeout_strike(&script_id);
                tracing::warn!(
                    "batch timed out after {:?} (script {}, {} ops)",
                    batch_timeout,
                    sid_short,
                    n_ops
                );
                for (_, reply) in data_replies {
                    let _ = reply.send(Err("batch timed out".into()));
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub async fn tunnel_connection(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    mux: &Arc<TunnelMux>,
) -> std::io::Result<()> {
    // Only try the bundled connect+data optimization when it's likely to
    // pay off — client-speaks-first protocols (TLS on 443 et al.) — and
    // only if the tunnel-node has already accepted `connect_data` at least
    // once this process lifetime (or we haven't tried yet). Check the
    // fallback cache first so `skip(unsup)` shadows `skip(port)` in the
    // metrics once the feature is disabled process-wide.
    let initial_data = if mux.connect_data_unsupported() {
        mux.record_preread_skip_unsupported(port);
        None
    } else if is_server_speaks_first(port) {
        mux.record_preread_skip_port(port);
        None
    } else {
        let mut buf = BytesMut::with_capacity(65536);
        let t0 = Instant::now();
        match tokio::time::timeout(CLIENT_FIRST_DATA_WAIT, sock.read_buf(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => {
                mux.record_preread_win(port, t0.elapsed());
                Some(buf.freeze())
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                mux.record_preread_loss(port);
                None
            }
        }
    };

    let (sid, first_resp, pending_client_data) = match initial_data {
        Some(data) => match connect_with_initial_data(host, port, data.clone(), mux).await? {
            ConnectDataOutcome::Opened { sid, response } => (sid, Some(response), None),
            ConnectDataOutcome::Unsupported => {
                mux.mark_connect_data_unsupported();
                let sid = connect_plain(host, port, mux).await?;
                // Replay the buffered ClientHello on the first tunnel_loop
                // iteration. `Bytes::clone()` is a cheap Arc bump — no
                // copy of the 64 KB buffer.
                (sid, None, Some(data))
            }
        },
        None => (connect_plain(host, port, mux).await?, None, None),
    };

    tracing::info!("tunnel session {} opened for {}:{}", sid, host, port);
    pipeline_debug::session_start(&sid);

    // Run the first-response write + tunnel_loop inside an async block so
    // any io-error propagates via `?` without bypassing the cleanup below.
    // We deliberately don't use a Drop guard for Close: a Drop impl can't
    // .await cleanly, and tokio::spawn from inside Drop is unreliable
    // during runtime shutdown. The explicit send below covers every
    // non-panic path; a panic during tunnel_loop would leak the session
    // on the tunnel-node until its 5-minute idle reaper runs.
    let result = async {
        if let Some(resp) = first_resp {
            match write_tunnel_response(&mut sock, &resp).await? {
                WriteOutcome::Wrote | WriteOutcome::NoData => {}
                WriteOutcome::BadBase64 => {
                    tracing::error!(
                        "tunnel session {}: bad base64 in connect_data response",
                        sid
                    );
                    return Ok(TunnelEnd::NeedsClose);
                }
            }
            if resp.eof.unwrap_or(false) {
                return Ok(TunnelEnd::RemoteEof);
            }
        }
        tunnel_loop(&mut sock, &sid, mux, pending_client_data).await
    }
    .await;

    if !matches!(result, Ok(TunnelEnd::RemoteEof)) {
        mux.send(MuxMsg::Close { sid: sid.clone() }).await;
    } else {
        tracing::debug!(
            "tunnel session {}: remote eof already reaped session; skipping close op",
            sid
        );
    }
    pipeline_debug::session_end(&sid);
    tracing::info!("tunnel session {} closed for {}:{}", sid, host, port);
    result.map(|_| ())
}

enum ConnectDataOutcome {
    Opened {
        sid: String,
        response: TunnelResponse,
    },
    Unsupported,
}

async fn connect_plain(host: &str, port: u16, mux: &Arc<TunnelMux>) -> std::io::Result<String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    mux.send(MuxMsg::Connect {
        host: host.to_string(),
        port,
        reply: reply_tx,
    })
    .await;

    match reply_rx.await {
        Ok(Ok((resp, _script_id))) => {
            if let Some(ref e) = resp.e {
                tracing::error!("tunnel connect error for {}:{}: {}", host, port, e);
                // Only cache here: `resp.e` is the tunnel-node's own connect()
                // result against the target. The outer `Ok(Err(_))` arm below
                // is a transport-level failure (relay → Apps Script → tunnel-
                // node never reached) and tells us nothing about the target.
                mux.record_unreachable_if_match(host, port, e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e.clone(),
                ));
            }
            resp.sid
                .ok_or_else(|| std::io::Error::other("tunnel connect: no session id"))
        }
        Ok(Err(e)) => {
            tracing::error!("tunnel connect error for {}:{}: {}", host, port, e);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                e,
            ))
        }
        Err(_) => Err(std::io::Error::other("mux channel closed")),
    }
}

async fn connect_with_initial_data(
    host: &str,
    port: u16,
    data: Bytes,
    mux: &Arc<TunnelMux>,
) -> std::io::Result<ConnectDataOutcome> {
    let attempts = if is_tls_record_handshake(&data) {
        CONNECT_DATA_TRANSPORT_RETRIES + 1
    } else {
        1
    };

    for attempt in 0..attempts {
        let (reply_tx, reply_rx) = oneshot::channel();
        mux.send(MuxMsg::ConnectData {
            host: host.to_string(),
            port,
            data: data.clone(),
            reply: reply_tx,
        })
        .await;

        let resp = match reply_rx.await {
            Ok(Ok((resp, _script_id))) => resp,
            Ok(Err(e)) => {
                if is_connect_data_unsupported_error_str(&e) {
                    tracing::debug!("connect_data unsupported for {}:{}: {}", host, port, e);
                    return Ok(ConnectDataOutcome::Unsupported);
                }
                if attempt + 1 < attempts && is_retryable_connect_data_transport_error(&e) {
                    tracing::warn!(
                        "tunnel connect_data transport error for {}:{} (attempt {}/{}): {}; retrying",
                        host,
                        port,
                        attempt + 1,
                        attempts,
                        e
                    );
                    continue;
                }
                tracing::error!("tunnel connect_data error for {}:{}: {}", host, port, e);
                // Outer transport failure (relay/Apps Script never reached the
                // tunnel-node). Don't poison the destination cache from here —
                // see `connect_plain` for the same reasoning.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e,
                ));
            }
            Err(_) => {
                return Err(std::io::Error::other("mux channel closed"));
            }
        };

        if is_connect_data_unsupported_response(&resp) {
            tracing::debug!(
                "connect_data unsupported for {}:{}: {:?}",
                host,
                port,
                resp.e
            );
            return Ok(ConnectDataOutcome::Unsupported);
        }

        if let Some(ref e) = resp.e {
            tracing::error!("tunnel connect_data error for {}:{}: {}", host, port, e);
            // `resp.e` is the tunnel-node's own connect result — cache it.
            mux.record_unreachable_if_match(host, port, e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                e.clone(),
            ));
        }

        let Some(sid) = resp.sid.clone() else {
            return Err(std::io::Error::other("tunnel connect_data: no session id"));
        };

        return Ok(ConnectDataOutcome::Opened {
            sid,
            response: resp,
        });
    }

    unreachable!("connect_data attempts is always at least one")
}

/// Decide whether a response indicates the tunnel-node (or apps_script
/// layer in front of it) didn't recognize `connect_data`.
///
/// Primary signal: the structured `code` field (`UNSUPPORTED_OP`), emitted
/// by any tunnel-node or apps_script deployment that has this change.
/// Fallback signal (for legacy deployments, pre-connect_data): substring
/// match on the stable error string. The string-match is a one-way
/// compatibility hatch — newer deployments set `code` so future refactors
/// of the error text won't silently break detection.
///
/// Two error shapes are possible on the legacy path:
///   * tunnel-node's single-op/batch handler: `"unknown op: connect_data"`
///   * apps_script's `_doTunnel` default branch: `"unknown tunnel op: connect_data"`
///
/// Apps_script and tunnel-node ship on independent cadences, so it is
/// realistic for a user to upgrade one but not the other — detection has
/// to cover both shapes or the feature hard-fails on version skew.
fn is_connect_data_unsupported_response(resp: &TunnelResponse) -> bool {
    if resp.code.as_deref() == Some(CODE_UNSUPPORTED_OP) {
        return true;
    }
    resp.e
        .as_deref()
        .map(is_connect_data_unsupported_error_str)
        .unwrap_or(false)
}

fn is_connect_data_unsupported_error_str(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    (e.contains("unknown op") || e.contains("unknown tunnel op")) && e.contains("connect_data")
}

fn is_retryable_connect_data_transport_error(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    e.contains("peer closed connection without sending tls close_notify")
        || e.contains("unexpected eof")
        || e.contains("early eof")
        || e.contains("connection reset")
        || e.contains("broken pipe")
}

fn is_tls_record_handshake(data: &[u8]) -> bool {
    matches!(data, [0x16, 0x03, ..])
}

/// Metadata for one in-flight Data op, returned alongside its reply.
struct InflightMeta {
    seq: u64,
    was_empty_poll: bool,
    send_at: Instant,
}

enum TunnelEnd {
    /// The tunnel-node returned EOF in a data response. The node removes
    /// the session in that same batch, so sending an extra `close` would
    /// only burn one more Apps Script fetch.
    RemoteEof,
    /// The local client closed first or the tunnel ended on an error.
    /// Send an explicit close so the tunnel-node can free resources now.
    NeedsClose,
}

async fn tunnel_loop(
    sock: &mut TcpStream,
    sid: &str,
    mux: &Arc<TunnelMux>,
    pending_client_data: Option<Bytes>,
) -> std::io::Result<TunnelEnd> {
    let (mut reader, mut writer) = sock.split();

    let inflight_cap = INFLIGHT_ACTIVE;
    let mut max_inflight = INFLIGHT_OPTIMIST.min(inflight_cap);
    let mut consecutive_empty = 0u32;
    let mut consecutive_data: u32 = 0;
    let mut is_elevated = false;
    let mut total_download_bytes: u64 = 0;
    let mut next_send_seq: u64 = 0;
    let mut next_write_seq: u64 = 0;
    let mut next_data_write_seq: u64 = 0;
    let mut eof_seen = false;
    let mut client_closed = false;
    let mut pending_writes: BTreeMap<u64, (TunnelResponse, String)> = BTreeMap::new();

    // Tunnel-node feature detection. Two facts:
    //   * Pipelining nodes echo `resp.seq` on every reply; pre-pipelining
    //     nodes drop the unknown field and return without it.
    //   * Both kinds of node tolerate `wseq` on the wire — legacy nodes
    //     drop it and write in arrival order, pipelining nodes use it
    //     for in-order flushing.
    //
    // So `send_data_op` unconditionally attaches `wseq` (no rollout
    // race: there is no transition window during which uploads carry
    // None then suddenly Some). What this flag DOES gate is *throughput*:
    //   * `max_inflight + 4` fast-path slack stays at 0 until we
    //     confirm pipelining (no point queuing more inflight ops on a
    //     server that processes them serially).
    //   * `max_inflight` is force-clamped to 1 if any reply lacks `seq`.
    // Detection is one-way (false → true on first `Some(seq)` reply)
    // and tied to the connection lifetime — a deployment swap mid-flight
    // is the only thing that would break the invariant, and even then
    // the worst case is the slack temporarily over-allocates ops the
    // serial server will process in order.
    let mut tunnel_node_supports_seq: bool = false;

    // Buffered upload data waiting to be sent (when pipeline is full).
    let mut buffered_upload: Option<Bytes> = None;

    enum ReplyOutcome {
        Ok(TunnelResponse, String),
        BatchErr(String),
        Timeout,
        Dropped,
    }
    type ReplyFut =
        std::pin::Pin<Box<dyn std::future::Future<Output = (InflightMeta, ReplyOutcome)> + Send>>;
    let mut inflight: FuturesUnordered<ReplyFut> = FuturesUnordered::new();
    let mut inflight_uploads: usize = 0;

    // Reply timeout: use the mux's config-derived value (request_timeout_secs
    // + REPLY_TIMEOUT_SLACK) rather than the hardcoded REPLY_TIMEOUT constant
    // so an operator who raised `request_timeout_secs` doesn't see pipelined
    // polls abandon their reply just before the HTTP round-trip would have
    // completed. Matches the contract on `TunnelMux::reply_timeout`.
    let reply_timeout = mux.reply_timeout();

    // Helper: wrap a reply_rx into a ReplyFut with timeout.
    fn wrap_reply(
        meta: InflightMeta,
        reply_rx: BatchedReplyRx,
        reply_timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (InflightMeta, ReplyOutcome)> + Send>>
    {
        Box::pin(async move {
            match tokio::time::timeout(reply_timeout, reply_rx).await {
                Ok(Ok(Ok((r, sid)))) => (meta, ReplyOutcome::Ok(r, sid)),
                Ok(Ok(Err(e))) => (meta, ReplyOutcome::BatchErr(e)),
                Ok(Err(_)) => (meta, ReplyOutcome::Dropped),
                Err(_) => (meta, ReplyOutcome::Timeout),
            }
        })
    }

    /// Send an empty poll Data op. Returns the InflightMeta and reply rx.
    #[inline]
    fn send_empty_poll(
        sid: &str,
        next_send_seq: &mut u64,
        mux: &Arc<TunnelMux>,
    ) -> (InflightMeta, BatchedReplyRx) {
        let seq = *next_send_seq;
        *next_send_seq += 1;
        let (reply_tx, reply_rx) = oneshot::channel();
        let send_at = Instant::now();
        mux.send_sync(MuxMsg::Data {
            sid: sid.to_string(),
            data: Bytes::new(),
            seq: Some(seq),
            wseq: None,
            reply: reply_tx,
        });
        let meta = InflightMeta {
            seq,
            was_empty_poll: true,
            send_at,
        };
        (meta, reply_rx)
    }

    /// Send a data op with a monotonic `wseq` attached. The wseq field
    /// is *always* set — pre-pipelining tunnel-nodes silently drop it
    /// (serde's default `#[derive(Deserialize)]` ignores unknown fields)
    /// and write in arrival order, so attaching wseq is a no-op there.
    /// Pipelining tunnel-nodes use wseq to flush per-session writes in
    /// client order. The previous shape gated wseq behind a runtime
    /// "supports_seq" flag, but that opened a rollout race: pre-detection
    /// uploads went out with `wseq=None`, the pipelining server wrote
    /// those immediately while later `Some(wseq)` uploads were ordered,
    /// and the two streams could interleave out of order on the upstream
    /// socket. Always-on wseq eliminates the race.
    #[inline]
    fn send_data_op(
        sid: &str,
        data: Bytes,
        next_send_seq: &mut u64,
        next_data_write_seq: &mut u64,
        mux: &Arc<TunnelMux>,
    ) -> (InflightMeta, BatchedReplyRx) {
        let seq = *next_send_seq;
        *next_send_seq += 1;
        let wseq = *next_data_write_seq;
        *next_data_write_seq += 1;
        let (reply_tx, reply_rx) = oneshot::channel();
        let send_at = Instant::now();
        let sid_short = &sid[..sid.len().min(8)];
        tracing::debug!(
            "sess {}: upload send seq={} wseq={} len={}B",
            sid_short,
            seq,
            wseq,
            data.len(),
        );
        mux.send_sync(MuxMsg::Data {
            sid: sid.to_string(),
            data,
            seq: Some(seq),
            wseq: Some(wseq),
            reply: reply_tx,
        });
        let meta = InflightMeta {
            seq,
            was_empty_poll: false,
            send_at,
        };
        (meta, reply_rx)
    }

    // ── Initial path: send pending client data or read from client ──
    if let Some(data) = pending_client_data {
        if !data.is_empty() {
            let (meta, reply_rx) =
                send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
            tracing::debug!(
                "sess {}: pending data seq={}",
                &sid[..sid.len().min(8)],
                meta.seq,
            );
            inflight_uploads += 1;
            inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
        }
    }

    // Pre-fill one poll synchronously (so we have something in flight
    // immediately and the tunnel-node sees a poll within the first RTT),
    // then hand the rest of the optimist-depth pre-fill off to the
    // refill timer below. The previous shape blocked the entire setup
    // path with a `tokio::time::sleep(1s)` per extra slot, during which
    // the client socket wasn't read — visible as a >1 s startup stall
    // on no-pending-data flows like HTTPS GETs that send a small
    // ClientHello and expect a fast first response.
    if inflight.len() < max_inflight {
        let (meta, reply_rx) = send_empty_poll(sid, &mut next_send_seq, mux);
        tracing::debug!(
            "sess {}: prefill poll seq={}, inflight={}",
            &sid[..sid.len().min(8)],
            meta.seq,
            inflight.len() + 1,
        );
        inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
    }

    // Timer for staggered refill polls — fires in the select, never blocks.
    // Active sessions refill after a short fixed gap. Long-idle sessions
    // gradually leave a larger no-poll gap after repeated empty replies to
    // save Apps Script quota.
    let mut refill_at: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;

    // Arm the refill timer if we still owe pre-fill slots. We bootstrap
    // with `ACTIVE_REFILL_DELAY_MS` (1 s) here because the session has
    // just started — there is no `consecutive_empty` history yet. After
    // the first reply lands, the reply arm and the refill arm both use
    // `refill_delay(max_inflight, consecutive_empty)`: that returns
    // `ACTIVE_REFILL_DELAY_MS` while max_inflight is non-idle, collapses
    // to zero only at IDLE depth with `consecutive_empty < IDLE_REFILL_
    // DELAY_START_EMPTY` (back-to-back long-polling), and then ramps to
    // `IDLE_REFILL_DELAY_MAX_MS` under sustained idleness.
    if inflight.len() < max_inflight {
        refill_at = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
            ACTIVE_REFILL_DELAY_MS,
        ))));
    }

    // Read buffer for client socket.
    let mut read_buf = BytesMut::with_capacity(65536);

    // Main select loop — handles both upload reads and download replies.
    loop {
        // If nothing in flight and tunnel EOF, we're done.
        if inflight.is_empty() && eof_seen {
            break;
        }

        // If nothing in flight and client closed, we're done.
        if inflight.is_empty() && client_closed {
            break;
        }

        // If eof was seen but inflight is not empty, give remaining
        // replies a short grace period to deliver any buffered data
        // before the remote connection closed. After 500ms, abandon them.
        if eof_seen && !inflight.is_empty() {
            match tokio::time::timeout(Duration::from_millis(500), inflight.next()).await {
                Ok(Some((meta, ReplyOutcome::Ok(resp, script_id)))) => {
                    if !meta.was_empty_poll {
                        inflight_uploads = inflight_uploads.saturating_sub(1);
                    }
                    if meta.seq == next_write_seq {
                        let _ = write_tunnel_response(&mut writer, &resp).await;
                        next_write_seq += 1;
                        while let Some(entry) = pending_writes.first_entry() {
                            if *entry.key() != next_write_seq {
                                break;
                            }
                            let (_, (buffered_resp, _)) = entry.remove_entry();
                            let _ = write_tunnel_response(&mut writer, &buffered_resp).await;
                            next_write_seq += 1;
                        }
                    } else {
                        pending_writes.insert(meta.seq, (resp, script_id));
                    }
                    continue;
                }
                _ => break,
            }
        }

        // When inflight is empty and we haven't seen eof, read from
        // client or send an empty poll to keep the session alive.
        if inflight.is_empty() && !eof_seen && refill_at.is_none() {
            let all_legacy = mux.all_servers_legacy();

            // If all servers are legacy and we've had many consecutive
            // empties, wait for client data before sending. Threshold
            // shared with `should_suppress_empty_refill` so the two idle-
            // gate sites stay in lockstep.
            if all_legacy && consecutive_empty >= IDLE_REFILL_DELAY_START_EMPTY && !client_closed {
                read_buf.reserve(65536);
                match reader.read_buf(&mut read_buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        consecutive_empty = 0;
                        let data = extract_bytes(&mut read_buf, n);
                        let (meta, reply_rx) = send_data_op(
                            sid,
                            data,
                            &mut next_send_seq,
                            &mut next_data_write_seq,
                            mux,
                        );
                        inflight_uploads += 1;
                        inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
                        continue;
                    }
                    Err(_) => break,
                }
            }

            let (meta, reply_rx) = send_empty_poll(sid, &mut next_send_seq, mux);
            tracing::debug!(
                "sess {}: keepalive poll seq={}",
                &sid[..sid.len().min(8)],
                meta.seq
            );
            inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
        }

        // Can we read from the client? Yes if not closed, not eof, and
        // we have room for more inflight ops. The +4 fast-path bonus
        // only applies once we've confirmed the tunnel-node supports
        // pipelined replies — on a legacy server (no `seq` echo) we
        // hold the loop at `max_inflight = 1` since extra inflight ops
        // would just queue on the server's serial reply path with no
        // throughput benefit.
        let fast_path_slack = if tunnel_node_supports_seq { 4 } else { 0 };
        let can_read =
            !client_closed && !eof_seen && inflight.len() < max_inflight + fast_path_slack;

        tokio::select! {
            biased;

            // Refill timer: pace empty polls so idle sessions do not spin
            // a new Apps Script batch immediately after every empty long-poll.
            _ = async { refill_at.as_mut().unwrap().await }, if refill_at.is_some() => {
                refill_at = None;
                if !eof_seen && inflight.len() < max_inflight {
                    if should_suppress_empty_refill(
                        buffered_upload.is_some(),
                        client_closed,
                        max_inflight,
                        consecutive_empty,
                        mux.all_servers_legacy(),
                    ) {
                        continue;
                    }
                    // Check buffered upload first — merge into a data op
                    // instead of sending an empty poll.
                    if let Some(data) = buffered_upload.take() {
                        let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                        inflight_uploads += 1;
                        inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
                    } else if inflight_uploads > 0 {
                        // A data op is already able to drain the upstream
                        // response. Sending an older empty poll here creates
                        // an in-order barrier for a later data-bearing reply.
                        tracing::debug!(
                            "sess {}: defer empty refill; {} upload op(s) in flight",
                            &sid[..sid.len().min(8)],
                            inflight_uploads,
                        );
                    } else {
                        let (meta, reply_rx) = send_empty_poll(sid, &mut next_send_seq, mux);
                        inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
                    }

                    if inflight.len() < max_inflight && !is_idle_depth(max_inflight) {
                        refill_at = Some(Box::pin(tokio::time::sleep(refill_delay(max_inflight, consecutive_empty))));
                    }
                }
            }

            // Process completed replies.
            Some((meta, outcome)) = inflight.next() => {
                if !meta.was_empty_poll {
                    inflight_uploads = inflight_uploads.saturating_sub(1);
                }
                match outcome {
                    ReplyOutcome::Ok(resp, script_id) => {
                        let has_data = resp.d.as_ref().map(|d| !d.is_empty()).unwrap_or(false);
                        tracing::debug!(
                            "sess {}: recv seq={}, rtt={:?}, data={}, inflight={}",
                            &sid[..sid.len().min(8)],
                            meta.seq,
                            meta.send_at.elapsed(),
                            has_data,
                            inflight.len(),
                        );
                        // Throughput gate: `tunnel_node_supports_seq`
                        // controls whether we use the fast-path slack
                        // (+4 reads beyond `max_inflight`) and whether
                        // depth ramps past 1. It does NOT control wseq
                        // emission — `send_data_op` always sets wseq,
                        // since a legacy server safely ignores the field
                        // (see the rollout-race note on `send_data_op`).
                        if resp.seq.is_some() && !tunnel_node_supports_seq {
                            tunnel_node_supports_seq = true;
                        }
                        if resp.seq.is_none() {
                            max_inflight = 1;
                        }

                        // Legacy / no-long-poll deployment detection.
                        // Two signals, both per-`script_id`:
                        //
                        //   1. `resp.seq.is_none()`: the deterministic
                        //      one. The pipelining tunnel-node echoes
                        //      `seq` on every reply; pre-pipelining nodes
                        //      drop the unknown field and return without
                        //      it. A single seq-absent reply is enough
                        //      to flag the deployment.
                        //   2. Fast-empty-poll heuristic (pre-PR style):
                        //      an empty poll that came back with no data
                        //      faster than `LEGACY_DETECT_THRESHOLD`
                        //      indicates the server isn't really
                        //      long-polling — covers pathological cases
                        //      where seq IS echoed but the server still
                        //      drains-and-returns immediately.
                        //
                        // The aggregate `all_servers_legacy()` gate
                        // drives the skip-empty-when-idle path in the
                        // outer loop (line ~1818). Without this call,
                        // legacy deployments keep fast-polling and burn
                        // Apps Script quota at the pipelined defaults.
                        let fast_empty_poll =
                            meta.was_empty_poll
                                && !has_data
                                && meta.send_at.elapsed() < LEGACY_DETECT_THRESHOLD;
                        if resp.seq.is_none() || fast_empty_poll {
                            mux.mark_server_no_longpoll(&script_id);
                        }

                        if let Some(ref e) = resp.e {
                            tracing::debug!("tunnel error: {}", e);
                            break;
                        }

                        let is_eof = resp.eof.unwrap_or(false);
                        let resp_has_seq = resp.seq.is_some();

                        // Write in-order to client.
                        if meta.seq == next_write_seq {
                            let got_data = match write_tunnel_response(&mut writer, &resp).await? {
                                WriteOutcome::Wrote => true,
                                WriteOutcome::NoData => false,
                                WriteOutcome::BadBase64 => break,
                            };
                            next_write_seq += 1;
                            if got_data {
                                consecutive_empty = 0;
                                consecutive_data = consecutive_data.saturating_add(1);
                                let bytes = resp.d.as_ref().map(|d| d.len() as u64 * 3 / 4).unwrap_or(0);
                                total_download_bytes += bytes;
                            } else {
                                consecutive_empty = consecutive_empty.saturating_add(1);
                            }
                            if is_eof {
                                eof_seen = true;
                            }

                            // Flush buffered out-of-order writes.
                            let mut bad_base64_in_buffered = false;
                            while let Some(entry) = pending_writes.first_entry() {
                                if *entry.key() != next_write_seq { break; }
                                let (_, (buffered_resp, _)) = entry.remove_entry();
                                let buf_eof = buffered_resp.eof.unwrap_or(false);
                                match write_tunnel_response(&mut writer, &buffered_resp).await? {
                                    WriteOutcome::Wrote => {
                                        consecutive_empty = 0;
                                        consecutive_data = consecutive_data.saturating_add(1);
                                        let bytes = buffered_resp.d.as_ref().map(|d| d.len() as u64 * 3 / 4).unwrap_or(0);
                                        total_download_bytes += bytes;
                                    }
                                    WriteOutcome::NoData => {
                                        consecutive_empty = consecutive_empty.saturating_add(1);
                                    }
                                    WriteOutcome::BadBase64 => {
                                        // The immediate-response path
                                        // (above) `break`s the outer
                                        // tunnel loop on BadBase64,
                                        // closing the session. The
                                        // buffered-flush path must do
                                        // the same: we just removed the
                                        // entry from `pending_writes`
                                        // without bumping
                                        // `next_write_seq`, so leaving
                                        // the session alive would stall
                                        // every subsequent reply behind
                                        // a seq that can't arrive.
                                        bad_base64_in_buffered = true;
                                        break;
                                    }
                                }
                                next_write_seq += 1;
                                if buf_eof {
                                    eof_seen = true;
                                }
                            }
                            if bad_base64_in_buffered {
                                break;
                            }
                        } else {
                            pending_writes.insert(meta.seq, (resp, script_id));
                        }

                        // Send buffered upload data now that a slot freed up.
                        if let Some(data) = buffered_upload.take() {
                            if inflight.len() < max_inflight {
                                let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                                consecutive_empty = 0;
                                inflight_uploads += 1;
                                refill_at = None;
                                inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
                            } else {
                                buffered_upload = Some(data);
                            }
                        }

                        // Adaptive pipeline depth management.
                        tracing::debug!(
                            "sess {}: depth={} cd={} ce={} inf={} has_seq={}",
                            &sid[..sid.len().min(8)],
                            max_inflight, consecutive_data, consecutive_empty, inflight.len(), resp_has_seq,
                        );
                        if resp_has_seq {
                            let prev = max_inflight;
                            if consecutive_empty >= 2 && !is_idle_depth(max_inflight) {
                                max_inflight = INFLIGHT_IDLE.min(inflight_cap);
                                if is_elevated {
                                    let n = mux.elevated_sessions.fetch_sub(1, Ordering::Relaxed);
                                    pipeline_debug::set_elevated(n.saturating_sub(1));
                                    is_elevated = false;
                                }
                            } else if consecutive_data >= 1 && max_inflight < INFLIGHT_OPTIMIST {
                                max_inflight = INFLIGHT_OPTIMIST.min(inflight_cap);
                            } else if consecutive_data >= 2
                                && max_inflight >= INFLIGHT_OPTIMIST
                                && max_inflight < inflight_cap
                                && total_download_bytes >= 32 * 1024
                            {
                                if !is_elevated {
                                    // CAS-loop admission: load + fetch_add
                                    // raced — two concurrent sessions could
                                    // both observe `cur < max_elevated`, both
                                    // fetch_add, and overshoot the cap.
                                    // compare_exchange_weak in a retry loop
                                    // keeps the count under the ceiling.
                                    let max = mux.max_elevated;
                                    let mut cur = mux.elevated_sessions.load(Ordering::Relaxed);
                                    loop {
                                        if cur >= max {
                                            break;
                                        }
                                        match mux.elevated_sessions.compare_exchange_weak(
                                            cur,
                                            cur + 1,
                                            Ordering::Relaxed,
                                            Ordering::Relaxed,
                                        ) {
                                            Ok(_) => {
                                                pipeline_debug::set_elevated(cur + 1);
                                                is_elevated = true;
                                                max_inflight =
                                                    (max_inflight + 1).min(inflight_cap);
                                                break;
                                            }
                                            Err(v) => cur = v,
                                        }
                                    }
                                } else {
                                    max_inflight = (max_inflight + 1).min(inflight_cap);
                                }
                            }
                            pipeline_debug::session_update(sid, max_inflight, inflight.len(), is_elevated);
                            if max_inflight != prev {
                                tracing::info!(
                                    "sess {}: pipeline {} -> {}{}",
                                    &sid[..sid.len().min(8)],
                                    prev,
                                    max_inflight,
                                    if is_elevated { " [elevated]" } else { "" },
                                );
                                pipeline_debug::push_event(format!(
                                    "{} {}->{}{}",
                                    &sid[..sid.len().min(8)],
                                    prev,
                                    max_inflight,
                                    if is_elevated { " E" } else { "" },
                                ));
                            }
                        }

                        // Schedule refill if pipeline needs more polls.
                        if !eof_seen
                            && inflight.len() < max_inflight
                            && inflight_uploads == 0
                            && refill_at.is_none()
                            && !should_suppress_empty_refill(
                                buffered_upload.is_some(),
                                client_closed,
                                max_inflight,
                                consecutive_empty,
                                mux.all_servers_legacy(),
                            ) {
                                refill_at = Some(Box::pin(tokio::time::sleep(refill_delay(
                                    max_inflight,
                                    consecutive_empty,
                                ))));
                            }
                    }
                    ReplyOutcome::BatchErr(e) => {
                        tracing::debug!("tunnel data error: {}", e);
                        break;
                    }
                    ReplyOutcome::Timeout => {
                        // Terminal: closing the session. Reasoning —
                        // downstream is strictly in-order by `meta.seq`
                        // (see the `meta.seq == next_write_seq` gate
                        // above), and any later replies are held in
                        // `pending_writes` until the missing seq catches
                        // up. A timed-out seq never catches up, so
                        // continuing here would silently stall the
                        // session until eviction; the client would see
                        // a half-open connection that accepts uploads
                        // but never receives a byte back. Closing forces
                        // the client (browser / app) to retry — usually
                        // over the regular TCP path or a new SOCKS5
                        // session — which is the correct recovery shape.
                        tracing::warn!(
                            "sess {}: reply timeout (seq {}), closing session",
                            &sid[..sid.len().min(8)],
                            meta.seq,
                        );
                        break;
                    }
                    ReplyOutcome::Dropped => {
                        break;
                    }
                }
            }

            // Read from client (overlapped with reply processing).
            result = async {
                read_buf.reserve(65536);
                reader.read_buf(&mut read_buf).await
            }, if can_read => {
                match result {
                    Ok(0) => {
                        client_closed = true;
                    }
                    Ok(n) => {
                        let data = extract_bytes(&mut read_buf, n);
                        if inflight.len() < max_inflight {
                            // Normal path: send immediately as data op.
                            let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                            consecutive_empty = 0;
                            inflight_uploads += 1;
                            refill_at = None;
                            inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
                        } else if inflight.len() < max_inflight + 4 {
                            // Fast-path: pipeline full but under +4 extra.
                            let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                            consecutive_empty = 0;
                            inflight_uploads += 1;
                            refill_at = None;
                            inflight.push(wrap_reply(meta, reply_rx, reply_timeout));
                        } else {
                            // Buffer upload data until a slot frees up.
                            if let Some(ref mut existing) = buffered_upload {
                                // Merge: append new data to existing buffer.
                                let mut merged = BytesMut::with_capacity(existing.len() + data.len());
                                merged.extend_from_slice(existing);
                                merged.extend_from_slice(&data);
                                *existing = merged.freeze();
                            } else {
                                buffered_upload = Some(data);
                            }
                        }
                    }
                    Err(_) => {
                        client_closed = true;
                    }
                }
            }
        }
    }

    // Release elevation permit.
    if is_elevated {
        let n = mux.elevated_sessions.fetch_sub(1, Ordering::Relaxed);
        pipeline_debug::set_elevated(n.saturating_sub(1));
    }
    Ok(if eof_seen {
        TunnelEnd::RemoteEof
    } else {
        TunnelEnd::NeedsClose
    })
}

enum WriteOutcome {
    Wrote,
    NoData,
    BadBase64,
}

async fn write_tunnel_response<W>(
    writer: &mut W,
    resp: &TunnelResponse,
) -> std::io::Result<WriteOutcome>
where
    W: AsyncWrite + Unpin,
{
    let Some(ref d) = resp.d else {
        return Ok(WriteOutcome::NoData);
    };
    if d.is_empty() {
        return Ok(WriteOutcome::NoData);
    }

    match B64.decode(d) {
        Ok(bytes) if !bytes.is_empty() => {
            writer.write_all(&bytes).await?;
            writer.flush().await?;
            Ok(WriteOutcome::Wrote)
        }
        Ok(_) => Ok(WriteOutcome::NoData),
        Err(e) => {
            tracing::error!("tunnel bad base64: {}", e);
            Ok(WriteOutcome::BadBase64)
        }
    }
}

/// Extract bytes from the read buffer, applying the zero-copy threshold.
/// Reads >= half the buffer use split+freeze (zero-copy); smaller reads
/// copy out and clear so the buffer allocation is reused.
fn extract_bytes(buf: &mut BytesMut, n: usize) -> Bytes {
    const ZERO_COPY_THRESHOLD: usize = 65536 / 2;
    if n >= ZERO_COPY_THRESHOLD {
        buf.split().freeze()
    } else {
        let owned = Bytes::copy_from_slice(&buf[..n]);
        buf.clear();
        owned
    }
}

pub fn decode_udp_packets(resp: &TunnelResponse) -> Result<Vec<Vec<u8>>, String> {
    let Some(pkts) = resp.pkts.as_ref() else {
        return Ok(Vec::new());
    };
    pkts.iter()
        .map(|pkt| {
            B64.decode(pkt)
                .map_err(|e| format!("bad UDP packet base64: {}", e))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn resp_with(code: Option<&str>, e: Option<&str>) -> TunnelResponse {
        TunnelResponse {
            sid: None,
            d: None,
            pkts: None,
            eof: None,
            e: e.map(str::to_string),
            code: code.map(str::to_string),
            seq: None,
        }
    }

    fn opened_resp(sid: &str) -> TunnelResponse {
        TunnelResponse {
            sid: Some(sid.to_string()),
            d: None,
            pkts: None,
            eof: None,
            e: None,
            code: None,
            seq: None,
        }
    }

    #[test]
    fn unsupported_detection_via_structured_code() {
        assert!(is_connect_data_unsupported_response(&resp_with(
            Some("UNSUPPORTED_OP"),
            None
        )));
        assert!(is_connect_data_unsupported_response(&resp_with(
            Some("UNSUPPORTED_OP"),
            Some("unknown op: connect_data"),
        )));
    }

    #[test]
    fn unsupported_detection_via_legacy_tunnel_node_string() {
        // Pre-change tunnel-node: no code field, bare "unknown op: ...".
        assert!(is_connect_data_unsupported_response(&resp_with(
            None,
            Some("unknown op: connect_data"),
        )));
        assert!(is_connect_data_unsupported_response(&resp_with(
            None,
            Some("Unknown Op: CONNECT_DATA"),
        )));
    }

    #[test]
    fn unsupported_detection_via_legacy_apps_script_string() {
        // Pre-change apps_script: default branch emits "unknown tunnel op: ...".
        // This is the realistic skew case — user upgrades tunnel-node + client
        // binary but hasn't redeployed the Apps Script yet.
        assert!(is_connect_data_unsupported_response(&resp_with(
            None,
            Some("unknown tunnel op: connect_data"),
        )));
    }

    #[test]
    fn unsupported_detection_rejects_unrelated_errors() {
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None,
            Some("connect failed: refused"),
        )));
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None,
            Some("bad base64")
        )));
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None, None
        )));
        // "connect_data" alone (without "unknown op") shouldn't trigger.
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None,
            Some("connect_data: bad port"),
        )));
    }

    #[test]
    fn retryable_connect_data_transport_error_matches_transient_io() {
        assert!(is_retryable_connect_data_transport_error(
            "io: peer closed connection without sending TLS close_notify"
        ));
        assert!(is_retryable_connect_data_transport_error(
            "io: unexpected eof"
        ));
        assert!(is_retryable_connect_data_transport_error(
            "io: connection reset by peer"
        ));
        assert!(!is_retryable_connect_data_transport_error(
            "batch timed out"
        ));
        assert!(!is_retryable_connect_data_transport_error(
            "connect failed: Network is unreachable"
        ));
        assert!(!is_retryable_connect_data_transport_error(
            "unknown op: connect_data"
        ));
    }

    #[test]
    fn tls_record_handshake_detection_is_narrow() {
        assert!(is_tls_record_handshake(&[0x16, 0x03, 0x03]));
        assert!(is_tls_record_handshake(&[0x16, 0x03]));
        assert!(!is_tls_record_handshake(&[0x16]));
        assert!(!is_tls_record_handshake(&[0x16, 0x04, 0x00]));
        assert!(!is_tls_record_handshake(b"GET / HTTP/1.1\r\n\r\n"));
    }

    #[tokio::test]
    async fn connect_data_retries_tls_transport_error_once() {
        let (mux, mut rx) = mux_for_test();
        let mux_for_task = mux.clone();
        let task = tokio::spawn(async move {
            connect_with_initial_data(
                "example.com",
                443,
                Bytes::from_static(&[0x16, 0x03, 0x03, 0x00, 0x01]),
                &mux_for_task,
            )
            .await
        });

        let first = rx.recv().await.expect("first connect_data");
        let reply = match first {
            MuxMsg::ConnectData { data, reply, .. } => {
                assert_eq!(data.as_ref(), &[0x16, 0x03, 0x03, 0x00, 0x01]);
                reply
            }
            other => panic!(
                "expected first ConnectData, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        let _ = reply.send(Err(
            "io: peer closed connection without sending TLS close_notify".into(),
        ));

        let second = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("retry should be sent")
            .expect("second connect_data");
        let reply = match second {
            MuxMsg::ConnectData { data, reply, .. } => {
                assert_eq!(data.as_ref(), &[0x16, 0x03, 0x03, 0x00, 0x01]);
                reply
            }
            other => panic!(
                "expected retry ConnectData, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        let _ = reply.send(Ok((opened_resp("sid-retry"), "script-b".to_string())));

        let outcome = task.await.expect("task").expect("connect_data result");
        match outcome {
            ConnectDataOutcome::Opened { sid, .. } => assert_eq!(sid, "sid-retry"),
            ConnectDataOutcome::Unsupported => panic!("retry should open"),
        }
    }

    #[tokio::test]
    async fn connect_data_does_not_retry_cleartext_transport_error() {
        let (mux, mut rx) = mux_for_test();
        let mux_for_task = mux.clone();
        let task = tokio::spawn(async move {
            connect_with_initial_data(
                "example.com",
                80,
                Bytes::from_static(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                &mux_for_task,
            )
            .await
        });

        let first = rx.recv().await.expect("first connect_data");
        let reply = match first {
            MuxMsg::ConnectData { data, reply, .. } => {
                assert!(data.starts_with(b"GET "));
                reply
            }
            other => panic!(
                "expected first ConnectData, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        let _ = reply.send(Err(
            "io: peer closed connection without sending TLS close_notify".into(),
        ));

        let err = match task.await.expect("task") {
            Ok(ConnectDataOutcome::Opened { .. }) => panic!("cleartext retry should not open"),
            Ok(ConnectDataOutcome::Unsupported) => panic!("cleartext retry should not fallback"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(
            rx.try_recv().is_err(),
            "cleartext connect_data must not emit a retry"
        );
    }

    #[test]
    fn unreachable_error_str_matches_expected_variants() {
        assert!(is_unreachable_error_str(
            "connect failed: Network is unreachable (os error 101)"
        ));
        assert!(is_unreachable_error_str("No route to host"));
        assert!(is_unreachable_error_str("os error 113"));
        // Case-insensitive.
        assert!(is_unreachable_error_str(
            "CONNECT FAILED: NETWORK IS UNREACHABLE"
        ));
    }

    #[test]
    fn unreachable_error_str_rejects_unrelated() {
        assert!(!is_unreachable_error_str("connection refused"));
        assert!(!is_unreachable_error_str("connect timed out"));
        assert!(!is_unreachable_error_str("connection reset by peer"));
        assert!(!is_unreachable_error_str(""));
    }

    #[test]
    fn negative_cache_records_and_short_circuits() {
        let (mux, _rx) = mux_for_test();
        // Initially nothing is cached.
        assert!(!mux.is_unreachable("ds6.probe.example", 443));
        // Record a matching error.
        mux.record_unreachable_if_match(
            "ds6.probe.example",
            443,
            "connect failed: Network is unreachable (os error 101)",
        );
        assert!(mux.is_unreachable("ds6.probe.example", 443));
        // A different port for the same host is its own entry.
        assert!(!mux.is_unreachable("ds6.probe.example", 80));
    }

    #[test]
    fn negative_cache_ignores_non_unreachable_errors() {
        let (mux, _rx) = mux_for_test();
        mux.record_unreachable_if_match("example.com", 443, "connect failed: connection refused");
        assert!(!mux.is_unreachable("example.com", 443));
    }

    #[test]
    fn negative_cache_normalizes_host_keys() {
        let (mux, _rx) = mux_for_test();
        // Cache under one casing/format...
        mux.record_unreachable_if_match(
            "Example.COM.",
            443,
            "Network is unreachable (os error 101)",
        );
        // ...and look up under several equivalent forms.
        assert!(mux.is_unreachable("example.com", 443));
        assert!(mux.is_unreachable("EXAMPLE.com", 443));
        assert!(mux.is_unreachable("example.com.", 443));
        // Different host should still miss.
        assert!(!mux.is_unreachable("other.com", 443));
    }

    /// Outer `Ok(Err(_))` from the mux channel means "the relay never
    /// reached the tunnel-node" (HTTP/TLS to Apps Script failed, batch
    /// timed out, etc.) — the destination wasn't even attempted. Even if
    /// that error string contains "Network is unreachable" (e.g. the
    /// client device's WAN was momentarily down), it must NOT poison the
    /// destination cache, or every host the user touched during a
    /// connectivity blip stays refused for 30s.
    #[tokio::test]
    async fn negative_cache_skips_outer_relay_errors() {
        let (mux, mut rx) = mux_for_test();
        let mux_for_task = mux.clone();
        let task =
            tokio::spawn(
                async move { connect_plain("real.target.example", 443, &mux_for_task).await },
            );

        // Receive the Connect msg and reply with an outer Err whose string
        // would otherwise match `is_unreachable_error_str`.
        let msg = rx.recv().await.expect("connect msg");
        let reply = match msg {
            MuxMsg::Connect { reply, .. } => reply,
            other => panic!("expected Connect, got {:?}", std::mem::discriminant(&other)),
        };
        let _ = reply.send(Err(
            "relay failed: Network is unreachable (os error 101)".into()
        ));

        let res = task.await.expect("task");
        assert!(res.is_err(), "connect_plain should surface the error");
        assert!(
            !mux.is_unreachable("real.target.example", 443),
            "outer relay error must not negative-cache the destination"
        );
    }

    #[test]
    fn negative_cache_enforces_hard_cap_under_unique_burst() {
        let (mux, _rx) = mux_for_test();
        // Insert enough unique still-live entries to exceed the cap. The
        // map size must never exceed UNREACHABLE_CACHE_MAX, even though
        // every entry is fresh and `retain(expired)` prunes nothing.
        let burst = UNREACHABLE_CACHE_MAX + 50;
        for i in 0..burst {
            let host = format!("h{}.example", i);
            mux.record_unreachable_if_match(
                &host,
                443,
                "connect failed: Network is unreachable (os error 101)",
            );
        }
        let len = mux.unreachable_cache.lock().map(|g| g.len()).unwrap_or(0);
        assert!(
            len <= UNREACHABLE_CACHE_MAX,
            "cache size {} exceeded cap {}",
            len,
            UNREACHABLE_CACHE_MAX
        );
    }

    #[test]
    fn server_speaks_first_covers_common_protocols() {
        for p in [21u16, 22, 25, 110, 143, 587] {
            assert!(
                is_server_speaks_first(p),
                "port {} should be server-first",
                p
            );
        }
        for p in [80u16, 443, 8443, 853, 993, 1234] {
            assert!(
                !is_server_speaks_first(p),
                "port {} should NOT be server-first",
                p
            );
        }
    }

    /// Build a TunnelMux whose send channel is exposed to the test rather
    /// than wired to a real DomainFronter. Lets tests assert what messages
    /// the client would emit without needing network or apps_script.
    fn mux_for_test() -> (Arc<TunnelMux>, mpsc::Receiver<MuxMsg>) {
        mux_for_test_with(2)
    }

    /// Build a TunnelMux for tests with a specific deployment count. The
    /// per-deployment legacy state's aggregate gate (`all_servers_legacy`)
    /// requires `legacy_deployments.len() == num_scripts`, so tests that
    /// exercise that gate need to control how many "deployments" exist.
    fn mux_for_test_with(num_scripts: usize) -> (Arc<TunnelMux>, mpsc::Receiver<MuxMsg>) {
        let (tx, rx) = mpsc::channel(MUX_CHANNEL_DEPTH);
        let mux = Arc::new(TunnelMux {
            tx,
            connect_data_unsupported: Arc::new(AtomicBool::new(false)),
            legacy_deployments: Mutex::new(HashMap::new()),
            all_legacy: Arc::new(AtomicBool::new(false)),
            num_scripts,
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
            unreachable_cache: Mutex::new(HashMap::new()),
            // Tests that exercise the reply-timeout path expect a
            // generous fixed value here; production derives this from
            // `fronter.batch_timeout()` (see `TunnelMux::start`).
            reply_timeout: Duration::from_secs(35),
            elevated_sessions: AtomicU64::new(0),
            max_elevated: MAX_ELEVATED_PER_DEPLOYMENT * num_scripts as u64,
        });
        (mux, rx)
    }

    /// `TunnelMux::reply_timeout` must co-vary with the configured
    /// `request_timeout_secs` plus `REPLY_TIMEOUT_SLACK`. Without this
    /// runtime derivation, operators who raise `request_timeout_secs`
    /// see sessions abandon `reply_rx` just before `fire_batch`'s
    /// HTTP round-trip would have completed — silently orphaning
    /// in-flight responses. The test muxes hardcode a value for
    /// convenience, so a regression in `TunnelMux::start`'s formula
    /// could ship unnoticed unless we exercise the real construction
    /// path.
    #[tokio::test]
    async fn mux_reply_timeout_tracks_batch_timeout_plus_slack() {
        use crate::config::Config;

        // Pick a non-default `request_timeout_secs` so the assertion
        // would fail under any hardcoded value (35 s in tests, 75 s in
        // the previous patch).
        let cfg: Config = serde_json::from_str(
            r#"{
                "mode": "apps_script",
                "google_ip": "127.0.0.1",
                "front_domain": "www.google.com",
                "script_id": "TEST",
                "auth_key": "test_auth_key",
                "listen_host": "127.0.0.1",
                "listen_port": 8085,
                "log_level": "info",
                "verify_ssl": true,
                "request_timeout_secs": 60
            }"#,
        )
        .unwrap();
        let fronter = Arc::new(DomainFronter::new(&cfg).expect("test fronter must construct"));
        let mux = TunnelMux::start(fronter, 0, 0);

        assert_eq!(
            mux.reply_timeout(),
            Duration::from_secs(60) + REPLY_TIMEOUT_SLACK,
            "reply_timeout must equal batch_timeout + REPLY_TIMEOUT_SLACK"
        );
    }

    /// Regression for the mux-loop semaphore-stall. The first cut of
    /// the unbounded-channel patch awaited the per-deployment permit
    /// inline in `fire_batch` BEFORE the `tokio::spawn`, so when all
    /// `CONCURRENCY_PER_DEPLOYMENT` permits were occupied, `mux_loop`
    /// stopped consuming from its `rx` while `send_sync` kept pushing
    /// into the unbounded channel. Memory grew, and the per-op
    /// `reply_timeout` could fire before the op even reached a permit.
    ///
    /// The fix moves the await inside the spawned task — `fire_batch`
    /// returns to mux_loop immediately regardless of semaphore state.
    /// This test pre-saturates the per-deployment semaphore and times
    /// the `fire_batch().await` call; with the fix it returns within
    /// a few milliseconds, without it would hang.
    #[tokio::test(start_paused = true)]
    async fn fire_batch_does_not_block_caller_on_saturated_semaphore() {
        use crate::config::Config;

        let cfg: Config = serde_json::from_str(
            r#"{
                "mode": "apps_script",
                "google_ip": "127.0.0.1",
                "front_domain": "www.google.com",
                "script_id": "X",
                "auth_key": "secret-test-secret-test"
            }"#,
        )
        .unwrap();
        let fronter = Arc::new(DomainFronter::new(&cfg).expect("test fronter must construct"));

        // Build `sems` with one entry for the only deployment, capacity 1.
        let sem = Arc::new(Semaphore::new(1));
        let sems: Arc<HashMap<String, DeploymentSemaphores>> = Arc::new(
            std::iter::once((
                "X".to_string(),
                DeploymentSemaphores {
                    total: sem.clone(),
                    idle: Arc::new(Semaphore::new(1)),
                },
            ))
            .collect(),
        );

        // Saturate by holding the sole permit forever.
        let hog_task = tokio::spawn({
            let sem = sem.clone();
            async move {
                let _p = sem.acquire_owned().await.unwrap();
                std::future::pending::<()>().await;
            }
        });
        // Yield so the hog task actually acquires the permit before
        // we measure.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(sem.available_permits(), 0, "hog must hold the permit");

        let t0 = std::time::Instant::now();
        fire_batch(&sems, &fronter, Vec::new(), Vec::new()).await;
        let elapsed = t0.elapsed();

        hog_task.abort();

        // With the fix, `fire_batch` returns immediately because the
        // permit await lives inside `tokio::spawn`. Allow 250ms of
        // slack for scheduler jitter; the pre-fix code would block
        // indefinitely (test framework would time out).
        assert!(
            elapsed < Duration::from_millis(250),
            "fire_batch blocked for {:?} with semaphore saturated — \
             expected immediate return because the permit await must \
             live inside the spawned batch task, not on the caller path",
            elapsed,
        );
    }

    /// The buffered ClientHello from the pre-read window must reach the
    /// tunnel-node as the first `Data` op on the fallback path. If this
    /// regresses, every TLS handshake stalls until the 30 s read-timeout
    /// fires — catastrophic and silent without a test.
    #[tokio::test]
    async fn tunnel_loop_replays_pending_client_data_before_reading_socket() {
        use tokio::net::TcpListener;

        // Set up a loopback pair so tunnel_loop has a real TcpStream to
        // work with. We never write to its peer, so tunnel_loop's "read
        // from client" branch would block indefinitely — meaning any
        // `Data` msg it emits must have come from pending_client_data.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let _client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();
        let pending = Some(Bytes::from_static(b"CLIENTHELLO"));

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-under-test", &mux, pending).await
            }
        });

        // The first message tunnel_loop emits must be Data carrying the
        // replayed bytes — NOT whatever it would have read from the socket.
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("tunnel_loop did not send a message within 2s")
            .expect("mux channel closed unexpectedly");

        match msg {
            MuxMsg::Data {
                sid, data, reply, ..
            } => {
                assert_eq!(sid, "sid-under-test");
                assert_eq!(&data[..], b"CLIENTHELLO");
                // Reply with eof so tunnel_loop unwinds cleanly.
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-under-test".into()),
                        d: None,
                        pkts: None,
                        eof: Some(true),
                        e: None,
                        code: None,
                        seq: Some(0),
                    },
                    "test-script".to_string(),
                )));
            }
            other => panic!(
                "first mux message was not Data (expected replay); got {:?}",
                match other {
                    MuxMsg::Connect { .. } => "Connect",
                    MuxMsg::ConnectData { .. } => "ConnectData",
                    MuxMsg::Data { .. } => unreachable!(),
                    MuxMsg::UdpOpen { .. } => "UdpOpen",
                    MuxMsg::UdpData { .. } => "UdpData",
                    MuxMsg::Close { .. } => "Close",
                }
            ),
        }

        // With pipelining, a later op is
        // launched after a 1 s stagger sleep, so we need to wait long
        // enough for it to arrive. Reply to any remaining messages so the
        // loop can exit cleanly.
        let mut seq = 1u64;
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await
        {
            if let MuxMsg::Data { reply, .. } = msg {
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-under-test".into()),
                        d: None,
                        pkts: None,
                        eof: Some(true),
                        e: None,
                        code: None,
                        seq: Some(seq),
                    },
                    "test-script".to_string(),
                )));
                seq += 1;
            }
        }

        let _ = tokio::time::timeout(Duration::from_secs(4), loop_handle)
            .await
            .expect("tunnel_loop did not exit after eof");
    }

    /// Regression for the mixed-mode stall: A is legacy, B is long-poll
    /// capable, the session's last reply came from A. A naive per-
    /// deployment skip (gated on the *previous* reply's `script_id`)
    /// would short-circuit every empty poll on this session — so B
    /// never gets a chance to long-poll for us, and remote→client data
    /// stalls until either the local client sends bytes or A's TTL
    /// expires. The fix gates skip-when-idle on the aggregate
    /// `all_servers_legacy()` instead, so the loop keeps emitting empty
    /// polls whenever at least one peer can still hold the request open.
    /// Replies are paced via `start_paused` time auto-advance — without
    /// it the test would take ~2 s of real wall-clock time per session.
    #[tokio::test(start_paused = true)]
    async fn tunnel_loop_keeps_polling_when_only_some_deployments_legacy() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let _client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        // 2 deployments, only A marked legacy → all_servers_legacy = false.
        let (mux, mut rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");
        assert!(!mux.all_servers_legacy());

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-mixed", &mux, None).await
            }
        });

        // Reply to 6 empty polls, all from A. With the regression
        // (per-deployment skip on `last_script_id == A`), the loop would
        // stop emitting at iteration 4 — `consecutive_empty > 3` plus
        // `last_was_legacy` would short-circuit the send. With the fix,
        // the aggregate gate stays false and the loop keeps polling.
        // The 60 s timeout below is paused-time, so it only "elapses"
        // if rx.recv() truly never resolves (i.e. the loop has stalled).
        let mut received = 0u32;
        while received < 6 {
            let msg = tokio::time::timeout(Duration::from_secs(60), rx.recv())
                .await
                .unwrap_or_else(|_| panic!(
                    "loop stopped emitting at iteration {} — regression: per-deployment skip-when-idle stalled session even though long-poll-capable peer was available",
                    received
                ))
                .expect("mux channel closed unexpectedly");
            match msg {
                MuxMsg::Data {
                    sid,
                    data,
                    seq,
                    reply,
                    ..
                } => {
                    assert_eq!(sid, "sid-mixed");
                    assert!(
                        data.is_empty(),
                        "expected empty poll, got {} bytes",
                        data.len()
                    );
                    let last = received == 5;
                    let _ = reply.send(Ok((
                        TunnelResponse {
                            sid: Some("sid-mixed".into()),
                            d: None,
                            pkts: None,
                            eof: if last { Some(true) } else { None },
                            e: None,
                            code: None,
                            seq,
                        },
                        "script-A".to_string(),
                    )));
                    received += 1;
                }
                _ => panic!(
                    "iteration {}: expected Data poll, got a different MuxMsg variant",
                    received
                ),
            }
        }

        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle)
            .await
            .expect("tunnel_loop did not exit after eof");
    }

    /// Once `mark_connect_data_unsupported` is called, future sessions
    /// must see the flag — no per-session repeat of the detect-and-fallback
    /// cost. If this regresses, every new flow pays an extra round trip
    /// against a tunnel-node that will never learn the new op.
    #[test]
    fn unsupported_cache_is_sticky() {
        let (mux, _rx) = mux_for_test();
        assert!(!mux.connect_data_unsupported());
        mux.mark_connect_data_unsupported();
        assert!(mux.connect_data_unsupported());
        mux.mark_connect_data_unsupported(); // idempotent
        assert!(mux.connect_data_unsupported());
    }

    /// Marking deployment A as legacy must NOT make B look legacy. This
    /// is the central guarantee of the per-deployment design: with the
    /// old global AtomicBool, one slow / legacy deployment dragged every
    /// session onto the 30 s legacy cadence even when the other 7 were
    /// long-polling fine.
    #[test]
    fn legacy_state_is_per_deployment() {
        let (mux, _rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");

        let deps = mux.legacy_deployments.lock().unwrap();
        assert!(deps.contains_key("script-A"));
        assert!(
            !deps.contains_key("script-B"),
            "marking A must not insert an entry for B"
        );
    }

    /// `all_servers_legacy` (the per-session 30 s read-timeout gate) flips
    /// to true *only* when every known deployment has been marked. With
    /// 2 deployments, marking one keeps the gate false; marking both
    /// flips it true.
    #[test]
    fn all_servers_legacy_requires_every_deployment() {
        let (mux, _rx) = mux_for_test_with(2);
        assert!(!mux.all_servers_legacy());

        mux.mark_server_no_longpoll("script-A");
        assert!(
            !mux.all_servers_legacy(),
            "1 of 2 marked: aggregate must stay false"
        );

        mux.mark_server_no_longpoll("script-B");
        assert!(
            mux.all_servers_legacy(),
            "all deployments marked: aggregate flips true"
        );

        // Idempotent re-mark of an already-legacy deployment doesn't
        // disturb the aggregate.
        mux.mark_server_no_longpoll("script-A");
        assert!(mux.all_servers_legacy());
    }

    /// After `LEGACY_RECOVER_AFTER`, an entry is treated as expired and
    /// the deployment rejoins the long-poll fast path. The next mark
    /// (against any deployment) sweeps stale entries before recomputing
    /// the aggregate gate, so a recovered peer doesn't keep counting
    /// toward `all_legacy`. Backdating the mark time avoids a real 60 s
    /// sleep in the test — same effect as the wall-clock moving forward.
    #[test]
    fn legacy_state_recovers_after_ttl() {
        let (mux, _rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");

        // Backdate A past LEGACY_RECOVER_AFTER, then mark B. B's mark
        // must trigger a sweep that drops the stale A entry.
        {
            let mut deps = mux.legacy_deployments.lock().unwrap();
            let stale = Instant::now()
                .checked_sub(LEGACY_RECOVER_AFTER + Duration::from_secs(1))
                .expect("test environment should have a non-trivial monotonic clock");
            deps.insert("script-A".to_string(), stale);
        }
        mux.mark_server_no_longpoll("script-B");

        let deps = mux.legacy_deployments.lock().unwrap();
        assert!(
            !deps.contains_key("script-A"),
            "expired entry must be swept on the next mark — otherwise stale legacy state never clears"
        );
        assert!(deps.contains_key("script-B"));
    }

    /// If every deployment is legacy and then time passes past
    /// `LEGACY_RECOVER_AFTER` *without any new mark*, the aggregate gate
    /// must self-correct on the next `all_servers_legacy()` call.
    /// Without the in-place sweep on read, stale legacy marks would keep
    /// the 30 s read-timeout active forever after every deployment
    /// recovers.
    #[test]
    fn all_servers_legacy_self_corrects_when_entries_expire() {
        let (mux, _rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");
        mux.mark_server_no_longpoll("script-B");
        assert!(mux.all_servers_legacy());

        // Backdate every entry past TTL.
        {
            let mut deps = mux.legacy_deployments.lock().unwrap();
            let stale = Instant::now()
                .checked_sub(LEGACY_RECOVER_AFTER + Duration::from_secs(1))
                .expect("monotonic clock should be far enough along");
            for (_, t) in deps.iter_mut() {
                *t = stale;
            }
        }

        assert!(
            !mux.all_servers_legacy(),
            "aggregate must self-correct when all entries expire — otherwise the 30 s read timeout sticks forever"
        );
    }

    #[test]
    fn should_fire_first_op_never_fires() {
        // Empty accumulator: even a single op larger than the payload cap
        // must not fire — there's nothing to fire yet, and the op gets
        // added (it will simply be the only op in the next batch).
        assert!(!should_fire(0, 0, 0));
        assert!(!should_fire(0, 0, MAX_BATCH_PAYLOAD_BYTES + 1_000_000));
    }

    #[test]
    fn should_fire_at_max_ops_threshold() {
        // 49 already-queued ops + 50th: still fits (boundary is `>=`).
        assert!(!should_fire(MAX_BATCH_OPS - 1, 0, 100));
        // 50 already-queued ops + 51st: must fire.
        assert!(should_fire(MAX_BATCH_OPS, 0, 100));
        // Well past the cap: must fire.
        assert!(should_fire(MAX_BATCH_OPS + 5, 0, 100));
    }

    #[test]
    fn is_handshake_priority_classifies_connect_and_tls_record_type() {
        let (tx, _rx) = oneshot::channel();
        // Connect / ConnectData are unconditionally priority — the
        // CONNECT response is a prerequisite for any later data, and
        // ConnectData typically bundles the client's first ClientHello.
        assert!(is_handshake_priority(&MuxMsg::Connect {
            host: "h".into(),
            port: 443,
            reply: tx,
        }));
        let (tx, _rx) = oneshot::channel();
        assert!(is_handshake_priority(&MuxMsg::ConnectData {
            host: "h".into(),
            port: 443,
            data: Bytes::from_static(b""),
            reply: tx,
        }));
        // Data carrying TLS record-layer Handshake (0x16) is priority.
        let (tx, _rx) = oneshot::channel();
        assert!(is_handshake_priority(&MuxMsg::Data {
            sid: "s".into(),
            data: Bytes::from_static(&[0x16, 0x03, 0x03]),
            seq: None,
            wseq: None,
            reply: tx,
        }));
        // ApplicationData (0x17) / Alert (0x15) / ChangeCipherSpec
        // (0x14) are post-handshake bulk traffic — NOT priority.
        for first in [0x17u8, 0x15, 0x14, 0x00] {
            let (tx, _rx) = oneshot::channel();
            assert!(
                !is_handshake_priority(&MuxMsg::Data {
                    sid: "s".into(),
                    data: Bytes::copy_from_slice(&[first, 0x03, 0x03]),
                    seq: None,
                    wseq: None,
                    reply: tx,
                }),
                "data starting with 0x{first:02x} should NOT be priority",
            );
        }
        // Empty data op (idle poll) is not priority — `[0x16, 0x03, ..]`
        // pattern match requires at least two bytes.
        let (tx, _rx) = oneshot::channel();
        assert!(!is_handshake_priority(&MuxMsg::Data {
            sid: "s".into(),
            data: Bytes::new(),
            seq: None,
            wseq: None,
            reply: tx,
        }));
        // Single 0x16 byte without a TLS version byte after it must NOT
        // be priority — the two-byte check is what makes the heuristic
        // false-positive-resistant on mid-stream ApplicationData chunks
        // that happen to start with 0x16.
        let (tx, _rx) = oneshot::channel();
        assert!(!is_handshake_priority(&MuxMsg::Data {
            sid: "s".into(),
            data: Bytes::from_static(&[0x16]),
            seq: None,
            wseq: None,
            reply: tx,
        }));
        // 0x16 followed by a non-TLS-major version byte: still NOT
        // priority. TLS records are always major version 3.
        for v in [0x00u8, 0x01, 0x02, 0x04, 0x16, 0xff] {
            let (tx, _rx) = oneshot::channel();
            assert!(
                !is_handshake_priority(&MuxMsg::Data {
                    sid: "s".into(),
                    data: Bytes::copy_from_slice(&[0x16, v, 0x00]),
                    seq: None,
                    wseq: None,
                    reply: tx,
                }),
                "[0x16, 0x{v:02x}] should NOT be priority — only major version 3 is TLS",
            );
        }
        // UDP and Close ops never carry TCP handshake bytes.
        let (tx, _rx) = oneshot::channel();
        assert!(!is_handshake_priority(&MuxMsg::UdpOpen {
            host: "h".into(),
            port: 53,
            data: Bytes::from_static(&[0x16]),
            reply: tx,
        }));
        let (tx, _rx) = oneshot::channel();
        assert!(!is_handshake_priority(&MuxMsg::UdpData {
            sid: "s".into(),
            data: Bytes::from_static(&[0x16]),
            reply: tx,
        }));
        assert!(!is_handshake_priority(&MuxMsg::Close { sid: "s".into() }));
    }

    #[test]
    fn upgrade_handshake_deadline_is_sticky_and_shrink_only() {
        let batch_start = tokio::time::Instant::now();
        let handshake = Duration::from_millis(50);
        let non_priority_deadline = batch_start + Duration::from_millis(1000);
        let already_priority_deadline = batch_start + handshake;
        let pre_clamped_deadline = batch_start + Duration::from_millis(30);

        // Case 1: batch was not priority and a non-priority op arrives —
        // no change.
        assert_eq!(
            upgrade_handshake_deadline(false, false, non_priority_deadline, batch_start, handshake),
            (false, non_priority_deadline),
        );
        // Case 2: batch was not priority and a priority op arrives —
        // flag flips, deadline clamps to batch_start + handshake.
        assert_eq!(
            upgrade_handshake_deadline(false, true, non_priority_deadline, batch_start, handshake),
            (true, batch_start + handshake),
        );
        // Case 3: batch already priority and another priority op arrives
        // — flag stays true, deadline does not move (already at the
        // floor, .min() doesn't extend it).
        assert_eq!(
            upgrade_handshake_deadline(
                true,
                true,
                already_priority_deadline,
                batch_start,
                handshake
            ),
            (true, already_priority_deadline),
        );
        // Case 4: batch already priority and a non-priority op arrives —
        // critical sticky case. Flag must stay true and deadline must
        // not be pushed back out to coalesce_max.
        assert_eq!(
            upgrade_handshake_deadline(
                true,
                false,
                already_priority_deadline,
                batch_start,
                handshake
            ),
            (true, already_priority_deadline),
        );
        // Case 5: operator pre-clamped the deadline tighter than the
        // handshake floor (e.g., via `coalesce_max_ms = 30`); shrink-only
        // means we keep their tighter value, not widen back to 50.
        assert_eq!(
            upgrade_handshake_deadline(false, true, pre_clamped_deadline, batch_start, handshake),
            (true, pre_clamped_deadline),
        );
    }

    #[test]
    fn should_fire_when_payload_would_exceed_cap() {
        // Exactly at the cap is fine — strict `>`.
        assert!(!should_fire(10, MAX_BATCH_PAYLOAD_BYTES - 100, 100,));
        // One byte over: fire.
        assert!(should_fire(10, MAX_BATCH_PAYLOAD_BYTES - 100, 101,));
        // Sum overflow well past the cap: fire.
        assert!(should_fire(10, MAX_BATCH_PAYLOAD_BYTES, 1,));
    }

    #[test]
    fn idle_poll_batch_detection_only_matches_empty_polls() {
        let poll = |op| PendingOp {
            op,
            sid: Some("sid".into()),
            host: None,
            port: None,
            data: None,
            encode_empty: false,
            seq: Some(1),
            wseq: None,
        };
        assert!(is_idle_poll_batch(&[poll("data")]));
        assert!(is_idle_poll_batch(&[poll("data"), poll("udp_data")]));

        let upload = PendingOp {
            data: Some(Bytes::from_static(b"x")),
            ..poll("data")
        };
        assert!(!is_idle_poll_batch(&[upload]));

        let connect = PendingOp {
            op: "connect",
            sid: None,
            host: Some("example.com".into()),
            port: Some(443),
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        assert!(!is_idle_poll_batch(&[connect]));
        assert!(!is_idle_poll_batch(&[]));
    }

    #[test]
    fn idle_refill_delay_ramps_after_repeated_empty_replies() {
        assert_eq!(refill_delay(INFLIGHT_OPTIMIST, 99), Duration::from_secs(1));
        assert_eq!(refill_delay(INFLIGHT_IDLE, 0), Duration::ZERO);
        assert_eq!(refill_delay(INFLIGHT_IDLE, 3), Duration::ZERO);
        assert_eq!(refill_delay(INFLIGHT_IDLE, 4), Duration::from_secs(1));
        assert_eq!(refill_delay(INFLIGHT_IDLE, 8), Duration::from_secs(2));
        assert_eq!(refill_delay(INFLIGHT_IDLE, 64), Duration::from_secs(7));
    }

    /// Sanity check on `is_idle_depth`: today `INFLIGHT_IDLE == 1`, but the
    /// predicate is centralized precisely so the test catches a drift if
    /// the constant ever moves.
    #[test]
    fn is_idle_depth_matches_only_inflight_idle() {
        assert!(is_idle_depth(INFLIGHT_IDLE));
        assert!(!is_idle_depth(INFLIGHT_OPTIMIST));
        assert!(!is_idle_depth(INFLIGHT_ACTIVE));
    }

    /// Active-batch path goes through the fair semaphore queue.
    #[tokio::test]
    async fn acquire_total_permit_active_waits_on_fair_queue() {
        let sem = Arc::new(Semaphore::new(1));
        let permit = acquire_total_permit(sem.clone(), false)
            .await
            .expect("permit");
        assert_eq!(sem.available_permits(), 0);
        drop(permit);
        assert_eq!(sem.available_permits(), 1);
    }

    /// Idle-batch path spin-polls and only succeeds once a permit is
    /// released — never queues. Without the spin loop, idle batches would
    /// occupy fair-queue slots that the next active arrival is entitled
    /// to.
    #[tokio::test]
    async fn acquire_total_permit_idle_spins_until_permit_available() {
        let sem = Arc::new(Semaphore::new(1));
        let hog = sem.clone().acquire_owned().await.expect("hog permit");

        let task_sem = sem.clone();
        let task = tokio::spawn(async move { acquire_total_permit(task_sem, true).await });

        // Give the task time to enter its first spin iteration. Two retry
        // intervals is plenty.
        tokio::time::sleep(Duration::from_millis(IDLE_BATCH_PERMIT_RETRY_MS * 2)).await;
        assert!(
            !task.is_finished(),
            "idle batch must not acquire while total pool is saturated"
        );

        drop(hog);

        // Bound: at most one full retry interval (plus scheduling slack)
        // between release and acquisition.
        let permit =
            tokio::time::timeout(Duration::from_millis(IDLE_BATCH_PERMIT_RETRY_MS * 4), task)
                .await
                .expect("idle batch should acquire within one retry tick of release")
                .expect("task panicked")
                .expect("acquire result");
        drop(permit);
        assert_eq!(sem.available_permits(), 1);
    }

    /// Concurrency invariant: an active batch arriving *after* an idle
    /// batch has started spinning still wins the next released permit,
    /// because the idle batch is in a sleep loop and not on the fair
    /// queue. This is the whole point of the two-tier design.
    #[tokio::test]
    async fn idle_batch_does_not_block_queued_active_batch() {
        let sem = Arc::new(Semaphore::new(1));
        let hog = sem.clone().acquire_owned().await.expect("hog permit");

        let idle_sem = sem.clone();
        let idle = tokio::spawn(async move { acquire_total_permit(idle_sem, true).await });

        // Let the idle task fall into its sleep loop before the active
        // arrival, so we know the active task is queued *after* it.
        tokio::time::sleep(Duration::from_millis(IDLE_BATCH_PERMIT_RETRY_MS * 2)).await;

        let active_sem = sem.clone();
        let active = tokio::spawn(async move { acquire_total_permit(active_sem, false).await });

        // Brief yield so the active task reaches its `acquire_owned().await`.
        tokio::time::sleep(Duration::from_millis(5)).await;

        drop(hog);

        let active_permit = tokio::time::timeout(Duration::from_millis(100), active)
            .await
            .expect("active should acquire promptly after release")
            .expect("task panicked")
            .expect("acquire result");
        assert!(
            !idle.is_finished(),
            "idle batch must not jump ahead of a queued active batch"
        );

        drop(active_permit);

        let idle_permit =
            tokio::time::timeout(Duration::from_millis(IDLE_BATCH_PERMIT_RETRY_MS * 4), idle)
                .await
                .expect("idle should acquire after active releases")
                .expect("task panicked")
                .expect("acquire result");
        drop(idle_permit);
    }

    /// Closed semaphore surfaces as an `Err` through both paths instead of
    /// hanging forever.
    #[tokio::test]
    async fn acquire_total_permit_surfaces_closed_semaphore() {
        let sem = Arc::new(Semaphore::new(0));
        sem.close();
        assert!(acquire_total_permit(sem.clone(), false).await.is_err());
        assert!(acquire_total_permit(sem, true).await.is_err());
    }

    /// Wire-shape regression for the new plain-CONNECT batching path. The
    /// pre-batching code spawned a free-floating `tunnel_request("connect",
    /// host, port, None, None)` — now plain Connect rides `BatchAccum` and
    /// must encode as a `BatchOp { op: "connect", host, port, d: None }`.
    /// If `encode_pending`'s `(data, encode_empty)` match arm ever decides
    /// to emit `Some("")` for connect (e.g. by setting `encode_empty: true`
    /// at the call site), tunnel-node sees the wrong shape — covered here
    /// so the regression can't ship silently.
    #[test]
    fn encode_pending_connect_emits_no_data_field() {
        let op = PendingOp {
            op: "connect",
            sid: None,
            host: Some("api.example.com".into()),
            port: Some(443),
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        let b = encode_pending(op);
        assert_eq!(b.op, "connect");
        assert_eq!(b.sid, None);
        assert_eq!(b.host, Some("api.example.com".into()));
        assert_eq!(b.port, Some(443));
        assert_eq!(
            b.d, None,
            "connect must serialize with no `d` field; an empty-string `d` \
             would be interpreted by tunnel-node as a zero-byte upload"
        );
        assert_eq!(b.seq, None);
        assert_eq!(b.wseq, None);
    }

    /// Happy-path regression for `connect_plain` against the batched
    /// reply shape. Pre-batching the reply channel was
    /// `oneshot::Sender<Result<TunnelResponse, String>>`; it is now the
    /// `BatchedReply` tuple `(TunnelResponse, script_id)`. Without this
    /// test the only coverage of `connect_plain`'s unwrap is the negative-
    /// cache path which only exercises `Ok(Err(_))`. Server-speaks-first
    /// ports (FTP/SMTP/IMAP) and the preread-timeout fallback both reach
    /// `connect_plain` rather than `connect_data`, so a typo in the tuple
    /// destructure here would break those flows silently.
    #[tokio::test]
    async fn connect_plain_unwraps_batched_reply_to_sid() {
        let (mux, mut rx) = mux_for_test();
        let mux_for_task = mux.clone();
        let task =
            tokio::spawn(async move { connect_plain("api.example.com", 443, &mux_for_task).await });

        let msg = rx
            .recv()
            .await
            .expect("connect_plain must enqueue a MuxMsg::Connect");
        let (host, port, reply) = match msg {
            MuxMsg::Connect { host, port, reply } => (host, port, reply),
            other => panic!("expected Connect, got {:?}", std::mem::discriminant(&other)),
        };
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);

        // Deliver the batched (TunnelResponse, script_id) reply shape.
        let resp = TunnelResponse {
            sid: Some("session-abc".into()),
            d: None,
            pkts: None,
            eof: None,
            e: None,
            code: None,
            seq: None,
        };
        let _ = reply.send(Ok((resp, "deployment-X".into())));

        let sid = task
            .await
            .expect("connect_plain task")
            .expect("connect_plain should succeed");
        assert_eq!(sid, "session-abc");
    }

    /// `should_suppress_empty_refill` shapes the predicate for two
    /// adjacent refill arms; the threshold lives in
    /// `IDLE_REFILL_DELAY_START_EMPTY` rather than being open-coded as
    /// `> 3`. Verify each gate triggers/clears independently so a future
    /// refactor that drops one input doesn't quietly broaden the
    /// suppression window.
    #[test]
    fn should_suppress_empty_refill_requires_every_gate() {
        // All gates aligned for suppression.
        assert!(should_suppress_empty_refill(
            /* has_buffered_upload */ false,
            /* client_closed */ false,
            INFLIGHT_IDLE,
            IDLE_REFILL_DELAY_START_EMPTY,
            /* all_servers_legacy */ true,
        ));

        // Each gate breaks suppression on its own.
        assert!(!should_suppress_empty_refill(
            true,
            false,
            INFLIGHT_IDLE,
            IDLE_REFILL_DELAY_START_EMPTY,
            true
        ));
        assert!(!should_suppress_empty_refill(
            false,
            true,
            INFLIGHT_IDLE,
            IDLE_REFILL_DELAY_START_EMPTY,
            true
        ));
        assert!(!should_suppress_empty_refill(
            false,
            false,
            INFLIGHT_OPTIMIST,
            IDLE_REFILL_DELAY_START_EMPTY,
            true
        ));
        assert!(!should_suppress_empty_refill(
            false,
            false,
            INFLIGHT_IDLE,
            IDLE_REFILL_DELAY_START_EMPTY - 1,
            true
        ));
        assert!(!should_suppress_empty_refill(
            false,
            false,
            INFLIGHT_IDLE,
            IDLE_REFILL_DELAY_START_EMPTY,
            false
        ));
    }

    /// Reply indices must point at the slot the op occupies *within its
    /// batch*. Pre-flush ops are 0..N-1 in batch A; post-flush ops
    /// restart at 0 in batch B. If this regresses, `fire_batch`'s
    /// `batch_resp.r.get(idx)` lookup hands the wrong response (or
    /// `None`) to the wrong session — silent data corruption that
    /// the encode-layer tests can't catch.
    #[tokio::test]
    async fn batch_accum_reindexes_after_flush() {
        // Stand-alone helper that mirrors `push_or_fire`'s push step
        // without the fire_batch call — lets us simulate a flush with
        // `mem::take` and assert the post-flush indexing without
        // mocking the whole tunnel_request stack.
        fn push_no_fire(
            accum: &mut BatchAccum,
            op: PendingOp,
            op_bytes: usize,
            reply: BatchedReply,
        ) {
            let idx = accum.pending_ops.len();
            accum.pending_ops.push(op);
            accum.data_replies.push((idx, reply));
            accum.payload_bytes += op_bytes;
        }

        let mk_op = |sid: &str| PendingOp {
            op: "data",
            sid: Some(sid.into()),
            host: None,
            port: None,
            data: Some(Bytes::from_static(b"x")),
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        let mk_reply = || oneshot::channel::<Result<(TunnelResponse, String), String>>().0;

        let mut accum = BatchAccum::new();

        // Batch A: 3 ops at indices 0, 1, 2.
        push_no_fire(&mut accum, mk_op("a0"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("a1"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("a2"), 4, mk_reply());
        assert_eq!(accum.pending_ops.len(), 3);
        assert_eq!(
            accum
                .data_replies
                .iter()
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
            vec![0, 1, 2],
        );
        assert_eq!(accum.payload_bytes, 12);

        // Simulate the flush: take the queued state and reset the byte
        // counter (matches what `push_or_fire` does after `fire_batch`).
        let _flushed_ops = std::mem::take(&mut accum.pending_ops);
        let _flushed_replies = std::mem::take(&mut accum.data_replies);
        accum.payload_bytes = 0;

        // Batch B: 2 ops, indices restart at 0.
        push_no_fire(&mut accum, mk_op("b0"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("b1"), 4, mk_reply());
        assert_eq!(accum.pending_ops.len(), 2);
        assert_eq!(
            accum
                .data_replies
                .iter()
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
            vec![0, 1],
            "post-flush indices must restart at 0 — otherwise fire_batch's \
             batch_resp.r.get(idx) returns None and every session in the \
             second batch sees a missing-response error"
        );
        assert_eq!(accum.payload_bytes, 8);
    }

    #[test]
    fn encode_pending_data_op_with_payload_emits_base64() {
        let op = PendingOp {
            op: "data",
            sid: Some("sid-1".into()),
            host: None,
            port: None,
            data: Some(Bytes::from_static(b"hello")),
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        let b = encode_pending(op);
        assert_eq!(b.op, "data");
        assert_eq!(b.sid.as_deref(), Some("sid-1"));
        assert_eq!(b.d.as_deref(), Some(B64.encode(b"hello").as_str()));
    }

    #[test]
    fn encode_pending_omits_d_for_empty_polls_and_close() {
        // Empty-poll Data: mux_loop converts empty Bytes to data: None.
        let empty_poll = PendingOp {
            op: "data",
            sid: Some("sid-2".into()),
            host: None,
            port: None,
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        assert!(encode_pending(empty_poll).d.is_none());

        // UDP poll with no payload: same shape.
        let udp_poll = PendingOp {
            op: "udp_data",
            sid: Some("sid-3".into()),
            host: None,
            port: None,
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        assert!(encode_pending(udp_poll).d.is_none());

        // Close has no data and no reply — `d` must stay omitted.
        let close = PendingOp {
            op: "close",
            sid: Some("sid-4".into()),
            host: None,
            port: None,
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        assert!(encode_pending(close).d.is_none());
    }

    #[test]
    fn encode_pending_connect_data_emits_empty_string_when_data_is_empty() {
        // Defensive: ConnectData's wire contract is that `d` is always
        // present (its presence is the signal that the caller is opting
        // into the bundled-first-bytes flow). If an empty Bytes ever
        // reaches the encoder, we must serialize `d: ""` not omit it.
        let op = PendingOp {
            op: "connect_data",
            sid: None,
            host: Some("example.com".into()),
            port: Some(443),
            data: Some(Bytes::new()),
            encode_empty: true,
            seq: None,
            wseq: None,
        };
        let b = encode_pending(op);
        assert_eq!(b.op, "connect_data");
        assert_eq!(b.d.as_deref(), Some(""));
    }

    #[test]
    fn encode_pending_connect_data_with_payload_encodes_normally() {
        let op = PendingOp {
            op: "connect_data",
            sid: None,
            host: Some("example.com".into()),
            port: Some(443),
            data: Some(Bytes::from_static(b"\x16\x03\x01")), // ClientHello prefix
            encode_empty: true,
            seq: None,
            wseq: None,
        };
        let b = encode_pending(op);
        assert_eq!(b.d.as_deref(), Some(B64.encode(b"\x16\x03\x01").as_str()));
    }

    #[test]
    fn preread_counters_track_each_outcome() {
        let (mux, _rx) = mux_for_test();

        mux.record_preread_win(443, Duration::from_micros(3_500));
        mux.record_preread_win(443, Duration::from_micros(1_500));
        mux.record_preread_loss(443);
        mux.record_preread_skip_port(80);
        mux.record_preread_skip_unsupported(443);

        assert_eq!(mux.preread_win.load(Ordering::Relaxed), 2);
        assert_eq!(mux.preread_loss.load(Ordering::Relaxed), 1);
        assert_eq!(mux.preread_skip_port.load(Ordering::Relaxed), 1);
        assert_eq!(mux.preread_skip_unsupported.load(Ordering::Relaxed), 1);
        // Two wins summing to 5000 µs.
        assert_eq!(mux.preread_win_total_us.load(Ordering::Relaxed), 5_000);
        // Five record_* calls, so trigger counter is at 5.
        assert_eq!(mux.preread_total_events.load(Ordering::Relaxed), 5);
    }

    /// Client data written to the socket *during* the reply wait must be
    /// buffered and sent in a subsequent op — not blocked until the reply
    /// arrives and a fresh read-timeout elapses.
    #[tokio::test]
    async fn tunnel_loop_reads_client_during_reply_wait() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-overlap", &mux, None).await
            }
        });

        // With pipelining, the loop may send several ops before we
        // can write client data. Collect all initial ops, reply to each,
        // then write data and check a subsequent op carries it.
        let mut pending_replies: Vec<BatchedReply> = Vec::new();
        let mut seq: u64 = 0;

        // Drain initial ops (up to the active cap).
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await
        {
            if let MuxMsg::Data { reply, .. } = msg {
                pending_replies.push(reply);
            }
            if pending_replies.len() >= INFLIGHT_ACTIVE {
                break;
            }
        }

        // Write client data while replies are pending.
        client.write_all(b"UPLOAD_DATA").await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Reply to all pending ops (no eof, no data).
        for reply in pending_replies.drain(..) {
            let _ = reply.send(Ok((
                TunnelResponse {
                    sid: Some("sid-overlap".into()),
                    d: None,
                    pkts: None,
                    eof: None,
                    e: None,
                    code: None,
                    seq: Some(seq),
                },
                "test-script".to_string(),
            )));
            seq += 1;
        }

        // Now check that a subsequent op carries the buffered upload data.
        let mut found_upload = false;
        for _ in 0..4 {
            let msg = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Some(m)) => m,
                _ => break,
            };
            if let MuxMsg::Data { data, reply, .. } = msg {
                if &data[..] == b"UPLOAD_DATA" {
                    found_upload = true;
                }
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-overlap".into()),
                        d: None,
                        pkts: None,
                        eof: Some(found_upload),
                        e: None,
                        code: None,
                        seq: Some(seq),
                    },
                    "test-script".to_string(),
                )));
                seq += 1;
                if found_upload {
                    break;
                }
            }
        }
        assert!(found_upload, "upload data must appear in a subsequent op");

        // Drain any remaining in-flight ops (stagger sleep is 1 s,
        // so allow enough time for late-arriving ops).
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await
        {
            if let MuxMsg::Data { reply, .. } = msg {
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-overlap".into()),
                        d: None,
                        pkts: None,
                        eof: Some(true),
                        e: None,
                        code: None,
                        seq: Some(seq),
                    },
                    "test-script".to_string(),
                )));
                seq += 1;
            }
        }

        let _ = tokio::time::timeout(Duration::from_secs(4), loop_handle)
            .await
            .expect("tunnel_loop did not exit after eof");
    }

    /// When a data-bearing op times out, downstream order is broken:
    /// the missing `meta.seq` would otherwise block every later reply
    /// in `pending_writes` forever. The session must close terminally so
    /// the client (browser / app) gets a TCP RST and can retry — silent
    /// stall would leave a half-open connection that accepts uploads
    /// but never writes a byte back.
    ///
    /// Reproduce by sending the initial pipelined polls, replying to
    /// seq=1 out-of-order (which goes into `pending_writes`), starving
    /// seq=0 of a reply, and letting paused-time auto-advance past
    /// `mux.reply_timeout`. The loop must exit on its own.
    #[tokio::test(start_paused = true)]
    async fn tunnel_loop_exits_when_reply_seq_times_out() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let _client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();
        let reply_timeout = mux.reply_timeout();

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-timeout", &mux, None).await
            }
        });

        // Collect the first two MuxMsgs — the optimist-depth pipeline
        // emits seq=0 then seq=1 first, even if more refills follow.
        let mut first_reply: Option<BatchedReply> = None;
        let mut second_reply: Option<BatchedReply> = None;
        let mut second_seq: Option<u64> = None;
        for _ in 0..2 {
            let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("did not receive initial poll")
                .expect("mux channel closed");
            if let MuxMsg::Data { reply, seq, .. } = msg {
                if first_reply.is_none() {
                    first_reply = Some(reply);
                } else {
                    second_seq = seq;
                    second_reply = Some(reply);
                }
            }
        }
        let second_seq = second_seq.expect("second op should have a seq");
        let second_reply = second_reply.expect("must have observed second op");

        // Reply to seq=1 first — pending_writes would buffer it waiting
        // for seq=0. seq=0's reply never comes; the loop must time out.
        let _ = second_reply.send(Ok((
            TunnelResponse {
                sid: Some("sid-timeout".into()),
                d: None,
                pkts: None,
                eof: None,
                e: None,
                code: None,
                seq: Some(second_seq),
            },
            "test-script".to_string(),
        )));

        // Hold the first reply but never send — it will time out.
        let _starved = first_reply.expect("must have observed first op");

        // Auto-advance fires the reply_timeout. The loop should exit
        // on its own within slightly more than `reply_timeout`.
        let exit = tokio::time::timeout(reply_timeout + Duration::from_secs(2), loop_handle)
            .await
            .expect("tunnel_loop did not exit after reply timeout");
        // The task itself must not panic — `Ok(_)` on the JoinHandle.
        let _ = exit.expect("tunnel_loop task panicked");
    }

    /// Pipelining can deliver replies in any order — a later poll on
    /// one deployment can win the tunnel-node's `notify_one` wake-up and
    /// drain bytes while an earlier poll on another deployment is still
    /// held under `LONGPOLL_DEADLINE`. The client must buffer the out-of-
    /// order reply (in `pending_writes`) until the missing earlier seq
    /// lands, then flush. Without that, downstream bytes either show up
    /// in the wrong order on the client socket or get dropped.
    ///
    /// Reproduce by replying to seq=1 with data first, asserting nothing
    /// reaches the client socket yet, then replying to seq=0 empty and
    /// asserting the buffered seq=1 payload now arrives at the client.
    #[tokio::test]
    async fn tunnel_loop_buffers_out_of_order_reply_and_flushes_on_catch_up() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-hol", &mux, None).await
            }
        });

        // Optimist-depth pipeline emits seq=0 then seq=1 first.
        let mut first_reply: Option<BatchedReply> = None;
        let mut second_reply: Option<BatchedReply> = None;
        let (mut first_seq, mut second_seq) = (None, None);
        for _ in 0..2 {
            let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("did not receive initial poll")
                .expect("mux channel closed");
            if let MuxMsg::Data { reply, seq, .. } = msg {
                if first_reply.is_none() {
                    first_seq = seq;
                    first_reply = Some(reply);
                } else {
                    second_seq = seq;
                    second_reply = Some(reply);
                }
            }
        }
        let first_seq = first_seq.expect("first op has seq");
        let second_seq = second_seq.expect("second op has seq");
        assert!(
            first_seq < second_seq,
            "tunnel_loop must send sequential meta.seqs"
        );

        // Reply to seq=1 with a marker payload FIRST.
        let payload_b64 = B64.encode(b"HOL_DATA");
        let _ = second_reply.take().unwrap().send(Ok((
            TunnelResponse {
                sid: Some("sid-hol".into()),
                d: Some(payload_b64),
                pkts: None,
                eof: None,
                e: None,
                code: None,
                seq: Some(second_seq),
            },
            "test-script".to_string(),
        )));

        // The bytes MUST NOT show up on the client socket yet: seq=0
        // hasn't been replied to, so the strict-in-order writer holds
        // seq=1's payload in `pending_writes`. Probe with a short
        // read-timeout and assert it times out.
        let mut buf = [0u8; 8];
        let blocked =
            tokio::time::timeout(Duration::from_millis(200), client.read_exact(&mut buf)).await;
        assert!(
            blocked.is_err(),
            "client must NOT receive seq=1 bytes before seq=0 reply lands — \
             got {:?} instead of timeout",
            blocked,
        );

        // Now reply to seq=0 empty. The buffered seq=1 payload should
        // flush immediately on the same select arm.
        let _ = first_reply.take().unwrap().send(Ok((
            TunnelResponse {
                sid: Some("sid-hol".into()),
                d: None,
                pkts: None,
                eof: None,
                e: None,
                code: None,
                seq: Some(first_seq),
            },
            "test-script".to_string(),
        )));

        // The 8 bytes of HOL_DATA must arrive on the client socket
        // within a short slack window (no LONGPOLL_DEADLINE wait).
        let n = tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .expect("client must receive buffered seq=1 payload after seq=0 lands")
            .expect("client read");
        assert_eq!(n, 8);
        assert_eq!(&buf, b"HOL_DATA");

        // Tidy up — drain any further polls so the loop can shut down
        // when we drop the senders, otherwise the test hangs at end.
        drop(client);
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {}
        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
    }
}
