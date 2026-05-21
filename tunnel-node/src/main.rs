//! HTTP Tunnel Node for MasterHttpRelayVPN "full" mode.
//!
//! Bridges HTTP tunnel requests (from Apps Script) to real TCP connections.
//! Supports both single-op (`POST /tunnel`) and batch (`POST /tunnel/batch`)
//! modes. Batch mode processes all active sessions in one HTTP round trip,
//! dramatically reducing the number of Apps Script calls.
//!
//! Env vars:
//!   TUNNEL_AUTH_KEY — shared secret (required)
//!   PORT           — listen port (default 8080, Cloud Run sets this)

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::post, Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinSet;

mod udpgw;

/// Structured error code returned when the tunnel-node receives an op it
/// doesn't recognize. Clients use this (rather than string-matching `e`) to
/// detect a version mismatch and gracefully fall back.
const CODE_UNSUPPORTED_OP: &str = "UNSUPPORTED_OP";

/// Drain-phase deadline when the batch contained writes or new
/// connections. We expect upstream servers to respond fast (TLS
/// ServerHello, HTTP response) so this is a ceiling for slow targets;
/// `wait_for_any_drainable` returns much sooner — usually within
/// milliseconds — once any session in the batch fires its notify.
const ACTIVE_DRAIN_DEADLINE: Duration = Duration::from_millis(350);

/// Adaptive straggler settle: after the first session in an active batch
/// wakes the drain, keep checking in STEP increments whether new data is
/// still arriving. Stops when no new data arrived in the last STEP (the
/// burst is over) or MAX is reached. Packing more session responses into
/// one batch saves quota on high-latency relays (~1.5s Apps Script overhead).
const STRAGGLER_SETTLE_STEP: Duration = Duration::from_millis(10);
const STRAGGLER_SETTLE_MAX: Duration = Duration::from_millis(1000);

/// Drain-phase deadline when the batch is a pure poll (no writes, no new
/// connections — clients just asking "any push data?"). Holding the
/// response open delivers server-initiated bytes (push notifications,
/// chat messages, server-sent events) within roughly one RTT instead of
/// waiting for the client's next tick.
///
/// **This is a knob, not a constant of nature.** It trades push latency
/// against per-session quota burn — every empty return is a
/// round-trip charged against the Apps Script daily ceiling.
///
/// **History:** the pre-pipelining tunnel-client was strictly serial
/// (one in-flight op per session). Holding the poll for 15 s was the
/// sweet spot — long enough that Telegram XMPP / Google Push didn't
/// interpret frequent empty returns as connection instability and
/// rotate sessions (which each cost a 4 s TLS handshake through Apps
/// Script), short enough to fit inside the client's 30 s `BATCH_TIMEOUT`.
///
/// The pipelining redesign (upstream PR #1115) changed the trade-off
/// shape entirely. Each session now keeps `INFLIGHT_OPTIMIST` (=3) to
/// `INFLIGHT_ACTIVE` (=6) batches in flight at once, so a poll resolving
/// at 4 s is invisible to the client: a sibling slot is still holding
/// the channel open and will collect any push data the moment it
/// arrives. The Telegram-stability concern that motivated 15 s no longer
/// applies — there is always at least one other slot in flight to
/// absorb push within ≤ 4 s. The 4 s value also gives the pipeline's
/// adaptive-depth controller faster feedback for ramp-down on idle.
///
/// Quota note (honest version): even at the `INFLIGHT_IDLE = 1` floor,
/// one idle session still cycles roughly every 5 s (4 s long-poll +
/// ~1 s refill stagger), or ~12 polls/min. The old serial design at
/// 15 s cycled every ~16 s — ~3.75 polls/min. Idle sessions cost about
/// 3× more polls under the pipelined defaults; that's amortized by the
/// throughput win on active sessions and by users typically having far
/// fewer idle sessions than active ones, but it IS a measurable
/// quota-rate increase. If a future deployment needs to clamp idle
/// quota burn back to pre-pipelining levels, the cleanest knob is to
/// stretch the refill-step count once `consecutive_empty` exceeds the
/// idle threshold (10 steps → 60 steps would give ~7 s pacing).
const LONGPOLL_DEADLINE: Duration = Duration::from_secs(4);

/// Bound on each UDP session's inbound queue. Beyond this we drop oldest
/// to keep recent voice/media packets moving — a stale RTP frame is
/// worse than a missing one. Sized so a 256-deep queue at typical 1500B
/// payloads is ~384 KB before backpressure kicks in.
const UDP_QUEUE_LIMIT: usize = 256;

/// Receive buffer for the UDP reader task. Must be ≥ 65535 to handle
/// a maximum-size IPv4 datagram without truncation.
const UDP_RECV_BUF_BYTES: usize = 65536;

/// Maximum raw bytes per TCP drain that we hand back to Apps Script in
/// one batch response. Apps Script's hard cap on Web App response body
/// is ~50 MiB. Accounting for base64 encoding (1.33×) and JSON envelope
/// overhead, the safe ceiling for raw bytes is roughly 32 MiB — but
/// `serde_json::to_vec` for a single 32-MiB string is also a CPU spike,
/// so we lean further back at 16 MiB. On a high-bandwidth VPS (1 Gbps+)
/// the reader task can stuff the per-session buffer with tens of MiB
/// between polls (issue #460); without this cap, `drain_now` would take
/// the lot, the response would exceed Apps Script's ceiling, the body
/// would be truncated mid-base64, and the client would fail JSON parse
/// with `EOF while parsing a string at line 1 column ~52428685`. By
/// returning at most this many bytes per drain and leaving the rest in
/// the read buffer for the next poll, we keep responses comfortably
/// under the cap and let throughput recover across batches.
const TCP_DRAIN_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Hard cap on the total raw bytes drained across **all sessions** in a
/// single batch response. The per-session cap (`TCP_DRAIN_MAX_BYTES`)
/// alone isn't enough — N concurrent sessions can each contribute up to
/// 16 MiB raw; with N≥4, the summed batch body exceeds Apps Script's
/// 50 MiB ceiling and the client fails JSON parse mid-stream (#863).
///
/// 32 MiB raw → ~43 MiB base64 + per-session JSON envelope overhead
/// (~80 bytes × ≤50 ops cap) → comfortably under 50 MiB total. Any
/// further sessions in the same batch are deferred to the next poll
/// (their data stays in their per-session `read_buf`, so no data loss
/// — they just settle one batch later).
const BATCH_RESPONSE_BUDGET: usize = 32 * 1024 * 1024;

/// Maximum number of out-of-order upload chunks buffered per session in
/// the wseq-ordering map. The official client's `INFLIGHT_ACTIVE` cap is
/// 4 (with +4 fast-path slack = 8 in-flight max), so a legitimate gap is
/// bounded to ~8 missing wseqs. Anything past 32 is an authenticated
/// caller intentionally jumping wseq to consume server memory — close
/// the session rather than letting `pending_writes` grow without bound.
const MAX_PENDING_WRITES_PER_SESSION: usize = 32;

/// Maximum aggregate bytes the wseq-ordering buffer holds for one session.
/// A misbehaving client that stays under `MAX_PENDING_WRITES_PER_SESSION`
/// by chance could still flood individual chunks; cap the total so the
/// per-session ceiling is bounded in both dimensions. Sized in step with
/// `TCP_DRAIN_MAX_BYTES` (16 MiB) — beyond that, the cumulative buffered
/// upload doesn't fit in one drain response anyway.
const MAX_PENDING_WRITE_BYTES_PER_SESSION: usize = 16 * 1024 * 1024;

/// First queue-drop on a session always logs at warn level; subsequent
/// drops log at debug only every Nth occurrence so a single congested
/// session can't flood the operator's log.
const UDP_QUEUE_DROP_LOG_STRIDE: u64 = 100;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Writer half — either a real TCP socket or an in-process duplex channel
/// (used for virtual sessions like udpgw).
enum SessionWriter {
    Tcp(OwnedWriteHalf),
    Duplex(tokio::io::WriteHalf<tokio::io::DuplexStream>),
}

impl SessionWriter {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            SessionWriter::Tcp(w) => w.write_all(buf).await,
            SessionWriter::Duplex(w) => w.write_all(buf).await,
        }
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SessionWriter::Tcp(w) => w.flush().await,
            SessionWriter::Duplex(w) => w.flush().await,
        }
    }
}

struct SessionInner {
    writer: Mutex<SessionWriter>,
    read_buf: Mutex<Vec<u8>>,
    eof: AtomicBool,
    last_active: Mutex<Instant>,
    /// Fired by `reader_task` whenever new bytes land in `read_buf` or the
    /// upstream socket closes. `wait_for_any_drainable` listens on this
    /// to wake the drain phase as soon as any session has something to
    /// ship, replacing the old fixed-sleep heuristic.
    notify: Notify,
    /// Sequence-ordered write buffer: pipelined data ops may arrive
    /// out of order (different batches completing at different times).
    /// We buffer out-of-order writes and flush in seq order.
    next_write_seq: Mutex<Option<u64>>,
    pending_writes: Mutex<std::collections::BTreeMap<u64, Vec<u8>>>,
}

struct ManagedSession {
    inner: Arc<SessionInner>,
    reader_handle: tokio::task::JoinHandle<()>,
    /// For udpgw sessions, the server task handle (so we can abort on close).
    udpgw_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ManagedSession {
    fn abort_all(&self) {
        self.reader_handle.abort();
        if let Some(ref h) = self.udpgw_handle {
            h.abort();
        }
    }
}

/// UDP equivalent of `SessionInner`. Holds a *connected* `UdpSocket`
/// pinned to one `(host, port)` upstream so we don't have to re-resolve
/// or re-parse the destination on every datagram. `notify` is fired by
/// the reader task on each inbound datagram (or on socket error) so the
/// batch drain phase can wake without polling — same primitive as the
/// TCP path.
struct UdpSessionInner {
    socket: Arc<UdpSocket>,
    packets: Mutex<VecDeque<Vec<u8>>>,
    last_active: Mutex<Instant>,
    notify: Notify,
    /// Set when the upstream socket dies (recv error). Mirrors TCP's
    /// `eof`: once true, subsequent batch drains return `eof: Some(true)`
    /// so the proxy-side session task knows to exit instead of polling
    /// a zombie session until the 120 s idle reaper kills it.
    eof: AtomicBool,
    /// Total datagrams dropped because the queue hit `UDP_QUEUE_LIMIT`.
    /// Surfaced via tracing so operators can correlate "choppy call"
    /// reports with relay backpressure.
    queue_drops: AtomicU64,
}

struct ManagedUdpSession {
    inner: Arc<UdpSessionInner>,
    reader_handle: tokio::task::JoinHandle<()>,
}

// ---------------------------------------------------------------------------
// Connect-path acceleration: DNS cache + idle TCP pool + hot-host tracker.
//
// Profiling on a typical session-open showed two real costs that compound
// across a multi-RTT TLS handshake against PSN/Akamai:
//   1) `TcpStream::connect(host:port)` does DNS resolution inline, which
//      adds 5-30 ms per uncached resolve from a non-local resolver.
//   2) The TCP three-way handshake to a far CDN edge adds 30-100 ms.
//
// `PrewarmState` caches both. The DNS cache is a straightforward
// host:port -> Vec<SocketAddr> map with a short TTL. The TCP pool keeps
// a small number of idle connections per hot host. "Hot" is defined
// as ≥ HOT_HOST_MIN_COUNT connects within HOT_HOST_WINDOW; this keeps
// the pool from filling up with one-off destinations and bounds the
// FD overhead on the tunnel-node.
//
// Pool entries are deliberately short-TTL (`TCP_POOL_TTL`) so we don't
// hand out connections an intermediary might have ghosted while idle,
// and `open_tcp` does a non-blocking `try_read` liveness check (see
// `is_likely_alive`) on every pool entry before handing it to a session;
// entries that fail the check are discarded and `connect_fresh` runs
// instead. Race-window stragglers (peer closed but the FIN hasn't
// propagated yet) can still slip through; the cost is one wasted
// round-trip before the session EOFs.

/// DNS resolution cache TTL. Conservative vs typical DNS record TTLs
/// (hours), short enough that we don't keep serving stale records past
/// a real backend rotation.
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
/// Maximum entries kept in the DNS cache. Bounded so a misbehaving
/// client can't OOM us by opening sessions to many distinct hosts.
const DNS_CACHE_MAX_ENTRIES: usize = 1024;
/// Idle TCP pool entries past this age are treated as stale and
/// discarded. Short enough to avoid handing out connections ghosted by
/// NAT/CDN intermediaries; long enough to cover a typical multi-RTT
/// handshake's gap between session-close and the next session-open
/// to the same host.
const TCP_POOL_TTL: Duration = Duration::from_secs(30);
/// Maximum idle TCP connections kept per (host, port). Two is enough
/// to absorb a small burst (e.g. a PSN sign-in opening two parallel
/// sessions to the same auth endpoint) without keeping a long tail of
/// idle file descriptors.
const TCP_POOL_PER_HOST_MAX: usize = 2;
/// Global cap on the total number of pooled TCP connections across
/// every host. A safety net against unbounded growth if many hosts
/// each accumulate per-host max — bounded FD budget on shared
/// tunnel-nodes.
const TCP_POOL_TOTAL_MAX: usize = 64;
/// Sliding window over which a host's connect-count is considered for
/// the "hot" decision. Long enough that a sign-in flow's multiple
/// connects to the same auth endpoint count together; short enough
/// that traffic patterns drift naturally.
const HOT_HOST_WINDOW: Duration = Duration::from_secs(300);
/// Minimum connects to (host, port) within `HOT_HOST_WINDOW` for the
/// host to qualify for prewarming. The first connect can't pre-warm
/// itself (we don't know yet that it's hot), but the second one
/// triggers a background prewarm so the third sees a pool hit.
const HOT_HOST_MIN_COUNT: usize = 2;
/// How long to wait for a TCP handshake before giving up. Mirrors the
/// pre-Phase-7 `create_session` hard timeout — we don't want a hung
/// outbound DNS or SYN to wedge a session-open. **Covers both DNS
/// resolution AND every per-address connect attempt under a single
/// budget**, so a stuck resolver can't add to the connect deadline.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum distinct (host, port) entries the hot-host tracker retains.
/// Bounded so adversarial / scanner-shaped input from authenticated
/// clients cannot grow the map without limit. Stale entries are
/// pruned opportunistically when this cap would otherwise be hit.
const HOT_HOSTS_MAX_KEYS: usize = 256;
/// Env-var kill switch for speculative TCP prewarming. Set to `1`,
/// `true`, or `TRUE` to disable: `maybe_prewarm` becomes a no-op,
/// the pool never gets populated, and every session-open takes the
/// `connect_fresh` path. Provided so an operator can fall back to
/// purely-reactive behaviour if a connection-limited or server-
/// speaks-first protocol turns out to misbehave under speculative
/// upstream sockets. The env var is read once at `PrewarmState::new`;
/// changing it requires a tunnel-node restart.
const PREWARM_DISABLED_ENV: &str = "MHRV_DISABLE_PREWARM";

/// One-shot read of `PREWARM_DISABLED_ENV` at startup. Recognises
/// the conventional truthy spellings; anything else (unset, empty,
/// "0", "false", arbitrary text) leaves prewarm enabled.
fn prewarm_enabled_from_env() -> bool {
    match std::env::var(PREWARM_DISABLED_ENV).as_deref() {
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES") => {
            tracing::info!(
                "{} set; speculative TCP prewarm disabled",
                PREWARM_DISABLED_ENV
            );
            false
        }
        _ => true,
    }
}

struct DnsEntry {
    addrs: Vec<SocketAddr>,
    expires_at: Instant,
}

struct DnsCache {
    entries: Mutex<HashMap<(String, u16), DnsEntry>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Return the cached addresses if fresh, otherwise resolve and
    /// cache. Errors bubble straight from `lookup_host` so the caller
    /// sees the same shape as the un-cached path.
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let key = (host.to_string(), port);
        let now = Instant::now();
        {
            let entries = self.entries.lock().await;
            if let Some(entry) = entries.get(&key) {
                if entry.expires_at > now {
                    return Ok(entry.addrs.clone());
                }
            }
        }
        let addrs: Vec<SocketAddr> = lookup_host((host, port)).await?.collect();
        if addrs.is_empty() {
            // Don't cache the empty resolution: a brief
            // resolver hiccup shouldn't latch in as 60 s of empty
            // results for this host.
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no addresses resolved",
            ));
        }
        let mut entries = self.entries.lock().await;
        // Bounded-cache eviction: when we'd cross the cap, drop one
        // arbitrary entry. HashMap iteration order is randomized so
        // this is effectively random eviction — fine for a small cache
        // dominated by recent re-resolves, and avoids the LRU
        // bookkeeping cost on the hot path.
        if entries.len() >= DNS_CACHE_MAX_ENTRIES {
            if let Some(victim) = entries.keys().next().cloned() {
                entries.remove(&victim);
            }
        }
        entries.insert(
            key,
            DnsEntry {
                addrs: addrs.clone(),
                expires_at: now + DNS_CACHE_TTL,
            },
        );
        Ok(addrs)
    }

    /// Drop the cached resolution for `(host, port)`. Called by
    /// `PrewarmState::connect_fresh` when every resolved address
    /// failed to connect — the cached entry may be a stale CDN /
    /// failover answer, and keeping it around for the full TTL would
    /// poison every subsequent session-open against the same host
    /// for up to `DNS_CACHE_TTL`. Eviction lets the next call
    /// re-resolve and pick whatever the current DNS answer is.
    async fn evict(&self, host: &str, port: u16) {
        let key = (host.to_string(), port);
        self.entries.lock().await.remove(&key);
    }
}

struct PooledConn {
    stream: TcpStream,
    opened_at: Instant,
}

/// Per-host pool state. `pending` is the count of in-flight prewarms
/// that have reserved a slot but haven't completed yet — gating
/// `try_reserve` on `queue.len() + pending` is what bounds parallel
/// prewarms to the per-host cap.
#[derive(Default)]
struct HostState {
    queue: VecDeque<PooledConn>,
    pending: usize,
}

impl HostState {
    fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.pending == 0
    }
}

struct PoolInner {
    hosts: HashMap<(String, u16), HostState>,
    /// Sum of `queue.len()` across all hosts. Kept consistent with
    /// the hosts map under the same lock — no separate atomic, no
    /// lock-order pair to deadlock against.
    total_actual: usize,
    /// Sum of `pending` across all hosts. Counts reserved-but-not-
    /// committed prewarms against the global cap so a burst of hot
    /// connects can't spawn N parallel TCP connects when there's
    /// only room for K.
    total_pending: usize,
}

impl PoolInner {
    /// Drop entries past TTL from every queue and update `total_actual`.
    /// Called from `try_reserve` when the global cap would otherwise
    /// be hit — this is the periodic-cleanup mechanism the reviewer
    /// asked for, amortized to the prewarm path so a quiescent pool
    /// pays no maintenance cost.
    fn prune_stale(&mut self) {
        let now = Instant::now();
        let mut dropped = 0;
        for state in self.hosts.values_mut() {
            let before = state.queue.len();
            state
                .queue
                .retain(|c| now.duration_since(c.opened_at) < TCP_POOL_TTL);
            dropped += before - state.queue.len();
        }
        self.hosts.retain(|_, s| !s.is_empty());
        self.total_actual = self.total_actual.saturating_sub(dropped);
    }
}

/// Single-mutex pool. All mutations and reads go through `inner` so
/// there's no second lock to pair with — eliminates the lock-order
/// hazard a two-mutex design would have under concurrent take/insert.
struct TcpPool {
    inner: Mutex<PoolInner>,
}

impl TcpPool {
    fn new() -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                hosts: HashMap::new(),
                total_actual: 0,
                total_pending: 0,
            }),
        }
    }

    /// Take a pooled connection for (host, port) if a fresh one
    /// exists. Stale entries (older than `TCP_POOL_TTL`) are dropped
    /// off the front of the queue until a fresh one is found or the
    /// queue is empty.
    async fn try_take(&self, host: &str, port: u16) -> Option<TcpStream> {
        let key = (host.to_string(), port);
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        let mut taken: Option<TcpStream> = None;
        let mut dropped: usize = 0;
        if let Some(state) = inner.hosts.get_mut(&key) {
            while let Some(conn) = state.queue.pop_front() {
                if now.duration_since(conn.opened_at) < TCP_POOL_TTL {
                    taken = Some(conn.stream);
                    break;
                }
                dropped += 1;
            }
        }
        let consumed = dropped + if taken.is_some() { 1 } else { 0 };
        inner.total_actual = inner.total_actual.saturating_sub(consumed);
        // Drop now-empty host entries so the hosts map doesn't
        // accumulate keys with empty queues and no pending work.
        if inner.hosts.get(&key).map(|s| s.is_empty()).unwrap_or(false) {
            inner.hosts.remove(&key);
        }
        taken
    }

    /// Reserve a pool slot for an in-flight prewarm. Returns true if
    /// both the per-host cap (`queue.len() + pending < per-host max`)
    /// and the global cap (`total_actual + total_pending < global max`)
    /// have room after pruning stale entries. Caller MUST follow up
    /// with exactly one of `commit_reserve` (on connect success) or
    /// `cancel_reserve` (on connect failure) so the counter stays
    /// consistent. Combined with `commit_reserve`'s rare ability to
    /// skip the cap (see its doc), the reservation pair is what makes
    /// prewarm-in-flight bounded.
    async fn try_reserve(&self, host: &str, port: u16) -> bool {
        let key = (host.to_string(), port);
        let mut inner = self.inner.lock().await;
        if inner.total_actual + inner.total_pending >= TCP_POOL_TOTAL_MAX {
            inner.prune_stale();
            if inner.total_actual + inner.total_pending >= TCP_POOL_TOTAL_MAX {
                return false;
            }
        }
        let state = inner.hosts.entry(key).or_default();
        if state.queue.len() + state.pending >= TCP_POOL_PER_HOST_MAX {
            return false;
        }
        state.pending += 1;
        inner.total_pending += 1;
        true
    }

    /// Convert a previously-reserved slot into an actual pooled
    /// stream. Always honors the reservation: even if other actors
    /// added entries since `try_reserve` returned, we already counted
    /// against the cap when we incremented `total_pending`, so the
    /// invariant holds.
    async fn commit_reserve(&self, host: &str, port: u16, stream: TcpStream) {
        let key = (host.to_string(), port);
        let mut inner = self.inner.lock().await;
        let state = inner.hosts.entry(key).or_default();
        state.pending = state.pending.saturating_sub(1);
        state.queue.push_back(PooledConn {
            stream,
            opened_at: Instant::now(),
        });
        inner.total_pending = inner.total_pending.saturating_sub(1);
        inner.total_actual += 1;
    }

    /// Release a previously-reserved slot without filling it. Used
    /// when a prewarm's connect fails.
    async fn cancel_reserve(&self, host: &str, port: u16) {
        let key = (host.to_string(), port);
        let mut inner = self.inner.lock().await;
        if let Some(state) = inner.hosts.get_mut(&key) {
            state.pending = state.pending.saturating_sub(1);
        }
        inner.total_pending = inner.total_pending.saturating_sub(1);
        if inner.hosts.get(&key).map(|s| s.is_empty()).unwrap_or(false) {
            inner.hosts.remove(&key);
        }
    }
}

struct HotHostsInner {
    seen: HashMap<(String, u16), VecDeque<Instant>>,
}

impl HotHostsInner {
    /// Drop stale timestamps from every queue and remove any queue
    /// that's now empty. Bounded by `HOT_HOSTS_MAX_KEYS` per call.
    fn prune(&mut self, cutoff: Instant) {
        self.seen.retain(|_, q| {
            while q.front().map(|t| *t < cutoff).unwrap_or(false) {
                q.pop_front();
            }
            !q.is_empty()
        });
    }
}

struct HotHosts {
    /// Bounded by `HOT_HOSTS_MAX_KEYS` keys. Stale timestamps are
    /// pruned on the hot path's same-key path; full-map prune runs
    /// opportunistically when the cap would otherwise be hit.
    inner: Mutex<HotHostsInner>,
}

impl HotHosts {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HotHostsInner {
                seen: HashMap::new(),
            }),
        }
    }

    /// Record a connect to (host, port) and return whether the host
    /// is now "hot" (≥ `HOT_HOST_MIN_COUNT` connects within
    /// `HOT_HOST_WINDOW`). Map-size is bounded by `HOT_HOSTS_MAX_KEYS`
    /// — a new key over the cap triggers a full-map prune; if still
    /// over after that, one arbitrary existing key is evicted.
    async fn record_and_check(&self, host: &str, port: u16) -> bool {
        let key = (host.to_string(), port);
        let now = Instant::now();
        let cutoff = now.checked_sub(HOT_HOST_WINDOW).unwrap_or(now);
        let mut inner = self.inner.lock().await;
        if !inner.seen.contains_key(&key) && inner.seen.len() >= HOT_HOSTS_MAX_KEYS {
            inner.prune(cutoff);
            if !inner.seen.contains_key(&key) && inner.seen.len() >= HOT_HOSTS_MAX_KEYS {
                if let Some(victim) = inner.seen.keys().next().cloned() {
                    inner.seen.remove(&victim);
                }
            }
        }
        let q = inner.seen.entry(key).or_insert_with(VecDeque::new);
        while q.front().map(|t| *t < cutoff).unwrap_or(false) {
            q.pop_front();
        }
        // Bound the queue per key. The hot decision only needs
        // `HOT_HOST_MIN_COUNT` in-window samples — anything beyond
        // that adds no information but lets a single very-popular
        // host (or a quiet host whose record path doesn't get hit
        // again) accumulate unboundedly within the window. Trim
        // before push so the final queue length is exactly
        // `HOT_HOST_MIN_COUNT` whenever the host is hot.
        while q.len() >= HOT_HOST_MIN_COUNT {
            q.pop_front();
        }
        q.push_back(now);
        q.len() >= HOT_HOST_MIN_COUNT
    }
}

struct PrewarmState {
    dns: DnsCache,
    pool: TcpPool,
    hot: HotHosts,
    /// One-shot snapshot of `PREWARM_DISABLED_ENV` taken at
    /// `PrewarmState::new`. False → `maybe_prewarm` is a no-op and
    /// the pool stays empty, which naturally degrades `open_tcp` to
    /// the legacy `connect_fresh` path. The DNS cache stays active
    /// either way — it's a pure resolver-call savings with no
    /// semantic change.
    prewarm_enabled: bool,
}

impl PrewarmState {
    fn new() -> Arc<Self> {
        Self::with_prewarm_enabled(prewarm_enabled_from_env())
    }

    /// Test-only constructor that bypasses the env-var check. Keeps
    /// `PrewarmState::new` env-driven for production callers while
    /// letting the unit tests pin the disabled / enabled branch
    /// deterministically — env vars are process-wide so test-time
    /// `set_var` would race across the test runner.
    fn with_prewarm_enabled(prewarm_enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            dns: DnsCache::new(),
            pool: TcpPool::new(),
            hot: HotHosts::new(),
            prewarm_enabled,
        })
    }

    /// Open a TCP connection to (host, port). Pool hit → instant
    /// return of the cached stream; pool miss → DNS-cached resolve
    /// followed by a fresh `TcpStream::connect`. Either path applies
    /// `TCP_CONNECT_TIMEOUT` so a wedged outbound can't stall the
    /// session-open path.
    async fn open_tcp(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        // Pooled TCP sockets can be up to TCP_POOL_TTL old. In that
        // window NAT/CDN intermediaries (or the destination itself)
        // may have closed the connection out from under us. The
        // tunnel-client side makes one attempt per session and has no
        // retry budget, so handing out a dead pool entry would brick
        // the session — drain the queue until either a likely-alive
        // entry surfaces or the queue is empty, then fall back to a
        // fresh connect.
        while let Some(stream) = self.pool.try_take(host, port).await {
            if is_likely_alive(&stream) {
                return Ok(stream);
            }
            tracing::debug!(
                "pool entry for {}:{} failed liveness check; discarding",
                host,
                port
            );
        }
        self.connect_fresh(host, port).await
    }

    /// Open a fresh TCP connection without consulting the pool — used
    /// by the prewarm path itself, which is the producer side of the
    /// pool. Kept distinct from `open_tcp` so it's syntactically
    /// impossible for the prewarm task to recurse into `try_take`.
    ///
    /// The `TCP_CONNECT_TIMEOUT` budget wraps **both** DNS resolution
    /// and every per-address connect attempt, so a stuck resolver
    /// can't add to the connect deadline (matches the pre-Phase-7
    /// `TcpStream::connect(host:port)` semantics where DNS was inline
    /// under the same outer timeout). On multi-A or dual-stack
    /// targets we iterate the resolved addresses in order — same as
    /// the pre-Phase-7 behavior — so a single dead IPv6 doesn't
    /// shadow a healthy IPv4.
    async fn connect_fresh(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        self.connect_fresh_with_timeout(host, port, TCP_CONNECT_TIMEOUT)
            .await
    }

    /// Same as `connect_fresh` but with a caller-supplied budget.
    /// Extracted so unit tests can exercise the timeout-eviction path
    /// without waiting `TCP_CONNECT_TIMEOUT` of wall-clock seconds.
    /// Production callers always go through `connect_fresh`.
    async fn connect_fresh_with_timeout(
        &self,
        host: &str,
        port: u16,
        budget: Duration,
    ) -> std::io::Result<TcpStream> {
        let dns = &self.dns;
        let host_owned = host;
        let attempt = async move {
            let addrs = dns.resolve(host_owned, port).await?;
            let mut last_err: Option<std::io::Error> = None;
            for addr in addrs {
                match TcpStream::connect(addr).await {
                    Ok(s) => return Ok::<TcpStream, std::io::Error>(s),
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no addresses resolved",
                )
            }))
        };
        // Match the timeout outcome explicitly so the timeout-Err arm
        // flows through the same eviction check as a resolved-Err.
        // The earlier `?` over the timeout's `map_err` short-circuited
        // before eviction, leaving stale/blackholed cached addresses
        // to keep poisoning sessions for the rest of DNS_CACHE_TTL.
        let result: std::io::Result<TcpStream> = match tokio::time::timeout(budget, attempt).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout (includes dns)",
            )),
        };
        if result.is_err() {
            // Every resolved address either refused, errored, or
            // exhausted the budget. The cached entry may be stale
            // (CDN failover, blocked region, etc.); drop it so the
            // next call re-resolves rather than rolling the same bad
            // address for `DNS_CACHE_TTL`.
            self.dns.evict(host, port).await;
        }
        result
    }

    /// Record a connect and, if the destination is now hot, spawn a
    /// background task to pre-open another connection for the next
    /// session-open to land on. The spawn is fire-and-forget: failure
    /// modes are handled by the reservation pair — a failed connect
    /// releases its slot via `cancel_reserve` so subsequent prewarms
    /// can take its place. `try_reserve` is what bounds parallel
    /// prewarm work: if the per-host cap or global cap (counting both
    /// pooled streams AND in-flight reservations) is exhausted, we
    /// don't even start the connect.
    fn maybe_prewarm(self: &Arc<Self>, host: String, port: u16) {
        // Kill switch: `MHRV_DISABLE_PREWARM=1` makes this a no-op so
        // the tunnel-node never opens a speculative upstream socket.
        // Pool entries are only ever produced here, so disabling
        // prewarm naturally drains the pool to zero and reverts
        // `open_tcp` to pure `connect_fresh` behaviour.
        if !self.prewarm_enabled {
            return;
        }
        let me = Arc::clone(self);
        tokio::spawn(async move {
            if !me.hot.record_and_check(&host, port).await {
                return;
            }
            if !me.pool.try_reserve(&host, port).await {
                return;
            }
            match me.connect_fresh(&host, port).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    me.pool.commit_reserve(&host, port, stream).await;
                }
                Err(e) => {
                    me.pool.cancel_reserve(&host, port).await;
                    tracing::debug!("prewarm {}:{} failed: {}", host, port, e);
                }
            }
        });
    }
}

/// Non-blocking liveness check on a pooled TCP stream. Returns
/// `false` if the peer has sent FIN, sent any unexpected bytes (a
/// pre-warmed outbound socket to a destination we haven't started
/// the protocol on yet must be quiet), or any other read error
/// surfaced through `try_read`. Returns `true` only on the
/// `WouldBlock` "no data available right now" case, which is what an
/// idle-but-alive socket reports.
///
/// The check is best-effort: an alive peer that hasn't yet noticed
/// the route is dead will still look alive here (the standard race
/// for any out-of-band liveness probe). That's acceptable because
/// the alternative is handing out a definitively-dead socket every
/// time — `try_read` catches the common case where an intermediary
/// (NAT, CDN edge) has already closed an idle connection out from
/// under us.
fn is_likely_alive(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => false,
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

async fn create_session(
    host: &str,
    port: u16,
    prewarm: &Arc<PrewarmState>,
) -> std::io::Result<ManagedSession> {
    let stream = prewarm.open_tcp(host, port).await?;
    let _ = stream.set_nodelay(true);
    prewarm.maybe_prewarm(host.to_string(), port);
    let (reader, writer) = stream.into_split();

    let inner = Arc::new(SessionInner {
        writer: Mutex::new(SessionWriter::Tcp(writer)),
        read_buf: Mutex::new(Vec::with_capacity(32768)),
        eof: AtomicBool::new(false),
        last_active: Mutex::new(Instant::now()),
        notify: Notify::new(),
        next_write_seq: Mutex::new(None),
        pending_writes: Mutex::new(std::collections::BTreeMap::new()),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(reader_task(reader, inner_ref));

    Ok(ManagedSession {
        inner,
        reader_handle,
        udpgw_handle: None,
    })
}

/// Create a virtual udpgw session backed by an in-process duplex channel.
fn create_udpgw_session() -> ManagedSession {
    let (client_half, server_half) = tokio::io::duplex(65536);
    let (read_half, write_half) = tokio::io::split(client_half);

    let inner = Arc::new(SessionInner {
        writer: Mutex::new(SessionWriter::Duplex(write_half)),
        read_buf: Mutex::new(Vec::with_capacity(32768)),
        eof: AtomicBool::new(false),
        last_active: Mutex::new(Instant::now()),
        notify: Notify::new(),
        next_write_seq: Mutex::new(None),
        pending_writes: Mutex::new(std::collections::BTreeMap::new()),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(reader_task(read_half, inner_ref));
    let udpgw_handle = Some(tokio::spawn(udpgw::udpgw_server_task(server_half)));

    ManagedSession {
        inner,
        reader_handle,
        udpgw_handle,
    }
}

async fn reader_task(mut reader: impl AsyncRead + Unpin, session: Arc<SessionInner>) {
    // 256 KiB syscall staging buffer. Upstream PR #1115 bumped this to
    // 2 MiB to fewer-syscall a single drain, but the buf is per-session
    // and persists for the session's lifetime — multiplying by N concurrent
    // sessions, 2 MiB became a multi-hundred-MiB ceiling on the tunnel-node.
    // 256 KiB stays large enough to absorb a full kernel TCP recv window
    // in one syscall on typical Linux defaults, while keeping per-session
    // baseline memory bounded.
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                session.eof.store(true, Ordering::Release);
                session.notify.notify_one();
                break;
            }
            Ok(n) => {
                // Extend the buffer before notifying. The MutexGuard is
                // dropped at the end of the statement, *before* the
                // notify_one call below, so any waiter that wakes on the
                // notify and then locks read_buf can immediately observe
                // the new bytes — no torn read where the wake fires but
                // the buffer still looks empty. Notify::notify_one also
                // stores a permit if no waiter is currently registered,
                // so we never lose an edge across the spawn race in
                // wait_for_any_drainable.
                session.read_buf.lock().await.extend_from_slice(&buf[..n]);
                session.notify.notify_one();
            }
            Err(_) => {
                session.eof.store(true, Ordering::Release);
                session.notify.notify_one();
                break;
            }
        }
    }
}

async fn create_udp_session(
    host: &str,
    port: u16,
    dns: &DnsCache,
) -> std::io::Result<ManagedUdpSession> {
    let addrs = dns.resolve(host, port).await?;
    let remote = *addrs.first().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no UDP address resolved",
        )
    })?;
    let bind_addr = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(remote).await?;
    let socket = Arc::new(socket);

    let inner = Arc::new(UdpSessionInner {
        socket: socket.clone(),
        packets: Mutex::new(VecDeque::with_capacity(UDP_QUEUE_LIMIT)),
        last_active: Mutex::new(Instant::now()),
        notify: Notify::new(),
        eof: AtomicBool::new(false),
        queue_drops: AtomicU64::new(0),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(udp_reader_task(socket, inner_ref));
    Ok(ManagedUdpSession {
        inner,
        reader_handle,
    })
}

/// UDP analogue of `reader_task`. Reads from the connected UDP socket
/// and queues each datagram on the session. Drops oldest on overflow,
/// updates `last_active` so server-push (download-only) UDP keeps the
/// session out of the idle reaper, and fires `notify` so the batch
/// drain phase can wake without polling.
async fn udp_reader_task(socket: Arc<UdpSocket>, session: Arc<UdpSessionInner>) {
    let mut buf = vec![0u8; UDP_RECV_BUF_BYTES];
    loop {
        match socket.recv(&mut buf).await {
            // Empty datagram is valid UDP; nothing to forward, ignore.
            Ok(0) => {}
            Ok(n) => {
                let mut packets = session.packets.lock().await;
                if packets.len() >= UDP_QUEUE_LIMIT {
                    packets.pop_front();
                    let dropped = session.queue_drops.fetch_add(1, Ordering::Relaxed) + 1;
                    if dropped == 1 {
                        tracing::warn!(
                            "udp queue full ({}); dropping oldest. Apps Script polling cannot keep up with upstream rate.",
                            UDP_QUEUE_LIMIT
                        );
                    } else if dropped % UDP_QUEUE_DROP_LOG_STRIDE == 0 {
                        tracing::debug!("udp queue drops: {} on session", dropped);
                    }
                }
                packets.push_back(buf[..n].to_vec());
                drop(packets);
                // Inbound packet counts as activity — keeps server-push
                // UDP (e.g. SIP/RTP, server-sent telemetry) out of the
                // idle reaper. Empty `udp_data` polls deliberately do
                // NOT bump this (see batch handler).
                *session.last_active.lock().await = Instant::now();
                session.notify.notify_one();
            }
            Err(e) => {
                // Upstream socket died (ICMP unreachable on a connected
                // socket, container netns torn down, etc.). Surface eof
                // so the proxy-side session task can exit on its next
                // poll instead of looping until the idle reaper.
                tracing::debug!("udp upstream recv error: {} — marking session eof", e);
                session.eof.store(true, Ordering::Release);
                session.notify.notify_one();
                break;
            }
        }
    }
}

/// Drain up to `min(TCP_DRAIN_MAX_BYTES, max_bytes)` from the per-session
/// read buffer — no waiting. Used by batch mode where we poll frequently.
///
/// `max_bytes` is the caller-supplied budget for this drain (typically the
/// remaining batch-response budget after summing previous drains in the
/// same batch). It allows the batch loop to stop one session short of
/// blowing past Apps Script's 50 MiB ceiling on the wire (#863). Pass
/// `usize::MAX` if there's no extra budget constraint (e.g. single-op
/// path outside the batch loop).
///
/// If the buffer is larger than the effective cap, we return a prefix of
/// the data and leave the remainder in the buffer for the next poll.
///
/// `eof` is reported as true only when the buffer has been fully drained
/// AND upstream has signaled EOF — otherwise a partial drain would
/// prematurely tear the session down on the client side.
async fn drain_now(session: &SessionInner, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut buf = session.read_buf.lock().await;
    let raw_eof = session.eof.load(Ordering::Acquire);
    let cap = max_bytes.min(TCP_DRAIN_MAX_BYTES);
    if buf.len() <= cap {
        let data = std::mem::take(&mut *buf);
        (data, raw_eof)
    } else {
        // Take the prefix; leave the tail in the buffer.
        let tail = buf.split_off(cap);
        let head = std::mem::replace(&mut *buf, tail);
        // Don't propagate eof yet — buffer still has data even if upstream
        // has closed. The client will get eof on the drain that returns
        // an empty (or sub-cap) buffer.
        (head, false)
    }
}

/// Block until *any* of `inners` has buffered data, hits EOF, or the
/// deadline elapses — whichever comes first. Returns immediately if any
/// session is already drainable when called.
///
/// This replaces the legacy `sleep(150ms)` + `sleep(200ms)` retry pattern
/// in batch drain. With `reader_task` firing `notify_one` on each
/// appended chunk, a typical TLS ServerHello (~30-50 ms) wakes the wait
/// in milliseconds instead of paying the 150 ms ceiling. For pure-poll
/// batches the same primitive holds the response open until upstream
/// pushes data or `LONGPOLL_DEADLINE` elapses, turning idle sessions
/// into a true long-poll.
///
/// Race-safety:
///   * `Notify::notify_one` stores a one-shot permit if no waiter is
///     registered, so a notify that fires between the buffer check and
///     the watcher's `.notified().await` is consumed on the next poll
///     rather than lost.
///   * Watchers self-filter against observable session state. A prior
///     batch that returned via the spawn-race shortcut may leave a
///     stale permit on the `Notify`; this batch's watcher will consume
///     it but, finding the buffer empty and EOF unset, loop back to
///     wait for a real notify. Without this filter, an idle long-poll
///     batch could return in <1 ms on a stale permit and degrade push
///     delivery to the client's idle re-poll cadence.
/// `JoinHandle` newtype that aborts the task on `Drop`. Lets the waiter
/// helpers below be cancel-safe under `tokio::select!`: a plain
/// `Vec<JoinHandle<()>>` only releases its handles via `Drop`, which
/// *detaches* tasks rather than aborting them. The previous shape
/// relied on a trailing `for w in &watchers { w.abort(); }` loop —
/// fine when the function ran to completion, but past the cancellation
/// points (`is_any_drainable().await`, the inner `select!`), so
/// cancelling the loser arm of the phase-2 `select!` left N orphan
/// watchers parked on `notify.notified()`. Each held an
/// `Arc<…Inner>` and could steal a `notify_one()` permit from a
/// future batch's watcher, making that batch wait until the next
/// notify or its deadline. Wrapping in `AbortOnDrop` makes cleanup
/// happen on every exit path, including cancellation.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn wait_for_any_drainable(inners: &[Arc<SessionInner>], deadline: Duration) {
    if inners.is_empty() {
        return;
    }

    // One watcher per session. Each loops until it observes real state
    // (eof set or buffer non-empty) before signaling — see the
    // race-safety note above. Watchers are held in a Vec of
    // `AbortOnDrop`, so they're aborted on every exit path —
    // including cancellation by an outer `select!`.
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let mut _watchers: Vec<AbortOnDrop> = Vec::with_capacity(inners.len());
    for inner in inners {
        let inner = inner.clone();
        let tx = tx.clone();
        _watchers.push(AbortOnDrop(tokio::spawn(async move {
            loop {
                inner.notify.notified().await;
                if inner.eof.load(Ordering::Acquire) {
                    break;
                }
                if !inner.read_buf.lock().await.is_empty() {
                    break;
                }
                // Stale permit (notify fired but state didn't change in
                // an observable way — e.g., bytes were already drained
                // by a prior batch). Loop back and wait for a real
                // notify, don't wake the caller.
            }
            let _ = tx.try_send(());
        })));
    }
    drop(tx);

    // Spawn-race shortcut: if state was already drainable when we got
    // here (bytes arrived between phase 1 and this point), return
    // without entering the select. The watcher self-filtering above
    // means the unconsumed permit we leave behind here is harmless to
    // future batches.
    let already_ready = is_any_drainable(inners).await;

    if !already_ready {
        tokio::select! {
            _ = rx.recv() => {}
            _ = tokio::time::sleep(deadline) => {}
        }
    }

    // No explicit abort loop: `_watchers`'s `AbortOnDrop` entries fire
    // on the function returning here AND on the future being dropped
    // mid-await by an outer `select!`.
}

/// True iff any session is currently drainable: its read buffer has
/// bytes, or it's been marked EOF. Pulled out of `wait_for_any_drainable`
/// so the same predicate can drive both the spawn-race shortcut and the
/// post-wake straggler poll.
async fn is_any_drainable(inners: &[Arc<SessionInner>]) -> bool {
    for inner in inners {
        if inner.eof.load(Ordering::Acquire) {
            return true;
        }
        if !inner.read_buf.lock().await.is_empty() {
            return true;
        }
    }
    false
}

/// Drain whatever UDP datagrams are currently queued — no waiting.
/// Returns the eof flag alongside packets so the batch handler can
/// surface upstream-socket death without an extra round-trip.
async fn drain_udp_now(session: &UdpSessionInner) -> (Vec<Vec<u8>>, bool) {
    let mut packets = session.packets.lock().await;
    let drained: Vec<Vec<u8>> = packets.drain(..).collect();
    let eof = session.eof.load(Ordering::Acquire);
    (drained, eof)
}

/// UDP analogue of `wait_for_any_drainable`. Wakes when any session has
/// at least one queued packet OR has been marked eof. Same race-safety
/// contract: watchers self-filter against observable state to ignore
/// stale permits.
async fn wait_for_any_udp_drainable(inners: &[Arc<UdpSessionInner>], deadline: Duration) {
    if inners.is_empty() {
        return;
    }

    // See `AbortOnDrop` and the comment on `wait_for_any_drainable`
    // for why watchers must be aborted on every exit path.
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let mut _watchers: Vec<AbortOnDrop> = Vec::with_capacity(inners.len());
    for inner in inners {
        let inner = inner.clone();
        let tx = tx.clone();
        _watchers.push(AbortOnDrop(tokio::spawn(async move {
            loop {
                inner.notify.notified().await;
                if inner.eof.load(Ordering::Acquire) {
                    break;
                }
                if !inner.packets.lock().await.is_empty() {
                    break;
                }
                // Stale permit — packets were already drained by a
                // prior batch. Loop back, don't wake the caller.
            }
            let _ = tx.try_send(());
        })));
    }
    drop(tx);

    let already_ready = is_any_udp_drainable(inners).await;
    if !already_ready {
        tokio::select! {
            _ = rx.recv() => {}
            _ = tokio::time::sleep(deadline) => {}
        }
    }
}

async fn is_any_udp_drainable(inners: &[Arc<UdpSessionInner>]) -> bool {
    for inner in inners {
        if inner.eof.load(Ordering::Acquire) {
            return true;
        }
        if !inner.packets.lock().await.is_empty() {
            return true;
        }
    }
    false
}

/// Wait for response data with drain window. Used by single-op mode.
async fn wait_and_drain(session: &SessionInner, max_wait: Duration) -> (Vec<u8>, bool) {
    let deadline = Instant::now() + max_wait;
    let mut prev_len = 0usize;
    let mut last_growth = Instant::now();
    let mut ever_had_data = false;

    loop {
        let (cur_len, is_eof) = {
            let buf = session.read_buf.lock().await;
            (buf.len(), session.eof.load(Ordering::Acquire))
        };
        if cur_len > prev_len {
            last_growth = Instant::now();
            prev_len = cur_len;
            ever_had_data = true;
        }
        if is_eof {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        if ever_had_data && last_growth.elapsed() > Duration::from_millis(100) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut buf = session.read_buf.lock().await;
    let data = std::mem::take(&mut *buf);
    let eof = session.eof.load(Ordering::Acquire);
    (data, eof)
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
    udp_sessions: Arc<Mutex<HashMap<String, ManagedUdpSession>>>,
    /// Shared, immutable after startup. `Arc<str>` so each `state.clone()`
    /// — once per phase-1 spawn in the batch handler — is a refcount bump
    /// instead of a fresh String allocation.
    auth_key: Arc<str>,
    /// Active probing defense: when false (default, production), bad
    /// AUTH_KEY responses are a generic-looking 404 with no JSON-shaped
    /// "unauthorized" body — same as a static nginx 404. Active scanners
    /// that POST malformed payloads to `/tunnel` to discover proxy
    /// endpoints categorize this as a non-tunnel host and move on.
    /// Enable via `MHRV_DIAGNOSTIC=1` for setup/debugging — restores the
    /// previous JSON `{"e":"unauthorized"}` body so it's clear *which*
    /// of "wrong key", "wrong URL path", or "wrong tunnel-node" you've
    /// hit. (Inspired by #365 Section 3.)
    diagnostic_mode: bool,
    /// Connect-path accelerator: DNS cache + idle TCP pool + hot-host
    /// tracker. Cloned (Arc bump) by every handler that opens a
    /// session; the per-cache state is shared across all sessions on
    /// this tunnel-node so a hot endpoint discovered by one client
    /// benefits the next.
    prewarm: Arc<PrewarmState>,
}

// ---------------------------------------------------------------------------
// Protocol types — single op (backward compat)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TunnelRequest {
    k: String,
    op: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct TunnelResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    /// UDP datagrams returned to the client, base64-encoded individually.
    /// `None` for TCP responses; `Some(vec![])` is never serialized
    /// (the field is dropped when empty by the empty-on-None check above).
    #[serde(skip_serializing_if = "Option::is_none")]
    pkts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
}

impl TunnelResponse {
    fn error(msg: impl Into<String>) -> Self {
        Self {
            sid: None,
            d: None,
            pkts: None,
            eof: None,
            e: Some(msg.into()),
            code: None,
            seq: None,
        }
    }
    fn unsupported_op(op: &str) -> Self {
        Self {
            sid: None,
            d: None,
            pkts: None,
            eof: None,
            e: Some(format!("unknown op: {}", op)),
            code: Some(CODE_UNSUPPORTED_OP.into()),
            seq: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol types — batch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BatchRequest {
    k: String,
    #[serde(default)]
    ops: Vec<BatchOp>,
    #[serde(default)]
    zops: Option<String>,
    #[serde(default)]
    zc: Option<u8>,
}

#[derive(Deserialize)]
struct BatchOp {
    op: String,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    d: Option<String>, // base64 data
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    wseq: Option<u64>,
}

#[derive(Serialize)]
struct BatchResponse {
    r: Vec<TunnelResponse>,
}

// ---------------------------------------------------------------------------
// Single-op handler (backward compat)
// ---------------------------------------------------------------------------

async fn handle_tunnel(
    State(state): State<AppState>,
    Json(req): Json<TunnelRequest>,
) -> axum::response::Response {
    if req.k != *state.auth_key {
        return decoy_or_unauthorized(state.diagnostic_mode);
    }
    let resp: TunnelResponse = match req.op.as_str() {
        "connect" => handle_connect(&state, req.host, req.port).await,
        "connect_data" => handle_connect_data_single(&state, req.host, req.port, req.data).await,
        "data" => handle_data_single(&state, req.sid, req.data).await,
        "close" => handle_close(&state, req.sid).await,
        other => TunnelResponse::unsupported_op(other),
    };
    Json(resp).into_response()
}

/// Active-probing defense for the bad-auth path. Production default is
/// a 404 with a generic "Not Found" HTML body that mimics a vanilla
/// nginx/apache static error page — active scanners categorize this
/// as a regular web server with nothing interesting and move on.
/// `MHRV_DIAGNOSTIC=1` restores the previous JSON `{"e":"unauthorized"}`
/// body so misconfigured clients get a clear error during setup.
fn decoy_or_unauthorized(diagnostic_mode: bool) -> axum::response::Response {
    if diagnostic_mode {
        return Json(TunnelResponse::error("unauthorized")).into_response();
    }
    let body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n\
                <body>\r\n<center><h1>404 Not Found</h1></center>\r\n\
                <hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html")],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Batch handler
// ---------------------------------------------------------------------------

async fn handle_batch(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    // Decompress if gzipped
    let json_bytes = if body.starts_with(&[0x1f, 0x8b]) {
        match decompress_gzip(&body) {
            Ok(b) => b,
            Err(e) => {
                let resp = serde_json::to_vec(&BatchResponse {
                    r: vec![TunnelResponse::error(format!("gzip decode: {}", e))],
                })
                .unwrap_or_default();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    resp,
                );
            }
        }
    } else {
        body.to_vec()
    };

    let req: BatchRequest = match serde_json::from_slice(&json_bytes) {
        Ok(r) => r,
        Err(e) => {
            let resp = serde_json::to_vec(&BatchResponse {
                r: vec![TunnelResponse::error(format!("bad json: {}", e))],
            })
            .unwrap_or_default();
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                resp,
            );
        }
    };

    if req.k != *state.auth_key {
        if state.diagnostic_mode {
            let resp = serde_json::to_vec(&BatchResponse {
                r: vec![TunnelResponse::error("unauthorized")],
            })
            .unwrap_or_default();
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                resp,
            );
        }
        // Production: same nginx-404 decoy as the single-op path. See
        // `decoy_or_unauthorized` for rationale.
        let body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n\
                    <body>\r\n<center><h1>404 Not Found</h1></center>\r\n\
                    <hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
            .as_bytes()
            .to_vec();
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html")],
            body,
        );
    }

    let had_zops = req.zops.is_some();
    let client_zstd = had_zops || req.zc.is_some();
    tracing::info!(
        "batch: had_zops={} zc={:?} client_zstd={} ops_len={}",
        had_zops,
        req.zc,
        client_zstd,
        req.ops.len()
    );
    let ops: Vec<BatchOp> = if let Some(zops_b64) = req.zops {
        tracing::debug!("zops received: encoded_len={}", zops_b64.len());
        match B64.decode(&zops_b64) {
            Ok(compressed) => match zstd::decode_all(compressed.as_slice()) {
                Ok(decompressed) => {
                    tracing::debug!("zops decompressed: {} bytes", decompressed.len());
                    match serde_json::from_slice(&decompressed) {
                        Ok(v) => v,
                        Err(e) => {
                            let resp = serde_json::to_vec(&BatchResponse {
                                r: vec![TunnelResponse::error(format!("zops json: {}", e))],
                            })
                            .unwrap_or_default();
                            return (
                                StatusCode::OK,
                                [(header::CONTENT_TYPE, "application/json")],
                                resp,
                            );
                        }
                    }
                }
                Err(e) => {
                    let resp = serde_json::to_vec(&BatchResponse {
                        r: vec![TunnelResponse::error(format!("zstd decode: {}", e))],
                    })
                    .unwrap_or_default();
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        resp,
                    );
                }
            },
            Err(e) => {
                let resp = serde_json::to_vec(&BatchResponse {
                    r: vec![TunnelResponse::error(format!("zops b64: {}", e))],
                })
                .unwrap_or_default();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    resp,
                );
            }
        }
    } else {
        req.ops
    };

    // Process all ops in two phases.
    //
    // Phase 1: dispatch new connections concurrently and write outbound
    // bytes for "data" ops. We track whether any op did real work
    // (`had_writes_or_connects`) — this drives the deadline picked in
    // phase 2.
    //
    // `connect` and `connect_data` each establish a brand-new upstream TCP
    // connection (up to 10 s timeout in `create_session`). Running them
    // inline would head-of-line-block every other op in the batch, so we
    // dispatch both into a JoinSet and await them concurrently below.
    //
    // `connect_data` dominates in practice (new clients), but `connect`
    // still fires from server-speaks-first ports and from the preread
    // timeout fallback path.
    let mut results: Vec<(usize, TunnelResponse)> = Vec::with_capacity(ops.len());
    // Each drain entry carries the session's `Arc<…Inner>` alongside the
    // sid. Phase 2 drains through the Arc directly so the global sessions
    // map lock isn't held across the per-session read_buf / packets
    // mutex acquisition — without this, every other batch (and every
    // connect/close op) head-of-line-blocks behind the drain.
    let mut tcp_drains: Vec<(usize, String, Arc<SessionInner>, Option<u64>)> = Vec::new();
    let mut udp_drains: Vec<(usize, String, Arc<UdpSessionInner>, Option<u64>)> = Vec::new();
    // True iff the batch contained any op that performed a real action
    // upstream — a new connection or a non-empty data write. A batch of
    // only empty "data" / "udp_data" polls (and possibly closes) leaves
    // this false and qualifies for long-poll behavior in phase 2.
    let mut had_writes_or_connects = false;

    enum NewConn {
        Connect(TunnelResponse),
        ConnectData(Result<(String, Arc<SessionInner>), TunnelResponse>),
        UdpOpen(Result<(String, Arc<UdpSessionInner>), TunnelResponse>),
    }
    let mut new_conn_jobs: JoinSet<(usize, NewConn)> = JoinSet::new();

    for (i, op) in ops.iter().enumerate() {
        match op.op.as_str() {
            "connect" => {
                had_writes_or_connects = true;
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                new_conn_jobs.spawn(async move {
                    (
                        i,
                        NewConn::Connect(handle_connect(&state, host, port).await),
                    )
                });
            }
            "connect_data" => {
                had_writes_or_connects = true;
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                let d = op.d.clone();
                new_conn_jobs.spawn(async move {
                    // Keep the returned Arc<SessionInner>: phase 2 drains
                    // through it directly, so the global sessions map
                    // lock doesn't have to be held across the per-session
                    // read_buf.lock().await.
                    let r = handle_connect_data_phase1(&state, host, port, d).await;
                    (i, NewConn::ConnectData(r))
                });
            }
            "udp_open" => {
                // An open *with* an initial datagram is real upstream
                // work; an open without one (rare — current proxy
                // never invokes it that way) is just resource alloc
                // and shouldn't suppress long-poll on sibling polls.
                if op.d.as_deref().map(|d| !d.is_empty()).unwrap_or(false) {
                    had_writes_or_connects = true;
                }
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                let d = op.d.clone();
                new_conn_jobs.spawn(async move {
                    let r = handle_udp_open_phase1(&state, host, port, d).await;
                    (i, NewConn::UdpOpen(r))
                });
            }
            "data" => {
                let sid = match &op.sid {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => {
                        results.push((i, TunnelResponse::error("missing sid")));
                        continue;
                    }
                };

                // Clone the inner under the map lock and release it
                // before any await. The previous shape held the global
                // sessions map across last_active.lock(), writer.lock(),
                // write_all, and flush — head-of-line-blocking every
                // other batch and connect/close op for the duration of
                // a single upstream write. The udp_data branch below
                // already does the right thing; this matches it.
                let inner = {
                    let sessions = state.sessions.lock().await;
                    sessions.get(&sid).map(|s| s.inner.clone())
                };
                if let Some(inner) = inner {
                    *inner.last_active.lock().await = Instant::now();
                    if let Some(ref data_b64) = op.d {
                        if !data_b64.is_empty() {
                            // Decode first; only count this op as a real
                            // write (and demote the batch out of long-poll)
                            // after a successful non-empty decode. Mirrors
                            // the udp_data branch and avoids silently
                            // dropping bytes on bad base64.
                            let bytes = match B64.decode(data_b64) {
                                Ok(b) => b,
                                Err(e) => {
                                    results.push((
                                        i,
                                        TunnelResponse::error(format!("bad base64: {}", e)),
                                    ));
                                    continue;
                                }
                            };
                            if !bytes.is_empty() {
                                had_writes_or_connects = true;
                                tracing::debug!(
                                    "session {} upload {}B wseq={:?}",
                                    &sid[..sid.len().min(8)],
                                    bytes.len(),
                                    op.wseq,
                                );
                                match op.wseq {
                                    None => {
                                        // Old client (no wseq): write immediately.
                                        let mut w = inner.writer.lock().await;
                                        let _ = w.write_all(&bytes).await;
                                        let _ = w.flush().await;
                                    }
                                    Some(wseq) => {
                                        let mut nws = inner.next_write_seq.lock().await;
                                        // Sessions start at wseq=0 on the client (see
                                        // `next_data_write_seq` in tunnel_client.rs).
                                        // Seed `expected` to 0 so a pipelined wseq=1
                                        // arriving before wseq=0 buffers correctly
                                        // instead of dropping wseq=0 as "stale".
                                        let expected = nws.get_or_insert(0);

                                        if wseq < *expected {
                                            // Stale / duplicate — skip.
                                            tracing::debug!(
                                                "session {} wseq {} < expected {} — skipping",
                                                &sid[..sid.len().min(8)],
                                                wseq,
                                                *expected,
                                            );
                                        } else if wseq == *expected {
                                            // In order — write immediately.
                                            let mut w = inner.writer.lock().await;
                                            let _ = w.write_all(&bytes).await;
                                            *expected += 1;

                                            // Flush any buffered writes that
                                            // are now in sequence.
                                            let mut pw = inner.pending_writes.lock().await;
                                            while let Some(entry) = pw.first_entry() {
                                                if *entry.key() != *expected {
                                                    break;
                                                }
                                                let (_, buffered) = entry.remove_entry();
                                                let _ = w.write_all(&buffered).await;
                                                *expected += 1;
                                            }
                                            let _ = w.flush().await;
                                        } else {
                                            // Out of order — buffer for later,
                                            // but cap so an authenticated caller
                                            // can't consume unbounded server
                                            // memory by jumping wseq.
                                            let mut pw = inner.pending_writes.lock().await;
                                            let pending_bytes: usize =
                                                pw.values().map(|v| v.len()).sum();
                                            let short = &sid[..sid.len().min(8)];
                                            if pw.len() >= MAX_PENDING_WRITES_PER_SESSION
                                                || pending_bytes + bytes.len()
                                                    > MAX_PENDING_WRITE_BYTES_PER_SESSION
                                            {
                                                tracing::warn!(
                                                    "session {} closing: wseq buffer cap \
                                                     reached ({} entries / {} pending bytes, \
                                                     incoming wseq {} +{}B)",
                                                    short,
                                                    pw.len(),
                                                    pending_bytes,
                                                    wseq,
                                                    bytes.len(),
                                                );
                                                drop(pw);
                                                results.push((
                                                    i,
                                                    TunnelResponse::error(
                                                        "wseq buffer cap exceeded",
                                                    ),
                                                ));
                                                // Close server-side so the
                                                // reader_task is aborted and the
                                                // map slot is freed immediately.
                                                if let Some(s) =
                                                    state.sessions.lock().await.remove(&sid)
                                                {
                                                    s.reader_handle.abort();
                                                }
                                                continue;
                                            }
                                            tracing::debug!(
                                                "session {} wseq {} > expected {} — buffering",
                                                short,
                                                wseq,
                                                *expected,
                                            );
                                            pw.insert(wseq, bytes);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    tcp_drains.push((i, sid, inner, op.seq));
                } else {
                    results.push((i, eof_response(sid, op.seq)));
                }
            }
            "udp_data" => {
                let sid = match &op.sid {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => {
                        results.push((i, TunnelResponse::error("missing sid")));
                        continue;
                    }
                };

                let inner = {
                    let sessions = state.udp_sessions.lock().await;
                    sessions.get(&sid).map(|s| s.inner.clone())
                };
                if let Some(inner) = inner {
                    let mut had_uplink = false;
                    if let Some(ref data_b64) = op.d {
                        if !data_b64.is_empty() {
                            let bytes = match B64.decode(data_b64) {
                                Ok(b) => b,
                                Err(e) => {
                                    results.push((
                                        i,
                                        TunnelResponse::error(format!("bad base64: {}", e)),
                                    ));
                                    continue;
                                }
                            };
                            if !bytes.is_empty() {
                                had_writes_or_connects = true;
                                had_uplink = true;
                                let _ = inner.socket.send(&bytes).await;
                            }
                        }
                    }
                    // last_active is bumped only on real activity:
                    // outbound here, or inbound in udp_reader_task.
                    // Empty long-poll batches must not refresh it, else
                    // the idle reaper never fires.
                    if had_uplink {
                        *inner.last_active.lock().await = Instant::now();
                    }
                    udp_drains.push((i, sid, inner, op.seq));
                } else {
                    results.push((i, eof_response(sid, op.seq)));
                }
            }
            "close" => {
                let r = handle_close(&state, op.sid.clone()).await;
                results.push((i, r));
            }
            other => {
                results.push((i, TunnelResponse::unsupported_op(other)));
            }
        }
    }

    // Await all concurrent connect / connect_data / udp_open jobs.
    // Successful drain-bearing ones join the appropriate drain list;
    // plain connects go straight to results.
    while let Some(join) = new_conn_jobs.join_next().await {
        match join {
            Ok((i, NewConn::Connect(r))) => results.push((i, r)),
            Ok((i, NewConn::ConnectData(Ok((sid, inner))))) => {
                tcp_drains.push((i, sid, inner, None));
            }
            Ok((i, NewConn::ConnectData(Err(r)))) => results.push((i, r)),
            Ok((i, NewConn::UdpOpen(Ok((sid, inner))))) => {
                udp_drains.push((i, sid, inner, None));
            }
            Ok((i, NewConn::UdpOpen(Err(r)))) => results.push((i, r)),
            Err(e) => {
                tracing::error!("new-connection task panicked: {}", e);
            }
        }
    }

    // Phase 2: signal-driven wait for any session (TCP or UDP) to have
    // data, then drain TCP and UDP independently in a single pass each.
    // Deadlines:
    //   * `ACTIVE_DRAIN_DEADLINE` (~350 ms) when the batch had real work.
    //     Typical responses arrive in ms; the wait helpers return on
    //     the first notify. For active batches we settle for
    //     `STRAGGLER_SETTLE` so neighbors whose replies trail by a few
    //     ms aren't reported empty.
    //   * `LONGPOLL_DEADLINE` for pure-poll batches — held open until
    //     upstream pushes data. UDP idle polls benefit from this just
    //     as much as TCP, so the same window applies.
    if !tcp_drains.is_empty() || !udp_drains.is_empty() {
        let deadline = if had_writes_or_connects {
            ACTIVE_DRAIN_DEADLINE
        } else {
            LONGPOLL_DEADLINE
        };

        // Phase 1 already gave us each session's Arc<…Inner>, so we
        // don't need to re-acquire the sessions map lock here. Cloning
        // the Arc is just a refcount bump.
        let tcp_inners: Vec<Arc<SessionInner>> = tcp_drains
            .iter()
            .map(|(_, _, inner, _)| inner.clone())
            .collect();
        let udp_inners: Vec<Arc<UdpSessionInner>> = udp_drains
            .iter()
            .map(|(_, _, inner, _)| inner.clone())
            .collect();

        // Wake on whichever side has work first. The previous
        // `tokio::join!` was conjunctive — a TCP burst still paid the
        // UDP deadline in mixed batches because the UDP waiter had to
        // elapse too. `wait_for_*_drainable` short-circuits on an empty
        // slice, so we have to skip the empty side; otherwise its
        // instant return would fire the select arm before the other
        // side ever got a chance to wait.
        match (tcp_inners.is_empty(), udp_inners.is_empty()) {
            (true, true) => {}
            (false, true) => wait_for_any_drainable(&tcp_inners, deadline).await,
            (true, false) => wait_for_any_udp_drainable(&udp_inners, deadline).await,
            (false, false) => {
                tokio::select! {
                    _ = wait_for_any_drainable(&tcp_inners, deadline) => {}
                    _ = wait_for_any_udp_drainable(&udp_inners, deadline) => {}
                }
            }
        }

        if had_writes_or_connects {
            // Adaptive settle: keep waiting in steps while new data
            // keeps arriving. Break when:
            //  1. No new data arrived in the last step (burst is over)
            //  2. STRAGGLER_SETTLE_MAX reached
            let settle_end = Instant::now() + STRAGGLER_SETTLE_MAX;
            let mut prev_tcp_bytes: usize = 0;
            let mut prev_udp_pkts: usize = 0;
            // Snapshot current buffer sizes.
            for inner in &tcp_inners {
                prev_tcp_bytes += inner.read_buf.lock().await.len();
            }
            for inner in &udp_inners {
                prev_udp_pkts += inner.packets.lock().await.len();
            }
            loop {
                let now = Instant::now();
                if now >= settle_end {
                    break;
                }
                let remaining = settle_end.duration_since(now);
                tokio::time::sleep(STRAGGLER_SETTLE_STEP.min(remaining)).await;

                // Measure current buffer sizes.
                let mut tcp_bytes: usize = 0;
                let mut udp_pkts: usize = 0;
                for inner in &tcp_inners {
                    tcp_bytes += inner.read_buf.lock().await.len();
                }
                for inner in &udp_inners {
                    udp_pkts += inner.packets.lock().await.len();
                }

                // No new data since last step — burst is over.
                if tcp_bytes == prev_tcp_bytes && udp_pkts == prev_udp_pkts {
                    break;
                }

                prev_tcp_bytes = tcp_bytes;
                prev_udp_pkts = udp_pkts;
            }
        }

        // ---- TCP drain ----
        // Drain through each session's already-cloned Arc so the global
        // sessions map lock isn't held across the per-session
        // read_buf.lock().await.
        //
        // Cleanup is driven off `drain_now`'s returned `eof`, NOT the
        // raw `inner.eof` atomic. When the buffer exceeds
        // `TCP_DRAIN_MAX_BYTES`, `drain_now` deliberately returns
        // `eof = false` and leaves the tail in the buffer so the
        // client can pick it up on the next poll. The previous cleanup
        // read the atomic directly, so on a high-throughput session
        // that closed mid-burst (issue #460-style) it would remove the
        // session and abort the reader_task with the tail still
        // buffered, dropping those bytes.
        let mut tcp_eof_sids: Vec<String> = Vec::new();
        // Track remaining batch-response budget across all session drains
        // (#863). Per-session `TCP_DRAIN_MAX_BYTES` alone wasn't enough —
        // several concurrent sessions each contributing 16 MiB summed past
        // Apps Script's 50 MiB response ceiling. This cap stops one session
        // short of the cliff; deferred sessions drain on the next poll.
        let mut remaining_budget: usize = BATCH_RESPONSE_BUDGET;
        // Batch-wide drain deadline. The previous shape gave each session a
        // fresh 1 s window — N sessions in a single batch could each spin
        // for a full second, blowing through Apps Script's batch budget and
        // letting the whole response time out client-side. With a single
        // shared deadline, the per-session loop never extends total drain
        // time past 1 s no matter how many sessions are in the batch; any
        // session whose tail wasn't drained still has its data intact in
        // `read_buf` and picks up on the next poll.
        let tcp_drain_deadline = Instant::now() + Duration::from_secs(1);
        for (i, sid, inner, seq) in &tcp_drains {
            // Budget exhausted by an earlier session: emit an empty drain
            // response so the client's positional index into `batch_resp.r`
            // still lines up with this op's `i`. The session's buffered
            // data is left intact and picked up on the next poll.
            if remaining_budget == 0 {
                results.push((*i, tcp_drain_response(sid.clone(), Vec::new(), false, *seq)));
                continue;
            }
            // Drain in a loop: keep reading until the buffer is empty
            // so we catch data that arrives during the drain itself.
            // Honors the BATCH-WIDE deadline so total drain time is
            // bounded regardless of how many sessions are in the batch.
            let mut all_data = Vec::new();
            let mut final_eof = false;
            loop {
                let (data, eof) =
                    drain_now(inner, remaining_budget.saturating_sub(all_data.len())).await;
                if eof {
                    final_eof = true;
                }
                if data.is_empty() {
                    break;
                }
                let hit_session_cap = data.len() >= TCP_DRAIN_MAX_BYTES;
                all_data.extend_from_slice(&data);
                if final_eof || hit_session_cap || all_data.len() >= remaining_budget {
                    break;
                }
                if Instant::now() >= tcp_drain_deadline {
                    break;
                }
                // Brief yield to let reader_task finish its current read
                tokio::task::yield_now().await;
            }
            let drained = all_data.len();
            if drained > 0 {
                tracing::debug!(
                    "session {} drained {}KB",
                    &sid[..sid.len().min(8)],
                    drained / 1024
                );
            }
            if final_eof {
                tcp_eof_sids.push(sid.clone());
            }
            results.push((
                *i,
                tcp_drain_response(sid.clone(), all_data, final_eof, *seq),
            ));
            remaining_budget = remaining_budget.saturating_sub(drained);
        }
        if !tcp_eof_sids.is_empty() {
            let mut sessions = state.sessions.lock().await;
            for sid in &tcp_eof_sids {
                if let Some(s) = sessions.remove(sid) {
                    s.reader_handle.abort();
                    tracing::info!("session {} closed by remote (batch)", sid);
                }
            }
        }

        // ---- UDP drain ----
        // Same shape as TCP. `drain_udp_now` currently drains the full
        // queue with no per-batch cap, so its returned `eof` already
        // matches the atomic — driving cleanup off the drain return
        // is future-proofing: if a UDP per-batch packet cap is ever
        // added (mirroring `TCP_DRAIN_MAX_BYTES`), the same data-loss
        // trap that motivated the TCP-side fix reappears, and tracking
        // eof from the drain return rather than the atomic catches it.
        let mut udp_eof_sids: Vec<String> = Vec::new();
        for (i, sid, inner, seq) in &udp_drains {
            let (packets, eof) = drain_udp_now(inner).await;
            if eof {
                udp_eof_sids.push(sid.clone());
            }
            results.push((*i, udp_drain_response(sid.clone(), packets, eof, *seq)));
        }
        if !udp_eof_sids.is_empty() {
            let mut sessions = state.udp_sessions.lock().await;
            for sid in &udp_eof_sids {
                if let Some(s) = sessions.remove(sid) {
                    s.reader_handle.abort();
                    tracing::info!("udp session {} closed by remote (batch)", sid);
                }
            }
        }
    }

    // Sort results by original index and build response
    results.sort_by_key(|(i, _)| *i);
    let r_vec: Vec<TunnelResponse> = results.into_iter().map(|(_, r)| r).collect();

    tracing::info!(
        "batch response: r_count={} client_zstd={}",
        r_vec.len(),
        client_zstd
    );
    let json = if client_zstd {
        let r_json = serde_json::to_vec(&r_vec).unwrap_or_default();
        match zstd::encode_all(r_json.as_slice(), 3) {
            Ok(compressed) => {
                let zr_b64 = B64.encode(&compressed);
                tracing::info!(
                    "batch response: sending zr ({} bytes compressed)",
                    compressed.len()
                );
                serde_json::to_vec(&serde_json::json!({"zr": zr_b64, "zc": 1})).unwrap_or_default()
            }
            Err(_) => serde_json::to_vec(&BatchResponse { r: r_vec }).unwrap_or_default(),
        }
    } else {
        serde_json::to_vec(&BatchResponse { r: r_vec }).unwrap_or_default()
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
}

fn tcp_drain_response(sid: String, data: Vec<u8>, eof: bool, seq: Option<u64>) -> TunnelResponse {
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() {
            None
        } else {
            Some(B64.encode(&data))
        },
        pkts: None,
        eof: Some(eof),
        e: None,
        code: None,
        seq,
    }
}

fn udp_drain_response(
    sid: String,
    packets: Vec<Vec<u8>>,
    eof: bool,
    seq: Option<u64>,
) -> TunnelResponse {
    let pkts = if packets.is_empty() {
        None
    } else {
        Some(packets.iter().map(|p| B64.encode(p)).collect())
    };
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts,
        eof: Some(eof),
        e: None,
        code: None,
        seq,
    }
}

fn eof_response(sid: String, seq: Option<u64>) -> TunnelResponse {
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts: None,
        eof: Some(true),
        e: None,
        code: None,
        seq,
    }
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shared op handlers
// ---------------------------------------------------------------------------

fn validate_host_port(
    host: Option<String>,
    port: Option<u16>,
) -> Result<(String, u16), TunnelResponse> {
    let host = match host {
        Some(h) if !h.is_empty() => h,
        _ => return Err(TunnelResponse::error("missing host")),
    };
    let port = match port {
        Some(p) if p > 0 => p,
        _ => return Err(TunnelResponse::error("missing or invalid port")),
    };
    Ok((host, port))
}

async fn handle_connect(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
) -> TunnelResponse {
    let (host, port) = match validate_host_port(host, port) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let session = if udpgw::is_udpgw_dest(&host, port) {
        create_udpgw_session()
    } else {
        match create_session(&host, port, &state.prewarm).await {
            Ok(s) => s,
            Err(e) => return TunnelResponse::error(format!("connect failed: {}", e)),
        }
    };
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{}", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts: None,
        eof: Some(false),
        e: None,
        code: None,
        seq: None,
    }
}

/// Open a session and write the client's first bytes in one round trip.
/// Returns the new sid plus an `Arc<SessionInner>`. Both callers keep
/// the Arc: the unary path (`handle_connect_data_single`) uses it to
/// drain the first response without a second sessions-map lookup, and
/// the batch path threads it into `tcp_drains` so phase-2 drain runs
/// without holding the global sessions map lock across the per-session
/// `read_buf.lock().await`.
async fn handle_connect_data_phase1(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> Result<(String, Arc<SessionInner>), TunnelResponse> {
    let (host, port) = validate_host_port(host, port)?;

    let session = if udpgw::is_udpgw_dest(&host, port) {
        create_udpgw_session()
    } else {
        create_session(&host, port, &state.prewarm)
            .await
            .map_err(|e| TunnelResponse::error(format!("connect failed: {}", e)))?
    };

    // Any failure below this point must abort the reader task, otherwise
    // the newly-opened upstream TCP connection would leak. Keep the
    // abort paths explicit rather than burying them in `.map_err`.
    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            let bytes = match B64.decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("bad base64: {}", e)));
                }
            };
            if !bytes.is_empty() {
                let mut w = session.inner.writer.lock().await;
                if let Err(e) = w.write_all(&bytes).await {
                    drop(w);
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("write failed: {}", e)));
                }
                let _ = w.flush().await;
            }
        }
    }

    let inner = session.inner.clone();
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{} (connect_data)", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    Ok((sid, inner))
}

/// UDP analogue of `handle_connect_data_phase1`. Opens a connected UDP
/// socket to `(host, port)` and optionally sends the client's first
/// datagram in the same op so a request-response flow (e.g. DNS, STUN)
/// saves a round trip on session establishment.
async fn handle_udp_open_phase1(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> Result<(String, Arc<UdpSessionInner>), TunnelResponse> {
    let (host, port) = validate_host_port(host, port)?;

    let session = create_udp_session(&host, port, &state.prewarm.dns)
        .await
        .map_err(|e| TunnelResponse::error(format!("udp connect failed: {}", e)))?;

    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            let bytes = match B64.decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("bad base64: {}", e)));
                }
            };
            if !bytes.is_empty() {
                if let Err(e) = session.inner.socket.send(&bytes).await {
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("udp write failed: {}", e)));
                }
            }
        }
    }

    let inner = session.inner.clone();
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("udp session {} -> {}:{}", sid, host, port);
    state.udp_sessions.lock().await.insert(sid.clone(), session);
    Ok((sid, inner))
}

async fn handle_connect_data_single(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> TunnelResponse {
    let (sid, inner) = match handle_connect_data_phase1(state, host, port, data).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (data, eof) = wait_and_drain(&inner, Duration::from_secs(5)).await;
    if eof {
        if let Some(s) = state.sessions.lock().await.remove(&sid) {
            s.reader_handle.abort();
            tracing::info!("session {} closed by remote", sid);
        }
    }
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() {
            None
        } else {
            Some(B64.encode(&data))
        },
        pkts: None,
        eof: Some(eof),
        e: None,
        code: None,
        seq: None,
    }
}

async fn handle_data_single(
    state: &AppState,
    sid: Option<String>,
    data: Option<String>,
) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    // Clone the inner Arc under the global sessions map lock and release
    // the map lock before any await. The previous shape held the map
    // across last_active.lock(), writer.lock(), write_all, flush, AND
    // wait_and_drain — up to 5 s of head-of-line blocking on every other
    // single-op or batch request. Mirrors the batch-handler "data" path.
    let inner = {
        let sessions = state.sessions.lock().await;
        sessions.get(&sid).map(|s| s.inner.clone())
    };
    let inner = match inner {
        Some(i) => i,
        None => return TunnelResponse::error("unknown session"),
    };
    *inner.last_active.lock().await = Instant::now();
    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            if let Ok(bytes) = B64.decode(data_b64) {
                if !bytes.is_empty() {
                    let mut w = inner.writer.lock().await;
                    if let Err(e) = w.write_all(&bytes).await {
                        drop(w);
                        state.sessions.lock().await.remove(&sid);
                        return TunnelResponse::error(format!("write failed: {}", e));
                    }
                    let _ = w.flush().await;
                }
            }
        }
    }
    let (data, eof) = wait_and_drain(&inner, Duration::from_secs(5)).await;
    if eof {
        if let Some(s) = state.sessions.lock().await.remove(&sid) {
            s.reader_handle.abort();
            tracing::info!("session {} closed by remote", sid);
        }
    }
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() {
            None
        } else {
            Some(B64.encode(&data))
        },
        pkts: None,
        eof: Some(eof),
        e: None,
        code: None,
        seq: None,
    }
}

async fn handle_close(state: &AppState, sid: Option<String>) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    if let Some(s) = state.sessions.lock().await.remove(&sid) {
        s.abort_all();
        tracing::info!("session {} closed by client", sid);
    }
    if let Some(s) = state.udp_sessions.lock().await.remove(&sid) {
        s.reader_handle.abort();
        tracing::info!("udp session {} closed by client", sid);
    }
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts: None,
        eof: Some(true),
        e: None,
        code: None,
        seq: None,
    }
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

async fn cleanup_task(
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
    udp_sessions: Arc<Mutex<HashMap<String, ManagedUdpSession>>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let now = Instant::now();

        {
            let mut map = sessions.lock().await;
            let mut stale = Vec::new();
            for (k, s) in map.iter() {
                let last = *s.inner.last_active.lock().await;
                if now.duration_since(last) > Duration::from_secs(300) {
                    stale.push(k.clone());
                }
            }
            for k in &stale {
                if let Some(s) = map.remove(k) {
                    s.reader_handle.abort();
                    tracing::info!("reaped idle session {}", k);
                }
            }
            if !stale.is_empty() {
                tracing::info!("cleanup: reaped {}, {} active", stale.len(), map.len());
            }
        }

        {
            // UDP sessions get a tighter idle window because UDP flows
            // are typically short-lived (DNS, STUN, single-RTT QUIC) or
            // make their own keepalives. 120 s avoids leaking sockets
            // for one-shot lookups while keeping calls/streams alive.
            let mut map = udp_sessions.lock().await;
            let mut stale = Vec::new();
            for (k, s) in map.iter() {
                let last = *s.inner.last_active.lock().await;
                if now.duration_since(last) > Duration::from_secs(120) {
                    stale.push(k.clone());
                }
            }
            for k in &stale {
                if let Some(s) = map.remove(k) {
                    s.reader_handle.abort();
                    tracing::info!("reaped idle udp session {}", k);
                }
            }
            if !stale.is_empty() {
                tracing::info!("cleanup: reaped {}, {} active udp", stale.len(), map.len());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let auth_key = std::env::var("TUNNEL_AUTH_KEY").unwrap_or_else(|_| {
        // Catch the recurring `MHRV_AUTH_KEY` typo (#391, #444). Several old
        // copy-paste guides used `MHRV_AUTH_KEY` for the docker run; tunnel-node
        // never read that name and silently fell through to `changeme`,
        // producing baffling AUTH_KEY-mismatch decoys on the client. If
        // `MHRV_AUTH_KEY` is set, point at it specifically so the user sees
        // why their value isn't taking effect.
        if std::env::var("MHRV_AUTH_KEY").is_ok() {
            tracing::warn!(
                "MHRV_AUTH_KEY is set but TUNNEL_AUTH_KEY is not — \
                 tunnel-node only reads TUNNEL_AUTH_KEY (uppercase, with \
                 underscores). Rename your env var: \
                 `docker run ... -e TUNNEL_AUTH_KEY=<your-secret>`. Falling \
                 back to default `changeme` for now (INSECURE — clients will \
                 fail with AUTH_KEY mismatch decoys until this is fixed)."
            );
        } else {
            tracing::warn!("TUNNEL_AUTH_KEY not set — using default (INSECURE)");
        }
        "changeme".into()
    });
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let sessions: Arc<Mutex<HashMap<String, ManagedSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let udp_sessions: Arc<Mutex<HashMap<String, ManagedUdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(cleanup_task(sessions.clone(), udp_sessions.clone()));

    // MHRV_DIAGNOSTIC=1 in env restores verbose JSON error responses on
    // bad auth (instead of the nginx-404 decoy). Use during setup so
    // misconfigured clients see "unauthorized"; flip back off in prod.
    let diagnostic_mode = std::env::var("MHRV_DIAGNOSTIC")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if diagnostic_mode {
        tracing::warn!(
            "MHRV_DIAGNOSTIC=1 — bad-auth responses are verbose JSON \
             errors instead of the production nginx-404 decoy. Disable \
             before exposing this tunnel-node to the public internet."
        );
    }
    let state = AppState {
        sessions,
        udp_sessions,
        auth_key: Arc::from(auth_key),
        diagnostic_mode,
        prewarm: PrewarmState::new(),
    };

    let app = Router::new()
        .route("/tunnel", post(handle_tunnel))
        .route("/tunnel/batch", post(handle_batch))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("tunnel-node listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutting down");
        })
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn fresh_state() -> AppState {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            auth_key: "test-key".into(),
            // Tests assert against the JSON `unauthorized` body shape
            // (see e.g. `bad_auth_returns_unauthorized`), so they need
            // diagnostic_mode enabled. Production default is false.
            diagnostic_mode: true,
            prewarm: PrewarmState::new(),
        }
    }

    #[tokio::test]
    async fn dns_cache_returns_same_addrs_on_repeated_resolve() {
        // Two back-to-back resolves of the same key must return the
        // same Vec, sourced from the cache on the second call.
        // Localhost resolves reliably without external DNS so we
        // can do the round-trip in-test.
        let cache = DnsCache::new();
        let first = cache.resolve("localhost", 7777).await.unwrap();
        assert!(
            !first.is_empty(),
            "localhost must resolve to at least one address"
        );
        let second = cache.resolve("localhost", 7777).await.unwrap();
        assert_eq!(
            first, second,
            "second resolve must return the cached addrs unchanged"
        );
        let entries = cache.entries.lock().await;
        let entry = entries
            .get(&("localhost".to_string(), 7777))
            .expect("entry must be cached");
        assert_eq!(entry.addrs, first, "cached addrs must match returned addrs");
        assert!(
            entry.expires_at > Instant::now(),
            "fresh entry must have expires_at in the future"
        );
    }

    #[tokio::test]
    async fn dns_cache_evict_drops_entry() {
        // Eviction is the recovery hook `connect_fresh` calls when
        // every resolved address fails — proves the operation in
        // isolation so the wired integration below isn't testing
        // two things at once.
        let cache = DnsCache::new();
        cache.resolve("localhost", 7778).await.unwrap();
        assert!(cache
            .entries
            .lock()
            .await
            .contains_key(&("localhost".to_string(), 7778)));
        cache.evict("localhost", 7778).await;
        assert!(!cache
            .entries
            .lock()
            .await
            .contains_key(&("localhost".to_string(), 7778)));
    }

    #[tokio::test]
    async fn connect_fresh_evicts_dns_on_timeout() {
        // The timeout-Err arm of `connect_fresh` must flow through the
        // same eviction path as a resolved-Err — otherwise a stale
        // cached address that blackholes (silent drop, not refused)
        // would keep poisoning sessions for the full DNS_CACHE_TTL.
        // We drive this deterministically by going through
        // `connect_fresh_with_timeout` with a tiny budget and a DNS
        // entry pointing at TEST-NET-1 (RFC 5737, never routes), so
        // the inner connect never returns and the budget always
        // fires.
        let state = PrewarmState::new();
        let blackhole = SocketAddr::from(([192, 0, 2, 1], 81));
        {
            let mut entries = state.dns.entries.lock().await;
            entries.insert(
                ("blackhole.example".into(), 443),
                DnsEntry {
                    addrs: vec![blackhole],
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let err = state
            .connect_fresh_with_timeout("blackhole.example", 443, Duration::from_millis(100))
            .await
            .expect_err("tight budget against TEST-NET-1 must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            !state
                .dns
                .entries
                .lock()
                .await
                .contains_key(&("blackhole.example".to_string(), 443)),
            "timeout must evict the cached DNS entry, not skip the eviction path",
        );
    }

    #[tokio::test]
    async fn hot_hosts_caps_samples_per_key() {
        // Same hot key recorded many times within the window must
        // not let its sample queue grow without bound. Cap is
        // `HOT_HOST_MIN_COUNT` — the hot decision needs no more
        // information than that, and a quiet host that never gets
        // re-recorded would otherwise carry whatever it accumulated
        // until the full-map prune fires.
        let hot = HotHosts::new();
        for _ in 0..100 {
            hot.record_and_check("very-hot", 443).await;
        }
        let inner = hot.inner.lock().await;
        let q = inner.seen.get(&("very-hot".into(), 443)).unwrap();
        assert_eq!(
            q.len(),
            HOT_HOST_MIN_COUNT,
            "per-key queue must be capped at HOT_HOST_MIN_COUNT regardless of record count",
        );
    }

    #[tokio::test]
    async fn maybe_prewarm_is_noop_when_kill_switch_set() {
        // With prewarm disabled, `maybe_prewarm` must not record to
        // HotHosts and must not enqueue a reservation. We assert the
        // observable side effects are absent after the call returns:
        //   1. HotHosts saw no record (seen map empty for the key).
        //   2. Pool has zero pending reservations and zero actual
        //      entries for the key.
        // The spawn would be async, so we sleep briefly to give any
        // hypothetical spawned task time to land before checking —
        // if it did anything, the check would fail.
        let state = PrewarmState::with_prewarm_enabled(false);
        state.maybe_prewarm("blocked.example".to_string(), 443);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let hot_inner = state.hot.inner.lock().await;
        assert!(
            !hot_inner
                .seen
                .contains_key(&("blocked.example".to_string(), 443)),
            "disabled prewarm must not write to HotHosts"
        );
        drop(hot_inner);
        let pool_inner = state.pool.inner.lock().await;
        assert_eq!(pool_inner.total_pending, 0);
        assert_eq!(pool_inner.total_actual, 0);
        assert!(pool_inner.hosts.is_empty());
    }

    #[tokio::test]
    async fn connect_fresh_evicts_dns_when_all_addresses_unreachable() {
        // Stale CDN/failover DNS answers would otherwise keep
        // returning unreachable addresses for the full TTL. Inject
        // an entry pointing at a guaranteed-refused port, let
        // connect_fresh exhaust the
        // address list, and assert the cached entry is gone so the
        // next call re-resolves.
        let state = PrewarmState::new();
        let unreachable = SocketAddr::from(([127, 0, 0, 1], 1));
        {
            let mut entries = state.dns.entries.lock().await;
            entries.insert(
                ("unreachable.example".into(), 443),
                DnsEntry {
                    addrs: vec![unreachable],
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let result = state.connect_fresh("unreachable.example", 443).await;
        assert!(
            result.is_err(),
            "connect to refused port must error: {result:?}"
        );
        assert!(
            !state
                .dns
                .entries
                .lock()
                .await
                .contains_key(&("unreachable.example".to_string(), 443)),
            "failed connect must evict the cached DNS entry"
        );
    }

    #[tokio::test]
    async fn pooled_stream_is_actually_usable_after_take() {
        // The basic pool tests above use `loopback_stream`, which
        // drops the server side immediately — they prove counts and
        // structural moves but never that a pooled stream can carry
        // bytes. Spin up a real echo server, put the client stream
        // into the pool, take it back out, and assert it can carry a
        // request/response round trip.
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 32];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.flush().await.unwrap();
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let pool = TcpPool::new();
        assert!(pool.try_reserve("echo", 9100).await);
        pool.commit_reserve("echo", 9100, stream).await;
        let mut taken = pool
            .try_take("echo", 9100)
            .await
            .expect("freshly pooled stream must come back via try_take");
        // The stream must be alive — pool was populated < 1ms ago.
        assert!(
            is_likely_alive(&taken),
            "freshly pooled, never-closed stream must pass the liveness check"
        );
        taken.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        taken.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping", "echo server must see the bytes we sent");
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn open_tcp_skips_dead_pool_entry_and_falls_back_to_fresh() {
        // Pooled streams up to 30 s old can be closed by
        // NAT/CDN/intermediary while idle. Without the liveness
        // check, `open_tcp` would hand the dead stream to the caller
        // and the session would EOF immediately — bricking it,
        // because tunnel_client has no retry budget.
        // This test seeds the pool with a stream whose peer has
        // explicitly closed, then injects a DNS entry pointing at a
        // separate live listener so `connect_fresh` has somewhere to
        // succeed. open_tcp must:
        //   1. take the dead entry off the pool,
        //   2. recognise it via `is_likely_alive`,
        //   3. drop it and fall back to `connect_fresh`,
        //   4. return a live stream.
        // Final pool state must be empty for the key (dead entry
        // consumed, no new entry inserted by the fallback path).
        let live_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let live_addr = live_listener.local_addr().unwrap();
        let live_accept = tokio::spawn(async move {
            let _ = live_listener.accept().await;
            // Hold the accept side briefly so the client connect succeeds
            // and the resulting stream stays open while the test
            // inspects it.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        // Open a TCP connection to a listener that immediately drops
        // the server side. The local end of the stream survives in
        // a half-closed state; `try_read` returns Ok(0).
        let dead_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = dead_listener.accept().await.unwrap();
            drop(sock);
        });
        let dead_stream = TcpStream::connect(dead_addr).await.unwrap();
        // Let the FIN propagate so `try_read` reliably returns Ok(0).
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !is_likely_alive(&dead_stream),
            "test pre-condition: peer-closed stream must fail the liveness check"
        );

        let state = PrewarmState::new();
        // Inject the dead stream into the pool under the test key.
        {
            let mut inner = state.pool.inner.lock().await;
            inner
                .hosts
                .entry(("synthetic.example".into(), 443))
                .or_default()
                .queue
                .push_back(PooledConn {
                    stream: dead_stream,
                    opened_at: Instant::now(),
                });
            inner.total_actual += 1;
        }
        // Resolve the same test key to the *live* listener so
        // connect_fresh can succeed.
        {
            let mut entries = state.dns.entries.lock().await;
            entries.insert(
                ("synthetic.example".into(), 443),
                DnsEntry {
                    addrs: vec![live_addr],
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }

        let stream = state
            .open_tcp("synthetic.example", 443)
            .await
            .expect("must fall back to connect_fresh when the pool entry is dead");
        assert!(
            is_likely_alive(&stream),
            "open_tcp must return a live stream after discarding a dead pool entry"
        );

        // Pool now empty for the key — dead entry was consumed and no
        // new entry was inserted by the fallback path. (The host's
        // empty queue is removed by `try_take`'s post-take cleanup.)
        let inner = state.pool.inner.lock().await;
        assert!(
            inner
                .hosts
                .get(&("synthetic.example".to_string(), 443))
                .is_none(),
            "pool entry must be cleaned up after the dead-stream fallback"
        );
        live_accept.await.unwrap();
    }

    #[tokio::test]
    async fn dns_cache_evicts_when_over_capacity() {
        // Direct-poke a near-full cache to verify the bounded-size
        // eviction kicks in without hammering the resolver in a loop.
        let cache = DnsCache::new();
        let now = Instant::now();
        let future = now + Duration::from_secs(60);
        {
            let mut entries = cache.entries.lock().await;
            for i in 0..DNS_CACHE_MAX_ENTRIES {
                entries.insert(
                    (format!("host{i}.example"), 80),
                    DnsEntry {
                        addrs: vec![SocketAddr::from(([127, 0, 0, 1], 80))],
                        expires_at: future,
                    },
                );
            }
            assert_eq!(entries.len(), DNS_CACHE_MAX_ENTRIES);
        }
        // A real resolve through localhost forces an insert under cap.
        let _ = cache.resolve("localhost", 7778).await.unwrap();
        let entries = cache.entries.lock().await;
        assert!(
            entries.len() <= DNS_CACHE_MAX_ENTRIES,
            "cache must not exceed cap; got {}",
            entries.len()
        );
    }

    /// Helper: open a loopback TCP stream against a one-shot acceptor
    /// listening on `:0`. The accepted side is dropped immediately;
    /// the client side comes back to the caller for pool tests.
    async fn loopback_stream() -> TcpStream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        TcpStream::connect(addr).await.unwrap()
    }

    #[tokio::test]
    async fn tcp_pool_returns_none_when_empty() {
        let pool = TcpPool::new();
        assert!(pool.try_take("nowhere", 80).await.is_none());
        // Counters start at zero.
        let inner = pool.inner.lock().await;
        assert_eq!(inner.total_actual, 0);
        assert_eq!(inner.total_pending, 0);
    }

    #[tokio::test]
    async fn tcp_pool_reserve_commit_then_take() {
        let pool = TcpPool::new();
        assert!(
            pool.try_reserve("127.0.0.1", 9001).await,
            "reserve on empty pool must succeed"
        );
        {
            let inner = pool.inner.lock().await;
            assert_eq!(inner.total_pending, 1, "pending count tracks the reserve");
            assert_eq!(inner.total_actual, 0);
        }
        let stream = loopback_stream().await;
        pool.commit_reserve("127.0.0.1", 9001, stream).await;
        {
            let inner = pool.inner.lock().await;
            assert_eq!(inner.total_pending, 0, "commit clears the pending slot");
            assert_eq!(inner.total_actual, 1);
        }
        assert!(pool.try_take("127.0.0.1", 9001).await.is_some());
        let inner = pool.inner.lock().await;
        assert_eq!(inner.total_actual, 0, "take decrements actual");
        assert!(
            !inner.hosts.contains_key(&("127.0.0.1".to_string(), 9001)),
            "empty host entry must be removed"
        );
    }

    #[tokio::test]
    async fn tcp_pool_cancel_reserve_releases_slot() {
        // Reservation that the caller cancels (e.g. connect failed)
        // must restore both per-host and global counters so the next
        // reserve can take its place.
        let pool = TcpPool::new();
        for _ in 0..TCP_POOL_PER_HOST_MAX {
            assert!(pool.try_reserve("x", 1).await);
        }
        assert!(
            !pool.try_reserve("x", 1).await,
            "per-host cap must reject the over-cap reserve"
        );
        pool.cancel_reserve("x", 1).await;
        assert!(
            pool.try_reserve("x", 1).await,
            "after cancel, the freed slot must be reservable again"
        );
    }

    #[tokio::test]
    async fn tcp_pool_per_host_cap_counts_pending_and_pooled() {
        // Mix of pending + pooled must respect the per-host cap.
        let pool = TcpPool::new();
        let stream = loopback_stream().await;
        assert!(pool.try_reserve("h", 2).await);
        pool.commit_reserve("h", 2, stream).await;
        // 1 actual + 0 pending. Reserve once more (== 1 actual + 1
        // pending). Then reserve again — must fail (would be 1 + 2).
        assert!(pool.try_reserve("h", 2).await, "second reserve under cap");
        assert!(
            !pool.try_reserve("h", 2).await,
            "reserve over cap (pooled + pending) must fail"
        );
    }

    #[tokio::test]
    async fn tcp_pool_global_cap_counts_pending() {
        // Fill the global cap with reservations alone — no commits.
        let pool = TcpPool::new();
        // Spread across many hosts so the per-host cap isn't the
        // gating factor; we want to prove the global cap counts
        // pending entries.
        let mut reserved = 0;
        for i in 0..(TCP_POOL_TOTAL_MAX + 1) {
            let host = format!("h{i}");
            if pool.try_reserve(&host, 80).await {
                reserved += 1;
            }
        }
        assert_eq!(
            reserved, TCP_POOL_TOTAL_MAX,
            "global cap must cap reservations across distinct hosts"
        );
    }

    #[tokio::test]
    async fn tcp_pool_try_reserve_prunes_stale_when_global_cap_hit() {
        // Stale-pool cleanup: a pool sitting at global cap with
        // stale entries for hosts that are never re-requested must
        // self-clean when the next reserve would otherwise be
        // rejected. Poke stale entries directly into the map under
        // TCP_POOL_TOTAL_MAX, then assert that the next try_reserve
        // succeeds for a fresh host (it can only succeed if
        // prune_stale ran).
        let pool = TcpPool::new();
        let stale_age = TCP_POOL_TTL + Duration::from_secs(5);
        {
            let mut inner = pool.inner.lock().await;
            for i in 0..TCP_POOL_TOTAL_MAX {
                let host = format!("stale{i}");
                let stream = loopback_stream().await;
                inner
                    .hosts
                    .entry((host, 80))
                    .or_default()
                    .queue
                    .push_back(PooledConn {
                        stream,
                        opened_at: Instant::now() - stale_age,
                    });
                inner.total_actual += 1;
            }
            assert_eq!(inner.total_actual, TCP_POOL_TOTAL_MAX);
        }
        assert!(
            pool.try_reserve("fresh", 80).await,
            "stale entries must be pruned so the fresh reservation fits"
        );
        let inner = pool.inner.lock().await;
        // After prune, all the stale entries are gone and the host
        // map only contains the fresh reservation's empty queue.
        assert_eq!(inner.total_actual, 0);
        assert_eq!(inner.total_pending, 1);
    }

    #[tokio::test]
    async fn tcp_pool_try_take_discards_stale_entries() {
        let pool = TcpPool::new();
        let stale_age = TCP_POOL_TTL + Duration::from_secs(5);
        let stale = loopback_stream().await;
        let fresh = loopback_stream().await;
        {
            let mut inner = pool.inner.lock().await;
            let state = inner.hosts.entry(("h".into(), 9000)).or_default();
            state.queue.push_back(PooledConn {
                stream: stale,
                opened_at: Instant::now() - stale_age,
            });
            state.queue.push_back(PooledConn {
                stream: fresh,
                opened_at: Instant::now(),
            });
            inner.total_actual += 2;
        }
        assert!(
            pool.try_take("h", 9000).await.is_some(),
            "stale entry must be skipped; fresh returned"
        );
        let inner = pool.inner.lock().await;
        assert_eq!(
            inner.total_actual, 0,
            "both the stale (dropped) and fresh (taken) must be accounted for"
        );
    }

    #[tokio::test]
    async fn tcp_pool_concurrent_take_and_reserve_do_not_deadlock() {
        // With the single-mutex design there is no lock-order pair to
        // deadlock against. This is a behavioral smoke test that
        // confirms many concurrent ops complete within a bounded
        // wall-clock budget.
        let pool = Arc::new(TcpPool::new());
        let mut set = JoinSet::new();
        for i in 0..32 {
            let p = Arc::clone(&pool);
            set.spawn(async move {
                let host = format!("h{}", i % 4);
                if p.try_reserve(&host, 443).await {
                    p.cancel_reserve(&host, 443).await;
                }
                let _ = p.try_take(&host, 443).await;
            });
        }
        let drain = async {
            while let Some(res) = set.join_next().await {
                res.expect("join must succeed");
            }
        };
        tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .expect("concurrent take/reserve must not deadlock");
    }

    #[tokio::test]
    async fn hot_hosts_flags_after_min_count_within_window() {
        let hot = HotHosts::new();
        assert!(
            !hot.record_and_check("psn", 443).await,
            "1 connect must not be hot (HOT_HOST_MIN_COUNT is {HOT_HOST_MIN_COUNT})"
        );
        assert!(
            hot.record_and_check("psn", 443).await,
            "{HOT_HOST_MIN_COUNT} connects in-window must be hot"
        );
        assert!(!hot.record_and_check("other", 443).await);
    }

    #[tokio::test]
    async fn hot_hosts_prunes_stale_timestamps_per_host() {
        let hot = HotHosts::new();
        {
            let mut inner = hot.inner.lock().await;
            let q = inner
                .seen
                .entry(("flaky".into(), 443))
                .or_insert_with(VecDeque::new);
            q.push_back(Instant::now() - HOT_HOST_WINDOW - Duration::from_secs(10));
        }
        assert!(
            !hot.record_and_check("flaky", 443).await,
            "stale timestamp must be pruned; fresh count=1 is below threshold"
        );
        let inner = hot.inner.lock().await;
        let q = inner.seen.get(&("flaky".into(), 443)).unwrap();
        assert_eq!(q.len(), 1, "pruned queue plus one fresh sample = 1");
    }

    #[tokio::test]
    async fn hot_hosts_caps_distinct_keys() {
        // Map size must stay bounded even under adversarial input.
        // Pre-fill with HOT_HOSTS_MAX_KEYS distinct stale-only
        // entries (so the prune-on-cap path can clean them up), then
        // record one new key. The map must not exceed the cap.
        let hot = HotHosts::new();
        let stale = Instant::now() - HOT_HOST_WINDOW - Duration::from_secs(10);
        {
            let mut inner = hot.inner.lock().await;
            for i in 0..HOT_HOSTS_MAX_KEYS {
                let mut q = VecDeque::new();
                q.push_back(stale);
                inner.seen.insert((format!("stale{i}"), 80), q);
            }
            assert_eq!(inner.seen.len(), HOT_HOSTS_MAX_KEYS);
        }
        // New key — must trigger the prune-on-cap path, drop all
        // the stale entries, and end up with just the new one.
        hot.record_and_check("new", 443).await;
        let inner = hot.inner.lock().await;
        assert!(
            inner.seen.len() <= HOT_HOSTS_MAX_KEYS,
            "map must respect cap; got {}",
            inner.seen.len()
        );
        assert!(inner.seen.contains_key(&("new".into(), 443)));
    }

    #[tokio::test]
    async fn hot_hosts_evicts_arbitrary_key_when_no_stale_to_prune() {
        // Edge case: all entries fresh and at cap — pruning yields
        // no space, so an arbitrary key is evicted to make room.
        let hot = HotHosts::new();
        let fresh = Instant::now();
        {
            let mut inner = hot.inner.lock().await;
            for i in 0..HOT_HOSTS_MAX_KEYS {
                let mut q = VecDeque::new();
                q.push_back(fresh);
                inner.seen.insert((format!("live{i}"), 80), q);
            }
        }
        hot.record_and_check("new", 443).await;
        let inner = hot.inner.lock().await;
        assert!(
            inner.seen.len() <= HOT_HOSTS_MAX_KEYS,
            "map must respect cap even when prune frees nothing; got {}",
            inner.seen.len()
        );
        assert!(inner.seen.contains_key(&("new".into(), 443)));
    }

    #[tokio::test]
    async fn connect_fresh_iterates_resolved_addresses() {
        // The previous TcpStream::connect("host:port") tried every
        // resolved address. The refactored connect_fresh must
        // preserve that: a list with one unreachable address followed
        // by a reachable one must succeed.
        //
        // We construct the failure case directly via DnsCache::entries
        // (no need to spin up a fake resolver). The reachable address
        // is a real loopback listener.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let live = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        // 127.0.0.1:1 is essentially guaranteed to refuse / be closed.
        let dead = SocketAddr::from(([127, 0, 0, 1], 1));
        let state = PrewarmState::new();
        {
            let mut entries = state.dns.entries.lock().await;
            entries.insert(
                ("multi.example".into(), live.port()),
                DnsEntry {
                    addrs: vec![dead, live],
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let stream = state
            .connect_fresh("multi.example", live.port())
            .await
            .expect("must fall through to the reachable address");
        assert_eq!(stream.peer_addr().unwrap(), live);
    }

    #[tokio::test]
    async fn connect_fresh_errors_when_no_addresses_available() {
        // Inject a cached DNS entry with zero addresses. The cache
        // hit returns the empty vec without re-resolving; connect_fresh
        // iterates zero addresses and the loop's `last_err` stays
        // None, so we return `AddrNotAvailable`. Exercises the
        // empty-iterate branch of the wrapped DNS+connect budget.
        let state = PrewarmState::new();
        {
            let mut entries = state.dns.entries.lock().await;
            entries.insert(
                ("nothing.example".into(), 443),
                DnsEntry {
                    addrs: vec![],
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let err = state
            .connect_fresh("nothing.example", 443)
            .await
            .expect_err("must fail when no addresses are available");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    }

    async fn start_udp_echo_server() -> u16 {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let mut out = b"ECHO: ".to_vec();
                out.extend_from_slice(&buf[..n]);
                let _ = socket.send_to(&out, peer).await;
            }
        });
        port
    }

    /// Spin up a one-shot TCP server that echoes everything it reads back
    /// with a `"ECHO: "` prefix, then returns the bound port.
    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = sock.read(&mut buf).await {
                    let mut out = b"ECHO: ".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(&out).await;
                    let _ = sock.flush().await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn unsupported_op_response_has_structured_code() {
        let resp = TunnelResponse::unsupported_op("connect_data");
        assert_eq!(resp.code.as_deref(), Some(CODE_UNSUPPORTED_OP));
        assert_eq!(resp.e.as_deref(), Some("unknown op: connect_data"));
    }

    #[tokio::test]
    async fn validate_host_port_rejects_empty_and_zero() {
        assert!(validate_host_port(None, Some(443)).is_err());
        assert!(validate_host_port(Some("".into()), Some(443)).is_err());
        assert!(validate_host_port(Some("x".into()), None).is_err());
        assert!(validate_host_port(Some("x".into()), Some(0)).is_err());
        assert_eq!(
            validate_host_port(Some("host".into()), Some(443)).unwrap(),
            ("host".to_string(), 443),
        );
    }

    #[tokio::test]
    async fn connect_data_phase1_writes_initial_data_and_returns_inner() {
        let port = start_echo_server().await;
        let state = fresh_state();

        let (sid, inner) = handle_connect_data_phase1(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"hello")),
        )
        .await
        .expect("phase1 should succeed");

        // Session was inserted.
        assert!(state.sessions.lock().await.contains_key(&sid));

        // Echo server sent back "ECHO: hello". Use wait_and_drain on the
        // returned Arc — no map re-lookup needed (this is the fix).
        let (data, _eof) = wait_and_drain(&inner, Duration::from_secs(2)).await;
        assert_eq!(&data[..], b"ECHO: hello");
    }

    #[tokio::test]
    async fn connect_data_single_bundles_connect_and_first_bytes() {
        let port = start_echo_server().await;
        let state = fresh_state();

        let resp = handle_connect_data_single(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"world")),
        )
        .await;

        assert!(resp.e.is_none(), "unexpected error: {:?}", resp.e);
        assert!(resp.sid.is_some());
        let decoded = B64.decode(resp.d.unwrap()).unwrap();
        assert_eq!(&decoded[..], b"ECHO: world");
    }

    #[tokio::test]
    async fn connect_data_rejects_missing_host() {
        let state = fresh_state();
        let resp =
            handle_connect_data_single(&state, None, Some(443), Some(B64.encode(b"x"))).await;
        assert!(resp.e.as_deref().unwrap_or("").contains("missing host"));
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn connect_data_rejects_bad_base64_and_does_not_leak_session() {
        // Need a live target so we reach the base64-decode step after
        // create_session succeeds — otherwise we'd fail earlier.
        let port = start_echo_server().await;
        let state = fresh_state();
        let resp = handle_connect_data_single(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some("!!!not base64!!!".into()),
        )
        .await;
        assert!(resp.e.as_deref().unwrap_or("").contains("bad base64"));
        // Session should NOT be in the map since phase1 rejected it.
        assert!(state.sessions.lock().await.is_empty());
    }

    // ---------------------------------------------------------------------
    // wait_for_any_drainable + notify wiring
    //
    // These guard the new event-driven drain. Regressions here mean the
    // batch handler either falls back to fixed sleeps (latency win lost)
    // or wedges on a missed signal (correctness lost) — both silent
    // without explicit tests.
    // ---------------------------------------------------------------------

    /// Build a SessionInner with no reader_task, suitable for tests that
    /// drive the read_buf / eof / notify state by hand. The writer half
    /// is wired to a live loopback peer so the Mutex<OwnedWriteHalf> has
    /// a real value, but tests never touch it.
    async fn fake_inner() -> Arc<SessionInner> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server_side = accept.await.unwrap();
        let (_reader, writer) = client.into_split();

        Arc::new(SessionInner {
            writer: Mutex::new(SessionWriter::Tcp(writer)),
            read_buf: Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
            next_write_seq: Mutex::new(None),
            pending_writes: Mutex::new(std::collections::BTreeMap::new()),
        })
    }

    /// Like `fake_inner`, but returns the upstream-side `TcpStream` so
    /// the caller can observe (in order) what bytes the SessionInner's
    /// writer actually flushed. Tests for `handle_batch`'s wseq ordering
    /// logic need this — `fake_inner` drops the upstream end and there's
    /// no way to recover the byte sequence.
    async fn fake_inner_with_observer() -> (Arc<SessionInner>, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();
        let (_reader, writer) = client.into_split();
        let inner = Arc::new(SessionInner {
            writer: Mutex::new(SessionWriter::Tcp(writer)),
            read_buf: Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
            next_write_seq: Mutex::new(None),
            pending_writes: Mutex::new(std::collections::BTreeMap::new()),
        });
        (inner, server_side)
    }

    #[tokio::test]
    async fn drain_now_caps_at_tcp_drain_max_bytes() {
        // Issue #460: a 1 Gbps VPS reader fills the buffer with tens of MiB
        // between polls; drain_now used to take the lot, the JSON response
        // exceeded Apps Script's body cap, and the client failed JSON parse.
        // The cap leaves the tail in the buffer for the next drain.
        let inner = fake_inner().await;
        let oversized = TCP_DRAIN_MAX_BYTES + 4096;
        inner.read_buf.lock().await.resize(oversized, 0xab);

        let (first, eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(first.len(), TCP_DRAIN_MAX_BYTES);
        assert!(!eof, "shouldn't propagate eof while buffer still has data");

        // Tail remains for the next poll.
        assert_eq!(inner.read_buf.lock().await.len(), 4096);

        let (second, _) = drain_now(&inner, usize::MAX).await;
        assert_eq!(second.len(), 4096);
        assert!(inner.read_buf.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_now_respects_caller_budget_below_per_session_cap() {
        // Issue #863: per-session TCP_DRAIN_MAX_BYTES alone wasn't enough
        // because N sessions × 16 MiB summed past Apps Script's 50 MiB
        // response ceiling. The batch loop now passes a remaining-budget
        // cap; drain_now must honor `min(budget, TCP_DRAIN_MAX_BYTES)`,
        // leaving the tail for the next poll exactly like the per-session
        // cap path does.
        let inner = fake_inner().await;
        // 1 MiB buffered, but caller only has 256 KiB budget left.
        inner.read_buf.lock().await.resize(1024 * 1024, 0xcd);

        let (drained, eof) = drain_now(&inner, 256 * 1024).await;
        assert_eq!(drained.len(), 256 * 1024);
        assert!(!eof, "tail still buffered, eof must wait");

        // The remaining 768 KiB stays put for the next poll.
        assert_eq!(inner.read_buf.lock().await.len(), 768 * 1024);

        // Next call with full budget drains the rest.
        let (rest, _) = drain_now(&inner, usize::MAX).await;
        assert_eq!(rest.len(), 768 * 1024);
        assert!(inner.read_buf.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_now_passes_through_when_under_cap() {
        let inner = fake_inner().await;
        inner
            .read_buf
            .lock()
            .await
            .extend_from_slice(b"hello world");

        let (data, eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(data, b"hello world");
        assert!(!eof);
        assert!(inner.read_buf.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_now_holds_eof_until_buffer_drained() {
        // If upstream signals EOF while the buffer is still oversized, we
        // must drain the head, leave the tail, and *not* set eof yet.
        // Eof flips on the final drain that returns a sub-cap buffer.
        let inner = fake_inner().await;
        inner.eof.store(true, Ordering::Release);
        inner
            .read_buf
            .lock()
            .await
            .resize(TCP_DRAIN_MAX_BYTES + 100, 0);

        let (head, head_eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(head.len(), TCP_DRAIN_MAX_BYTES);
        assert!(!head_eof, "premature eof would tear the session");

        let (tail, tail_eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(tail.len(), 100);
        assert!(tail_eof, "eof finally flips when buffer is drained");
    }

    #[tokio::test]
    async fn wait_for_any_drainable_returns_immediately_when_buffer_has_data() {
        let inner = fake_inner().await;
        inner
            .read_buf
            .lock()
            .await
            .extend_from_slice(b"already here");

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "should short-circuit on pre-buffered data, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_returns_immediately_when_eof_set() {
        let inner = fake_inner().await;
        inner.eof.store(true, Ordering::Release);

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "should short-circuit on pre-set eof, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_returns_immediately_for_empty_list() {
        let t0 = Instant::now();
        wait_for_any_drainable(&[], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "empty input should be a no-op, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_wakes_on_notify() {
        let inner = fake_inner().await;
        let signal = inner.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            signal.read_buf.lock().await.extend_from_slice(b"pushed");
            signal.notify.notify_one();
        });

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], Duration::from_secs(5)).await;
        let elapsed = t0.elapsed();
        // We only assert the upper bound — wake latency under load can be
        // tens of ms but should never approach the 5 s deadline.
        assert!(
            elapsed < Duration::from_millis(800),
            "did not wake on notify within reasonable time: {:?}",
            elapsed
        );
    }

    /// Any-of-N: when one session in a multi-session batch fires its
    /// notify, the wait returns. Regression here would mean idle
    /// neighbors block the drain for a session that has data ready.
    #[tokio::test]
    async fn wait_for_any_drainable_wakes_on_any_session_notify() {
        let a = fake_inner().await;
        let b = fake_inner().await;
        let c = fake_inner().await;
        let signal = b.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            signal.read_buf.lock().await.push(b'x');
            signal.notify.notify_one();
        });

        let t0 = Instant::now();
        wait_for_any_drainable(&[a, b, c], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(800),
            "any-of-N wake too slow: {:?}",
            t0.elapsed()
        );
    }

    /// Stale-permit guard: if a previous batch consumed the buffer and
    /// returned via the spawn-race shortcut without consuming the notify
    /// permit, the next batch's watcher consumes that stale permit but
    /// MUST NOT wake the caller — the buffer is empty. This regressed
    /// silently in the first version; the self-filtering watcher closes
    /// it. Without this test, an empty long-poll batch could return in
    /// <1 ms and degrade push delivery to the client's idle re-poll
    /// cadence (~500 ms).
    #[tokio::test]
    async fn wait_for_any_drainable_ignores_stale_permit() {
        let inner = fake_inner().await;

        // Plant a permit (no waiter yet, so it's stored as a one-shot).
        inner.notify.notify_one();

        // Buffer is empty and EOF is unset, so the only thing that
        // could wake the wait is the permit. With self-filtering the
        // watcher consumes it, sees no observable state, loops back —
        // the wait should run for the full deadline and then return.
        let deadline = Duration::from_millis(200);
        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], deadline).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= deadline,
            "stale permit incorrectly woke the wait: {:?} < {:?}",
            elapsed,
            deadline
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_hits_deadline_when_no_events() {
        let inner = fake_inner().await;
        let deadline = Duration::from_millis(150);

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], deadline).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= deadline,
            "returned before deadline: {:?} < {:?}",
            elapsed,
            deadline
        );
        assert!(
            elapsed < deadline + Duration::from_millis(300),
            "overshot deadline by too much: {:?}",
            elapsed
        );
    }

    /// Real reader_task → notify path. If reader_task ever stops calling
    /// notify_one after an extend, the long-poll silently degrades to
    /// "wait the full deadline every time" — this catches that.
    #[tokio::test]
    async fn reader_task_notifies_on_incoming_bytes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
            sock.write_all(b"hello").await.unwrap();
            sock.flush().await.unwrap();
            // Hold the connection so reader_task doesn't immediately EOF
            // and confuse the assertion.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let inner = Arc::new(SessionInner {
            writer: Mutex::new(SessionWriter::Tcp(writer)),
            read_buf: Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
            next_write_seq: Mutex::new(None),
            pending_writes: Mutex::new(std::collections::BTreeMap::new()),
        });
        let _reader_handle = tokio::spawn(reader_task(reader, inner.clone()));

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner.clone()], Duration::from_secs(2)).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(800),
            "wait did not wake on reader_task notify: {:?}",
            elapsed
        );
        assert_eq!(&inner.read_buf.lock().await[..], b"hello");

        // The spawned server's only job is to deliver one chunk and hold
        // the connection open long enough for the assertion. abort() is
        // intentional cleanup, not a failure path.
        server.abort();
    }

    // ---------------------------------------------------------------------
    // handle_batch deadline selection (end-to-end through the actual
    // batch handler — not just wait_for_any_drainable in isolation)
    //
    // These tests guard the adaptive deadline logic: an empty-poll batch
    // must engage LONGPOLL_DEADLINE, an active batch must cap at
    // ACTIVE_DRAIN_DEADLINE + STRAGGLER_SETTLE, and `Some("")` must NOT
    // count as a write. Each was a separate review concern and would
    // regress silently without explicit coverage.
    // ---------------------------------------------------------------------

    /// TCP server that pushes `data` exactly `delay` after accept,
    /// without reading from the client first. Simulates server-initiated
    /// push (notifications, SSE) on a real socket.
    async fn start_push_server(delay: Duration, data: Vec<u8>) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                tokio::time::sleep(delay).await;
                let _ = sock.write_all(&data).await;
                let _ = sock.flush().await;
                // Hold the socket open well beyond any test's deadline
                // so reader_task doesn't EOF mid-assertion.
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        port
    }

    /// TCP server that accepts and does NOTHING — never writes, never
    /// closes. Used to test deadline behavior when there's no upstream
    /// response.
    async fn start_silent_server() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                // Hold the socket alive past any reasonable test deadline.
                tokio::time::sleep(Duration::from_secs(60)).await;
                drop(sock);
            }
        });
        port
    }

    /// Drive `handle_batch` end-to-end and parse its JSON response into a
    /// `serde_json::Value` for assertion (TunnelResponse/BatchResponse
    /// don't derive Deserialize, and we don't want to add it just for
    /// tests).
    async fn invoke_handle_batch(state: &AppState, body: Vec<u8>) -> serde_json::Value {
        let resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    /// Pure-poll batch (one `data` op with no `d`) holds open and wakes
    /// when upstream pushes data. Push arrives at ~150 ms — well past
    /// any active-batch ceiling. If long-poll didn't engage we'd return
    /// at ACTIVE_DRAIN_DEADLINE (350 ms) with no data.
    #[tokio::test]
    async fn batch_pure_poll_wakes_on_push() {
        let push_port = start_push_server(Duration::from_millis(150), b"PUSHED".to_vec()).await;
        let state = fresh_state();
        let connect_resp = handle_connect(&state, Some("127.0.0.1".into()), Some(push_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid}],
        }))
        .unwrap();

        let t0 = Instant::now();
        let resp = invoke_handle_batch(&state, body).await;
        let elapsed = t0.elapsed();

        assert!(
            elapsed >= Duration::from_millis(120),
            "returned before push could realistically arrive: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "long-poll did not return promptly on push: {:?}",
            elapsed
        );

        let r = resp["r"].as_array().expect("response must be an array");
        let d_b64 = r[0]["d"]
            .as_str()
            .expect("response should carry pushed bytes");
        let data = B64.decode(d_b64).unwrap();
        assert_eq!(&data[..], b"PUSHED");
    }

    /// Active batch (write op) bounds the wait at roughly
    /// ACTIVE_DRAIN_DEADLINE + a little overhead, even when upstream
    /// doesn't respond. Upper bound proves long-poll did NOT engage.
    #[tokio::test]
    async fn batch_active_caps_at_active_deadline() {
        let silent_port = start_silent_server().await;
        let state = fresh_state();
        let connect_resp =
            handle_connect(&state, Some("127.0.0.1".into()), Some(silent_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid, "d": B64.encode(b"PING")}],
        }))
        .unwrap();

        let t0 = Instant::now();
        let _resp = invoke_handle_batch(&state, body).await;
        let elapsed = t0.elapsed();

        // No upstream response → wait full ACTIVE_DRAIN_DEADLINE (~350ms),
        // no straggler settle (we never woke). Upper bound is tight
        // enough that a regression bumping the active deadline above
        // ~600ms would fail this test instead of slipping through.
        assert!(
            elapsed >= Duration::from_millis(300),
            "active batch returned before active deadline: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(600),
            "active batch held longer than ACTIVE_DRAIN_DEADLINE + margin: {:?}",
            elapsed
        );
    }

    /// `Some("")` must NOT flip `had_writes_or_connects`. If it did, the
    /// batch would return at the active deadline (350 ms) without the
    /// pushed bytes — push arrives at 600 ms here, deliberately past
    /// the active ceiling, so the only way the test gets data is if
    /// long-poll actually engaged.
    #[tokio::test]
    async fn batch_empty_string_payload_engages_long_poll() {
        let push_port = start_push_server(Duration::from_millis(600), b"DELAYED".to_vec()).await;
        let state = fresh_state();
        let connect_resp = handle_connect(&state, Some("127.0.0.1".into()), Some(push_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid, "d": ""}],
        }))
        .unwrap();

        let t0 = Instant::now();
        let resp = invoke_handle_batch(&state, body).await;
        let elapsed = t0.elapsed();

        assert!(
            elapsed >= Duration::from_millis(550),
            "returned before push arrived (deadline likely set to active, not long-poll): {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(1100),
            "long-poll didn't wake promptly on push: {:?}",
            elapsed
        );

        let r = resp["r"].as_array().unwrap();
        let d_b64 = r[0]["d"]
            .as_str()
            .expect("Some(\"\") payload should have engaged long-poll and delivered DELAYED");
        let data = B64.decode(d_b64).unwrap();
        assert_eq!(&data[..], b"DELAYED");
    }

    // ---------------------------------------------------------------------
    // UDP path
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn udp_open_writes_initial_datagram_and_buffers_reply() {
        let port = start_udp_echo_server().await;
        let state = fresh_state();

        let (sid, inner) = handle_udp_open_phase1(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"ping")),
        )
        .await
        .expect("udp open should succeed");

        assert!(state.udp_sessions.lock().await.contains_key(&sid));
        wait_for_any_udp_drainable(std::slice::from_ref(&inner), Duration::from_secs(2)).await;
        let (packets, eof) = drain_udp_now(&inner).await;
        assert_eq!(packets, vec![b"ECHO: ping".to_vec()]);
        assert!(!eof);
    }

    /// When the upstream sends faster than the relay drains, the queue
    /// must drop oldest packets (so recent voice/video stays current)
    /// AND increment the counter so operators can correlate user
    /// reports of choppiness with relay backpressure.
    #[tokio::test]
    async fn udp_queue_overflow_drops_oldest_and_counts() {
        let state = fresh_state();
        let sink = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let sink_port = sink.local_addr().unwrap().port();

        let (_sid, inner) =
            handle_udp_open_phase1(&state, Some("127.0.0.1".into()), Some(sink_port), None)
                .await
                .expect("udp open");

        // Flood the session socket from sink — its connected remote is
        // exactly sink_port, so packets pass the kernel's source check.
        let session_addr = inner.socket.local_addr().unwrap();
        let burst = UDP_QUEUE_LIMIT + 16;
        for i in 0..burst {
            let payload = format!("p{}", i).into_bytes();
            sink.send_to(&payload, session_addr).await.unwrap();
        }
        // Give the reader_task a chance to drain the OS buffer.
        for _ in 0..50 {
            if inner.queue_drops.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let drops = inner.queue_drops.load(Ordering::Relaxed);
        let queued = inner.packets.lock().await.len();
        assert!(
            drops >= 1,
            "expected ≥1 drop, got {} (queued={})",
            drops,
            queued
        );
        assert!(
            queued <= UDP_QUEUE_LIMIT,
            "queue exceeded limit: {}",
            queued
        );
    }

    /// Regression for the bug the review caught: a batch mixing UDP and
    /// TCP-data ops must let the TCP side benefit from the same
    /// event-driven drain. With the new architecture both sides share
    /// one wait_start / deadline window — ensure a delayed TCP response
    /// still makes it into the batch even when UDP is along for the ride.
    #[tokio::test]
    async fn tcp_drain_runs_when_batch_also_contains_udp() {
        use axum::body::Bytes;
        use axum::extract::State;

        // TCP server that delays its response past the typical wake but
        // well within ACTIVE_DRAIN_DEADLINE (350ms).
        let tcp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(120)).await;
                let _ = sock.write_all(b"DELAYED").await;
                let _ = sock.flush().await;
            }
        });

        // Idle UDP target — never replies. Just sets up the dual-drain
        // path through Phase 2.
        let udp_target = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let udp_port = udp_target.local_addr().unwrap().port();

        let state = fresh_state();
        let tcp_sid = match handle_connect(&state, Some("127.0.0.1".into()), Some(tcp_port)).await {
            TunnelResponse {
                sid: Some(s),
                e: None,
                ..
            } => s,
            other => panic!("connect failed: {:?}", other),
        };
        let (udp_sid, _udp_inner) =
            handle_udp_open_phase1(&state, Some("127.0.0.1".into()), Some(udp_port), None)
                .await
                .expect("udp open");

        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "data", "sid": tcp_sid, "d": B64.encode(b"hello")},
                {"op": "udp_data", "sid": udp_sid},
            ]
        })
        .to_string();
        let resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let (parts, body) = resp.into_parts();
        assert_eq!(parts.status, axum::http::StatusCode::OK);
        let body_bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let r = parsed["r"].as_array().unwrap();
        assert_eq!(r.len(), 2);
        let tcp_d = r[0]["d"].as_str().expect("tcp data missing");
        let decoded = B64.decode(tcp_d).unwrap();
        assert_eq!(&decoded[..], b"DELAYED");
    }

    /// When the upstream UDP socket dies (recv error), the reader_task
    /// must mark the session eof so subsequent batches return
    /// `eof: true` instead of looping the proxy on a zombie session.
    #[tokio::test]
    async fn udp_drain_surfaces_upstream_eof() {
        let inner = Arc::new(UdpSessionInner {
            socket: Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap()),
            packets: Mutex::new(VecDeque::new()),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
            eof: AtomicBool::new(false),
            queue_drops: AtomicU64::new(0),
        });
        // Healthy state: drain reports no eof.
        let (pkts, eof) = drain_udp_now(&inner).await;
        assert!(pkts.is_empty());
        assert!(!eof);

        // Simulate the failure path udp_reader_task takes on socket err.
        inner.eof.store(true, Ordering::Release);
        inner.notify.notify_one();

        let (pkts, eof) = drain_udp_now(&inner).await;
        assert!(pkts.is_empty());
        assert!(eof, "drain should surface eof once the reader marks it");

        // wait_for_any_udp_drainable also wakes immediately on eof.
        let t0 = Instant::now();
        wait_for_any_udp_drainable(std::slice::from_ref(&inner), Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "eof should short-circuit the wait, took {:?}",
            t0.elapsed()
        );

        // The `udp_drain_response` helper threads eof into `eof: Some(true)`.
        let resp = udp_drain_response("zombie".into(), pkts, eof, None);
        assert_eq!(resp.eof, Some(true));
        assert!(resp.pkts.is_none());
    }

    /// A batch that targets a UDP session reaped by the cleanup task
    /// (or removed via close) returns `eof: true` so the proxy task
    /// exits its select loop instead of polling a zombie.
    #[tokio::test]
    async fn udp_data_for_missing_session_returns_eof() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "udp_data", "sid": "does-not-exist"},
            ]
        })
        .to_string();
        let resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let (_parts, body) = resp.into_parts();
        let body_bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let r = parsed["r"].as_array().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["eof"], serde_json::Value::Bool(true));
    }

    /// Regression for the cleanup-correctness fix. Previously, the
    /// batch handler reaped any session whose `inner.eof` atomic was
    /// set, even when `drain_now` had withheld eof to keep tail bytes
    /// buffered (i.e. the buffer exceeded `TCP_DRAIN_MAX_BYTES`).
    /// Reaping aborted the reader_task and dropped the tail. Cleanup
    /// is now driven off the drain's returned `eof`, so an over-cap
    /// buffer + atomic eof keeps the session alive through the first
    /// poll and only reaps on the drain that actually returns eof.
    #[tokio::test]
    async fn batch_keeps_over_cap_session_until_tail_is_drained() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();
        let inner = fake_inner().await;
        // Prime an over-cap buffer + raw eof. drain_now will return
        // TCP_DRAIN_MAX_BYTES bytes with eof=false; the previous
        // cleanup would still reap because it read inner.eof directly.
        inner
            .read_buf
            .lock()
            .await
            .resize(TCP_DRAIN_MAX_BYTES + 4096, 0u8);
        inner.eof.store(true, Ordering::Release);

        let sid = "over-cap-sid".to_string();
        state.sessions.lock().await.insert(
            sid.clone(),
            ManagedSession {
                inner: inner.clone(),
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        let body = serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": &sid}]
        })
        .to_string();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();

        // First poll: session must still be in the map, tail intact.
        // The previous code reaped here and dropped the 4096 tail bytes.
        {
            let sessions = state.sessions.lock().await;
            let s = sessions.get(&sid).expect(
                "session removed despite tail bytes still buffered; \
                 drain_now returned eof=false but cleanup ignored that \
                 and read inner.eof directly",
            );
            let remaining = s.inner.read_buf.lock().await.len();
            assert_eq!(remaining, 4096, "tail must be preserved for next drain");
        }

        // Second poll: drain_now sees buf.len() ≤ cap AND raw_eof,
        // so returns eof=true. Cleanup runs and the session is reaped.
        let body2 = serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": &sid}]
        })
        .to_string();
        let _resp2 = handle_batch(State(state.clone()), Bytes::from(body2))
            .await
            .into_response();

        assert!(
            !state.sessions.lock().await.contains_key(&sid),
            "session should be reaped on the drain that returns eof=true",
        );
    }

    /// Regression for the pipelined-drain batch budget. The first cut of
    /// the wseq-pipelining patch gave each TCP session a fresh 1 s
    /// drain-loop deadline, so a batch with N continuously-producing
    /// sessions could spend up to N seconds in the drain phase — long
    /// past Apps Script's batch budget. The batch-wide deadline caps
    /// total drain time at 1 s regardless of how many sessions share
    /// the batch. Background tasks below keep appending one byte every
    /// 10 ms so `drain_now` never returns empty (its empty-buffer break
    /// would otherwise mask the deadline check).
    #[tokio::test]
    async fn batch_tcp_drain_phase_is_bounded_across_many_sessions() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();
        let n_sessions = 5usize;
        let mut sids: Vec<String> = Vec::with_capacity(n_sessions);
        let mut producers: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(n_sessions);

        for i in 0..n_sessions {
            let inner = fake_inner().await;
            // Trickle one byte every 10 ms into read_buf for the lifetime
            // of the test — keeps `drain_now` returning Non-empty so the
            // per-session loop must rely on the deadline to break out.
            let inner_for_producer = inner.clone();
            let producer = tokio::spawn(async move {
                loop {
                    {
                        let mut g = inner_for_producer.read_buf.lock().await;
                        g.push(0xab);
                    }
                    inner_for_producer.notify.notify_one();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            producers.push(producer);

            let sid = format!("drain-bounded-sid-{}", i);
            state.sessions.lock().await.insert(
                sid.clone(),
                ManagedSession {
                    inner,
                    reader_handle: tokio::spawn(async {}),
                    udpgw_handle: None,
                },
            );
            sids.push(sid);
        }

        // Build a batch containing one "data" op per session — that's
        // what populates the TCP drain phase that the deadline gates.
        let ops: Vec<serde_json::Value> = sids
            .iter()
            .map(|sid| serde_json::json!({ "op": "data", "sid": sid }))
            .collect();
        let body = serde_json::json!({"k": "test-key", "ops": ops}).to_string();

        let t0 = Instant::now();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let elapsed = t0.elapsed();

        for p in producers {
            p.abort();
        }

        // Allow generous slack for scheduler jitter on slower CI hosts:
        // batch-wide deadline is 1 s, the test budget is 2.5 s. The
        // pre-fix code would burn ~`n_sessions × 1 s` here.
        assert!(
            elapsed < Duration::from_millis(2500),
            "TCP drain phase took {:?} for {} sessions — \
             expected < 2.5s under the batch-wide deadline; per-session \
             1 s deadlines stack and would have produced > {}s",
            elapsed,
            n_sessions,
            n_sessions,
        );
    }

    /// Regression for the `tokio::join!` → `tokio::select!` mixed-drain
    /// fix. Before the change, a TCP-ready / UDP-idle pure-poll batch
    /// paid the full UDP `LONGPOLL_DEADLINE` (15 s) because the join
    /// was conjunctive — both arms had to complete. Under select! the
    /// TCP wake returns the response promptly even though UDP is
    /// quiet. The bound is loose (1 s) on purpose: real elapsed is
    /// in the millisecond range, but the prior bug would have
    /// triggered the test timeout instead of the assert.
    #[tokio::test]
    async fn batch_tcp_ready_does_not_pay_udp_longpoll_deadline() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();

        // TCP session with bytes already buffered → immediately drainable.
        let tcp_inner = fake_inner().await;
        tcp_inner.read_buf.lock().await.extend_from_slice(b"ready");
        let tcp_sid = "tcp-sid".to_string();
        state.sessions.lock().await.insert(
            tcp_sid.clone(),
            ManagedSession {
                inner: tcp_inner,
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        // Idle UDP session — never wakes. Real upstream so udp_open
        // succeeds; we just never send anything to it.
        let udp_target = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let udp_port = udp_target.local_addr().unwrap().port();
        let (udp_sid, _udp_inner) =
            handle_udp_open_phase1(&state, Some("127.0.0.1".into()), Some(udp_port), None)
                .await
                .expect("udp open");

        // Pure-poll batch (no `d` payload) → had_writes_or_connects =
        // false → deadline = LONGPOLL_DEADLINE (15 s). Under the
        // previous tokio::join! wait, the UDP arm would have held the
        // response open for the full window even though TCP was
        // already drainable.
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "data", "sid": &tcp_sid},
                {"op": "udp_data", "sid": &udp_sid},
            ]
        })
        .to_string();

        let t0 = Instant::now();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let elapsed = t0.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "TCP-ready / UDP-idle pure-poll batch must not pay \
             LONGPOLL_DEADLINE; elapsed={:?}",
            elapsed,
        );
    }

    // ---------------------------------------------------------------------
    // wseq ordering protocol — server-side correctness.
    //
    // The pipelining client (`tunnel_client.rs`) sends data ops with a
    // monotonic `wseq` so that pipelined batches completing out of order
    // still get written upstream in the order the client read them off
    // the SOCKS5 socket. handle_batch's `data` op handler buffers
    // out-of-order writes in `inner.pending_writes` and flushes them in
    // sequence as the gaps fill. Without these tests, a refactor of
    // that block silently breaks upstream byte order — a class of bug
    // that's nearly invisible to manual testing because it only shows up
    // under specific scheduling.
    // ---------------------------------------------------------------------

    /// Helper for the wseq tests: install `inner` into `state.sessions`
    /// under `sid` and drive a single `data` op through `handle_batch`.
    /// The batch body is the smallest valid wire payload for a data op
    /// with a wseq attached.
    async fn drive_data_op_with_wseq(state: &AppState, sid: &str, wseq: u64, payload: &[u8]) {
        use axum::body::Bytes;
        use axum::extract::State;
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [{
                "op": "data",
                "sid": sid,
                "d": B64.encode(payload),
                "wseq": wseq,
            }]
        })
        .to_string();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
    }

    /// Drain whatever bytes the SessionInner's writer wrote to the
    /// upstream socket. Reads until we've collected `expected_len` bytes
    /// or the timeout fires (which lets a test assert "exactly N bytes,
    /// no trailing junk").
    async fn read_upstream_exact(
        server_side: &mut TcpStream,
        expected_len: usize,
        timeout: Duration,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(expected_len);
        let deadline = Instant::now() + timeout;
        let mut chunk = [0u8; 256];
        while out.len() < expected_len {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, server_side.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        out
    }

    /// In-order arrivals (wseq=0 then wseq=1) must write upstream in
    /// arrival order with no buffering. Establishes the baseline that
    /// the next three tests' assertions are compared against.
    #[tokio::test]
    async fn wseq_in_order_writes_pass_through_immediately() {
        let state = fresh_state();
        let (inner, mut server_side) = fake_inner_with_observer().await;
        let sid = "wseq-in-order".to_string();
        state.sessions.lock().await.insert(
            sid.clone(),
            ManagedSession {
                inner: inner.clone(),
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        drive_data_op_with_wseq(&state, &sid, 0, b"AAA").await;
        drive_data_op_with_wseq(&state, &sid, 1, b"BB").await;

        let upstream = read_upstream_exact(&mut server_side, 5, Duration::from_secs(2)).await;
        assert_eq!(&upstream[..], b"AAABB");

        // After both writes, pending_writes must be empty (nothing was
        // buffered for later) and next_write_seq has advanced past 1.
        let pending = inner.pending_writes.lock().await;
        assert!(pending.is_empty(), "in-order arrivals must not buffer");
        let nws = *inner.next_write_seq.lock().await;
        assert_eq!(nws, Some(2));
    }

    /// Out-of-order: wseq=1 arrives first, buffers; wseq=0 arrives
    /// second, the wseq=0 byte is written, then the buffered wseq=1
    /// byte flushes. Upstream sees the bytes in client-write order
    /// regardless of arrival order.
    #[tokio::test]
    async fn wseq_buffers_out_of_order_and_flushes_when_gap_fills() {
        let state = fresh_state();
        let (inner, mut server_side) = fake_inner_with_observer().await;
        let sid = "wseq-ooo".to_string();
        state.sessions.lock().await.insert(
            sid.clone(),
            ManagedSession {
                inner: inner.clone(),
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        // wseq=1 arrives first. Nothing should reach upstream yet.
        drive_data_op_with_wseq(&state, &sid, 1, b"second").await;
        let early =
            tokio::time::timeout(Duration::from_millis(150), server_side.read(&mut [0u8; 32]))
                .await;
        assert!(
            early.is_err(),
            "wseq=1 must not write upstream while wseq=0 is missing — got {:?}",
            early,
        );
        // pending_writes carries the buffered chunk.
        assert_eq!(inner.pending_writes.lock().await.len(), 1);

        // wseq=0 arrives. Should write "first" then drain the buffered
        // "second" in sequence.
        drive_data_op_with_wseq(&state, &sid, 0, b"first").await;
        let upstream = read_upstream_exact(&mut server_side, 11, Duration::from_secs(2)).await;
        assert_eq!(&upstream[..], b"firstsecond");

        // Buffer drained; next_write_seq advanced past both ops.
        assert!(inner.pending_writes.lock().await.is_empty());
        assert_eq!(*inner.next_write_seq.lock().await, Some(2));
    }

    /// Stale duplicate (wseq below `next_write_seq`) must be dropped
    /// silently — never written, never buffered. This is the "duplicate
    /// retry" failure mode: a client re-sends an op the server already
    /// flushed, and we must not double-write.
    #[tokio::test]
    async fn wseq_drops_stale_duplicate_silently() {
        let state = fresh_state();
        let (inner, mut server_side) = fake_inner_with_observer().await;
        let sid = "wseq-stale".to_string();
        state.sessions.lock().await.insert(
            sid.clone(),
            ManagedSession {
                inner: inner.clone(),
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        // Advance next_write_seq to 2 by sending wseq 0 then 1.
        drive_data_op_with_wseq(&state, &sid, 0, b"X").await;
        drive_data_op_with_wseq(&state, &sid, 1, b"Y").await;
        let initial = read_upstream_exact(&mut server_side, 2, Duration::from_secs(1)).await;
        assert_eq!(&initial[..], b"XY");
        assert_eq!(*inner.next_write_seq.lock().await, Some(2));

        // Now replay wseq=0 — must NOT be written upstream and must
        // NOT pollute pending_writes.
        drive_data_op_with_wseq(&state, &sid, 0, b"REPLAY").await;
        let dup =
            tokio::time::timeout(Duration::from_millis(150), server_side.read(&mut [0u8; 32]))
                .await;
        assert!(
            dup.is_err(),
            "stale duplicate must produce no upstream write"
        );
        assert!(inner.pending_writes.lock().await.is_empty());
        assert_eq!(*inner.next_write_seq.lock().await, Some(2));
    }

    /// Exceeding `MAX_PENDING_WRITES_PER_SESSION` closes the session:
    /// the offending op gets an error response, and `state.sessions`
    /// no longer holds the sid (preventing further out-of-order writes
    /// from consuming server memory).
    #[tokio::test]
    async fn wseq_cap_exceeded_closes_session_and_errors_op() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();
        let (inner, mut _server_side) = fake_inner_with_observer().await;
        let sid = "wseq-cap".to_string();
        state.sessions.lock().await.insert(
            sid.clone(),
            ManagedSession {
                inner: inner.clone(),
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        // Fill pending_writes to exactly the cap by sending
        // `MAX_PENDING_WRITES_PER_SESSION` non-zero wseqs (each
        // out-of-order because wseq=0 never arrives). These succeed.
        for i in 1..=MAX_PENDING_WRITES_PER_SESSION as u64 {
            drive_data_op_with_wseq(&state, &sid, i, b"x").await;
        }
        assert_eq!(
            inner.pending_writes.lock().await.len(),
            MAX_PENDING_WRITES_PER_SESSION,
        );
        assert!(state.sessions.lock().await.contains_key(&sid));

        // One more out-of-order op triggers the cap. The batch response
        // must surface "wseq buffer cap exceeded" and the session must
        // be removed from state.sessions.
        let trigger_wseq = (MAX_PENDING_WRITES_PER_SESSION as u64) + 1;
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [{
                "op": "data",
                "sid": &sid,
                "d": B64.encode(b"x"),
                "wseq": trigger_wseq,
            }]
        })
        .to_string();
        let resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("response JSON parses");
        let err = parsed["r"][0]["e"].as_str().unwrap_or("");
        assert!(
            err.contains("wseq buffer cap exceeded"),
            "cap-triggering op must return the exact error string, got: {}",
            err,
        );
        assert!(
            !state.sessions.lock().await.contains_key(&sid),
            "session must be removed when the cap fires",
        );
    }
}
