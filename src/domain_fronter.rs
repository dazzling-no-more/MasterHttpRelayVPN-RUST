//! Apps Script relay client.
//!
//! Opens a TLS connection to the configured Google IP while the TLS SNI is set
//! to `front_domain` (e.g. "www.google.com"). Inside the encrypted stream, HTTP
//! `Host` points to `script.google.com`, and we POST a JSON payload to
//! `/macros/s/{script_id}/exec`. Apps Script performs the actual upstream
//! HTTP fetch server-side and returns a JSON envelope.
//!
//! Multiplexes over HTTP/2 when the relay edge agrees via ALPN; falls back
//! to HTTP/1.1 keep-alive when h2 is refused or fails. Range-parallel
//! downloads are implemented by `relay_parallel_range_to` (writer-based,
//! streams files larger than Apps Script's single-GET ceiling) with a
//! buffered `relay_parallel_range` compatibility wrapper for callers that
//! want a `Vec<u8>` back.

use std::collections::HashMap;

use arc_swap::ArcSwap;
// AtomicU64 via portable-atomic: native on 64-bit / armv7, spinlock-
// backed on mipsel (MIPS32 has no 64-bit atomic instructions). API
// is identical to std::sync::atomic::AtomicU64 so call sites need
// no other changes.
use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use rand::{thread_rng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use crate::cache::{cache_key, is_cacheable_method, parse_ttl, ResponseCache};
use crate::config::Config;

#[derive(Debug, thiserror::Error)]
pub enum FronterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid dns name: {0}")]
    Dns(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("relay error: {0}")]
    Relay(String),
    #[error("timeout")]
    Timeout,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Wraps another error and tells outer retry/fallback layers
    /// (`do_relay_with_retry`, the exit-node→direct-Apps-Script
    /// fallback in `relay()`) NOT to replay the request. Used when an
    /// h2 attempt failed *after* `send_request` succeeded — the
    /// request may have already reached and been processed by Apps
    /// Script (or the exit node), and replaying via h1 / direct path
    /// would duplicate side effects for non-idempotent methods.
    ///
    /// `Display` is transparent so error messages look identical to
    /// the wrapped variant; tests/observability use `is_retryable()`
    /// and `into_inner()` to introspect.
    #[error(transparent)]
    NonRetryable(Box<FronterError>),
}

impl FronterError {
    /// True if outer retry/fallback layers may safely re-issue the
    /// request. False for `NonRetryable(_)` — those errors signal
    /// "request may have been sent; do not duplicate."
    pub fn is_retryable(&self) -> bool {
        !matches!(self, FronterError::NonRetryable(_))
    }

    /// Strip the `NonRetryable` wrapper, returning the underlying
    /// error. Useful for surfacing the original message after the
    /// retry/fallback policy has already done its job.
    pub fn into_inner(self) -> FronterError {
        match self {
            FronterError::NonRetryable(inner) => *inner,
            other => other,
        }
    }
}

type PooledStream = TlsStream<TcpStream>;
const POOL_TTL_SECS: u64 = 60;
const POOL_MIN: usize = 8;
const POOL_REFILL_INTERVAL_SECS: u64 = 5;
const POOL_MAX: usize = 80;
const REQUEST_TIMEOUT_SECS: u64 = 25;
const RANGE_PARALLEL_CHUNK_BYTES: u64 = 256 * 1024;
/// Inclusive ms range for jittered backoff between per-chunk retries in
/// `fetch_chunks_stream`. Tuned for the single-script-id case where
/// retries land on the same Apps Script project: long enough to let a
/// stuck server-side execution finish/time out (REQUEST_TIMEOUT_SECS
/// caps it at 25 s but the script may complete sooner), short enough
/// not to add user-visible latency on transient failures. Multi-script
/// configs rotate inside `relay()` anyway so the backoff is harmless.
const CHUNK_RETRY_BACKOFF_RANGE_MS: std::ops::RangeInclusive<u64> = 200..=600;
/// HTTP/2 connection lifetime before we proactively reopen. Apps Script's
/// edge has been observed to send GOAWAY at ~10 min anyway, so we cycle
/// at 9 min to do an orderly reconnect on our schedule rather than
/// letting an in-flight stream race a server-initiated close.
const H2_CONN_TTL_SECS: u64 = 540;
/// Bound on the h2 ready/back-pressure phase only. `SendRequest::ready()`
/// awaits a free slot under the server's `MAX_CONCURRENT_STREAMS`. A
/// stall here means the connection is overloaded (or dead at the
/// muxer level) but no stream has been opened yet — RequestSent::No,
/// safe to fall back to h1 without duplication risk. Kept short
/// (5 s) so a saturated conn doesn't burn the caller's whole budget.
///
/// The post-send phase (response headers + body drain) uses the
/// caller-supplied `response_deadline` instead — see
/// `h2_round_trip`. This way a slow but legitimate Apps Script call
/// isn't cut off at an arbitrary fixed cap, and Full-mode batches can
/// honor the user's `request_timeout_secs` setting.
const H2_READY_TIMEOUT_SECS: u64 = 5;
/// Default response-phase deadline used by `relay_uncoalesced` callers
/// (the Apps-Script direct path). Sized to be just under the outer
/// `REQUEST_TIMEOUT_SECS` (25 s) so an h2 timeout still leaves a few
/// seconds of outer budget for an h1 fallback round-trip when the
/// caller chose to retry.
const H2_RESPONSE_DEADLINE_DEFAULT_SECS: u64 = 20;
/// Bound on the TCP connect + TLS handshake + h2 handshake phase. A
/// blackholed `connect_host:443` previously stalled `ensure_h2` until
/// the outer 25 s timeout fired (returning 504 without ever falling
/// back). With this bound, a slow open trips after 8 s and the caller
/// drops to h1 with ~17 s of outer budget to spare.
const H2_OPEN_TIMEOUT_SECS: u64 = 8;
/// After an h2 open failure, suppress further open attempts for this
/// long. Prevents every concurrent caller during an h2 outage from
/// paying its own full handshake-timeout cost in turn.
const H2_OPEN_FAILURE_BACKOFF_SECS: u64 = 15;
/// Cadence for h2 application-level PINGs on the live connection.
/// Without this, a blackholed TCP socket (RST eaten by middlebox,
/// common on Iran ISPs for long-lived flows to YouTube / Telegram-web
/// / x.com) leaves the h2 `Connection` future blocked indefinitely on
/// a read that never errors. The cell looks "alive" to `ensure_h2`
/// and every queued request stalls until the app is restarted.
const H2_PING_INTERVAL: Duration = Duration::from_secs(15);
/// Budget for the PONG to arrive after a PING is sent. Iran→Google
/// typical RTT is 200–400 ms; 10 s is ~25× that, generous enough that
/// transient mobile / WiFi jitter won't false-positive-close a healthy
/// connection. Combined with `H2_PING_INTERVAL` the worst-case detection
/// latency for a fully-dead socket is interval + timeout ≈ 25 s.
const H2_PING_TIMEOUT: Duration = Duration::from_secs(10);
/// Same idea as `H2_OPEN_TIMEOUT_SECS` but for the legacy h1 socket
/// path. Without this, a stuck TCP connect or TLS handshake to a
/// blackholed `connect_host:443` would block `acquire()` (and the
/// `warm()` prewarm loop) until the outer batch budget elapsed —
/// the same symptom #924 hit during the warm-race window. Bounded
/// here so a single hung handshake aborts fast and the loop / caller
/// makes progress on the next attempt.
const H1_OPEN_TIMEOUT_SECS: u64 = 8;
/// Cadence for Apps Script container keepalive pings. Apps Script
/// containers go cold after ~5min idle and cost 1-3s on the first
/// request to wake back up — most painful on YouTube / streaming where
/// the first chunk after a quiet pause stalls the player.
const H1_KEEPALIVE_INTERVAL_SECS: u64 = 240;
/// Largest response body Apps Script's `UrlFetchApp` will deliver before
/// the script gets killed mid-execution. The hard wire ceiling is ~50 MiB;
/// after base64 / envelope overhead and edge variance, the practical raw
/// ceiling for a single GET sits around 40 MiB. This bounds the
/// **writer-based** API's streaming threshold: above this, the buffered
/// stitch path's single-GET fallback wouldn't fit through Apps Script
/// even if invoked, so streaming chunks straight to the wire (with
/// truncate-on-failure semantics the client can resume via Range)
/// strictly beats today's 25 s timeout + 504 "Apps Script
/// unresponsive" (#1042).
const APPS_SCRIPT_BODY_MAX_BYTES: u64 = 40 * 1024 * 1024;

/// Hard ceiling on how many bytes the streaming side of the
/// range-parallel path will fetch for a single response. A hostile
/// origin can advertise an absurd `Content-Range` total
/// (`bytes 0-262143/<huge>`), pass our probe-checks with a normally-
/// sized 256 KiB first-chunk body, and then drive us to keep issuing
/// chunk Apps Script calls until the client disconnects. Each chunk
/// is one Apps Script invocation, counting against the account's
/// daily quota (~20 k requests/day on the free tier), so an
/// unattended hostile download can exhaust the quota and lock the
/// user out of the relay entirely.
///
/// 16 GiB is well above any legitimate single-file download a user
/// is likely to do through a relay VPN (game patches, OS images,
/// video files all fit) but small enough to bound worst-case quota
/// drain to ~65 k chunks per pwned URL. Above this cap the streaming
/// branch refuses the response with a 502 instead of plowing
/// through.
const MAX_STREAMED_RANGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Byte interval between `range-parallel-stream` progress log lines.
/// Large downloads through the streaming branch otherwise look stuck
/// in the logs (one "starting N chunks" line at the top, nothing
/// until completion or failure). At 16 MiB intervals the operator sees
/// ~6 lines per 100 MiB and ~64 lines per 1 GiB — useful pace at the
/// ~1.4 MB/s typical through-relay throughput, and quiet enough that
/// even a 16 GiB file won't drown the log (~1024 progress lines over
/// the multi-hour download). Per user feedback on PR #1085.
const STREAM_PROGRESS_LOG_INTERVAL_BYTES: u64 = 16 * 1024 * 1024;

/// Hard ceiling on the buffered stitch buffer's `Vec::with_capacity(total)`
/// allocation. Two roles:
///
///   1. Memory-safety cap. A hostile/buggy origin advertising
///      `Content-Range: bytes 0-1/<huge>` could otherwise drive
///      preallocation to enormous values; totals above this either
///      stream (writer-based API) or fall back to a single GET
///      (`Vec<u8>` compatibility wrapper, see
///      [`DomainFronter::relay_parallel_range`]).
///   2. Pre-1.9.23 compatibility floor for the `Vec<u8>` wrapper.
///      Range-capable downloads in the 40-64 MiB band used to stitch
///      successfully via the buffered path; collapsing this constant
///      into [`APPS_SCRIPT_BODY_MAX_BYTES`] would have pushed those
///      onto the single-GET fallback path, where Apps Script returns
///      502/504 because they're above its 50 MiB response ceiling.
///      Keeping the two cutoffs separate restores that band's
///      working buffered behavior for wrapper callers.
const BUFFERED_STITCH_MAX_BYTES: u64 = 64 * 1024 * 1024;

struct PoolEntry {
    stream: PooledStream,
    created: Instant,
    /// The `connect_host` snapshot this socket was opened against.
    /// `run_ip_health` swaps `connect_host` to a fresh `Arc<String>`
    /// when the active IP becomes unreachable; entries opened against
    /// a prior snapshot are stale because they're still bound to the
    /// old IP. `acquire` / `release` / `run_pool_refill` test
    /// `Arc::ptr_eq` against the current snapshot and drop on
    /// mismatch so the pool can't accumulate connections to a
    /// just-swapped-out IP. The Arc clone is cheap (refcount bump).
    host: Arc<String>,
}

/// Single shared HTTP/2 connection to the Google edge. One TCP/TLS
/// socket carries up to ~100 concurrent streams (server's
/// `MAX_CONCURRENT_STREAMS` setting); each relay request takes a clone
/// of the `SendRequest` handle and opens its own stream. Cheaper than
/// the legacy per-request socket pool — no head-of-line blocking when
/// a single Apps Script call stalls.
///
/// `generation` is monotonic per fronter and lets `poison_h2_if_gen`
/// avoid the race where task A's stale failure clears task B's
/// freshly-reopened healthy cell.
///
/// `dead` is set by the spawned connection-driver task when the h2
/// `Connection` future ends (GOAWAY, network error, normal close).
/// Without this, the cell silently held a dead `SendRequest` after a
/// mid-session disconnect — the next request paid a wasted h2 round
/// trip to detect it via `ready()` failure, AND `run_pool_refill`
/// kept maintaining the small `POOL_MIN_H2_FALLBACK` (2-socket) pool
/// instead of expanding to `POOL_MIN` (8). With the flag,
/// `run_pool_refill` notices h2 is dead within one tick (≤5 s) and
/// pre-warms the larger fallback pool before the next request burst,
/// and `ensure_h2` short-circuits the `H2_CONN_TTL_SECS`-based
/// liveness check on a known-dead cell.
struct H2Cell {
    send: h2::client::SendRequest<Bytes>,
    created: Instant,
    generation: u64,
    dead: Arc<AtomicBool>,
    /// The `connect_host` snapshot the h2 connection was opened
    /// against. Compared via `Arc::ptr_eq` against the live
    /// `connect_host` on every cache read so a heartbeat swap that
    /// landed in the window between "open completed → cell stored"
    /// and "swap-path runs `*h2_cell = None`" can still be detected
    /// — ensure_h2's reader paths reject the cached entry and
    /// reopen against the new host. See `connect_host` doc-comment
    /// for the rationale.
    host: Arc<String>,
}

/// "Did this request reach Apps Script?" signal carried out of every
/// h2 failure so callers know whether replaying via h1 is safe.
///
/// - `No`: the failure occurred before `send_request` returned. The
///   stream was never opened on the wire; replaying through h1 is
///   guaranteed not to duplicate any side effect.
/// - `Maybe`: `send_request` succeeded (headers queued for sending)
///   but a later step failed — server may have already received the
///   request and may already be processing it. Replaying a
///   non-idempotent op (POST/PUT/DELETE, tunnel write, batch ops)
///   risks duplicating side effects. Only safe to retry for methods
///   that are idempotent by HTTP semantics.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum RequestSent {
    No,
    Maybe,
}

/// Typed errors from `open_h2`. Used so `ensure_h2` can recognize the
/// "peer refused h2 in ALPN" outcome and sticky-disable the fast path
/// without resorting to string matching across function boundaries.
#[derive(Debug, thiserror::Error)]
enum OpenH2Error {
    #[error("ALPN did not negotiate h2; peer prefers http/1.1")]
    AlpnRefused,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("dns: {0}")]
    Dns(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("h2 handshake: {0}")]
    Handshake(String),
}

impl From<OpenH2Error> for FronterError {
    fn from(e: OpenH2Error) -> Self {
        match e {
            OpenH2Error::Io(e) => FronterError::Io(e),
            OpenH2Error::Tls(e) => FronterError::Tls(e),
            OpenH2Error::Dns(e) => FronterError::Dns(e),
            OpenH2Error::AlpnRefused => FronterError::Relay("alpn refused h2".into()),
            OpenH2Error::Handshake(m) => FronterError::Relay(format!("h2 handshake: {}", m)),
        }
    }
}

pub struct DomainFronter {
    /// Active Google front IP for TCP+TLS open. `ArcSwap` so the
    /// background heartbeat loop (`run_ip_health`) can swap in a fresh
    /// candidate when the current IP becomes unreachable, without
    /// locking out the hot `open()` / `open_h2()` paths that read it
    /// on every connection.
    ///
    /// Each swap installs a *fresh* `Arc<String>`. Code that needs to
    /// detect "did the host change while I was opening?" captures
    /// `Arc<String>` via `load_full()` before calling `open()` (or
    /// receives it back from `open()` / `open_h2()`) and compares
    /// pointer identity with `Arc::ptr_eq` against a later
    /// `load_full()`. That gives a single atomic
    /// "host-state-changed" signal — no separate generation counter,
    /// no torn read between host and version. Pool entries also
    /// carry their opening Arc so `acquire` / `release` /
    /// `run_pool_refill` can drop stale connections.
    connect_host: ArcSwap<String>,
    /// Pool of SNI domains to rotate through per outbound connection. All of
    /// them must be hosted on the same Google edge as `connect_host` (that's
    /// the whole point of domain fronting). Rotating across several of them
    /// defeats naive DPI that would count "too many connections to a single
    /// SNI". Populated from config's front_domain: if that's a single name we
    /// add a small pool of known-safe Google subdomains automatically.
    sni_hosts: Vec<String>,
    sni_idx: AtomicUsize,
    http_host: &'static str,
    auth_key: String,
    script_ids: Vec<String>,
    script_idx: AtomicUsize,
    /// Fan-out factor: fire this many Apps Script instances in parallel
    /// per request and return first success. `<= 1` = off.
    parallel_relay: usize,
    /// Enable the `normalize_x_graphql` URL rewrite (issue #16, credit
    /// seramo_ir). When true, GETs to `x.com/i/api/graphql/<hash>/<op>`
    /// have their query trimmed to the first `variables=` block so the
    /// response cache isn't busted by the constantly-changing `features`
    /// / `fieldToggles` params.
    normalize_x_graphql: bool,
    /// Opt-in: allow `br` / `zstd` in the outbound `Accept-Encoding`
    /// forwarded to destinations through Apps Script, and decode such
    /// bodies on the way back. When `false` (the historical default),
    /// `filter_forwarded_headers` strips br/zstd from client
    /// `Accept-Encoding` so destinations only ever respond with
    /// gzip/identity that `UrlFetchApp` auto-decodes. See
    /// `Config::allow_brotli_zstd` for the full rationale.
    allow_brotli_zstd: bool,
    /// Set once we've emitted the "UnknownIssuer means ISP MITM" hint,
    /// so we don't spam it every time a cert-validation error repeats.
    cert_hint_shown: std::sync::atomic::AtomicBool,
    /// Connector used by `open_h2`: advertises ALPN `["h2", "http/1.1"]`
    /// when the h2 fast path is enabled, else just `["http/1.1"]`. Never
    /// used by the h1 pool path — see `tls_connector_h1`.
    tls_connector: TlsConnector,
    /// Connector used by `open()` (h1 pool warm/refill/acquire). ALPN
    /// is forced to `["http/1.1"]` so a Google edge that would have
    /// preferred h2 still negotiates h1 here. Without this, pooled
    /// sockets could end up speaking h2 frames after handshake, and
    /// the `write_all(b"GET / HTTP/1.1\r\n...")` fallback would land
    /// on a server that has no idea what we're doing.
    tls_connector_h1: TlsConnector,
    pool: Arc<Mutex<Vec<PoolEntry>>>,
    /// HTTP/2 fast path. `None` until first relay opens it; cleared on
    /// connection failure or expiry so the next call reopens. Skipped
    /// entirely when `force_http1` is set or when the peer refused h2
    /// during ALPN (sticky `h2_disabled`).
    h2_cell: Arc<Mutex<Option<H2Cell>>>,
    /// Serializes "open a new h2 connection" attempts so that during
    /// an outage, only one task pays the handshake cost — concurrent
    /// callers see the lock contended via `try_lock` and fall through
    /// to h1 immediately rather than queueing behind a slow handshake.
    /// Distinct from `h2_cell` so the cell mutex is never held across
    /// network I/O.
    h2_open_lock: Arc<Mutex<()>>,
    /// Wall-clock timestamp of the last failed `open_h2`. While within
    /// `H2_OPEN_FAILURE_BACKOFF_SECS` of this, `ensure_h2` returns None
    /// without retrying — prevents thundering-herd handshake attempts
    /// during transient h2 outages.
    h2_open_failed_at: Arc<Mutex<Option<Instant>>>,
    /// Monotonic counter for `H2Cell::generation`. Each successful
    /// `open_h2` increments and tags the new cell so `poison_h2_if_gen`
    /// can avoid the race where a stale failure clears a freshly-opened
    /// cell that another task just installed.
    h2_generation: Arc<AtomicU64>,
    /// Set when ALPN negotiates http/1.1 (peer refused h2) or when
    /// `force_http1` is true. Sticky for the lifetime of the fronter:
    /// once we know this peer doesn't speak h2, don't keep retrying
    /// the handshake on every relay call.
    h2_disabled: Arc<AtomicBool>,
    cache: Arc<ResponseCache>,
    inflight: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>>,
    coalesced: AtomicU64,
    blacklist: Arc<std::sync::Mutex<HashMap<String, BlacklistEntry>>>,
    /// Per-deployment rolling timeout counter. Maps `script_id` →
    /// `(window_start, strike_count)`. Reset when the window expires
    /// or when a batch succeeds. Triggers a short-cooldown blacklist
    /// at `TIMEOUT_STRIKE_LIMIT`. Distinct from `blacklist` because
    /// strike state is per-deployment health bookkeeping, not the
    /// permanent ban list.
    script_timeouts: Arc<std::sync::Mutex<HashMap<String, (Instant, u32)>>>,
    /// Per-deployment EWMA of recent successful batch RTT, in
    /// milliseconds, alongside the time of the last fold. Updated by
    /// [`record_batch_latency`] after each successful batch (failed
    /// batches are excluded — their elapsed time is whatever timeout
    /// fired, not the deployment's actual throughput). Read by
    /// [`next_script_id`] to deprioritize deployments running
    /// materially slower than peers. The timestamp lets the slow-set
    /// snapshot expire stale entries so a deployment marked slow
    /// gets a fresh probe pick after `LATENCY_FRESH_FOR_SECS`.
    script_latency_ewma: Arc<std::sync::Mutex<HashMap<String, (f64, Instant)>>>,
    relay_calls: AtomicU64,
    relay_failures: AtomicU64,
    bytes_relayed: AtomicU64,
    /// Relay calls that successfully completed over the h2 fast path,
    /// across **all** entry points: Apps-Script direct relays,
    /// exit-node outer calls, full-mode tunnel single ops, and
    /// full-mode tunnel batches.
    ///
    /// **Not** comparable to `relay_calls`: that counter only counts
    /// the Apps-Script-direct path (incremented in `relay_uncoalesced`).
    /// The other three paths bypass `relay_uncoalesced` entirely, so in
    /// full-mode deployments `h2_calls` can exceed `relay_calls` —
    /// reading their ratio as a "% on h2" gives a wrong number.
    ///
    /// To gauge h2 health, compute `h2_calls / (h2_calls + h2_fallbacks)`.
    /// That's the success ratio across all transports; a healthy
    /// deployment shows > 95 %.
    h2_calls: AtomicU64,
    /// Relay calls that attempted h2 but had to fall back to h1
    /// (transient handshake failure, mid-stream error, conn poisoned,
    /// open backoff, or `RequestSent::No` failure that the call site
    /// chose to retry on h1). Same all-entry-points scope as
    /// `h2_calls`. A persistently high `h2_fallbacks / (h2_calls +
    /// h2_fallbacks)` ratio indicates an unhealthy h2 conn or a flaky
    /// middlebox eating h2 frames; consider `force_http1: true`.
    h2_fallbacks: AtomicU64,
    /// Successful SNI-rewrite HTTP forwarder calls (the b3b9220 path —
    /// non-`/youtubei/` paths on `force_mitm_hosts` taking the direct
    /// SNI-rewrite TLS path instead of burning Apps Script quota).
    /// Counts upstream-fetch success: incremented as soon as the
    /// forwarder has the response bytes in hand, BEFORE writing to the
    /// browser. A client-disconnect during the downstream write still
    /// counts — the path filter did upstream work, that's the metric.
    /// Useful for diagnosing reports like #977: a high
    /// `forwarder_calls / (forwarder_calls + relay_calls)` ratio means
    /// the path filter is doing its job; a near-zero ratio means it's
    /// inert (and any reported regression isn't from the forwarder).
    forwarder_calls: AtomicU64,
    /// Response bytes successfully fetched by the forwarder from the
    /// upstream (Google edge). Same upstream-fetch-success semantic as
    /// `forwarder_calls`.
    forwarder_bytes: AtomicU64,
    /// Forwarder dispatch errors — connect failure, TLS error, read
    /// timeout, response cap exceeded, or upstream EOF before any
    /// bytes. Counts the forwarder fast-path miss; says nothing about
    /// whether the subsequent relay-path fallback recovered the
    /// request. Use `relay_failures` for request-failure counting.
    forwarder_errors: AtomicU64,
    /// Per-host breakdown of traffic going through this fronter. Keyed by
    /// the host of the URL (e.g. "api.x.com"). Read-mostly; only touched
    /// on the slow path (once per relayed request), so a plain Mutex is
    /// fine.
    per_site: Arc<std::sync::Mutex<HashMap<String, HostStat>>>,
    /// Daily-scoped counters, reset at 00:00 UTC. Tracks what *this
    /// rahgozar process* has observed today — NOT the authoritative
    /// Apps Script quota bucket on Google's side (which counts across
    /// every client hitting the same deployment). Useful as a local
    /// "budget used today" estimate in the UI.
    ///
    /// Both counters rebase to zero the first time any recording call
    /// crosses a UTC date boundary. `day_key` holds "YYYY-MM-DD" of
    /// the currently-counted day; when we see a new date we swap and
    /// clear the counters.
    today_calls: AtomicU64,
    today_bytes: AtomicU64,
    today_key: std::sync::Mutex<String>,
    /// Suppress the random `_pad` field that v1.8.0+ adds to outbound
    /// payloads. Mirrors `Config::disable_padding` (#391). Default false
    /// (padding active = stronger DPI defense at +25% bandwidth cost).
    disable_padding: bool,
    zstd_enabled: Arc<AtomicBool>,
    /// Per-instance auto-blacklist tuning. Mirrors `Config::auto_blacklist_*`
    /// (#391, #444). Cached here so the hot path in `record_timeout_strike`
    /// doesn't have to reach back through the Config (which we don't keep
    /// a reference to).
    auto_blacklist_strikes: u32,
    auto_blacklist_window: Duration,
    auto_blacklist_cooldown: Duration,
    /// Per-batch HTTP timeout. Mirrors `Config::request_timeout_secs`
    /// (#430, masterking32 PR #25). Read by `tunnel_client::fire_batch`
    /// so a single config field tunes the timeout used everywhere.
    batch_timeout: Duration,
    /// Optional second-hop exit node (Deno Deploy / fly.io / etc.)
    /// to bypass CF-anti-bot blocks on sites that flag Google datacenter
    /// IPs (chatgpt.com, claude.ai, grok.com, x.com). Mirrors
    /// `Config::exit_node`. When `exit_node_enabled` is false (the more
    /// common state), all relay traffic takes the regular Apps Script
    /// path. When true, hosts matching `exit_node_hosts` (or all hosts
    /// when `exit_node_full`) route through the exit-node URL inside
    /// the Apps Script call.
    exit_node_enabled: bool,
    exit_node_url: String,
    exit_node_psk: String,
    exit_node_full: bool,
    /// Pre-normalized (lowercased, leading-dot stripped) host list for
    /// fast O(N) match in `exit_node_matches`.
    exit_node_hosts: Vec<String>,
    /// Strip SABR quality-track entries from `/videoplayback` POST
    /// bodies. Mirrors `Config::sabr_strip`. Default `true`. Kill-switch
    /// for users who hit the speed-up-playback buffering regression
    /// reported in #977. See config.rs `sabr_strip` for the full
    /// trade-off.
    sabr_strip: bool,
    /// Language hint passed to Apps Script as `?hl=<lang>` on every
    /// `/macros/s/<sid>/exec` request. Pinned to English by default so
    /// the envelope classifier patterns match. Mirrors
    /// `Config::apps_script_lang`. Sanitised at construction by
    /// [`Config::apps_script_lang_resolved`].
    apps_script_lang: String,
    /// Pre-built `Accept-Language` header value derived from
    /// `apps_script_lang`. Stored as a string so it's a single Bytes
    /// reference per request rather than a per-call format!. Built once
    /// via [`accept_language_for_lang`] in [`DomainFronter::new`].
    apps_script_accept_lang: String,
}

/// Aggregated stats for one remote host.
#[derive(Default, Clone, Debug)]
pub struct HostStat {
    pub requests: u64,
    pub cache_hits: u64,
    pub bytes: u64,
    pub total_latency_ns: u64,
}

impl HostStat {
    pub fn avg_latency_ms(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            (self.total_latency_ns as f64) / (self.requests as f64) / 1_000_000.0
        }
    }
}

const BLACKLIST_COOLDOWN_SECS: u64 = 600;

/// EWMA weight for the most recent batch RTT. 0.3 makes the score
/// responsive to a deployment that just sped up or slowed down without
/// being dominated by a single outlier sample.
const LATENCY_EWMA_ALPHA: f64 = 0.3;
/// Skip a deployment from `next_script_id` when its EWMA exceeds the
/// group median by this multiple. Tuned so a deployment running 2-3×
/// slower than peers (the typical "Apps Script is having a bad minute"
/// pattern) drops out of selection without ejecting one that is merely
/// 20-30% slower from quota or h2-warmup effects.
const LATENCY_SLOW_THRESHOLD: f64 = 2.0;
/// Skip-logic stays inert below this many configured deployments. With
/// only one or two, the "skip the slow one" rule would either be a
/// no-op (1 deployment) or oscillate (2 deployments — median equals
/// whichever sample arrived last). Three is the smallest size where a
/// stable median exists.
const LATENCY_MIN_DEPLOYMENTS: usize = 3;
/// Skip-logic stays inert below this median. When everyone is already
/// fast (median < 500 ms), a 2× outlier is still a fine batch and
/// kicking it out of round-robin just churns the selector for no win.
const LATENCY_SKIP_MIN_MEDIAN_MS: f64 = 500.0;
/// Successful tunnel batches above this wall-clock RTT are user-visible
/// tail-latency outliers, even if the deployment's EWMA has not drifted
/// above the relative median threshold yet. Cool the deployment down
/// immediately so bursts don't keep landing on a currently-slow Apps
/// Script container/account.
const LATENCY_HARD_SLOW_BATCH_MS: f64 = 6000.0;
/// Short cooldown for a hard-slow successful batch. Kept equal to the
/// latency freshness window so the deployment naturally re-enters for a
/// probe pick after the same period EWMA slow entries age out.
const LATENCY_HARD_SLOW_COOLDOWN_SECS: u64 = LATENCY_FRESH_FOR_SECS;
/// How long an EWMA sample stays "fresh" for the slow-set decision.
/// Past this age, the entry is ignored by both the median calculation
/// and the slow-set filter — effectively letting the deployment back
/// into rotation. Without an expiry, a deployment marked slow would
/// never be picked again (no new sample → EWMA frozen high → still
/// slow forever), so a transient bad minute could permanently
/// blacklist it. With 30 s, a long-skipped deployment gets a probe
/// pick the next time its turn comes around, and either recovers
/// (new sample folds in lower, exits slow-set) or stays out for
/// another 30 s.
const LATENCY_FRESH_FOR_SECS: u64 = 30;

/// Filter `map` down to entries whose timestamp is within `fresh` of
/// `now`, projecting away the timestamp. Pure helper so the staleness
/// filter has direct unit coverage without standing up a live fronter
/// or fighting `std::time::Instant`'s wall-clock-only semantics.
fn fresh_latency_snapshot(
    map: &HashMap<String, (f64, Instant)>,
    now: Instant,
    fresh: Duration,
) -> HashMap<String, f64> {
    map.iter()
        .filter(|(_, (_, ts))| now.duration_since(*ts) < fresh)
        .map(|(k, (score, _))| (k.clone(), *score))
        .collect()
}

/// Set of script IDs whose recent EWMA latency is materially worse
/// than the group median. The selector skips these in round-robin so
/// a deployment having a slow minute (Apps Script quota throttle, h2
/// stream contention, etc.) doesn't repeatedly stall handshake-stage
/// traffic. Pure function over the EWMA snapshot — easy to unit-test
/// without standing up a live fronter. See `LATENCY_SLOW_THRESHOLD`
/// and the two `LATENCY_*_MIN_*` guards for the inertness conditions.
fn compute_slow_set(ewma_snapshot: &HashMap<String, f64>) -> std::collections::HashSet<String> {
    use std::collections::HashSet;
    if ewma_snapshot.len() < LATENCY_MIN_DEPLOYMENTS {
        return HashSet::new();
    }
    let mut values: Vec<f64> = ewma_snapshot.values().copied().collect();
    // f64 has no total ordering due to NaN, but our values come from
    // `Duration::as_secs_f64() * 1000.0` so NaN is unreachable here;
    // `partial_cmp().unwrap_or(Equal)` is the safe-by-fallback form.
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = values[values.len() / 2];
    if median < LATENCY_SKIP_MIN_MEDIAN_MS {
        return HashSet::new();
    }
    let threshold = median * LATENCY_SLOW_THRESHOLD;
    ewma_snapshot
        .iter()
        .filter(|(_, &v)| v > threshold)
        .map(|(k, _)| k.clone())
        .collect()
}

/// Outcome of [`DomainFronter::apply_probe_recovery`] — the
/// compare-and-swap step the probe loop runs after a recovery-
/// indicating relay round-trip. Public-by-`pub(crate)` so tests can
/// drive the post-decision logic without instantiating a live relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeApplyResult {
    /// The captured `until` still matched the live entry; the entry
    /// was removed.
    Cleared,
    /// The captured `until` no longer matched — a concurrent
    /// blacklist write landed between probe issue and probe completion
    /// (cooldown extended, new probe-disowned reason). The clear is
    /// declined so the in-flight extension isn't silently undone.
    RewrittenInFlight,
    /// The entry was no longer in the map at CAS time (TTL expired
    /// during the probe).
    AlreadyExpired,
}

/// One entry of `DomainFronter::blacklist`. Carries the cooldown expiry
/// plus a `probe_recoverable` flag so the background probe loop knows
/// which entries it owns. Without that flag, a generic `example.com`
/// probe success could clear entries created for reasons the probe
/// never checked — most notably `record_timeout_strike` entries whose
/// trigger is a network-level stall rather than a deployment-side
/// failure the probe would diagnose.
#[derive(Clone, Copy, Debug)]
struct BlacklistEntry {
    /// Wall-clock deadline. Entry stays in the map until either the
    /// probe loop clears it (when `probe_recoverable`) or `Instant::now()`
    /// passes this value (every blacklist consumer prunes on read).
    until: Instant,
    /// `true` when the entry was added for a reason the example.com
    /// probe path can validate: an envelope-classified permanent
    /// failure (quota/auth/deploy/admin) or an HTTP 429/403 from the
    /// Apps Script edge. `false` when the entry was added by
    /// [`DomainFronter::record_timeout_strike`] — probing those would
    /// risk silent recovery on a still-broken deployment because
    /// rolling timeouts can stem from causes the probe doesn't
    /// reproduce (transient network stall, slow client tunnel write,
    /// etc.).
    probe_recoverable: bool,
}

/// Lower bound of the randomized probe interval (seconds). See
/// [`SCRIPT_PROBE_INTERVAL_MAX`].
const SCRIPT_PROBE_INTERVAL_MIN_SECS: u64 = 300;
/// Upper bound of the randomized probe interval (seconds).
///
/// The probe loop sleeps for a uniform draw from `[MIN, MAX]` each
/// cycle so a deployment that recovers ahead of `BLACKLIST_COOLDOWN_SECS`
/// (most visibly: a quota-blacklisted SID rolling past 00:00 PT in less
/// than ten minutes) gets noticed without spamming Apps Script with
/// probes. Matches upstream Python `SCRIPT_PROBE_INTERVAL_MIN/MAX`
/// (commit 190e6fa).
const SCRIPT_PROBE_INTERVAL_MAX_SECS: u64 = 600;
/// Per-probe response budget (seconds). One probe is a cheap GET to
/// `http://example.com/` through the SID, so anything longer than this
/// indicates the deployment is still wedged; the probe fails and the
/// blacklist entry stays.
const SCRIPT_PROBE_TIMEOUT_SECS: u64 = 15;

/// Host suffixes that always bypass the exit-node hop, even in `full`
/// mode. Used by [`DomainFronter::exit_node_matches`].
///
/// Currently only `googlevideo.com` — YouTube video chunks are large
/// (multi-MB per `/videoplayback` call) and Apps Script already reaches
/// `*.googlevideo.com` directly over Google's internal network, so
/// chaining them through a Cloudflare / Deno / VPS exit node just doubles
/// the bandwidth and the latency for zero anti-bot benefit (googlevideo
/// doesn't run the GCP-IP heuristic that the exit-node feature exists
/// to defeat). Ported from upstream Python 6745dd1
/// (`_EXIT_NODE_BYPASS_SUFFIXES`).
const EXIT_NODE_BYPASS_SUFFIXES: &[&str] = &["googlevideo.com"];

// Auto-blacklist defaults are now per-instance fields on `DomainFronter`,
// driven by `Config::auto_blacklist_strikes` / `_window_secs` /
// `_cooldown_secs` (#391, #444). The constants below are gone — see the
// `Config` doc comments for tuning guidance and `default_auto_blacklist_*`
// for the historical defaults (3 strikes / 30s window / 120s cooldown).

/// Request payload sent to Apps Script (single, non-batch).
#[derive(Serialize)]
struct RelayRequest<'a> {
    k: &'a str,
    m: &'a str,
    u: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    h: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ct: Option<&'a str>,
    r: bool,
    /// Tells Code.gs / Worker / CodeFull to return the destination's
    /// response body verbatim instead of wrapping it in another
    /// `{s, h, b}` envelope. Set ONLY by the exit-node outer call —
    /// without it, Apps Script's wrap would double-encapsulate the
    /// exit-node's own `{s, h, b}` envelope and the browser would
    /// receive raw JSON instead of the destination's content.
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<bool>,
}

/// Parsed Apps Script response JSON (single mode).
#[derive(Deserialize, Default)]
struct RelayResponse {
    #[serde(default)]
    s: Option<u16>,
    #[serde(default)]
    h: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    b: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// Parsed tunnel response JSON (full mode).
#[derive(Deserialize, Debug, Clone)]
pub struct TunnelResponse {
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub d: Option<String>,
    /// UDP datagrams returned by tunnel-node, base64-encoded individually.
    #[serde(default)]
    pub pkts: Option<Vec<String>>,
    #[serde(default)]
    pub eof: Option<bool>,
    #[serde(default)]
    pub e: Option<String>,
    /// Structured error code from the tunnel-node (e.g. `UNSUPPORTED_OP`).
    /// `None` for legacy tunnel-nodes; clients should fall back to parsing
    /// `e` only when this is `None` and compatibility is needed.
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub seq: Option<u64>,
}

/// A single op in a batch tunnel request.
#[derive(Serialize, Clone, Debug)]
pub struct BatchOp {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wseq: Option<u64>,
}

/// Batch tunnel response from Apps Script / tunnel node.
#[derive(Deserialize, Debug)]
pub struct BatchTunnelResponse {
    #[serde(default)]
    pub r: Vec<TunnelResponse>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub zr: Option<String>,
    #[serde(default)]
    pub zc: Option<u8>,
}

impl DomainFronter {
    pub fn new(config: &Config) -> Result<Self, FronterError> {
        let script_ids = config.script_ids_resolved();
        if script_ids.is_empty() {
            return Err(FronterError::Relay("no script_id configured".into()));
        }
        // Resolve once so the URL builder and the Accept-Language
        // builder agree on the same sanitised value — `apps_script_lang_resolved`
        // hits the validator path on each call, so calling it twice
        // would needlessly re-walk the BCP47 grammar check.
        let apps_script_lang_resolved = config.apps_script_lang_resolved();
        // Helper that builds a fresh ClientConfig with the verifier
        // policy from config. We need two of these so the h2-capable
        // and h1-only paths can advertise different ALPN sets without
        // mutating one shared config across calls.
        let build_tls_config = || {
            if config.verify_ssl {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            } else {
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify))
                    .with_no_client_auth()
            }
        };

        // Connector for `open_h2`: advertises h2 first (or just h1 if
        // the kill switch is set, in which case both connectors end up
        // identical — fine, just slightly redundant).
        let mut tls_h2 = build_tls_config();
        if !config.force_http1 {
            tls_h2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        } else {
            tls_h2.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        let tls_connector = TlsConnector::from(Arc::new(tls_h2));

        // Connector for `open()` (h1 pool path). ALPN is forced to
        // http/1.1 so a Google edge that would otherwise prefer h2
        // still negotiates h1 here — pooled sockets always speak the
        // protocol the fallback path expects.
        let mut tls_h1 = build_tls_config();
        tls_h1.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_connector_h1 = TlsConnector::from(Arc::new(tls_h1));

        Ok(Self {
            connect_host: ArcSwap::from_pointee(config.google_ip.clone()),
            sni_hosts: build_sni_pool_for(
                &config.front_domain,
                config.sni_hosts.as_deref().unwrap_or(&[]),
            ),
            sni_idx: AtomicUsize::new(0),
            http_host: "script.google.com",
            auth_key: config.auth_key.clone(),
            parallel_relay: config.parallel_relay as usize,
            normalize_x_graphql: config.normalize_x_graphql,
            allow_brotli_zstd: config.allow_brotli_zstd,
            cert_hint_shown: std::sync::atomic::AtomicBool::new(false),
            script_ids,
            script_idx: AtomicUsize::new(0),
            tls_connector,
            tls_connector_h1,
            pool: Arc::new(Mutex::new(Vec::new())),
            h2_cell: Arc::new(Mutex::new(None)),
            h2_open_lock: Arc::new(Mutex::new(())),
            h2_open_failed_at: Arc::new(Mutex::new(None)),
            h2_generation: Arc::new(AtomicU64::new(0)),
            h2_disabled: Arc::new(AtomicBool::new(config.force_http1)),
            cache: Arc::new(ResponseCache::with_default()),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            coalesced: AtomicU64::new(0),
            blacklist: Arc::new(std::sync::Mutex::new(HashMap::new())),
            script_timeouts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            script_latency_ewma: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_calls: AtomicU64::new(0),
            relay_failures: AtomicU64::new(0),
            bytes_relayed: AtomicU64::new(0),
            h2_calls: AtomicU64::new(0),
            h2_fallbacks: AtomicU64::new(0),
            forwarder_calls: AtomicU64::new(0),
            forwarder_bytes: AtomicU64::new(0),
            forwarder_errors: AtomicU64::new(0),
            per_site: Arc::new(std::sync::Mutex::new(HashMap::new())),
            today_calls: AtomicU64::new(0),
            today_bytes: AtomicU64::new(0),
            today_key: std::sync::Mutex::new(current_pt_day_key()),
            disable_padding: config.disable_padding,
            zstd_enabled: Arc::new(AtomicBool::new(false)),
            auto_blacklist_strikes: config.auto_blacklist_strikes.max(1),
            auto_blacklist_window: Duration::from_secs(
                config.auto_blacklist_window_secs.clamp(1, 3600),
            ),
            auto_blacklist_cooldown: Duration::from_secs(
                config.auto_blacklist_cooldown_secs.clamp(1, 86400),
            ),
            batch_timeout: Duration::from_secs(config.request_timeout_secs.clamp(5, 300)),
            exit_node_enabled: config.exit_node.enabled
                && !config.exit_node.relay_url.is_empty()
                && !config.exit_node.psk.is_empty(),
            exit_node_url: config.exit_node.relay_url.trim_end_matches('/').to_string(),
            exit_node_psk: config.exit_node.psk.clone(),
            exit_node_full: matches!(config.exit_node.mode.to_ascii_lowercase().as_str(), "full"),
            exit_node_hosts: config
                .exit_node
                .hosts
                .iter()
                .map(|h| h.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            sabr_strip: config.sabr_strip,
            apps_script_lang: apps_script_lang_resolved.clone(),
            apps_script_accept_lang: accept_language_for_lang(&apps_script_lang_resolved),
        })
    }

    /// Build the `/macros/s/<sid>/exec?hl=<lang>` path. Centralised so the
    /// `?hl=` query stays consistent across every relay call site
    /// (single relay, fan-out relay, tunnel single, tunnel batch, prewarm,
    /// blacklist probe).
    fn exec_path_for(&self, script_id: &str) -> String {
        format!("/macros/s/{}/exec?hl={}", script_id, self.apps_script_lang)
    }

    /// True when the configured exit node should handle this URL.
    /// In `selective` mode (default), checks the host against the
    /// pre-normalized `exit_node_hosts` list (exact match OR
    /// dot-anchored suffix, mirroring `passthrough_hosts` semantics).
    /// In `full` mode, every URL routes through the exit node — except
    /// for hosts in [`EXIT_NODE_BYPASS_SUFFIXES`] (currently only
    /// `googlevideo.com`), which always take the direct Apps-Script
    /// path. Ported from upstream Python 6745dd1.
    pub(crate) fn exit_node_matches(&self, url: &str) -> bool {
        if !self.exit_node_enabled {
            return false;
        }
        let host = match extract_host(url) {
            Some(h) => h,
            None => return self.exit_node_full,
        };
        let host_lc = host.to_ascii_lowercase();
        // YouTube video chunks (`*.googlevideo.com`) are large, CPU-heavy,
        // and already covered by Apps Script's direct Google-network path.
        // Chaining them through a Cloudflare / Deno / VPS exit node burns
        // exit-node bandwidth for zero anti-bot benefit (googlevideo
        // doesn't run the GCP-IP heuristic) and turns 1080p playback into
        // a buffering loop. Bypass before either match path can pick it up.
        for suffix in EXIT_NODE_BYPASS_SUFFIXES {
            if host_lc == *suffix || host_lc.ends_with(&format!(".{}", suffix)) {
                return false;
            }
        }
        if self.exit_node_full {
            return true;
        }
        for entry in &self.exit_node_hosts {
            if host_lc == *entry || host_lc.ends_with(&format!(".{}", entry)) {
                return true;
            }
        }
        false
    }

    /// Per-batch HTTP round-trip timeout. Read by `tunnel_client` so the
    /// `BATCH_TIMEOUT` constant doesn't have to be touched on every config
    /// change. Clamped to `[5s, 300s]` at construction.
    pub(crate) fn batch_timeout(&self) -> Duration {
        self.batch_timeout
    }

    /// Record a successful upstream fetch by the SNI-rewrite forwarder.
    /// `bytes` is the response size received from the Google edge.
    /// Counted at the point of upstream success, BEFORE the proxy
    /// writes the bytes to the browser — a client disconnect mid-write
    /// still leaves the metric accurate (the path filter did its
    /// work). Called by `proxy_server::handle_mitm_request`.
    pub(crate) fn record_forwarder_call(&self, bytes: u64) {
        self.forwarder_calls.fetch_add(1, Ordering::Relaxed);
        self.forwarder_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a forwarder dispatch error (connect failure, TLS error,
    /// read timeout, cap exceeded, ...). Says nothing about whether
    /// the subsequent relay-path fallback recovered the request — use
    /// `relay_failures` for that. The two metrics together let
    /// diagnostics distinguish "fast path missed but request still
    /// served" from "request failed end-to-end."
    pub(crate) fn record_forwarder_error(&self) {
        self.forwarder_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Return `Some(stripped_body)` when the SABR quality-track strip
    /// applies to this request and actually removed bytes; `None` when
    /// the original body should pass through untouched.
    ///
    /// Six gates, all of which must pass for the strip to fire:
    ///   1. `Config::sabr_strip` is on (kill-switch from #977 testing —
    ///      see `src/config.rs` for the full trade-off).
    ///   2. POST method (segment fetches are POSTs in YouTube's SABR
    ///      protocol; GETs and other methods don't carry the protobuf).
    ///   3. Non-empty body (no body to walk → nothing to strip).
    ///   4. URL path contains `/videoplayback` (the SABR endpoint).
    ///   5. URL host is in `url_host_is_youtube_video_endpoint`'s set
    ///      (`*.googlevideo.com` or `*.youtube.com`) — defends against
    ///      an unrelated service that happens to expose the same path
    ///      shape with a protobuf-like body.
    ///   6. The strip itself actually removed at least one byte —
    ///      session-init bodies (no field-2) and bodies without any
    ///      field-3 entries return unchanged from
    ///      `strip_sabr_quality_tracks` and we report `None` so the
    ///      caller skips the allocation churn.
    ///
    /// Pulled out of `relay()` so the gate can be exercised by unit
    /// tests without standing up a live Apps Script connection — see
    /// `sabr_strip_off_keeps_body_unchanged` /
    /// `sabr_strip_on_strips_segment_fetch_body`.
    pub(crate) fn maybe_strip_sabr_body(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> Option<Vec<u8>> {
        if !self.sabr_strip
            || method != "POST"
            || body.is_empty()
            || !url.contains("/videoplayback")
            || !url_host_is_youtube_video_endpoint(url)
        {
            return None;
        }
        let stripped = strip_sabr_quality_tracks(body);
        if stripped.len() == body.len() {
            return None;
        }
        tracing::debug!(
            "SABR strip: removed {} quality-track bytes from {}",
            body.len() - stripped.len(),
            url.split('?').next().unwrap_or(url),
        );
        Some(stripped)
    }

    /// Record one relay call toward the daily budget. Called once per
    /// outbound Apps Script fetch. Rolls over both daily counters at
    /// 00:00 Pacific Time, matching Apps Script's quota reset cadence
    /// (#230, #362). Crate-public so the Full-mode batch path in
    /// `tunnel_client::fire_batch` can wire into the same accounting
    /// (Apps Script sees Full-mode batches as ordinary `UrlFetchApp`
    /// calls and counts them against the same daily quota).
    pub(crate) fn record_today(&self, bytes: u64) {
        let today = current_pt_day_key();
        // Fast path: same day as what we last saw. No lock.
        let mut guard = self.today_key.lock().unwrap();
        if *guard != today {
            // Date rolled over — reset counters before this call is counted.
            *guard = today;
            self.today_calls.store(0, Ordering::Relaxed);
            self.today_bytes.store(0, Ordering::Relaxed);
        }
        drop(guard);
        self.today_calls.fetch_add(1, Ordering::Relaxed);
        self.today_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment the per-site counters. Called on every logical request
    /// (both cache hits and relay roundtrips).
    fn record_site(&self, url: &str, cache_hit: bool, bytes: u64, latency_ns: u64) {
        let host = match extract_host(url) {
            Some(h) => h,
            None => return,
        };
        let mut m = self.per_site.lock().unwrap();
        let e = m.entry(host).or_default();
        e.requests += 1;
        if cache_hit {
            e.cache_hits += 1;
        }
        e.bytes += bytes;
        e.total_latency_ns += latency_ns;
    }

    /// Snapshot per-site stats, sorted by request count descending.
    pub fn snapshot_per_site(&self) -> Vec<(String, HostStat)> {
        let m = self.per_site.lock().unwrap();
        let mut v: Vec<(String, HostStat)> =
            m.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort_by_key(|(_, stat)| std::cmp::Reverse(stat.requests));
        v
    }

    pub fn snapshot_stats(&self) -> StatsSnapshot {
        let bl = self.blacklist.lock().unwrap();
        // Read today_key under lock and cheaply check rollover so the
        // UI never sees stale "today_calls=1847" on a day where no
        // traffic has flowed yet (e.g. user left the app open past
        // midnight PT).
        let today_now = current_pt_day_key();
        let today_key = {
            let mut guard = self.today_key.lock().unwrap();
            if *guard != today_now {
                *guard = today_now.clone();
                self.today_calls.store(0, Ordering::Relaxed);
                self.today_bytes.store(0, Ordering::Relaxed);
            }
            guard.clone()
        };
        StatsSnapshot {
            relay_calls: self.relay_calls.load(Ordering::Relaxed),
            relay_failures: self.relay_failures.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            bytes_relayed: self.bytes_relayed.load(Ordering::Relaxed),
            cache_hits: self.cache.hits(),
            cache_misses: self.cache.misses(),
            cache_bytes: self.cache.size(),
            blacklisted_scripts: bl.len(),
            total_scripts: self.script_ids.len(),
            today_calls: self.today_calls.load(Ordering::Relaxed),
            today_bytes: self.today_bytes.load(Ordering::Relaxed),
            today_key,
            today_reset_secs: seconds_until_pacific_midnight(),
            h2_calls: self.h2_calls.load(Ordering::Relaxed),
            h2_fallbacks: self.h2_fallbacks.load(Ordering::Relaxed),
            h2_disabled: self.h2_disabled.load(Ordering::Relaxed),
            forwarder_calls: self.forwarder_calls.load(Ordering::Relaxed),
            forwarder_bytes: self.forwarder_bytes.load(Ordering::Relaxed),
            forwarder_errors: self.forwarder_errors.load(Ordering::Relaxed),
        }
    }

    pub fn num_scripts(&self) -> usize {
        self.script_ids.len()
    }

    pub fn script_id_list(&self) -> &[String] {
        &self.script_ids
    }

    pub fn cache(&self) -> &ResponseCache {
        &self.cache
    }

    pub fn coalesced_count(&self) -> u64 {
        self.coalesced.load(Ordering::Relaxed)
    }

    pub fn next_script_id(&self) -> String {
        let n = self.script_ids.len();
        // Compute the slow-set BEFORE taking the blacklist mutex — both
        // are short-lived locks but nesting them widens the critical
        // section and creates a lock-order dependency between two
        // otherwise-independent maps. The snapshot is a self-contained
        // value, so it's safe to compute outside any other lock.
        let slow_set = compute_slow_set(&self.script_latency_snapshot());
        let mut bl = self.blacklist.lock().unwrap();
        let now = Instant::now();
        bl.retain(|_, e| e.until > now);

        for _ in 0..n {
            let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
            let sid = &self.script_ids[idx % n];
            if !bl.contains_key(sid) && !slow_set.contains(sid) {
                return sid.clone();
            }
        }
        // Nothing healthy *and* fast — relax the slow-set guard and
        // pick the first non-blacklisted deployment we encounter.
        // Better to use a known-slow deployment than to fall through
        // to the all-blacklisted fallback below.
        for _ in 0..n {
            let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
            let sid = &self.script_ids[idx % n];
            if !bl.contains_key(sid) {
                return sid.clone();
            }
        }
        // All blacklisted: pick whichever comes off cooldown soonest.
        if let Some((sid, _)) = bl.iter().min_by_key(|(_, e)| e.until) {
            let sid = sid.clone();
            bl.remove(&sid);
            return sid;
        }
        self.script_ids[0].clone()
    }

    /// Pick `want` distinct non-blacklisted script IDs for a parallel fan-out
    /// dispatch. Returns fewer than `want` if there aren't enough non-blacklisted
    /// IDs available. Advances the round-robin index by `want` to spread load
    /// across subsequent calls.
    fn next_script_ids(&self, want: usize) -> Vec<String> {
        let n = self.script_ids.len();
        if n == 0 {
            return vec![];
        }
        // Snapshot before the blacklist lock — see next_script_id.
        let slow_set = compute_slow_set(&self.script_latency_snapshot());
        let mut bl = self.blacklist.lock().unwrap();
        let now = Instant::now();
        bl.retain(|_, e| e.until > now);

        let mut picked: Vec<String> = Vec::with_capacity(want);
        // Pass 1: blacklist-free AND slow-set-free.
        for _ in 0..n {
            if picked.len() >= want {
                break;
            }
            let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
            let sid = &self.script_ids[idx % n];
            if !bl.contains_key(sid) && !slow_set.contains(sid) && !picked.iter().any(|p| p == sid)
            {
                picked.push(sid.clone());
            }
        }
        // Pass 2: relax the slow-set guard if we didn't get enough on
        // pass 1 — same fallback rationale as `next_script_id`.
        if picked.len() < want {
            for _ in 0..n {
                if picked.len() >= want {
                    break;
                }
                let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
                let sid = &self.script_ids[idx % n];
                if !bl.contains_key(sid) && !picked.iter().any(|p| p == sid) {
                    picked.push(sid.clone());
                }
            }
        }
        if picked.is_empty() {
            picked.push(self.script_ids[0].clone());
        }
        picked
    }

    /// Blacklist an Apps Script deployment for the default cooldown
    /// after an envelope-classified failure or an HTTP 429/403 from the
    /// edge. Probe-recoverable: the background [`run_probe_loop`] task
    /// owns the entry and may clear it early if a cheap `example.com`
    /// roundtrip succeeds before the cooldown expires.
    fn blacklist_script(&self, script_id: &str, reason: &str) {
        self.blacklist_script_inner(
            script_id,
            Duration::from_secs(BLACKLIST_COOLDOWN_SECS),
            true,
            reason,
        );
    }

    /// Blacklist for `cooldown` with the probe loop disowned — used by
    /// [`record_timeout_strike`] where the trigger isn't something a
    /// generic roundtrip can validate (network-level stall, slow
    /// tunnel write, etc.). Entries written through this path expire
    /// only via their TTL.
    fn blacklist_script_for(&self, script_id: &str, cooldown: Duration, reason: &str) {
        self.blacklist_script_inner(script_id, cooldown, false, reason);
    }

    fn blacklist_script_inner(
        &self,
        script_id: &str,
        cooldown: Duration,
        probe_recoverable: bool,
        reason: &str,
    ) {
        let entry = BlacklistEntry {
            until: Instant::now() + cooldown,
            probe_recoverable,
        };
        let mut bl = self.blacklist.lock().unwrap();
        bl.insert(script_id.to_string(), entry);
        tracing::warn!(
            "blacklisted script {} for {}s: {}",
            mask_script_id(script_id),
            cooldown.as_secs(),
            reason
        );
    }

    /// Record a batch timeout against `script_id`. After
    /// `TIMEOUT_STRIKE_LIMIT` timeouts inside `TIMEOUT_STRIKE_WINDOW`
    /// the deployment is blacklisted with a short cooldown so the
    /// round-robin stops sending real traffic to a deployment that's
    /// hung (most commonly: stale `TUNNEL_SERVER_URL` after the
    /// tunnel-node moved hosts).
    pub(crate) fn record_timeout_strike(&self, script_id: &str) {
        let now = Instant::now();
        let mut counts = self.script_timeouts.lock().unwrap();
        let entry = counts.entry(script_id.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) > self.auto_blacklist_window {
            *entry = (now, 1);
        } else {
            entry.1 += 1;
        }
        let strikes = entry.1;
        if strikes >= self.auto_blacklist_strikes {
            counts.remove(script_id);
            drop(counts);
            self.blacklist_script_for(
                script_id,
                self.auto_blacklist_cooldown,
                &format!(
                    "{} timeouts in {}s",
                    strikes,
                    self.auto_blacklist_window.as_secs()
                ),
            );
        }
    }

    /// Clear the timeout strike counter for `script_id`. Called after
    /// a batch succeeds so a recovered deployment doesn't keep stale
    /// strikes from hours ago — three strikes must occur within one
    /// real failure burst, not accumulate across unrelated incidents.
    pub(crate) fn record_batch_success(&self, script_id: &str) {
        let mut counts = self.script_timeouts.lock().unwrap();
        counts.remove(script_id);
    }

    /// Fold a successful batch RTT into the deployment's EWMA score.
    /// Only successful batches are recorded — a failed batch's elapsed
    /// time is the timeout, not the deployment's actual speed, and
    /// would poison the EWMA upward.
    pub(crate) fn record_batch_latency(&self, script_id: &str, latency: Duration) {
        let ms = latency.as_secs_f64() * 1000.0;
        let now = Instant::now();
        {
            let mut map = self.script_latency_ewma.lock().unwrap();
            map.entry(script_id.to_string())
                .and_modify(|(score, ts)| {
                    *score = LATENCY_EWMA_ALPHA * ms + (1.0 - LATENCY_EWMA_ALPHA) * *score;
                    *ts = now;
                })
                .or_insert((ms, now));
        }

        if self.script_ids.len() >= LATENCY_MIN_DEPLOYMENTS && ms >= LATENCY_HARD_SLOW_BATCH_MS {
            self.blacklist_script_for(
                script_id,
                Duration::from_secs(LATENCY_HARD_SLOW_COOLDOWN_SECS),
                "successful tunnel batch exceeded hard latency threshold",
            );
        }
    }

    /// Snapshot of `script_latency_ewma` for read-only consumers
    /// (tests, the selector), restricted to samples taken within the
    /// last `LATENCY_FRESH_FOR_SECS`. Stale entries are filtered out
    /// so a deployment that's been skipped long enough for its sample
    /// to expire becomes eligible again — the recovery path that
    /// keeps a single bad minute from being a permanent ban.
    fn script_latency_snapshot(&self) -> HashMap<String, f64> {
        let map = self.script_latency_ewma.lock().unwrap();
        fresh_latency_snapshot(
            &map,
            Instant::now(),
            Duration::from_secs(LATENCY_FRESH_FOR_SECS),
        )
    }

    /// Log a relay failure with extra guidance on cert-validation cases.
    /// Rate-limited so a flood of identical "UnknownIssuer" errors doesn't
    /// fill the log.
    fn log_relay_failure(&self, e: &FronterError) {
        let msg = e.to_string();
        let is_cert_issue = msg.contains("UnknownIssuer")
            || msg.contains("invalid peer certificate")
            || msg.contains("CertificateExpired")
            || msg.contains("CertNotValidYet")
            || msg.contains("NotValidForName");
        if is_cert_issue
            && !self
                .cert_hint_shown
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            // First time — print the full diagnostic. Subsequent hits
            // drop to debug so the log stays readable.
            tracing::error!(
                "Relay failed: {} — this almost always means one of:\n  \
                 (1) your ISP or a middlebox is intercepting TLS to the Google edge \
                 (common in Iran / IR);\n  \
                 (2) the `google_ip` in your config is pointing at a non-Google host;\n  \
                 (3) your system clock is way off (NTP not synced).\n\
                 Fixes (try in order): run `rahgozar scan-ips` to find a different Google \
                 frontend IP that isn't being MITM'd; check `date` on your host; as a \
                 LAST RESORT set `\"verify_ssl\": false` in config.json — this lets the \
                 relay work even through a middlebox, but your traffic is then only \
                 protected by the Apps Script relay's secret `auth_key`, not by outer TLS.",
                e
            );
        } else if is_cert_issue {
            tracing::debug!("Relay failed (cert): {}", e);
        } else {
            tracing::error!("Relay failed: {}", e);
        }
    }

    fn next_sni(&self) -> String {
        let n = self.sni_hosts.len();
        let i = self.sni_idx.fetch_add(1, Ordering::Relaxed) % n;
        self.sni_hosts[i].clone()
    }

    /// Open a TCP+TLS connection to the current `connect_host`.
    /// Returns the stream plus the `Arc<String>` snapshot of the host
    /// the connection was opened against — callers cache that
    /// alongside the stream so `acquire` / `release` /
    /// `run_pool_refill` can later detect "did `run_ip_health` swap
    /// the host while we were opening?" via a single `Arc::ptr_eq`
    /// check against the current snapshot. No separate generation
    /// counter; the Arc identity is the version.
    async fn open(&self) -> Result<(PooledStream, Arc<String>), FronterError> {
        // Bounded TCP+TLS open. See `H1_OPEN_TIMEOUT_SECS`. Snapshot
        // the host once at the top so the returned Arc is exactly the
        // one the socket was opened against — even if `connect_host`
        // swaps mid-connect, this Arc reflects the actual peer.
        let host = self.connect_host.load_full();
        let host_for_async = host.clone();
        let work = async move {
            let tcp = TcpStream::connect((host_for_async.as_str(), 443u16)).await?;
            let _ = tcp.set_nodelay(true);
            let sni = self.next_sni();
            let name = ServerName::try_from(sni)?;
            // Always use the h1-only connector here — the pool only holds
            // sockets that the raw HTTP/1.1 fallback path can write to.
            // Using the shared connector would let some pooled sockets
            // negotiate h2, which would then misframe every fallback
            // request that lands on them.
            let tls = self.tls_connector_h1.connect(name, tcp).await?;
            Ok::<_, FronterError>(tls)
        };
        match tokio::time::timeout(Duration::from_secs(H1_OPEN_TIMEOUT_SECS), work).await {
            Ok(Ok(s)) => Ok((s, host)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(FronterError::Relay(format!(
                "h1 open timed out after {}s",
                H1_OPEN_TIMEOUT_SECS
            ))),
        }
    }

    /// Open outbound TLS connections eagerly so the first relay request
    /// doesn't pay a cold handshake.
    ///
    /// h2 and h1 prewarm run in parallel: a request that arrives while
    /// the h2 handshake is still in flight (or has just hit its 8 s
    /// timeout) needs a warm h1 socket waiting for it, otherwise the
    /// h1 fallback path pays a cold handshake on the same slow network
    /// and the 30 s outer batch budget elapses (#924). v1.9.14 warmed
    /// h1 unconditionally; v1.9.15 (PR #799) accidentally gated the h1
    /// prewarm behind `ensure_h2()` so the h1 pool stayed empty during
    /// the h2 init window.
    ///
    /// The spawned h2 handshake races h1[0] — boot fires two TLS
    /// handshakes back-to-back. The 500 ms stagger only applies between
    /// h1[i] and h1[i+1] for i ≥ 1, so we don't burst the remaining
    /// h1[1..n] handshakes at the Google edge simultaneously. Each
    /// connection gets an 8 s expiry offset so they roll off gradually
    /// instead of all hitting POOL_TTL_SECS at once. If h2 ends up the
    /// active fast path, `run_pool_refill` trims the pool back down to
    /// `POOL_MIN_H2_FALLBACK` on the next tick — the extra warm h1
    /// sockets just age out naturally instead of being kept alive.
    pub async fn warm(self: &Arc<Self>, n: usize) {
        // Spawn the h2 prewarm in parallel so the h1 prewarm loop
        // below isn't blocked on it. Capturing the join handle lets
        // us still log "h2 fast path active" / "h1 fallback only"
        // accurately at the end.
        let h2_self = self.clone();
        let h2_handle = tokio::spawn(async move {
            !h2_self.h2_disabled.load(Ordering::Relaxed) && h2_self.ensure_h2().await.is_some()
        });

        let mut warmed = 0usize;
        for i in 0..n {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            match self.open().await {
                Ok((s, host)) => {
                    let entry = PoolEntry {
                        stream: s,
                        created: Instant::now() - Duration::from_secs(8 * i as u64),
                        host,
                    };
                    let mut pool = self.pool.lock().await;
                    // Skip if a heartbeat swap landed during the open
                    // — the freshly opened socket would target the
                    // pre-swap IP. The pool was cleared by the swap;
                    // pushing here would re-poison it.
                    let current = self.connect_host.load_full();
                    if !Arc::ptr_eq(&entry.host, &current) {
                        tracing::debug!("pool warm: dropping post-swap stale connection");
                    } else if pool.len() < POOL_MAX {
                        pool.push(entry);
                        warmed += 1;
                    }
                }
                Err(e) => {
                    tracing::debug!("pool warm: open failed: {}", e);
                }
            }
        }
        // Join the h2 prewarm here only to log whether it landed; the
        // h1 pool above is already populated either way. A panic in
        // the spawned task surfaces as `JoinError` — log it explicitly
        // so it isn't indistinguishable from a clean ALPN refusal.
        let h2_alive = match h2_handle.await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("h2 prewarm task failed to join: {}", e);
                false
            }
        };
        if h2_alive {
            tracing::info!(
                "h2 fast path active; h1 fallback pool pre-warmed with {} connection(s)",
                warmed
            );
        } else if warmed > 0 {
            tracing::info!("pool pre-warmed with {} connection(s)", warmed);
        }
    }

    /// Background loop that keeps the h1 pool warm.
    ///
    /// Always maintains `POOL_MIN` (8) connections. Full-tunnel mode
    /// uses the h1 pool for all batch traffic (h2 is skipped for
    /// tunnel batches), so the pool must stay at full capacity
    /// regardless of h2 status. Relay mode also benefits from a warm
    /// pool as h1 fallback.
    ///
    /// A connection only counts toward the minimum if it has at least
    /// 20 s of TTL remaining — nearly-expired entries don't help.
    /// Checks every `POOL_REFILL_INTERVAL_SECS`, evicts expired entries,
    /// and opens replacements one at a time so there's no burst.
    pub async fn run_pool_refill(self: Arc<Self>) {
        const MIN_REMAINING_SECS: u64 = 20;
        loop {
            tokio::time::sleep(Duration::from_secs(POOL_REFILL_INTERVAL_SECS)).await;

            // Evict expired entries first.
            {
                let mut pool = self.pool.lock().await;
                pool.retain(|e| e.created.elapsed().as_secs() < POOL_TTL_SECS);
            }

            let target = POOL_MIN;

            // Count only connections with enough life left.
            // Refill one at a time to avoid bursting TLS handshakes.
            loop {
                let healthy = {
                    let pool = self.pool.lock().await;
                    pool.iter()
                        .filter(|e| {
                            let age = e.created.elapsed().as_secs();
                            age + MIN_REMAINING_SECS < POOL_TTL_SECS
                        })
                        .count()
                };
                if healthy >= target {
                    break;
                }
                // `open()` returns the `Arc<String>` snapshot the
                // socket was opened against. Under the pool lock,
                // compare it to the live `connect_host` — Arc
                // pointer mismatch means `run_ip_health` swapped
                // hosts during our open, so this socket would target
                // a just-decommissioned IP. Drop it rather than
                // poison the freshly-cleared pool with a stale entry.
                match self.open().await {
                    Ok((s, host)) => {
                        let mut pool = self.pool.lock().await;
                        let current = self.connect_host.load_full();
                        if !Arc::ptr_eq(&host, &current) {
                            tracing::debug!("pool refill: dropping post-swap stale connection");
                        } else if pool.len() < POOL_MAX {
                            pool.push(PoolEntry {
                                stream: s,
                                created: Instant::now(),
                                host,
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!("pool refill: open failed: {}", e);
                        break;
                    }
                }
            }
        }
    }

    /// Background loop that periodically re-probes blacklisted SIDs to
    /// detect recovery ahead of the static [`BLACKLIST_COOLDOWN_SECS`]
    /// expiry. Most useful for quota-blacklisted deployments: Apps
    /// Script's daily UrlFetchApp counter resets at 00:00 Pacific Time,
    /// which can be minutes-or-less from a fresh blacklist entry, but
    /// the 10-min cooldown keeps the SID out of rotation for the full
    /// window anyway. With this loop, a recovered SID re-enters the
    /// pool within one probe interval.
    ///
    /// No-op when only one script ID is configured — single-SID users
    /// have no rotation pool, so probing the only deployment burns the
    /// same quota that triggered the blacklist in the first place. The
    /// per-instance check happens once at startup; mid-life config
    /// changes that add more SIDs require a restart to enable probing.
    ///
    /// Each probe sends one cheap HEAD (`http://example.com/`) through
    /// the same `do_relay_once_with` path normal traffic uses — h2
    /// fast-path with h1 pool fallback, the same retry policy, the
    /// same blacklist side effects on a classifier match. A response
    /// that [`probe_indicates_recovery`] accepts (healthy 200 or
    /// transient envelope) clears the SID from the blacklist, but
    /// only when the entry's `until` is still the value the probe
    /// captured at issue time — a concurrent blacklist-extend write
    /// (longer cooldown, new reason) cancels the recovery so the
    /// extended entry isn't silently undone. Any transport error,
    /// non-200 status without a transient envelope, or envelope error
    /// matched by [`classify_envelope_error`] leaves the SID
    /// blacklisted with its existing TTL — no escalation, no TTL
    /// extension, no logging spam. Ported from upstream Python
    /// `_probe_blacklisted_sids` (commit 190e6fa).
    pub async fn run_probe_loop(self: Arc<Self>) {
        if self.script_ids.len() <= 1 {
            return;
        }
        loop {
            let interval_secs = {
                let mut rng = thread_rng();
                rng.gen_range(SCRIPT_PROBE_INTERVAL_MIN_SECS..=SCRIPT_PROBE_INTERVAL_MAX_SECS)
            };
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            self.probe_blacklisted_once().await;
        }
    }

    /// Background heartbeat for the active Google front IP. Probes
    /// `connect_host:443` on a fixed interval; after
    /// `failure_threshold` consecutive failures, runs a fresh
    /// `scan_ips::rescan_and_pick` and swaps `connect_host` to the
    /// first reachable alternative. Existing pool entries are dropped
    /// on swap so subsequent opens go to the new IP — in-flight
    /// requests on already-open sockets continue against the old IP
    /// and drain naturally.
    ///
    /// Returns immediately when the user has disabled the heartbeat
    /// via `heartbeat_enabled = false`. The `config_for_rescan` clone
    /// captures only the IP-scan-relevant fields at spawn time;
    /// runtime config edits aren't picked up (mirrors `run_probe_loop`
    /// /  `run_pool_refill` — config changes require a restart).
    pub async fn run_ip_health(
        self: Arc<Self>,
        enabled: bool,
        interval_secs: u64,
        failure_threshold: u32,
        config_for_rescan: Config,
    ) {
        if !enabled {
            return;
        }
        let interval = Duration::from_secs(interval_secs.max(1));
        // `heartbeat_failure_threshold = 0` would be surprising —
        // "threshold zero" reads as "never trigger" to most users
        // but the comparison would also be satisfied at the very
        // first probe failure, rescanning on every blip. Clamp to 1
        // and log so a config typo surfaces in the log instead of
        // silently picking the most-aggressive behaviour.
        let failure_threshold = if failure_threshold == 0 {
            tracing::warn!(
                "ip-health: heartbeat_failure_threshold=0 clamped to 1 (rescan on first probe failure)"
            );
            1
        } else {
            failure_threshold
        };
        let validation = config_for_rescan.google_ip_validation;
        let verify_ssl = config_for_rescan.verify_ssl;
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::time::sleep(interval).await;
            let current = self.connect_host.load().to_string();
            // Probe with the same SNI rotation pool real connections
            // use, not `config.front_domain` alone. Users who override
            // `sni_hosts` (e.g. dropping a blocked default) would
            // otherwise see the heartbeat fail forever on an SNI the
            // proxy never actually opens against, false-flagging a
            // working IP and triggering pointless rescans.
            let sni = self.next_sni();
            let ok = crate::scan_ips::heartbeat_probe(&current, &sni, validation, verify_ssl).await;
            if ok {
                if consecutive_failures > 0 {
                    tracing::info!("ip-health: {} recovered", current);
                    consecutive_failures = 0;
                }
                continue;
            }
            consecutive_failures += 1;
            tracing::warn!(
                "ip-health: probe failed for {} ({}/{})",
                current,
                consecutive_failures,
                failure_threshold
            );
            if consecutive_failures < failure_threshold {
                continue;
            }
            tracing::warn!(
                "ip-health: {} unreachable, rescanning for replacement",
                current
            );
            // Rescan validates candidates against the relay's actual
            // SNI rotation pool — see `rescan_and_pick` doc-comment
            // for the why. Cloning lazily here (only on rescan
            // trigger) keeps the common-case probe loop allocation-
            // free.
            let rescan_snis = self.sni_hosts.clone();
            let picked = crate::scan_ips::rescan_and_pick(&config_for_rescan, &rescan_snis).await;
            match picked {
                Some(next) if next != current => {
                    tracing::warn!("ip-health: swapping {} -> {}", current, next);
                    // The atomic Arc swap is the single source of
                    // truth: any subsequent `connect_host.load_full`
                    // returns the new Arc, and any pool/cell entry
                    // that captured the old Arc fails `Arc::ptr_eq`
                    // against the new one. No separate generation
                    // counter to keep coherent with the host. Clear
                    // pool + h2 cell after the store so a concurrent
                    // open that races the swap also lands the
                    // ptr_eq-mismatch path under the pool / cell
                    // lock.
                    self.connect_host.store(Arc::new(next));
                    self.pool.lock().await.clear();
                    *self.h2_cell.lock().await = None;
                    consecutive_failures = 0;
                }
                Some(_) => {
                    tracing::warn!("ip-health: no alternative reachable, keeping {}", current);
                    consecutive_failures = 0;
                }
                None => {
                    tracing::error!("ip-health: rescan found zero reachable IPs");
                    consecutive_failures = 0;
                }
            }
        }
    }

    /// One pass of the probe loop — fan out across every currently
    /// blacklisted SID flagged probe-recoverable and re-probe in
    /// parallel. Public-by-`pub(crate)` so unit tests can drive a tick
    /// deterministically without sleeping inside [`run_probe_loop`]'s
    /// timer.
    ///
    /// Entries with `probe_recoverable == false` (added through
    /// [`record_timeout_strike`]) are filtered out: probing them with a
    /// generic `example.com` roundtrip risks silent recovery on a still-
    /// broken deployment, because rolling timeouts can stem from causes
    /// the probe doesn't reproduce.
    pub(crate) async fn probe_blacklisted_once(&self) {
        let now = Instant::now();
        // Capture `until` alongside `sid` under the lock so the probe
        // can prove later that the entry it's about to remove is the
        // same one it owned at the start of this cycle. Without that
        // pairing a probe-extend race (cooldown-extended write while
        // the probe is in flight) would silently undo the extension.
        // Also prune expired entries here so the background task is
        // self-contained — normal `next_script_id` consumers already
        // prune on read, but the probe tick should never see a stale
        // entry it would then try (and fail) to clear.
        let candidates: Vec<(String, Instant)> = {
            let mut bl = self.blacklist.lock().unwrap();
            bl.retain(|_, e| e.until > now);
            bl.iter()
                .filter(|(_, e)| e.probe_recoverable)
                .map(|(s, e)| (s.clone(), e.until))
                .collect()
        };
        if candidates.is_empty() {
            return;
        }
        let mut tasks = Vec::with_capacity(candidates.len());
        for (sid, until) in candidates {
            tasks.push(self.probe_one_sid(sid, until));
        }
        futures_util::future::join_all(tasks).await;
    }

    /// Probe one blacklisted SID with a single cheap HEAD through the
    /// same `do_relay_once_with` path normal traffic uses. On a
    /// recovery-indicating outcome (see [`probe_indicates_recovery`])
    /// the blacklist entry is cleared — but only if its `until` still
    /// matches `captured_until`, so a concurrent blacklist write
    /// (longer cooldown, new probe-disowned reason) isn't undone.
    ///
    /// Why route through `do_relay_once_with` instead of poking
    /// `h2_relay_request` directly: the SID we want to probe is the
    /// blacklisted one, but the **transport** to Apps Script (h2 cell,
    /// h1 pool, sticky `h2_disabled`) is shared across all SIDs. If we
    /// only tried h2 here, a fronter whose h2 was sticky-disabled by an
    /// edge that doesn't speak h2 (ALPN refusal, persistent middlebox
    /// problem) would never recover any blacklisted SID — h1 would
    /// have worked fine for the probe just like it works for normal
    /// traffic. Sharing `do_relay_once_with` also avoids reinventing
    /// the inner timeout / RequestSent / fallback policy, which was a
    /// hand-wrap-with-outer-timeout footgun in the first cut of this
    /// loop (the outer `tokio::time::timeout` preempted the h2 layer's
    /// own poisoning logic before it could mark the connection dead).
    async fn probe_one_sid(&self, sid: String, captured_until: Instant) {
        let result = self
            .do_relay_once_with(sid.clone(), "HEAD", "http://example.com/", &[], &[])
            .await;
        let recovery = probe_indicates_recovery(&result);
        if !recovery {
            if let Err(ref e) = result {
                tracing::debug!(
                    "probe {} not healthy ({}) — keeping blacklisted",
                    mask_script_id(&sid),
                    e
                );
            }
            return;
        }
        match self.apply_probe_recovery(&sid, captured_until) {
            ProbeApplyResult::Cleared => {
                tracing::info!("re-validated script {} — recovered", mask_script_id(&sid));
            }
            ProbeApplyResult::RewrittenInFlight => {
                tracing::debug!(
                    "probe {} succeeded but blacklist entry was rewritten — not clearing",
                    mask_script_id(&sid)
                );
            }
            ProbeApplyResult::AlreadyExpired => {
                // The entry timed out between probe issue and probe
                // completion. Nothing to do; another probe tick would
                // also no-op once the read-time prune in
                // `probe_blacklisted_once` runs.
            }
        }
    }

    /// Compare-and-swap step extracted so tests can drive the
    /// post-recovery decision tree without standing up a live relay.
    /// `captured_until` is what the probe loop read out of the
    /// blacklist at probe issue; if the live entry's `until` doesn't
    /// match, a concurrent write landed mid-probe and the entry must
    /// not be silently cleared. The probe loop itself only calls this
    /// when [`probe_indicates_recovery`] returned `true`.
    pub(crate) fn apply_probe_recovery(
        &self,
        sid: &str,
        captured_until: Instant,
    ) -> ProbeApplyResult {
        let mut bl = self.blacklist.lock().unwrap();
        match bl.get(sid) {
            None => ProbeApplyResult::AlreadyExpired,
            Some(entry) if entry.until == captured_until => {
                bl.remove(sid);
                ProbeApplyResult::Cleared
            }
            Some(_) => ProbeApplyResult::RewrittenInFlight,
        }
    }

    /// Keep the Apps Script container warm with a periodic HEAD ping.
    ///
    /// The TCP/TLS pool stays warm via `run_pool_refill`, but the V8
    /// container Apps Script runs in goes cold ~5min after the last
    /// `UrlFetchApp` call and costs 1-3s to spin back up. The symptom
    /// is "first request after a quiet period stalls" — most visible
    /// on YouTube where the player gives up on a 1.5s `googlevideo.com`
    /// chunk that's actually waiting on a cold-start.
    ///
    /// Transport-agnostic: the underlying call goes through the same
    /// `relay_uncoalesced` path everything else uses, so when h2 is
    /// up the keepalive rides the multiplexed connection too.
    ///
    /// Bypasses the response cache (`cache_key_opt = None`) and the
    /// inflight coalescer — otherwise the second iteration would just
    /// hit the cached response from the first and never reach Apps
    /// Script. The relay payload itself is the cheapest non-error one
    /// we can build: a HEAD against `http://example.com/` returns a few
    /// hundred bytes, no body decode, no auth.
    ///
    /// Best-effort. Failures are debug-logged so a flaky network or
    /// quota-exhausted account doesn't spam warnings every 4 minutes.
    /// Loops forever — caller is expected to drop the JoinHandle on
    /// shutdown (the task lives as long as the process).
    pub async fn run_keepalive(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(H1_KEEPALIVE_INTERVAL_SECS)).await;
            let t0 = Instant::now();
            // relay_uncoalesced returns Vec<u8> (always — errors are
            // baked into 5xx responses), so just observe the duration
            // for the debug line. We intentionally don't use relay()
            // here because that path goes through the cache + coalesce
            // layer, which would short-circuit subsequent pings.
            let _ = self
                .relay_uncoalesced("HEAD", "http://example.com/", &[], &[], None)
                .await;
            tracing::debug!("container keepalive: {}ms", t0.elapsed().as_millis());
        }
    }

    async fn acquire(&self) -> Result<PoolEntry, FronterError> {
        // Evict expired AND stale-host entries, then hand out the
        // freshest survivor. A heartbeat swap clears the pool, but a
        // request that started on the old host could still release
        // its entry afterwards — the host-Arc check rejects those
        // before they're handed back to a new caller.
        {
            let mut pool = self.pool.lock().await;
            let current = self.connect_host.load_full();
            pool.retain(|e| {
                e.created.elapsed().as_secs() < POOL_TTL_SECS && Arc::ptr_eq(&e.host, &current)
            });
            if !pool.is_empty() {
                // Freshest = smallest elapsed time. swap_remove is O(1).
                let freshest = pool
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.created.elapsed())
                    .map(|(i, _)| i)
                    .unwrap();
                return Ok(pool.swap_remove(freshest));
            }
        }
        // Fall-through: no pooled entry, open a fresh one. Same
        // ptr_eq check as `run_pool_refill` / `release`: if a swap
        // landed during the open, the resulting socket targets the
        // old IP. Retry exactly once with the new host (covers the
        // common "swap-during-open" case) — if a second swap races
        // in too, fall through to handing out the stale connection
        // rather than spinning. The caller's response-parse error
        // handling + h1-fallback path catches a connection that
        // fails immediately.
        let (stream, host) = self.open().await?;
        let current = self.connect_host.load_full();
        if Arc::ptr_eq(&host, &current) {
            return Ok(PoolEntry {
                stream,
                created: Instant::now(),
                host,
            });
        }
        tracing::debug!("acquire: post-open swap detected, retrying open against new host");
        drop(stream);
        let (stream, host) = self.open().await?;
        Ok(PoolEntry {
            stream,
            created: Instant::now(),
            host,
        })
    }

    async fn release(&self, entry: PoolEntry) {
        if entry.created.elapsed().as_secs() >= POOL_TTL_SECS {
            return;
        }
        let mut pool = self.pool.lock().await;
        // Reject entries whose host no longer matches the live
        // snapshot — they were opened against an IP that
        // `run_ip_health` has since swapped away from, and pushing
        // them back into the pool would re-poison it with stale
        // sockets after the swap-clear.
        let current = self.connect_host.load_full();
        if !Arc::ptr_eq(&entry.host, &current) {
            tracing::debug!("pool release: dropping post-swap stale connection");
            return;
        }
        if pool.len() < POOL_MAX {
            pool.push(entry);
        }
    }

    /// Return a cloned `SendRequest` handle (paired with its cell
    /// generation) to the active HTTP/2 connection, opening a new one
    /// if needed. `None` means the h2 fast path is unavailable for
    /// this call — the caller should fall through to the h1 path.
    ///
    /// Reasons we may return `None`:
    ///   - `force_http1` set, or peer previously refused h2 via ALPN
    ///     (sticky `h2_disabled`).
    ///   - We're inside the `H2_OPEN_FAILURE_BACKOFF_SECS` cooldown
    ///     after a recent open failure.
    ///   - Another task is currently opening a connection and we
    ///     don't want to pile on (`try_lock` on `h2_open_lock`).
    ///   - The open we just attempted timed out within
    ///     `H2_OPEN_TIMEOUT_SECS` or otherwise failed.
    ///
    /// The lock on `h2_cell` is *never* held across network I/O —
    /// that's the whole point of `h2_open_lock`. Concurrent first-time
    /// callers compete for `h2_open_lock` via `try_lock`; the loser
    /// returns None immediately and uses h1 rather than serializing
    /// behind a slow handshake.
    ///
    /// The returned generation lets the caller later
    /// `poison_h2_if_gen(gen)` to clear *only* this specific cell on
    /// per-stream error, avoiding the race where a stale failure
    /// clobbers a freshly-reopened healthy cell.
    async fn ensure_h2(&self) -> Option<(h2::client::SendRequest<Bytes>, u64)> {
        if self.h2_disabled.load(Ordering::Relaxed) {
            return None;
        }

        // Fast path: existing cell, within TTL and not flagged dead by
        // the connection driver. We can't peek at SendRequest liveness
        // synchronously (h2 0.4 doesn't expose `is_closed`), but the
        // driver task does flip `dead` when the underlying connection
        // ends — so a known-dead cell is rejected here without paying
        // a wasted h2 round trip to discover it.
        {
            let cell = self.h2_cell.lock().await;
            if let Some(c) = cell.as_ref() {
                let current = self.connect_host.load_full();
                if c.created.elapsed().as_secs() < H2_CONN_TTL_SECS
                    && !c.dead.load(Ordering::Relaxed)
                    && Arc::ptr_eq(&c.host, &current)
                {
                    return Some((c.send.clone(), c.generation));
                }
            }
        }

        // Backoff check — recent open failure means h2 is currently
        // unhealthy; don't pile on retries until the window expires.
        {
            let last = self.h2_open_failed_at.lock().await;
            if let Some(t) = *last {
                if t.elapsed().as_secs() < H2_OPEN_FAILURE_BACKOFF_SECS {
                    return None;
                }
            }
        }

        // Open dedup: only one task does the actual handshake at a
        // time. Concurrent callers see the lock contended and fall
        // through to h1 immediately — preserves cold-start latency
        // for the burst that arrives during a slow open.
        let _open_guard = match self.h2_open_lock.try_lock() {
            Ok(g) => g,
            Err(_) => return None,
        };

        // Re-check the cell under open_lock — another task may have
        // just stored a fresh connection while we were arbitrating.
        {
            let cell = self.h2_cell.lock().await;
            if let Some(c) = cell.as_ref() {
                let current = self.connect_host.load_full();
                if c.created.elapsed().as_secs() < H2_CONN_TTL_SECS
                    && !c.dead.load(Ordering::Relaxed)
                    && Arc::ptr_eq(&c.host, &current)
                {
                    return Some((c.send.clone(), c.generation));
                }
            }
        }

        // Bounded handshake. A blackholed connect target can stall
        // for many seconds otherwise, eating the outer budget that
        // should be reserved for an h1 fallback round-trip.
        //
        // `open_h2` returns the `Arc<String>` snapshot of the host
        // the connection was opened against. Before caching, we
        // compare it against the *current* `connect_host` snapshot
        // with `Arc::ptr_eq`. Mismatch means `run_ip_health` swapped
        // hosts during the handshake; caching this `SendRequest`
        // would pin subsequent requests to the dead IP. Hand it back
        // to the caller anyway (one stray request against the old
        // IP is strictly less bad than dropping a working connection
        // outright; h1 fallback will recover if it fails).
        let open_result =
            tokio::time::timeout(Duration::from_secs(H2_OPEN_TIMEOUT_SECS), self.open_h2()).await;

        let (send, dead, host_used) = match open_result {
            Ok(Ok(triple)) => triple,
            Ok(Err(OpenH2Error::AlpnRefused)) => {
                // Definitive: this peer doesn't speak h2. Sticky-disable
                // so we never re-attempt the handshake.
                self.h2_disabled.store(true, Ordering::Relaxed);
                tracing::info!("relay peer refused h2 via ALPN; staying on http/1.1");
                *self.h2_cell.lock().await = None;
                return None;
            }
            Ok(Err(e)) => {
                tracing::debug!("h2 open failed: {} — falling back to h1", e);
                *self.h2_open_failed_at.lock().await = Some(Instant::now());
                *self.h2_cell.lock().await = None;
                return None;
            }
            Err(_) => {
                tracing::debug!(
                    "h2 open timed out after {}s — falling back to h1",
                    H2_OPEN_TIMEOUT_SECS
                );
                *self.h2_open_failed_at.lock().await = Some(Instant::now());
                *self.h2_cell.lock().await = None;
                return None;
            }
        };

        // Open succeeded. Tag with a fresh generation, store, return.
        // Clear any stale backoff timestamp.
        let generation = self.h2_generation.fetch_add(1, Ordering::Relaxed) + 1;
        *self.h2_open_failed_at.lock().await = None;
        let mut cell = self.h2_cell.lock().await;
        let host_now = self.connect_host.load_full();
        if !Arc::ptr_eq(&host_used, &host_now) {
            tracing::debug!("ensure_h2: refusing to cache post-swap stale connection");
            *cell = None;
            return Some((send, generation));
        }
        *cell = Some(H2Cell {
            send: send.clone(),
            created: Instant::now(),
            generation,
            dead,
            host: host_used,
        });
        Some((send, generation))
    }

    /// Open one TLS connection and run the h2 handshake. Returns a
    /// typed `OpenH2Error` so the caller can recognize ALPN refusal
    /// (sticky disable) without string-matching across boundaries.
    /// The returned `Arc<AtomicBool>` is the death flag, flipped when
    /// either the h2 `Connection` future ends (GOAWAY / network error /
    /// TTL) or the application-level PING loop observes an unanswered
    /// PONG — see `spawn_h2_driver_with_ping_liveness`.
    async fn open_h2(
        &self,
    ) -> Result<(h2::client::SendRequest<Bytes>, Arc<AtomicBool>, Arc<String>), OpenH2Error> {
        let host = self.connect_host.load_full();
        let tcp = TcpStream::connect((host.as_str(), 443u16)).await?;
        let _ = tcp.set_nodelay(true);
        let sni = self.next_sni();
        let name = ServerName::try_from(sni)?;
        let tls = self.tls_connector.connect(name, tcp).await?;
        let (send, dead) = Self::h2_handshake_post_tls(tls).await?;
        Ok((send, dead, host))
    }

    /// Post-TLS portion of the h2 open path: ALPN check + h2 handshake
    /// + connection-driver task spawn. Split out from `open_h2` so
    ///
    /// tests can drive it with a TLS stream from any local server,
    /// bypassing the hard-coded `connect_host:443` target.
    async fn h2_handshake_post_tls(
        tls: PooledStream,
    ) -> Result<(h2::client::SendRequest<Bytes>, Arc<AtomicBool>), OpenH2Error> {
        let alpn_h2 = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| p == b"h2")
            .unwrap_or(false);
        if !alpn_h2 {
            return Err(OpenH2Error::AlpnRefused);
        }
        // Larger initial windows mean we don't have to call
        // `release_capacity` on every chunk for typical Apps Script
        // payloads (usually < 1 MB; range chunks are 256 KB). We still
        // release capacity in the body-read loop for safety on larger
        // bodies.
        let (send, conn) = h2::client::Builder::new()
            .initial_window_size(4 * 1024 * 1024)
            .initial_connection_window_size(8 * 1024 * 1024)
            .handshake(tls)
            .await
            .map_err(|e| OpenH2Error::Handshake(e.to_string()))?;
        let dead =
            Self::spawn_h2_driver_with_ping_liveness(conn, H2_PING_INTERVAL, H2_PING_TIMEOUT);
        tracing::info!("h2 connection established to relay edge");
        Ok((send, dead))
    }

    /// Spawn the h2 connection driver task with application-level PING
    /// liveness. Returns the `dead` flag that gets flipped when either
    /// the driver future ends (GOAWAY / network error / TTL) OR the
    /// pinger observes an unanswered PONG.
    ///
    /// The PingPong handle MUST be taken before `conn` is moved into
    /// the spawn — h2 0.4 only hands one out per connection and the API
    /// requires `&mut self`.
    ///
    /// Generic over the I/O type so tests can wire this up against a
    /// plain-TCP h2c connection without needing a TLS mock. Production
    /// callers always pass `PooledStream` (TLS).
    ///
    /// `interval` / `timeout` are arguments rather than the constants
    /// directly so tests can pass millisecond values and assert the
    /// timing behavior without burning the full 25 s real-clock window.
    fn spawn_h2_driver_with_ping_liveness<T>(
        mut conn: h2::client::Connection<T, Bytes>,
        interval: Duration,
        timeout: Duration,
    ) -> Arc<AtomicBool>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let ping_pong = conn.ping_pong();
        let dead = Arc::new(AtomicBool::new(false));
        let dead_for_driver = dead.clone();
        tokio::spawn(async move {
            let driver = async {
                if let Err(e) = conn.await {
                    tracing::debug!("h2 connection closed: {}", e);
                }
            };
            let pinger = async {
                let Some(mut pp) = ping_pong else {
                    std::future::pending::<()>().await;
                    return;
                };
                loop {
                    tokio::time::sleep(interval).await;
                    let started = Instant::now();
                    match tokio::time::timeout(timeout, pp.ping(h2::Ping::opaque())).await {
                        Ok(Ok(_)) => {
                            tracing::debug!("h2 ping ok ({} ms)", started.elapsed().as_millis());
                            continue;
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("h2 ping error: {} — closing connection", e);
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(
                                "h2 ping unanswered after {:?} — closing stale connection",
                                timeout
                            );
                            return;
                        }
                    }
                }
            };
            tokio::select! {
                _ = driver => {}
                _ = pinger => {}
            }
            dead_for_driver.store(true, Ordering::Relaxed);
        });
        dead
    }

    /// React to an h2-fronting-incompatibility HTTP response (status
    /// matched by `is_h2_fronting_refusal_status`) by:
    ///   * sticky-disabling the h2 fast path so subsequent calls go
    ///     straight to h1 without re-paying the handshake / refusal,
    ///   * clearing any current cell so the SendRequest is dropped,
    ///   * rebalancing the h2 stat counters so this request shows
    ///     up as a fallback, not a successful h2 call. (The
    ///     `run_h2_relay_with_send` Ok path bumps `h2_calls` for any
    ///     completed round-trip; for a 421 we want it counted as
    ///     `h2_fallbacks` instead since the request will take the
    ///     h1 path.)
    ///
    /// Logs at info because this is a meaningful state transition for
    /// the deployment, not a per-request hiccup.
    async fn sticky_disable_h2_for_fronting_refusal(&self, status: u16, context: &str) {
        if !self.h2_disabled.swap(true, Ordering::Relaxed) {
            tracing::info!(
                "h2 returned HTTP {} for {} — likely :authority/SNI mismatch via \
                 domain fronting. Disabling h2 fast path for this fronter and \
                 falling back to http/1.1.",
                status,
                context,
            );
        }
        *self.h2_cell.lock().await = None;
        // Reclassify: undo the h2_calls increment from
        // run_h2_relay_with_send and bill this attempt as a fallback.
        // saturating_sub-style guard: only decrement if non-zero so a
        // direct caller of this helper from a non-Ok path can't
        // underflow the counter.
        let _ = self
            .h2_calls
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                if c > 0 {
                    Some(c - 1)
                } else {
                    None
                }
            });
        self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    /// Clear the h2 cell *only if* its generation matches the one the
    /// caller observed. Prevents the race where:
    ///   1. Task A holds SendRequest from generation N
    ///   2. Generation N's connection dies; Task B reopens → cell now
    ///      holds generation N+1 (healthy)
    ///   3. Task A's stale stream errors → unconditionally clearing
    ///      the cell would kill the healthy N+1
    ///
    /// With generation matching, A's poison is a no-op against N+1.
    async fn poison_h2_if_gen(&self, generation: u64) {
        let mut cell = self.h2_cell.lock().await;
        if let Some(c) = cell.as_ref() {
            if c.generation == generation {
                *cell = None;
            }
        }
    }

    /// Send one POST through the active h2 connection, follow up to 5
    /// redirects, and return `(status, headers, body)` — the same shape
    /// the h1 path's `read_http_response` produces, so callers can stay
    /// transport-agnostic from this point on.
    ///
    /// `path` is the HTTP path including the leading slash. The Host /
    /// :authority header is taken from `self.http_host` for the initial
    /// request and from the `Location` URL on redirect. `payload` is the
    /// body bytes; `content_type` is set when non-None (for the JSON
    /// envelope). Empty body + None content_type → GET (used for redirect
    /// follow-up).
    /// Run one h2 stream and return `(status, headers, body)`. Errors
    /// carry a `RequestSent` flag so the caller can distinguish "never
    /// sent" (safe to retry on h1) from "may have been processed by
    /// origin" (only safe to retry for idempotent methods).
    ///
    /// Two phases, two timeouts:
    ///   * **Ready (back-pressure):** bounded by `H2_READY_TIMEOUT_SECS`
    ///     (5 s constant). A stall here means the conn is saturated
    ///     under `MAX_CONCURRENT_STREAMS` (or dead at the muxer level)
    ///     but no stream has opened — `RequestSent::No`.
    ///   * **Response (post-send):** bounded by the caller-provided
    ///     `response_deadline`. After `send_request` returns Ok the
    ///     headers are queued; we conservatively treat any later
    ///     failure or timeout as `RequestSent::Maybe`. Caller picks
    ///     the deadline so legitimate slow Apps Script calls and
    ///     Full-mode batches with custom `request_timeout_secs` aren't
    ///     cut off at an arbitrary fixed cap.
    #[allow(clippy::too_many_arguments)]
    async fn h2_round_trip(
        &self,
        send: h2::client::SendRequest<Bytes>,
        method: &str,
        path: &str,
        host: &str,
        payload: Bytes,
        content_type: Option<&str>,
        response_deadline: Duration,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), (FronterError, RequestSent)> {
        // h2 requires absolute-form URIs with the :authority pseudo-header
        // populated from the Host. http::Request's URI parser accepts
        // `https://{host}{path}` for that.
        let uri = format!("https://{}{}", host, path);
        let mut builder = http::Request::builder().method(method).uri(uri);
        // Apps Script accepts gzip on the response; mirror the h1 path so
        // payloads stay small.
        builder = builder.header("accept-encoding", "gzip");
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
            // Paired with the `?hl=<lang>` query parameter on Apps
            // Script paths so the envelope classifier patterns match
            // (default `"en"` keeps the wire-shape `en-US,en;q=0.9` for
            // existing fingerprints). Only set on the initial POST —
            // redirect follow-ups (content_type == None) target
            // googleusercontent.com which doesn't need this hint.
            builder = builder.header("accept-language", self.apps_script_accept_lang.as_str());
        }
        let req = builder.body(()).map_err(|e| {
            (
                FronterError::Relay(format!("h2 request build: {}", e)),
                RequestSent::No,
            )
        })?;

        // Phase 1: ready/back-pressure. Bounded short. Timeout here
        // means saturation, not server-side processing — the stream
        // hasn't even opened, so `RequestSent::No`.
        let ready_result =
            tokio::time::timeout(Duration::from_secs(H2_READY_TIMEOUT_SECS), send.ready()).await;
        let mut send = match ready_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err((
                    FronterError::Relay(format!("h2 ready: {}", e)),
                    RequestSent::No,
                ));
            }
            Err(_) => {
                return Err((FronterError::Timeout, RequestSent::No));
            }
        };

        let has_body = !payload.is_empty();
        // send_request is synchronous; it queues the HEADERS frame.
        // After this returns Ok we conservatively assume the request
        // reached the server. An Err here means the stream couldn't
        // be opened (e.g. connection-level GOAWAY), safe to retry.
        let (response_fut, mut body_tx) = send.send_request(req, !has_body).map_err(|e| {
            (
                FronterError::Relay(format!("h2 send_request: {}", e)),
                RequestSent::No,
            )
        })?;

        if has_body {
            // body_tx errors here are RequestSent::Maybe — headers were
            // already queued, so we may have invoked Apps Script's doPost
            // even if the body never finished.
            body_tx.send_data(payload, true).map_err(|e| {
                (
                    FronterError::Relay(format!("h2 send_data: {}", e)),
                    RequestSent::Maybe,
                )
            })?;
        }

        // Phase 2: response headers + body drain. Bounded by the
        // caller's deadline. Errors and timeout here are
        // `RequestSent::Maybe` — the request is on the wire and may
        // already have side effects.
        let response_phase = async {
            let response = response_fut.await.map_err(|e| {
                (
                    FronterError::Relay(format!("h2 response: {}", e)),
                    RequestSent::Maybe,
                )
            })?;
            let (parts, mut body) = response.into_parts();
            let status = parts.status.as_u16();

            // Convert headers to the (String, String) Vec the rest of
            // the codebase expects. Multi-valued headers (set-cookie,
            // etc.) are expanded one entry per value, matching
            // httparse's emission.
            let mut headers: Vec<(String, String)> = Vec::with_capacity(parts.headers.len());
            for (name, value) in parts.headers.iter() {
                if let Ok(v) = value.to_str() {
                    headers.push((name.as_str().to_string(), v.to_string()));
                }
            }

            // Drain body. Release flow-control credit per chunk so
            // large responses don't stall after the initial 4 MB window.
            let mut buf: Vec<u8> = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|e| {
                    (
                        FronterError::Relay(format!("h2 body chunk: {}", e)),
                        RequestSent::Maybe,
                    )
                })?;
                let n = chunk.len();
                buf.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(n);
            }
            Ok::<_, (FronterError, RequestSent)>((status, headers, buf))
        };

        let (status, headers, mut buf) =
            match tokio::time::timeout(response_deadline, response_phase).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err((FronterError::Timeout, RequestSent::Maybe)),
            };

        // Mirror `read_http_response`: if the server gzipped the body
        // (we asked for it via accept-encoding), decompress before
        // handing back so downstream JSON / envelope parsers see plain
        // bytes regardless of transport.
        if let Some(enc) = header_get(&headers, "content-encoding") {
            if enc.eq_ignore_ascii_case("gzip") {
                if let Ok(decoded) = decode_gzip(&buf) {
                    buf = decoded;
                }
            }
        }

        Ok((status, headers, buf))
    }

    /// Run a full relay round-trip over h2: initial POST + up to 5
    /// redirect hops. `path` is the Apps Script `/macros/s/{id}/exec`
    /// path. Returns the same `(status, headers, body)` triple as the
    /// h1 path on success.
    ///
    /// `response_deadline` bounds the post-send phase of each round
    /// trip (response headers + body drain). The ready/back-pressure
    /// phase has its own short bound (`H2_READY_TIMEOUT_SECS`).
    /// Caller picks the deadline based on its own outer budget:
    ///   * Apps-Script direct (`relay_uncoalesced`): a few seconds
    ///     under `REQUEST_TIMEOUT_SECS` (25 s) so an h2 timeout still
    ///     leaves room for an h1 fallback.
    ///   * Full-mode tunnel (`tunnel_request` / `tunnel_batch_request_to`):
    ///     `self.batch_timeout` so the user's
    ///     `request_timeout_secs` setting actually applies.
    ///
    /// On error, the second tuple field is `RequestSent::No` if the
    /// request never reached Apps Script (safe to retry on h1) or
    /// `RequestSent::Maybe` if it may have been processed (replaying
    /// risks duplicating side effects for non-idempotent methods).
    /// `ensure_h2` returning None always reports `RequestSent::No`.
    ///
    /// Takes `payload` as `Bytes` so callers can clone (Arc bump,
    /// not memcpy) when they want to retain a copy for h1 fallback.
    async fn h2_relay_request(
        &self,
        path: &str,
        payload: Bytes,
        response_deadline: Duration,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), (FronterError, RequestSent)> {
        let (send, generation) = match self.ensure_h2().await {
            Some(s) => s,
            None => {
                // ensure_h2 returning None covers:
                //   1. force_http1 / sticky-disabled — never tried h2
                //      this call. NOT a fallback, don't count.
                //   2. open_h2 just failed / timed out / backoff active.
                //      We DID attempt h2 and lost it; count as fallback
                //      so the stat reflects reality. `ensure_h2` itself
                //      sets the backoff timestamp on failure.
                if !self.h2_disabled.load(Ordering::Relaxed) {
                    self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
                }
                return Err((
                    FronterError::Relay("h2 unavailable".into()),
                    RequestSent::No,
                ));
            }
        };

        self.run_h2_relay_with_send(send, generation, path, payload, response_deadline)
            .await
    }

    /// Inner h2 relay loop — split out so tests can inject a
    /// `SendRequest` (from a local h2c test server) without going
    /// through `ensure_h2`'s real-network handshake.
    ///
    /// Each h2_round_trip uses its own internal phase-split timeouts
    /// (ready=5s constant, response=`response_deadline`). No outer
    /// wrap is needed here — the inner timeouts are what poisons the
    /// cell on stall.
    async fn run_h2_relay_with_send(
        &self,
        send: h2::client::SendRequest<Bytes>,
        generation: u64,
        path: &str,
        payload: Bytes,
        response_deadline: Duration,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), (FronterError, RequestSent)> {
        let mut current_host = self.http_host.to_string();
        let mut current_path = path.to_string();

        let res = self
            .h2_round_trip(
                send.clone(),
                "POST",
                &current_path,
                &current_host,
                payload,
                Some("application/json"),
                response_deadline,
            )
            .await;
        let (mut status, mut hdrs, mut body) = match res {
            Ok(t) => t,
            Err((e, sent)) => {
                self.poison_h2_if_gen(generation).await;
                self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
                return Err((e, sent));
            }
        };

        // The initial POST already succeeded — the request reached
        // Apps Script. From here on, redirect-follow failures are
        // RequestSent::Maybe regardless of where they land in the
        // chain, because the *original* Apps Script call may have
        // already executed.
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&hdrs, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            current_host = rhost.unwrap_or(current_host);
            current_path = rpath;
            let res = self
                .h2_round_trip(
                    send.clone(),
                    "GET",
                    &current_path,
                    &current_host,
                    Bytes::new(),
                    None,
                    response_deadline,
                )
                .await;
            match res {
                Ok((s, h, b)) => {
                    status = s;
                    hdrs = h;
                    body = b;
                }
                Err((e, _)) => {
                    self.poison_h2_if_gen(generation).await;
                    self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
                    return Err((e, RequestSent::Maybe));
                }
            }
        }

        self.h2_calls.fetch_add(1, Ordering::Relaxed);
        Ok((status, hdrs, body))
    }

    /// Relay an HTTP request through Apps Script.
    /// Returns a raw HTTP/1.1 response (status line + headers + body) suitable
    /// for writing back to the browser over an MITM'd TLS stream.
    pub async fn relay(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        // Optional URL rewrite for X/Twitter GraphQL (issue #16). Applied
        // here, at the top of relay(), so it affects BOTH the cache key
        // (so matching requests collapse into one entry) AND the URL that
        // gets sent upstream to Apps Script (so Apps Script only has to
        // fetch the trimmed variant, cutting quota usage).
        let normalized;
        let url: &str = if self.normalize_x_graphql {
            normalized = normalize_x_graphql_url(url);
            normalized.as_str()
        } else {
            url
        };

        // SABR quality-track strip — applied before the exit-node
        // short-circuit so both paths benefit. The full decision +
        // trade-off is in `maybe_strip_sabr_body` so the gate can be
        // unit-tested without invoking the network-coupled relay path.
        let stripped_body;
        let body: &[u8] = match self.maybe_strip_sabr_body(method, url, body) {
            None => body,
            Some(stripped) => {
                stripped_body = stripped;
                stripped_body.as_slice()
            }
        };

        // Exit-node short-circuit: route through the configured second-hop
        // relay (Deno Deploy / fly.io / etc.) for hosts that need a
        // non-Google exit IP. The cache + coalesce layer below is bypassed
        // for these — exit-node-eligible hosts are the ones with active
        // anti-bot challenges (CF Turnstile, ChatGPT login, Claude.ai,
        // grok.com), and serving cached responses across users for those
        // would be wrong (auth tokens, session state, per-user
        // personalization). Falls back to the regular Apps Script relay
        // if the exit node fails (network error, 5xx from the exit node, etc.)
        // so a misconfigured or down exit node doesn't take the user
        // offline for the sites that DON'T need it.
        if self.exit_node_matches(url) {
            let t0 = Instant::now();
            match self.relay_via_exit_node(method, url, headers, body).await {
                Ok(bytes) => {
                    self.record_site(
                        url,
                        false,
                        bytes.len() as u64,
                        t0.elapsed().as_nanos() as u64,
                    );
                    // Bot-block detection for the exit-node path —
                    // rationale + hint shape lives in `bot_block`'s
                    // module docs. This branch is the parallel hook to
                    // the one in `relay_uncoalesced`, which the
                    // exit-node short-circuit bypasses.
                    if let Some(host) = extract_host(url) {
                        crate::bot_block::note_if_blocked_via_exit_node(&host, &bytes);
                    }
                    return bytes;
                }
                Err(e) if !e.is_retryable() => {
                    // The exit node may have already processed this
                    // request (h2 post-send failure on a POST etc.).
                    // Don't fall through to the direct path — that
                    // would re-send to the same destination via Apps
                    // Script and duplicate the side effect.
                    tracing::warn!(
                        "exit node failed for {} and request was already sent ({}); not falling back to direct Apps Script",
                        url,
                        e,
                    );
                    self.relay_failures.fetch_add(1, Ordering::Relaxed);
                    let inner = e.into_inner();
                    self.record_site(url, false, 0, t0.elapsed().as_nanos() as u64);
                    return error_response(502, &format!("Relay error: {}", inner));
                }
                Err(e) => {
                    tracing::warn!(
                        "exit node failed for {}: {} — falling back to direct Apps Script",
                        url,
                        e
                    );
                    // fall through to the regular relay path below
                }
            }
        }

        // Range requests are partial-content responses; caching or
        // coalescing them against a non-range key would be catastrophic
        // (wrong bytes for the wrong consumer). The range-parallel
        // downloader calls `relay()` concurrently with N different Range
        // headers for the same URL, and absolutely needs each call to go
        // to the relay independently. Simplest correct answer: if any
        // Range header is present, skip cache and coalesce entirely.
        let has_range = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let coalescible = is_cacheable_method(method) && body.is_empty() && !has_range;
        let key = if coalescible {
            Some(cache_key(method, url))
        } else {
            None
        };
        let t_start = Instant::now();

        if let Some(ref k) = key {
            if let Some(hit) = self.cache.get(k) {
                tracing::debug!("cache hit: {}", url);
                self.record_site(
                    url,
                    true,
                    hit.len() as u64,
                    t_start.elapsed().as_nanos() as u64,
                );
                return hit;
            }
        }

        // Coalesce concurrent identical requests: only the first caller actually
        // hits the relay; waiters subscribe to the same broadcast channel.
        let waiter = if let Some(ref k) = key {
            let mut inflight = self.inflight.lock().await;
            match inflight.get(k) {
                Some(tx) => {
                    let rx = tx.subscribe();
                    self.coalesced.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("coalesced: {}", url);
                    Some(rx)
                }
                None => {
                    let (tx, _) = broadcast::channel(1);
                    inflight.insert(k.clone(), tx);
                    None
                }
            }
        } else {
            None
        };

        if let Some(mut rx) = waiter {
            match rx.recv().await {
                Ok(bytes) => return bytes,
                Err(_) => return error_response(502, "coalesced request dropped"),
            }
        }

        let bytes = self
            .relay_uncoalesced(method, url, headers, body, key.as_deref())
            .await;

        if let Some(ref k) = key {
            let mut inflight = self.inflight.lock().await;
            if let Some(tx) = inflight.remove(k) {
                let _ = tx.send(bytes.clone());
            }
        }

        self.record_site(
            url,
            false,
            bytes.len() as u64,
            t_start.elapsed().as_nanos() as u64,
        );
        bytes
    }

    /// Range-parallel relay — the big difference between this port and
    /// the upstream Python version. Apps Script's per-call cost is
    /// ~flat (1-2s regardless of payload), so a 10MB single GET is
    /// ~10s round-trip; the same 10MB sliced into 40 x 256KB chunks
    /// and fetched 16-at-a-time is 3-4 round-trips, total ~6-8s, and
    /// the client sees the first byte in 1-2s instead of 10. This is
    /// what actually makes YouTube video playback viable through the
    /// relay — without it, googlevideo.com chunks timeout or stall
    /// while the player waits for the next 10s-away Apps Script call
    /// to finish.
    ///
    /// Flow (mirrors upstream `relay_parallel`):
    ///   1. For anything other than GET-without-body, defer to
    ///      `relay()` — range requests on POSTs / PUTs aren't well
    ///      defined, and the user-sent-Range-header case is handled
    ///      by relay() already (we skip cache for it).
    ///   2. Probe with `Range: bytes=0-<chunk-1>`.
    ///   3. 200 back (origin doesn't support ranges) → write as-is.
    ///   4. 206 back → parse Content-Range total. If Content-Range says
    ///      the entity fits in the first probe, rewrite the 206 to a 200
    ///      so the client — which never asked for a
    ///      range — doesn't choke on a stray Partial Content. (x.com
    ///      and Cloudflare turnstile in particular reject unsolicited
    ///      206 on XHR/fetch.)
    ///   5. Else: compute the remaining ranges, fetch them with
    ///      bounded concurrency. Two output modes:
    ///        * `total ≤ APPS_SCRIPT_BODY_MAX_BYTES` (buffered): stitch
    ///          all chunks into one `Vec<u8>`, transform the response
    ///          head, write to caller in one shot. On chunk failure,
    ///          fall back to a single GET — Apps Script can deliver
    ///          the file in one piece up to its ~40 MiB cap. Safety
    ///          net intact.
    ///        * `total > APPS_SCRIPT_BODY_MAX_BYTES` (streaming): write
    ///          the response head with `Content-Length: total` and the
    ///          probe body straight to the client, then stream each
    ///          remaining chunk to the client as it arrives in order.
    ///          No buffered fallback (we've already committed bytes on
    ///          the wire), but single-GET fallback wouldn't fit through
    ///          Apps Script for files this size anyway — streaming with
    ///          truncation on hard chunk failure beats today's 25s
    ///          timeout + 504 (#1042).
    ///
    /// `transform_head` lets the caller rewrite the response head block
    /// (e.g. CORS injection) without coupling this module to the
    /// caller's policy. The input is the head bytes from "HTTP/1.x …"
    /// through the trailing `\r\n\r\n`; the output should be the same
    /// shape. Pass an identity closure if no rewrite is needed.
    pub async fn relay_parallel_range_to<W, F>(
        &self,
        writer: &mut W,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        transform_head: F,
    ) -> std::io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
        F: Fn(&[u8]) -> Vec<u8>,
    {
        self.do_relay_parallel_range_to(
            writer,
            method,
            url,
            headers,
            body,
            &transform_head,
            /*streaming_allowed=*/ true,
        )
        .await
    }

    /// Shared dispatch for [`Self::relay_parallel_range_to`] (streaming
    /// enabled) and [`Self::relay_parallel_range`] (the `Vec<u8>`
    /// compatibility wrapper, streaming disabled).
    ///
    /// When `streaming_allowed=false`, the function refuses the
    /// streaming branch even when the response is large enough to
    /// warrant it — instead falling back to a plain `self.relay()`
    /// single GET, matching the pre-1.9.23 wrapper contract that a
    /// `Vec<u8>` return must never be a fake-200 with the
    /// `Content-Length` of the full advertised total but only a
    /// prefix of the body (Issue #162). The streaming branch can
    /// commit head + partial body before discovering a chunk
    /// failure; that's correct for a wire writer (download client
    /// sees Content-Length mismatch, retries via Range from the
    /// partial position) but a buffered `Vec<u8>` consumer has no
    /// way to react to the truncation, so we keep them off that
    /// path entirely.
    #[allow(clippy::too_many_arguments)]
    async fn do_relay_parallel_range_to<W, F>(
        &self,
        writer: &mut W,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        transform_head: &F,
        streaming_allowed: bool,
    ) -> std::io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
        F: Fn(&[u8]) -> Vec<u8>,
    {
        const MAX_PARALLEL: usize = 16;
        let chunk = RANGE_PARALLEL_CHUNK_BYTES;

        if method != "GET" || !body.is_empty() {
            let raw = self.relay(method, url, headers, body).await;
            return write_response_with_head_transform(writer, &raw, &transform_head).await;
        }
        // If the client already sent a Range header, honour it as-is —
        // don't second-guess a caller that knows what bytes they want.
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range")) {
            let raw = self.relay(method, url, headers, body).await;
            return write_response_with_head_transform(writer, &raw, &transform_head).await;
        }

        // Probe with the first chunk.
        let mut probe_headers: Vec<(String, String)> = headers.to_vec();
        probe_headers.push(("Range".into(), format!("bytes=0-{}", chunk - 1)));
        let first = self.relay(method, url, &probe_headers, body).await;

        let (status, resp_headers, resp_body) = match split_response(&first) {
            Some(v) => v,
            None => {
                return write_response_with_head_transform(writer, &first, &transform_head).await
            }
        };

        if status != 206 {
            // Origin returned the whole thing (or an error). Either way,
            // pass through.
            return write_response_with_head_transform(writer, &first, &transform_head).await;
        }

        let probe_range = match validate_probe_range(status, &resp_headers, resp_body, chunk - 1) {
            Some(r) => r,
            None => {
                tracing::warn!(
                    "range-parallel: probe returned invalid 206 for {}; falling back to single GET",
                    url,
                );
                let raw = self.relay(method, url, headers, body).await;
                return write_response_with_head_transform(writer, &raw, &transform_head).await;
            }
        };
        let total = probe_range.total;

        if total <= chunk || (probe_range.end + 1) >= total {
            let raw = rewrite_206_to_200(&first);
            return write_response_with_head_transform(writer, &raw, &transform_head).await;
        }

        // Range planning is lazy via `plan_remaining_ranges` — a hostile
        // origin can advertise `Content-Range: bytes 0-262143/<huge>` and
        // pass the probe checks (matching 256 KiB body, claimed total >
        // probe end), so eagerly building a `Vec<(u64, u64)>` for the
        // full plan would let it drive arbitrary allocations on the
        // stream branch (a 100 TiB advertised total at 256 KiB chunks
        // is ~400M tuples, ~6 GB). PR #151's original `MAX_STITCHED_…`
        // guard prevented this on the buffered side; lazy iteration
        // preserves that protection for streaming without imposing a
        // hard ceiling on legitimate large downloads.
        let probe_end = probe_range.end;
        let expected_chunks = (total - probe_end - 1).div_ceil(chunk);

        // Branch: buffered stitch (fallback-safe) vs. streaming vs.
        // single-GET fallback for the compat wrapper. See
        // `dispatch_range_response` doc for the per-caller contract.
        match dispatch_range_response(total, streaming_allowed) {
            RangeDispatch::Stream => {
                tracing::info!(
                    "range-parallel-stream: {} bytes total, {} chunks after probe, up to {} in flight",
                    total, expected_chunks, MAX_PARALLEL,
                );
                let fetches = self.fetch_chunks_stream(
                    url,
                    headers,
                    plan_remaining_ranges(probe_end, total, chunk),
                    total,
                    MAX_PARALLEL,
                );
                return stream_range_response_to(
                    writer,
                    &resp_headers,
                    resp_body,
                    total,
                    fetches,
                    transform_head,
                    url,
                )
                .await;
            }
            RangeDispatch::FallbackSingleGet => {
                // `Vec<u8>` wrapper above 64 MiB: stream branch is
                // off-limits (truncate-then-Err can't be reacted to),
                // so we fall back to a single GET — same path the
                // pre-1.9.23 wrapper took above its 64 MiB cap. Apps
                // Script will typically return 502/504 because the
                // response exceeds its delivery ceiling, but that's
                // the contract: callers see Apps Script's error, not
                // a half-written success.
                tracing::info!(
                    "range-parallel: {} bytes total > {} buffered cap and streaming disallowed; falling back to single GET",
                    total, BUFFERED_STITCH_MAX_BYTES,
                );
                let raw = self.relay(method, url, headers, body).await;
                return write_response_with_head_transform(writer, &raw, transform_head).await;
            }
            RangeDispatch::RejectTooLarge => {
                // Quota-DoS guard: refuse the response. Streaming
                // an advertised 16 GiB+ total would issue ~65 k
                // chunk Apps Script calls (~daily quota on the free
                // tier) per pwned URL — see `MAX_STREAMED_RANGE_BYTES`.
                // 502 is the right status: this is upstream-induced
                // refusal, not a client error.
                tracing::warn!(
                    "range-parallel: refusing {} bytes total for {} — exceeds {} streaming cap",
                    total,
                    url,
                    MAX_STREAMED_RANGE_BYTES,
                );
                let raw = error_response(
                    502,
                    "Advertised Content-Range total exceeds relay's streaming \
                     ceiling. The origin reported a size larger than the relay \
                     is willing to fetch through Apps Script; refusing to spend \
                     daily quota on a likely-hostile or buggy origin.",
                );
                return write_response_with_head_transform(writer, &raw, transform_head).await;
            }
            RangeDispatch::Buffered => {
                // Fall through to the buffered stitch code below.
            }
        }

        tracing::info!(
            "range-parallel: {} bytes total, {} chunks remaining after probe, up to {} in flight",
            total,
            expected_chunks,
            MAX_PARALLEL,
        );

        // Buffered stitch. `total` is bounded above by
        // `BUFFERED_STITCH_MAX_BYTES` (64 MiB) for the `Vec<u8>`
        // wrapper path and by `APPS_SCRIPT_BODY_MAX_BYTES` (40 MiB)
        // for the writer-based API — see `dispatch_range_response`.
        // Either way, well inside `usize` even on 32-bit targets, and
        // the lazy range iterator produces at most ~256 tuples for a
        // 64 MiB total at 256 KiB chunks, so collecting results into
        // `Vec<_>` for stitching is cheap.
        let total_usize = total as usize;

        // Concurrent fetch with `buffered` — preserves input order
        // (important for stitching) and caps in-flight count. Each task
        // calls back into `relay()`, which already has retry + fan-out
        // wiring on single-request granularity; we don't duplicate
        // those here.
        use futures_util::stream::StreamExt;
        let fetches = self
            .fetch_chunks_stream(
                url,
                headers,
                plan_remaining_ranges(probe_end, total, chunk),
                total,
                MAX_PARALLEL,
            )
            .collect::<Vec<_>>()
            .await;

        // Stitch: probe body first, then the chunks in order.
        let mut full = Vec::with_capacity(total_usize);
        full.extend_from_slice(resp_body);
        for (start, end, chunk) in fetches {
            match chunk {
                Ok(chunk) => full.extend_from_slice(&chunk),
                Err(reason) => {
                    // Issue #162: silently rewriting the probe to a 200
                    // here truncates the response to whatever the probe
                    // saw (typically 256 KiB — the chunk size). Browsers
                    // see HTTP 200 + Content-Length=262144 and treat
                    // the download as complete; users reported "every
                    // file capped at 256 KB" because every download
                    // that hit this failure path landed there. Common
                    // triggers: Apps Script stripping Content-Range,
                    // origin returning 200-instead-of-206 on later
                    // chunks, total mismatch across chunks. Correct
                    // recovery is a fresh single GET — Apps Script
                    // fetches the full URL up to its ~40 MiB cap. Slow
                    // for big files vs. the parallel path but produces
                    // a complete response, which is what matters.
                    tracing::warn!(
                        "range-parallel: invalid chunk {}-{} for {} ({}); falling back to single GET",
                        start, end, url, reason,
                    );
                    let raw = self.relay(method, url, headers, body).await;
                    return write_response_with_head_transform(writer, &raw, &transform_head).await;
                }
            }
        }

        if (full.len() as u64) != total {
            // Same fallback rationale as the chunk-validation case
            // above: returning the probe truncates to 256 KiB. Single
            // GET is the only way to give the user a complete file
            // when the parallel stitch can't be trusted.
            tracing::warn!(
                "range-parallel: stitched {}/{} bytes for {}; falling back to single GET",
                full.len(),
                total,
                url,
            );
            let raw = self.relay(method, url, headers, body).await;
            return write_response_with_head_transform(writer, &raw, &transform_head).await;
        }

        // Build a 200 OK with Content-Length = full body length. Drop
        // the Content-Range header (no longer applicable) and
        // Transfer-Encoding/Content-Encoding (origin already decoded
        // what we got; we ship plain bytes).
        let raw = assemble_full_200(&resp_headers, &full);
        write_response_with_head_transform(writer, &raw, &transform_head).await
    }

    /// Backward-compatible wrapper around `relay_parallel_range_to`
    /// that buffers the full response into a `Vec<u8>` before
    /// returning. Retained so downstream callers (and external
    /// consumers of `rahgozar` as a library) that depend on the pre-
    /// 1.9.23 `-> Vec<u8>` signature keep working without code
    /// changes. New code should prefer `relay_parallel_range_to`,
    /// which streams large files chunk-by-chunk instead of buffering
    /// the response in memory.
    ///
    /// **Pre-1.9.23 contract preservation:** for responses above the
    /// buffered ceiling (`BUFFERED_STITCH_MAX_BYTES`, 64 MiB) the
    /// wrapper deliberately falls back to a single `relay()` call
    /// rather than taking the streaming branch. Streaming commits a
    /// `200 OK` head with `Content-Length: <total>` plus a partial
    /// body before discovering chunk failures — that's correct for a
    /// wire writer (download client retries via Range) but exactly
    /// the "fake-truncated-success" contract violation from Issue
    /// #162 once the bytes are collected into a buffer the caller
    /// can't react to. Wrapper callers therefore see the same upper
    /// bound on response size and the same fallback semantics they
    /// had before 1.9.23; only the failure surface changes (502/504
    /// from Apps Script for the >40 MiB case, same as before).
    pub async fn relay_parallel_range(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let identity = |head: &[u8]| head.to_vec();
        // Writing to a `Vec<u8>` through `VecAsyncWriter` never fails
        // (no I/O), so the `io::Result` from the writer-based API is
        // always `Ok` here — modulo the streaming branch's chunk-
        // validation error path. Disabling streaming
        // (`streaming_allowed=false`) keeps the wrapper off that
        // path, so the only `Err` cases left are unreachable for
        // `VecAsyncWriter`.
        let _ = self
            .do_relay_parallel_range_to(
                &mut VecAsyncWriter(&mut buf),
                method,
                url,
                headers,
                body,
                &identity,
                /*streaming_allowed=*/ false,
            )
            .await;
        buf
    }

    /// Build the concurrent fetch stream used by both the buffered and
    /// streaming branches of `relay_parallel_range_to`. Each yielded
    /// item is `(start, end, Result<chunk_body, validation_reason>)`
    /// in input order (via `buffered`, which preserves order while
    /// capping in-flight count). Splitting this out keeps the
    /// branching at the call site small and lets tests for the
    /// streaming writer use a synthetic `Stream` with no
    /// `DomainFronter` dependency.
    fn fetch_chunks_stream<'a, I>(
        &'a self,
        url: &str,
        base_headers: &[(String, String)],
        ranges: I,
        total: u64,
        max_parallel: usize,
    ) -> impl futures_util::Stream<Item = (u64, u64, Result<Vec<u8>, &'static str>)> + 'a
    where
        I: IntoIterator<Item = (u64, u64)> + 'a,
        I::IntoIter: 'a,
    {
        use futures_util::stream::{self, StreamExt};
        let url_owned = url.to_string();
        let base_h = base_headers.to_vec();
        stream::iter(ranges)
            .map(move |(s, e)| {
                let url = url_owned.clone();
                let mut h = base_h.clone();
                // Force a single Range header — if the caller's headers
                // somehow already had one we wouldn't be here, but be
                // defensive anyway.
                h.retain(|(k, _)| !k.eq_ignore_ascii_case("range"));
                h.push(("Range".into(), format!("bytes={}-{}", s, e)));
                async move {
                    // Bounded per-chunk retry. A multi-GB download splits
                    // into tens of thousands of 256 KiB chunks; a single
                    // transient Apps Script timeout would otherwise kill
                    // the entire stream (see archive.org issue: chunk
                    // 5767168-6029311 of a 3.8 GB download hit
                    // REQUEST_TIMEOUT_SECS, `relay()` returned a synthetic
                    // 504, `extract_exact_range_body` rejected it as
                    // "expected 206 Partial Content", and the consumer
                    // truncated the response after ~5.6 MB).
                    //
                    // `do_relay_with_retry` doesn't help here because
                    // `relay_uncoalesced` catches timeouts and converts
                    // them to a synthetic 504 *body* (intentional — the
                    // 504 carries a user-readable hint about quota
                    // exhaustion), so the retry path above us never sees
                    // an `Err`. Chunk GETs with explicit Range are fully
                    // idempotent so re-firing is safe; we only retry
                    // categories that are plausibly transient
                    // (relay-level 5xx, unparseable responses).
                    //
                    // A small jittered backoff between attempts matters
                    // for the single-script-id deployment (typical
                    // user config) where every retry lands on the same
                    // Apps Script project; back-to-back retries would
                    // race the still-stuck origin-side execution.
                    // Multi-deployment configs rotate scripts inside
                    // `relay()` anyway, so the backoff is harmless there.
                    const MAX_CHUNK_ATTEMPTS: usize = 3;
                    let mut last_err: &'static str = "no attempts";
                    let mut attempts_used: usize = 0;
                    for attempt in 0..MAX_CHUNK_ATTEMPTS {
                        attempts_used = attempt + 1;
                        let raw = self.relay("GET", &url, &h, &[]).await;
                        match extract_exact_range_body(&raw, s, e, total) {
                            Ok(body) => return (s, e, Ok(body)),
                            Err(reason) => {
                                last_err = reason;
                                if !chunk_failure_is_retryable(&raw) {
                                    break;
                                }
                                if attempt + 1 < MAX_CHUNK_ATTEMPTS {
                                    tracing::warn!(
                                        "range-parallel-stream: chunk {}-{} attempt {} failed \
                                         ({}); retrying",
                                        s,
                                        e,
                                        attempt + 1,
                                        reason,
                                    );
                                    let backoff_ms =
                                        rand::thread_rng().gen_range(CHUNK_RETRY_BACKOFF_RANGE_MS);
                                    tokio::time::sleep(std::time::Duration::from_millis(
                                        backoff_ms,
                                    ))
                                    .await;
                                }
                            }
                        }
                    }
                    // Single terminal log so the consumer's "invalid chunk
                    // / truncating response" warning has a paired
                    // "gave up after N attempts" line right before it —
                    // makes the failure mode obvious in the log without
                    // requiring the reader to count retry warnings.
                    tracing::warn!(
                        "range-parallel-stream: chunk {}-{} giving up after {} attempt(s) ({})",
                        s,
                        e,
                        attempts_used,
                        last_err,
                    );
                    (s, e, Err(last_err))
                }
            })
            .buffered(max_parallel)
    }

    async fn relay_uncoalesced(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        cache_key_opt: Option<&str>,
    ) -> Vec<u8> {
        self.relay_calls.fetch_add(1, Ordering::Relaxed);
        let bytes = match timeout(
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
            self.do_relay_with_retry(method, url, headers, body),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                self.relay_failures.fetch_add(1, Ordering::Relaxed);
                self.log_relay_failure(&e);
                return error_response(502, &format!("Relay error: {}", e));
            }
            Err(_) => {
                // Timeout here means Apps Script didn't respond within
                // REQUEST_TIMEOUT_SECS (currently 25). The most common
                // cause by far is the account's daily UrlFetchApp quota
                // being exhausted — once Google kills the script mid-exec,
                // our relay hangs until timeout because no body ever comes
                // back. Surface that possibility in the message instead
                // of just "timeout", which has burned several users asking
                // "why did it work yesterday" (see issues #99, #111, #105).
                self.relay_failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!("Relay timeout — Apps Script unresponsive");
                return error_response(
                    504,
                    "Relay timeout — Apps Script did not respond. \
                     Most likely cause: daily UrlFetchApp quota exhausted \
                     (resets 00:00 UTC). Other possibilities: script.google.com \
                     unreachable from your network, or the Apps Script edge is having issues. \
                     Check the script's Executions tab at script.google.com for the real error.",
                );
            }
        };
        self.bytes_relayed
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        // Daily-budget counters (reset at 00:00 UTC). Only counts
        // successful relays — the two error branches above don't reach
        // here, matching what Google actually billed to quota.
        self.record_today(bytes.len() as u64);

        // Centralised bot-block detection. Every Apps Script response
        // that returns bytes to a caller — buffered MITM, plain-HTTP
        // relay, parallel-range probes, individual range chunks —
        // passes through here. Hooking in once at this layer keeps it
        // off the exit-node short-circuit path (which returns earlier
        // in `relay()` and *should* skip detection: a block via the
        // user's own exit node is a different problem class) and off
        // cache/coalesce returns (the original fetch already ran).
        // Dedup'd per-host inside `bot_block` so noisy multi-asset
        // page loads don't spam the log.
        if let Some(host) = extract_host(url) {
            crate::bot_block::note_if_blocked(&host, &bytes);
        }

        if let Some(k) = cache_key_opt {
            if let Some(ttl) = parse_ttl(&bytes, url) {
                tracing::debug!("cache store: {} ttl={}s", url, ttl.as_secs());
                self.cache.put(k.to_string(), bytes.clone(), ttl);
            }
        }
        bytes
    }

    async fn do_relay_with_retry(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        // Fan-out path: fire N instances in parallel, return first Ok, cancel
        // the rest. Clamps to number of available script IDs so the single-ID
        // case is a no-op even if parallel_relay>1 was configured.
        //
        // `select_ok` cancels the loser futures, but those futures only own
        // the OUR-side I/O (TLS write, response read) — the Apps Script
        // server has no idea the racing Rust task is gone, so every fan-out
        // call still completes server-side and Apps Script's
        // `UrlFetchApp.fetch()` to the destination still fires. For
        // **non-idempotent** methods (POST / PUT / PATCH / DELETE) this
        // surfaces as duplicate writes at the destination — a comment
        // posted twice, a vote double-counted, a payment double-charged.
        //
        // Reported in #743: parallel_relay=2 + a POST to GitHub created
        // two issue comments per submission. Same root cause as the
        // SAFE_REPLAY_METHODS guard in Code.gs's `_doBatch` fallback —
        // safe methods are idempotent, so re-firing is at worst wasteful;
        // unsafe methods can have side effects, so re-firing is incorrect.
        //
        // Drop to sequential for non-idempotent methods regardless of
        // `parallel_relay` setting. Users keep p95 wins on browsing /
        // GET-heavy traffic (the common case) and don't lose correctness
        // on form submits.
        let method_safe_for_fanout = is_method_safe_for_fanout(method);
        let fan = self.parallel_relay.min(self.script_ids.len()).max(1);
        if fan >= 2 && method_safe_for_fanout {
            return self
                .do_relay_parallel(method, url, headers, body, fan)
                .await;
        }

        // Sequential path: one retry on connection failure, *unless*
        // the failure is `FronterError::NonRetryable` — that wrapper
        // says "the request may have already reached the server, do
        // not duplicate." Without this guard, an h2 post-send failure
        // on a non-idempotent method (POST/PUT/PATCH/DELETE) that the
        // h2 layer correctly refused to replay on h1 would be
        // re-issued here anyway, defeating the safety policy.
        match self.do_relay_once(method, url, headers, body).await {
            Ok(v) => Ok(v),
            Err(e) if !e.is_retryable() => {
                tracing::warn!(
                    "relay attempt 1 failed and is non-retryable ({}); not duplicating {} {}",
                    e,
                    method,
                    url,
                );
                Err(e.into_inner())
            }
            Err(e) => {
                tracing::debug!("relay attempt 1 failed: {}; retrying", e);
                self.do_relay_once(method, url, headers, body).await
            }
        }
    }

    async fn do_relay_parallel(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        fan: usize,
    ) -> Result<Vec<u8>, FronterError> {
        use futures_util::future::FutureExt;
        let ids = self.next_script_ids(fan);
        if ids.is_empty() {
            return Err(FronterError::Relay("no script_ids available".into()));
        }

        // Build one future per script, each a pinned boxed future so we can
        // `select_ok` over them.
        let mut futs = Vec::with_capacity(ids.len());
        for sid in ids {
            let fut = self
                .do_relay_once_with(sid.clone(), method, url, headers, body)
                .boxed();
            futs.push(fut);
        }

        // `select_ok`: drive all futures concurrently, return the first Ok
        // (cancelling the rest when the returned future is dropped). If all
        // error out, returns the last error.
        match futures_util::future::select_ok(futs).await {
            Ok((bytes, _remaining)) => Ok(bytes),
            Err(e) => Err(e),
        }
    }

    async fn do_relay_once(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let script_id = self.next_script_id();
        self.do_relay_once_with(script_id, method, url, headers, body)
            .await
    }

    async fn do_relay_once_with(
        &self,
        script_id: String,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        // Build once, wrap in Bytes (zero-copy move). h2 takes a clone
        // (Arc bump, not memcpy); h1 fallback uses the same Bytes via
        // Deref<&[u8]>. Saves a full payload allocation+copy per call
        // — meaningful on range-parallel fan-out where N copies fire
        // in parallel for one user-facing GET.
        let payload: Bytes = Bytes::from(self.build_payload_json(method, url, headers, body)?);
        let path = self.exec_path_for(&script_id);

        // h2 fast path: one shared TCP/TLS connection multiplexes all
        // streams.
        //
        // The h2 layer reports `RequestSent::No` when it can prove
        // the request never reached Apps Script (ensure_h2 unavailable,
        // ready/back-pressure timeout, send_request error). In that
        // case we fall through to h1 unconditionally — there's no
        // duplication risk.
        //
        // For `RequestSent::Maybe` (anything after send_request
        // succeeded) we only fall through for HTTP-idempotent methods.
        // POST / PUT / PATCH / DELETE get wrapped in
        // `FronterError::NonRetryable` so `do_relay_with_retry`'s
        // outer retry also skips replay — without that wrap, the
        // outer retry would re-issue the request anyway and the
        // safety policy would be illusory.
        match self
            .h2_relay_request(
                &path,
                payload.clone(),
                Duration::from_secs(H2_RESPONSE_DEADLINE_DEFAULT_SECS),
            )
            .await
        {
            Ok((status, _hdrs, _resp_body)) if is_h2_fronting_refusal_status(status) => {
                // Edge rejected the fronted h2 request before
                // forwarding to Apps Script. Sticky-disable h2,
                // log once, fall through to h1 — this request is
                // safe to replay because it never reached Apps Script.
                self.sticky_disable_h2_for_fronting_refusal(
                    status,
                    &format!("relay {} {}", method, url),
                )
                .await;
                // fall through to h1
            }
            Ok((status, _hdrs, resp_body)) => {
                if status != 200 {
                    let body_txt = String::from_utf8_lossy(&resp_body)
                        .chars()
                        .take(200)
                        .collect::<String>();
                    if should_blacklist(status, &body_txt) {
                        self.blacklist_script(&script_id, &format!("HTTP {}", status));
                    }
                    return Err(FronterError::Relay(format!(
                        "Apps Script HTTP {}: {}",
                        status, body_txt
                    )));
                }
                return parse_relay_json(&resp_body, self.allow_brotli_zstd).map_err(|e| {
                    if let FronterError::Relay(ref msg) = e {
                        if let Some(cat) = classify_envelope_error(msg) {
                            self.blacklist_script(
                                &script_id,
                                &format!("{}: {}", cat.as_str(), msg),
                            );
                        }
                    }
                    e
                });
            }
            Err((e, RequestSent::No)) => {
                tracing::debug!("h2 pre-send failure: {} — falling back to h1", e);
            }
            Err((e, RequestSent::Maybe)) => {
                if is_method_safe_for_fanout(method) {
                    tracing::debug!(
                        "h2 post-send failure for safe method {}: {} — falling back to h1",
                        method,
                        e
                    );
                } else {
                    tracing::warn!(
                        "h2 post-send failure for non-idempotent {} {}: {} — \
                         marking non-retryable to prevent duplicating side effects",
                        method,
                        url,
                        e
                    );
                    // NonRetryable wrapper bubbles all the way through
                    // do_relay_once_with → do_relay_with_retry, where
                    // the retry loop skips its second attempt. Without
                    // this wrap, returning a plain Err would let
                    // do_relay_with_retry re-issue the request via h1
                    // (or a fresh h2 cell), defeating the safety policy.
                    return Err(FronterError::NonRetryable(Box::new(e)));
                }
            }
        }

        let mut entry = self.acquire().await?;
        let reuse_ok = {
            let write_res = async {
                let req_head = format!(
                    "POST {path} HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {len}\r\n\
                     Accept-Encoding: gzip\r\n\
                     Accept-Language: {accept_lang}\r\n\
                     Connection: keep-alive\r\n\
                     \r\n",
                    path = path,
                    host = self.http_host,
                    len = payload.len(),
                    accept_lang = self.apps_script_accept_lang,
                );
                entry.stream.write_all(req_head.as_bytes()).await?;
                entry.stream.write_all(&payload).await?;
                entry.stream.flush().await?;

                let (status, resp_headers, resp_body) =
                    read_http_response(&mut entry.stream).await?;
                Ok::<_, FronterError>((status, resp_headers, resp_body))
            }
            .await;

            match write_res {
                Err(e) => {
                    // Connection may be dead — don't return to pool.
                    return Err(e);
                }
                Ok((mut status, mut resp_headers, mut resp_body)) => {
                    // Follow redirect chain (Apps Script usually redirects
                    // /exec to googleusercontent.com). Up to 5 hops, same
                    // connection.
                    for _ in 0..5 {
                        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                            break;
                        }
                        let Some(loc) = header_get(&resp_headers, "location") else {
                            break;
                        };
                        let (rpath, rhost) = parse_redirect(&loc);
                        let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
                        let req = format!(
                            "GET {rpath} HTTP/1.1\r\n\
                             Host: {rhost}\r\n\
                             Accept-Encoding: gzip\r\n\
                             Connection: keep-alive\r\n\
                             \r\n",
                        );
                        entry.stream.write_all(req.as_bytes()).await?;
                        entry.stream.flush().await?;
                        let (s, h, b) = read_http_response(&mut entry.stream).await?;
                        status = s;
                        resp_headers = h;
                        resp_body = b;
                    }

                    if status != 200 {
                        let body_txt = String::from_utf8_lossy(&resp_body)
                            .chars()
                            .take(200)
                            .collect::<String>();
                        if should_blacklist(status, &body_txt) {
                            self.blacklist_script(&script_id, &format!("HTTP {}", status));
                        }
                        return Err(FronterError::Relay(format!(
                            "Apps Script HTTP {}: {}",
                            status, body_txt
                        )));
                    }
                    match parse_relay_json(&resp_body, self.allow_brotli_zstd) {
                        Ok(bytes) => Ok::<_, FronterError>((bytes, true)),
                        Err(e) => {
                            if let FronterError::Relay(ref msg) = e {
                                if let Some(cat) = classify_envelope_error(msg) {
                                    self.blacklist_script(
                                        &script_id,
                                        &format!("{}: {}", cat.as_str(), msg),
                                    );
                                }
                            }
                            Err(e)
                        }
                    }
                }
            }
        };

        match reuse_ok {
            Ok((bytes, reuse)) => {
                if reuse {
                    self.release(entry).await;
                }
                Ok(bytes)
            }
            Err(e) => Err(e),
        }
    }

    /// Send a request through the configured exit node, chained inside
    /// an Apps Script call. Path:
    ///
    /// ```text
    /// client → SNI rewrite → Apps Script (Google IP)
    ///        → UrlFetchApp.fetch(exit_node_url)
    ///        → exit node (non-Google IP)
    ///        → fetch(real_url)
    ///        → response back through both layers
    /// ```
    ///
    /// Apps Script sees the outer call (URL = exit_node_url, method =
    /// POST, body = inner relay JSON authenticated with the exit-node
    /// PSK). The exit node sees the inner JSON, fetches the real
    /// destination, returns a `{s, h, b}` JSON envelope. Apps Script
    /// returns that envelope as the body of its raw HTTP response
    /// (because we set `r: true`). We then unwrap one extra layer:
    /// extract Apps Script's body → parse the exit-node JSON → reconstruct
    /// the destination's raw HTTP response so the rest of the proxy
    /// pipeline (MITM TLS write-back) sees the same shape it gets from
    /// the regular path.
    async fn relay_via_exit_node(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let inner_json = self.build_exit_node_inner_payload(method, url, headers, body)?;

        // The outer payload is just a normal Apps Script relay request
        // pointing at the exit-node URL with POST + the inner JSON as body.
        // Reusing build_payload_json keeps the outer envelope consistent
        // with everything else (including the random padding for DPI
        // evasion). We then splice in `raw: true` so Code.gs returns the
        // exit-node's response body verbatim instead of wrapping it in
        // another `{s, h, b}` envelope — without this, parse_exit_node_response
        // would see Apps Script's wrap around the exit-node's wrap and only
        // unwrap one layer, delivering raw JSON to the browser.
        //
        // **Deployment pairing:** the `raw` field is additive on the wire,
        // so a regular (non-exit-node) relay against an old Code.gs / Worker
        // deployment is unaffected — they just ignore the unknown field.
        // BUT the exit-node path specifically needs the matching server
        // change (raw-return branch in Code.gs / CodeFull.gs / worker.js).
        // A v2.0.2+ binary against a pre-v2.0.2 Apps Script or Worker will
        // still double-wrap exit-node responses and the browser will see
        // raw JSON instead of page content. The v2.0.2 release notes call
        // this out — users with `exit_node.enabled: true` must redeploy
        // Code.gs (or Code.cfw.gs + worker.js) when they upgrade.
        let exit_url = self.exit_node_url.clone();
        let outer_headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let mut outer_value: Value = serde_json::from_slice(&self.build_payload_json(
            "POST",
            &exit_url,
            &outer_headers,
            &inner_json,
        )?)?;
        if let Value::Object(map) = &mut outer_value {
            map.insert("raw".to_string(), Value::Bool(true));
        }
        let outer_payload: Bytes = Bytes::from(serde_json::to_vec(&outer_value)?);

        // Send the outer payload through the relay machinery and get back
        // Apps Script's response body (which is exit-node's JSON envelope).
        let app_body = self
            .send_prebuilt_payload_through_relay(outer_payload)
            .await?;

        // exit-node's JSON envelope: {s: u16, h: {...}, b: "<base64>"} on
        // success, {e: "..."} on its own internal error.
        parse_exit_node_response(&app_body, self.allow_brotli_zstd)
    }

    /// Build the inner-layer payload that the exit node will execute.
    /// Same wire shape as a normal `RelayRequest` (`{k, m, u, h, b, ct, r}`)
    /// but `k` is the exit-node PSK rather than the user's Apps Script
    /// `auth_key`, and we skip the random-padding field — padding only
    /// helps DPI evasion on the Iran-side leg, which the inner payload
    /// is invisible to (it's encrypted inside the Apps Script HTTPS
    /// connection that the ISP can't inspect).
    fn build_exit_node_inner_payload(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let filtered = filter_forwarded_headers_with_brotli_zstd(headers, self.allow_brotli_zstd);
        let hmap = if filtered.is_empty() {
            None
        } else {
            let mut m = serde_json::Map::with_capacity(filtered.len());
            for (k, v) in &filtered {
                m.insert(k.clone(), Value::String(v.clone()));
            }
            Some(m)
        };
        let b_encoded = if body.is_empty() {
            None
        } else {
            Some(B64.encode(body))
        };
        let ct = if body.is_empty() {
            None
        } else {
            find_header(headers, "content-type")
        };
        let req = RelayRequest {
            k: &self.exit_node_psk,
            m: method,
            u: url,
            h: hmap,
            b: b_encoded,
            ct,
            r: false,  // the exit node returns its own JSON envelope, not raw HTTP
            raw: None, // exit-node TS handler ignores `raw`; field is for Code.gs
        };
        Ok(serde_json::to_vec(&req)?)
    }

    /// Drive the standard script-id rotation + TLS pool send path with
    /// a payload we already built. Mirrors `do_relay_once_with` but
    /// returns the **raw response body bytes** (Apps Script's HTTP body)
    /// instead of running the body through `parse_relay_json` — the
    /// exit-node path needs to peel off exit-node's JSON envelope, which
    /// has a different shape from Code.gs's raw-HTTP wrapping.
    async fn send_prebuilt_payload_through_relay(
        &self,
        payload: Bytes,
    ) -> Result<Vec<u8>, FronterError> {
        let script_id = self.next_script_id();
        let path = self.exec_path_for(&script_id);

        // h2 fast path. The exit-node outer call is always POST and
        // carries the inner relay payload — replaying on h1 after the
        // outer reached Apps Script duplicates the inner request to
        // the exit node. Only fall back when h2 definitely never sent.
        // Same default response deadline as the direct path; the
        // exit-node leg ultimately exits via Apps Script too.
        match self
            .h2_relay_request(
                &path,
                payload.clone(),
                Duration::from_secs(H2_RESPONSE_DEADLINE_DEFAULT_SECS),
            )
            .await
        {
            Ok((status, _hdrs, _resp_body)) if is_h2_fronting_refusal_status(status) => {
                // Same fronting-refusal path as the direct relay.
                // Safe to fall back: 421 means the edge rejected
                // before invoking the exit node.
                self.sticky_disable_h2_for_fronting_refusal(status, "exit-node outer call")
                    .await;
                // fall through to h1
            }
            Ok((status, _hdrs, resp_body)) => {
                if status != 200 {
                    let body_txt = String::from_utf8_lossy(&resp_body)
                        .chars()
                        .take(200)
                        .collect::<String>();
                    return Err(FronterError::Relay(format!(
                        "Apps Script HTTP {} (exit-node outer call): {}",
                        status, body_txt
                    )));
                }
                return Ok(resp_body);
            }
            Err((e, RequestSent::No)) => {
                tracing::debug!(
                    "h2 exit-node outer call pre-send failure: {} — falling back to h1",
                    e
                );
            }
            Err((e, RequestSent::Maybe)) => {
                tracing::warn!(
                    "h2 exit-node outer call post-send failure: {} — \
                     marking non-retryable to prevent duplicating the inner request",
                    e
                );
                // NonRetryable propagates back to relay()'s exit-node
                // match arm, which will *not* fall through to the
                // direct Apps Script path (that fall-through would
                // re-send the outer call and could also re-trigger
                // the inner request to the destination).
                return Err(FronterError::NonRetryable(Box::new(e)));
            }
        }

        let mut entry = self.acquire().await?;
        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Accept-Language: {accept_lang}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
            accept_lang = self.apps_script_accept_lang,
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response(&mut entry.stream).await?;

        // Follow Apps Script's /exec → /macros/.../exec redirect chain
        // (typical: 1-2 hops to script.googleusercontent.com). Mirrors
        // the redirect handling in do_relay_once_with.
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&resp_headers, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\n\
                 Host: {rhost}\r\n\
                 Accept-Encoding: gzip\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) = read_http_response(&mut entry.stream).await?;
            status = s;
            resp_headers = h;
            resp_body = b;
        }

        // Don't return to pool — the exit-node path is rare enough that
        // the connection-reuse semantics aren't worth replicating here.
        drop(entry);

        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body)
                .chars()
                .take(200)
                .collect::<String>();
            return Err(FronterError::Relay(format!(
                "Apps Script HTTP {} (exit-node outer call): {}",
                status, body_txt
            )));
        }
        Ok(resp_body)
    }

    fn build_payload_json(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let filtered = filter_forwarded_headers_with_brotli_zstd(headers, self.allow_brotli_zstd);
        let hmap = if filtered.is_empty() {
            None
        } else {
            let mut m = serde_json::Map::with_capacity(filtered.len());
            for (k, v) in &filtered {
                m.insert(k.clone(), Value::String(v.clone()));
            }
            Some(m)
        };
        let b_encoded = if body.is_empty() {
            None
        } else {
            Some(B64.encode(body))
        };
        let ct = if body.is_empty() {
            None
        } else {
            find_header(headers, "content-type")
        };
        let req = RelayRequest {
            k: &self.auth_key,
            m: method,
            u: url,
            h: hmap,
            b: b_encoded,
            ct,
            r: true,
            raw: None,
        };
        // Serialize via Value so we can splice in the random `_pad` field
        // without changing RelayRequest's wire schema. Apps Script ignores
        // unknown JSON fields, so old Code.gs deployments stay compatible
        // — the pad is just bytes-on-the-wire that the server sees and
        // discards.
        let mut v = serde_json::to_value(&req)?;
        if let Value::Object(map) = &mut v {
            if !self.disable_padding {
                add_random_pad(map);
            }
        }
        Ok(serde_json::to_vec(&v)?)
    }

    // ────── Full-mode tunnel protocol ──────────────────────────────────

    /// Send a tunnel-protocol request through the domain-fronted connection
    /// to Apps Script. Reuses the same TLS pool as `relay()` but builds a
    /// tunnel JSON payload (the `t` field triggers `_doTunnel` in CodeFull.gs).
    pub async fn tunnel_request(
        &self,
        op: &str,
        host: Option<&str>,
        port: Option<u16>,
        sid: Option<&str>,
        data: Option<String>,
    ) -> Result<TunnelResponse, FronterError> {
        let payload: Bytes = Bytes::from(self.build_tunnel_payload(op, host, port, sid, data)?);
        let script_id = self.next_script_id();
        let path = self.exec_path_for(&script_id);

        // Skip h2 for tunnel ops — same rationale as tunnel_batch_request_to
        // (PR #1040): tunnel ops are already single HTTP requests, h2
        // multiplexing adds no benefit and causes 16-17s long-poll stalls.
        let mut entry = self.acquire().await?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Accept-Language: {accept_lang}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
            accept_lang = self.apps_script_accept_lang,
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response(&mut entry.stream).await?;

        // Follow redirect chain (Apps Script usually redirects /exec to
        // googleusercontent.com). Same logic as do_relay_once_with.
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&resp_headers, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\n\
                 Host: {rhost}\r\n\
                 Accept-Encoding: gzip\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) = read_http_response(&mut entry.stream).await?;
            status = s;
            resp_headers = h;
            resp_body = b;
        }

        let resp = self.finalize_tunnel_response(&script_id, status, resp_body)?;
        self.release(entry).await;
        Ok(resp)
    }

    /// Validate a tunnel-protocol response (status check + Apps-Script
    /// HTML-prefix tolerance + JSON parse). Used by both the h2 and h1
    /// branches of `tunnel_request` so the parsing logic doesn't drift
    /// across transports.
    fn finalize_tunnel_response(
        &self,
        script_id: &str,
        status: u16,
        resp_body: Vec<u8>,
    ) -> Result<TunnelResponse, FronterError> {
        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body)
                .chars()
                .take(200)
                .collect::<String>();
            if should_blacklist(status, &body_txt) {
                self.blacklist_script(script_id, &format!("HTTP {}", status));
            }
            return Err(FronterError::Relay(format!(
                "tunnel HTTP {}: {}",
                status, body_txt
            )));
        }
        let text = std::str::from_utf8(&resp_body)
            .map_err(|_| FronterError::BadResponse("non-utf8 tunnel response".into()))?
            .trim();
        // Apps Script may prepend HTML on cold-start or quota-exceeded
        // pages; extract the first {...} block tolerantly so we don't
        // bail on a recoverable warning frame.
        let json_str = if text.starts_with('{') {
            text
        } else {
            let start = text.find('{').ok_or_else(|| {
                FronterError::BadResponse(format!(
                    "no json in tunnel response: {}",
                    &text[..text.len().min(200)]
                ))
            })?;
            let end = text.rfind('}').ok_or_else(|| {
                FronterError::BadResponse("no json end in tunnel response".into())
            })?;
            if start > end {
                return Err(FronterError::BadResponse(format!(
                    "no valid json object in: {}",
                    &text.chars().take(200).collect::<String>()
                )));
            }
            &text[start..=end]
        };
        Ok(serde_json::from_str(json_str)?)
    }

    fn build_tunnel_payload(
        &self,
        op: &str,
        host: Option<&str>,
        port: Option<u16>,
        sid: Option<&str>,
        data: Option<String>,
    ) -> Result<Vec<u8>, FronterError> {
        let mut map = serde_json::Map::new();
        map.insert("k".into(), Value::String(self.auth_key.clone()));
        map.insert("t".into(), Value::String(op.to_string()));
        if let Some(h) = host {
            map.insert("h".into(), Value::String(h.to_string()));
        }
        if let Some(p) = port {
            map.insert("p".into(), Value::Number(serde_json::Number::from(p)));
        }
        if let Some(s) = sid {
            map.insert("sid".into(), Value::String(s.to_string()));
        }
        if let Some(d) = data {
            map.insert("d".into(), Value::String(d));
        }
        if !self.disable_padding {
            add_random_pad(&mut map);
        }
        Ok(serde_json::to_vec(&Value::Object(map))?)
    }

    /// Send a batch of tunnel operations in one Apps Script round trip.
    /// All active sessions' data is collected and sent together, and all
    /// responses come back in one response. This reduces N Apps Script
    /// calls to 1 per tick.
    pub async fn tunnel_batch_request(
        &self,
        ops: &[BatchOp],
    ) -> Result<BatchTunnelResponse, FronterError> {
        let script_id = self.next_script_id();
        self.tunnel_batch_request_to(&script_id, ops).await
    }

    /// Like `tunnel_batch_request` but targets a specific deployment ID.
    /// Used by the pipeline mux to pin a batch to a deployment whose
    /// per-account concurrency slot has already been acquired.
    pub async fn tunnel_batch_request_to(
        &self,
        script_id: &str,
        ops: &[BatchOp],
    ) -> Result<BatchTunnelResponse, FronterError> {
        // Time the whole batch round-trip — including request build,
        // socket acquire, redirect chain, and response parse. Recorded
        // on the success return below so the EWMA reflects what the
        // deployment actually delivered (failed batches' elapsed time
        // would be dominated by the timeout, not throughput).
        let t0 = std::time::Instant::now();
        let mut map = serde_json::Map::new();
        map.insert("k".into(), Value::String(self.auth_key.clone()));
        map.insert("t".into(), Value::String("batch".into()));
        if self.zstd_enabled.load(Ordering::Relaxed) {
            let ops_json = serde_json::to_vec(ops)?;
            match zstd::encode_all(ops_json.as_slice(), 3) {
                Ok(compressed) => {
                    map.insert("zops".into(), Value::String(B64.encode(&compressed)));
                }
                Err(_) => {
                    map.insert("ops".into(), serde_json::to_value(ops)?);
                }
            }
        } else {
            map.insert("ops".into(), serde_json::to_value(ops)?);
        }
        map.insert("zc".into(), Value::Number(1.into()));
        if !self.disable_padding {
            add_random_pad(&mut map);
        }
        let payload: Bytes = Bytes::from(serde_json::to_vec(&Value::Object(map))?);

        let path = self.exec_path_for(script_id);

        // Skip h2 for tunnel batches. Batched ops are already coalesced
        // into one HTTP request so h2 multiplexing adds no benefit.
        // The h1 pool path is simpler and avoids h2-specific overhead
        // (ready timeout, NonRetryable errors, concurrent stream
        // contention with long-poll batches).
        let mut entry = self.acquire().await?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Accept-Language: {accept_lang}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
            accept_lang = self.apps_script_accept_lang,
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        // Use the configured `request_timeout_secs` for the header read,
        // not the hardcoded 10 s default. With Apps Script cold starts
        // routinely landing in the 8–12 s range, the 10 s cliff was
        // firing as a false-positive batch timeout (issue #1088), killing
        // every in-flight tunnel session under it. The outer
        // `tokio::time::timeout(batch_timeout, ...)` in `fire_batch`
        // remains the authoritative bound on total batch round-trip time.
        let batch_timeout = self.batch_timeout();
        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response_with_header_timeout(&mut entry.stream, batch_timeout).await?;

        // Follow redirect chain
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&resp_headers, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\nHost: {rhost}\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) =
                read_http_response_with_header_timeout(&mut entry.stream, batch_timeout).await?;
            status = s;
            resp_headers = h;
            resp_body = b;
        }

        // Route through the same `finalize_batch_response` helper the
        // h2 path uses. This keeps the redacted-logging policy in
        // exactly one place — the previous inline parse here logged
        // raw payload at debug AND error level, which leaked the
        // base64-encoded tunneled bytes (TCP/UDP packets, possibly
        // app data or credentials) into bug-report logs. Both
        // transports now emit only `status=` + `body_len=`, with the
        // raw body gated behind RUST_LOG=trace.
        let resp = self.finalize_batch_response(script_id, status, resp_body)?;
        self.release(entry).await;
        self.record_batch_latency(script_id, t0.elapsed());
        Ok(resp)
    }

    /// Parse a batch-tunnel response body once we already have it in
    /// hand — used by the h2 fast path in `tunnel_batch_request_to`,
    /// where the response is read off a multiplexed stream rather than
    /// drained from a checked-out socket. Mirrors the validate-and-parse
    /// tail of the h1 path (status check + JSON extraction +
    /// quota-blacklist book-keeping).
    fn finalize_batch_response(
        &self,
        script_id: &str,
        status: u16,
        resp_body: Vec<u8>,
    ) -> Result<BatchTunnelResponse, FronterError> {
        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body)
                .chars()
                .take(200)
                .collect::<String>();
            if should_blacklist(status, &body_txt) {
                self.blacklist_script(script_id, &format!("HTTP {}", status));
            }
            return Err(FronterError::Relay(format!(
                "batch tunnel HTTP {}: {}",
                status, body_txt
            )));
        }
        let text = std::str::from_utf8(&resp_body)
            .map_err(|_| FronterError::BadResponse("non-utf8 batch response".into()))?
            .trim();
        let json_str = if text.starts_with('{') {
            text
        } else {
            let start = text.find('{').ok_or_else(|| {
                FronterError::BadResponse(format!(
                    "no json in batch response: {}",
                    &text[..text.len().min(200)]
                ))
            })?;
            let end = text
                .rfind('}')
                .ok_or_else(|| FronterError::BadResponse("no json end in batch response".into()))?;
            if start > end {
                return Err(FronterError::BadResponse(format!(
                    "no valid json object in: {}",
                    &text.chars().take(200).collect::<String>()
                )));
            }
            &text[start..=end]
        };
        // Don't log payload content. Batch responses carry base64-encoded
        // tunneled bytes (TCP/UDP packets, possibly app data, possibly
        // credentials), and even at debug level a leaked log line ends
        // up in user-shared bug reports. Status + length are sufficient
        // for diagnosis; full body is available behind RUST_LOG=trace.
        tracing::debug!(
            "batch response: status={} body_len={}",
            status,
            json_str.len()
        );
        tracing::trace!(
            "batch response body (trace only): {}",
            &json_str[..json_str.len().min(500)]
        );
        match serde_json::from_str::<BatchTunnelResponse>(json_str) {
            Ok(mut resp) => {
                if let Some(zr_b64) = resp.zr.take() {
                    match B64.decode(&zr_b64) {
                        Ok(compressed) => match zstd::decode_all(compressed.as_slice()) {
                            Ok(decompressed) => match serde_json::from_slice(&decompressed) {
                                Ok(r) => {
                                    resp.r = r;
                                }
                                Err(e) => tracing::error!("zr json parse failed: {}", e),
                            },
                            Err(e) => tracing::error!("zr zstd decompress failed: {}", e),
                        },
                        Err(e) => tracing::error!("zr base64 decode failed: {}", e),
                    }
                }
                if resp.zc.is_some() && !self.zstd_enabled.load(Ordering::Relaxed) {
                    tracing::info!("tunnel-node supports zstd, enabling compressed batches");
                    self.zstd_enabled.store(true, Ordering::Relaxed);
                }
                Ok(resp)
            }
            Err(e) => {
                // Same redaction policy on the error path. Length and
                // the serde error message are enough to locate the
                // parse failure (offset / unexpected-token info comes
                // from `e` itself); the raw body is trace-only.
                tracing::error!(
                    "batch JSON parse error: {} (body_len={})",
                    e,
                    json_str.len()
                );
                tracing::trace!(
                    "batch parse-error body (trace only): {}",
                    &json_str[..json_str.len().min(300)]
                );
                Err(FronterError::Json(e))
            }
        }
    }
}

// ─── HTTP response helpers used by relay_parallel_range ──────────────────

type SplitResponse<'a> = (u16, Vec<(String, String)>, &'a [u8]);

/// Split an HTTP/1.x response blob into `(status, headers, body)`.
/// Returns `None` if the buffer doesn't even have a status line + CRLFCRLF
/// separator — the caller should then pass the bytes through unchanged.
fn split_response(raw: &[u8]) -> Option<SplitResponse<'_>> {
    // Locate end-of-headers.
    let sep = b"\r\n\r\n";
    let sep_pos = raw.windows(sep.len()).position(|w| w == sep)?;
    let head = &raw[..sep_pos];
    let body = &raw[sep_pos + sep.len()..];

    let mut lines = head.split(|&b| b == b'\n');
    let status_line = lines.next()?;
    // Status line: "HTTP/1.1 206 Partial Content"
    let status_line = std::str::from_utf8(status_line)
        .ok()?
        .trim_end_matches('\r');
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next()?;
    let code = parts.next()?.parse::<u16>().ok()?;

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Some((code, headers, body))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentRange {
    start: u64,
    end: u64,
    total: u64,
}

/// Parse `Content-Range: bytes START-END/TOTAL`.
fn parse_content_range(headers: &[(String, String)]) -> Option<ContentRange> {
    let cr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-range"))?;
    let value = cr.1.trim();
    let (unit, rest) = value.split_once(' ')?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (range, total) = rest.trim_start().split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = end.trim().parse::<u64>().ok()?;
    let total = total.trim().parse::<u64>().ok()?;
    if start > end || total == 0 || end >= total {
        return None;
    }
    Some(ContentRange { start, end, total })
}

/// Pull the total size out of a valid `Content-Range: bytes START-END/TOTAL` header.
fn parse_content_range_total(headers: &[(String, String)]) -> Option<u64> {
    parse_content_range(headers).map(|r| r.total)
}

fn content_range_matches_body(range: ContentRange, body_len: usize) -> bool {
    body_len > 0 && (range.end - range.start + 1) == body_len as u64
}

fn validate_probe_range(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    requested_end: u64,
) -> Option<ContentRange> {
    if status != 206 {
        return None;
    }
    let range = parse_content_range(headers)?;
    if range.start != 0 || range.end > requested_end {
        return None;
    }
    if content_range_matches_body(range, body.len())
        || probe_range_covers_complete_entity(range, requested_end)
    {
        return Some(range);
    }
    None
}

fn probe_range_covers_complete_entity(range: ContentRange, requested_end: u64) -> bool {
    // Apps Script may decode a gzip body while preserving the origin's
    // compressed Content-Range. For the synthetic first probe only, a
    // 0..total-1 range within the requested chunk is enough to prove we
    // already have the complete entity; later chunks still require exact
    // Content-Range/body length validation in extract_exact_range_body().
    range.start == 0
        && range.end.saturating_add(1) >= range.total
        && range.total <= requested_end.saturating_add(1)
}

fn extract_exact_range_body(
    raw: &[u8],
    start: u64,
    end: u64,
    total: u64,
) -> Result<Vec<u8>, &'static str> {
    let (status, headers, body) = split_response(raw).ok_or("malformed HTTP response")?;
    if status != 206 {
        return Err("expected 206 Partial Content");
    }
    let range = parse_content_range(&headers).ok_or("missing or invalid Content-Range")?;
    if range.start != start || range.end != end || range.total != total {
        return Err("unexpected Content-Range");
    }
    if !content_range_matches_body(range, body.len()) {
        return Err("Content-Range/body length mismatch");
    }
    Ok(body.to_vec())
}

/// Decide whether a failed chunk fetch is worth retrying. Used by
/// `fetch_chunks_stream` to recover from transient Apps Script /
/// origin errors mid-stream without giving up on the whole download.
///
/// Retryable:
///   * Unparseable response (`split_response` returned None) — relay
///     layer hit a connection-level failure before getting a status
///     line; another attempt may succeed.
///   * 5xx status — relay-level 504 (Apps Script timeout, by far the
///     common case at scale), 502 (Apps Script connection/quota
///     error), or genuine origin 5xx; all plausibly transient.
///
/// Not retryable:
///   * 2xx with wrong shape (e.g. origin started serving a 200 with
///     full body instead of 206 — happens for tiny files where the
///     origin ignored Range). The same request will return the same
///     thing; retrying just burns quota.
///   * 3xx / 4xx — origin's authoritative answer (range unsatisfiable,
///     auth lapsed, etc.). Retrying won't change it.
fn chunk_failure_is_retryable(raw: &[u8]) -> bool {
    match split_response(raw) {
        None => true,
        Some((status, _, _)) => (500..600).contains(&status),
    }
}

/// Rewrite a 206 response to a 200 OK, dropping Content-Range and
/// recomputing Content-Length. Used when we probed with a synthetic
/// Range header but the client sent a plain GET — handing a 206 back to
/// XHR/fetch code on some sites (x.com, Cloudflare Turnstile) makes them
/// treat the response as aborted. Same rationale as the upstream Python
/// `_rewrite_206_to_200`.
fn rewrite_206_to_200(raw: &[u8]) -> Vec<u8> {
    let (_status, headers, body) = match split_response(raw) {
        Some(v) => v,
        None => return raw.to_vec(),
    };
    assemble_full_200(&headers, body)
}

/// Build a complete `HTTP/1.1 200 OK` response with the given header
/// set + body. Skips headers the caller shouldn't be forwarding
/// verbatim (content-length/range/encoding, transfer-encoding, hop-by-hop
/// wire-level stuff) — we set Content-Length from the body we're
/// actually shipping.
fn assemble_full_200(src_headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut out = assemble_200_head(src_headers, body.len() as u64);
    out.extend_from_slice(body);
    out
}

/// Build only the `HTTP/1.1 200 OK` head block — status line, headers,
/// and the `\r\n\r\n` terminator — with `Content-Length:
/// declared_length`. Used by the streaming side of the range-parallel
/// path, where the body hasn't been assembled yet but we know its
/// total size from the probe's `Content-Range`. Matches
/// `assemble_full_200`'s header-skip rules so the two paths produce
/// identical headers for a given probe.
fn assemble_200_head(src_headers: &[(String, String)], declared_length: u64) -> Vec<u8> {
    let skip = |k: &str| {
        matches!(
            k.to_ascii_lowercase().as_str(),
            "content-length"
                | "content-range"
                | "content-encoding"
                | "transfer-encoding"
                | "connection"
                | "keep-alive",
        )
    };
    let mut out: Vec<u8> = b"HTTP/1.1 200 OK\r\n".to_vec();
    for (k, v) in src_headers {
        if skip(k) {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", declared_length).as_bytes());
    out
}

/// Apply `transform_head` to the head block of an HTTP/1.x response
/// (everything up to and including the first `\r\n\r\n` terminator),
/// then write the transformed head followed by the unchanged body to
/// `writer`. If the response can't be parsed as HTTP/1.x (no header
/// terminator), passes the bytes through unchanged. This is the
/// buffered-path bridge to the writer-based API: callers see the
/// same head-rewrite policy regardless of whether we took the
/// streaming or buffered branch.
async fn write_response_with_head_transform<W, F>(
    writer: &mut W,
    response: &[u8],
    transform_head: &F,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn(&[u8]) -> Vec<u8>,
{
    use tokio::io::AsyncWriteExt;

    let sep = b"\r\n\r\n";
    let Some(idx) = response.windows(sep.len()).position(|w| w == sep) else {
        writer.write_all(response).await?;
        return Ok(());
    };
    let head_with_terminator = &response[..idx + sep.len()];
    let body = &response[idx + sep.len()..];
    let new_head = transform_head(head_with_terminator);
    writer.write_all(&new_head).await?;
    writer.write_all(body).await?;
    Ok(())
}

/// Three-way dispatch for the range-parallel response delivery in
/// `do_relay_parallel_range_to`. Extracted as a pure function so the
/// branching contract is unit-testable without a live `DomainFronter`,
/// and split into an enum so the writer-based and `Vec<u8>` APIs can
/// pick different cutoffs (which is exactly the regression that
/// motivated PR #1043's third-round review).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeDispatch {
    /// Stitch all chunks into a single in-memory buffer, then deliver
    /// the response to the writer in one shot. Chunk failure falls
    /// back to a single GET — which actually recovers when the file
    /// fits through Apps Script's response cap.
    Buffered,
    /// Write the response head + probe body to the wire, then stream
    /// each remaining chunk in order. Chunk failure truncates the
    /// response and surfaces as a Content-Length mismatch the
    /// download client resumes via Range. Only reachable from the
    /// writer-based API (`streaming_allowed=true`).
    Stream,
    /// Fall back to a plain `self.relay()` single GET. Used by the
    /// `Vec<u8>` compatibility wrapper when the response would
    /// exceed the buffered stitch buffer's memory cap and the wrapper
    /// can't take the streaming branch (a `Vec<u8>` consumer can't
    /// react to a truncated 200 OK — Issue #162).
    FallbackSingleGet,
    /// Refuse the response outright with a 502. Only reachable from
    /// the writer-based API for advertised totals above
    /// [`MAX_STREAMED_RANGE_BYTES`]. Prevents an absurd
    /// `Content-Range` total from turning one GET into an unbounded
    /// stream of chunk Apps Script calls (quota drain DoS — see the
    /// constant's doc). The compat wrapper has the lower
    /// [`BUFFERED_STITCH_MAX_BYTES`] cliff above it, so this variant
    /// is not reachable via `streaming_allowed=false`.
    RejectTooLarge,
}

/// Decide how to deliver a range-capable response of size `total`.
///
/// Two callers, two contracts:
///   * Writer-based public API ([`DomainFronter::relay_parallel_range_to`])
///     passes `streaming_allowed=true`. It streams above
///     [`APPS_SCRIPT_BODY_MAX_BYTES`] (40 MiB) — that's where
///     single-GET fallback would fail through Apps Script anyway,
///     so streaming with truncate-and-resume beats a hard 504.
///   * `Vec<u8>` compatibility wrapper
///     ([`DomainFronter::relay_parallel_range`]) passes
///     `streaming_allowed=false`. It buffers up to
///     [`BUFFERED_STITCH_MAX_BYTES`] (64 MiB) and only falls back to
///     single GET above that. The 40-64 MiB band still stitches
///     successfully (the pre-1.9.23 behavior); above 64 MiB the
///     wrapper returns whatever Apps Script's single-GET returns
///     (typically 502/504), matching the pre-1.9.23 cliff exactly.
fn dispatch_range_response(total: u64, streaming_allowed: bool) -> RangeDispatch {
    if streaming_allowed && total > MAX_STREAMED_RANGE_BYTES {
        // Quota-DoS guard for the writer API. The wrapper never
        // hits this branch because its `streaming_allowed=false`
        // path is gated by the lower `BUFFERED_STITCH_MAX_BYTES`
        // (64 MiB) cliff above — Apps Script's single-GET refuses
        // the response there, no chunk loop runs.
        RangeDispatch::RejectTooLarge
    } else if streaming_allowed && total > APPS_SCRIPT_BODY_MAX_BYTES {
        RangeDispatch::Stream
    } else if !streaming_allowed && total > BUFFERED_STITCH_MAX_BYTES {
        RangeDispatch::FallbackSingleGet
    } else {
        RangeDispatch::Buffered
    }
}

/// Lazy iterator over the byte ranges that need to be fetched after
/// the probe. Yields `(start, end)` pairs of inclusive byte indices,
/// each ≤ `chunk_size` long, covering `(probe_end, total - 1]`.
///
/// Crucially this is `O(1)` memory regardless of `total`. A hostile or
/// buggy origin advertising `Content-Range: bytes 0-262143/<huge>`
/// can pass the probe checks (matching 256 KiB body, valid total) but
/// must not be allowed to drive an eager `Vec<(u64, u64)>` allocation
/// — at 256 KiB chunks a claimed 100 TiB total is ~400M tuples
/// (~6 GB resident). PR #151's original guard was a fixed
/// `MAX_STITCHED_RANGE_BYTES` cap; the writer-based path replaces it
/// with this lazy iterator so streaming downloads have no hard size
/// ceiling but also no eager allocation.
fn plan_remaining_ranges(
    probe_end: u64,
    total: u64,
    chunk_size: u64,
) -> impl Iterator<Item = (u64, u64)> {
    let mut start = probe_end.saturating_add(1);
    std::iter::from_fn(move || {
        if start >= total {
            return None;
        }
        let s = start;
        let e = (s.saturating_add(chunk_size).saturating_sub(1)).min(total - 1);
        start = e.saturating_add(1);
        Some((s, e))
    })
}

/// Streaming write loop for the range-parallel path. Writes `head`,
/// then `probe_body`, then each chunk from `fetches` in input order
/// (which is by-range-start since `fetch_chunks_stream` uses
/// `buffered` to preserve order). On the first validation failure
/// flushes the committed prefix and returns `Err`; the partial
/// response surfaces to the download client as a truncated body
/// (Content-Length mismatch), which most clients — curl `-C -`,
/// browsers' built-in download manager, wget — treat as a resumable
/// failure and reissue via Range from the partial byte count.
///
/// The pre-Err flush is load-bearing on TLS streams (and to a
/// lesser extent on plain sockets with the kernel send buffer):
/// `write_all` returns once the bytes are in the TLS writer's
/// in-memory buffer, NOT once they've been encrypted and shipped
/// down the socket. If we returned `Err` without flushing, the
/// caller's `?` typically propagates the error and the connection
/// is dropped — taking buffered ciphertext with it. The client then
/// sees a clean connection close before any body bytes, instead of
/// the partial body it needs to compute a resume offset.
///
/// Kept as a free function (no `&self`) so the streaming logic can be
/// unit-tested with synthetic `Stream`s built from `stream::iter(…)`
/// instead of needing a fully-constructed `DomainFronter`.
async fn stream_chunks_to_writer<W, S>(
    writer: &mut W,
    head: &[u8],
    probe_body: &[u8],
    total: u64,
    fetches: S,
    url_for_log: &str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    S: futures_util::Stream<Item = (u64, u64, Result<Vec<u8>, &'static str>)>,
{
    use futures_util::stream::StreamExt;
    use tokio::io::AsyncWriteExt;

    writer.write_all(head).await?;
    writer.write_all(probe_body).await?;
    // Flush head + probe body to the wire before kicking off remote
    // chunk fetches. First bytes hit the client immediately so the
    // browser / download manager sees the response start (status
    // code + Content-Length, plus the first 256 KiB of body) while
    // the Apps Script round-trips for the remaining chunks are in
    // flight. Without this, intermediate buffering (TLS writer
    // buffer, kernel send buffer with small initial cwnd, browsers'
    // own pre-read thresholds) can make the progress bar sit at
    // zero for the first several hundred ms of the download.
    //
    // Propagate flush errors here — if the client already
    // disconnected, no point firing N more Apps Script calls.
    writer.flush().await?;
    futures_util::pin_mut!(fetches);

    // Progress accounting: bytes emitted as wire body so far (the
    // probe body, plus every successfully-written chunk). The head
    // doesn't count — it's protocol framing, not body progress.
    // `next_progress_log_at` is the next body-byte threshold at
    // which we emit a progress line, advanced past the current
    // count each time so a single large chunk crossing multiple
    // intervals only logs once.
    let mut body_bytes_emitted: u64 = probe_body.len() as u64;
    let mut next_progress_log_at: u64 = STREAM_PROGRESS_LOG_INTERVAL_BYTES;

    while let Some((s, e, chunk_result)) = fetches.next().await {
        match chunk_result {
            Ok(c) => {
                writer.write_all(&c).await?;
                body_bytes_emitted = body_bytes_emitted.saturating_add(c.len() as u64);
                if body_bytes_emitted >= next_progress_log_at {
                    // Percentage is well-defined here: streaming
                    // branch is only reached for total >
                    // APPS_SCRIPT_BODY_MAX_BYTES (≥ 40 MiB), so the
                    // divisor is never zero.
                    let pct = (body_bytes_emitted * 100) / total;
                    tracing::info!(
                        "range-parallel-stream: {}/{} MiB ({}%) emitted for {}",
                        body_bytes_emitted / (1024 * 1024),
                        total / (1024 * 1024),
                        pct,
                        url_for_log,
                    );
                    // Advance to the next interval past the current
                    // count — a chunk much larger than the interval
                    // (shouldn't happen at 256 KiB chunks, but defend
                    // against future tuning) skips intermediate
                    // thresholds rather than firing N log lines back
                    // to back.
                    next_progress_log_at =
                        body_bytes_emitted.saturating_add(STREAM_PROGRESS_LOG_INTERVAL_BYTES);
                }
            }
            Err(reason) => {
                tracing::warn!(
                    "range-parallel-stream: invalid chunk {}-{} for {} ({}); truncating response",
                    s,
                    e,
                    url_for_log,
                    reason,
                );
                // Flush the committed prefix to the wire before
                // declaring failure — see function doc. We
                // deliberately ignore a flush failure here: if the
                // socket is already broken the original
                // chunk-validation error is still the more useful
                // diagnosis for the caller.
                let _ = writer.flush().await;
                return Err(std::io::Error::other(format!(
                    "range-parallel-stream chunk failure: {}",
                    reason
                )));
            }
        }
    }
    Ok(())
}

/// Glue between probe response + chunk stream + writer. Composes
/// `assemble_200_head` (builds a synthetic 200 with
/// `Content-Length: total`), the caller's head-transform closure
/// (e.g. CORS injection), and `stream_chunks_to_writer` (writes the
/// transformed head, the probe body, then each chunk in order).
///
/// Extracted as a free function so the streaming-branch wiring in
/// `do_relay_parallel_range_to` is unit-testable without a live
/// `DomainFronter`. A test can feed a synthetic probe-header set, a
/// probe body, and a `stream::iter(…)` of canned chunk results, then
/// inspect the bytes written to a `Vec<u8>` to assert the right
/// composition (head → probe → chunks in order, transform_head
/// applied to the head only, mid-stream Err propagation with the
/// committed prefix intact).
async fn stream_range_response_to<W, S, F>(
    writer: &mut W,
    probe_resp_headers: &[(String, String)],
    probe_body: &[u8],
    total: u64,
    chunks_stream: S,
    transform_head: &F,
    url_for_log: &str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    S: futures_util::Stream<Item = (u64, u64, Result<Vec<u8>, &'static str>)>,
    F: Fn(&[u8]) -> Vec<u8>,
{
    let head = assemble_200_head(probe_resp_headers, total);
    let head = transform_head(&head);
    stream_chunks_to_writer(writer, &head, probe_body, total, chunks_stream, url_for_log).await
}

/// Tiny adapter that lets `relay_parallel_range_to` write into a
/// `Vec<u8>` so the backward-compat `relay_parallel_range` wrapper
/// can stay on the writer-based code path. `Vec<u8>` itself doesn't
/// implement `tokio::io::AsyncWrite`; this just extends in-place,
/// never fails, and never needs to block — `poll_*` immediately
/// returns `Ready`.
struct VecAsyncWriter<'a>(&'a mut Vec<u8>);

impl tokio::io::AsyncWrite for VecAsyncWriter<'_> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.get_mut().0.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Trim X/Twitter GraphQL URLs down to just the `variables=` query param,
/// stripping everything from the first `&` in the query onward. See the
/// `normalize_x_graphql` config field for the why.
///
/// Exact pattern mirrored from the Python community patch (issue #16):
///
///   host == "x.com"
///   && path starts with "/i/api/graphql/"
///   && query starts with "variables="
///   → truncate at first `&` past the `?`.
///
/// Returns the possibly-rewritten URL. If the URL doesn't match the
/// pattern the input is returned unchanged (as an owned String — the
/// allocation is cheap on the slow path and keeps the caller's
/// type-signature-juggling simple).
fn normalize_x_graphql_url(url: &str) -> String {
    // Split host from the rest. We accept both "x.com" and common legacy
    // forms; the Python patch only checks x.com so we do the same to be
    // safe about the endpoint actually accepting truncated requests.
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return url.to_string();
    };
    let Some(slash) = rest.find('/') else {
        return url.to_string();
    };
    let host = &rest[..slash];
    let path_and_query = &rest[slash..];

    // Strip port if present in host.
    let host_no_port = host.split(':').next().unwrap_or(host);
    if host_no_port != "x.com" {
        return url.to_string();
    }

    let Some(q_idx) = path_and_query.find('?') else {
        return url.to_string();
    };
    let path = &path_and_query[..q_idx];
    let query = &path_and_query[q_idx + 1..];

    if !path.starts_with("/i/api/graphql/") || !query.starts_with("variables=") {
        return url.to_string();
    }

    let new_query = match query.find('&') {
        Some(amp) => &query[..amp],
        None => query,
    };
    let scheme = if url.starts_with("https://") {
        "https://"
    } else {
        "http://"
    };
    format!("{}{}{}?{}", scheme, host, path, new_query)
}

/// Maximum bytes of random padding appended to outbound Apps Script
/// JSON request bodies. Picked so the per-request padding distribution
/// (uniformly 0..MAX) shifts the body length enough to defeat naive
/// length-fingerprint DPI without bloating bandwidth — at the average
/// 512-byte add, on a typical 2 KB tunnel batch this is +25%, which is
/// negligible compared to Apps Script's per-call latency floor anyway.
/// (Issue #313, #365 Section 1 — DPI evasion.)
const MAX_RANDOM_PAD_BYTES: usize = 1024;

/// Insert a `_pad` field of random length (0..MAX_RANDOM_PAD_BYTES)
/// into a request payload before serialization. Server-side ignores
/// unknown JSON fields, so this is fully backward-compatible with old
/// `Code.gs` / `CodeFull.gs` deployments — the pad is just along for
/// the ride.
///
/// Random bytes are base64-encoded (NO inner JSON-escape worries) and
/// the pad LENGTH itself is uniformly distributed, so packet sizes
/// land all over the place rather than clustering at a few discrete
/// peaks. That's the property DPI's length-distribution clustering
/// fingerprints can't match.
fn add_random_pad(map: &mut serde_json::Map<String, Value>) {
    let mut rng = thread_rng();
    let len = rng.gen_range(0..=MAX_RANDOM_PAD_BYTES);
    if len == 0 {
        // Skip the field entirely sometimes — adds another bit of
        // distribution variance (presence-vs-absence of `_pad` itself).
        return;
    }
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    map.insert("_pad".into(), Value::String(B64.encode(&buf)));
}

/// "YYYY-MM-DD" of the current Pacific Time date. Used as the daily-reset
/// boundary for `today_calls` / `today_bytes` because **Apps Script's
/// quota counter resets at midnight Pacific Time, not UTC** — that's
/// where Google's quota bookkeeping lives. We format manually so this
/// stays std-only and doesn't pull `time-tz` or `chrono` plus a ~3 MB
/// IANA tzdb just for one ~50-line helper. (Issue #230, #362.)
///
/// PT offset depends on DST: PST = UTC-8, PDT = UTC-7. We use the
/// stable US DST rule (2nd Sunday of March 02:00 → 1st Sunday of
/// November 02:00 = PDT, otherwise PST). The hour-of-day boundary on
/// transition days is approximated; this drifts by up to 1h for at
/// most 2h/year on the spring-forward / fall-back transitions, which
/// is fine for a daily countdown.
fn current_pt_day_key() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pt_secs = unix_to_pt_seconds(secs);
    let (y, m, d) = unix_to_ymd_utc(pt_secs);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Seconds until the next 00:00 Pacific Time. Used by the UI to render
/// a "resets in Xh Ym" countdown matching Apps Script's actual quota
/// reset cadence (#230, #362). Conservative: if the system clock is
/// broken we return 0 instead of a huge negative-looking number.
fn seconds_until_pacific_midnight() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pt_secs = unix_to_pt_seconds(secs);
    let day = 86_400u64;
    let rem = pt_secs % day;
    if rem == 0 {
        day
    } else {
        day - rem
    }
}

/// Convert Unix UTC seconds to "Pacific Time as if it were UTC" seconds,
/// i.e. add the PT-from-UTC offset (negative for the western hemisphere
/// becomes a subtraction). Result is suitable for feeding into
/// `unix_to_ymd_utc` to extract the PT calendar date, or for `% 86_400`
/// to find PT seconds-into-day.
fn unix_to_pt_seconds(utc_secs: u64) -> u64 {
    // First-pass guess at PT date using PST (-8) — used to determine
    // whether DST is currently in effect, which then settles the actual
    // offset. The two-pass approach avoids the chicken-and-egg of
    // "I need the PT date to know if it's DST, but I need the offset
    // to compute the PT date." A 1-hour fudge in the guess is harmless
    // because DST never starts within the first hour after midnight
    // PST or ends within the first hour after midnight PDT.
    let pst_guess = utc_secs.saturating_sub(8 * 3600);
    let (y, m, d) = unix_to_ymd_utc(pst_guess);
    let offset_secs = if pacific_is_dst(y, m, d) {
        7 * 3600
    } else {
        8 * 3600
    };
    utc_secs.saturating_sub(offset_secs)
}

/// Whether Pacific Time is observing daylight saving on the given
/// calendar date (year, month=1..12, day=1..31). US DST window:
/// 2nd Sunday of March through 1st Sunday of November. The transition
/// hour itself (02:00 local) is approximated to whole-day boundaries —
/// good enough for a daily-quota countdown.
fn pacific_is_dst(year: i64, month: u32, day: u32) -> bool {
    if !(3..=11).contains(&month) {
        return false;
    }
    if month > 3 && month < 11 {
        return true;
    }
    if month == 3 {
        let dst_start = nth_sunday_of_month(year, 3, 2);
        day >= dst_start
    } else {
        // month == 11
        let dst_end = nth_sunday_of_month(year, 11, 1);
        day < dst_end
    }
}

/// Day-of-month for the Nth Sunday (1-indexed) of (year, month). Uses
/// Sakamoto's method for the month's-1st day-of-week, then offsets to
/// the desired Sunday. Pure arithmetic, no calendar tables.
fn nth_sunday_of_month(year: i64, month: u32, nth: u32) -> u32 {
    // Sakamoto's day-of-week. 0 = Sunday.
    static T: [i64; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let y = if month < 3 { year - 1 } else { year };
    let m = month as i64;
    let dow_of_1st =
        ((y + y / 4 - y / 100 + y / 400 + T[(m - 1) as usize] + 1).rem_euclid(7)) as u32;
    let first_sunday = if dow_of_1st == 0 { 1 } else { 8 - dow_of_1st };
    first_sunday + (nth - 1) * 7
}

/// Convert a Unix timestamp (seconds since 1970-01-01 UTC) to a
/// (year, month, day) tuple, UTC. Standalone so we can stay
/// std-only — no chrono/time/jiff dependency pulled for one caller.
///
/// Algorithm: Howard Hinnant's civil_from_days, widely cited and
/// simple enough to audit by eye. Works for years 1970–9999 which
/// we'll outlive.
fn unix_to_ymd_utc(secs: u64) -> (i64, u32, u32) {
    let days = (secs / 86_400) as i64;
    // Shift so day 0 is 0000-03-01 (Hinnant's era-based trick).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Heuristic: does this byte slice parse as an exit-node `{s, h, b}`
/// envelope? Used to detect the pre-v2.0.2 Code.gs double-wrap case
/// where Apps Script ignored `raw: true` and re-wrapped the exit-node
/// response — the symptom is that, after one layer of unwrapping, the
/// body is *itself* another envelope. We require all three fields with
/// the expected types so a legitimate API response that happens to be
/// JSON with one matching key (e.g. an upstream that returns `{"s":
/// "ok"}`) doesn't trip the detector.
fn looks_like_exit_node_envelope(bytes: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    v.get("s").and_then(|x| x.as_u64()).is_some()
        && v.get("h").is_some_and(|x| x.is_object())
        && v.get("b").is_some_and(|x| x.is_string())
}

/// Parse the exit-node JSON envelope back into a raw HTTP/1.1
/// response. The envelope shape is:
///
/// - On success: `{ "s": <status u16>, "h": { ... }, "b": "<base64>" }`
/// - On exit-node-side error: `{ "e": "<message>" }` with HTTP 4xx/5xx
///   from exit-node's own status code (decoded from the outer Apps Script
///   layer, not the inner field).
///
/// We synthesize a complete HTTP/1.1 response from these fields so the
/// MITM TLS write-back path sees the same shape it gets from the regular
/// Apps Script relay (status line + headers + body).
fn parse_exit_node_response(body: &[u8], allow_brotli_zstd: bool) -> Result<Vec<u8>, FronterError> {
    // Defensive: if Apps Script accidentally prepends an HTTP-framing
    // prefix (status line + headers terminated by `\r\n\r\n`) before
    // the JSON envelope, skip past it before parsing. Normally Code.gs
    // returns just the envelope text under MimeType.JSON, but the raw
    // surface here is whatever bytes h2_round_trip / read_http_response
    // handed back, so a single defensive skip is cheap insurance.
    let json_start = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let json_bytes = &body[json_start..];
    let v: Value = serde_json::from_slice(json_bytes).map_err(|e| {
        FronterError::Relay(format!(
            "exit-node response not valid JSON ({}): {}",
            e,
            String::from_utf8_lossy(&json_bytes[..json_bytes.len().min(200)])
        ))
    })?;

    // Surface exit-node's internal errors clearly rather than as a 502
    // from the outer envelope. The `{e: "..."}` shape is what the exit-node's
    // script emits on bad PSK, malformed URL, or any caught exception.
    if let Some(err_msg) = v.get("e").and_then(|x| x.as_str()) {
        return Err(FronterError::Relay(format!(
            "exit node refused or errored: {}",
            err_msg
        )));
    }

    let status = v
        .get("s")
        .and_then(|x| x.as_u64())
        .map(|n| n as u16)
        .unwrap_or(502);
    let body_b64 = v.get("b").and_then(|x| x.as_str()).unwrap_or("");
    let mut body_bytes = if body_b64.is_empty() {
        Vec::new()
    } else {
        B64.decode(body_b64).map_err(|e| {
            FronterError::Relay(format!("exit-node body base64 decode failed: {}", e))
        })?
    };

    // Detect the pre-v2.0.2 double-wrap. If any layer between rahgozar
    // and the exit-node ignored our `raw: true` flag and re-wrapped the
    // exit-node response, the decoded body is itself another {s, h, b}
    // envelope rather than the destination's bytes. Without this check
    // the inner JSON would be handed to the browser as page content,
    // which is what users saw on upstream issue #1239. Surface the
    // misconfig as a specific error pointing at the fix.
    //
    // In CFW mode the symptom is identical for three deployment states
    // (Apps Script stale, Worker stale, or both), so the message must
    // list both fixes rather than naming one — a chain simulation
    // (`new GS + old Worker`, `old GS + new Worker`, `old GS + old
    // Worker`) all produce this exact error indistinguishably.
    if looks_like_exit_node_envelope(&body_bytes) {
        return Err(FronterError::Relay(
            "exit-node response was double-wrapped — at least one relay layer is \
             still running pre-v2.0.2 code that ignores the `raw: true` flag. \
             Redeploy BOTH of these:\n  \
             1. Apps Script: paste assets/apps_script/Code.gs (or Code.cfw.gs in \
                CFW mode), then Deploy → Manage deployments → pencil icon → \
                Version: New version → Deploy. Saving without cutting a new \
                version keeps the old code live at /exec.\n  \
             2. Cloudflare Worker (only in CFW mode): paste \
                assets/cloudflare/worker.js, then click \"Save and deploy\" in \
                the dashboard editor — \"Save\" alone only saves the draft.\n\
             Pasting code is not enough on either platform; both require an \
             explicit deploy click."
                .to_string(),
        ));
    }

    // Mirror parse_relay_json's decode-or-preserve policy for
    // Content-Encoding. Background: exit-node runtimes built on
    // `fetch` (Deno Deploy, modern Cloudflare Workers, recent Node)
    // auto-decompress gzip and brotli BUT NOT zstd — so a
    // destination served zstd reaches the relay as raw zstd bytes
    // with `Content-Encoding: zstd` intact. Stripping the header
    // unconditionally (as the pre-v2.1 code did) then delivers raw
    // zstd to the browser as plaintext, corrupting the page.
    //
    // The new logic:
    //   - Single-token gzip / br / identity / no header → strip
    //     (body is plain because the fetch runtime decoded it).
    //   - Single-token zstd with `allow_brotli_zstd` on → try to
    //     decode here; strip on success, preserve header on
    //     failure (browser tries its own decoder, browser surfaces
    //     a real error rather than rahgozar silently corrupting).
    //   - Single-token br with `allow_brotli_zstd` on → same
    //     try-decode-then-strip-or-preserve, in case a runtime
    //     somewhere doesn't auto-decode br either.
    //   - Anything else (multi-token chain, unknown encoding,
    //     decode failure) → preserve, let the browser try.
    //
    // When `allow_brotli_zstd` is off, the inner-request filter
    // strips `br`/`zstd` from outbound Accept-Encoding, so
    // destinations only ever respond with gzip/identity and the
    // historical "always strip" assumption holds for everything we
    // see here.
    // When `allow_brotli_zstd` is OFF we stay in legacy mode: the
    // inner-request filter stripped br/zstd from outbound
    // Accept-Encoding, so destinations only ever respond with
    // gzip/identity, and fetch-based exit-node runtimes
    // auto-decoded gzip server-side — the body reaching us is
    // always plain. Strip Content-Encoding unconditionally, just
    // like the pre-v2.1 code.
    //
    // When the flag is ON, br/zstd CAN reach us as raw bytes (some
    // exit-node runtimes don't auto-decode zstd), so apply the same
    // decode-or-preserve policy parse_relay_json uses.
    let mut strip_content_encoding = true;
    if allow_brotli_zstd && !body_bytes.is_empty() {
        if let Some(headers_obj) = v.get("h").and_then(|x| x.as_object()) {
            let enc_owned = headers_obj
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                .and_then(|(_, val)| header_string_value(val));
            if let Some(raw_enc) = enc_owned.as_deref() {
                let tokens: Vec<String> = raw_enc
                    .split(',')
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| !t.is_empty() && t != "identity")
                    .collect();
                if tokens.is_empty() {
                    strip_content_encoding = true;
                } else if tokens.len() == 1 {
                    match tokens[0].as_str() {
                        "gzip" => {
                            // fetch runtime auto-decoded — body plain.
                            strip_content_encoding = true;
                        }
                        "br" => match decode_brotli(&body_bytes) {
                            Ok(d) => {
                                body_bytes = d;
                                strip_content_encoding = true;
                            }
                            Err(_) => {
                                strip_content_encoding = false;
                            }
                        },
                        "zstd" => match decode_zstd(&body_bytes) {
                            Ok(d) => {
                                body_bytes = d;
                                strip_content_encoding = true;
                            }
                            Err(_) => {
                                strip_content_encoding = false;
                            }
                        },
                        _ => {
                            strip_content_encoding = false;
                        }
                    }
                } else {
                    strip_content_encoding = false;
                }
            }
        }
    }

    const BASE_SKIP_RESPONSE_HEADERS: &[&str] = &[
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
    ];

    let mut out = Vec::with_capacity(body_bytes.len() + 256);
    let _ = std::io::Write::write_fmt(
        &mut out,
        format_args!("HTTP/1.1 {} {}\r\n", status, status_reason(status)),
    );
    if let Some(headers_obj) = v.get("h").and_then(|x| x.as_object()) {
        for (k, v_val) in headers_obj {
            let lc = k.to_ascii_lowercase();
            if BASE_SKIP_RESPONSE_HEADERS.contains(&lc.as_str()) {
                continue;
            }
            if lc == "content-encoding" && strip_content_encoding {
                continue;
            }
            if let Some(val_str) = v_val.as_str() {
                let _ = std::io::Write::write_fmt(&mut out, format_args!("{}: {}\r\n", k, val_str));
            }
        }
    }
    let _ = std::io::Write::write_fmt(
        &mut out,
        format_args!("Content-Length: {}\r\n\r\n", body_bytes.len()),
    );
    out.extend_from_slice(&body_bytes);
    Ok(out)
}

/// Minimal HTTP status reason-phrase table for synthesizing status
/// lines in `parse_exit_node_response`. Browsers don't actually parse
/// the reason phrase (only the status code matters), but a recognizable
/// string makes log lines readable.
fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// True if `url`'s host is one of YouTube's `/videoplayback` endpoints.
/// Gates `strip_sabr_quality_tracks` so an unrelated service that
/// happens to expose `/videoplayback` and serves a protobuf-shaped body
/// with top-level fields 2 and 3 doesn't get its field-3 entries
/// silently rewritten.
///
/// Two host families serve `/videoplayback`:
///
/// * `*.googlevideo.com` — the YouTube chunk CDN. Most segment-fetch
///   POSTs land here on subdomains like `rrx---sn-xxx.googlevideo.com`.
/// * `youtube.com` (and subdomains) — direct same-origin endpoints
///   used by the YouTube web client in some client variants.
///
/// Match is case-insensitive and trailing-dot tolerant. Anything else
/// returns false; the strip is a no-op.
fn url_host_is_youtube_video_endpoint(url: &str) -> bool {
    let host = match extract_host(url) {
        Some(h) => h,
        None => return false,
    };
    let h = host.trim_end_matches('.');
    if h.is_empty() {
        return false;
    }
    const YT_VIDEOPLAYBACK_SUFFIXES: &[&str] = &["googlevideo.com", "youtube.com"];
    YT_VIDEOPLAYBACK_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

/// Strip surplus field-3 (quality-track selection) entries from a SABR
/// segment-fetch protobuf body, keeping the first one intact.
///
/// YouTube's SABR (Server-Adaptive Bitrate) `videoplayback` POST bodies
/// come in two distinct message shapes:
///
/// * **Segment-fetch** — carries field-2 (tag `0x12`) byte-range entries
///   for video/audio segments. Field-3 (tag `0x1a`) entries here are
///   quality-track selectors that ask googlevideo to return a particular
///   quality track. When the player asks for *multiple* tracks at once
///   (multi-track bundling), googlevideo concatenates them into a single
///   response — easily exceeding Apps Script `UrlFetchApp`'s ~10 MB cap
///   → 502.
///
/// * **Session-init** — carries field-5 (tag `0x2a`) entries and *no*
///   field-2 entries. Field-3 here is essential session metadata
///   (language, viewer state, ...). Stripping it corrupts the init
///   handshake → CDN returns 403.
///
/// **Heuristic**:
///
/// 1. Body must be segment-fetch shape (≥ 1 field-2 entry). Otherwise
///    no-op — session-init bodies must not be touched.
/// 2. Body must carry **2 or more** field-3 entries before stripping
///    fires. The first field-3 is always kept; only the 2nd, 3rd, ...
///    are removed.
///
/// **Why keep the first field-3** (#977, unacoder testing, May 2026):
/// the original "strip all field-3" rule produced empty googlevideo
/// responses on single-track requests — the player asks for ONE track
/// via a sole field-3, we strip it, and the CDN answers a request with
/// zero tracks selected by sending nothing. The player retries
/// indefinitely with the `rn=` retry counter incrementing, never
/// advancing its buffer. Keeping the first field-3 means single-track
/// requests pass through unchanged (no regression at low quality)
/// while multi-track requests still get capped to one track (the
/// 10 MB-blowup fix is preserved).
///
/// Only top-level fields are inspected; nested messages are left intact.
/// On a malformed body (truncated tag, unknown wire type) the unparsed
/// tail is appended verbatim so a corrupt request is never silently
/// truncated. Originally ported from upstream
/// `_strip_sabr_quality_tracks` (commits 9b6d03e + 33db28a); the
/// keep-first refinement diverges from upstream based on local testing.
pub(crate) fn strip_sabr_quality_tracks(body: &[u8]) -> Vec<u8> {
    // Phase 1: single pass — collect (field_number, start, end) for every
    // top-level field. We need both the segment-fetch detection (field-2
    // present) AND the field-3 count (≥ 2 to fire) before deciding,
    // and a two-pass walk would be wasteful.
    let mut segments: Vec<(u32, usize, usize)> = Vec::new();
    let mut has_field2 = false;
    let mut field3_count: usize = 0;
    let mut i = 0usize;
    let n = body.len();
    let mut tail_start = n;

    'outer: while i < n {
        let seg_start = i;

        // Decode varint tag.
        let mut tag: u64 = 0;
        let mut shift: u32 = 0;
        let mut tag_complete = false;
        while i < n {
            let b = body[i];
            i += 1;
            tag |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                tag_complete = true;
                break;
            }
            shift += 7;
            if shift >= 64 {
                // Pathologically long varint — bail.
                tail_start = seg_start;
                break 'outer;
            }
        }
        if !tag_complete {
            tail_start = seg_start;
            break;
        }

        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        // Each branch advances `i` past the field's payload. Truncation
        // (running off the end before the payload is whole) bails out
        // with `tail_start = seg_start` so the malformed segment and
        // everything after it is preserved verbatim — never silently
        // dropped, never half-stripped.
        match wire_type {
            0 => {
                // varint payload: bytes with high bit set are
                // continuation; first byte with high bit clear is the
                // terminator. EOF before terminator = truncated.
                let mut term = false;
                while i < n {
                    let b = body[i];
                    i += 1;
                    if b & 0x80 == 0 {
                        term = true;
                        break;
                    }
                }
                if !term {
                    tail_start = seg_start;
                    break;
                }
            }
            1 => {
                // 64-bit fixed
                if n - i < 8 {
                    tail_start = seg_start;
                    break;
                }
                i += 8;
            }
            2 => {
                // length-delimited: varint length, then `val_len` bytes.
                let mut val_len: u64 = 0;
                let mut shift: u32 = 0;
                let mut len_complete = false;
                while i < n {
                    let b = body[i];
                    i += 1;
                    val_len |= ((b & 0x7F) as u64) << shift;
                    if b & 0x80 == 0 {
                        len_complete = true;
                        break;
                    }
                    shift += 7;
                    if shift >= 64 {
                        tail_start = seg_start;
                        break 'outer;
                    }
                }
                if !len_complete {
                    tail_start = seg_start;
                    break;
                }
                // Payload truncated: declared length runs past buffer end.
                // Bail BEFORE recording the segment so a half-present
                // field-3 isn't accidentally stripped from the output.
                let val_len = val_len as usize;
                if val_len > n - i {
                    tail_start = seg_start;
                    break;
                }
                i += val_len;
            }
            5 => {
                // 32-bit fixed
                if n - i < 4 {
                    tail_start = seg_start;
                    break;
                }
                i += 4;
            }
            _ => {
                // Unknown wire type — bail, tail copied verbatim.
                tail_start = seg_start;
                break;
            }
        }

        if field_number == 2 {
            has_field2 = true;
        } else if field_number == 3 {
            field3_count += 1;
        }
        segments.push((field_number, seg_start, i));
    }

    // Phase 2: only strip when this is a segment-fetch body (has field
    // 2) AND there are at least 2 field-3 entries — i.e. real multi-
    // track bundling. Single-track requests (one field-3) flow through
    // unchanged so googlevideo still has a track selected.
    if !has_field2 || field3_count < 2 {
        return body.to_vec();
    }

    // Keep the first field-3 entry, strip the rest. `field3_kept`
    // flips to `true` after the first encounter so subsequent ones
    // fall through the strip branch.
    let mut out = Vec::with_capacity(body.len());
    let mut field3_kept = false;
    for (field_number, seg_start, seg_end) in segments {
        if field_number == 3 {
            if !field3_kept {
                field3_kept = true;
                out.extend_from_slice(&body[seg_start..seg_end]);
            }
            // else: strip
        } else {
            out.extend_from_slice(&body[seg_start..seg_end]);
        }
    }
    if tail_start < n {
        out.extend_from_slice(&body[tail_start..]);
    }
    out
}

/// Extract the host (no scheme, no port, no path) from a URL string.
/// Falls back to the input verbatim if no `://` is present, so callers
/// get a best-effort authority rather than `None` on bare hostnames.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or("");
    // Strip userinfo if present.
    let authority = authority
        .rsplit_once('@')
        .map(|(_, a)| a)
        .unwrap_or(authority);
    // Strip port. Handle IPv6 literals in brackets.
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // [::1]:443 -> ::1
        stripped.split_once(']').map(|(h, _)| h).unwrap_or(stripped)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// The default pool of SNI names that share the Google Front End with
/// `www.google.com`. Used both when auto-expanding from `front_domain` and
/// when the UI wants to show the starting candidates for the SNI editor.
pub const DEFAULT_GOOGLE_SNI_POOL: &[&str] = &[
    "www.google.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "calendar.google.com",
    // accounts.google.com — standard Google account service, covered by
    // the *.google.com wildcard cert. Previously listed as
    // accounts.googl.com (issue #42), but googl.com is NOT in the SAN
    // list of Google's GFE certificate — connections with verify_ssl=true
    // fail with "certificate not valid for name" when the round-robin
    // lands on it.
    "accounts.google.com",
    // scholar.google.com — reported
    // in #47 as a DPI-passing SNI on MCI / Samantel. Covered by the
    // core *.google.com cert so it handshakes normally against
    // google_ip:443.
    "scholar.google.com",
    // Additional Google properties for rotation. Ported from upstream
    // Python `FRONT_SNI_POOL_GOOGLE` (masterking32/MasterHttpRelayVPN
    // commit 57738ec, "Add additional Google services to exclusion
    // lists"). All served off the same GFE IP range, all covered by the
    // wildcard cert, all give the DPI-fingerprint spread without extra
    // config. A few of these (maps.google.com, play.google.com) reliably
    // pass DPI on carriers where the shorter `*.google.com` names don't.
    "maps.google.com",
    "chat.google.com",
    "translate.google.com",
    "play.google.com",
    "lens.google.com",
    // chromewebstore.google.com — reported in issue #75 as a working
    // SNI. Same family as the rest: wildcard cert, GFE-hosted,
    // handshake against google_ip:443 with no content negotiation.
    "chromewebstore.google.com",
];

/// Build the pool of SNI hosts used for outbound connections to the Google
/// edge.
///
/// Precedence:
/// 1. If `user_pool` is non-empty, use it verbatim (user is in charge).
/// 2. If `primary` is one of the DEFAULT_GOOGLE_SNI_POOL entries, auto-expand
///    to the full default list with `primary` first. This gives the per-SNI
///    connection-count fingerprint spread without the user configuring
///    anything.
/// 3. Otherwise — custom / non-Google `primary` — use just `[primary]`, since
///    we have no way to verify which sibling names share a non-Google edge.
///
/// All entries MUST be hosted on the same edge as `connect_host`, otherwise
/// the TLS handshake will land on the wrong server.
pub fn build_sni_pool_for(primary: &str, user_pool: &[String]) -> Vec<String> {
    let primary = primary.trim().to_string();
    let user_filtered: Vec<String> = user_pool
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !user_filtered.is_empty() {
        return user_filtered;
    }

    let looks_like_google_edge = DEFAULT_GOOGLE_SNI_POOL.iter().any(|s| *s == primary);
    let mut pool = vec![primary.clone()];
    if looks_like_google_edge {
        for s in DEFAULT_GOOGLE_SNI_POOL {
            if *s != primary {
                pool.push((*s).to_string());
            }
        }
    }
    pool
}

/// Back-compat thin wrapper for the old callers / tests.
fn build_sni_pool(primary: &str) -> Vec<String> {
    build_sni_pool_for(primary, &[])
}

/// Back-compat facade for callers pinned to the pre-v2.1 signature.
/// Equivalent to `filter_forwarded_headers_with_brotli_zstd(headers,
/// false)`, i.e. the historical strip-br/zstd behaviour. Internal
/// rahgozar code uses the `_with_brotli_zstd` variant directly so the
/// `allow_brotli_zstd` config flag actually has effect; the public
/// no-flag entry point is preserved purely so downstream crates
/// linking against `rahgozar::domain_fronter::filter_forwarded_headers`
/// don't break on this point release.
pub fn filter_forwarded_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    filter_forwarded_headers_with_brotli_zstd(headers, false)
}

pub fn filter_forwarded_headers_with_brotli_zstd(
    headers: &[(String, String)],
    allow_brotli_zstd: bool,
) -> Vec<(String, String)> {
    const SKIP: &[&str] = &[
        // Hop-by-hop / framing — must not be forwarded across the proxy.
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "proxy-authorization",
        // Identity-revealing forwarding headers (issue #104).
        // If the user sits behind another proxy or uses a browser
        // extension that inserts any of these, they'd normally carry
        // the client's real IP. We strip every known variant so the
        // origin server only ever sees whatever source IP the Apps
        // Script or GFE path terminates on — never the user's home IP.
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-forwarded-server",
        "x-forwarded-ssl",
        "forwarded",
        "via",
        "x-real-ip",
        "x-client-ip",
        "x-originating-ip",
        "true-client-ip",
        "cf-connecting-ip",
        "fastly-client-ip",
        "x-cluster-client-ip",
        "client-ip",
    ];
    headers
        .iter()
        .filter_map(|(k, v)| {
            let lk = k.to_ascii_lowercase();
            if SKIP.contains(&lk.as_str()) {
                return None;
            }
            if lk == "accept-encoding" {
                if allow_brotli_zstd {
                    // User opted in: forward br/zstd through to the
                    // destination. `parse_relay_json` decodes any
                    // resulting encoded body before stripping the
                    // `Content-Encoding` header for browser delivery.
                    return Some((k.clone(), v.clone()));
                }
                let cleaned = strip_brotli_from_accept_encoding(v);
                if cleaned.is_empty() {
                    return None;
                }
                return Some((k.clone(), cleaned));
            }
            Some((k.clone(), v.clone()))
        })
        .collect()
}

/// Strip `br` and `zstd` from an `Accept-Encoding` header value.
/// Name is historical (added when only brotli was in scope);
/// implementation also drops `zstd` because `UrlFetchApp` doesn't
/// auto-decompress that either — see `Config::allow_brotli_zstd`
/// for the policy this enforces by default. q-values
/// (`br;q=0.5`) are recognised and dropped along with their token.
fn strip_brotli_from_accept_encoding(value: &str) -> String {
    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
    let kept: Vec<&str> = parts
        .into_iter()
        .filter(|p| {
            let tok = p
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            tok != "br" && tok != "zstd"
        })
        .collect();
    kept.join(", ")
}

/// Normalise an Apps Script JSON header value to its string form.
///
/// `getAllHeaders()` returns header values as either a plain string
/// (the common case) or, for headers that appeared multiple times in
/// the upstream response, a JSON array of strings. The historical
/// header-handling paths in this module assumed string-only — array
/// forms silently fell through, which is fine for headers we
/// pass-through but catastrophic for `Content-Encoding` where the
/// downstream code makes a strip-or-keep decision based on the
/// recognised value.
///
/// Array values are joined with `", "` to mimic the comma-form
/// fold-multi-value-headers convention; downstream tokenisers split
/// on `','` anyway. `Null` / number / object / unparseable arrays
/// return `None` (treated by callers as "header absent").
fn header_string_value(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(arr) => {
            let parts: Vec<&str> = arr.iter().filter_map(|item| item.as_str()).collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(", "))
            }
        }
        _ => None,
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn parse_redirect(location: &str) -> (String, Option<String>) {
    // Absolute URL: http(s)://host/path?query
    if let Some(rest) = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))
    {
        let slash = rest.find('/').unwrap_or(rest.len());
        let host = rest[..slash].to_string();
        let path = if slash < rest.len() {
            rest[slash..].to_string()
        } else {
            "/".into()
        };
        return (path, Some(host));
    }
    // Relative path.
    (location.to_string(), None)
}

/// Read a single HTTP/1.1 response from the stream. Keep-alive safe: respects
/// Content-Length or chunked transfer-encoding.
///
/// Uses a 10 s *total* header-read deadline — the historical 10 s value
/// preserved for most callers (relay path, exit-node, etc.). Note the
/// semantics changed in this patch: the underlying loop now treats this
/// as an absolute deadline across all header reads, not a per-read budget
/// that would silently extend on drip-feed. The tunnel batch path overrides
/// the 10 s value via `read_http_response_with_header_timeout`, since the
/// configurable `request_timeout_secs` (default 30 s) is the authoritative
/// cliff there.
async fn read_http_response<S>(
    stream: &mut S,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    read_http_response_with_header_timeout(stream, Duration::from_secs(10)).await
}

/// `read_http_response` with a caller-supplied header-read timeout. The
/// timeout applies only to the *initial* header-block read; the body-read
/// timeouts in this function are deliberately left at their fixed values
/// because once the response has started flowing, per-chunk stalls are a
/// separate signal from "Apps Script hasn't started writing yet."
///
/// The tunnel batch path passes `DomainFronter::batch_timeout()` so that
/// `Config::request_timeout_secs` is the *only* knob controlling how long
/// we wait for an Apps Script edge to start responding — the hardcoded 10 s
/// inner cliff was firing well before the outer `batch_timeout` in
/// `tunnel_client::fire_batch` could, masquerading as a 10 s "batch
/// timeout" in user logs (issue #1088).
async fn read_http_response_with_header_timeout<S>(
    stream: &mut S,
    header_read_timeout: Duration,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    // One deadline for the whole header read, not per-iteration. Otherwise
    // a slow peer drip-feeding one byte just under `header_read_timeout`
    // keeps this loop alive forever and defeats the outer `batch_timeout`
    // wiring (the entire point of #1088's fix).
    let deadline = tokio::time::Instant::now() + header_read_timeout;
    let header_end = loop {
        let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp))
            .await
            .map_err(|_| FronterError::Timeout)??;
        if n == 0 {
            return Err(FronterError::BadResponse(
                "connection closed before headers".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 1024 * 1024 {
            return Err(FronterError::BadResponse("headers too large".into()));
        }
    };

    let header_section = &buf[..header_end];
    let header_str = std::str::from_utf8(header_section)
        .map_err(|_| FronterError::BadResponse("non-utf8 headers".into()))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = parse_status_line(status_line)?;

    let mut headers_out: Vec<(String, String)> = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers_out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    let content_length: Option<usize> =
        header_get(&headers_out, "content-length").and_then(|v| v.parse().ok());
    let te = header_get(&headers_out, "transfer-encoding").unwrap_or_default();
    let is_chunked = te.to_ascii_lowercase().contains("chunked");

    if is_chunked {
        body = read_chunked(stream, body).await?;
    } else if let Some(cl) = content_length {
        while body.len() < cl {
            let need = cl - body.len();
            let want = need.min(tmp.len());
            // Handle ungraceful TLS close-without-close_notify (rustls
            // surfaces this as `io::ErrorKind::UnexpectedEof`). Some
            // origins — notably exit-node path through Apps
            // Script (#585, v1.9.4) and certain Apps Script `Connection:
            // close` responses — terminate the underlying TCP without
            // sending the TLS close_notify alert first. Treat that the
            // same as a clean `n == 0`: if we already have the full body
            // declared by Content-Length, the response *is* complete.
            // Only propagate the error if Content-Length couldn't be
            // satisfied (real truncation, not a polite-protocol violation).
            let read_res = timeout(Duration::from_secs(20), stream.read(&mut tmp[..want]))
                .await
                .map_err(|_| FronterError::Timeout)?;
            let n = match read_res {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(FronterError::BadResponse(
                    "connection closed before full response body".into(),
                ));
            }
            body.extend_from_slice(&tmp[..n]);
        }
    } else {
        // No framing — read until short timeout, EOF, or ungraceful
        // TLS close (UnexpectedEof). Each is treated as "we got what
        // the peer wanted to send"; the response we already have is
        // returned to the caller. UnexpectedEof here is the most common
        // case for `Connection: close` responses from servers that
        // don't bother with TLS close_notify (#585).
        loop {
            match timeout(Duration::from_secs(2), stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => body.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }
        }
    }

    // gzip decompress if content-encoding says so.
    if let Some(enc) = header_get(&headers_out, "content-encoding") {
        if enc.eq_ignore_ascii_case("gzip") {
            if let Ok(decoded) = decode_gzip(&body) {
                body = decoded;
            }
        }
    }

    Ok((status, headers_out, body))
}

async fn read_chunked<S>(stream: &mut S, mut buf: Vec<u8>) -> Result<Vec<u8>, FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 16384];
    loop {
        let size_line_owned =
            std::str::from_utf8(&read_crlf_line(stream, &mut buf, &mut tmp).await?)
                .map_err(|_| FronterError::BadResponse("bad chunk size".into()))?
                .trim()
                .to_string();
        if size_line_owned.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(size_line_owned.split(';').next().unwrap_or(""), 16)
            .map_err(|_| {
                FronterError::BadResponse(format!("bad chunk size '{}'", size_line_owned))
            })?;
        if size == 0 {
            loop {
                if read_crlf_line(stream, &mut buf, &mut tmp).await?.is_empty() {
                    return Ok(out);
                }
            }
        }
        while buf.len() < size + 2 {
            // UnexpectedEof tolerance — see read_http_response for
            // rationale. Treated as `n == 0`; if we haven't accumulated
            // the full chunk yet, that's still a real truncation and
            // we return BadResponse below.
            let read_res = timeout(Duration::from_secs(20), stream.read(&mut tmp))
                .await
                .map_err(|_| FronterError::Timeout)?;
            let n = match read_res {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(FronterError::BadResponse(
                    "connection closed mid-chunked response".into(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        if &buf[size..size + 2] != b"\r\n" {
            return Err(FronterError::BadResponse(
                "chunk missing trailing CRLF".into(),
            ));
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<Vec<u8>, FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(idx) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..idx].to_vec();
            buf.drain(..idx + 2);
            return Ok(line);
        }
        let n = timeout(Duration::from_secs(20), stream.read(tmp))
            .await
            .map_err(|_| FronterError::Timeout)??;
        if n == 0 {
            return Err(FronterError::BadResponse(
                "connection closed mid-chunked response".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn decode_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut out = Vec::with_capacity(data.len() * 2);
    flate2::read::GzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

/// Hard cap on decompressed output for `decode_brotli` / `decode_zstd`.
/// The inputs are origin-controlled bytes, so a tiny payload could in
/// principle decode to many gigabytes (compression-bomb / zip-bomb
/// pattern). Cap matches Apps Script's ~50 MB response ceiling so a
/// legitimate body never trips it but a malicious bomb does. Hit on
/// the cap is treated as a decode failure by callers, who deliver the
/// raw bytes through with `Content-Encoding` preserved so the browser
/// can decide what to do.
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// Decode a `Content-Encoding: br` body. Pure-Rust via the `brotli`
/// crate's `Decompressor` reader, bounded by `MAX_DECOMPRESSED_BYTES`
/// so a compression-bomb upstream can't blow the relay's heap. Used
/// only when `allow_brotli_zstd` is on — see
/// [`Config::allow_brotli_zstd`] for the policy rationale.
fn decode_brotli(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut out = Vec::with_capacity(data.len() * 2);
    brotli::Decompressor::new(data, 4096)
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "brotli payload exceeds size cap",
        ));
    }
    Ok(out)
}

/// Decode a `Content-Encoding: zstd` body, bounded by
/// `MAX_DECOMPRESSED_BYTES` in two distinct ways:
///
/// 1. **Frame-header pre-check.** Zstd frames declare a *window
///    size* and (optionally) a *content size*; `ruzstd` will
///    allocate a decode buffer proportional to the declared window
///    even before any output flows. A hostile origin can ship a tiny
///    body that declares a multi-GiB window and force the decoder to
///    pre-allocate huge buffers, defeating an output-side cap. We
///    parse the frame header first, reject anything that declares a
///    window or a content size larger than the cap, and only then
///    hand the bytes to the streaming decoder.
/// 2. **Output-side cap.** `.take(MAX+1)` on the streaming-decode
///    read end so a frame that decodes to more than the cap (only
///    possible if the declared window was below the cap but the
///    actual payload still overruns) is rejected on the way out.
///
/// Used only when `allow_brotli_zstd` is on. See `decode_brotli` for
/// the parallel bomb-defence on brotli.
fn decode_zstd(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    // Frame-header pre-check on a temporary cursor. The streaming
    // decoder below re-parses the header itself from a fresh slice,
    // so the cursor advance here is throwaway work.
    let mut header_cursor = std::io::Cursor::new(data);
    let (frame, _bytes_read) = ruzstd::frame::read_frame_header(&mut header_cursor)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}", e)))?;
    let window_size = frame.header.window_size().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("zstd window invalid: {:?}", e),
        )
    })?;
    if window_size > MAX_DECOMPRESSED_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "zstd window exceeds size cap",
        ));
    }
    // Declared content size is u64; the zstd format uses 0 as
    // "unknown" when single_segment is not set, but a real
    // single-segment frame with declared size 0 is a zero-byte
    // payload and is harmless either way. A non-zero declaration
    // above the cap is a clear bomb signal — reject.
    let declared_content = frame.header.frame_content_size();
    if declared_content > MAX_DECOMPRESSED_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "zstd declared content size exceeds cap",
        ));
    }
    let decoder = ruzstd::StreamingDecoder::new(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}", e)))?;
    let mut out = Vec::with_capacity(data.len() * 2);
    decoder
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "zstd payload exceeds size cap",
        ));
    }
    Ok(out)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<u16, FronterError> {
    // "HTTP/1.1 200 OK"
    let mut parts = line.split_whitespace();
    let _version = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| FronterError::BadResponse(format!("bad status line: {}", line)))?;
    code.parse::<u16>()
        .map_err(|_| FronterError::BadResponse(format!("bad status code: {}", code)))
}

/// Returns `true` if the HTTP method is safe to fan-out across multiple
/// Apps Script deployments (i.e. idempotent per RFC 9110 §9.2.2). Used
/// by `do_relay_with_retry` to gate the `parallel_relay` fan-out so that
/// non-idempotent operations (POST / PUT / PATCH / DELETE) don't double-
/// fire at the destination — Apps Script `UrlFetchApp.fetch()` can't be
/// cancelled mid-request from our side, so every parallel attempt
/// completes server-side even when our `select_ok` already returned a
/// winner. See #743 for the user-visible bug (duplicate POSTs).
fn is_method_safe_for_fanout(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

/// Recognize HTTP statuses from the h2 path that mean "this edge
/// won't accept your fronted h2 request, but might accept the same
/// request over h1." Used to trigger an automatic sticky-disable of
/// the h2 fast path + h1 fallback.
///
/// 421 (Misdirected Request) is the spec signal: per RFC 7540
/// §9.1.2, the server returns it when the connection's authority is
/// not appropriate for the request URI. With domain fronting that
/// means the edge enforced "TLS SNI must match :authority" — true
/// on h2 (the server sees both pseudo-headers in cleartext) but
/// historically lenient on h1 (the encrypted Host header is what
/// the bypass relies on). Treating 421 as h2-fallback rather than
/// "Apps Script error" prevents h2 default-on from breaking
/// previously-working h1 deployments.
///
/// Other edge-level rejects (403, etc.) are ambiguous — could be a
/// real Apps Script geoblock or a real upstream — so we don't
/// blanket-treat them.
///
/// The h2 layer treats this as a "request not sent upstream"
/// outcome (the edge rejected before forwarding to Apps Script),
/// so falling back to h1 is safe with no duplication risk.
fn is_h2_fronting_refusal_status(status: u16) -> bool {
    status == 421
}

/// Parse the JSON envelope from Apps Script and build a raw HTTP response.
fn parse_relay_json(body: &[u8], allow_brotli_zstd: bool) -> Result<Vec<u8>, FronterError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| FronterError::BadResponse("non-utf8 json".into()))?
        .trim();
    if text.is_empty() {
        return Err(FronterError::BadResponse("empty relay body".into()));
    }

    let data: RelayResponse = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            // Some deployments (legacy Code.gs that used HtmlService for
            // _json, or our own doGet hit accidentally via a redirect
            // chain) wrap the JSON inside the goog.script sandbox iframe
            // as `goog.script.init("\x7b...userHtml...\x7d", "", undefined)`.
            // Try that unwrap first — if it succeeds, the inner userHtml
            // *is* our JSON. Mirrors upstream's Python client extractor.
            if let Some(unwrapped) = extract_apps_script_user_html(text) {
                if let Ok(v) = serde_json::from_str(&unwrapped) {
                    v
                } else {
                    return Err(FronterError::BadResponse(format!(
                        "no json in apps_script user_html: {}",
                        &unwrapped[..unwrapped.len().min(200)]
                    )));
                }
            } else {
                // Last resort: extract first { ... last }, in case Apps
                // Script prepended HTML preamble before the raw JSON.
                let start = text.find('{').ok_or_else(|| {
                    FronterError::BadResponse(format!(
                        "no json in: {}",
                        &text[..text.len().min(200)]
                    ))
                })?;
                let end = text.rfind('}').ok_or_else(|| {
                    FronterError::BadResponse(format!(
                        "no json end in: {}",
                        &text[..text.len().min(200)]
                    ))
                })?;
                if start > end {
                    return Err(FronterError::BadResponse(format!(
                        "no valid json object in: {}",
                        &text.chars().take(200).collect::<String>()
                    )));
                }
                serde_json::from_str(&text[start..=end])?
            }
        }
    };

    if let Some(e) = data.e {
        return Err(FronterError::Relay(e));
    }

    let status = data.s.unwrap_or(200);
    let status_text = status_text(status);
    let mut resp_body = match data.b {
        Some(b) => B64
            .decode(b)
            .map_err(|e| FronterError::BadResponse(format!("bad relay body base64: {}", e)))?,
        None => Vec::new(),
    };

    // Decide whether to strip `Content-Encoding` from the response
    // delivered to the browser, and decode brotli/zstd bodies when
    // the user has opted in.
    //
    // The historical logic stripped `Content-Encoding` unconditionally
    // because Apps Script's `UrlFetchApp` auto-decodes gzip
    // server-side, so by the time bodies reach us they were always
    // plain — leaving the header would have browsers retry
    // decompression on plaintext and fail with
    // `ERR_CONTENT_DECODING_FAILED`. That assumption holds only for
    // gzip (and missing/identity headers). With `allow_brotli_zstd`
    // we may now see real br/zstd bytes here, so the strip becomes
    // conditional:
    //
    //   - Single-token `gzip` / `identity` / no header: strip (body
    //     is plain because Apps Script auto-decoded or never encoded).
    //   - Single-token `br` / `zstd` with the flag on and a
    //     successful decode: strip (we just produced plain bytes).
    //   - Anything else (decode failure, size-cap exceeded, multi-
    //     token chain like `gzip, br` whose peel-order we can't
    //     prove): keep `Content-Encoding` so the browser can try its
    //     own decoders. Better an honest decode error than corrupted
    //     bytes silently delivered.
    let mut strip_content_encoding = true;
    if !resp_body.is_empty() {
        if let Some(hmap) = data.h.as_ref() {
            // `getAllHeaders()` in Apps Script can serialise a
            // repeated header either as a JSON string (single value
            // or comma-joined) OR as a JSON array of strings. The
            // historical code only matched the string form, which
            // meant an array-form `content-encoding: ["br"]` was
            // silently invisible: we wouldn't decode, but the BASE
            // strip-list above would still strip the header,
            // corrupting the body delivered to the browser. Normalise
            // both shapes through `header_string_value` so the same
            // decode-or-preserve decision logic below covers both.
            let enc_owned = hmap
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                .and_then(|(_, v)| header_string_value(v));
            if let Some(raw_enc) = enc_owned.as_deref() {
                let tokens: Vec<String> = raw_enc
                    .split(',')
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| !t.is_empty() && t != "identity")
                    .collect();
                if tokens.is_empty() {
                    // header was just "identity" or whitespace — body is plain.
                    strip_content_encoding = true;
                } else if tokens.len() == 1 {
                    match tokens[0].as_str() {
                        "gzip" => {
                            // Apps Script auto-decoded; body is plain.
                            strip_content_encoding = true;
                        }
                        "br" if allow_brotli_zstd => match decode_brotli(&resp_body) {
                            Ok(d) => {
                                resp_body = d;
                                strip_content_encoding = true;
                            }
                            Err(_) => {
                                strip_content_encoding = false;
                            }
                        },
                        "zstd" if allow_brotli_zstd => match decode_zstd(&resp_body) {
                            Ok(d) => {
                                resp_body = d;
                                strip_content_encoding = true;
                            }
                            Err(_) => {
                                strip_content_encoding = false;
                            }
                        },
                        _ => {
                            // Unknown single-token encoding (e.g. "deflate"
                            // — UrlFetchApp doesn't auto-decode that
                            // either) or br/zstd with the flag off.
                            // Pass the header through so the browser can
                            // try.
                            strip_content_encoding = false;
                        }
                    }
                } else {
                    // Multi-token chain (e.g. "gzip, br"). We don't
                    // know which layer Apps Script peeled and which
                    // it left, so don't guess — leave header intact.
                    strip_content_encoding = false;
                }
            }
        }
    }

    let mut out = Vec::with_capacity(resp_body.len() + 256);
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status, status_text).as_bytes());

    // `content-encoding` is conditionally stripped: when we just
    // decoded the body, the header is stale and must go (otherwise
    // browsers retry decoding plaintext and fail with
    // `ERR_CONTENT_DECODING_FAILED`). When we did NOT decode — flag
    // off, decode failed, or unrecognised encoding chain — keep the
    // header so the browser can try its own decoders.
    const BASE_SKIP: &[&str] = &[
        "transfer-encoding",
        "connection",
        "keep-alive",
        "content-length",
    ];

    if let Some(hmap) = data.h {
        for (k, v) in hmap {
            let lk = k.to_ascii_lowercase();
            if BASE_SKIP.contains(&lk.as_str()) {
                continue;
            }
            if lk == "content-encoding" && strip_content_encoding {
                continue;
            }
            match v {
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = value_to_header_str(&item) {
                            out.extend_from_slice(format!("{}: {}\r\n", k, s).as_bytes());
                        }
                    }
                }
                other => {
                    if let Some(s) = value_to_header_str(&other) {
                        out.extend_from_slice(format!("{}: {}\r\n", k, s).as_bytes());
                    }
                }
            }
        }
    }

    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", resp_body.len()).as_bytes());
    out.extend_from_slice(&resp_body);
    Ok(out)
}

/// Unwrap the `goog.script.init` sandbox iframe that wraps every
/// HtmlService web-app response. The wrapper text looks roughly like:
///
/// ```text
/// <html>...
/// goog.script.init("\x7b\x22userHtml\x22:\x22{...}\x22,...\x7d", "", undefined);
/// ...
/// ```
///
/// where the first parameter is a JSON string (with `\xNN` byte-escapes
/// for `{`, `"`, etc.) whose `userHtml` field carries our actual JSON
/// body. We find the marker, decode the byte-escapes, parse the outer
/// JSON, and return `userHtml`. Returns `None` if any step doesn't
/// match — the caller falls back to the brace-scan path.
///
/// Mirrors `_extract_apps_script_user_html` in upstream Python client.
fn extract_apps_script_user_html(text: &str) -> Option<String> {
    let marker = "goog.script.init(\"";
    let start_idx = text.find(marker)? + marker.len();
    // The marker is closed by `", "", undefined` (Apps Script always
    // emits this exact literal — there are two more positional args after
    // the JSON string, both empty / undefined).
    let end_marker = "\", \"\", undefined";
    let end_idx = text[start_idx..].find(end_marker)? + start_idx;
    let encoded = &text[start_idx..end_idx];

    // Decode `\xNN` and `\u00NN` byte-escapes that Apps Script uses to
    // protect `{`, `"`, `\`, etc. inside the JS string literal.
    let decoded = decode_js_string_escapes(encoded)?;

    // Outer JSON — typically `{"userHtml":"<our JSON>", ...}`.
    let outer: Value = serde_json::from_str(&decoded).ok()?;
    let user_html = outer.get("userHtml")?.as_str()?;
    Some(user_html.to_string())
}

/// Minimal JS string-literal escape decoder for `\xNN`, `\uNNNN`, and
/// the standard backslash forms (`\\`, `\"`, `\n`, `\r`, `\t`, `\/`).
/// Used to unwrap the `goog.script.init("...")` parameter — Apps Script
/// emits ASCII-only `\xNN` for every non-alphanumeric byte, so the
/// decoder doesn't need to handle full Unicode surrogates.
fn decode_js_string_escapes(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c != b'\\' {
            // Fast path: copy ASCII / valid UTF-8 byte through.
            out.push(c as char);
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            return None;
        }
        let esc = bytes[i + 1];
        match esc {
            b'x' => {
                if i + 3 >= bytes.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&bytes[i + 2..i + 4]).ok()?;
                let v = u8::from_str_radix(hex, 16).ok()?;
                out.push(v as char);
                i += 4;
            }
            b'u' => {
                if i + 5 >= bytes.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).ok()?;
                let v = u32::from_str_radix(hex, 16).ok()?;
                let ch = char::from_u32(v)?;
                out.push(ch);
                i += 6;
            }
            b'\\' => {
                out.push('\\');
                i += 2;
            }
            b'"' => {
                out.push('"');
                i += 2;
            }
            b'\'' => {
                out.push('\'');
                i += 2;
            }
            b'/' => {
                out.push('/');
                i += 2;
            }
            b'n' => {
                out.push('\n');
                i += 2;
            }
            b'r' => {
                out.push('\r');
                i += 2;
            }
            b't' => {
                out.push('\t');
                i += 2;
            }
            b'b' => {
                out.push('\x08');
                i += 2;
            }
            b'f' => {
                out.push('\x0c');
                i += 2;
            }
            _ => return None,
        }
    }
    Some(out)
}

#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub relay_calls: u64,
    pub relay_failures: u64,
    pub coalesced: u64,
    pub bytes_relayed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_bytes: usize,
    pub blacklisted_scripts: usize,
    pub total_scripts: usize,
    /// Relay calls attributed to the current Pacific Time day. Resets
    /// at 00:00 PT (midnight Pacific) — matches Apps Script's actual
    /// quota reset cadence (#230, #362). This is what-this-process-
    /// has-done today, not the Google-side bucket.
    pub today_calls: u64,
    /// Response bytes from relay calls attributed to the current PT day.
    pub today_bytes: u64,
    /// "YYYY-MM-DD" of the PT day `today_calls` / `today_bytes` refer
    /// to. Useful for cross-referencing against Google's dashboard,
    /// which is also PT-aligned.
    pub today_key: String,
    /// Seconds until the next 00:00 PT rollover. Convenient for the UI
    /// to render "Resets in Xh Ym" without importing time libraries.
    pub today_reset_secs: u64,
    /// Calls served by the HTTP/2 multiplexed transport, across all
    /// entry points (Apps-Script direct, exit-node outer call,
    /// full-mode tunnel single op, full-mode tunnel batch).
    ///
    /// Not comparable to `relay_calls` — that counter only sees the
    /// Apps-Script-direct path. To gauge h2 health, compute
    /// `h2_calls / (h2_calls + h2_fallbacks)`.
    pub h2_calls: u64,
    /// Calls that attempted h2 but had to fall back to h1 (per-call
    /// failures, open timeout, backoff, sticky ALPN refusal). Same
    /// all-entry-points scope as `h2_calls`.
    pub h2_fallbacks: u64,
    /// True when h2 is permanently off for this fronter (config kill
    /// switch set, or peer refused h2 during ALPN). All traffic on the
    /// h1 path.
    pub h2_disabled: bool,
    /// Successful upstream fetches by the SNI-rewrite forwarder
    /// (b3b9220 fast path — non-`/youtubei/` paths on
    /// `force_mitm_hosts`). Counted at upstream success, before the
    /// downstream write to the browser, so a client-disconnect during
    /// write still counts as "the path filter did upstream work."
    /// Useful for diagnosing whether the path filter is firing as
    /// expected; a near-zero ratio against `relay_calls` means the
    /// forwarder is inert and any reported regression is elsewhere.
    pub forwarder_calls: u64,
    /// Response bytes successfully fetched by the forwarder from the
    /// upstream. Same upstream-fetch-success semantic as
    /// `forwarder_calls`.
    pub forwarder_bytes: u64,
    /// Forwarder dispatch errors (connect failure, TLS error, read
    /// timeout, cap exceeded). Distinct from `relay_failures` —
    /// `relay_failures` counts request-level failures, this counts
    /// fast-path-only misses regardless of whether the relay-fallback
    /// then recovered the request. Combine the two to distinguish
    /// "fast path missed but request served" from "request failed
    /// end-to-end".
    pub forwarder_errors: u64,
}

impl StatsSnapshot {
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total as f64) * 100.0
        }
    }

    pub fn fmt_line(&self) -> String {
        // h2 segment is the success ratio across all transports
        // (h2_calls + h2_fallbacks). Showing "X/Y" against relay_calls
        // would mislead — relay_calls only counts the Apps-Script
        // direct path, while h2_calls also includes exit-node and
        // tunnel paths that bypass relay_uncoalesced.
        let h2_seg = if self.h2_disabled {
            " h2=off".to_string()
        } else {
            let total = self.h2_calls + self.h2_fallbacks;
            if total == 0 {
                String::new()
            } else {
                let pct = (self.h2_calls as f64 / total as f64) * 100.0;
                format!(" h2-success={}/{} ({:.0}%)", self.h2_calls, total, pct)
            }
        };
        // Forwarder segment is only emitted when the path filter has
        // actually fired — keeps the line clean for the typical
        // (non-AppsScript / no-pattern-hit) case. `err` is the
        // fast-path miss count (regardless of whether relay-fallback
        // recovered the request); `relay_failures` covers actual
        // end-to-end request failures.
        let fwd_seg = if self.forwarder_calls + self.forwarder_errors == 0 {
            String::new()
        } else {
            format!(
                " fwd={} ({}KB) err={}",
                self.forwarder_calls,
                self.forwarder_bytes / 1024,
                self.forwarder_errors,
            )
        };
        format!(
            "stats: relay={} ({}KB) failures={} coalesced={} cache={}/{} ({:.0}% hit, {}KB) scripts={}/{} active{}{}",
            self.relay_calls,
            self.bytes_relayed / 1024,
            self.relay_failures,
            self.coalesced,
            self.cache_hits,
            self.cache_hits + self.cache_misses,
            self.hit_rate(),
            self.cache_bytes / 1024,
            self.total_scripts - self.blacklisted_scripts,
            self.total_scripts,
            h2_seg,
            fwd_seg,
        )
    }

    /// Hand-rolled JSON serialization so the Android side can read the
    /// snapshot via JNI without pulling `serde_derive` through this struct.
    /// Field names match the Rust side verbatim so Kotlin can `JSONObject`
    /// parse them directly.
    pub fn to_json(&self) -> String {
        fn esc(s: &str) -> String {
            s.replace('\\', "\\\\").replace('"', "\\\"")
        }
        format!(
            r#"{{"relay_calls":{},"relay_failures":{},"coalesced":{},"bytes_relayed":{},"cache_hits":{},"cache_misses":{},"cache_bytes":{},"blacklisted_scripts":{},"total_scripts":{},"today_calls":{},"today_bytes":{},"today_key":"{}","today_reset_secs":{},"h2_calls":{},"h2_fallbacks":{},"h2_disabled":{},"forwarder_calls":{},"forwarder_bytes":{},"forwarder_errors":{}}}"#,
            self.relay_calls,
            self.relay_failures,
            self.coalesced,
            self.bytes_relayed,
            self.cache_hits,
            self.cache_misses,
            self.cache_bytes,
            self.blacklisted_scripts,
            self.total_scripts,
            self.today_calls,
            self.today_bytes,
            esc(&self.today_key),
            self.today_reset_secs,
            self.h2_calls,
            self.h2_fallbacks,
            self.h2_disabled,
            self.forwarder_calls,
            self.forwarder_bytes,
            self.forwarder_errors,
        )
    }
}

/// Decide whether a probe round-trip result indicates the SID has
/// recovered (and the blacklist entry should be cleared) or not.
///
/// * `Ok(_)` — Apps Script returned a healthy JSON envelope. The
///   deployment is reachable and the script ran without error.
///   **Healthy.**
/// * `Err(FronterError::Relay(msg))` where
///   [`classify_envelope_error`] returns `None` — Apps Script returned
///   an envelope error the classifier doesn't bucket as permanent
///   (`"Server not available"`, `"please try again"`, or any other
///   transient string). The script ID itself works; the inner script
///   hit a hiccup. **Healthy** (recovery intent — retry traffic can
///   safely target this SID again).
/// * `Err(FronterError::Relay(msg))` where the classifier returns
///   `Some(_)` — permanent failure. The caller (`do_relay_once_with`)
///   has already re-blacklisted the SID, so the captured `until` no
///   longer matches and the compare-and-swap in
///   [`DomainFronter::probe_one_sid`] will reject the clear anyway.
///   **Not healthy** (returned `false` for clarity).
/// * Any other `Err(_)` — transport / network / pool exhaustion /
///   non-`Relay` failure. **Not healthy**: a generic
///   `tokio::io::ErrorKind::ConnectionReset` says nothing about
///   whether the Apps Script deployment itself has recovered.
///
/// Pure function so the decision tree is unit-testable without
/// spinning up a relay endpoint.
fn probe_indicates_recovery(result: &Result<Vec<u8>, FronterError>) -> bool {
    match result {
        Ok(_) => true,
        Err(FronterError::Relay(msg)) => classify_envelope_error(msg).is_none(),
        Err(_) => false,
    }
}

/// Build the `Accept-Language` header value paired with
/// [`Config::apps_script_lang`]. `"en"` (the default) maps to the
/// browser-shaped `"en-US,en;q=0.9"` so the wire fingerprint stays
/// unchanged for the common case; any other validated BCP47-ish tag
/// (`"fr"`, `"zh-CN"`) becomes `"<tag>;q=0.9"`. Input is assumed to
/// have passed [`Config::apps_script_lang_resolved`] — no further
/// validation is performed here.
fn accept_language_for_lang(lang: &str) -> String {
    if lang == "en" || lang.is_empty() {
        "en-US,en;q=0.9".into()
    } else {
        format!("{};q=0.9", lang)
    }
}

fn should_blacklist(status: u16, body: &str) -> bool {
    if status == 429 || status == 403 {
        return true;
    }
    classify_envelope_error(body).is_some()
}

fn looks_like_quota_error(msg: &str) -> bool {
    matches!(classify_envelope_error(msg), Some(EnvelopeCategory::Quota))
}

/// Permanent-failure categories for an Apps Script envelope `"e"` field.
/// Mapped onto the script-blacklist by [`should_blacklist`] and by the
/// post-`parse_relay_json` map_err sites in [`do_relay_once_with`] /
/// [`fanout_relay_once`]. Transient envelope strings (`"Server not available"`,
/// `"please try again"`) and any other unrecognised content return `None`
/// from [`classify_envelope_error`] — those deployments are still working,
/// they just had a bad RPC, so the existing retry path handles them
/// without a blacklist entry.
///
/// Ported from upstream Python `_QUOTA_PATTERNS` / `_AUTH_PATTERNS` /
/// `_DEPLOY_PATTERNS` / `_ADMIN_PATTERNS` (commit 190e6fa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeCategory {
    /// Daily quota exhausted. Recovers at 00:00 Pacific Time.
    Quota,
    /// Apps Script claims the user isn't authorised — typically means
    /// the user revoked OAuth on the Apps Script project or Google
    /// pushed a forced re-auth. Recovery requires user action.
    Auth,
    /// Deployment ID is wrong / the deployment was deleted /
    /// the user accidentally deployed a fresh version. Permanent until
    /// the maintainer reconfigures `script_id`.
    Deploy,
    /// Workspace admin disabled `UrlFetchApp` for the user's domain /
    /// blocked the destination URL. Permanent without admin action.
    Admin,
}

impl EnvelopeCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Quota => "quota",
            Self::Auth => "auth",
            Self::Deploy => "deploy",
            Self::Admin => "admin",
        }
    }
}

/// Quota / rate-limit patterns. Lowercase, substring match.
///
/// English patterns target the canonical UrlFetchApp daily-quota strings
/// (`"Service invoked too many times for one day: urlfetch."`,
/// `"Daily limit exceeded"`); German entries cover the localized variants
/// some users have seen in production with German Google accounts.
/// `"urlfetch"` is included on its own because it appears in the
/// daily-quota message across all locales — Google never translates the
/// service identifier.
///
/// Patterns are deliberately specific phrases rather than single words.
/// Standalone tokens like `"exceeded"` / `"daily"` would also match
/// transient Apps Script errors such as
/// `"Exceeded maximum execution time"` (the per-invocation 6-min cap,
/// not a quota condition) and benign words in unrelated error text,
/// wrongly sidelining healthy scripts for the full cooldown.
const QUOTA_PATTERNS: &[&str] = &[
    "service invoked too many times",
    "invoked too many times",
    "too many times",
    "service invoked",
    "for one day",
    "per day",
    "daily limit",
    "quota exceeded",
    "quota",
    "rate limit",
    "limit exceeded",
    "bandwidth quota",
    "bandwidth exceeded",
    "too much upload bandwidth",
    "too much traffic",
    "transfer rate",
    "bandbreitenkontingent",
    "datenübertragungsrate",
    "urlfetch",
];

/// OAuth / authorization patterns. Triggered when Apps Script demands
/// re-consent or when Code.gs returns its own `unauthorized` response.
const AUTH_PATTERNS: &[&str] = &[
    "authorization is required",
    "unauthorized",
    "not authorized",
    "permission denied",
    "access denied",
];

/// Deployment-state patterns: wrong `script_id`, deleted deployment,
/// stale version reference. Apps Script surfaces these as
/// `"Error code Not_Found"` / `"missing library version or a deployment
/// version"`.
///
/// Deliberately phrase-level. Standalone `"deployment"` would match
/// transient messages such as `"deployment is being updated"`, sidelining
/// a healthy script for the full cooldown.
const DEPLOY_PATTERNS: &[&str] = &[
    "error code not_found",
    "not_found",
    "deployment version",
    "deployment id",
    "deployment not found",
    "missing library version",
    "script id",
    "scriptid",
    "no script",
];

/// Workspace-admin policy patterns: `UrlFetchApp` blocked / specific
/// destinations blocked / Apps Script disabled at the OU level.
const ADMIN_PATTERNS: &[&str] = &[
    "not permitted by your admin",
    "contact your administrator",
    "disabled. please contact",
    "domain policy has disabled",
    "administrator to enable",
];

/// Bucket an Apps Script envelope error string into a permanent-failure
/// category. Lowercases once and runs an ordered substring sweep —
/// quota first (most common, most specific), then auth, deploy, admin.
/// Returns `None` for transient envelopes (`"Server not available"`,
/// `"please try again"`) and any other unrecognised content so the
/// regular retry path handles them.
fn classify_envelope_error(msg: &str) -> Option<EnvelopeCategory> {
    let lower = msg.to_ascii_lowercase();
    if QUOTA_PATTERNS.iter().any(|p| lower.contains(p)) {
        return Some(EnvelopeCategory::Quota);
    }
    if AUTH_PATTERNS.iter().any(|p| lower.contains(p)) {
        return Some(EnvelopeCategory::Auth);
    }
    if DEPLOY_PATTERNS.iter().any(|p| lower.contains(p)) {
        return Some(EnvelopeCategory::Deploy);
    }
    if ADMIN_PATTERNS.iter().any(|p| lower.contains(p)) {
        return Some(EnvelopeCategory::Admin);
    }
    None
}

fn mask_script_id(id: &str) -> String {
    let n = id.chars().count();
    if n <= 8 {
        return "***".into();
    }
    let head: String = id.chars().take(4).collect();
    let tail: String = id.chars().skip(n - 4).collect();
    format!("{}...{}", head, tail)
}

fn value_to_header_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        _ => None,
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

pub fn error_response(status: u16, message: &str) -> Vec<u8> {
    let body = format!(
        "<html><body><h1>{}</h1><p>{}</p></body></html>",
        status,
        html_escape(message)
    );
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
        status,
        status_text(status),
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// Dangerous "accept anything" TLS verifier, used only when config.verify_ssl=false.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{duplex, AsyncRead, AsyncWriteExt, ReadBuf};

    // Test fixture for ungraceful TLS close: emit a fixed prefix of bytes
    // then return io::ErrorKind::UnexpectedEof on the next read. Mirrors
    // what rustls surfaces when the peer closes TCP without sending a
    // TLS close_notify alert (#585).
    struct UnexpectedEofAfter {
        bytes: Vec<u8>,
        position: usize,
    }

    impl AsyncRead for UnexpectedEofAfter {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.position >= self.bytes.len() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed connection without sending TLS close_notify",
                )));
            }
            let remaining = &self.bytes[self.position..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.position += take;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn read_http_response_tolerates_unexpected_eof_with_content_length() {
        // Issue #585 / v1.9.4 exit-node bug. Some peers (the deployed exit-node in
        // particular, certain Apps Script `Connection: close` paths) close
        // the TCP without TLS close_notify. Body should still be returned
        // when Content-Length is satisfied, even though the read after
        // the body closes ungracefully.
        let body = b"{\"ok\":true}";
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut full = header.into_bytes();
        full.extend_from_slice(body);
        let mut stream = UnexpectedEofAfter {
            bytes: full,
            position: 0,
        };

        let (status, _headers, got_body) = read_http_response(&mut stream)
            .await
            .expect("must succeed despite UnexpectedEof");
        assert_eq!(status, 200);
        assert_eq!(got_body, body);
    }

    #[tokio::test]
    async fn read_http_response_tolerates_unexpected_eof_no_framing() {
        // Same #585 fix, but for the no-framing branch (server didn't
        // send Content-Length or Transfer-Encoding). Read until peer
        // closes — UnexpectedEof should terminate the loop with the
        // body we accumulated so far, not bubble up as an error.
        let header = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        let body = b"hello world";
        let mut full = header.to_vec();
        full.extend_from_slice(body);
        let mut stream = UnexpectedEofAfter {
            bytes: full,
            position: 0,
        };

        let (status, _headers, got_body) = read_http_response(&mut stream)
            .await
            .expect("must succeed despite UnexpectedEof");
        assert_eq!(status, 200);
        assert_eq!(got_body, body);
    }

    /// Issue #1088. The tunnel batch path passes `batch_timeout` (default
    /// 30 s, configurable up to 300 s) to `read_http_response_with_header_timeout`
    /// so Apps Script cold starts in the 8-12 s range no longer trip a
    /// hardcoded 10 s cliff. A regression that re-introduces the old 10 s
    /// inner timeout — or that ignores the parameter entirely — would let
    /// cold-start batches fail in the field while passing every existing
    /// test. This locks the parameter down: headers arriving at virtual
    /// T=15 s must succeed when the caller asked for a 30 s budget.
    #[tokio::test(start_paused = true)]
    async fn read_http_response_respects_configured_header_timeout() {
        use tokio::io::AsyncWriteExt;

        let (mut client_side, mut server_side) = tokio::io::duplex(8192);
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

        tokio::spawn(async move {
            // Slow Apps Script edge: response doesn't start streaming
            // for 15 s. Under a 10 s budget this would be Timeout; under
            // the 30 s budget the caller passed it must succeed.
            tokio::time::sleep(Duration::from_secs(15)).await;
            server_side.write_all(response).await.unwrap();
        });

        let (status, _, body) =
            read_http_response_with_header_timeout(&mut client_side, Duration::from_secs(30))
                .await
                .expect("15 s response must succeed under 30 s header-read budget");
        assert_eq!(status, 200);
        assert!(body.is_empty());
    }

    /// The header-read deadline must be *total*, not reset on every read.
    /// Without this, a peer that drip-feeds one byte just under the
    /// per-read timeout keeps the loop alive forever and defeats the
    /// outer `batch_timeout` wiring — defeating the whole point of
    /// #1088's fix. This is the regression that would survive a naive
    /// revert to `timeout(d, stream.read(...))` inside the loop, because
    /// every individual read completes well under `d`. With the
    /// `timeout_at(deadline, ...)` form, total elapsed exceeds the
    /// deadline and we get `FronterError::Timeout`.
    #[tokio::test(start_paused = true)]
    async fn read_http_response_header_deadline_is_total_not_per_read() {
        use tokio::io::AsyncWriteExt;

        let (mut client_side, mut server_side) = tokio::io::duplex(8192);
        // Header block is 38 bytes; drip-feeding at 3 s/byte takes 114 s
        // total. Each individual read returns within 3 s — well under
        // the 10 s budget — so per-read semantics would NOT detect the
        // stall.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();

        tokio::spawn(async move {
            for byte in response {
                tokio::time::sleep(Duration::from_secs(3)).await;
                server_side.write_all(&[byte]).await.unwrap();
                server_side.flush().await.unwrap();
            }
        });

        let result =
            read_http_response_with_header_timeout(&mut client_side, Duration::from_secs(10)).await;
        assert!(
            matches!(result, Err(FronterError::Timeout)),
            "drip-feed slower than the total deadline must time out — \
             got {:?}",
            result.map(|(s, _, _)| s)
        );
    }

    #[tokio::test]
    async fn parse_exit_node_response_unwraps_exit_node_envelope() {
        // The exit-node path through Apps Script returns exit node's JSON
        // envelope as the response body. parse_exit_node_response must
        // unwrap it back into a raw HTTP/1.1 response so the MITM TLS
        // write-back path sees the same shape it gets from the regular
        // Apps Script relay.
        let envelope = br#"{"s":200,"h":{"content-type":"application/json","x-cf-cache":"DYNAMIC"},"b":"eyJtZXNzYWdlIjoiaGVsbG8ifQ=="}"#;
        let raw =
            parse_exit_node_response(envelope, false).expect("envelope unwrap should succeed");
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(raw_str.contains("content-type: application/json\r\n"));
        assert!(raw_str.contains("x-cf-cache: DYNAMIC\r\n"));
        assert!(raw_str.contains("Content-Length: 19\r\n"));
        // Body is `{"message":"hello"}` (19 bytes; the base64-decoded
        // contents of the b field).
        assert!(raw.ends_with(b"{\"message\":\"hello\"}"));
    }

    #[tokio::test]
    async fn parse_exit_node_response_surfaces_explicit_error() {
        // When the exit node returns `{e: "..."}` instead of the {s,h,b} shape,
        // surface that error message specifically rather than letting
        // it through as an unparseable 502 — the message string is what
        // tells the user what went wrong (placeholder PSK, bad URL,
        // unauthorized, etc.).
        let envelope = br#"{"e":"unauthorized"}"#;
        let err = parse_exit_node_response(envelope, false).expect_err("must surface error");
        let msg = format!("{}", err);
        assert!(msg.contains("unauthorized"), "got: {}", msg);
        assert!(msg.contains("exit node"), "got: {}", msg);
    }

    fn multi_deployment_fronter(ids: &[&str]) -> DomainFronter {
        let ids_json = serde_json::to_string(ids).unwrap();
        let json = format!(
            r#"{{
                "mode": "apps_script",
                "google_ip": "127.0.0.1",
                "front_domain": "www.google.com",
                "script_id": {ids_json},
                "auth_key": "test_auth_key",
                "listen_host": "127.0.0.1",
                "listen_port": 8085,
                "log_level": "info",
                "verify_ssl": true
            }}"#
        );
        let cfg: Config = serde_json::from_str(&json).unwrap();
        DomainFronter::new(&cfg).expect("test fronter must construct")
    }

    #[test]
    fn compute_slow_set_empty_when_below_min_deployments() {
        // 1-2 deployments → no stable median → always inert.
        let mut m = HashMap::new();
        m.insert("a".into(), 200.0);
        assert!(compute_slow_set(&m).is_empty());
        m.insert("b".into(), 10_000.0);
        assert!(
            compute_slow_set(&m).is_empty(),
            "2 deployments: even a 50× outlier must not trigger skip"
        );
    }

    #[test]
    fn compute_slow_set_empty_when_median_below_floor() {
        // 3 deployments, all under LATENCY_SKIP_MIN_MEDIAN_MS (500ms).
        // Even a 5× outlier within "everyone is fast" stays in rotation.
        let mut m = HashMap::new();
        m.insert("a".into(), 100.0);
        m.insert("b".into(), 150.0);
        m.insert("c".into(), 800.0);
        assert!(
            compute_slow_set(&m).is_empty(),
            "median 150ms < 500ms floor: skip must be inert"
        );
    }

    #[test]
    fn compute_slow_set_skips_outlier_above_threshold() {
        // 3 deployments, median 1000ms, one outlier at 3000ms (3× median).
        let mut m = HashMap::new();
        m.insert("fast".into(), 800.0);
        m.insert("median".into(), 1000.0);
        m.insert("slow".into(), 3000.0);
        let slow = compute_slow_set(&m);
        assert_eq!(slow.len(), 1);
        assert!(slow.contains("slow"));
    }

    #[test]
    fn compute_slow_set_keeps_outlier_within_threshold() {
        // Same shape but the "slow" one is only 1.8× median — under the
        // 2× threshold, so it stays in rotation.
        let mut m = HashMap::new();
        m.insert("a".into(), 800.0);
        m.insert("b".into(), 1000.0);
        m.insert("c".into(), 1800.0);
        assert!(
            compute_slow_set(&m).is_empty(),
            "1.8× median is below the 2× cutoff and must stay in rotation"
        );
    }

    #[test]
    fn compute_slow_set_skips_multiple_outliers() {
        // 5 deployments, two of them well above 2× median.
        let mut m = HashMap::new();
        m.insert("a".into(), 700.0);
        m.insert("b".into(), 900.0);
        m.insert("c".into(), 1000.0); // median
        m.insert("d".into(), 2500.0);
        m.insert("e".into(), 4000.0);
        let slow = compute_slow_set(&m);
        assert_eq!(slow.len(), 2);
        assert!(slow.contains("d"));
        assert!(slow.contains("e"));
    }

    #[test]
    fn record_batch_latency_folds_with_ewma_weight() {
        let fronter = multi_deployment_fronter(&["A", "B", "C"]);
        // First observation seeds the EWMA at exactly the sample.
        fronter.record_batch_latency("A", Duration::from_millis(1000));
        let snap = fronter.script_latency_snapshot();
        assert!(
            (snap["A"] - 1000.0).abs() < 0.001,
            "first sample seeds EWMA; got {}",
            snap["A"]
        );
        // Second observation folds with α = LATENCY_EWMA_ALPHA.
        // expected = α*2000 + (1-α)*1000 = 0.3*2000 + 0.7*1000 = 1300
        fronter.record_batch_latency("A", Duration::from_millis(2000));
        let snap = fronter.script_latency_snapshot();
        let expected = LATENCY_EWMA_ALPHA * 2000.0 + (1.0 - LATENCY_EWMA_ALPHA) * 1000.0;
        assert!(
            (snap["A"] - expected).abs() < 0.001,
            "EWMA fold mismatched: got {}, expected {}",
            snap["A"],
            expected
        );
        // Different deployments tracked independently.
        fronter.record_batch_latency("B", Duration::from_millis(500));
        let snap = fronter.script_latency_snapshot();
        assert!((snap["B"] - 500.0).abs() < 0.001);
        assert!((snap["A"] - expected).abs() < 0.001, "A unaffected by B");
    }

    #[test]
    fn hard_slow_successful_batch_cools_down_deployment_immediately() {
        let fronter = multi_deployment_fronter(&["FAST1", "FAST2", "SLOW"]);

        // Establish a normal baseline. A single 7s success would only
        // fold SLOW's EWMA to 3500ms (0.3*7000 + 0.7*2000), which is
        // below the relative 2x threshold when FAST* sit around 2s.
        // The hard-slow path should still remove SLOW immediately.
        fronter.record_batch_latency("FAST1", Duration::from_millis(2000));
        fronter.record_batch_latency("FAST2", Duration::from_millis(2000));
        fronter.record_batch_latency("SLOW", Duration::from_millis(2000));
        fronter.record_batch_latency("SLOW", Duration::from_millis(7000));

        let snap = fronter.script_latency_snapshot();
        assert!(
            !compute_slow_set(&snap).contains("SLOW"),
            "EWMA alone should still be too gentle here; snap={snap:?}"
        );

        let mut picks: Vec<String> = (0..30).map(|_| fronter.next_script_id()).collect();
        picks.sort();
        picks.dedup();
        assert_eq!(
            picks,
            vec!["FAST1".to_string(), "FAST2".to_string()],
            "hard-slow successful batch should temporarily skip SLOW"
        );
    }

    #[test]
    fn next_script_id_skips_slow_deployment_when_others_healthy() {
        let fronter = multi_deployment_fronter(&["FAST1", "FAST2", "SLOW"]);
        // FAST* steady-state must clear `LATENCY_SKIP_MIN_MEDIAN_MS`
        // (500ms) for the skip logic to engage at all — below that
        // floor the rule is intentionally inert. SLOW at 5× the
        // median sits well over the 2× threshold.
        for _ in 0..5 {
            fronter.record_batch_latency("FAST1", Duration::from_millis(800));
            fronter.record_batch_latency("FAST2", Duration::from_millis(800));
            fronter.record_batch_latency("SLOW", Duration::from_millis(4000));
        }
        // Drive the round-robin for several picks; SLOW must never come up.
        let mut picks: Vec<String> = (0..30).map(|_| fronter.next_script_id()).collect();
        picks.sort();
        picks.dedup();
        assert_eq!(
            picks,
            vec!["FAST1".to_string(), "FAST2".to_string()],
            "SLOW should be excluded from round-robin while FAST* are available"
        );
    }

    #[test]
    fn next_script_id_does_not_skip_when_median_below_floor() {
        // Companion test pinning the floor behavior: when all
        // deployments are sub-500ms, even a 10× outlier stays in
        // rotation. Prevents the skip from kicking in on a fast
        // network where the "slow" deployment is still plenty fast
        // in absolute terms.
        let fronter = multi_deployment_fronter(&["A", "B", "FAST_BUT_OUTLIER"]);
        for _ in 0..5 {
            fronter.record_batch_latency("A", Duration::from_millis(30));
            fronter.record_batch_latency("B", Duration::from_millis(30));
            fronter.record_batch_latency("FAST_BUT_OUTLIER", Duration::from_millis(300));
        }
        let mut picks: Vec<String> = (0..30).map(|_| fronter.next_script_id()).collect();
        picks.sort();
        picks.dedup();
        assert_eq!(
            picks,
            vec![
                "A".to_string(),
                "B".to_string(),
                "FAST_BUT_OUTLIER".to_string()
            ],
            "median 30ms is below 500ms floor — all three must stay in rotation"
        );
    }

    #[test]
    fn fresh_latency_snapshot_filters_stale_entries() {
        let now = Instant::now();
        let fresh = Duration::from_secs(30);
        let mut map = HashMap::new();
        map.insert("FRESH".into(), (1000.0, now - Duration::from_secs(5)));
        map.insert("STALE".into(), (5000.0, now - Duration::from_secs(60)));
        map.insert("EDGE_KEEP".into(), (1500.0, now - Duration::from_secs(29)));
        // Strictly-less-than guards the boundary: a 30s-old entry is
        // already stale, only entries newer than 30s survive.
        map.insert("EDGE_DROP".into(), (2000.0, now - Duration::from_secs(30)));

        let snap = fresh_latency_snapshot(&map, now, fresh);

        assert!(snap.contains_key("FRESH"));
        assert!(snap.contains_key("EDGE_KEEP"));
        assert!(!snap.contains_key("STALE"));
        assert!(!snap.contains_key("EDGE_DROP"));
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn slow_deployment_recovers_when_sample_expires() {
        // Integration: deployment scored as slow with FRESH samples is
        // skipped; once those samples age past LATENCY_FRESH_FOR_SECS,
        // the slow_set snapshot drops them and the selector lets the
        // deployment back into rotation. This is the recovery path
        // that prevents a transient slow minute from being a permanent
        // ban. We poke the private map directly to inject samples with
        // controlled timestamps — `std::time::Instant` doesn't compose
        // with tokio's paused time and we don't want to actually sleep
        // 30 s in a unit test.
        let fronter = multi_deployment_fronter(&["A", "B", "SLOW"]);
        let now = Instant::now();
        let fresh_age = Duration::from_secs(5);
        let stale_age = Duration::from_secs(LATENCY_FRESH_FOR_SECS + 5);
        // Step 1: fresh slow sample — SLOW must be skipped.
        {
            let mut map = fronter.script_latency_ewma.lock().unwrap();
            map.insert("A".into(), (800.0, now - fresh_age));
            map.insert("B".into(), (800.0, now - fresh_age));
            map.insert("SLOW".into(), (4000.0, now - fresh_age));
        }
        assert!(
            compute_slow_set(&fronter.script_latency_snapshot()).contains("SLOW"),
            "step 1: fresh SLOW sample must put it in the slow_set"
        );
        // Step 2: replace SLOW's timestamp with a stale one.
        // A's and B's stay fresh.
        {
            let mut map = fronter.script_latency_ewma.lock().unwrap();
            map.insert("SLOW".into(), (4000.0, now - stale_age));
        }
        let snap = fronter.script_latency_snapshot();
        assert!(
            !snap.contains_key("SLOW"),
            "step 2: stale SLOW sample must not appear in the snapshot — got {snap:?}"
        );
        // With SLOW absent from the snapshot, only A and B count for
        // the median, and there's no entry above 2× median → slow_set
        // is empty.
        assert!(compute_slow_set(&snap).is_empty());
        // The selector should now reach SLOW too on pass 1 (no longer
        // in slow_set), so over a sufficient number of picks all
        // three must appear.
        let mut picks: Vec<String> = (0..30).map(|_| fronter.next_script_id()).collect();
        picks.sort();
        picks.dedup();
        assert_eq!(
            picks,
            vec!["A".to_string(), "B".to_string(), "SLOW".to_string()],
            "step 2: SLOW should be back in rotation after sample expiry"
        );
    }

    #[test]
    fn next_script_id_falls_back_when_only_slow_deployment_is_left() {
        // 3 deployments, two blacklisted, the only remaining one is
        // the slow one. The selector must still return it (the
        // relaxed-guard pass 2) rather than fall through to the
        // all-blacklisted fallback. Latencies must clear
        // `LATENCY_SKIP_MIN_MEDIAN_MS` (500 ms) — otherwise
        // compute_slow_set returns empty and this test would pass for
        // the wrong reason (pass 1 picks SLOW directly, never
        // exercising the relaxed pass).
        let fronter = multi_deployment_fronter(&["A", "B", "SLOW"]);
        for _ in 0..5 {
            fronter.record_batch_latency("A", Duration::from_millis(800));
            fronter.record_batch_latency("B", Duration::from_millis(800));
            fronter.record_batch_latency("SLOW", Duration::from_millis(4000));
        }
        // Pre-condition: SLOW must actually be in the slow_set so we
        // know this test exercises the relaxed-pass code path.
        assert!(
            compute_slow_set(&fronter.script_latency_snapshot()).contains("SLOW"),
            "test pre-condition: SLOW must be in slow_set"
        );
        fronter.blacklist_script("A", "test");
        fronter.blacklist_script("B", "test");
        assert_eq!(fronter.next_script_id(), "SLOW");
    }

    #[test]
    fn parse_exit_node_response_strips_stale_content_encoding() {
        // The exit-node's fetch() auto-decompresses gzip/br/deflate response
        // bodies, so the destination's Content-Encoding header is stale by
        // the time it reaches us. Forwarding it to the browser as-is is
        // exactly what ERR_CONTENT_DECODING_FAILED is — the browser tries
        // to decompress already-plain bytes. The skip list in
        // parse_exit_node_response must scrub `content-encoding` from `h`
        // before synthesising the HTTP response.
        let envelope =
            br#"{"s":200,"h":{"content-type":"text/html","content-encoding":"br","x-served-by":"edge-1"},"b":"PGgxPmhpPC9oMT4="}"#;
        let raw = parse_exit_node_response(envelope, false)
            .expect("envelope unwrap should succeed even with stale content-encoding");
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(raw_str.contains("content-type: text/html\r\n"));
        // Non-skipped headers pass through.
        assert!(raw_str.contains("x-served-by: edge-1\r\n"));
        // Stale Content-Encoding must be stripped (case-insensitive).
        assert!(
            !raw_str.to_ascii_lowercase().contains("content-encoding"),
            "Content-Encoding header should be stripped, got: {}",
            raw_str
        );
        // Body is `<h1>hi</h1>` (11 bytes; base64-decoded from the b field).
        assert!(raw.ends_with(b"<h1>hi</h1>"));
        assert!(raw_str.contains("Content-Length: 11\r\n"));
    }

    #[test]
    fn parse_exit_node_response_detects_pre_v202_double_wrap() {
        // Upstream issue #1239 symptom: client is v2.0.2+ but Apps Script
        // is running an old Code.gs that doesn't honour `raw: true`, so it
        // re-wraps the exit-node JSON envelope inside its own {s, h, b}.
        // After one layer of unwrapping, the decoded `b` is *itself* an
        // envelope. Without detection, parse_exit_node_response would
        // hand that inner envelope to the browser as page content; with
        // detection we surface a specific error telling the user to
        // redeploy Code.gs.
        let inner_envelope =
            br#"{"s":200,"h":{"content-type":"text/html"},"b":"PGgxPmhpPC9oMT4="}"#;
        let inner_b64 = B64.encode(inner_envelope);
        let outer = format!(
            r#"{{"s":200,"h":{{"content-type":"application/json"}},"b":"{}"}}"#,
            inner_b64
        );
        let err = parse_exit_node_response(outer.as_bytes(), false)
            .expect_err("double-wrap must be detected");
        let msg = format!("{}", err);
        assert!(
            msg.contains("double-wrapped") && msg.contains("Code.gs") && msg.contains("worker.js"),
            "error must name both redeploy targets, got: {}",
            msg
        );
    }

    #[test]
    fn parse_exit_node_response_does_not_misdetect_json_api_response() {
        // The detector must require all three envelope fields (s number,
        // h object, b string). A destination that legitimately returns
        // JSON with only some matching keys (e.g. an API returning
        // `{"s":"ok"}`) must not trip the double-wrap check.
        let api_body = br#"{"s":"ok","message":"hello"}"#;
        let api_b64 = B64.encode(api_body);
        let envelope = format!(
            r#"{{"s":200,"h":{{"content-type":"application/json"}},"b":"{}"}}"#,
            api_b64
        );
        let raw = parse_exit_node_response(envelope.as_bytes(), false)
            .expect("non-envelope JSON body must pass through unchanged");
        assert!(raw.ends_with(api_body));
    }

    #[test]
    fn parse_exit_node_response_decodes_zstd_body_when_flag_on() {
        // Regression guard for the dropped-decode bug: when the user
        // has opted in to brotli/zstd, the inner-request filter
        // forwards `Accept-Encoding: zstd` to destinations through
        // the exit-node. fetch-based exit-node runtimes (Deno
        // Deploy, Cloudflare Workers, Node) auto-decompress gzip
        // and brotli but NOT zstd — so a zstd response from the
        // destination reaches us as raw zstd bytes with
        // `Content-Encoding: zstd` intact. The historical "always
        // strip content-encoding" code would then deliver raw zstd
        // to the browser as plaintext, corrupting the page.
        //
        // With the flag on, parse_exit_node_response must decode
        // the zstd body and strip the now-stale Content-Encoding
        // header — same decode-or-preserve policy parse_relay_json
        // uses.
        //
        // Fixture: a minimal zstd frame for "hello zstd"
        // (round-tripped through decode_zstd_roundtrip's fixture).
        let frame = B64
            .decode("KLUv/SAKUQAAaGVsbG8genN0ZA==")
            .expect("known-good zstd frame base64");
        let b64 = B64.encode(&frame);
        let envelope = format!(
            r#"{{"s":200,"h":{{"content-type":"text/plain","content-encoding":"zstd"}},"b":"{}"}}"#,
            b64
        );
        let raw = parse_exit_node_response(envelope.as_bytes(), true)
            .expect("exit-node envelope unwrap should decode zstd when flag is on");
        let raw_str = String::from_utf8_lossy(&raw);
        // Body must be the decoded plain text.
        assert!(raw_str.ends_with("hello zstd"), "got: {}", raw_str);
        // Stale content-encoding must be stripped after successful
        // decode (so the browser doesn't try to decode plaintext
        // and fail).
        assert!(
            !raw_str.to_ascii_lowercase().contains("content-encoding"),
            "content-encoding must be stripped after exit-node zstd decode, got: {}",
            raw_str
        );
    }

    #[test]
    fn parse_exit_node_response_preserves_zstd_header_when_flag_off() {
        // Symmetric negative test: with the flag OFF, the inner
        // request filter strips br/zstd from outbound
        // Accept-Encoding, so destinations shouldn't return zstd in
        // the first place. But if one slips through (or future
        // exit-node runtime behaviour changes), the legacy "always
        // strip" branch must not silently corrupt the body. The
        // flag-off branch matches the historical pre-v2.1 behaviour
        // (assume runtime decoded, strip header) — this test pins
        // it so a refactor of the decode-or-preserve policy doesn't
        // accidentally drift the legacy path.
        let envelope = br#"{"s":200,"h":{"content-encoding":"zstd"},"b":"PGgxPmhpPC9oMT4="}"#;
        let raw = parse_exit_node_response(envelope, false)
            .expect("legacy mode must not error on zstd header");
        let raw_str = String::from_utf8_lossy(&raw);
        // Legacy: header stripped, body passed through (raw bytes).
        // This is the historical behaviour the comment block above
        // the new logic preserves.
        assert!(
            !raw_str.to_ascii_lowercase().contains("content-encoding"),
            "legacy mode strips content-encoding unconditionally"
        );
    }

    #[test]
    fn parse_exit_node_response_tolerates_leading_http_framing() {
        // Defensive: if h2_round_trip / read_http_response ever hands back
        // bytes that include an HTTP status line + headers before the JSON
        // envelope (e.g. a misconfigured intermediary), parse_exit_node_response
        // must skip past the `\r\n\r\n` separator and parse the envelope
        // anyway rather than failing with "not valid JSON".
        let prefixed = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
            {\"s\":200,\"h\":{\"content-type\":\"application/json\"},\"b\":\"eyJvayI6dHJ1ZX0=\"}";
        let raw = parse_exit_node_response(prefixed, false)
            .expect("envelope unwrap should tolerate a leading HTTP framing prefix");
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.starts_with("HTTP/1.1 200 OK\r\n"));
        // Body is `{"ok":true}` (11 bytes).
        assert!(raw.ends_with(b"{\"ok\":true}"));
    }

    #[test]
    fn relay_request_serialization_omits_raw_by_default() {
        // The `raw` flag is wire-additive — it must NOT appear in serialized
        // payloads when unset, so non-exit-node relays against deployments
        // that don't know about `raw` see the same wire shape as before.
        // Pre-v2.0.2 Apps Script/Worker deployments parsing this JSON would
        // ignore an unknown `raw` field anyway, but adding bytes that don't
        // exist in the old contract changes the random-padding budget and
        // is wasteful — `skip_serializing_if` is the right call.
        let regular = RelayRequest {
            k: "secret",
            m: "GET",
            u: "https://example.com/",
            h: None,
            b: None,
            ct: None,
            r: true,
            raw: None,
        };
        let json = serde_json::to_string(&regular).expect("serialize regular");
        assert!(
            !json.contains("\"raw\""),
            "raw must be absent when None, got: {}",
            json
        );

        // And when explicitly set, it serializes as `"raw":true` so the
        // splice in relay_via_exit_node lands on the correct wire field.
        let exit_outer = RelayRequest {
            k: "secret",
            m: "POST",
            u: "https://exit.example.com/",
            h: None,
            b: None,
            ct: None,
            r: true,
            raw: Some(true),
        };
        let json = serde_json::to_string(&exit_outer).expect("serialize exit_outer");
        assert!(
            json.contains("\"raw\":true"),
            "raw:true must appear when Some(true), got: {}",
            json
        );
    }

    #[test]
    fn unix_to_ymd_utc_handles_known_epochs() {
        // Anchors chosen to catch the common off-by-one errors (pre/post
        // leap day, pre/post epoch, year-end rollover).
        assert_eq!(unix_to_ymd_utc(0), (1970, 1, 1)); // epoch
        assert_eq!(unix_to_ymd_utc(86_399), (1970, 1, 1)); // one sec before day 2
        assert_eq!(unix_to_ymd_utc(86_400), (1970, 1, 2)); // day 2 starts at midnight
        assert_eq!(unix_to_ymd_utc(951_782_400), (2000, 2, 29)); // leap day (Feb 29, 2000)
        assert_eq!(unix_to_ymd_utc(951_868_800), (2000, 3, 1)); // day after leap Feb
        assert_eq!(unix_to_ymd_utc(1_583_020_800), (2020, 3, 1)); // day after a leap Feb
        assert_eq!(unix_to_ymd_utc(1_735_689_599), (2024, 12, 31)); // last sec of 2024
        assert_eq!(unix_to_ymd_utc(1_735_689_600), (2025, 1, 1)); // first sec of 2025
    }

    #[test]
    fn seconds_until_pacific_midnight_is_bounded() {
        let n = seconds_until_pacific_midnight();
        // Must be in (0, 86400] for any valid system clock.
        assert!(n > 0 && n <= 86_400);
    }

    #[test]
    fn nth_sunday_of_month_anchors() {
        // Spot-check Sakamoto's day-of-week + offset arithmetic against
        // a few known Sundays. Mistakes here would silently shift the
        // DST transition by ±1 week.
        // March 2026: 2nd Sunday is March 8 (Sun Mar 1, Sun Mar 8).
        assert_eq!(nth_sunday_of_month(2026, 3, 2), 8);
        // November 2026: 1st Sunday is November 1 (Sun Nov 1).
        assert_eq!(nth_sunday_of_month(2026, 11, 1), 1);
        // March 2024: 2nd Sunday is March 10 (Sun Mar 3, Sun Mar 10).
        assert_eq!(nth_sunday_of_month(2024, 3, 2), 10);
        // November 2024: 1st Sunday is November 3.
        assert_eq!(nth_sunday_of_month(2024, 11, 1), 3);
        // March 2027: 2nd Sunday is March 14.
        assert_eq!(nth_sunday_of_month(2027, 3, 2), 14);
    }

    #[test]
    fn pacific_dst_window_anchors() {
        // Outside the DST window: PST.
        assert!(!pacific_is_dst(2026, 1, 15));
        assert!(!pacific_is_dst(2026, 12, 25));
        assert!(!pacific_is_dst(2026, 2, 28));
        assert!(!pacific_is_dst(2026, 11, 5)); // first Sun of Nov 2026 = Nov 1; Nov 5 is past
                                               // Inside: PDT.
        assert!(pacific_is_dst(2026, 6, 1));
        assert!(pacific_is_dst(2026, 9, 30));
        // Boundary: March 8, 2026 (DST start day) and after = PDT.
        assert!(!pacific_is_dst(2026, 3, 7));
        assert!(pacific_is_dst(2026, 3, 8));
        // Boundary: Oct 31 = PDT, Nov 1 = first Sunday = PST flips on.
        assert!(pacific_is_dst(2026, 10, 31));
        assert!(!pacific_is_dst(2026, 11, 1));
    }

    #[test]
    fn filter_forwarded_headers_strips_identity_revealing_headers() {
        // Issue #104: any proxy/extension that inserts these must not
        // leak the client's real IP to origin via the Apps Script relay.
        let input: Vec<(String, String)> = vec![
            ("X-Forwarded-For".into(), "203.0.113.42".into()),
            ("X-Real-IP".into(), "203.0.113.42".into()),
            ("Forwarded".into(), "for=203.0.113.42".into()),
            ("Via".into(), "1.1 squid".into()),
            ("CF-Connecting-IP".into(), "203.0.113.42".into()),
            ("True-Client-IP".into(), "203.0.113.42".into()),
            ("X-Client-IP".into(), "203.0.113.42".into()),
            ("Fastly-Client-IP".into(), "203.0.113.42".into()),
            ("X-Cluster-Client-IP".into(), "203.0.113.42".into()),
            ("Client-IP".into(), "203.0.113.42".into()),
            ("X-Originating-IP".into(), "203.0.113.42".into()),
            ("X-Forwarded-Host".into(), "internal.example".into()),
            ("X-Forwarded-Proto".into(), "https".into()),
            ("X-Forwarded-Port".into(), "8080".into()),
            ("X-Forwarded-Server".into(), "lb-01.example".into()),
            ("X-Forwarded-Ssl".into(), "on".into()),
            // Mix in a legitimate header that MUST pass through.
            ("User-Agent".into(), "Mozilla/5.0".into()),
            ("Accept".into(), "text/html".into()),
        ];
        // Use the back-compat single-arg facade — this test pins the
        // behaviour external callers see at that signature.
        let out = filter_forwarded_headers(&input);
        let keys: Vec<String> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        // All identity-revealing headers must be dropped.
        for h in [
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "via",
            "cf-connecting-ip",
            "true-client-ip",
            "x-client-ip",
            "fastly-client-ip",
            "x-cluster-client-ip",
            "client-ip",
            "x-originating-ip",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-forwarded-ssl",
        ] {
            assert!(!keys.iter().any(|k| k == h), "{} must be stripped", h);
        }
        // And legitimate headers must survive.
        assert!(keys.iter().any(|k| k == "user-agent"));
        assert!(keys.iter().any(|k| k == "accept"));
    }

    #[test]
    fn normalize_x_graphql_trims_after_variables() {
        // Real-looking x.com GraphQL URL with variables + features +
        // fieldToggles. Only the variables= prefix should survive.
        let in_url = "https://x.com/i/api/graphql/abcd1234/TweetDetail?variables=%7B%22focalTweetId%22%3A%221234%22%7D&features=%7B%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D&fieldToggles=%7B%22withArticleRichContentState%22%3Atrue%7D";
        let out = normalize_x_graphql_url(in_url);
        assert!(out.starts_with("https://x.com/i/api/graphql/abcd1234/TweetDetail?variables="));
        assert!(!out.contains("features="));
        assert!(!out.contains("fieldToggles="));
        assert!(!out.contains('&'));
    }

    #[test]
    fn normalize_x_graphql_leaves_non_x_hosts_alone() {
        let cases = [
            "https://twitter.com/i/api/graphql/x/y?variables=z&features=q",
            "https://x.co/i/api/graphql/x/y?variables=z&features=q",
            "https://api.x.com/i/api/graphql/x/y?variables=z&features=q",
            "https://example.com/?variables=1&other=2",
        ];
        for u in cases {
            assert_eq!(normalize_x_graphql_url(u), u, "should pass through: {}", u);
        }
    }

    #[test]
    fn normalize_x_graphql_leaves_non_graphql_paths_alone() {
        let cases = [
            "https://x.com/home",
            "https://x.com/i/api/2/notifications/view/generic.json",
            "https://x.com/i/api/graphql/x/y", // no query
            "https://x.com/i/api/graphql/x/y?features=1&variables=2", // variables not first
        ];
        for u in cases {
            assert_eq!(normalize_x_graphql_url(u), u, "should pass through: {}", u);
        }
    }

    #[test]
    fn normalize_x_graphql_is_idempotent() {
        let once = normalize_x_graphql_url(
            "https://x.com/i/api/graphql/H/Op?variables=%7B%7D&features=%7B%7D",
        );
        let twice = normalize_x_graphql_url(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn extract_host_strips_scheme_port_path() {
        assert_eq!(
            extract_host("https://example.com/foo"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host("http://foo.bar:8080/x"),
            Some("foo.bar".into())
        );
        assert_eq!(
            extract_host("https://user:pw@host.test/x"),
            Some("host.test".into())
        );
        assert_eq!(
            extract_host("https://[2001:db8::1]:443/"),
            Some("2001:db8::1".into())
        );
        assert_eq!(extract_host("API.X.com/foo"), Some("api.x.com".into()));
        assert_eq!(extract_host(""), None);
    }

    #[test]
    fn build_sni_pool_extends_for_google() {
        let p = build_sni_pool("www.google.com");
        assert!(p.len() >= 2);
        assert_eq!(p[0], "www.google.com");
        assert!(p.iter().any(|s| s == "mail.google.com"));
    }

    #[test]
    fn build_sni_pool_preserves_custom_primary() {
        let p = build_sni_pool("mycustom.edge.example.com");
        assert_eq!(p, vec!["mycustom.edge.example.com".to_string()]);
    }

    #[test]
    fn filter_drops_connection_specific() {
        let h = vec![
            ("Host".into(), "example.com".into()),
            ("Connection".into(), "keep-alive".into()),
            ("Content-Length".into(), "5".into()),
            ("Cookie".into(), "a=b".into()),
            ("Proxy-Connection".into(), "close".into()),
        ];
        let out = filter_forwarded_headers(&h);
        let names: Vec<_> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        assert!(names.contains(&"cookie".to_string()));
        assert!(!names.contains(&"host".to_string()));
        assert!(!names.contains(&"connection".to_string()));
        assert!(!names.contains(&"content-length".to_string()));
        assert!(!names.contains(&"proxy-connection".to_string()));
    }

    #[test]
    fn strip_brotli_keeps_gzip() {
        let r = strip_brotli_from_accept_encoding("gzip, deflate, br");
        assert_eq!(r, "gzip, deflate");
        let r = strip_brotli_from_accept_encoding("br");
        assert_eq!(r, "");
        let r = strip_brotli_from_accept_encoding("gzip;q=1.0, br;q=0.5");
        assert_eq!(r, "gzip;q=1.0");
    }

    #[test]
    fn filter_forwarded_headers_strips_brotli_when_flag_off() {
        let input = vec![(
            "Accept-Encoding".to_string(),
            "gzip, deflate, br, zstd".to_string(),
        )];
        let out = filter_forwarded_headers_with_brotli_zstd(&input, false);
        let ae = out
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
            .expect("accept-encoding should survive the filter");
        assert_eq!(ae.1, "gzip, deflate");
    }

    #[test]
    fn filter_forwarded_headers_preserves_brotli_when_flag_on() {
        let input = vec![(
            "Accept-Encoding".to_string(),
            "gzip, deflate, br, zstd".to_string(),
        )];
        let out = filter_forwarded_headers_with_brotli_zstd(&input, true);
        let ae = out
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
            .expect("accept-encoding should survive the filter");
        assert_eq!(ae.1, "gzip, deflate, br, zstd");
    }

    #[test]
    fn decode_brotli_roundtrip() {
        use brotli::enc::BrotliEncoderParams;
        let plain = b"hello brotli world hello brotli world";
        let mut encoded = Vec::new();
        let params = BrotliEncoderParams::default();
        brotli::BrotliCompress(&mut &plain[..], &mut encoded, &params)
            .expect("brotli encode for test");
        let decoded = decode_brotli(&encoded).expect("brotli decode");
        assert_eq!(decoded, plain);
    }

    #[test]
    fn parse_relay_json_decodes_brotli_body_when_flag_on() {
        use brotli::enc::BrotliEncoderParams;
        let plain = b"<h1>hi from brotli</h1>";
        let mut encoded = Vec::new();
        brotli::BrotliCompress(
            &mut &plain[..],
            &mut encoded,
            &BrotliEncoderParams::default(),
        )
        .expect("brotli encode for test");
        let b64 = B64.encode(&encoded);
        let body = format!(
            r#"{{"s":200,"h":{{"content-type":"text/html","content-encoding":"br"}},"b":"{}"}}"#,
            b64
        );
        let raw = parse_relay_json(body.as_bytes(), true).unwrap();
        let s = String::from_utf8_lossy(&raw);
        // Decoded body must reach the client.
        assert!(s.ends_with("<h1>hi from brotli</h1>"));
        // Content-Encoding is stripped on forward — see SKIP in parse_relay_json.
        assert!(
            !s.to_ascii_lowercase().contains("content-encoding"),
            "content-encoding must be stripped after decode, got: {}",
            s
        );
    }

    #[test]
    fn parse_relay_json_leaves_brotli_body_when_flag_off() {
        // With the flag off, a br body that somehow arrives gets
        // delivered verbatim AND `Content-Encoding: br` is preserved
        // on the way out so the browser can try its own decoder
        // (instead of seeing a stripped header + raw brotli bytes,
        // which would silently corrupt the page). Different from the
        // pre-feature behaviour where content-encoding was always
        // stripped — that was only correct under the strip-policy
        // assumption that no br/zstd ever reached the relay.
        use brotli::enc::BrotliEncoderParams;
        let plain = b"<h1>raw brotli bytes</h1>";
        let mut encoded = Vec::new();
        brotli::BrotliCompress(
            &mut &plain[..],
            &mut encoded,
            &BrotliEncoderParams::default(),
        )
        .expect("brotli encode for test");
        let b64 = B64.encode(&encoded);
        let body = format!(
            r#"{{"s":200,"h":{{"content-encoding":"br"}},"b":"{}"}}"#,
            b64
        );
        let raw = parse_relay_json(body.as_bytes(), false).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(
            s.to_ascii_lowercase().contains("content-encoding: br"),
            "content-encoding must be preserved when we cannot decode, got: {}",
            s
        );
        let sep = b"\r\n\r\n";
        let sep_pos = raw.windows(4).position(|w| w == sep).expect("crlfcrlf");
        let body_bytes = &raw[sep_pos + 4..];
        assert_eq!(body_bytes, encoded.as_slice());
    }

    #[test]
    fn parse_relay_json_strips_gzip_content_encoding() {
        // Apps Script's UrlFetchApp auto-decodes gzip server-side, so
        // a body with `Content-Encoding: gzip` reaching us is already
        // plaintext. The header must be stripped on forward —
        // otherwise the browser retries decompression on plaintext
        // and fails with ERR_CONTENT_DECODING_FAILED. Regression
        // guard against the multi-token refactor.
        let body =
            r#"{"s":200,"h":{"content-encoding":"gzip","content-type":"text/plain"},"b":"aGk="}"#;
        let raw = parse_relay_json(body.as_bytes(), false).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(
            !s.to_ascii_lowercase().contains("content-encoding"),
            "gzip content-encoding must be stripped (AS auto-decoded), got: {}",
            s
        );
        assert!(s.ends_with("hi"));
    }

    #[test]
    fn parse_relay_json_preserves_unknown_encoding() {
        // Unknown single-token encoding (here: `deflate`, which Apps
        // Script does NOT auto-decode) should leave the header AND
        // the body untouched. Letting it through preserves the
        // browser's chance to decode; stripping the header would
        // corrupt the page silently.
        let plain = b"raw deflate bytes";
        let b64 = B64.encode(plain);
        let body = format!(
            r#"{{"s":200,"h":{{"content-encoding":"deflate"}},"b":"{}"}}"#,
            b64
        );
        let raw = parse_relay_json(body.as_bytes(), true).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(
            s.to_ascii_lowercase().contains("content-encoding: deflate"),
            "unknown encoding must be preserved, got: {}",
            s
        );
    }

    #[test]
    fn parse_relay_json_preserves_multi_token_encoding_chain() {
        // `gzip, br` is ambiguous: we don't know which layer Apps
        // Script peeled. Refuse to decode either way and pass the
        // header through.
        let body = r#"{"s":200,"h":{"content-encoding":"gzip, br"},"b":"aGk="}"#;
        let raw = parse_relay_json(body.as_bytes(), true).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(
            s.to_ascii_lowercase().contains("content-encoding"),
            "multi-token encoding chain must be preserved, got: {}",
            s
        );
    }

    #[test]
    fn decode_zstd_roundtrip() {
        // Hand-build a minimal zstd frame by round-tripping through
        // the brotli/zstd test data the `ruzstd` crate ships — we
        // don't have a Rust-only encoder to use here. Skipping the
        // round-trip encode and instead using a small known-good
        // zstd-compressed blob, encoded once with the `zstd` CLI:
        // `printf 'hello zstd' | zstd -c | base64`.
        // Frame for "hello zstd" (10 bytes).
        let frame = B64
            .decode("KLUv/SAKUQAAaGVsbG8genN0ZA==")
            .expect("known-good zstd frame base64");
        let decoded = decode_zstd(&frame).expect("zstd decode");
        assert_eq!(decoded, b"hello zstd");
    }

    #[test]
    fn parse_relay_json_decodes_zstd_body_when_flag_on() {
        // Same fixture as decode_zstd_roundtrip above, threaded
        // through parse_relay_json so we exercise the integration
        // path (header detect, decode, content-encoding strip).
        let frame = B64
            .decode("KLUv/SAKUQAAaGVsbG8genN0ZA==")
            .expect("known-good zstd frame base64");
        let b64 = B64.encode(&frame);
        let body = format!(
            r#"{{"s":200,"h":{{"content-encoding":"zstd","content-type":"text/plain"}},"b":"{}"}}"#,
            b64
        );
        let raw = parse_relay_json(body.as_bytes(), true).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.ends_with("hello zstd"));
        assert!(
            !s.to_ascii_lowercase().contains("content-encoding"),
            "zstd content-encoding must be stripped after decode, got: {}",
            s
        );
    }

    #[test]
    fn decode_zstd_rejects_oversized_window_declaration() {
        // Hand-crafted minimal zstd frame header declaring a window
        // size far above `MAX_DECOMPRESSED_BYTES`. The frame-header
        // pre-check in `decode_zstd` must reject this BEFORE the
        // streaming decoder is created — that's the bomb defence
        // the reviewer's audit flagged (an output-side `.take()` cap
        // alone wouldn't stop a hostile origin from forcing the
        // decoder to pre-allocate a huge internal buffer).
        //
        // Byte breakdown:
        //   28 B5 2F FD  — zstd magic number
        //   00           — Frame_Header_Descriptor:
        //                  Single_Segment=0, no FCS, no DID
        //   F0           — Window_Descriptor: exp=30, mantissa=0
        //                  → window = 2^(10+30) = 1 TiB
        // (No further bytes; we never get past the header check.)
        let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xF0];
        let err = decode_zstd(&frame).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains("window"),
            "error must identify the window-size violation, got: {}",
            msg
        );
    }

    #[test]
    fn decode_brotli_rejects_oversize_bomb() {
        // Build a brotli payload that decodes to more than
        // `MAX_DECOMPRESSED_BYTES`. Using a highly-repetitive input
        // so the encoded form stays tiny.
        use brotli::enc::BrotliEncoderParams;
        let plain = vec![0u8; (MAX_DECOMPRESSED_BYTES as usize) + 1];
        let mut encoded = Vec::new();
        brotli::BrotliCompress(
            &mut &plain[..],
            &mut encoded,
            &BrotliEncoderParams::default(),
        )
        .expect("brotli encode");
        let err = decode_brotli(&encoded).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn redirect_absolute_url() {
        let (p, h) = parse_redirect("https://script.googleusercontent.com/abc?x=1");
        assert_eq!(p, "/abc?x=1");
        assert_eq!(h.as_deref(), Some("script.googleusercontent.com"));
    }

    #[test]
    fn redirect_relative() {
        let (p, h) = parse_redirect("/somewhere");
        assert_eq!(p, "/somewhere");
        assert!(h.is_none());
    }

    #[test]
    fn parse_relay_basic_json() {
        let body = r#"{"s":200,"h":{"Content-Type":"text/plain"},"b":"SGVsbG8="}"#;
        let raw = parse_relay_json(body.as_bytes(), false).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("Hello"));
    }

    #[test]
    fn parse_content_range_total_accepts_mixed_case_unit() {
        let headers = vec![("Content-Range".to_string(), "Bytes 0-4/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), Some(20));
    }

    #[test]
    fn parse_content_range_total_rejects_descending_range() {
        let headers = vec![("Content-Range".to_string(), "bytes 10-4/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), None);
    }

    #[test]
    fn parse_content_range_total_rejects_end_past_total() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-20/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), None);
    }

    #[test]
    fn validate_probe_range_accepts_decoded_full_entity_body_mismatch() {
        let mut raw = b"HTTP/1.1 206 Partial Content\r\n\
Content-Range: bytes 0-11247/11248\r\n\
Content-Type: text/javascript\r\n\
Vary: Accept-Encoding\r\n\
Content-Length: 45812\r\n\r\n"
            .to_vec();
        raw.extend(std::iter::repeat_n(b'x', 45_812));

        let (status, headers, body) = split_response(&raw).unwrap();
        assert_eq!(
            validate_probe_range(status, &headers, body, RANGE_PARALLEL_CHUNK_BYTES - 1),
            Some(ContentRange {
                start: 0,
                end: 11_247,
                total: 11_248,
            }),
        );

        let rewritten = rewrite_206_to_200(&raw);
        let (status, headers, body) = split_response(&rewritten).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.len(), 45_812);
        assert!(!headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-range")));
        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.as_str()),
            Some("45812"),
        );
    }

    #[test]
    fn validate_probe_range_rejects_missing_content_range() {
        assert!(validate_probe_range(206, &[], b"hello", 4).is_none());
    }

    #[test]
    fn validate_probe_range_rejects_nonzero_start() {
        let headers = vec![("Content-Range".to_string(), "bytes 1-4/20".to_string())];
        assert!(validate_probe_range(206, &headers, b"hell", 4).is_none());
    }

    #[test]
    fn validate_probe_range_rejects_end_past_requested_end() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-5/20".to_string())];
        assert!(validate_probe_range(206, &headers, b"hello!", 4).is_none());
    }

    #[test]
    fn validate_probe_range_rejects_body_length_mismatch() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-4/20".to_string())];
        assert!(validate_probe_range(206, &headers, b"hey", 4).is_none());
    }

    #[test]
    fn extract_exact_range_body_rejects_body_length_mismatch() {
        let raw = b"HTTP/1.1 206 Partial Content\r\n\
Content-Range: bytes 5-9/20\r\n\
Content-Length: 3\r\n\r\n\
hey";
        let err = extract_exact_range_body(raw, 5, 9, 20).unwrap_err();
        assert_eq!(err, "Content-Range/body length mismatch");
    }

    #[test]
    fn extract_exact_range_body_rejects_mismatched_content_range() {
        let raw = b"HTTP/1.1 206 Partial Content\r\n\
Content-Range: bytes 5-9/20\r\n\
Content-Length: 5\r\n\r\n\
hello";
        let err = extract_exact_range_body(raw, 10, 14, 20).unwrap_err();
        assert_eq!(err, "unexpected Content-Range");
    }

    #[test]
    fn chunk_failure_is_retryable_for_relay_504_timeout() {
        // The exact shape `relay_uncoalesced` returns on Apps Script
        // timeout — the dominant failure mode behind the archive.org
        // bug report (3.8 GB download died on chunk 22 of 14647).
        let raw = error_response(
            504,
            "Relay timeout — Apps Script did not respond. \
             Most likely cause: daily UrlFetchApp quota exhausted",
        );
        assert!(chunk_failure_is_retryable(&raw));
    }

    #[test]
    fn chunk_failure_is_retryable_for_relay_502_error() {
        // `relay_uncoalesced` returns a synthetic 502 for connection-
        // level relay failures. Plausibly transient — another script
        // ID / another deployment may succeed.
        let raw = error_response(502, "Relay error: connection refused");
        assert!(chunk_failure_is_retryable(&raw));
    }

    #[test]
    fn chunk_failure_is_retryable_for_origin_5xx() {
        // Origin 503 / 500 / 504 — same retry policy. The chunk fetch
        // is idempotent (GET + explicit Range, no body) so re-firing
        // is safe.
        for status in [500u16, 503, 504, 599] {
            let raw = error_response(status, "origin error");
            assert!(
                chunk_failure_is_retryable(&raw),
                "{status} must be retryable",
            );
        }
    }

    #[test]
    fn chunk_failure_is_retryable_when_response_unparseable() {
        // No HTTP head terminator: relay never got a full response.
        // Treat like a connection-level failure and retry.
        assert!(chunk_failure_is_retryable(b""));
        assert!(chunk_failure_is_retryable(b"HTTP/1.1 ???"));
    }

    #[test]
    fn chunk_failure_is_not_retryable_for_2xx_3xx_4xx() {
        // 200/206/3xx/4xx are the origin's authoritative answer —
        // retrying the same request burns quota without changing the
        // result. Specifically: 206 here means
        // `extract_exact_range_body` rejected the response for a
        // shape mismatch (wrong Content-Range, body length, etc.) —
        // a real protocol-level disagreement, not a transient glitch.
        for status in [200u16, 204, 206, 301, 304, 400, 403, 404, 416, 429] {
            let raw = error_response(status, "x");
            assert!(
                !chunk_failure_is_retryable(&raw),
                "{status} must NOT be retryable",
            );
        }
    }

    #[test]
    fn assemble_200_head_uses_declared_length_and_strips_range_meta() {
        // Streaming path passes `total` (full file size) as the declared
        // length even though the body hasn't been assembled yet. The head
        // block must carry that as Content-Length and must NOT carry the
        // probe's Content-Range (would mark response as partial and
        // clients would reject mid-stream chunks past the probe's end).
        let probe_headers = vec![
            (
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            ),
            (
                "Content-Range".to_string(),
                "bytes 0-262143/109605203".to_string(),
            ),
            ("Content-Length".to_string(), "262144".to_string()),
            ("Content-Encoding".to_string(), "gzip".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Connection".to_string(), "close".to_string()),
            ("Cache-Control".to_string(), "max-age=300".to_string()),
        ];
        let head = assemble_200_head(&probe_headers, 109_605_203);
        let s = std::str::from_utf8(&head).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        assert!(s.contains("Content-Length: 109605203\r\n"));
        // Hop-by-hop and content-meta the buffered path strips must
        // ALSO be stripped by the streaming head (else range responses
        // would mislead clients).
        assert!(!s.contains("Content-Range:"));
        assert!(!s.contains("Content-Encoding:"));
        assert!(!s.contains("Transfer-Encoding:"));
        assert!(!s.contains("Connection:"));
        // Original Content-Length from the probe must NOT survive —
        // we computed our own from `total`.
        assert!(!s.contains("Content-Length: 262144\r\n"));
        // Non-stripped headers pass through.
        assert!(s.contains("Content-Type: application/octet-stream\r\n"));
        assert!(s.contains("Cache-Control: max-age=300\r\n"));
    }

    #[test]
    fn assemble_200_head_matches_full_200_head_for_buffered_path() {
        // The two assemblers must agree on header semantics so a
        // response taken via the buffered path is byte-identical (in
        // its head block) to the same response taken via the streaming
        // path. Lock that in here so future header-skip changes don't
        // drift between the two.
        let headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Content-Range".to_string(), "bytes 0-9/10".to_string()),
            ("X-Custom".to_string(), "foo".to_string()),
        ];
        let body = b"helloworld";
        let full = assemble_full_200(&headers, body);
        let head_only = assemble_200_head(&headers, body.len() as u64);
        let sep = b"\r\n\r\n";
        let idx = full.windows(sep.len()).position(|w| w == sep).unwrap();
        assert_eq!(&full[..idx + sep.len()], head_only.as_slice());
    }

    #[tokio::test]
    async fn write_response_with_head_transform_applies_to_head_not_body() {
        // The bridge between writer-based API and the buffered/error
        // paths: head gets the transform; body bytes are forwarded
        // unchanged so binary payloads aren't corrupted by an
        // accidental UTF-8 round-trip in the transform path.
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: app/octet-stream\r\nContent-Length: 4\r\n\r\n\x00\x01\x02\xff";
        let mut buf: Vec<u8> = Vec::new();
        let transform = |head: &[u8]| -> Vec<u8> {
            // Tag the head so we can prove the transform ran on it.
            // Strip the trailing CRLFCRLF terminator, append a new
            // header line, then restore the terminator.
            let sep = b"\r\n\r\n";
            let mut out = head.strip_suffix(sep).unwrap_or(head).to_vec();
            out.extend_from_slice(b"\r\nX-Tag: yes\r\n\r\n");
            out
        };
        write_response_with_head_transform(&mut buf, response, &transform)
            .await
            .unwrap();
        let sep_pos = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let (head, body) = (&buf[..sep_pos + 4], &buf[sep_pos + 4..]);
        let head_s = std::str::from_utf8(head).unwrap();
        assert!(head_s.contains("X-Tag: yes\r\n"));
        // Body is byte-identical — no UTF-8 lossy conversion.
        assert_eq!(body, b"\x00\x01\x02\xff");
    }

    #[tokio::test]
    async fn write_response_with_head_transform_passes_through_when_no_terminator() {
        // Defensive: a payload missing `\r\n\r\n` (corrupted upstream,
        // raw error blob) must be forwarded byte-identical so we don't
        // synthesise a fake header for non-HTTP/1.x bytes.
        let response = b"not an http response";
        let mut buf: Vec<u8> = Vec::new();
        let transform = |_: &[u8]| -> Vec<u8> { b"XX".to_vec() };
        write_response_with_head_transform(&mut buf, response, &transform)
            .await
            .unwrap();
        assert_eq!(buf.as_slice(), response);
    }

    #[test]
    fn plan_remaining_ranges_basic_chunking() {
        // probe covered 0..=3 of a 20-byte file at 5-byte chunks →
        // remaining ranges are 4-8, 9-13, 14-18, 19-19.
        let ranges: Vec<_> = plan_remaining_ranges(3, 20, 5).collect();
        assert_eq!(ranges, vec![(4, 8), (9, 13), (14, 18), (19, 19)]);
    }

    #[test]
    fn plan_remaining_ranges_yields_nothing_when_probe_covers_everything() {
        // Defensive: even though the caller is supposed to short-circuit
        // when the probe covers the entity, the iterator itself must be
        // a no-op rather than emit a bogus 0-length range.
        let ranges: Vec<_> = plan_remaining_ranges(19, 20, 5).collect();
        assert!(ranges.is_empty());
    }

    #[test]
    fn plan_remaining_ranges_handles_huge_total_lazily_without_oom() {
        // Regression for the DoS introduced when the buffered+streaming
        // refactor (1.9.23) initially built the full ranges Vec before
        // branching on size. A hostile origin advertising
        // `Content-Range: bytes 0-262143/<huge>` can pass the probe
        // checks (matching 256 KiB body, valid total) and used to drive
        // ~6 GB of `Vec<(u64, u64)>` allocation for a 100 TiB total.
        //
        // Lazy iteration must let us pull a bounded number of items
        // from a u64::MAX-sized total without panicking or allocating
        // the whole plan. Pulling 10 items proves we never materialised
        // ~2^44 of them up front.
        let total = u64::MAX;
        let chunk = 256 * 1024;
        let probe_end = chunk - 1;
        let first_ten: Vec<_> = plan_remaining_ranges(probe_end, total, chunk)
            .take(10)
            .collect();
        assert_eq!(first_ten.len(), 10);
        // First range starts right after the probe.
        assert_eq!(first_ten[0].0, probe_end + 1);
        // Each range covers exactly one chunk except possibly the last
        // — which here can't be the tail because we only took 10.
        for (s, e) in &first_ten {
            assert_eq!(e - s + 1, chunk);
        }
        // Successive ranges are contiguous.
        for w in first_ten.windows(2) {
            assert_eq!(w[1].0, w[0].1 + 1);
        }
    }

    #[tokio::test]
    async fn stream_chunks_to_writer_writes_head_probe_then_chunks_in_order() {
        // Happy path: streaming writer must emit
        //   head + probe_body + chunk1_body + chunk2_body + …
        // in input order so a download client reading byte 0 onward
        // sees a coherent response.
        use futures_util::stream::{self, StreamExt as _};
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
        let probe = b"AB";
        // The streaming function consumes whatever `Stream` it's given;
        // tests feed it `stream::iter` of synthetic chunk results so
        // we exercise the writer + ordering logic without needing a
        // live DomainFronter / Apps Script.
        let fetches = stream::iter(vec![
            (2u64, 5u64, Ok::<Vec<u8>, &'static str>(b"CDEF".to_vec())),
            (6u64, 9u64, Ok::<Vec<u8>, &'static str>(b"GHIJ".to_vec())),
        ]);
        let mut buf = Vec::new();
        stream_chunks_to_writer(
            &mut VecAsyncWriter(&mut buf),
            head,
            probe,
            10,
            fetches.map(|x| x),
            "https://example.test/file",
        )
        .await
        .unwrap();
        // Whole wire output: head, then probe body, then chunks in
        // input order — no chunk reordered to "fastest first."
        let expected: Vec<u8> = [head.as_slice(), probe.as_slice(), b"CDEF", b"GHIJ"].concat();
        assert_eq!(buf, expected);
    }

    #[test]
    fn dispatch_range_response_wrapper_buffers_through_64mib_ceiling() {
        // Pre-1.9.23 behavior preservation: `relay_parallel_range ->
        // Vec<u8>` used to stitch range-capable responses up to the
        // old `MAX_STITCHED_RANGE_BYTES` cap of 64 MiB. The first
        // round of this PR collapsed that cap into the new 40 MiB
        // streaming threshold, regressing 40-64 MiB downloads
        // through the wrapper (Apps Script's single-GET path returns
        // 502/504 above ~40 MiB). Restored via separate constants:
        // wrapper stays buffered up to BUFFERED_STITCH_MAX_BYTES,
        // not APPS_SCRIPT_BODY_MAX_BYTES.
        assert_eq!(
            dispatch_range_response(40 * 1024 * 1024, false),
            RangeDispatch::Buffered,
        );
        assert_eq!(
            dispatch_range_response(50 * 1024 * 1024, false),
            RangeDispatch::Buffered,
        );
        assert_eq!(
            dispatch_range_response(BUFFERED_STITCH_MAX_BYTES, false),
            RangeDispatch::Buffered,
        );
    }

    #[test]
    fn dispatch_range_response_wrapper_falls_back_above_buffered_cap() {
        // Lock-in for the Vec<u8> wrapper contract (Issue #162):
        // above the buffered ceiling the wrapper MUST NOT take the
        // streaming branch (which would emit a partial 200 OK that
        // a `Vec<u8>` consumer can't react to). Above the buffered
        // cap, fall back to single GET — same path the pre-1.9.23
        // wrapper took above its 64 MiB cliff.
        assert_eq!(
            dispatch_range_response(BUFFERED_STITCH_MAX_BYTES + 1, false),
            RangeDispatch::FallbackSingleGet,
        );
        assert_eq!(
            dispatch_range_response(100 * 1024 * 1024, false),
            RangeDispatch::FallbackSingleGet,
        );
        assert_eq!(
            dispatch_range_response(u64::MAX, false),
            RangeDispatch::FallbackSingleGet,
        );
    }

    #[test]
    fn dispatch_range_response_writer_api_streams_above_apps_script_ceiling() {
        // Writer-based API contract: streams above the Apps Script
        // single-GET ceiling so large downloads (>40 MiB) actually
        // deliver. Without this, we'd be back to the pre-fix 504
        // timeout for the 104 MiB DMG that motivated #1042. The
        // writer API streams in the 40-64 MiB band too (where the
        // wrapper would still buffer): that's intentional — on
        // chunk failure, streaming truncates and the download client
        // resumes via Range, while the buffered path's fallback
        // can't recover at this size anyway.
        //
        // Upper bound is the streaming cap MAX_STREAMED_RANGE_BYTES
        // (quota-DoS guard); above it, see
        // `dispatch_range_response_rejects_streamed_totals_above_streaming_cap`.
        assert_eq!(
            dispatch_range_response(APPS_SCRIPT_BODY_MAX_BYTES + 1, true),
            RangeDispatch::Stream,
        );
        assert_eq!(
            dispatch_range_response(50 * 1024 * 1024, true),
            RangeDispatch::Stream,
        );
        assert_eq!(
            dispatch_range_response(BUFFERED_STITCH_MAX_BYTES + 1, true),
            RangeDispatch::Stream,
        );
        // Just under the streaming cap still streams.
        assert_eq!(
            dispatch_range_response(MAX_STREAMED_RANGE_BYTES, true),
            RangeDispatch::Stream,
        );
    }

    #[test]
    fn dispatch_range_response_rejects_streamed_totals_above_streaming_cap() {
        // Quota-DoS guard for the writer API: a hostile origin can
        // advertise an absurd Content-Range total (e.g. u64::MAX) and
        // pass the probe checks with a normal-sized first-chunk body,
        // making us issue chunk Apps Script calls until the client
        // disconnects. Each call counts toward the daily quota
        // (~20 k requests/day free tier), so an unattended hostile
        // download would lock the user out of the relay. Refuse
        // anything above MAX_STREAMED_RANGE_BYTES instead of
        // streaming.
        assert_eq!(
            dispatch_range_response(MAX_STREAMED_RANGE_BYTES + 1, true),
            RangeDispatch::RejectTooLarge,
        );
        assert_eq!(
            dispatch_range_response(u64::MAX, true),
            RangeDispatch::RejectTooLarge,
        );
        // At the cap, streaming is still allowed. The boundary is
        // strict greater-than so the constant itself is reachable.
        assert_eq!(
            dispatch_range_response(MAX_STREAMED_RANGE_BYTES, true),
            RangeDispatch::Stream,
        );
        // Wrapper (streaming_allowed=false) hits its own
        // BUFFERED_STITCH_MAX_BYTES cliff far below MAX_STREAMED_…,
        // so any oversized total routes to FallbackSingleGet (Apps
        // Script's single-GET will reject it naturally), not to
        // RejectTooLarge.
        assert_eq!(
            dispatch_range_response(MAX_STREAMED_RANGE_BYTES + 1, false),
            RangeDispatch::FallbackSingleGet,
        );
        assert_eq!(
            dispatch_range_response(u64::MAX, false),
            RangeDispatch::FallbackSingleGet,
        );
    }

    #[test]
    fn dispatch_range_response_at_or_below_apps_script_ceiling_stays_buffered() {
        // At or below the Apps Script ceiling, both API surfaces stay
        // buffered — the buffered path has a real recovery story (a
        // chunk failure falls back to single GET, which delivers a
        // complete file when ≤ 40 MiB).
        for streaming_allowed in [true, false] {
            assert_eq!(
                dispatch_range_response(APPS_SCRIPT_BODY_MAX_BYTES, streaming_allowed),
                RangeDispatch::Buffered,
            );
            assert_eq!(
                dispatch_range_response(1024 * 1024, streaming_allowed),
                RangeDispatch::Buffered,
            );
            assert_eq!(
                dispatch_range_response(1, streaming_allowed),
                RangeDispatch::Buffered,
            );
            assert_eq!(
                dispatch_range_response(0, streaming_allowed),
                RangeDispatch::Buffered,
            );
        }
    }

    /// Test-only `AsyncWrite` that records the byte-offset of every
    /// `poll_flush` call. Used to verify
    /// `stream_chunks_to_writer` flushes the committed prefix before
    /// surfacing a chunk-validation error — critical for TLS streams
    /// where the partial body sits in the TLS writer's in-memory
    /// buffer and would otherwise be dropped on connection close.
    struct FlushTrackingWriter {
        buf: Vec<u8>,
        /// Byte offset (relative to `buf.len()` at the time) of each
        /// `poll_flush` call. Lets a test assert "flush happened
        /// after byte N had been written."
        flushed_at: Vec<usize>,
    }

    impl FlushTrackingWriter {
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                flushed_at: Vec::new(),
            }
        }
    }

    impl tokio::io::AsyncWrite for FlushTrackingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_mut().buf.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            let at = me.buf.len();
            me.flushed_at.push(at);
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn stream_chunks_to_writer_flushes_before_returning_chunk_error() {
        // TLS-safety lock-in: chunk-validation failure surfaces as
        // `Err`, and the caller (proxy_server.rs) typically uses `?`
        // to propagate — which means the post-error `stream.flush()`
        // in the caller never runs. Without the in-function flush,
        // bytes buffered inside the TLS writer get dropped when the
        // connection closes, and the download client sees a clean
        // empty body instead of the partial prefix it needs to
        // resume via Range. This test asserts flush() is called
        // after the committed prefix bytes have been written and
        // before the function returns.
        use futures_util::stream::{self, StreamExt as _};
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n";
        let probe = b"AB";
        let fetches = stream::iter(vec![
            (2u64, 5u64, Ok::<Vec<u8>, &'static str>(b"CDEF".to_vec())),
            (
                6u64,
                9u64,
                Err::<Vec<u8>, &'static str>("validation failure"),
            ),
        ]);
        let mut writer = FlushTrackingWriter::new();
        let result = stream_chunks_to_writer(
            &mut writer,
            head,
            probe,
            12,
            fetches.map(|x| x),
            "https://example.test/file",
        )
        .await;
        assert!(result.is_err());

        // Bytes written before the failure: head + probe + first
        // chunk = head_len + 2 + 4.
        let expected_committed = head.len() + 2 + 4;
        assert_eq!(writer.buf.len(), expected_committed);

        // Flush must have been called after the committed prefix
        // was in place — i.e., at the same byte count as `buf.len()`.
        assert!(
            writer.flushed_at.contains(&expected_committed),
            "flush() must run after committed prefix is written; flushed_at={:?}, expected at byte {}",
            writer.flushed_at,
            expected_committed,
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_chunks_to_writer_emits_progress_log_at_each_16mib_boundary() {
        // User feedback on PR #1085: large streamed downloads went
        // silent in the logs between "starting N chunks" and
        // completion, with no progress signal. This test locks in
        // the periodic progress lines by capturing the tracing
        // output of a synthetic 40 MiB stream and counting how many
        // `range-parallel-stream:` lines mention "MiB" (the progress
        // lines do; the start-up summary phrases it differently).
        //
        // At 40 MiB total and 16 MiB intervals we expect two
        // crossings — at 16 MiB and 32 MiB. Strictly *not* one at
        // 0 MiB (the threshold must be reached, not just initialised)
        // and *not* one at 40 MiB (40 < next_progress_log_at=48 once
        // we've crossed 32 MiB).
        use futures_util::stream;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct LogCapture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for LogCapture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for LogCapture {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_target(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // 40 MiB total. Probe is one 256 KiB chunk; the rest of the
        // file is 159 same-sized chunks fed as a synthetic stream.
        let chunk_size: u64 = 256 * 1024;
        let total: u64 = 40 * 1024 * 1024;
        let probe_body = vec![0u8; chunk_size as usize];
        type TestChunk = (u64, u64, Result<Vec<u8>, &'static str>);
        let mut chunks_data: Vec<TestChunk> = Vec::new();
        let mut start = chunk_size;
        while start < total {
            let end = (start + chunk_size - 1).min(total - 1);
            let len = (end - start + 1) as usize;
            chunks_data.push((start, end, Ok(vec![0u8; len])));
            start = end + 1;
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", total).into_bytes();

        let mut buf: Vec<u8> = Vec::new();
        stream_chunks_to_writer(
            &mut VecAsyncWriter(&mut buf),
            &head,
            &probe_body,
            total,
            stream::iter(chunks_data),
            "https://example.test/big",
        )
        .await
        .unwrap();
        // Wire output sanity: head + 40 MiB body, exactly.
        assert_eq!(buf.len() as u64, head.len() as u64 + total);

        // Inspect the captured log. The two progress lines should
        // mention `16/40` and `32/40` (MiB emitted / MiB total).
        // Drop the subscriber guard so any inadvertent log lines
        // from drop-handlers don't race with our read.
        drop(_guard);
        let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        let progress_lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("range-parallel-stream:") && l.contains(" MiB ("))
            .collect();
        assert_eq!(
            progress_lines.len(),
            2,
            "expected 2 progress lines at the 16 / 32 MiB crossings; full log:\n{}",
            log,
        );
        assert!(
            progress_lines[0].contains("16/40 MiB (40%)"),
            "first progress line should read 16/40 MiB (40%); got: {}",
            progress_lines[0],
        );
        assert!(
            progress_lines[1].contains("32/40 MiB (80%)"),
            "second progress line should read 32/40 MiB (80%); got: {}",
            progress_lines[1],
        );
    }

    #[tokio::test]
    async fn stream_chunks_to_writer_flushes_after_head_and_probe_for_first_byte_latency() {
        // "First bytes quickly" lock-in: after writing head + probe
        // body, the function must flush before going into the
        // chunk-fetch loop. Without this, the response start
        // (status code, headers, first 256 KiB of body) may sit in
        // intermediate buffers (TLS writer, kernel send buffer with
        // small initial cwnd, intermediate proxy buffers) while we
        // round-trip ~2s/chunk to Apps Script for the remaining
        // chunks — giving the user a "stuck at 0%" progress bar
        // for hundreds of ms to seconds on a multi-MiB download.
        use futures_util::stream::{self, StreamExt as _};
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n";
        let probe = b"AB";
        let fetches = stream::iter(vec![
            (2u64, 5u64, Ok::<Vec<u8>, &'static str>(b"CDEF".to_vec())),
            (6u64, 9u64, Ok::<Vec<u8>, &'static str>(b"GHIJ".to_vec())),
            (10u64, 13u64, Ok::<Vec<u8>, &'static str>(b"KLMN".to_vec())),
        ]);
        let mut writer = FlushTrackingWriter::new();
        stream_chunks_to_writer(
            &mut writer,
            head,
            probe,
            14,
            fetches.map(|x| x),
            "https://example.test/file",
        )
        .await
        .unwrap();

        // At least one flush must land at byte offset = head + probe
        // (BEFORE any chunk bytes), proving the early flush ran.
        let head_plus_probe = head.len() + probe.len();
        assert!(
            writer.flushed_at.contains(&head_plus_probe),
            "early flush must run after head+probe but before chunks; flushed_at={:?}, expected at byte {}",
            writer.flushed_at,
            head_plus_probe,
        );
    }

    #[tokio::test]
    async fn streaming_branch_with_real_cors_transform_emits_acl_headers_then_body() {
        // Cross-module integration test: the streaming branch's
        // `transform_head` closure is wired up in proxy_server.rs
        // from the request's Origin header to call
        // `inject_cors_into_head`. Helper tests cover the head
        // assembler and the CORS rewriter in isolation; this test
        // composes them as the production proxy dispatch does, so
        // a regression in either the closure construction or the
        // head-only CORS variant surfaces here.
        use crate::proxy_server::inject_cors_into_head;
        use futures_util::stream::{self, StreamExt as _};

        let cors_origin: Option<String> = Some("https://www.youtube.com".to_string());
        // Same closure the proxy_server dispatch uses (see
        // proxy_server.rs `handle_mitm_request`).
        let transform = |head: &[u8]| -> Vec<u8> {
            match cors_origin.as_deref() {
                Some(o) => inject_cors_into_head(head, o).unwrap_or_else(|| head.to_vec()),
                None => head.to_vec(),
            }
        };

        let probe_headers = vec![
            (
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            ),
            ("Content-Range".to_string(), "bytes 0-3/12".to_string()),
            // Origin sent ACL=* with credentials — exactly the YouTube
            // comments failure mode `inject_cors_response_headers`
            // was added to fix. The streaming-path CORS variant must
            // strip this and substitute the request origin.
            ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        ];
        let probe_body = b"ABCD";
        let chunks = stream::iter(vec![
            (4u64, 7u64, Ok::<Vec<u8>, &'static str>(b"EFGH".to_vec())),
            (8u64, 11u64, Ok::<Vec<u8>, &'static str>(b"IJKL".to_vec())),
        ]);
        let mut buf: Vec<u8> = Vec::new();
        stream_range_response_to(
            &mut VecAsyncWriter(&mut buf),
            &probe_headers,
            probe_body,
            12,
            chunks.map(|x| x),
            &transform,
            "https://example.test/big-file",
        )
        .await
        .unwrap();

        let sep_pos = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head terminator");
        let head_s = std::str::from_utf8(&buf[..sep_pos + 4]).unwrap();
        let body = &buf[sep_pos + 4..];

        // Wildcard origin is gone; request origin is echoed.
        assert!(
            !head_s.contains("Access-Control-Allow-Origin: *"),
            "wildcard origin must be stripped, head was: {}",
            head_s,
        );
        assert!(head_s.contains("Access-Control-Allow-Origin: https://www.youtube.com\r\n"));
        assert!(head_s.contains("Access-Control-Allow-Credentials: true\r\n"));
        assert!(head_s.contains("Vary: Origin\r\n"));
        // Synthesised Content-Length = full advertised total.
        assert!(head_s.contains("Content-Length: 12\r\n"));
        // Body unaffected by the head transform; chunks in order.
        assert_eq!(body, b"ABCDEFGHIJKL");
    }

    #[tokio::test]
    async fn stream_range_response_to_assembles_head_from_probe_and_streams_chunks() {
        // Integration test for the streaming-branch wiring in
        // `do_relay_parallel_range_to`: given a probe response (the
        // probe's response headers + first-chunk body), a known
        // total, and a stream of remaining chunk results, the
        // streaming branch must:
        //   1. Build the response head from the probe headers via
        //      `assemble_200_head` (keeps Content-Type etc., strips
        //      Content-Range and writes Content-Length=total).
        //   2. Apply the caller's `transform_head` closure to the
        //      assembled head (e.g. CORS injection).
        //   3. Write head → probe body → chunks (in input order)
        //      with no reordering, no body buffering.
        //
        // Helper-only tests can miss the composition wiring
        // (assemble + transform + stream_chunks); this test
        // exercises all three together through the same free
        // function the production dispatch uses.
        use futures_util::stream::{self, StreamExt as _};
        let probe_headers = vec![
            (
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            ),
            ("Content-Range".to_string(), "bytes 0-3/12".to_string()),
            ("Content-Length".to_string(), "4".to_string()),
            ("X-Origin-Hint".to_string(), "abcd".to_string()),
        ];
        let probe_body = b"ABCD";
        let total: u64 = 12;
        let chunks = stream::iter(vec![
            (4u64, 7u64, Ok::<Vec<u8>, &'static str>(b"EFGH".to_vec())),
            (8u64, 11u64, Ok::<Vec<u8>, &'static str>(b"IJKL".to_vec())),
        ]);
        let transform = |head: &[u8]| -> Vec<u8> {
            // Append a synthetic CORS-style header so we can assert
            // the transform actually got the head bytes, not the
            // probe body.
            let sep = b"\r\n\r\n";
            let mut out = head.strip_suffix(sep).unwrap_or(head).to_vec();
            out.extend_from_slice(b"\r\nX-Transform: applied\r\n\r\n");
            out
        };
        let mut buf: Vec<u8> = Vec::new();
        stream_range_response_to(
            &mut VecAsyncWriter(&mut buf),
            &probe_headers,
            probe_body,
            total,
            chunks.map(|x| x),
            &transform,
            "https://example.test/big-file",
        )
        .await
        .unwrap();

        let sep_pos = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head terminator");
        let head = &buf[..sep_pos + 4];
        let body = &buf[sep_pos + 4..];
        let head_s = std::str::from_utf8(head).unwrap();

        // Composition #1: assemble_200_head ran with the probe
        // headers and the full total.
        assert!(head_s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head_s.contains("Content-Length: 12\r\n"));
        // Original Content-Length from the probe (=4) must be gone.
        assert!(!head_s.contains("Content-Length: 4\r\n"));
        // Content-Range is stripped (it described the probe slice,
        // not the synthesised full response).
        assert!(!head_s.contains("Content-Range:"));
        // Non-stripped probe headers pass through.
        assert!(head_s.contains("Content-Type: application/octet-stream\r\n"));
        assert!(head_s.contains("X-Origin-Hint: abcd\r\n"));

        // Composition #2: transform_head ran on the assembled head.
        assert!(head_s.contains("X-Transform: applied\r\n"));

        // Composition #3: body is probe_body followed by chunks in
        // input order, with no reordering or interleaving.
        assert_eq!(body, b"ABCDEFGHIJKL");
    }

    #[tokio::test]
    async fn stream_range_response_to_propagates_mid_stream_chunk_failure() {
        // Integration counterpart: the streaming branch must
        // propagate a mid-stream chunk failure as Err, and the
        // committed prefix (head + probe + earlier-good chunks)
        // must already be on the wire so the download client can
        // resume via Range. Combined with the flush test above,
        // this gives end-to-end coverage of the failure surface.
        use futures_util::stream::{self, StreamExt as _};
        let probe_headers = vec![
            (
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            ),
            ("Content-Range".to_string(), "bytes 0-3/12".to_string()),
        ];
        let probe_body = b"ABCD";
        let chunks = stream::iter(vec![
            (4u64, 7u64, Ok::<Vec<u8>, &'static str>(b"EFGH".to_vec())),
            (
                8u64,
                11u64,
                Err::<Vec<u8>, &'static str>("chunk validation failure"),
            ),
        ]);
        let identity = |head: &[u8]| head.to_vec();
        let mut buf: Vec<u8> = Vec::new();
        let result = stream_range_response_to(
            &mut VecAsyncWriter(&mut buf),
            &probe_headers,
            probe_body,
            12,
            chunks.map(|x| x),
            &identity,
            "https://example.test/big-file",
        )
        .await;
        assert!(
            result.is_err(),
            "mid-stream chunk failure must propagate as Err"
        );

        let sep_pos = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head terminator");
        let body = &buf[sep_pos + 4..];
        // Committed prefix: probe + first good chunk. NOT the failed
        // chunk and NOT any "after-failure" chunks (there aren't any
        // in this test, but the contract is "stop on first error").
        assert_eq!(body, b"ABCDEFGH");
    }

    #[tokio::test]
    async fn stream_chunks_to_writer_aborts_on_chunk_validation_failure() {
        // Mid-stream chunk failure must return Err *after* the head,
        // probe body, and earlier successful chunks have been
        // committed. Single-GET fallback isn't possible at this point
        // — we've already written wire bytes — and partial write +
        // Err is what the caller (TLS socket) needs to surface a
        // Content-Length mismatch to the download client so it
        // retries via Range from the partial position.
        use futures_util::stream::{self, StreamExt as _};
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n";
        let probe = b"AB";
        let fetches = stream::iter(vec![
            (2u64, 5u64, Ok::<Vec<u8>, &'static str>(b"CDEF".to_vec())),
            (
                6u64,
                9u64,
                Err::<Vec<u8>, &'static str>("Content-Range/body length mismatch"),
            ),
            // This third chunk must NOT be written — the function must
            // bail on the first Err.
            (10u64, 11u64, Ok::<Vec<u8>, &'static str>(b"KL".to_vec())),
        ]);
        let mut buf = Vec::new();
        let result = stream_chunks_to_writer(
            &mut VecAsyncWriter(&mut buf),
            head,
            probe,
            12,
            fetches.map(|x| x),
            "https://example.test/file",
        )
        .await;
        assert!(result.is_err(), "must return Err on first chunk failure");
        // Bytes already committed up to (but not past) the failure:
        // head + probe + successfully-validated chunk 1.
        let expected: Vec<u8> = [head.as_slice(), probe.as_slice(), b"CDEF"].concat();
        assert_eq!(
            buf, expected,
            "post-failure chunks must not be written; partial body length tells client to retry"
        );
    }

    #[test]
    fn parse_relay_error_field() {
        let body = r#"{"e":"unauthorized"}"#;
        let err = parse_relay_json(body.as_bytes(), false).unwrap_err();
        assert!(matches!(err, FronterError::Relay(_)));
    }

    #[test]
    fn parse_relay_rejects_invalid_body_base64() {
        let body = r#"{"s":200,"b":"***not-base64***"}"#;
        let err = parse_relay_json(body.as_bytes(), false).unwrap_err();
        assert!(matches!(err, FronterError::BadResponse(_)));
    }

    #[test]
    fn blacklist_heuristics() {
        assert!(should_blacklist(429, ""));
        assert!(should_blacklist(403, "quota"));
        assert!(should_blacklist(
            500,
            "Service invoked too many times per day: urlfetch"
        ));
        assert!(!should_blacklist(200, ""));
        assert!(!should_blacklist(502, "bad gateway"));
        assert!(looks_like_quota_error(
            "Exception: Service invoked too many times per day"
        ));
        assert!(looks_like_quota_error(
            "Exception: Bandbreitenkontingent überschritten: https://example.com. Verringern Sie die Datenübertragungsrate."
        ));
        assert!(!looks_like_quota_error("bad url"));
    }

    #[test]
    fn classify_envelope_error_buckets_each_category() {
        // Quota — daily UrlFetchApp ceiling.
        assert_eq!(
            classify_envelope_error("Service invoked too many times for one day: urlfetch"),
            Some(EnvelopeCategory::Quota),
        );
        // Auth — Apps Script re-authorization required.
        assert_eq!(
            classify_envelope_error("Authorization is required to perform that action."),
            Some(EnvelopeCategory::Auth),
        );
        assert_eq!(
            classify_envelope_error("unauthorized"),
            Some(EnvelopeCategory::Auth),
        );
        // Deploy — wrong/deleted deployment.
        assert_eq!(
            classify_envelope_error(
                "Error occurred due to a missing library version or a deployment version. Error code Not_Found"
            ),
            Some(EnvelopeCategory::Deploy),
        );
        // Admin — workspace policy block. Pick strings that don't also
        // match the quota `"urlfetch"` substring (which has higher
        // priority); the practical case where Admin bucketing matters
        // is when the admin policy message names a different service.
        assert_eq!(
            classify_envelope_error("Domain policy has disabled this Apps Script."),
            Some(EnvelopeCategory::Admin),
        );
        assert_eq!(
            classify_envelope_error("Contact your administrator for access."),
            Some(EnvelopeCategory::Admin),
        );
        // Transient envelopes stay None so the deployment isn't blacklisted.
        assert_eq!(
            classify_envelope_error("Server not available. Please try again later."),
            None,
        );
        // Unrecognised content also stays None.
        assert_eq!(classify_envelope_error(""), None);
        assert_eq!(classify_envelope_error("bad url"), None);
    }

    #[test]
    fn classify_envelope_error_rejects_common_transient_phrases() {
        // The per-invocation 6-minute cap is transient — the next call
        // through the same SID may finish in milliseconds. Apps Script
        // returns this when a single execution runs long, NOT when the
        // daily quota is exhausted. Must not bucket as Quota or Deploy
        // (would sideline a healthy script for the full cooldown).
        assert_eq!(
            classify_envelope_error("Exception: Exceeded maximum execution time"),
            None,
            "per-invocation 6-min cap must not be classified as a permanent failure"
        );
        // "deployment" appears in transient Apps Script messages about
        // ongoing deployments being updated; the narrower
        // `"deployment version"` / `"deployment id"` patterns avoid the
        // false positive.
        assert_eq!(
            classify_envelope_error("The deployment is being updated. Try again."),
            None,
            "transient deployment-update notice must not bucket as Deploy"
        );
        // Benign use of `"daily"` in user-script error output — e.g.
        // a script that calls `MailApp` returns a string containing the
        // word "daily" as part of its content.
        assert_eq!(
            classify_envelope_error("Sent the daily report successfully."),
            None,
            "benign occurrences of `daily` outside quota phrasing must not match"
        );
        // Benign use of `"exceeded"` outside quota phrasing.
        assert_eq!(
            classify_envelope_error("Exception: Exceeded the configured retry count on inner API"),
            None,
            "benign `exceeded` outside quota / limit phrasing must not match"
        );
    }

    #[test]
    fn exit_node_matches_bypasses_googlevideo_in_full_mode() {
        // Even in `full` mode, *.googlevideo.com must skip the exit node
        // — chaining video chunks through Cloudflare/Deno/VPS is slow
        // and the GCP-IP heuristic that exit-node defeats doesn't apply
        // to googlevideo anyway.
        let json = r#"{
            "mode": "apps_script",
            "google_ip": "127.0.0.1",
            "front_domain": "www.google.com",
            "script_id": "TEST",
            "auth_key": "test_auth_key",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.deno.dev",
                "psk": "test-psk",
                "mode": "full"
            }
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let fronter = DomainFronter::new(&cfg).expect("test fronter must construct");
        assert!(
            !fronter.exit_node_matches("https://r1---sn-aigl6n7e.googlevideo.com/videoplayback")
        );
        assert!(!fronter.exit_node_matches("https://googlevideo.com/foo"));
        // Anything else under full mode still routes through the exit node.
        assert!(fronter.exit_node_matches("https://www.example.com/"));
    }

    // ─── Heartbeat / IP-swap invariants ───────────────────────
    //
    // The full `run_ip_health` loop sleeps for a real interval and
    // calls into `scan_ips::heartbeat_probe` (real network), so unit-
    // testing the loop end-to-end isn't tractable. These tests pin
    // the *individual invariants* the loop relies on so a refactor
    // that breaks them fails CI before users see broken failover.

    #[tokio::test(flavor = "current_thread")]
    async fn host_swap_changes_arc_pointer() {
        // The whole staleness-detection design rests on this:
        // every swap installs a *fresh* `Arc<String>`, so
        // `Arc::ptr_eq` against a pre-swap snapshot returns false.
        // If a future refactor reuses the same Arc instance (e.g.
        // mutates it in place), every `ptr_eq` check in the module
        // silently regresses to "always equal" and stale connections
        // sneak back into the pool. This test fails first.
        let fronter = fronter_for_test(false);
        let before = fronter.connect_host.load_full();
        fronter.connect_host.store(Arc::new("127.0.0.2".into()));
        let after = fronter.connect_host.load_full();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "swap must install a fresh Arc — staleness detection depends on it"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ensure_h2_rejects_cached_cell_with_stale_host() {
        // The race the host tag defends against: a heartbeat swap
        // lands between an h2 open completing (cell stored with the
        // old host Arc) and the swap-path's `*h2_cell = None`. A
        // reader hitting `ensure_h2` in that window would otherwise
        // return the cached SendRequest bound to the just-
        // decommissioned IP. With the host tag, the
        // `Arc::ptr_eq(&cell.host, &current)` check rejects the
        // stale entry and reopens.
        //
        // Setup: seed a healthy-looking cell with a synthetic
        // *stale* host Arc, then swap `connect_host` to a fresh
        // Arc. ensure_h2 must see the mismatch and refuse the
        // cell, NOT return the stale SendRequest. We pin
        // `h2_open_failed_at` to keep the reopen path from
        // attempting a real handshake (the test is about cell
        // rejection, not about reopen flow).
        let (addr, server_handle) = spawn_h2c_echo_server().await;
        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let stale_host: Arc<String> = Arc::new("127.0.0.99".into());
        {
            let mut cell = fronter.h2_cell.lock().await;
            *cell = Some(H2Cell {
                send,
                created: Instant::now(),
                generation: 42,
                dead: Arc::new(AtomicBool::new(false)),
                host: stale_host.clone(),
            });
        }
        // Swap to a different Arc — current host now mismatches the
        // cell's host tag.
        fronter.connect_host.store(Arc::new("127.0.0.100".into()));
        // Pin the failure backoff so the reopen short-circuits
        // without real network. We're only asserting the cell-read
        // path rejects the stale entry.
        *fronter.h2_open_failed_at.lock().await = Some(Instant::now());

        let result = fronter.ensure_h2().await;
        assert!(
            result.is_none(),
            "ensure_h2 must refuse a cell whose host Arc no longer matches connect_host"
        );
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ensure_h2_accepts_cached_cell_with_matching_host() {
        // Positive control for the test above — confirms that the
        // host-tag check doesn't reject a legitimately fresh cell.
        // Without this, a regression that hard-codes the host check
        // to always-mismatch would silently pass the
        // stale-rejection test but break the cache entirely.
        let (addr, server_handle) = spawn_h2c_echo_server().await;
        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let current_host = fronter.connect_host.load_full();
        {
            let mut cell = fronter.h2_cell.lock().await;
            *cell = Some(H2Cell {
                send,
                created: Instant::now(),
                generation: 99,
                dead: Arc::new(AtomicBool::new(false)),
                host: current_host,
            });
        }
        let result = fronter.ensure_h2().await;
        assert!(
            result.is_some(),
            "ensure_h2 must return a cached cell whose host matches connect_host"
        );
        let (_send, gen) = result.unwrap();
        assert_eq!(gen, 99, "should return the cached generation, not reopen");
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rescan_returns_none_on_empty_sni_list() {
        // Defence-in-depth: if for any reason `sni_hosts` is empty
        // (constructor invariants currently prevent this — see
        // `build_sni_pool_for` — but a future refactor could break
        // that), `rescan_and_pick` short-circuits to None instead of
        // probing IPs against a vacuous SNI set.
        let json = r#"{
            "mode": "apps_script",
            "google_ip": "127.0.0.1",
            "front_domain": "www.google.com",
            "script_id": "TEST",
            "auth_key": "test_auth_key"
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let picked = crate::scan_ips::rescan_and_pick(&cfg, &[]).await;
        assert!(picked.is_none());
    }

    #[test]
    fn header_string_value_normalizes_string_and_array() {
        // Apps Script `getAllHeaders()` returns repeated headers as
        // either a string (single value or comma-folded) OR a JSON
        // array of strings. parse_relay_json's strip-or-keep
        // decision must see both shapes the same way.
        let s: Value = serde_json::from_str(r#""br""#).unwrap();
        assert_eq!(header_string_value(&s).as_deref(), Some("br"));

        let a: Value = serde_json::from_str(r#"["br"]"#).unwrap();
        assert_eq!(header_string_value(&a).as_deref(), Some("br"));

        let chain: Value = serde_json::from_str(r#"["gzip","br"]"#).unwrap();
        assert_eq!(header_string_value(&chain).as_deref(), Some("gzip, br"));

        // Numeric / null / mixed-non-string array → None.
        let n: Value = serde_json::from_str("42").unwrap();
        assert_eq!(header_string_value(&n), None);
        let nl: Value = serde_json::from_str("null").unwrap();
        assert_eq!(header_string_value(&nl), None);
        let mixed: Value = serde_json::from_str("[42]").unwrap();
        assert_eq!(header_string_value(&mixed), None);
    }

    #[test]
    fn parse_relay_json_handles_array_form_content_encoding() {
        // `Content-Encoding: ["br"]` (array form) must take the
        // same decode path as `Content-Encoding: "br"`. Regression
        // guard for the pre-fix bug where array-form encoding was
        // silently invisible to the decode logic but still stripped
        // by the base SKIP list, corrupting the body.
        use brotli::enc::BrotliEncoderParams;
        let plain = b"<h1>array-form brotli</h1>";
        let mut encoded = Vec::new();
        brotli::BrotliCompress(
            &mut &plain[..],
            &mut encoded,
            &BrotliEncoderParams::default(),
        )
        .expect("brotli encode");
        let b64 = B64.encode(&encoded);
        let body = format!(
            r#"{{"s":200,"h":{{"content-encoding":["br"]}},"b":"{}"}}"#,
            b64
        );
        let raw = parse_relay_json(body.as_bytes(), true).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.ends_with("<h1>array-form brotli</h1>"));
        assert!(
            !s.to_ascii_lowercase().contains("content-encoding"),
            "array-form br must take the strip path after successful decode"
        );
    }

    #[test]
    fn apps_script_lang_query_string_present_in_exec_path() {
        let json = r#"{
            "mode": "apps_script",
            "google_ip": "127.0.0.1",
            "front_domain": "www.google.com",
            "script_id": "TEST",
            "auth_key": "test_auth_key"
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let fronter = DomainFronter::new(&cfg).expect("test fronter must construct");
        assert_eq!(
            fronter.exec_path_for("ABCDEF"),
            "/macros/s/ABCDEF/exec?hl=en"
        );
    }

    #[test]
    fn apps_script_lang_resolved_falls_back_on_blank_override() {
        let json = r#"{
            "mode": "apps_script",
            "google_ip": "127.0.0.1",
            "front_domain": "www.google.com",
            "script_id": "TEST",
            "auth_key": "test_auth_key",
            "apps_script_lang": "   "
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.apps_script_lang_resolved(), "en");
    }

    #[test]
    fn apps_script_lang_resolved_rejects_url_injection_attempts() {
        // Hand-edited configs can contain values that would smuggle
        // extra query parameters into the `?hl=` URL or break HTTP
        // header serialization. The sanitiser falls back to `"en"` for
        // anything outside the BCP47-ish whitelist so the wire shape
        // stays predictable regardless of file contents.
        for bad in [
            "en&foo=bar",
            "en\r\nX-Injected: header",
            "en us",
            "en/../etc",
            "en;quality=0.1",
            "fa%2F",
            "中文",
            "-en",
            "en-",
            "x".repeat(64).as_str(),
        ] {
            let json = format!(
                r#"{{"mode":"apps_script","google_ip":"127.0.0.1","front_domain":"www.google.com","script_id":"TEST","auth_key":"test_auth_key","apps_script_lang":{}}}"#,
                serde_json::to_string(bad).unwrap()
            );
            let cfg: Config = serde_json::from_str(&json).unwrap();
            assert_eq!(
                cfg.apps_script_lang_resolved(),
                "en",
                "bad value {:?} must fall back to en",
                bad
            );
        }
        // Valid BCP47-ish tags round-trip lowercase.
        for (input, expected) in [
            ("en", "en"),
            ("EN", "en"),
            ("en-US", "en-us"),
            ("fa-IR", "fa-ir"),
            ("zh-CN", "zh-cn"),
        ] {
            let json = format!(
                r#"{{"mode":"apps_script","google_ip":"127.0.0.1","front_domain":"www.google.com","script_id":"TEST","auth_key":"test_auth_key","apps_script_lang":{}}}"#,
                serde_json::to_string(input).unwrap()
            );
            let cfg: Config = serde_json::from_str(&json).unwrap();
            assert_eq!(cfg.apps_script_lang_resolved(), expected);
        }
    }

    #[test]
    fn accept_language_for_lang_keeps_browser_shape_for_english() {
        // `en` keeps the wire fingerprint that pre-port traffic showed,
        // so existing DPI heuristics don't flip on the new header.
        assert_eq!(accept_language_for_lang("en"), "en-US,en;q=0.9");
        assert_eq!(accept_language_for_lang(""), "en-US,en;q=0.9");
        // Non-default tags use the simpler `<tag>;q=0.9` form.
        assert_eq!(accept_language_for_lang("fa"), "fa;q=0.9");
        assert_eq!(accept_language_for_lang("zh-cn"), "zh-cn;q=0.9");
    }

    #[test]
    fn probe_indicates_recovery_decides_per_result_shape() {
        // Healthy 200 — relay returned bytes. Probe clears the SID.
        assert!(probe_indicates_recovery(&Ok::<Vec<u8>, _>(b"ok".to_vec())));

        // Permanent envelope — the script returned a quota / auth /
        // deploy / admin string. do_relay_once_with already re-blacklisted
        // the SID before returning Err; this helper must return false
        // so the probe path skips the CAS clear (defence in depth: the
        // CAS would also fail because `until` was rewritten).
        for msg in [
            "Service invoked too many times for one day: urlfetch",
            "Authorization is required to perform that action.",
            "Error code Not_Found",
            "Domain policy has disabled this Apps Script.",
        ] {
            let err: Result<Vec<u8>, FronterError> = Err(FronterError::Relay(msg.into()));
            assert!(
                !probe_indicates_recovery(&err),
                "permanent envelope must not indicate recovery: {:?}",
                msg
            );
        }

        // Transient envelope — Apps Script returned but the script
        // itself hit a hiccup. The deployment is reachable, so the
        // probe should recover (clear the blacklist entry).
        let err: Result<Vec<u8>, FronterError> = Err(FronterError::Relay(
            "Server not available. Please try again later.".into(),
        ));
        assert!(
            probe_indicates_recovery(&err),
            "transient envelope must indicate recovery (deployment reachable)"
        );

        // Transport-level failure — the probe never reached Apps Script
        // or got back a non-`Relay` failure. Can't conclude anything
        // about deployment health.
        let err: Result<Vec<u8>, FronterError> = Err(FronterError::Timeout);
        assert!(!probe_indicates_recovery(&err));
        let err: Result<Vec<u8>, FronterError> = Err(FronterError::BadResponse("bad".into()));
        assert!(!probe_indicates_recovery(&err));
    }

    #[test]
    fn apply_probe_recovery_end_to_end_decision_matrix() {
        // The four CAS-step outcomes a probe can hit, driven by hand
        // so the test doesn't depend on the relay pipeline:
        //
        //   1. Captured `until` matches the live entry → clear it.
        //   2. Captured `until` doesn't match (concurrent rewrite) →
        //      keep the entry.
        //   3. Entry no longer in the map (TTL expired during probe)
        //      → no-op.
        //
        // Together with `probe_indicates_recovery` this covers the
        // full probe decision tree without needing a live h2/h1 server.
        let fronter = fronter_for_test(false);

        // (1) Healthy probe + matching captured_until → Cleared.
        fronter.blacklist_script("HEALTHY_SID", "first ban");
        let until_healthy = fronter
            .blacklist
            .lock()
            .unwrap()
            .get("HEALTHY_SID")
            .map(|e| e.until)
            .expect("entry just inserted");
        assert_eq!(
            fronter.apply_probe_recovery("HEALTHY_SID", until_healthy),
            ProbeApplyResult::Cleared,
        );
        assert!(
            !fronter
                .blacklist
                .lock()
                .unwrap()
                .contains_key("HEALTHY_SID"),
            "Cleared outcome must remove the entry from the map"
        );

        // (2) Healthy probe + stale captured_until → RewrittenInFlight.
        fronter.blacklist_script("RACE_SID", "first ban");
        let stale_until = fronter
            .blacklist
            .lock()
            .unwrap()
            .get("RACE_SID")
            .map(|e| e.until)
            .expect("first entry");
        // A second blacklist write lands while the probe is in flight.
        // Sleep ensures the new `Instant::now()` is strictly greater so
        // `until` actually changes.
        std::thread::sleep(Duration::from_millis(2));
        fronter.blacklist_script("RACE_SID", "second ban — cooldown extended");
        assert_eq!(
            fronter.apply_probe_recovery("RACE_SID", stale_until),
            ProbeApplyResult::RewrittenInFlight,
        );
        assert!(
            fronter.blacklist.lock().unwrap().contains_key("RACE_SID"),
            "RewrittenInFlight must preserve the (rewritten) entry"
        );

        // (3) Probe finishes after the entry's TTL ran out → AlreadyExpired.
        // We simulate by capturing a synthetic `until` and never inserting.
        assert_eq!(
            fronter.apply_probe_recovery("MISSING_SID", Instant::now()),
            ProbeApplyResult::AlreadyExpired,
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_round_trip_sends_accept_language_paired_with_apps_script_lang() {
        // Wire-level proof that the new `apps_script_accept_lang` field
        // is actually transmitted on the initial POST. The h2c server
        // captures the request headers; we assert that
        // `accept-language` carries `en-US,en;q=0.9` for the default
        // `apps_script_lang = "en"` (preserving the existing wire
        // fingerprint).
        let captured = Arc::new(std::sync::Mutex::new(None::<http::HeaderMap>));
        let cap_clone = captured.clone();
        let (addr, server_handle) = spawn_h2c_server(move |req| {
            *cap_clone.lock().unwrap() = Some(req.headers().clone());
            let resp = http::Response::builder().status(200).body(()).unwrap();
            (resp, b"ok".to_vec())
        })
        .await;
        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let (status, _hdrs, _body) = fronter
            .h2_round_trip(
                send,
                "POST",
                "/macros/s/TEST/exec?hl=en",
                "127.0.0.1",
                Bytes::from_static(b"{}"),
                Some("application/json"),
                TEST_RESPONSE_DEADLINE,
            )
            .await
            .expect("h2 round trip");
        assert_eq!(status, 200);
        let headers = captured
            .lock()
            .unwrap()
            .clone()
            .expect("server must have captured a request");
        assert_eq!(
            headers
                .get("accept-language")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "en-US,en;q=0.9",
            "default apps_script_lang=en must produce the browser-shaped header"
        );
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_does_not_clear_timeout_strike_blacklist() {
        // record_timeout_strike writes a probe-disowned entry. Even when
        // the SID is technically in the blacklist map, the probe loop
        // must not touch it — timeout strikes can be triggered by
        // network conditions a generic example.com roundtrip can't
        // diagnose, so silent recovery would put real traffic back on a
        // still-hung deployment.
        let fronter = fronter_for_test(false);
        // Pretend a deployment hit the strike limit.
        fronter.blacklist_script_for(
            "STRIKE_SID",
            Duration::from_secs(60),
            "synthetic timeout strike",
        );
        assert!(fronter.blacklist.lock().unwrap().contains_key("STRIKE_SID"));
        // probe_blacklisted_once filters by probe_recoverable, so the
        // network is never touched: this returns immediately and the
        // entry stays put.
        fronter.probe_blacklisted_once().await;
        let bl = fronter.blacklist.lock().unwrap();
        let entry = bl.get("STRIKE_SID").expect("entry must remain blacklisted");
        assert!(
            !entry.probe_recoverable,
            "strike entries must stay probe-disowned"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_one_sid_capture_until_blocks_clearing_rewritten_entry() {
        // A probe-recoverable entry that's rewritten while the probe is
        // in flight (longer cooldown, new reason) must survive the
        // probe's `remove` call. We simulate the race by writing entry
        // A, capturing its `until`, rewriting it with a different
        // `until`, and asking the probe-side compare-and-swap to clear
        // it. The rewrite wins.
        let fronter = fronter_for_test(false);
        fronter.blacklist_script("RACE_SID", "first ban");
        let first_until = fronter
            .blacklist
            .lock()
            .unwrap()
            .get("RACE_SID")
            .map(|e| e.until)
            .expect("first entry");
        // Rewrite — simulates a concurrent blacklist write landing
        // between probe issue and probe completion. Sleep ensures the
        // new `Instant::now()` is strictly greater so equality fails.
        tokio::time::sleep(Duration::from_millis(2)).await;
        fronter.blacklist_script("RACE_SID", "second ban (different reason)");
        let second_until = fronter
            .blacklist
            .lock()
            .unwrap()
            .get("RACE_SID")
            .map(|e| e.until)
            .expect("second entry");
        assert_ne!(
            first_until, second_until,
            "rewrite must produce a different `until`"
        );

        // Hand-run the compare-and-swap step the probe uses on a
        // healthy reply. The captured `until` no longer matches, so the
        // entry must remain.
        let bl = fronter.blacklist.lock().unwrap();
        let still_ours = bl
            .get("RACE_SID")
            .map(|e| e.until == first_until)
            .unwrap_or(false);
        assert!(
            !still_ours,
            "compare-and-swap must reject the stale captured `until`"
        );
        // The probe would `return` early at this point — assert that
        // the entry stays in the map.
        assert!(bl.contains_key("RACE_SID"));
    }

    #[test]
    fn mask_script_id_hides_middle() {
        assert_eq!(mask_script_id("short"), "***");
        assert_eq!(mask_script_id("AKfycbx1234567890abcdef"), "AKfy...cdef");
    }

    #[test]
    fn parallel_relay_only_safe_for_idempotent_methods() {
        // Locks down #743: parallel_relay must never fan-out non-idempotent
        // methods because Apps Script can't be cancelled mid-request, so
        // every concurrent attempt completes server-side and side-effects
        // duplicate at the destination (comment posted twice, etc.).
        for safe in ["GET", "HEAD", "OPTIONS", "get", "head", "options"] {
            assert!(
                is_method_safe_for_fanout(safe),
                "{} should be safe for fan-out (idempotent per RFC 9110)",
                safe,
            );
        }
        for unsafe_m in [
            "POST", "PUT", "PATCH", "DELETE", "post", "put", "patch", "delete",
        ] {
            assert!(
                !is_method_safe_for_fanout(unsafe_m),
                "{} must NOT be safe for fan-out (non-idempotent — duplicate side-effects)",
                unsafe_m,
            );
        }
        // Unknown methods (CONNECT, TRACE, custom verbs) default to NOT
        // safe — conservative call, matches the upstream `UrlFetchApp`
        // lookup behavior.
        for unknown in ["CONNECT", "TRACE", "PROPFIND", ""] {
            assert!(
                !is_method_safe_for_fanout(unknown),
                "{} must default to NOT safe for fan-out when unrecognised",
                unknown,
            );
        }
    }

    #[test]
    fn parse_relay_array_set_cookie() {
        let body = r#"{"s":200,"h":{"Set-Cookie":["a=1","b=2"]},"b":""}"#;
        let raw = parse_relay_json(body.as_bytes(), false).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("Set-Cookie: a=1\r\n"));
        assert!(s.contains("Set-Cookie: b=2\r\n"));
    }

    #[test]
    fn decode_js_string_escapes_xnn_and_unicode() {
        // \x7b = '{', \x22 = '"', \x7d = '}', \x5b = '[', \x5d = ']'
        let inner = r#"\x7b\x22s\x22:200,\x22b\x22:\x22\x22\x7d"#;
        let out = decode_js_string_escapes(inner).unwrap();
        assert_eq!(out, r#"{"s":200,"b":""}"#);

        // A = 'A', mixed with literal
        assert_eq!(decode_js_string_escapes(r"ABC").unwrap(), "ABC");

        // standard escapes
        assert_eq!(
            decode_js_string_escapes(r#"a\nb\t\\\"c"#).unwrap(),
            "a\nb\t\\\"c"
        );

        // truncated escape returns None instead of panicking
        assert!(decode_js_string_escapes(r"\x7").is_none());
        assert!(decode_js_string_escapes(r"\u00").is_none());
    }

    /// Hand-build the `goog.script.init("...", "", undefined)` wrapper for
    /// a given inner relay JSON, matching the form Apps Script HtmlService
    /// emits when the deployment uses HtmlService for its response. Every
    /// `{`/`}` becomes `\x7b`/`\x7d`, every `"` becomes `\"`, every `:`
    /// stays — that's the realistic subset our unwrapper has to cope with.
    fn build_goog_script_init_wrapper(inner_relay_json: &str) -> String {
        // Step 1: build the outer JSON object {"userHtml": "<inner>", ...}
        // using serde so the inner JSON is properly JSON-escaped (including
        // each `"` → `\"`).
        let outer = serde_json::json!({ "userHtml": inner_relay_json });
        let outer_str = serde_json::to_string(&outer).unwrap();
        // Step 2: re-escape `{`/`}` → `\xNN` and `"` → `\"` to match the
        // form Apps Script wraps inside the `goog.script.init("…")`
        // JS string literal.
        let mut wire = String::with_capacity(outer_str.len() * 2);
        for ch in outer_str.chars() {
            match ch {
                '{' => wire.push_str(r"\x7b"),
                '}' => wire.push_str(r"\x7d"),
                '"' => wire.push_str(r#"\""#),
                other => wire.push(other),
            }
        }
        format!(
            "<html><body><script>goog.script.init(\"{}\", \"\", undefined);</script></body></html>",
            wire
        )
    }

    #[test]
    fn extract_apps_script_user_html_unwraps_goog_init() {
        let inner_json = r#"{"s":200,"h":{},"b":"aGk="}"#;
        let wrapped = build_goog_script_init_wrapper(inner_json);
        let extracted = extract_apps_script_user_html(&wrapped).unwrap();
        assert_eq!(extracted, inner_json);
    }

    #[test]
    fn parse_relay_json_unwraps_goog_script_init() {
        // End-to-end: an iframe-wrapped body should still parse correctly
        // through parse_relay_json. Without the unwrap helper this used
        // to fail with `key must be a string at line 2`.
        let inner_json = r#"{"s":200,"h":{},"b":""}"#;
        let wrapped = build_goog_script_init_wrapper(inner_json);
        let raw = parse_relay_json(wrapped.as_bytes(), false).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("HTTP/1.1 200 "), "got: {}", s);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_consumes_final_crlf_and_trailers() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\nX-Test: 1\r\n\r\n",
            )
            .await
            .unwrap();

        let (status, _headers, body) = read_http_response(&mut server).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"Hello");

        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();

        let (status2, _headers2, body2) = read_http_response(&mut server).await.unwrap();
        assert_eq!(status2, 200);
        assert_eq!(body2, b"OK");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn content_length_reader_rejects_truncated_body() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHel")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(
                    msg.contains("full response body"),
                    "unexpected error: {}",
                    msg
                );
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_rejects_truncated_chunk_body() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHel")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("mid-chunked"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_rejects_missing_chunk_crlf() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHelloXX")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("trailing CRLF"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    // ─── h2 transport ──────────────────────────────────────────────────

    /// Generous response-phase deadline used by transport tests. We
    /// pick something well above any expected latency on a localhost
    /// h2c hop so test flakiness can't be confused with a real timeout
    /// firing. Tests that *want* to observe a timeout pick a small
    /// value explicitly.
    const TEST_RESPONSE_DEADLINE: Duration = Duration::from_secs(10);

    /// Build a minimal valid `DomainFronter` for unit tests. The
    /// `connect_host` is unused unless a test actually opens a socket;
    /// `verify_ssl=true` and a placeholder `google_ip` are fine because
    /// `DomainFronter::new` doesn't touch the network.
    fn fronter_for_test(force_http1: bool) -> DomainFronter {
        fronter_for_test_with(force_http1, true)
    }

    /// `fronter_for_test` plus a `sabr_strip` knob for the SABR
    /// kill-switch gate tests. Lets the tests prove the runtime
    /// behaviour at the `relay()` strip-decision branch — not just
    /// the config-default round-trip.
    fn fronter_for_test_with(force_http1: bool, sabr_strip: bool) -> DomainFronter {
        let json = format!(
            r#"{{
                "mode": "apps_script",
                "google_ip": "127.0.0.1",
                "front_domain": "www.google.com",
                "script_id": "TEST",
                "auth_key": "test_auth_key",
                "listen_host": "127.0.0.1",
                "listen_port": 8085,
                "log_level": "info",
                "verify_ssl": true,
                "force_http1": {},
                "sabr_strip": {}
            }}"#,
            force_http1, sabr_strip
        );
        let cfg: Config = serde_json::from_str(&json).unwrap();
        DomainFronter::new(&cfg).expect("test fronter must construct")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn force_http1_disables_h2_at_construction() {
        // The kill switch: force_http1=true must mark the fronter as
        // h2-disabled before the first call so ensure_h2 short-circuits
        // without ever trying ALPN.
        let fronter = fronter_for_test(true);
        assert!(
            fronter.h2_disabled.load(Ordering::Relaxed),
            "force_http1=true must set h2_disabled at construction"
        );
        assert!(
            fronter.ensure_h2().await.is_none(),
            "ensure_h2 must return None when h2 is disabled"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn force_http1_false_leaves_h2_enabled() {
        let fronter = fronter_for_test(false);
        assert!(
            !fronter.h2_disabled.load(Ordering::Relaxed),
            "default must leave h2 enabled"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poison_h2_if_gen_is_noop_when_cell_is_empty() {
        // Defensive: we call poison on every per-request error; cell
        // may already be None due to a concurrent poison. Must not
        // panic or wedge.
        let fronter = fronter_for_test(false);
        fronter.poison_h2_if_gen(0).await;
        let cell = fronter.h2_cell.lock().await;
        assert!(cell.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poison_h2_if_gen_only_clears_matching_generation() {
        // Race protection: task A holds gen=1 SendRequest, gen=1 dies,
        // task B reopens → cell now gen=2 (healthy). Task A's
        // poison(1) MUST NOT clear gen=2. Without generation matching
        // the previous code unconditionally cleared the cell, causing
        // connection churn during recovery.
        let (addr, server_handle) = spawn_h2c_server(|_req| {
            let resp = http::Response::builder().status(200).body(()).unwrap();
            (resp, Vec::new())
        })
        .await;
        let send_v2 = h2c_client(addr).await;

        let fronter = fronter_for_test(false);
        // Seed the cell with gen=2 (simulating "task B just reopened").
        {
            let mut cell = fronter.h2_cell.lock().await;
            *cell = Some(H2Cell {
                send: send_v2.clone(),
                created: Instant::now(),
                generation: 2,
                dead: Arc::new(AtomicBool::new(false)),
                host: fronter.connect_host.load_full(),
            });
        }
        // Task A poisons with stale gen=1.
        fronter.poison_h2_if_gen(1).await;
        // gen=2 cell must survive.
        let cell = fronter.h2_cell.lock().await;
        assert!(
            cell.is_some(),
            "poison_h2_if_gen(1) must not clear gen=2 cell"
        );
        assert_eq!(cell.as_ref().unwrap().generation, 2);
        drop(cell);

        // And matching gen=2 actually does clear.
        fronter.poison_h2_if_gen(2).await;
        let cell = fronter.h2_cell.lock().await;
        assert!(cell.is_none(), "poison_h2_if_gen(2) must clear gen=2 cell");

        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ensure_h2_rejects_dead_cell_within_ttl() {
        // Cell is within H2_CONN_TTL_SECS but the connection driver
        // already flipped `dead` (e.g., upstream sent GOAWAY). Without
        // the dead-flag check `ensure_h2` would happily hand out the
        // stale SendRequest and the next request would pay a wasted
        // h2 round trip to discover the breakage. With the check in
        // place a second pre-existing healthy cell still works fine —
        // the dead one is replaced via the open-lock path.
        let (addr, server_handle) = spawn_h2c_server(|_req| {
            let resp = http::Response::builder().status(200).body(()).unwrap();
            (resp, Vec::new())
        })
        .await;
        let send = h2c_client(addr).await;

        let fronter = fronter_for_test(false);
        let dead = Arc::new(AtomicBool::new(true)); // simulate driver having exited
        {
            let mut cell = fronter.h2_cell.lock().await;
            *cell = Some(H2Cell {
                send,
                created: Instant::now(), // well within TTL
                generation: 1,
                dead: dead.clone(),
                host: fronter.connect_host.load_full(),
            });
        }

        // The fast path normally returns Some(send, gen) when the cell
        // is within TTL. With dead=true it must NOT return the stale
        // SendRequest. Pre-set the failure-backoff timestamp so
        // ensure_h2 short-circuits at the backoff check (no network
        // I/O) regardless of whatever's bound on 127.0.0.1:443 on the
        // dev/CI host. This isolates the assertion to the new
        // dead-flag check.
        *fronter.h2_open_failed_at.lock().await = Some(Instant::now());

        let result = fronter.ensure_h2().await;
        assert!(
            result.is_none(),
            "ensure_h2 must not serve a cell whose driver flipped `dead`"
        );

        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ensure_h2_skips_reopen_during_failure_backoff() {
        // After an open failure, ensure_h2 must return None for at
        // least H2_OPEN_FAILURE_BACKOFF_SECS without attempting a
        // new handshake — otherwise concurrent callers each pay the
        // full handshake-timeout cost during an outage.
        let fronter = fronter_for_test(false);
        // Simulate a recent open failure.
        *fronter.h2_open_failed_at.lock().await = Some(Instant::now());

        // ensure_h2 must return None immediately, without trying open_h2
        // (open_h2 would try TCP-connect to 127.0.0.1:443 which would
        // either fail slowly or succeed against an unrelated service —
        // either way, this test would observably take longer if backoff
        // wasn't honored).
        let t0 = Instant::now();
        let result = fronter.ensure_h2().await;
        assert!(result.is_none(), "must return None during backoff");
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "must return immediately without open attempt; took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_pinger_marks_dead_when_peer_stops_responding_to_pings() {
        // The whole reason for the pinger: a middlebox can silently
        // swallow long-lived TCP traffic (no RST, no FIN), leaving the
        // h2 driver future blocked on a read that never errors. Without
        // the pinger the cell looks alive forever and `ensure_h2` keeps
        // handing out a poisoned SendRequest until the user restarts
        // the app. With the pinger, an unanswered PONG flips `dead`
        // within `interval + timeout`.
        //
        // We use real (sub-second) timings here rather than the
        // production-tuned 15 s / 10 s — `tokio::time::pause()` would
        // require real socket I/O to also be virtual, which it isn't.
        // The helper is parameterized on interval / timeout precisely
        // to keep this test deterministic and fast.
        let interval = Duration::from_millis(100);
        let timeout = Duration::from_millis(200);

        let (addr, server) = spawn_silent_h2c_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (_send, conn) = h2::client::handshake(stream).await.unwrap();
        let dead = DomainFronter::spawn_h2_driver_with_ping_liveness(conn, interval, timeout);
        assert!(
            !dead.load(Ordering::Relaxed),
            "dead must start false on a fresh connection"
        );

        // Wait past `interval + timeout + slack`. Pinger sends the
        // first PING after `interval`, then the `timeout` future fires
        // because the silent server never PONGs. `select!` resolves on
        // the pinger branch, dead.store(true) runs.
        tokio::time::sleep(interval + timeout + Duration::from_millis(300)).await;

        assert!(
            dead.load(Ordering::Relaxed),
            "pinger must flip `dead` after the silent peer fails to send PONG"
        );

        server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_pinger_stays_quiet_on_responsive_peer() {
        // Symmetric negative test: against a server that DOES process
        // frames (the regular h2c server, which auto-PONGs PINGs), the
        // pinger must never flip `dead`. Guards against tuning the
        // timeout so tight that healthy connections false-positive
        // close, and against any future change that breaks the
        // pinger's `Ok(Ok(_))` continue branch.
        //
        // Generous timeout (5 s) on purpose: a stressed CI runner could
        // delay a local PONG round-trip past a tight cap and false-fail
        // this test. The interval stays short to keep the test fast.
        let interval = Duration::from_millis(100);
        let timeout = Duration::from_secs(5);

        let (addr, server) = spawn_h2c_server(|_req| {
            let resp = http::Response::builder().status(200).body(()).unwrap();
            (resp, Vec::new())
        })
        .await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (_send, conn) = h2::client::handshake(stream).await.unwrap();
        let dead = DomainFronter::spawn_h2_driver_with_ping_liveness(conn, interval, timeout);

        // Five PING cycles. A responsive server PONGs immediately,
        // pinger logs `h2 ping ok`, loops. `dead` must stay false.
        tokio::time::sleep(interval * 5 + Duration::from_millis(100)).await;
        assert!(
            !dead.load(Ordering::Relaxed),
            "responsive peer must not cause the pinger to flip `dead`"
        );

        server.abort();
    }

    /// Spawn a TCP listener that completes the h2 server handshake but
    /// then stops processing frames — holding the connection without
    /// polling. The TCP socket stays open (we still own the
    /// `connection`), so client PINGs are written to the wire, but the
    /// server never reads or responds to them. Simulates the silent-drop
    /// middlebox behavior we're trying to defend against on Iran ISPs.
    async fn spawn_silent_h2c_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // `handshake` only completes after the initial SETTINGS
            // exchange; after that we suspend without polling
            // `connection` further, which freezes frame processing on
            // this side while keeping the TCP socket alive.
            let _connection = h2::server::handshake(sock).await.unwrap();
            std::future::pending::<()>().await;
        });
        (addr, handle)
    }

    /// Spawn a minimal local h2c server (plaintext h2, no TLS) on a
    /// random port. The handler closure builds the response from the
    /// incoming request — used by `h2_round_trip_*` tests below.
    /// Returns the bound address and the JoinHandle so the test can
    /// `abort()` the server when done.
    async fn spawn_h2c_server<F>(handler: F) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: Fn(http::Request<h2::RecvStream>) -> (http::Response<()>, Vec<u8>)
            + Send
            + Sync
            + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let handle = tokio::spawn(async move {
            // Single-connection server is enough for these tests.
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (req, mut respond) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let (resp, body) = handler(req);
                let has_body = !body.is_empty();
                let mut send = respond
                    .send_response(resp, !has_body)
                    .expect("send_response in test");
                if has_body {
                    send.send_data(Bytes::from(body), true)
                        .expect("send_data in test");
                }
            }
        });
        (addr, handle)
    }

    /// Variant that gives the handler async access to the request body
    /// before producing the response. Needed to assert what the client
    /// actually sent (rather than relying on the request's existence).
    async fn spawn_h2c_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (req, mut respond) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let mut body = req.into_body();
                let mut received = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = match chunk {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let n = chunk.len();
                    received.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(n);
                }
                let resp = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::from(received), true).unwrap();
            }
        });
        (addr, handle)
    }

    /// Open a plaintext h2c connection to `addr` and return a usable
    /// `SendRequest<Bytes>`. The connection driver is spawned in the
    /// background and lives for the test's scope.
    async fn h2c_client(addr: std::net::SocketAddr) -> h2::client::SendRequest<Bytes> {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (send, conn) = h2::client::handshake(stream).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        send
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_round_trip_actually_transmits_post_body() {
        // Server reads the request body and echoes it. We assert the
        // server received the exact bytes we passed — proves the
        // send_data path works, not just that 200 came back.
        let (addr, server_handle) = spawn_h2c_echo_server().await;

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let req_body = b"the-actual-payload-sent-by-h2_round_trip";
        let (status, _hdrs, echoed) = fronter
            .h2_round_trip(
                send,
                "POST",
                "/echo",
                "127.0.0.1",
                Bytes::from_static(req_body),
                Some("application/json"),
                TEST_RESPONSE_DEADLINE,
            )
            .await
            .expect("h2 round trip should succeed");
        assert_eq!(status, 200);
        assert_eq!(
            echoed, req_body,
            "server must have received the exact bytes we sent"
        );
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_round_trip_decodes_gzip_responses() {
        // Mirror the h1 read_http_response behavior: gzip-encoded
        // bodies must be transparently decompressed before we hand
        // them back, so downstream JSON parsers see plain bytes
        // regardless of transport.
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let plain = b"{\"hello\":\"world\"}";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(plain).unwrap();
        let gzipped = enc.finish().unwrap();
        let gzipped_arc = Arc::new(gzipped);

        let g = gzipped_arc.clone();
        let (addr, server_handle) = spawn_h2c_server(move |_req| {
            let resp = http::Response::builder()
                .status(200)
                .header("content-encoding", "gzip")
                .body(())
                .unwrap();
            (resp, (*g).clone())
        })
        .await;

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let (status, _hdrs, body) = fronter
            .h2_round_trip(
                send,
                "GET",
                "/",
                "127.0.0.1",
                Bytes::new(),
                None,
                TEST_RESPONSE_DEADLINE,
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, plain, "gzip body must be decoded transparently");
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_follows_redirect_chain() {
        // Now exercises run_h2_relay_with_send (the testable inner
        // of h2_relay_request) so the production redirect loop —
        // including timeout, RequestSent classification, and per-hop
        // poison-by-gen — is actually under test, not a hand-rolled
        // duplicate.
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = counter.clone();
        let (addr, server_handle) = spawn_h2c_server(move |req| {
            let n = c.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                let resp = http::Response::builder()
                    .status(302)
                    .header("location", "/next")
                    .body(())
                    .unwrap();
                (resp, Vec::new())
            } else {
                assert_eq!(req.uri().path(), "/next", "second hop must follow Location");
                let resp = http::Response::builder().status(200).body(()).unwrap();
                (resp, b"final".to_vec())
            }
        })
        .await;

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);

        let (status, _hdrs, body) = fronter
            .run_h2_relay_with_send(
                send,
                /* generation */ 1,
                "/start",
                Bytes::new(),
                TEST_RESPONSE_DEADLINE,
            )
            .await
            .expect("h2 relay should follow redirect to 200");
        assert_eq!(status, 200);
        assert_eq!(body, b"final");
        // Successful round-trip must increment h2_calls.
        assert_eq!(fronter.h2_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fronter.h2_fallbacks.load(Ordering::Relaxed), 0);
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_reports_request_sent_no_on_dead_connection() {
        // Set up an h2c client whose connection is severed before we
        // call run_h2_relay_with_send. The first `send.ready().await`
        // inside h2_round_trip should fail — RequestSent::No is the
        // correct classification (stream never opened on the wire).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // Accept the connection, do the h2 handshake, then drop.
            // After drop the client's SendRequest will fail at ready().
            let (sock, _) = listener.accept().await.unwrap();
            let _connection = h2::server::handshake(sock).await.unwrap();
            // Hold briefly so client can complete handshake, then drop.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let send = h2c_client(addr).await;
        // Wait for server to drop.
        server_task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fronter = fronter_for_test(false);
        let result = fronter
            .run_h2_relay_with_send(
                send,
                1,
                "/x",
                Bytes::from_static(b"some-body"),
                TEST_RESPONSE_DEADLINE,
            )
            .await;
        match result {
            Err((_, RequestSent::No)) => {} // expected
            Err((e, RequestSent::Maybe)) => {
                panic!(
                    "dead-conn failure classified as Maybe (unsafe to retry): {}",
                    e
                )
            }
            Ok(_) => panic!("expected error against dropped server"),
        }
        // Failure must increment h2_fallbacks counter.
        assert_eq!(fronter.h2_fallbacks.load(Ordering::Relaxed), 1);
        assert_eq!(fronter.h2_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_reports_request_sent_maybe_on_post_send_reset() {
        // Server accepts headers (so the request reaches it) and then
        // resets the stream. The client sees a stream error AFTER
        // send_request returned Ok. RequestSent::Maybe is the only
        // safe classification — Apps Script may have started executing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            if let Some(Ok((_req, mut respond))) = connection.accept().await {
                // Reset the stream after receiving headers — simulates
                // the server starting to process and then bailing
                // (matches the "Apps Script started UrlFetchApp then
                // failed" scenario).
                respond.send_reset(h2::Reason::INTERNAL_ERROR);
            }
            // Keep the connection alive briefly so the client sees the
            // RST_STREAM rather than a connection-level close.
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let result = fronter
            .run_h2_relay_with_send(
                send,
                1,
                "/x",
                Bytes::from_static(b"body"),
                TEST_RESPONSE_DEADLINE,
            )
            .await;
        match result {
            Err((_, RequestSent::Maybe)) => {} // expected
            Err((e, RequestSent::No)) => panic!(
                "post-send RST classified as No — would let caller \
                 unsafely replay non-idempotent request: {}",
                e
            ),
            Ok(_) => panic!("expected error against RST_STREAM"),
        }

        server_task.await.unwrap();
    }

    // ─── NonRetryable wrapper + retry/fallback policy ────────────────────

    #[test]
    fn nonretryable_wrapper_is_not_retryable_other_variants_are() {
        // Surfaces the contract that do_relay_with_retry and the
        // exit-node fallback rely on. If this ever flips, those
        // sites would silently start re-issuing post-send failures.
        let plain = FronterError::Relay("transient".into());
        assert!(plain.is_retryable(), "plain Relay error must be retryable");

        let plain2 = FronterError::Timeout;
        assert!(plain2.is_retryable(), "Timeout must be retryable");

        let wrapped = FronterError::NonRetryable(Box::new(FronterError::Relay("post-send".into())));
        assert!(
            !wrapped.is_retryable(),
            "NonRetryable must not be retryable"
        );

        // Display must be transparent so log lines look identical.
        let inner_msg = "h2 response: stream RST".to_string();
        let inner = FronterError::Relay(inner_msg.clone());
        let wrapped = FronterError::NonRetryable(Box::new(inner));
        let displayed = wrapped.to_string();
        assert!(
            displayed.contains(&inner_msg),
            "transparent Display should surface inner: got {}",
            displayed
        );

        // into_inner unwraps once.
        let inner_again = wrapped.into_inner();
        assert!(matches!(inner_again, FronterError::Relay(_)));
        assert!(inner_again.is_retryable(), "unwrapped error is retryable");
    }

    // Note on test coverage gap: we don't have a deterministic test
    // that the ready/back-pressure phase's timeout reports
    // `RequestSent::No`. h2 client enforces remote
    // `MAX_CONCURRENT_STREAMS` at `send_request` time rather than at
    // `ready` time, so a "saturate the slots, expect ready to block"
    // setup actually races down the response-phase path instead.
    // The ready-arm code in `h2_round_trip` is small (single match
    // arm with `RequestSent::No` literally written next to the
    // timeout error) and covered by review. Other safety properties
    // (post-send Maybe via stream RST, pre-send No via dead conn,
    // NonRetryable wrap propagation) are covered by the tests above
    // and below.

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_does_not_wrap_pre_send_in_nonretryable() {
        // Regression guard: the NonRetryable wrap is the *call site's*
        // job (do_relay_once_with applies it for unsafe methods only).
        // run_h2_relay_with_send returns the raw RequestSent::No so
        // the call site can decide. If h2_relay_request started
        // wrapping unconditionally, even safe-method requests would
        // become non-retryable on transient pre-send failures.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _connection = h2::server::handshake(sock).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let send = h2c_client(addr).await;
        server_task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fronter = fronter_for_test(false);
        let result = fronter
            .run_h2_relay_with_send(
                send,
                1,
                "/x",
                Bytes::from_static(b"x"),
                TEST_RESPONSE_DEADLINE,
            )
            .await;
        match result {
            Err((e, RequestSent::No)) => {
                assert!(
                    e.is_retryable(),
                    "pre-send error must be raw FronterError, not pre-wrapped NonRetryable; got {:?}",
                    e
                );
            }
            other => panic!("expected (Err, RequestSent::No); got {:?}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sticky_disable_h2_for_fronting_refusal_flips_disabled_and_clears_cell() {
        // Verify the helper that runs from each call site's 421 arm:
        // sets h2_disabled, clears the cell, rebalances counters
        // (h2_calls -=1 since the round-trip already counted; h2_fallbacks +=1).
        // Tests the helper directly so we don't depend on a real h2
        // server returning 421 — call sites already exercise the
        // status-match wiring through code review.
        let (addr, server_handle) = spawn_h2c_server(|_req| {
            let resp = http::Response::builder().status(200).body(()).unwrap();
            (resp, Vec::new())
        })
        .await;
        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        // Seed the cell so we can verify it gets cleared.
        {
            let mut cell = fronter.h2_cell.lock().await;
            *cell = Some(H2Cell {
                send: send.clone(),
                created: Instant::now(),
                generation: 7,
                dead: Arc::new(AtomicBool::new(false)),
                host: fronter.connect_host.load_full(),
            });
        }
        // Pretend a round-trip just incremented h2_calls (which is
        // what run_h2_relay_with_send does on Ok before the call site
        // sees the 421 status).
        fronter.h2_calls.fetch_add(1, Ordering::Relaxed);

        fronter
            .sticky_disable_h2_for_fronting_refusal(421, "test context")
            .await;

        assert!(
            fronter.h2_disabled.load(Ordering::Relaxed),
            "must sticky-disable"
        );
        let cell = fronter.h2_cell.lock().await;
        assert!(cell.is_none(), "cell must be cleared");
        assert_eq!(
            fronter.h2_calls.load(Ordering::Relaxed),
            0,
            "the h2_calls increment from the failed round-trip must be reversed"
        );
        assert_eq!(
            fronter.h2_fallbacks.load(Ordering::Relaxed),
            1,
            "must count as a fallback"
        );
        drop(cell);

        // Subsequent ensure_h2 must short-circuit to None without
        // attempting to open.
        let t0 = Instant::now();
        assert!(fronter.ensure_h2().await.is_none());
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "sticky-disabled ensure_h2 must return immediately"
        );

        // Calling the helper a second time must not log again or
        // double-count fallbacks beyond +1 per call.
        fronter
            .sticky_disable_h2_for_fronting_refusal(421, "test context")
            .await;
        // h2_calls would underflow without the saturating guard; assert
        // it stays at 0.
        assert_eq!(fronter.h2_calls.load(Ordering::Relaxed), 0);
        // h2_fallbacks goes up unconditionally (this is "another
        // attempt that ended up on h1") — that's fine.
        assert_eq!(fronter.h2_fallbacks.load(Ordering::Relaxed), 2);

        server_handle.abort();
    }

    #[test]
    fn is_h2_fronting_refusal_status_only_matches_421() {
        // Guard against the helper accidentally matching ambiguous
        // edge statuses (403 could be a real Apps Script geoblock,
        // 4xx generally is not a "this is h2's fault" signal).
        assert!(is_h2_fronting_refusal_status(421));
        for s in [200, 301, 400, 403, 404, 429, 500, 502, 503] {
            assert!(
                !is_h2_fronting_refusal_status(s),
                "status {} must NOT trigger sticky h2 disable",
                s
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_handshake_post_tls_returns_alpn_refused_when_peer_picks_h1() {
        // Verify the OpenH2Error::AlpnRefused path: if the TLS layer
        // negotiated http/1.1 (not h2), the post-TLS helper must
        // return the typed sentinel that ensure_h2 uses to sticky-
        // disable. We construct a fake TlsStream by short-circuiting
        // through a real local TLS server that only advertises h1.
        //
        // This needs a real TLS handshake (rustls + a self-signed
        // cert), so we set up the smallest possible test server with
        // ALPN forced to ["http/1.1"].
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // Drive the handshake; the test only needs the negotiation
            // to complete with ALPN=h1. After that we can drop.
            let _tls = acceptor.accept(sock).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        // Client side: open TLS with ALPN advertising h2 + h1.1; the
        // server picks h1 → alpn_protocol() returns "http/1.1" not "h2".
        let mut client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let tls = connector.connect(name, tcp).await.unwrap();

        let result = DomainFronter::h2_handshake_post_tls(tls).await;
        match result {
            Err(OpenH2Error::AlpnRefused) => {} // expected
            Err(other) => panic!("expected AlpnRefused, got {:?}", other),
            Ok((_send, _dead)) => panic!("expected AlpnRefused, got Ok"),
        }
        server.await.unwrap();
    }

    // ── SABR quality-track strip (commits 9b6d03e + 33db28a) ─────────────

    /// Encode a single varint at the front of a buffer.
    fn enc_varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    /// Encode a single length-delimited (wire-type 2) field.
    fn enc_length_delim(out: &mut Vec<u8>, field: u32, payload: &[u8]) {
        enc_varint(out, ((field as u64) << 3) | 2);
        enc_varint(out, payload.len() as u64);
        out.extend_from_slice(payload);
    }

    /// Encode a single varint (wire-type 0) field.
    fn enc_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
        // Wire-type 0 is the zero bits; explicit `| 0` would be clippy
        // `identity_op`. The shift is the entire encoding.
        enc_varint(out, (field as u64) << 3);
        enc_varint(out, value);
    }

    #[test]
    fn sabr_strip_keeps_sole_field3_unchanged() {
        // The #977 regression case from unacoder's testing: a
        // segment-fetch body with exactly ONE field-3 entry (the
        // single-track request the player sends at low/medium quality).
        // The original "strip all field-3" rule turned this into a
        // request with zero tracks selected, which googlevideo answered
        // with an empty body — buffer never advanced, player retried
        // 11+ times with `rn=` incrementing. Keep-first heuristic
        // returns the body unchanged so the player gets a valid
        // single-track response.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"range-descriptor");
        enc_length_delim(&mut body, 3, b"sole-quality-track");
        enc_varint_field(&mut body, 4, 12345);

        // No transform: 1 field-3 < 2-entry threshold.
        assert_eq!(strip_sabr_quality_tracks(&body), body);
    }

    #[test]
    fn sabr_strip_segment_fetch_keeps_first_field3_strips_rest() {
        // Segment-fetch shape with TWO field-3 entries (multi-track
        // bundling). The first field-3 is kept (preserves a single
        // track on the wire so googlevideo has something to send); the
        // second is stripped (caps the response under 10 MB). Other
        // fields pass through unchanged.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"range-descriptor-1");
        enc_length_delim(&mut body, 3, b"quality-track-selector-1");
        enc_length_delim(&mut body, 2, b"range-descriptor-2");
        enc_length_delim(&mut body, 3, b"quality-track-selector-2");
        enc_varint_field(&mut body, 4, 12345); // some other field

        let mut expected: Vec<u8> = Vec::new();
        enc_length_delim(&mut expected, 2, b"range-descriptor-1");
        enc_length_delim(&mut expected, 3, b"quality-track-selector-1"); // KEPT
        enc_length_delim(&mut expected, 2, b"range-descriptor-2");
        // quality-track-selector-2: STRIPPED
        enc_varint_field(&mut expected, 4, 12345);

        assert_eq!(strip_sabr_quality_tracks(&body), expected);
    }

    #[test]
    fn sabr_strip_session_init_leaves_field3_alone() {
        // Session-init shape: has field-5 entries and field-3, but NO
        // field-2. Field-3 here is essential session metadata —
        // stripping it would corrupt the handshake → CDN 403. Heuristic:
        // require field-2 presence before stripping field-3.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 5, b"session-context");
        enc_length_delim(&mut body, 3, b"language-and-state-metadata");
        enc_varint_field(&mut body, 7, 1);

        let original = body.clone();
        // Untouched.
        assert_eq!(strip_sabr_quality_tracks(&body), original);
    }

    #[test]
    fn sabr_strip_no_field3_is_noop() {
        // Plain segment-fetch with only field-2 entries — nothing to strip.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"only-range-descriptors");
        enc_length_delim(&mut body, 2, b"more-range-descriptors");

        let original = body.clone();
        assert_eq!(strip_sabr_quality_tracks(&body), original);
    }

    #[test]
    fn sabr_strip_empty_body_is_noop() {
        assert_eq!(strip_sabr_quality_tracks(b""), b"");
    }

    #[test]
    fn sabr_strip_truncated_tag_preserves_remainder_verbatim() {
        // A field-2 entry followed by a truncated varint tag (high bit
        // set, no continuation byte). Strip should bail at the truncated
        // tag, copying the remaining bytes verbatim — never silently
        // dropping the tail.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"first-entry");
        // Truncated: high bit set, then EOF.
        body.push(0x80);

        let result = strip_sabr_quality_tracks(&body);
        // Body had no field-3 to strip → entire input returned.
        assert_eq!(result, body);
    }

    #[test]
    fn sabr_strip_truncated_tag_after_single_field3_is_noop() {
        // field-2 + ONE field-3 (single-track request) + truncated tag.
        // Under the keep-first heuristic, single field-3 is preserved
        // → strip is a no-op → body returned verbatim (truncated tail
        // included). The original behaviour was to strip the sole
        // field-3 here, but that's exactly the regression #977
        // identified.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"range-desc");
        enc_length_delim(&mut body, 3, b"quality-track");
        body.push(0x80); // truncated tag

        // No transform — single field-3 < 2-entry threshold.
        assert_eq!(strip_sabr_quality_tracks(&body), body);
    }

    #[test]
    fn sabr_strip_unknown_wire_type_preserves_remainder() {
        // Wire type 6 (unused / reserved) — the strip should bail at
        // the unknown wire type and copy the rest verbatim. Build it
        // manually so we control the wire-type bits.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"first-range");
        // tag = (field 9 << 3) | wire 6 = 0x4E
        body.push(0x4E);
        body.extend_from_slice(b"\x01\x02\x03"); // some bytes after

        // No field-3 ever seen → nothing to strip → full body returned.
        assert_eq!(strip_sabr_quality_tracks(&body), body);
    }

    #[test]
    fn sabr_strip_truncated_field3_payload_preserves_segment_verbatim() {
        // field-2 (legitimate range descriptor) followed by a TRUNCATED
        // field-3 entry: the length varint says 100 bytes but only 5 are
        // present. The original `i.saturating_add(val_len).min(n)` would
        // have clamped to EOF and let the segment be stripped, silently
        // dropping the partial bytes. Correct behaviour: bail at the
        // truncated payload and emit everything from there to EOF
        // verbatim, untouched.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"good-range");
        // Manually emit a truncated field-3 length-delimited header:
        // tag = (field 3 << 3) | 2 = 0x1A, len = 100, then only 5 bytes.
        body.push(0x1A);
        body.push(100); // declares 100-byte payload
        body.extend_from_slice(b"short");

        let mut expected: Vec<u8> = Vec::new();
        enc_length_delim(&mut expected, 2, b"good-range");
        // Truncated tail copied verbatim from where field-3 starts.
        expected.push(0x1A);
        expected.push(100);
        expected.extend_from_slice(b"short");

        assert_eq!(strip_sabr_quality_tracks(&body), expected);
    }

    #[test]
    fn sabr_strip_truncated_field2_payload_preserves_segment_verbatim() {
        // Even segment-fetch detection must not over-eagerly believe a
        // truncated field-2 is real — the segment-fetch heuristic only
        // fires on COMPLETE field-2 entries. Here field-2 is truncated;
        // the parser bails at it and the malformed tail is preserved.
        let mut body: Vec<u8> = Vec::new();
        // Tag = field 2, wire 2 = 0x12, declared len = 50, only 3 bytes.
        body.push(0x12);
        body.push(50);
        body.extend_from_slice(b"abc");

        // No prior field-2 OR field-3 captured → strip is a no-op
        // and returns the buffer unchanged.
        assert_eq!(strip_sabr_quality_tracks(&body), body);
    }

    #[test]
    fn sabr_strip_truncated_fixed_width_with_single_field3_is_noop() {
        // 64-bit fixed (wire type 1) — only 3 of 8 bytes present. The
        // bail-on-truncated-payload behaviour is unchanged; what's
        // different from the older "strip all field-3" version is
        // that a SOLE field-3 is now kept (keep-first heuristic),
        // so the body comes back unchanged.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"r");
        enc_length_delim(&mut body, 3, b"q"); // sole field-3 → kept
        body.push(0x21);
        body.extend_from_slice(b"\x01\x02\x03");

        assert_eq!(strip_sabr_quality_tracks(&body), body);
    }

    #[test]
    fn sabr_strip_truncated_fixed_width_with_two_field3_strips_extras() {
        // Same fixed-width-truncation shape, but with TWO field-3
        // entries. Keep-first rule fires: first field-3 kept, second
        // stripped, malformed tail verbatim.
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"r");
        enc_length_delim(&mut body, 3, b"q1");
        enc_length_delim(&mut body, 3, b"q2"); // stripped
        body.push(0x21);
        body.extend_from_slice(b"\x01\x02\x03");

        let mut expected: Vec<u8> = Vec::new();
        enc_length_delim(&mut expected, 2, b"r");
        enc_length_delim(&mut expected, 3, b"q1"); // kept
        expected.push(0x21);
        expected.extend_from_slice(b"\x01\x02\x03");
        assert_eq!(strip_sabr_quality_tracks(&body), expected);
    }

    // ── SABR host gate (defense against unrelated /videoplayback) ────────

    // ── SABR kill-switch runtime gate (#977) ─────────────────────────────

    /// Build a known segment-fetch body that the strip would actually
    /// shrink — multi-track shape (field-2 + 2× field-3) so the
    /// keep-first heuristic fires and removes the second field-3.
    /// Used to prove the gate at runtime rather than just the
    /// config-default round-trip.
    fn segment_fetch_body() -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"range-descriptor");
        enc_length_delim(&mut body, 3, b"quality-track-selector-1");
        enc_length_delim(&mut body, 3, b"quality-track-selector-2");
        body
    }

    #[test]
    fn sabr_strip_on_strips_extra_field3_entries_via_relay_gate() {
        // sabr_strip = true (default), multi-track segment-fetch body
        // (the keep-first heuristic threshold). The first field-3
        // entry must survive (so the player still has a track selected
        // — the #977 lesson); subsequent field-3 entries must be gone
        // (the 10 MB-blowup fix). Protects the main behaviour the
        // kill-switch gates: if a future refactor drops the
        // `self.sabr_strip` check, the strip still applies on `true`
        // and the test passes; if the refactor inverts the check, this
        // fails because no bytes are removed.
        let fronter = fronter_for_test_with(false, true);
        let body = segment_fetch_body();
        let result = fronter.maybe_strip_sabr_body(
            "POST",
            "https://rrx---sn-xxx.googlevideo.com/videoplayback?id=42",
            &body,
        );
        let stripped = result.expect("sabr_strip=true must strip a multi-track body");
        assert!(
            stripped.len() < body.len(),
            "strip must remove at least one byte ({} -> {})",
            body.len(),
            stripped.len(),
        );
        // First field-3 kept (single-track preservation), second stripped.
        assert!(
            stripped
                .windows(b"quality-track-selector-1".len())
                .any(|w| w == b"quality-track-selector-1"),
            "first field-3 payload (quality-track-selector-1) must SURVIVE the strip",
        );
        assert!(
            !stripped
                .windows(b"quality-track-selector-2".len())
                .any(|w| w == b"quality-track-selector-2"),
            "subsequent field-3 payload (quality-track-selector-2) must be STRIPPED",
        );
    }

    #[test]
    fn sabr_strip_off_keeps_body_unchanged_via_relay_gate() {
        // sabr_strip = false: same body, same URL, gate must report
        // None so `relay()` passes the body through verbatim. This is
        // the regression test for the #977 kill-switch — if someone
        // removes the `self.sabr_strip` check, this test fails.
        let fronter = fronter_for_test_with(false, false);
        let body = segment_fetch_body();
        let result = fronter.maybe_strip_sabr_body(
            "POST",
            "https://rrx---sn-xxx.googlevideo.com/videoplayback?id=42",
            &body,
        );
        assert!(
            result.is_none(),
            "sabr_strip=false must report None (no transformation): got {:?}",
            result,
        );
    }

    #[test]
    fn sabr_strip_gate_respects_method_and_url_even_when_flag_is_on() {
        // Other gates: only POST + /videoplayback + YT-host triggers.
        // This protects the host-gate / method-gate / path-gate work
        // from a refactor that conflates the kill-switch with the rest.
        let fronter = fronter_for_test_with(false, true);
        let body = segment_fetch_body();

        // GET on the right URL: gate off (not POST).
        assert!(fronter
            .maybe_strip_sabr_body(
                "GET",
                "https://rrx---sn-xxx.googlevideo.com/videoplayback",
                &body,
            )
            .is_none());

        // POST on a non-YT host: gate off (host gate).
        assert!(fronter
            .maybe_strip_sabr_body("POST", "https://api.example.com/videoplayback", &body,)
            .is_none());

        // POST on YT host without /videoplayback path: gate off.
        assert!(fronter
            .maybe_strip_sabr_body("POST", "https://www.youtube.com/youtubei/v1/player", &body,)
            .is_none());
    }

    #[test]
    fn sabr_strip_gate_returns_none_when_strip_is_a_no_op() {
        // Body without field-3 (or without field-2) survives
        // `strip_sabr_quality_tracks` unchanged. The gate then reports
        // None so the caller doesn't pay for a redundant clone of an
        // unmodified buffer.
        let fronter = fronter_for_test_with(false, true);
        let mut session_init: Vec<u8> = Vec::new();
        // field-5 + field-3, no field-2 → strip is a no-op.
        enc_length_delim(&mut session_init, 5, b"session-context");
        enc_length_delim(&mut session_init, 3, b"essential-metadata");
        let result = fronter.maybe_strip_sabr_body(
            "POST",
            "https://rrx---sn-xxx.googlevideo.com/videoplayback",
            &session_init,
        );
        assert!(
            result.is_none(),
            "no-op strip must report None to avoid redundant alloc"
        );
    }

    #[test]
    fn sabr_host_gate_recognises_youtube_video_endpoints() {
        // YouTube chunk CDN and yt itself.
        assert!(url_host_is_youtube_video_endpoint(
            "https://rrx---sn-xxx.googlevideo.com/videoplayback?...&itag=18"
        ));
        assert!(url_host_is_youtube_video_endpoint(
            "https://googlevideo.com/videoplayback"
        ));
        assert!(url_host_is_youtube_video_endpoint(
            "https://www.youtube.com/videoplayback"
        ));
        // Case-insensitive + trailing dot.
        assert!(url_host_is_youtube_video_endpoint(
            "https://GoogleVideo.com/videoplayback"
        ));
        assert!(url_host_is_youtube_video_endpoint(
            "https://googlevideo.com./videoplayback"
        ));
    }

    #[test]
    fn sabr_host_gate_rejects_unrelated_hosts_with_videoplayback_path() {
        // Any service that incidentally has `/videoplayback` must not
        // be treated as YouTube SABR.
        assert!(!url_host_is_youtube_video_endpoint(
            "https://api.example.com/videoplayback"
        ));
        assert!(!url_host_is_youtube_video_endpoint(
            "https://my-company.internal/videoplayback?id=42"
        ));
        // Suffix-attack: non-googlevideo hosts ending in similar bytes.
        assert!(!url_host_is_youtube_video_endpoint(
            "https://evilgooglevideo.com/videoplayback"
        ));
        assert!(!url_host_is_youtube_video_endpoint(
            "https://notyoutube.com/videoplayback"
        ));
    }

    #[test]
    fn sabr_strip_truncated_varint_payload_with_single_field3_is_noop() {
        // Wire type 0 (varint) with a continuation byte and no
        // terminator. Sole field-3 → kept under keep-first heuristic
        // → body returned verbatim (truncated tail included).
        let mut body: Vec<u8> = Vec::new();
        enc_length_delim(&mut body, 2, b"r");
        enc_length_delim(&mut body, 3, b"q"); // sole field-3 → kept
        body.push(0x28);
        body.push(0x80); // continuation, then EOF

        assert_eq!(strip_sabr_quality_tracks(&body), body);
    }

    // ── StatsSnapshot::fmt_line + to_json (forwarder fields) ────────────

    /// Build a `StatsSnapshot` fixture for serialization tests.
    /// All non-forwarder fields take fixed sentinels; the three
    /// forwarder fields are caller-supplied so each test can target
    /// the zero / non-zero branches.
    fn snapshot_with_forwarder(
        forwarder_calls: u64,
        forwarder_bytes: u64,
        forwarder_errors: u64,
    ) -> StatsSnapshot {
        StatsSnapshot {
            relay_calls: 100,
            relay_failures: 2,
            coalesced: 5,
            bytes_relayed: 4096,
            cache_hits: 30,
            cache_misses: 70,
            cache_bytes: 8192,
            blacklisted_scripts: 0,
            total_scripts: 1,
            today_calls: 100,
            today_bytes: 4096,
            today_key: "2026-05-10".into(),
            today_reset_secs: 3600,
            h2_calls: 80,
            h2_fallbacks: 4,
            h2_disabled: false,
            forwarder_calls,
            forwarder_bytes,
            forwarder_errors,
        }
    }

    #[test]
    fn fmt_line_omits_forwarder_segment_when_zero() {
        // Path filter never fired → forwarder values all zero. The
        // CLI line must NOT carry an `fwd=0 err=0` segment, otherwise
        // every non-AppsScript / no-pattern-hit user sees a confusing
        // always-zero pair.
        let s = snapshot_with_forwarder(0, 0, 0);
        let line = s.fmt_line();
        assert!(
            !line.contains("fwd="),
            "fmt_line must omit forwarder segment when all-zero: {}",
            line
        );
        assert!(
            !line.contains("err="),
            "fmt_line must omit forwarder error count when all-zero: {}",
            line
        );
    }

    #[test]
    fn fmt_line_includes_forwarder_segment_when_nonzero() {
        // Once the path filter has fired (any of calls / errors > 0),
        // the diagnostic segment shows up. Bytes are converted to KB
        // (mirrors `bytes_relayed`).
        let s = snapshot_with_forwarder(42, 1_048_576, 3);
        let line = s.fmt_line();
        assert!(line.contains("fwd=42"), "fmt_line missing fwd=42: {}", line);
        // 1_048_576 / 1024 = 1024 KB
        assert!(
            line.contains("(1024KB)"),
            "fmt_line missing bytes segment: {}",
            line
        );
        assert!(line.contains("err=3"), "fmt_line missing err=3: {}", line);
    }

    #[test]
    fn fmt_line_includes_forwarder_segment_when_only_errors_nonzero() {
        // Edge: forwarder consistently failed → calls=0, errors > 0.
        // Segment must still appear so users see the failure rate;
        // otherwise a fully-broken fast path looks identical to one
        // that's never been triggered.
        let s = snapshot_with_forwarder(0, 0, 5);
        let line = s.fmt_line();
        assert!(line.contains("fwd=0"), "fmt_line missing fwd=0: {}", line);
        assert!(line.contains("err=5"), "fmt_line missing err=5: {}", line);
    }

    #[test]
    fn to_json_emits_forwarder_fields_with_zero_values() {
        // Hand-rolled to_json must include the new fields even when
        // zero — Android JNI consumers expect a stable schema and
        // shouldn't have to handle "missing field" branches per
        // version. Parse the output as JSON to also validate the
        // hand-rolled format string is syntactically correct.
        let s = snapshot_with_forwarder(0, 0, 0);
        let json = s.to_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("to_json must produce valid JSON");
        assert_eq!(parsed["forwarder_calls"], 0);
        assert_eq!(parsed["forwarder_bytes"], 0);
        assert_eq!(parsed["forwarder_errors"], 0);
        // No `forwarder_fallbacks` key — that was the pre-rename name
        // and shipping it would confuse JNI consumers parsing both.
        assert!(
            parsed.get("forwarder_fallbacks").is_none(),
            "stale field name must not appear: {}",
            json
        );
    }

    #[test]
    fn to_json_emits_forwarder_fields_with_nonzero_values() {
        let s = snapshot_with_forwarder(42, 1_048_576, 3);
        let json = s.to_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("to_json must produce valid JSON");
        assert_eq!(parsed["forwarder_calls"], 42);
        assert_eq!(parsed["forwarder_bytes"], 1_048_576);
        assert_eq!(parsed["forwarder_errors"], 3);
    }

    #[test]
    fn to_json_round_trips_existing_fields_alongside_new_ones() {
        // Regression guard for the hand-rolled format string: adding
        // the new forwarder fields must not have broken any of the
        // preexisting fields. Pick a sample of each to confirm.
        let s = snapshot_with_forwarder(7, 1024, 0);
        let json = s.to_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("to_json must produce valid JSON");
        assert_eq!(parsed["relay_calls"], 100);
        assert_eq!(parsed["bytes_relayed"], 4096);
        assert_eq!(parsed["h2_calls"], 80);
        assert_eq!(parsed["h2_disabled"], false);
        assert_eq!(parsed["today_key"], "2026-05-10");
        assert_eq!(parsed["forwarder_calls"], 7);
    }
}
