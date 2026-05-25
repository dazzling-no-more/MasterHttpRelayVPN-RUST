//! Drive-mode client — Google Drive as a covert mailbox transport.
//!
//! every TCP session
//! becomes a sequence of encrypted frames uploaded to a shared Drive
//! folder. A separate `rahgozar-drive-relay` binary on a VPS abroad
//! polls the folder, dials the real destination, and writes response
//! frames back. The Iranian ISP only sees TLS to `*.google.com`.
//!
//! This module is the in-Iran half: the client mux + per-CONNECT
//! tunnel adapter that `proxy_server::dispatch_tunnel` calls when
//! [`crate::proxy_server::EarlyRoute::Drive`] fires.
//!
//! ## Architecture
//!
//! [`DriveMux`] is the long-lived state shared across every active
//! session: HTTP client, OAuth token cache, parsed relay pubkey,
//! session table, and one background poller task that scans
//! `r2c_*` files. Built once at proxy start; lives until the mode
//! switches away from Drive (at which point the outer `Arc` drops,
//! the poller's `Weak` upgrade fails, and the poller exits
//! naturally).
//!
//! [`tunnel_connection`] is per-CONNECT — invoked by the dispatcher
//! for every browser CONNECT in Drive mode. It mints a fresh
//! session id + ephemeral X25519 keypair, uploads the `h_*` Hello,
//! sends a Connect frame to the relay, registers itself in the
//! session table, and runs the bidirectional pump until either
//! side closes. Symmetric to the relay's [`session::session_driver`]
//! but with the local TCP socket playing the role the destination
//! TCP plays on the relay side.
//!
//! ## Wire-protocol responsibility split
//!
//! | Direction       | Client (this module)                          | Relay
//! | --------------- | --------------------------------------------- | -----
//! | c2r_<sid>_0     | Mint Hello + Connect; upload `[Hello][sealed]` | Poll, strip Hello, derive keys, open sealed
//! | c2r_<sid>_seq>0 | AEAD-seal with k_c2r, upload                  | Poll, download, AEAD-open with k_c2r
//! | r2c_*           | Poll, download, AEAD-open with k_r2c          | Encode, AEAD-seal with k_r2c, upload
//!
//! Pre-v3 the client uploaded the Hello as a separate unsealed
//! `h_<sid>_0` file and the Connect as `c2r_<sid>_0`. Folding the
//! Hello into the seq=0 body removes one Drive upload + one cold-
//! folder visibility wait from every new CONNECT.
//!
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use drive_wire::filename::{parse_filename, Direction, DriveFilename, FilenameKind};
use drive_wire::frame::{Batch, FrameKind, SessionId, WireFrame, WIRE_VERSION};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tokio::task::JoinSet;

use crate::config::Config;
use crate::drive_api::{
    build_drive_http_client, DriveApiClient, DriveApiError, DriveFile, MAX_SEALED_FRAME_BODY_BYTES,
};
use crate::drive_crypto::{
    AeadCipher, HelloBody, RelayPubkey, ReplayWindow, SessionKeys, StrictSeqError,
};
use crate::drive_oauth;

// --------------------------------------------------------------------
// Tunables
// --------------------------------------------------------------------

/// 16 KiB local-socket read buffer per session. Same value the
/// relay uses on the destination side — symmetric per-frame size,
/// symmetric latency.
const LOCAL_SOCKET_READ_BUFFER: usize = 16 * 1024;

/// Tiny open-cork window for HTTPS CONNECT. After the local proxy has
/// replied 200, browsers usually send TLS ClientHello immediately.
/// Waiting a few milliseconds lets us embed that first payload in
/// `c2r_<sid>_0` with Connect, saving a whole Drive object discovery
/// hop on cold-start TLS.
const OPEN_PREFACE_WAIT: Duration = Duration::from_millis(15);

/// Mailbox depth between the r2c poll worker and a per-session
/// driver. Small enough to apply back-pressure if the local socket
/// can't keep up; large enough that one poll cycle's burst lands
/// without stalling the worker.
const SESSION_MAILBOX_DEPTH: usize = 64;

/// After any non-empty poll cycle, drop the next sleep to this
/// value (pipeline mode). Lets a burst of inbound replies land
/// without paying the baseline interval again.
/// `BurstPollMS = 75`-ish range — aggressive enough that the
/// per-RTT wait is dominated by Drive's `files.list` latency
/// (~150-300 ms from Iran via the google_ip override) rather than
/// our sleep gap.
const PIPELINE_INTERVAL_MS: u64 = 25;

/// Each consecutive empty cycle adds this much to the next sleep.
const IDLE_BACKOFF_STEP_MS: u64 = 100;

/// Cap on the idle sleep. Only reached when the session table is
/// empty (no active CONNECT) — see `adapt_interval`. Was 1.5 s
/// originally; lowered to 500 ms because the cold-start tax it
/// imposed on the first r2c after an idle period is effectively
/// wasted time (Drive's listing latency is what we're waiting on,
/// not the sleep). Idle QPS at 500 ms cap is 2/s, comfortably
/// under Drive's 10 QPS budget.
const MAX_IDLE_INTERVAL_MS: u64 = 500;

const MODIFIED_CURSOR_LOOKBACK_SECS: i64 = 8;

// c2r batching:
//
// Each Drive file carries 1..=BATCH_MAX_FRAMES frames sealed as one
// AEAD batch. Coalesce delay is picked based on accumulated payload
// bytes — small frames (likely interactive traffic, TLS handshake)
// flush fast; large frames (likely bulk transfer, HTTP body) hold a
// bit longer to pack more per upload. This is the load-bearing fix
// for Drive Mode latency: instead of 1 upload per 16 KiB chunk of
// TCP read (= ~500 ms × N frames for a single HTTPS request), one
// upload carries every frame produced within the coalesce window.

/// Coalesce wait for accumulated batches up to this byte count.
/// Interactive tier: TLS handshake records, HTTP request headers,
/// keystrokes — flush at 5 ms so latency stays tight.
const COALESCE_INTERACTIVE_BYTES: usize = 8 * 1024;
const COALESCE_INTERACTIVE_DELAY: Duration = Duration::from_millis(5);

/// Coalesce wait for batches in the 8 KiB..64 KiB range. Medium
/// tier: full HTTP request bodies, small JSON responses.
const COALESCE_MEDIUM_BYTES: usize = 64 * 1024;
const COALESCE_MEDIUM_DELAY: Duration = Duration::from_millis(50);

/// Coalesce wait for batches ≥64 KiB. Bulk tier: download progress,
/// large response bodies. Hold longer to pack more — the extra
/// latency is invisible against the bulk transfer wall time.
const COALESCE_BULK_DELAY: Duration = Duration::from_millis(100);

/// Hard cap on bytes accumulated in one batch before forcing a flush.
/// Above this we want the upload in flight even if more frames could
/// pile in — keeps any one Drive upload below the ResponseTooLarge
/// safety cap on the relay side.
const BATCH_FLUSH_BYTES: usize = 1024 * 1024;

/// Hard cap on frame count per batch. Matches drive-wire's
/// `MAX_BATCH_FRAMES` minus a safety margin so we never construct a
/// batch the codec would refuse.
const BATCH_MAX_FRAMES: usize = 200;

// --------------------------------------------------------------------
// Public types
// --------------------------------------------------------------------

/// Drive-mode mux. Long-lived state shared across every active
/// session in this mode: HTTP client, OAuth token cache, parsed
/// relay pubkey, session table, and the background r2c poller.
///
/// Construction is via [`Self::start`]; the dispatch site holds
/// `Arc<DriveMux>` clones inside the proxy's `ModeBundle` and
/// hands one to each [`tunnel_connection`] call.
pub struct DriveMux(Arc<DriveMuxInner>);

/// Internal state. The outer wrapper exists so the background
/// poller can hold a `Weak<DriveMuxInner>` (not `Weak<DriveMux>`):
/// when the last `Arc<DriveMux>` drops, the inner Arc count also
/// drops to zero and the poller's `Weak::upgrade()` returns
/// `None`, exiting the loop. Without the wrapper, the poller's
/// own Arc<DriveMux> would cycle and never drop.
pub(crate) struct DriveMuxInner {
    cfg: DriveModeRuntimeCfg,
    drive_api: DriveApiClient,
    token_cache: Arc<TokenCache>,
    upload_permits: Arc<Semaphore>,
    relay_pubkey: RelayPubkey,
    sessions: Arc<RwLock<HashMap<SessionId, SessionHandle>>>,
}

/// Snapshot of the Drive-mode-relevant config fields, taken once
/// at [`DriveMux::start`] time. Stored owned (no `&Config`
/// borrow) so the mux can outlive the `Config` reference that
/// built it.
#[derive(Debug, Clone)]
struct DriveModeRuntimeCfg {
    folder_id: String,
    poll_interval_ms: u32,
    max_concurrent_uploads: u8,
}

impl DriveMux {
    /// Build the mux from a parsed `Config`. Validates the OAuth
    /// refresh token by triggering one refresh; parses the bech32m
    /// relay pubkey (the config validator already did this at
    /// load, but we re-parse for the typed [`RelayPubkey`]); spawns
    /// the background poller task.
    ///
    /// Returns `std::io::Result` (not the richer `ConfigError` etc.)
    /// to match `TunnelMux::start`'s contract — `proxy_server`
    /// plumbs errors out via `std::io::Error::other(...)` at the
    /// call site, so any richer error here would just get
    /// stringified anyway.
    pub async fn start(config: &Config) -> std::io::Result<Arc<Self>> {
        let relay_pubkey = RelayPubkey::from_bech32m(&config.drive.relay_pubkey)
            .map_err(|e| std::io::Error::other(format!("drive.relay_pubkey: {e}")))?;

        // Domain-front the Drive API + OAuth endpoints through the
        // existing `google_ip` so the Drive transport inherits
        // rahgozar's Iran-tested edge IP. Empty `google_ip` means
        // the resolver override is skipped (`build_drive_http_client`
        // falls back to system DNS, logged as a warning).
        let google_ip = if config.google_ip.is_empty() {
            None
        } else {
            Some(config.google_ip.as_str())
        };
        let http = build_drive_http_client(google_ip).map_err(std::io::Error::other)?;
        let drive_api = DriveApiClient::with_default_base_url(http.clone());
        let token_cache = TokenCache::new(
            config.drive.oauth_refresh_token.clone(),
            config.drive.oauth_client_id.clone(),
            config.drive.oauth_client_secret.clone(),
            http,
        );
        let access_token = token_cache
            .get()
            .await
            .map_err(|e| std::io::Error::other(format!("drive oauth refresh: {e}")))?;

        // Pre-warm the TLS pool to `www.googleapis.com`. The OAuth
        // refresh above hits `oauth2.googleapis.com` (different host),
        // so without this the first session upload pays the full TLS
        // handshake to a cold Drive host. A no-op cursor-mode list
        // call (no files match) is the cheapest way to open the h2
        // connection + complete TLS so subsequent uploads find a warm
        // pool. Failure is logged at warn but never fatal — the
        // poller will retry on its first cycle either way.
        let prewarm_cursor = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .ok();
        if let Err(e) = drive_api
            .list_files_in_folder_since(
                &access_token,
                &config.drive.folder_id,
                "",
                prewarm_cursor.as_deref(),
            )
            .await
        {
            tracing::warn!(
                "drive client: TLS pre-warm list call failed (non-fatal): {}",
                e
            );
        }

        let cfg = DriveModeRuntimeCfg {
            folder_id: config.drive.folder_id.clone(),
            poll_interval_ms: config.drive.poll_interval_ms,
            max_concurrent_uploads: config.drive.max_concurrent_uploads,
        };
        let upload_permits = Arc::new(Semaphore::new(std::cmp::max(
            1,
            cfg.max_concurrent_uploads as usize,
        )));

        let inner = Arc::new(DriveMuxInner {
            cfg,
            drive_api,
            token_cache,
            upload_permits,
            relay_pubkey,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        });
        let mux = Arc::new(DriveMux(inner.clone()));

        // Background poller: holds a `Weak<DriveMuxInner>`. When the
        // outer Arc<DriveMux> drops (e.g. mode switch away from
        // Drive), `inner`'s strong count drops to zero, and the
        // poller's next `upgrade()` returns `None`, ending the loop.
        let weak = Arc::downgrade(&inner);
        tokio::spawn(poll_loop(weak));

        tracing::info!(
            "drive client mux started (folder_id={}, poll={}ms, max_concurrent={})",
            inner.cfg.folder_id,
            inner.cfg.poll_interval_ms,
            inner.cfg.max_concurrent_uploads,
        );
        Ok(mux)
    }

    fn inner(&self) -> &Arc<DriveMuxInner> {
        &self.0
    }
}

/// Drive-mode CONNECT dispatcher. Wired into `dispatch_tunnel`
/// under [`crate::proxy_server::EarlyRoute::Drive`].
///
/// Runs as the dispatcher's call frame (no extra task spawn) for
/// the full lifetime of one client CONNECT. On entry: mints a
/// session, uploads `h_*` + initial Connect frame, registers in
/// the session table. Steady state: pumps both directions until
/// either the local socket closes (browser disconnected) or the
/// poller signals Close from the relay side. On exit: best-effort
/// uploads a closing Close frame, removes itself from the table.
pub async fn tunnel_connection(
    sock: TcpStream,
    host: &str,
    port: u16,
    mux: &Arc<DriveMux>,
) -> std::io::Result<()> {
    tunnel_connection_with_preface(sock, host, port, mux, Bytes::new()).await
}

/// Drive-mode tunnel with bytes that must be sent to the relay before
/// reading more from the local socket. Used by plain HTTP proxy
/// requests: the proxy has already consumed and rewritten the request
/// head, so those bytes become the first Data frame after Connect.
pub async fn tunnel_connection_with_preface(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    mux: &Arc<DriveMux>,
    initial_client_bytes: Bytes,
) -> std::io::Result<()> {
    let inner = mux.inner().clone();

    // 1. Mint a fresh session.
    let mut rng = OsRng;
    let mut sid: SessionId = [0u8; 16];
    rng.fill_bytes(&mut sid);
    let (keys, hello) = SessionKeys::client_initiate(&inner.relay_pubkey, sid, &mut rng)
        .map_err(|e| std::io::Error::other(format!("drive key agreement: {e}")))?;
    let keys = Arc::new(keys);

    // 2. Per-session channels + state.
    let (inbound_tx, inbound_rx) = mpsc::channel::<InboundFrame>(SESSION_MAILBOX_DEPTH);
    let replay = Arc::new(Mutex::new(ReplayWindow::new()));

    // 3. Register BEFORE uploading so any r2c frames that arrive in
    //    a poll cycle racing our startup uploads land in the
    //    table-populated state. The relay can't produce r2c until it
    //    sees c2r_<sid>_0 (Connect); startup uploads are pipelined
    //    below, so this defensive ordering is load-bearing.
    {
        let mut sessions = inner.sessions.write().await;
        sessions.insert(
            sid,
            SessionHandle {
                keys: keys.clone(),
                replay: replay.clone(),
                inbound_tx,
            },
        );
    }

    // Cleanup is unconditional via the guard's Drop impl. Captures
    // the sid + sessions Arc; runs even if `pump_session` panics or
    // an early return fires below.
    let _guard = SessionGuard {
        sid,
        sessions: inner.sessions.clone(),
    };

    // 4. Queue ONE combined session-open upload: `c2r_<sid>_0` carries
    //    `[HelloBody: 64 bytes][AEAD-sealed open batch]`. The relay
    //    derives `k_c2r` from the unsealed Hello prefix, then opens the
    //    rest with that key. One file = one Drive upload + one
    //    cold-folder visibility wait on the relay side, instead of the
    //    previous two-file (`h_<sid>_0` + `c2r_<sid>_0`) handshake.
    let send_cipher = AeadCipher::new(&keys.k_c2r);
    let mut next_c2r_seq: u64 = 1;
    let open_data_frames = if initial_client_bytes.is_empty() {
        read_open_preface_frames(&mut sock, sid, &mut next_c2r_seq).await?
    } else {
        data_frames_from_bytes(sid, &mut next_c2r_seq, initial_client_bytes)
    };
    let open_data_frame_count = open_data_frames.len();
    let open_data_bytes: usize = open_data_frames.iter().map(|f| f.payload.len()).sum();
    {
        let inner = inner.clone();
        let cipher = send_cipher.clone();
        let host = host.to_string();
        let hello = hello.clone();
        tokio::spawn(async move {
            if let Err(e) = upload_session_open_frame(
                &inner,
                sid,
                &cipher,
                &hello,
                &host,
                port,
                open_data_frames,
            )
            .await
            {
                tracing::warn!(
                    "drive session {:?}: session-open upload failed for {}:{}: {}",
                    sid,
                    host,
                    port,
                    e
                );
            }
        });
    }
    tracing::info!(
        "drive session {:?}: opened to {}:{} (session-open upload queued, embedded_frames={}, embedded_bytes={})",
        sid,
        host,
        port,
        open_data_frame_count,
        open_data_bytes
    );

    // 5. Steady-state pump until either side closes. `pump_session`
    //    is responsible for uploading the right closing frames on
    //    every exit path it controls (local EOF: Eof; both directions
    //    EOF or local read/write error: Close; inbound Close: no upload
    //    — the relay already knows). No post-pump Close upload here: the
    //    seq counter lives inside `pump_session`, and a redundant
    //    Close at an arbitrary seq would either replay-reject on
    //    the relay (best case) or overwrite a real frame (worst
    //    case).
    pump_session(sock, sid, &inner, &send_cipher, inbound_rx, next_c2r_seq).await
}

// --------------------------------------------------------------------
// Internal: token cache (single-flight refresh)
// --------------------------------------------------------------------

/// Cached OAuth access token with proactive refresh. Mirrors the
/// relay's `TokenCache` (intentional duplication — extraction to a
/// shared crate is a future cleanup once both sides have stabilised).
pub(crate) struct TokenCache {
    refresh_token: String,
    /// User-supplied BYO OAuth client_id from `Config::drive`. See
    /// [`crate::drive_oauth`] module docstring for the BYO model.
    oauth_client_id: String,
    /// User-supplied BYO OAuth client_secret from `Config::drive`.
    oauth_client_secret: String,
    cached: Mutex<Option<drive_oauth::OAuthTokens>>,
    http: reqwest::Client,
}

impl TokenCache {
    pub(crate) fn new(
        refresh_token: String,
        oauth_client_id: String,
        oauth_client_secret: String,
        http: reqwest::Client,
    ) -> Arc<Self> {
        Arc::new(Self {
            refresh_token,
            oauth_client_id,
            oauth_client_secret,
            cached: Mutex::new(None),
            http,
        })
    }

    /// Return a valid Bearer-eligible access token, refreshing
    /// against Google if the cache is empty or near expiry. The
    /// mutex serialises concurrent callers so N parallel uploaders
    /// don't fan out N refresh requests for the same expired token.
    pub(crate) async fn get(&self) -> Result<String, drive_oauth::OAuthError> {
        let mut guard = self.cached.lock().await;
        let now = Instant::now();
        if let Some(tokens) = guard.as_ref() {
            if !tokens.is_near_expiry(now) {
                return Ok(tokens.access_token.clone());
            }
        }
        let fresh = drive_oauth::refresh_access_token(
            &self.http,
            &self.refresh_token,
            &self.oauth_client_id,
            &self.oauth_client_secret,
        )
        .await?;
        let access = fresh.access_token.clone();
        *guard = Some(fresh);
        Ok(access)
    }
}

// --------------------------------------------------------------------
// Internal: session table
// --------------------------------------------------------------------

/// Per-session state held in the mux's table. The driver task
/// (running on `tunnel_connection`'s call frame) holds the
/// `mpsc::Receiver` half of `inbound_tx`; the poll worker fills
/// `inbound_tx` with opened-and-verified r2c frames.
struct SessionHandle {
    /// Derived directional AEAD keys + sid. `Arc` because the poll
    /// worker needs to open r2c frames (k_r2c) while the driver
    /// simultaneously seals c2r frames (k_c2r). Immutable after
    /// `client_initiate`.
    keys: Arc<SessionKeys>,
    /// Inbound replay tracker for `r2c_*` frames. Mutated by the
    /// poll worker on every inbound frame.
    replay: Arc<Mutex<ReplayWindow>>,
    /// Channel the poll worker uses to hand off opened+verified
    /// inbound events to the per-session driver.
    inbound_tx: mpsc::Sender<InboundFrame>,
}

/// Mailbox shape between the r2c poll worker (decoder) and the
/// per-session driver (executor). The poll worker AEAD-opens the
/// r2c frame and converts the [`WireFrame`] into one of these
/// variants — the driver never sees ciphertext or wire frames.
///
/// Note: no `Connect` variant (client never receives Connects —
/// it SENDS them) and no `Error` variant (mapped to `Close` with
/// a log line, same shape as the relay's frame-to-inbound logic).
#[derive(Debug)]
enum InboundFrame {
    Data(Bytes),
    Eof,
    Close,
}

/// RAII guard that removes the session from the mux table on
/// drop. Runs even if the tunnel_connection future is dropped
/// mid-pump (mode-switch, proxy shutdown, browser RST).
///
/// Drop can't await, so cleanup is scheduled on the current tokio
/// runtime. If the runtime is already gone, the process is shutting
/// down and the table is about to disappear with it.
struct SessionGuard {
    sid: SessionId,
    sessions: Arc<RwLock<HashMap<SessionId, SessionHandle>>>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let sid = self.sid;
        let sessions = self.sessions.clone();
        // Schedule the cleanup on the runtime since Drop is sync
        // and we need `.write().await`. `try_current` returns None
        // if we're being dropped outside a tokio runtime (e.g.
        // during process shutdown after the runtime exited) — in
        // that case the entry stays, but the process is going away
        // so it's harmless.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                sessions.write().await.remove(&sid);
            });
        }
    }
}

// --------------------------------------------------------------------
// Outbound encoding + upload helpers
// --------------------------------------------------------------------

/// Construct a wire frame ready to be sealed + uploaded.
fn build_wire_frame(kind: FrameKind, sid: SessionId, seq: u64, payload: Bytes) -> WireFrame {
    WireFrame {
        version: WIRE_VERSION,
        kind,
        sid,
        seq,
        payload,
    }
}

fn data_frames_from_bytes(sid: SessionId, next_seq: &mut u64, bytes: Bytes) -> Vec<WireFrame> {
    bytes
        .chunks(LOCAL_SOCKET_READ_BUFFER)
        .map(|chunk| {
            let seq = *next_seq;
            *next_seq += 1;
            build_wire_frame(FrameKind::Data, sid, seq, Bytes::copy_from_slice(chunk))
        })
        .collect()
}

async fn read_open_preface_frames(
    sock: &mut TcpStream,
    sid: SessionId,
    next_seq: &mut u64,
) -> std::io::Result<Vec<WireFrame>> {
    let mut read_buf = vec![0u8; LOCAL_SOCKET_READ_BUFFER];
    match tokio::time::timeout(OPEN_PREFACE_WAIT, sock.read(&mut read_buf)).await {
        Ok(Ok(0)) | Err(_) => Ok(Vec::new()),
        Ok(Ok(n)) => {
            let seq = *next_seq;
            *next_seq += 1;
            Ok(vec![build_wire_frame(
                FrameKind::Data,
                sid,
                seq,
                Bytes::copy_from_slice(&read_buf[..n]),
            )])
        }
        Ok(Err(e)) => Err(e),
    }
}

fn build_session_open_batch(
    sid: SessionId,
    host: &str,
    port: u16,
    mut initial_data_frames: Vec<WireFrame>,
) -> drive_wire::frame::Batch {
    let payload = Bytes::from(format!("{host}:{port}").into_bytes());
    let connect = build_wire_frame(FrameKind::Connect, sid, 0, payload);
    let mut frames = Vec::with_capacity(1 + initial_data_frames.len());
    frames.push(connect);
    frames.append(&mut initial_data_frames);
    drive_wire::frame::Batch { frames }
}

/// Seal a [`Batch`] of 1..=N frames as a single AEAD-encrypted body
/// for one Drive upload. The nonce + AAD are derived from the
/// FIRST frame's seq + sid — same convention the receiver uses to
/// rebuild them from the filename (`c2r_<sid>_<first_seq>`). Inside
/// the batch, individual frame seqs are checked against the replay
/// window per-frame on the receive side.
fn seal_batch(cipher: &AeadCipher, sid: SessionId, batch: &drive_wire::frame::Batch) -> Vec<u8> {
    debug_assert!(!batch.frames.is_empty(), "Batch must contain ≥1 frame");
    let first_seq = batch.frames[0].seq;
    let plaintext = batch.encode().freeze();
    cipher.seal(&sid, first_seq, &plaintext)
}

/// Pick the coalesce wait window based on currently-accumulated batch
/// payload bytes.
///   <  8 KB → 5 ms  (interactive: TLS records, request headers)
///   <  64 KB → 50 ms (medium: full request bodies)
///   ≥ 64 KB → 100 ms (bulk: large response bodies)
fn pick_coalesce_delay(pending_bytes: usize) -> Duration {
    if pending_bytes < COALESCE_INTERACTIVE_BYTES {
        COALESCE_INTERACTIVE_DELAY
    } else if pending_bytes < COALESCE_MEDIUM_BYTES {
        COALESCE_MEDIUM_DELAY
    } else {
        COALESCE_BULK_DELAY
    }
}

/// Seal the accumulated batch synchronously, then SPAWN the HTTP
/// upload as a detached task — returns Ok(()) without waiting for
/// the upload to complete. This is the load-bearing optimization
/// over plain batching: while the previous batch's upload is
/// in-flight to Drive (200-500 ms of TLS + body transfer), the
/// pump's select! loop can keep reading from the local socket and
/// forming the NEXT batch. Concurrency is bounded by the existing
/// `inner.upload_permits` semaphore (the spawned task acquires a
/// permit before doing the HTTP work).
///
/// Out-of-order completion is safe: the relay's c2r poller sorts
/// files numerically by sid+seq before dispatching, so if upload of
/// `c2r_<sid>_8` lands on Drive before `c2r_<sid>_5`, the relay
/// still processes them in seq order on its next listing cycle.
///
/// Upload failures are logged at warn but don't propagate — the
/// pump session continues, and the missing seq leaves a gap that
/// the relay's strict-monotonic replay window will block on until
/// the next batch arrives (which will trip "future seq" and the
/// orphan reaper eventually evicts the session). This is the same
/// failure semantics as the pre-pipelining single-frame path.
fn flush_c2r_batch(
    inner: &Arc<DriveMuxInner>,
    sid: SessionId,
    cipher: &AeadCipher,
    pending: &mut Vec<WireFrame>,
    pending_bytes: &mut usize,
    flush_deadline: &mut Option<tokio::time::Instant>,
) {
    if pending.is_empty() {
        return;
    }
    let first_seq = pending[0].seq;
    let frame_count = pending.len();
    let batch = drive_wire::frame::Batch {
        frames: std::mem::take(pending),
    };
    *pending_bytes = 0;
    *flush_deadline = None;
    let sealed = seal_batch(cipher, sid, &batch);
    if frame_count > 1 {
        // INFO temporarily so we can see batch effectiveness in
        // default-level journalctl. Drop back to debug once Drive
        // Mode latency tuning is settled.
        tracing::info!(
            "drive session {:?}: flushing batch first_seq={} count={} bytes={}",
            sid,
            first_seq,
            frame_count,
            sealed.len()
        );
    }
    let inner_for_task = inner.clone();
    tokio::spawn(async move {
        if let Err(e) = upload_c2r_frame(&inner_for_task, sid, first_seq, sealed).await {
            tracing::warn!(
                "drive session {:?}: pipelined c2r upload failed at first_seq={}: {}",
                sid,
                first_seq,
                e
            );
        }
    });
}

/// Append a frame to the pending batch and update bookkeeping. If
/// `flush_now` is true (Eof / Close / Error / Connect — anything but
/// Data), or the batch crosses a size/count threshold, spawn the
/// upload immediately. Otherwise updates the coalesce deadline so
/// the next select! iteration's timer arm fires and flushes.
///
/// Synchronous (no .await) since `flush_c2r_batch` is now spawn-
/// detached — that's the pipelining win, see its doc.
fn push_c2r_frame(
    inner: &Arc<DriveMuxInner>,
    sid: SessionId,
    cipher: &AeadCipher,
    pending: &mut Vec<WireFrame>,
    pending_bytes: &mut usize,
    flush_deadline: &mut Option<tokio::time::Instant>,
    frame: WireFrame,
    flush_now: bool,
) {
    *pending_bytes += frame.payload.len();
    pending.push(frame);
    // EAGER FLUSH on second+ frame in the batch. The
    // coalesce delay's only job is to let a 2nd frame ARRIVE; the
    // moment one does, batch + flush immediately. Waiting longer
    // just adds latency without packing more frames (subsequent
    // reads block on TLS/HTTP roundtrips, not on each other).
    let should_flush = flush_now
        || pending.len() >= 2
        || pending.len() >= BATCH_MAX_FRAMES
        || *pending_bytes >= BATCH_FLUSH_BYTES;
    if should_flush {
        flush_c2r_batch(inner, sid, cipher, pending, pending_bytes, flush_deadline);
        return;
    }
    // Only one frame in pending — arm the coalesce timer to flush
    // if no 2nd frame arrives within the tier window.
    let delay = pick_coalesce_delay(*pending_bytes);
    let deadline = tokio::time::Instant::now() + delay;
    match flush_deadline {
        Some(existing) if *existing <= deadline => {}
        _ => *flush_deadline = Some(deadline),
    }
}

/// Build the per-direction r2c/c2r filename for a given session.
fn frame_filename(direction: Direction, sid: SessionId, seq: u64) -> String {
    DriveFilename {
        kind: FilenameKind::Frame(direction),
        sid,
        seq,
    }
    .format()
}

/// Upload one sealed frame to Drive as a `c2r_<sid>_<seq>` file.
async fn upload_c2r_frame(
    inner: &DriveMuxInner,
    sid: SessionId,
    seq: u64,
    sealed: Vec<u8>,
) -> Result<(), ClientError> {
    let name = frame_filename(Direction::ClientToRelay, sid, seq);
    let body_len = sealed.len();
    let started = Instant::now();
    let token = inner.token_cache.get().await?;
    let _permit = inner
        .upload_permits
        .acquire()
        .await
        .map_err(|_| ClientError::UploadSemaphoreClosed)?;
    inner
        .drive_api
        .upload_file(&token, &inner.cfg.folder_id, &name, Bytes::from(sealed))
        .await?;
    if seq <= 4 {
        tracing::info!(
            "drive session {:?}: uploaded c2r seq={} bytes={} in {}ms",
            sid,
            seq,
            body_len,
            started.elapsed().as_millis()
        );
    }
    Ok(())
}

/// Build, seal, and upload the combined session-opener at seq=0.
///
/// The file body has the shape
/// `[HelloBody: 64 bytes][AEAD-sealed open batch: N bytes]`. The
/// relay strips the first 64 bytes as the unsealed key-agreement
/// input, derives `k_c2r` from it, then opens the rest as a normal
/// AEAD-sealed Batch (nonce + AAD bound to `(sid, first_seq=0)` the
/// same way every other c2r frame is). The seq>0 c2r files keep the
/// old format (just sealed bytes).
///
/// Combining Hello, Connect, and first client bytes into ONE Drive
/// upload removes a full upload + discovery hop from cold-start TLS.
async fn upload_session_open_frame(
    inner: &DriveMuxInner,
    sid: SessionId,
    cipher: &AeadCipher,
    hello: &HelloBody,
    host: &str,
    port: u16,
    initial_data_frames: Vec<WireFrame>,
) -> Result<(), ClientError> {
    let batch = build_session_open_batch(sid, host, port, initial_data_frames);
    let sealed = seal_batch(cipher, sid, &batch);
    let hello_bytes = hello.encode();
    let mut body = Vec::with_capacity(hello_bytes.len() + sealed.len());
    body.extend_from_slice(&hello_bytes);
    body.extend_from_slice(&sealed);
    upload_c2r_frame(inner, sid, 0, body).await
}

// The legacy `upload_{data,eof,close}_frame` per-frame helpers were
// retired when c2r switched to batched uploads — see
// `push_c2r_frame` / `flush_c2r_batch` above for the new path.
// `upload_session_open_frame` survives outside the steady batching
// path because it carries the unsealed Hello prefix and anchors the
// AEAD nonce at seq=0.

// --------------------------------------------------------------------
// Per-session pump
// --------------------------------------------------------------------

/// Bidirectional pump for one session. Runs to completion as the
/// dispatcher's call frame; returns when either:
///   - both directions reach EOF: uploads the final Close, exits Ok
///   - local socket error: uploads Close best-effort, exits Err
///   - InboundFrame::Close received: shuts down local socket, exits Ok
///   - inbound channel closed (mux dropped): exits Ok
#[allow(unused_assignments)] // `next_c2r_seq += 1` before some returns is intentional bookkeeping
async fn pump_session(
    mut sock: TcpStream,
    sid: SessionId,
    inner: &Arc<DriveMuxInner>,
    cipher: &AeadCipher,
    mut inbound_rx: mpsc::Receiver<InboundFrame>,
    mut next_c2r_seq: u64,
) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);
    let mut read_buf = vec![0u8; LOCAL_SOCKET_READ_BUFFER];
    let mut local_writable = true; // false once we receive Eof from the relay
    let mut local_read_closed = false; // true once browser half-closes its write side

    // Outbound batch state. `pending` accumulates frames from local
    // socket reads (and terminal Eof/Close) until either:
    //   * the coalesce timer fires (size-tier delay), OR
    //   * we hit `BATCH_FLUSH_BYTES` / `BATCH_MAX_FRAMES`, OR
    //   * a non-Data frame (Eof/Close/Error) is pushed (flush now so
    //     the relay sees the control event without waiting), OR
    //   * the session is exiting (final flush before return).
    // `pending_bytes` tracks accumulated payload bytes (not including
    // wire framing overhead) for the size-tier pick.
    let mut pending: Vec<WireFrame> = Vec::new();
    let mut pending_bytes: usize = 0;
    let mut flush_deadline: Option<tokio::time::Instant> = None;

    loop {
        // Future for the coalesce timer. Resolves only when there's
        // a pending batch with a deadline set; otherwise blocks
        // forever. We copy the `Option<Instant>` into the async block
        // (Instant is Copy) so the block doesn't hold an outstanding
        // borrow of `flush_deadline` — the push/flush helpers in the
        // other select! arms need `&mut flush_deadline`.
        let deadline_snapshot = flush_deadline;
        let timer_future = async move {
            if let Some(d) = deadline_snapshot {
                tokio::time::sleep_until(d).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(timer_future);
        tokio::select! {
            biased;
            evt = inbound_rx.recv() => {
                match evt {
                    Some(InboundFrame::Data(bytes)) => {
                        if !local_writable {
                            tracing::warn!(
                                "drive session {:?}: Data after Eof; dropping {} bytes",
                                sid, bytes.len()
                            );
                            continue;
                        }
                        if let Err(e) = sock.write_all(&bytes).await {
                            tracing::warn!(
                                "drive session {:?}: local write failed: {}", sid, e
                            );
                            let close_seq = next_c2r_seq;
                            next_c2r_seq += 1;
                            let frame = build_wire_frame(FrameKind::Close, sid, close_seq, Bytes::new());
                            push_c2r_frame(
                                inner, sid, cipher,
                                &mut pending, &mut pending_bytes, &mut flush_deadline,
                                frame, true,
                            );
                            return Err(e);
                        }
                    }
                    Some(InboundFrame::Eof) => {
                        // Relay half-closed its write side. Shutdown local
                        // write so the browser sees EOF on read.
                        if let Err(e) = sock.shutdown().await {
                            tracing::debug!(
                                "drive session {:?}: local shutdown failed: {}", sid, e
                            );
                        }
                        local_writable = false;
                        if local_read_closed {
                            let close_seq = next_c2r_seq;
                            next_c2r_seq += 1;
                            let frame = build_wire_frame(FrameKind::Close, sid, close_seq, Bytes::new());
                            push_c2r_frame(
                                inner, sid, cipher,
                                &mut pending, &mut pending_bytes, &mut flush_deadline,
                                frame, true,
                            );
                            return Ok(());
                        }
                    }
                    Some(InboundFrame::Close) | None => {
                        // Relay sent Close, OR mux dropped. Final flush of
                        // any pending batch then exit. We don't upload
                        // another Close — the relay already sent one (or
                        // the mux doesn't care).
                        flush_c2r_batch(
                            inner, sid, cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                        );
                        return Ok(());
                    }
                }
            }
            _ = &mut timer_future => {
                // Coalesce deadline reached — flush whatever accumulated.
                flush_c2r_batch(
                    inner, sid, cipher,
                    &mut pending, &mut pending_bytes, &mut flush_deadline,
                );
            }
            read_result = sock.read(&mut read_buf), if !local_read_closed => {
                match read_result {
                    Ok(0) => {
                        // Local EOF (browser half-closed write). Push Eof
                        // and flush. Eof is a control frame: flush_now=true
                        // so the relay sees it without waiting on coalesce.
                        let eof_seq = next_c2r_seq;
                        next_c2r_seq += 1;
                        let eof_frame = build_wire_frame(FrameKind::Eof, sid, eof_seq, Bytes::new());
                        push_c2r_frame(
                            inner, sid, cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                            eof_frame, true,
                        );
                        local_read_closed = true;
                        if !local_writable {
                            let close_seq = next_c2r_seq;
                            next_c2r_seq += 1;
                            let close_frame = build_wire_frame(
                                FrameKind::Close, sid, close_seq, Bytes::new()
                            );
                            push_c2r_frame(
                                inner, sid, cipher,
                                &mut pending, &mut pending_bytes, &mut flush_deadline,
                                close_frame, true,
                            );
                            return Ok(());
                        }
                    }
                    Ok(n) => {
                        let payload = Bytes::copy_from_slice(&read_buf[..n]);
                        let seq = next_c2r_seq;
                        next_c2r_seq += 1;
                        let frame = build_wire_frame(FrameKind::Data, sid, seq, payload);
                        // Data frames are coalesced — flush_now=false. The
                        // timer arm above fires the spawn-and-forget upload
                        // once the size-tier delay elapses (or threshold hits).
                        push_c2r_frame(
                            inner, sid, cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                            frame, false,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "drive session {:?}: local read failed: {}", sid, e
                        );
                        let close_seq = next_c2r_seq;
                        next_c2r_seq += 1;
                        let close_frame = build_wire_frame(
                            FrameKind::Close, sid, close_seq, Bytes::new()
                        );
                        push_c2r_frame(
                            inner, sid, cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                            close_frame, true,
                        );
                        return Err(e);
                    }
                }
            }
        }
    }
}

// --------------------------------------------------------------------
// r2c poll loop
// --------------------------------------------------------------------

/// Long-lived background task that polls `r2c_*` files and
/// dispatches AEAD-opened payloads to per-session driver tasks.
///
/// Holds a [`Weak`] reference to the inner mux state — when the
/// outer `Arc<DriveMux>` drops (mode switch, proxy shutdown), the
/// next `upgrade()` returns `None` and this loop exits naturally.
async fn poll_loop(weak: Weak<DriveMuxInner>) {
    let baseline_ms = match weak.upgrade() {
        Some(inner) => inner.cfg.poll_interval_ms as u64,
        None => return,
    };
    let mut interval_ms = baseline_ms;
    let mut empty_streak: u64 = 0;
    // Sliding modifiedTime cursor — None on the very first poll
    // (full folder list); advanced after each cycle to the latest
    // modifiedTime seen, minus a small safety window so delayed
    // Drive visibility does not strand an older missing seq behind
    // the cursor.
    let mut modified_cursor: Option<String> = None;

    tracing::info!(
        "drive client poll loop starting (baseline={}ms)",
        baseline_ms
    );

    loop {
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        let inner = match weak.upgrade() {
            Some(i) => i,
            None => {
                tracing::info!("drive client poll loop exiting (mux dropped)");
                return;
            }
        };
        let found = run_one_cycle(inner.clone(), &mut modified_cursor).await;
        // While at least one CONNECT is registered, every empty cycle
        // is still a cycle where r2c traffic is EXPECTED — back-off
        // would just add per-request tail latency for no quota win.
        // The ramp only fires when the proxy is genuinely idle.
        let sessions_present = !inner.sessions.read().await.is_empty();
        interval_ms = adapt_interval(baseline_ms, found, &mut empty_streak, sessions_present);
    }
}

/// Adaptive-interval computation, factored out for unit testing.
/// - `found_work`: drop to pipeline interval, reset the streak.
/// - empty cycle with `sessions_present`: stay at baseline; we
///   expect r2c shortly and idle backoff would just delay it.
/// - empty cycle with no sessions: ramp `baseline + step * streak`,
///   capped at `MAX_IDLE_INTERVAL_MS`.
fn adapt_interval(
    baseline_ms: u64,
    found_work: bool,
    empty_streak: &mut u64,
    sessions_present: bool,
) -> u64 {
    if found_work {
        *empty_streak = 0;
        PIPELINE_INTERVAL_MS
    } else if sessions_present {
        *empty_streak = 0;
        baseline_ms
    } else {
        *empty_streak = empty_streak.saturating_add(1);
        baseline_ms
            .saturating_add(IDLE_BACKOFF_STEP_MS.saturating_mul(*empty_streak))
            .min(MAX_IDLE_INTERVAL_MS)
    }
}

/// Advance the sliding `modifiedTime >= since` cursor.
///
/// `now` is the wall-clock timestamp captured BEFORE the list call —
/// it lets us advance the cursor even on empty listings, which is
/// load-bearing for steady polling: with `since=None` the query path
/// falls back to Drive's slow `name contains` full-text index
/// (multi-second visibility lag for newly uploaded mailbox files).
/// Once we set a cursor, subsequent calls use the much-faster
/// `modifiedTime >= ...` predicate over the folder's recently-modified
/// children.
fn advance_modified_cursor(
    files: &[DriveFile],
    cursor: &mut Option<String>,
    now: time::OffsetDateTime,
) {
    let file_max = files.iter().filter_map(|f| f.modified_time).max();
    let basis = match file_max {
        Some(m) if m > now => m,
        _ => now,
    };
    let proposed = basis - time::Duration::seconds(MODIFIED_CURSOR_LOOKBACK_SECS);
    let current = cursor.as_deref().and_then(|s| {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
    });
    if current.is_some_and(|c| c >= proposed) {
        return;
    }
    if let Ok(formatted) = proposed.format(&time::format_description::well_known::Rfc3339) {
        *cursor = Some(formatted);
    }
}

/// Run one poll iteration. Returns true iff at least one r2c file
/// was processed (drives the adaptive interval).
///
/// `modified_cursor` is the sliding `modifiedTime >= since` filter —
/// `None` on the first call (full folder list), then advanced to the
/// latest `modifiedTime` observed in each non-empty cycle so
/// subsequent calls return only the delta.
async fn run_one_cycle(inner: Arc<DriveMuxInner>, modified_cursor: &mut Option<String>) -> bool {
    let access_token = match inner.token_cache.get().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                "drive client: token refresh failed (will retry next cycle): {}",
                e
            );
            return false;
        }
    };

    // Capture `now` BEFORE the list call so `advance_modified_cursor`
    // can safely move forward even when the listing comes back empty.
    // Without this, the first poll (cursor = None) uses Drive's slow
    // `name contains` query path; if that listing is empty the cursor
    // never gets set and every subsequent poll keeps paying the same
    // slow path. See `advance_modified_cursor` for why `now` is a
    // safe lower bound here.
    let call_start = time::OffsetDateTime::now_utc();
    let files = match inner
        .drive_api
        .list_files_in_folder_since(
            &access_token,
            &inner.cfg.folder_id,
            "r2c_",
            modified_cursor.as_deref(),
        )
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("drive client: list r2c_* failed: {}", e);
            return false;
        }
    };
    // Advance the cursor before filtering / processing. The 8s
    // lookback keeps us robust against out-of-order Drive visibility;
    // the `now` argument bootstraps the cursor when the listing is
    // empty so steady polling stops re-hitting the full-text name
    // index path.
    advance_modified_cursor(&files, modified_cursor, call_start);

    // Snapshot the local session sid-set under a single read lock —
    // we use it to filter out r2c files that belong to OTHER clients
    // sharing the same Drive folder (a multi-device setup with one
    // relay watching one folder). Without this filter, we'd download
    // every r2c file, try to AEAD-open with our own keys, and fail
    // on the other client's files because their session keys differ.
    // That wastes Drive bandwidth, floods the log with AEAD-failure
    // warnings, and races against the orphan reaper. With the filter,
    // foreign r2c files are silently ignored at the listing stage
    // (matched to no sid → never downloaded); the foreign client's
    // own poll loop picks them up. The relay's wire format already
    // tags every r2c file with the sid it's a reply to, so this is
    // a strict client-side improvement — no relay-side change needed.
    // See docs/drive_mode.md "Multiple devices sharing one Drive
    // folder" — this is the v2 fix mentioned there.
    let known_sids: std::collections::HashSet<SessionId> = {
        let sessions = inner.sessions.read().await;
        sessions.keys().copied().collect()
    };
    let mut sorted: Vec<(DriveFile, DriveFilename)> = files
        .into_iter()
        .filter_map(|f| parse_filename(&f.name).map(|p| (f, p)))
        .filter(|(_, p)| matches!(p.kind, FilenameKind::Frame(Direction::RelayToClient)))
        .filter(|(_, p)| known_sids.contains(&p.sid))
        .collect();
    if sorted.is_empty() {
        return false;
    }
    // Drive sorts lex, so seq=10 appears before seq=2 in the
    // listing. Re-sort numerically by (sid, seq) so per-session
    // ordering is correct before dispatch.
    sorted.sort_by_key(|(_, p)| (p.sid, p.seq));

    let permits_cap = std::cmp::max(1, inner.cfg.max_concurrent_uploads as usize);
    let download_permits = Arc::new(tokio::sync::Semaphore::new(permits_cap));

    // Group by sid so commit stays strictly ordered per TCP stream,
    // but let each group prefetch Drive bodies concurrently. Drive
    // download/decrypt/decode can race, while replay-window commit
    // and mpsc delivery happen later in sorted seq order.
    let mut frames_by_sid: std::collections::HashMap<SessionId, Vec<(DriveFile, DriveFilename)>> =
        std::collections::HashMap::new();
    for entry in sorted {
        frames_by_sid.entry(entry.1.sid).or_default().push(entry);
    }
    let mut workers: JoinSet<()> = JoinSet::new();
    for (sid, group) in frames_by_sid {
        let inner = inner.clone();
        let access_token = access_token.clone();
        let download_permits = download_permits.clone();
        workers.spawn(async move {
            if let Err(e) = process_r2c_group(inner, access_token, download_permits, group).await {
                tracing::warn!(
                    "drive client: r2c group processing failed for sid {:?}: {}",
                    sid,
                    e
                );
            }
        });
    }
    while workers.join_next().await.is_some() {}
    true
}

struct PreparedR2cBatch {
    file: DriveFile,
    parsed: DriveFilename,
    batch: Batch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryOutcome {
    Consumed,
    Duplicate,
    Blocked,
}

/// Process one sid's r2c files with parallel Drive-body prefetch,
/// then ordered commit. Network-bound downloads run concurrently, but
/// replay-window advancement and local socket delivery stay strictly
/// sequential.
async fn process_r2c_group(
    inner: Arc<DriveMuxInner>,
    access_token: String,
    download_permits: Arc<Semaphore>,
    group: Vec<(DriveFile, DriveFilename)>,
) -> Result<(), ClientError> {
    if group.is_empty() {
        return Ok(());
    }

    let sid = group[0].1.sid;
    let session_view = {
        let sessions = inner.sessions.read().await;
        sessions
            .get(&sid)
            .map(|h| (h.keys.clone(), h.replay.clone(), h.inbound_tx.clone()))
    };
    let (keys, replay, inbound_tx) = match session_view {
        Some(v) => v,
        None => {
            // No session — probably stale r2c from a tunnel whose
            // SessionGuard already removed the entry. Best-effort
            // delete to keep the listing tidy.
            for (file, parsed) in group {
                let _ = inner.drive_api.delete_file(&access_token, &file.id).await;
                tracing::debug!(
                    "drive client: r2c {} dropped (no session for sid {:?})",
                    file.name,
                    parsed.sid
                );
            }
            return Ok(());
        }
    };

    let next_expected = {
        let window = replay.lock().await;
        match window.last_seen() {
            None => Some(0),
            Some(prev) => prev.checked_add(1),
        }
    };
    let Some(next_expected) = next_expected else {
        for (file, _) in group {
            let _ = inner.drive_api.delete_file(&access_token, &file.id).await;
        }
        return Ok(());
    };

    let mut downloads: JoinSet<Result<Option<PreparedR2cBatch>, ClientError>> = JoinSet::new();
    let mut saw_expected_seq = false;
    for (file, parsed) in group {
        if !matches!(parsed.kind, FilenameKind::Frame(Direction::RelayToClient)) {
            tracing::debug!("drive client: ignoring non-r2c filename: {}", file.name);
            continue;
        }
        if parsed.seq < next_expected {
            tracing::debug!(
                "drive client: r2c {} rejected by replay window: seq {} < expected {}",
                file.name,
                parsed.seq,
                next_expected
            );
            let _ = inner.drive_api.delete_file(&access_token, &file.id).await;
            continue;
        }
        if parsed.seq == next_expected {
            saw_expected_seq = true;
        } else if !saw_expected_seq {
            tracing::debug!(
                "drive client: r2c {} arrived before seq {}; leaving for a later poll",
                file.name,
                next_expected
            );
            break;
        }

        let permit = download_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ClientError::WorkerSemaphoreClosed)?;
        let inner = inner.clone();
        let access_token = access_token.clone();
        let keys = keys.clone();
        downloads.spawn(async move {
            let _permit = permit;
            prepare_r2c_batch(inner, access_token, keys, file, parsed).await
        });
    }

    let mut prepared = Vec::new();
    while let Some(joined) = downloads.join_next().await {
        match joined {
            Ok(Ok(Some(batch))) => prepared.push(batch),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("drive client: r2c prefetch failed: {}", e),
            Err(e) => tracing::warn!("drive client: r2c prefetch task failed: {}", e),
        }
    }
    prepared.sort_by_key(|p| p.parsed.seq);

    for prepared in prepared {
        match deliver_prepared_r2c_batch(&inner, &access_token, &replay, &inbound_tx, prepared)
            .await?
        {
            DeliveryOutcome::Consumed | DeliveryOutcome::Duplicate => {}
            DeliveryOutcome::Blocked => break,
        }
    }

    Ok(())
}

async fn prepare_r2c_batch(
    inner: Arc<DriveMuxInner>,
    access_token: String,
    keys: Arc<SessionKeys>,
    file: DriveFile,
    parsed: DriveFilename,
) -> Result<Option<PreparedR2cBatch>, ClientError> {
    if let Some(size) = file.size {
        if size > MAX_SEALED_FRAME_BODY_BYTES {
            tracing::warn!(
                "drive client: r2c {} is {} bytes; maximum accepted is {}; deleting",
                file.name,
                size,
                MAX_SEALED_FRAME_BODY_BYTES
            );
            let _ = inner.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(None);
        }
    }

    let sealed = match inner
        .drive_api
        .download_file(&access_token, &file.id, MAX_SEALED_FRAME_BODY_BYTES)
        .await
    {
        Ok(bytes) => bytes,
        Err(DriveApiError::ResponseTooLarge { .. }) => {
            tracing::warn!(
                "drive client: r2c {} exceeded the protocol size cap; deleting",
                file.name
            );
            let _ = inner.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    let cipher = AeadCipher::new(&keys.k_r2c);
    let plaintext = match cipher.open(&parsed.sid, parsed.seq, &sealed) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::warn!("drive client: r2c {} AEAD open failed: {}", file.name, e);
            return Ok(None);
        }
    };
    let batch = match Batch::decode(&plaintext) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("drive client: r2c {} batch decode failed: {}", file.name, e);
            return Ok(None);
        }
    };
    if batch.frames.is_empty() {
        tracing::warn!("drive client: r2c {} decoded to empty batch", file.name);
        return Ok(None);
    }
    if batch.frames[0].seq != parsed.seq {
        tracing::warn!(
            "drive client: r2c {} first-frame seq mismatch: filename={} first_frame={}",
            file.name,
            parsed.seq,
            batch.frames[0].seq,
        );
        return Ok(None);
    }

    Ok(Some(PreparedR2cBatch {
        file,
        parsed,
        batch,
    }))
}

async fn deliver_prepared_r2c_batch(
    inner: &DriveMuxInner,
    access_token: &str,
    replay: &Arc<Mutex<ReplayWindow>>,
    inbound_tx: &mpsc::Sender<InboundFrame>,
    prepared: PreparedR2cBatch,
) -> Result<DeliveryOutcome, ClientError> {
    let PreparedR2cBatch {
        file,
        parsed,
        batch,
    } = prepared;
    let frame_count = batch.frames.len();
    let mut committed_through: Option<u64> = None;

    for (idx, wire) in batch.frames.into_iter().enumerate() {
        if wire.sid != parsed.sid {
            tracing::warn!(
                "drive client: r2c {} batch index {} sid mismatch",
                file.name,
                idx
            );
            break;
        }
        let replay_check = {
            let window = replay.lock().await;
            window.check_next(wire.seq)
        };
        match replay_check {
            Ok(()) => {}
            Err(StrictSeqError::Replay(e)) => {
                tracing::debug!(
                    "drive client: r2c {} batch index {} seq {} rejected by replay: {}",
                    file.name,
                    idx,
                    wire.seq,
                    e,
                );
                if committed_through.is_none() {
                    delete_r2c_file_detached(&inner.drive_api, access_token, &file);
                    return Ok(DeliveryOutcome::Duplicate);
                }
                break;
            }
            Err(StrictSeqError::Future { expected, .. }) => {
                tracing::debug!(
                    "drive client: r2c {} batch index {} arrived before seq {}; leaving for a later poll",
                    file.name,
                    idx,
                    expected
                );
                if committed_through.is_none() {
                    return Ok(DeliveryOutcome::Blocked);
                }
                break;
            }
        }
        let frame_seq = wire.seq;
        let inbound = match wire_to_inbound(wire) {
            Some(i) => i,
            None => {
                tracing::warn!(
                    "drive client: r2c {} batch index {} carried an unexpected frame kind",
                    file.name,
                    idx,
                );
                break;
            }
        };
        if let Err(e) = inbound_tx.send(inbound).await {
            tracing::debug!(
                "drive client: r2c {} batch index {}: session driver gone, dropping inbound: {}",
                file.name,
                idx,
                e
            );
            break;
        }
        {
            let mut window = replay.lock().await;
            window.commit(frame_seq);
        }
        committed_through = Some(frame_seq);
    }

    let Some(committed_through) = committed_through else {
        return Ok(DeliveryOutcome::Blocked);
    };

    if frame_count > 1 {
        tracing::info!(
            "drive client: r2c {} consumed batch first_seq={} through={} ({} frames)",
            file.name,
            parsed.seq,
            committed_through,
            frame_count
        );
    }

    delete_r2c_file_detached(&inner.drive_api, access_token, &file);
    Ok(DeliveryOutcome::Consumed)
}

fn delete_r2c_file_detached(drive_api: &DriveApiClient, access_token: &str, file: &DriveFile) {
    let drive_api = drive_api.clone();
    let access_token = access_token.to_string();
    let file_id = file.id.clone();
    let file_name = file.name.clone();
    tokio::spawn(async move {
        if let Err(e) = drive_api.delete_file(&access_token, &file_id).await {
            tracing::debug!("drive client: r2c {} delete failed: {}", file_name, e);
        }
    });
}

/// Translate a verified r2c [`WireFrame`] into the
/// [`InboundFrame`] the per-session driver consumes. Returns
/// `None` if the wire frame's `kind` isn't valid for the r2c
/// direction (Hello, Connect — those only flow client→relay).
fn wire_to_inbound(frame: WireFrame) -> Option<InboundFrame> {
    match frame.kind {
        FrameKind::Data => Some(InboundFrame::Data(frame.payload)),
        FrameKind::Eof => Some(InboundFrame::Eof),
        FrameKind::Close => Some(InboundFrame::Close),
        FrameKind::Error => {
            let reason = String::from_utf8_lossy(&frame.payload).into_owned();
            tracing::warn!("drive client: relay reported Error: {}", reason);
            Some(InboundFrame::Close)
        }
        FrameKind::Hello | FrameKind::Connect => None,
    }
}

// --------------------------------------------------------------------
// Error type
// --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("OAuth refresh failed: {0}")]
    Oauth(#[from] drive_oauth::OAuthError),
    #[error("Drive API error: {0}")]
    Api(#[from] crate::drive_api::DriveApiError),
    #[error("Drive upload semaphore closed")]
    UploadSemaphoreClosed,
    #[error("Drive worker semaphore closed")]
    WorkerSemaphoreClosed,
}

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drive_crypto::RelaySecret;

    fn fixed_sid() -> SessionId {
        [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00,
        ]
    }

    // ---- Adaptive interval ----------------------------------------

    #[test]
    fn adapt_interval_resets_on_work() {
        let mut streak = 5;
        let next = adapt_interval(300, true, &mut streak, false);
        assert_eq!(next, PIPELINE_INTERVAL_MS);
        assert_eq!(streak, 0);
    }

    #[test]
    fn adapt_interval_ramps_on_empty() {
        let mut streak = 0;
        let n1 = adapt_interval(300, false, &mut streak, false);
        assert_eq!(streak, 1);
        assert_eq!(n1, 300 + IDLE_BACKOFF_STEP_MS);
        let n2 = adapt_interval(300, false, &mut streak, false);
        assert_eq!(streak, 2);
        assert_eq!(n2, 300 + 2 * IDLE_BACKOFF_STEP_MS);
    }

    #[test]
    fn adapt_interval_caps_at_max_idle() {
        let mut streak = 0;
        for _ in 0..100 {
            let v = adapt_interval(300, false, &mut streak, false);
            assert!(v <= MAX_IDLE_INTERVAL_MS, "exceeded cap: {}", v);
        }
        // After many empty cycles we MUST land exactly on the cap.
        assert_eq!(
            adapt_interval(300, false, &mut streak, false),
            MAX_IDLE_INTERVAL_MS
        );
    }

    #[test]
    fn adapt_interval_stays_at_baseline_when_sessions_present() {
        // With at least one CONNECT registered, an empty cycle MUST
        // stay at baseline — idle backoff would add multi-second
        // tail latency to every r2c response after a brief lull.
        let mut streak = 7;
        let next = adapt_interval(300, false, &mut streak, true);
        assert_eq!(next, 300);
        assert_eq!(streak, 0, "session-present resets the empty streak");
    }

    #[test]
    fn adapt_interval_resumes_ramp_when_sessions_drop() {
        // Sessions present → no ramp; sessions then drop to zero →
        // ramp resumes from a fresh streak. Pins the transition
        // behaviour so a future refactor that forgets to reset
        // streak doesn't reintroduce a long first idle sleep.
        let mut streak = 4;
        let _ = adapt_interval(300, false, &mut streak, true);
        assert_eq!(streak, 0);
        let next = adapt_interval(300, false, &mut streak, false);
        assert_eq!(streak, 1);
        assert_eq!(next, 300 + IDLE_BACKOFF_STEP_MS);
    }

    fn parse_rfc3339(s: &str) -> time::OffsetDateTime {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
    }

    #[test]
    fn modified_cursor_advances_with_lookback() {
        // Files non-empty, file_max >= now → basis is file_max,
        // cursor advances to file_max - lookback.
        let mt = parse_rfc3339("2026-05-24T12:00:08Z");
        let files = vec![DriveFile {
            id: "id".into(),
            name: "r2c_x_1".into(),
            modified_time: Some(mt),
            size: Some(1),
        }];
        let mut cursor = None;
        advance_modified_cursor(&files, &mut cursor, mt);
        assert_eq!(cursor.as_deref(), Some("2026-05-24T12:00:00Z"));
    }

    #[test]
    fn modified_cursor_never_moves_backward() {
        let older = parse_rfc3339("2026-05-24T12:00:07Z");
        let files = vec![DriveFile {
            id: "id".into(),
            name: "r2c_x_1".into(),
            modified_time: Some(older),
            size: Some(1),
        }];
        let mut cursor = Some("2026-05-24T12:00:00Z".to_string());
        // Pass a `now` that matches file_max so the proposed value
        // is 11:59:59, strictly before the current cursor — must not move.
        advance_modified_cursor(&files, &mut cursor, older);
        assert_eq!(cursor.as_deref(), Some("2026-05-24T12:00:00Z"));
    }

    #[test]
    fn modified_cursor_advances_on_empty_listing() {
        // Empty listing must still advance the cursor — otherwise the
        // first poll's `name contains` path (used when cursor is None)
        // never gets swapped for the much-faster `modifiedTime >= ...`
        // path on subsequent polls.
        let now = parse_rfc3339("2026-05-24T12:00:08Z");
        let mut cursor: Option<String> = None;
        advance_modified_cursor(&[], &mut cursor, now);
        assert_eq!(cursor.as_deref(), Some("2026-05-24T12:00:00Z"));
    }

    #[test]
    fn modified_cursor_uses_wall_clock_when_files_older_than_now() {
        // file_max is well behind `now` (no recent traffic but the
        // folder has older leftover files in the listing) → cursor
        // should still advance based on `now`, not get anchored to
        // the stale file_max.
        let stale_mt = parse_rfc3339("2026-05-24T11:00:00Z");
        let now = parse_rfc3339("2026-05-24T12:00:08Z");
        let files = vec![DriveFile {
            id: "id".into(),
            name: "r2c_x_1".into(),
            modified_time: Some(stale_mt),
            size: Some(1),
        }];
        let mut cursor: Option<String> = None;
        advance_modified_cursor(&files, &mut cursor, now);
        assert_eq!(cursor.as_deref(), Some("2026-05-24T12:00:00Z"));
    }

    // ---- wire_to_inbound -------------------------------------------

    fn frame(kind: FrameKind, payload: &[u8]) -> WireFrame {
        WireFrame {
            version: WIRE_VERSION,
            kind,
            sid: fixed_sid(),
            seq: 0,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn wire_to_inbound_data_preserves_bytes() {
        let payload = b"\x00\x01\x02hello\xff\xfe";
        let f = frame(FrameKind::Data, payload);
        match wire_to_inbound(f).unwrap() {
            InboundFrame::Data(b) => assert_eq!(&b[..], payload),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn wire_to_inbound_eof_and_close() {
        assert!(matches!(
            wire_to_inbound(frame(FrameKind::Eof, b"")).unwrap(),
            InboundFrame::Eof
        ));
        assert!(matches!(
            wire_to_inbound(frame(FrameKind::Close, b"")).unwrap(),
            InboundFrame::Close
        ));
    }

    #[test]
    fn wire_to_inbound_error_maps_to_close() {
        // The relay can send an Error frame on dial failure. The
        // client maps it to Close (log the reason). Browser sees
        // the connection close — the right user-visible behavior
        // for "destination unreachable".
        assert!(matches!(
            wire_to_inbound(frame(FrameKind::Error, b"dial failed: connection refused")).unwrap(),
            InboundFrame::Close
        ));
    }

    #[test]
    fn wire_to_inbound_rejects_client_only_frame_kinds() {
        // Hello + Connect are uploaded by the client, never received
        // by the client. An r2c file carrying either is a protocol
        // violation; surface as None so the caller drops the frame.
        assert!(wire_to_inbound(frame(FrameKind::Hello, b"")).is_none());
        assert!(wire_to_inbound(frame(FrameKind::Connect, b"x.com:80")).is_none());
    }

    // ---- Outbound frame builders -----------------------------------

    #[test]
    fn build_wire_frame_fields_preserved() {
        let f = build_wire_frame(
            FrameKind::Data,
            fixed_sid(),
            42,
            Bytes::from_static(b"payload"),
        );
        assert_eq!(f.version, WIRE_VERSION);
        assert_eq!(f.kind, FrameKind::Data);
        assert_eq!(f.sid, fixed_sid());
        assert_eq!(f.seq, 42);
        assert_eq!(&f.payload[..], b"payload");
    }

    #[test]
    fn frame_filename_uses_correct_prefix_per_direction() {
        let c2r = frame_filename(Direction::ClientToRelay, fixed_sid(), 7);
        assert!(c2r.starts_with("c2r_"));
        let r2c = frame_filename(Direction::RelayToClient, fixed_sid(), 7);
        assert!(r2c.starts_with("r2c_"));
        // Both end with the same seq segment.
        assert!(c2r.ends_with("_7"));
        assert!(r2c.ends_with("_7"));
    }

    // ---- Wire compatibility with the relay -------------------------
    //
    // These tests prove the client's outbound frames are wire-
    // compatible with the relay's inbound handling. The key
    // derivation paths (`client_initiate` / `relay_accept`) are
    // already round-trip-tested in `drive_crypto`; here we lock in
    // the end-to-end seal+encode shape so a refactor on either side
    // can't silently break wire compat.

    fn matched_sessions() -> (SessionKeys, SessionKeys, SessionId) {
        // Mint one X25519 keypair, run client_initiate + relay_accept
        // — same DH agreement on both sides.
        let relay_secret = RelaySecret::generate(OsRng);
        let relay_pubkey = relay_secret.public_key();
        let sid = fixed_sid();
        let (client_keys, hello) =
            SessionKeys::client_initiate(&relay_pubkey, sid, OsRng).expect("client initiate");
        let relay_keys =
            SessionKeys::relay_accept(&relay_secret, sid, &hello).expect("relay accept");
        (client_keys, relay_keys, sid)
    }

    #[test]
    fn outbound_data_frame_round_trips_through_relay_simulation() {
        // Client seals with k_c2r → relay opens with k_c2r.
        let (client_keys, relay_keys, sid) = matched_sessions();
        assert_eq!(client_keys.k_c2r, relay_keys.k_c2r);

        let cipher = AeadCipher::new(&client_keys.k_c2r);
        let payload = Bytes::from_static(b"GET / HTTP/1.1\r\n");
        let frame = build_wire_frame(FrameKind::Data, sid, 1, payload.clone());
        let batch = drive_wire::frame::Batch::single(frame);
        let sealed = seal_batch(&cipher, sid, &batch);

        // Simulate the relay's process_frame: open with k_c2r, then
        // verify the batch bytes decode back to the expected frame.
        let relay_cipher = AeadCipher::new(&relay_keys.k_c2r);
        let opened = relay_cipher
            .open(&sid, 1, &sealed)
            .expect("relay must open client's Data frame");
        let opened_batch = drive_wire::frame::Batch::decode(&opened).expect("batch decode");
        let opened_frame = &opened_batch.frames[0];
        assert_eq!(opened_frame.kind, FrameKind::Data);
        assert_eq!(opened_frame.sid, sid);
        assert_eq!(opened_frame.seq, 1);
        assert_eq!(&opened_frame.payload[..], &payload[..]);
    }

    #[test]
    fn outbound_connect_frame_payload_round_trips() {
        // The host:port payload the client puts in a Connect frame
        // must parse back via the relay's `parse_connect_addr`. We
        // can't directly call the relay's parser from rahgozar (it
        // lives in the drive-relay crate), but the conversion is
        // simple enough to mirror in-line here.
        let (client_keys, relay_keys, sid) = matched_sessions();
        let cipher = AeadCipher::new(&client_keys.k_c2r);

        let host = "example.com";
        let port = 443u16;
        let payload = Bytes::from(format!("{host}:{port}").into_bytes());
        let frame = build_wire_frame(FrameKind::Connect, sid, 0, payload.clone());
        let batch = drive_wire::frame::Batch::single(frame);
        let sealed = seal_batch(&cipher, sid, &batch);

        let relay_cipher = AeadCipher::new(&relay_keys.k_c2r);
        let opened = relay_cipher.open(&sid, 0, &sealed).unwrap();
        let opened_batch = drive_wire::frame::Batch::decode(&opened).unwrap();
        let opened_frame = &opened_batch.frames[0];
        assert_eq!(opened_frame.kind, FrameKind::Connect);

        // Manually reparse the payload as the relay does. If the
        // relay's `parse_connect_addr` ever diverges from this
        // shape, the drive-relay's own test for it will catch it.
        let s = std::str::from_utf8(&opened_frame.payload).unwrap();
        let (got_host, got_port) = s.rsplit_once(':').unwrap();
        assert_eq!(got_host, host);
        assert_eq!(got_port.parse::<u16>().unwrap(), port);
    }

    #[test]
    fn session_open_batch_embeds_first_client_bytes_after_connect() {
        let (client_keys, relay_keys, sid) = matched_sessions();
        let cipher = AeadCipher::new(&client_keys.k_c2r);
        let mut next_seq = 1;
        let first_payload = Bytes::from_static(b"\x16\x03\x01fake client hello");
        let initial_frames = data_frames_from_bytes(sid, &mut next_seq, first_payload.clone());
        let batch = build_session_open_batch(sid, "example.com", 443, initial_frames);
        let sealed = seal_batch(&cipher, sid, &batch);

        assert_eq!(next_seq, 2, "first embedded Data consumes seq=1");

        let relay_cipher = AeadCipher::new(&relay_keys.k_c2r);
        let opened = relay_cipher.open(&sid, 0, &sealed).unwrap();
        let opened_batch = drive_wire::frame::Batch::decode(&opened).unwrap();
        assert_eq!(opened_batch.frames.len(), 2);
        assert_eq!(opened_batch.frames[0].kind, FrameKind::Connect);
        assert_eq!(opened_batch.frames[0].seq, 0);
        assert_eq!(opened_batch.frames[1].kind, FrameKind::Data);
        assert_eq!(opened_batch.frames[1].seq, 1);
        assert_eq!(&opened_batch.frames[1].payload[..], &first_payload[..]);
    }

    #[test]
    fn hello_body_round_trips_to_relay_session_keys() {
        // Client's Hello body is the only unsealed payload on the
        // wire. The relay decodes it + runs `relay_accept` and
        // must derive the same keys the client got from
        // `client_initiate`.
        let relay_secret = RelaySecret::generate(OsRng);
        let relay_pubkey = relay_secret.public_key();
        let sid = fixed_sid();
        let (client_keys, hello) =
            SessionKeys::client_initiate(&relay_pubkey, sid, OsRng).expect("client initiate");

        let encoded = hello.encode();
        let decoded = HelloBody::decode(&encoded).unwrap();
        assert_eq!(decoded, hello);

        let relay_keys =
            SessionKeys::relay_accept(&relay_secret, sid, &decoded).expect("relay accept");
        assert_eq!(client_keys.k_c2r, relay_keys.k_c2r);
        assert_eq!(client_keys.k_r2c, relay_keys.k_r2c);
    }

    #[test]
    fn r2c_response_round_trips_to_client() {
        // Symmetric of `outbound_data_frame_...`: the relay seals
        // with k_r2c, the client opens with k_r2c. Locks in the
        // r2c-direction wire compat.
        let (client_keys, relay_keys, sid) = matched_sessions();
        assert_eq!(client_keys.k_r2c, relay_keys.k_r2c);

        let relay_cipher = AeadCipher::new(&relay_keys.k_r2c);
        let payload = Bytes::from_static(b"HTTP/1.1 200 OK\r\n");
        let frame = build_wire_frame(FrameKind::Data, sid, 0, payload.clone());
        let batch = drive_wire::frame::Batch::single(frame);
        let plaintext = batch.encode().freeze();
        let sealed = relay_cipher.seal(&sid, 0, &plaintext);

        let client_cipher = AeadCipher::new(&client_keys.k_r2c);
        let opened = client_cipher.open(&sid, 0, &sealed).unwrap();
        let opened_batch = drive_wire::frame::Batch::decode(&opened).unwrap();
        let opened_frame = &opened_batch.frames[0];
        assert_eq!(opened_frame.kind, FrameKind::Data);
        assert_eq!(&opened_frame.payload[..], &payload[..]);
    }

    // ---- Token cache (cache-hit only; HTTP path is covered by the
    //      relay's identical TokenCache + the wiremock e2e slice). --

    #[tokio::test]
    async fn token_cache_returns_cached_when_fresh() {
        let http = build_drive_http_client(None).expect("build client");
        let cache = TokenCache::new(
            "REFRESH".into(),
            "test-client.apps.googleusercontent.com".into(),
            "test-secret".into(),
            http,
        );
        // Manually populate the cached entry to simulate a recent
        // successful refresh.
        {
            let mut guard = cache.cached.lock().await;
            *guard = Some(drive_oauth::OAuthTokens {
                access_token: "ya29.fresh".into(),
                refresh_token: None,
                expires_at: Instant::now() + Duration::from_secs(3600),
                scope: String::new(),
            });
        }
        let token = cache.get().await.expect("cache hit");
        assert_eq!(token, "ya29.fresh");
    }
}
