//! Drive-mode client — Google Drive as a covert mailbox transport.
//!
//! Mirrors the Skirk technique (ShahabSL/Skirk): every TCP session
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
//! | Direction | Client (this module)                | Relay
//! | --------- | ----------------------------------- | -----
//! | c2r_*     | Mint, encode, AEAD-seal with k_c2r, upload | Poll, download, AEAD-open with k_c2r
//! | r2c_*     | Poll, download, AEAD-open with k_r2c | Encode, AEAD-seal with k_r2c, upload
//! | h_*       | Mint Hello body, upload (unsealed)  | Poll, parse, derive keys via `relay_accept`
//!
//! ## Limitations (v1)
//!
//! - **Sequential uploads** per session. A burst of small TCP reads
//!   becomes a chain of one-at-a-time Drive uploads; the next read
//!   doesn't happen until the previous upload returns. Drive's QPS
//!   budget is the bottleneck anyway, so the latency cost is
//!   small in practice. Parallel uploads (with `max_concurrent_uploads`
//!   as the cap) are a v2 optimisation.
//! - **No client-side orphan reaper.** Stale `r2c_*` files (relay
//!   pushed after we closed the local socket) accumulate in the
//!   shared folder until the relay's own reaper sweeps them. Fine
//!   for now — the relay reaper sweeps every 2 minutes.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use drive_wire::filename::{parse_filename, Direction, DriveFilename, FilenameKind};
use drive_wire::frame::{FrameKind, SessionId, WireFrame, WIRE_VERSION};
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

/// Mailbox depth between the r2c poll worker and a per-session
/// driver. Small enough to apply back-pressure if the local socket
/// can't keep up; large enough that one poll cycle's burst lands
/// without stalling the worker.
const SESSION_MAILBOX_DEPTH: usize = 64;

/// After any non-empty poll cycle, drop the next sleep to this
/// value (pipeline mode). Lets a burst of inbound replies land
/// without paying the baseline interval again.
const PIPELINE_INTERVAL_MS: u64 = 100;

/// Each consecutive empty cycle adds this much to the next sleep.
const IDLE_BACKOFF_STEP_MS: u64 = 200;

/// Cap on the idle sleep — keeps the polling cost low even when
/// the proxy is unused, but bounds the wake-up latency when a
/// session finally lands.
const MAX_IDLE_INTERVAL_MS: u64 = 5_000;

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
        token_cache
            .get()
            .await
            .map_err(|e| std::io::Error::other(format!("drive oauth refresh: {e}")))?;

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
    sock: TcpStream,
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
    //    a poll cycle racing our Hello upload land in the
    //    table-populated state. The relay can't produce an r2c
    //    before it sees our c2r_<sid>_0 (Connect), and that c2r
    //    upload happens AFTER the Hello — so this ordering is
    //    correct, but the defensive shape costs nothing.
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

    // 4. Upload Hello (UNSEALED) + initial Connect (sealed at seq=0).
    if let Err(e) = upload_hello(&inner, sid, &hello).await {
        tracing::warn!(
            "drive session {:?}: hello upload failed for {}:{}: {}",
            sid,
            host,
            port,
            e
        );
        return Err(std::io::Error::other(format!("hello upload: {e}")));
    }
    let send_cipher = AeadCipher::new(&keys.k_c2r);
    if let Err(e) = upload_connect_frame(&inner, sid, &send_cipher, host, port).await {
        tracing::warn!(
            "drive session {:?}: connect frame upload failed for {}:{}: {}",
            sid,
            host,
            port,
            e
        );
        return Err(std::io::Error::other(format!("connect upload: {e}")));
    }
    tracing::info!("drive session {:?}: opened to {}:{}", sid, host, port);

    // 5. Optional initial client payload, used when the HTTP proxy
    //    path has already read bytes from the local socket before
    //    the Drive session existed. Connect was seq=0, so prefaced
    //    Data starts at seq=1 and the live pump continues after it.
    let mut next_c2r_seq: u64 = 1;
    if !initial_client_bytes.is_empty() {
        for chunk in initial_client_bytes.chunks(LOCAL_SOCKET_READ_BUFFER) {
            let seq = next_c2r_seq;
            next_c2r_seq += 1;
            if let Err(e) = upload_data_frame(
                &inner,
                sid,
                seq,
                &send_cipher,
                Bytes::copy_from_slice(chunk),
            )
            .await
            {
                tracing::warn!(
                    "drive session {:?}: initial c2r upload failed at seq={}: {}",
                    sid,
                    seq,
                    e
                );
                return Err(std::io::Error::other(format!("initial c2r upload: {e}")));
            }
        }
    }

    // 6. Steady-state pump until either side closes. `pump_session`
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

/// Seal a wire frame with the given (sid, seq) bound to the AAD
/// and return the ciphertext ready for upload.
fn seal_frame(cipher: &AeadCipher, frame: &WireFrame) -> Vec<u8> {
    let plaintext = frame.encode().freeze();
    cipher.seal(&frame.sid, frame.seq, &plaintext)
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
    Ok(())
}

/// Upload the unsealed Hello body as `h_<sid>_0`. Hello is the
/// key-agreement input; the rest of the session is AEAD-sealed.
async fn upload_hello(
    inner: &DriveMuxInner,
    sid: SessionId,
    hello: &HelloBody,
) -> Result<(), ClientError> {
    let name = DriveFilename {
        kind: FilenameKind::Hello,
        sid,
        seq: 0,
    }
    .format();
    let body = Bytes::from(hello.encode().to_vec());
    let token = inner.token_cache.get().await?;
    let _permit = inner
        .upload_permits
        .acquire()
        .await
        .map_err(|_| ClientError::UploadSemaphoreClosed)?;
    inner
        .drive_api
        .upload_file(&token, &inner.cfg.folder_id, &name, body)
        .await?;
    Ok(())
}

/// Build, seal, and upload the initial Connect frame. Payload is
/// the destination address as `host:port`; the relay's
/// `frame_to_inbound` parses it back via `parse_connect_addr`.
async fn upload_connect_frame(
    inner: &DriveMuxInner,
    sid: SessionId,
    cipher: &AeadCipher,
    host: &str,
    port: u16,
) -> Result<(), ClientError> {
    let payload = Bytes::from(format!("{host}:{port}").into_bytes());
    let frame = build_wire_frame(FrameKind::Connect, sid, 0, payload);
    let sealed = seal_frame(cipher, &frame);
    upload_c2r_frame(inner, sid, 0, sealed).await
}

/// Build, seal, and upload one Data frame.
async fn upload_data_frame(
    inner: &DriveMuxInner,
    sid: SessionId,
    seq: u64,
    cipher: &AeadCipher,
    payload: Bytes,
) -> Result<(), ClientError> {
    let frame = build_wire_frame(FrameKind::Data, sid, seq, payload);
    let sealed = seal_frame(cipher, &frame);
    upload_c2r_frame(inner, sid, seq, sealed).await
}

/// Build, seal, and upload an Eof frame (writer-side half-close).
async fn upload_eof_frame(
    inner: &DriveMuxInner,
    sid: SessionId,
    seq: u64,
    cipher: &AeadCipher,
) -> Result<(), ClientError> {
    let frame = build_wire_frame(FrameKind::Eof, sid, seq, Bytes::new());
    let sealed = seal_frame(cipher, &frame);
    upload_c2r_frame(inner, sid, seq, sealed).await
}

/// Build, seal, and upload a Close frame (full close).
async fn upload_close_frame(
    inner: &DriveMuxInner,
    sid: SessionId,
    cipher: &AeadCipher,
    seq: u64,
) -> Result<(), ClientError> {
    let frame = build_wire_frame(FrameKind::Close, sid, seq, Bytes::new());
    let sealed = seal_frame(cipher, &frame);
    upload_c2r_frame(inner, sid, seq, sealed).await
}

// --------------------------------------------------------------------
// Per-session pump
// --------------------------------------------------------------------

/// Bidirectional pump for one session. Runs to completion as the
/// dispatcher's call frame; returns when either:
///   - both directions reach EOF: uploads the final Close, exits Ok
///   - local socket error: uploads Close best-effort, exits Err
///   - InboundFrame::Close received: shuts down local socket, exits Ok
///   - inbound channel closed (mux dropped): exits Ok
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

    loop {
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
                            let _ = upload_close_frame(inner, sid, cipher, next_c2r_seq).await;
                            return Err(e);
                        }
                    }
                    Some(InboundFrame::Eof) => {
                        // Relay half-closed its write side (real destination
                        // closed). Shutdown the local write so the browser
                        // sees EOF on read. If the browser already half-closed
                        // its write side, both directions are done and Close is
                        // now safe as the final teardown signal.
                        if let Err(e) = sock.shutdown().await {
                            tracing::debug!(
                                "drive session {:?}: local shutdown failed: {}", sid, e
                            );
                        }
                        local_writable = false;
                        if local_read_closed {
                            let close_seq = next_c2r_seq;
                            if let Err(e) = upload_close_frame(inner, sid, cipher, close_seq).await {
                                tracing::debug!(
                                    "drive session {:?}: Close upload failed: {}",
                                    sid,
                                    e
                                );
                            }
                            return Ok(());
                        }
                    }
                    Some(InboundFrame::Close) | None => {
                        // Relay sent Close, OR the mux dropped (channel
                        // closed). Either way, the session is done.
                        // Don't upload another Close — relay either sent
                        // one already (loop case) or no longer cares
                        // (mux dropped case).
                        return Ok(());
                    }
                }
            }
            read_result = sock.read(&mut read_buf), if !local_read_closed => {
                match read_result {
                    Ok(0) => {
                        // Local EOF (browser half-closed write). Upload Eof
                        // and keep receiving r2c frames; some protocols use
                        // this to mark end-of-request while still expecting a
                        // response body.
                        let eof_seq = next_c2r_seq;
                        next_c2r_seq += 1;
                        if let Err(e) = upload_eof_frame(inner, sid, eof_seq, cipher).await {
                            tracing::debug!(
                                "drive session {:?}: Eof upload failed: {}", sid, e
                            );
                        }
                        local_read_closed = true;
                        if !local_writable {
                            let close_seq = next_c2r_seq;
                            if let Err(e) = upload_close_frame(inner, sid, cipher, close_seq).await {
                                tracing::debug!(
                                    "drive session {:?}: Close upload failed: {}",
                                    sid,
                                    e
                                );
                            }
                            return Ok(());
                        }
                    }
                    Ok(n) => {
                        let payload = Bytes::copy_from_slice(&read_buf[..n]);
                        let seq = next_c2r_seq;
                        next_c2r_seq += 1;
                        if let Err(e) = upload_data_frame(inner, sid, seq, cipher, payload).await {
                            tracing::warn!(
                                "drive session {:?}: c2r upload failed at seq={}: {}",
                                sid, seq, e
                            );
                            return Err(std::io::Error::other(format!("c2r upload: {e}")));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "drive session {:?}: local read failed: {}", sid, e
                        );
                        let _ = upload_close_frame(inner, sid, cipher, next_c2r_seq).await;
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
        let found = run_one_cycle(inner).await;
        interval_ms = adapt_interval(baseline_ms, found, &mut empty_streak);
    }
}

/// Adaptive-interval computation, factored out for unit testing.
/// On `found_work`: drop to pipeline interval. On empty: ramp
/// `baseline + step * empty_streak`, capped at `MAX_IDLE_INTERVAL_MS`.
fn adapt_interval(baseline_ms: u64, found_work: bool, empty_streak: &mut u64) -> u64 {
    if found_work {
        *empty_streak = 0;
        PIPELINE_INTERVAL_MS
    } else {
        *empty_streak = empty_streak.saturating_add(1);
        baseline_ms
            .saturating_add(IDLE_BACKOFF_STEP_MS.saturating_mul(*empty_streak))
            .min(MAX_IDLE_INTERVAL_MS)
    }
}

/// Run one poll iteration. Returns true iff at least one r2c file
/// was processed (drives the adaptive interval).
async fn run_one_cycle(inner: Arc<DriveMuxInner>) -> bool {
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

    let files = match inner
        .drive_api
        .list_files_in_folder(&access_token, &inner.cfg.folder_id, "r2c_")
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("drive client: list r2c_* failed: {}", e);
            return false;
        }
    };

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
    let permits = Arc::new(tokio::sync::Semaphore::new(permits_cap));

    // Group by sid + process each sid serially. Different sids
    // still run in parallel (bounded by the semaphore). Same
    // rationale as the relay's poll loop: per-sid serial preserves
    // wire ordering — concurrent r2c workers for c2r_0+c2r_1 of
    // the same session race after the replay-window check and
    // can deliver Data frames out of seq order to the session's
    // mpsc, which writes them to the local socket in wrong order.
    // For TLS that's a flow-killer; for plaintext HTTP it's a
    // silent corruption.
    let mut frames_by_sid: std::collections::HashMap<SessionId, Vec<(DriveFile, DriveFilename)>> =
        std::collections::HashMap::new();
    for entry in sorted {
        frames_by_sid.entry(entry.1.sid).or_default().push(entry);
    }
    let mut workers: JoinSet<()> = JoinSet::new();
    for (_sid, group) in frames_by_sid {
        let inner = inner.clone();
        let access_token = access_token.clone();
        let permit = match permits.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return true,
        };
        workers.spawn(async move {
            let _permit = permit;
            for (file, parsed) in group {
                if let Err(e) = process_r2c_frame(&inner, &access_token, file, parsed).await {
                    tracing::warn!("drive client: r2c frame processing failed: {}", e);
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
    true
}

/// Download, decrypt, and dispatch one r2c frame to the
/// per-session driver. Symmetric to the relay's `process_frame`.
async fn process_r2c_frame(
    inner: &DriveMuxInner,
    access_token: &str,
    file: DriveFile,
    parsed: DriveFilename,
) -> Result<(), ClientError> {
    // Snapshot session state under the read lock; drop the lock
    // before any await on Drive.
    let session_view = {
        let sessions = inner.sessions.read().await;
        sessions
            .get(&parsed.sid)
            .map(|h| (h.keys.clone(), h.replay.clone(), h.inbound_tx.clone()))
    };
    let (keys, replay, inbound_tx) = match session_view {
        Some(v) => v,
        None => {
            // No session — probably a stale r2c from a session
            // whose tunnel_connection has already returned (and
            // whose SessionGuard removed the entry). Best-effort
            // delete to keep the listing tidy.
            let _ = inner.drive_api.delete_file(access_token, &file.id).await;
            tracing::debug!(
                "drive client: r2c {} dropped (no session for sid {:?})",
                file.name,
                parsed.sid
            );
            return Ok(());
        }
    };

    // Strict replay/ordering check on filename seq BEFORE download.
    // Pure *check* — we deliberately do NOT advance the window here.
    // Advance happens after delivery completes successfully
    // (`commit` below). A transient download / AEAD / dispatch
    // failure would otherwise permanently consume the seq and the
    // redelivered file would be wrongly rejected as a replay next
    // poll. Future frames are left in Drive until the missing earlier
    // seq becomes visible.
    {
        let window = replay.lock().await;
        match window.check_next(parsed.seq) {
            Ok(()) => {}
            Err(StrictSeqError::Replay(e)) => {
                tracing::debug!(
                    "drive client: r2c {} rejected by replay window: {}",
                    file.name,
                    e
                );
                let _ = inner.drive_api.delete_file(access_token, &file.id).await;
                return Ok(());
            }
            Err(StrictSeqError::Future { expected, .. }) => {
                tracing::debug!(
                    "drive client: r2c {} arrived before seq {}; leaving for a later poll",
                    file.name,
                    expected
                );
                return Ok(());
            }
        }
    }

    if let Some(size) = file.size {
        if size > MAX_SEALED_FRAME_BODY_BYTES {
            tracing::warn!(
                "drive client: r2c {} is {} bytes; maximum accepted is {}; deleting",
                file.name,
                size,
                MAX_SEALED_FRAME_BODY_BYTES
            );
            let _ = inner.drive_api.delete_file(access_token, &file.id).await;
            return Ok(());
        }
    }

    let sealed = match inner
        .drive_api
        .download_file(access_token, &file.id, MAX_SEALED_FRAME_BODY_BYTES)
        .await
    {
        Ok(bytes) => bytes,
        Err(DriveApiError::ResponseTooLarge { .. }) => {
            tracing::warn!(
                "drive client: r2c {} exceeded the protocol size cap; deleting",
                file.name
            );
            let _ = inner.drive_api.delete_file(access_token, &file.id).await;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let cipher = AeadCipher::new(&keys.k_r2c);
    let plaintext = match cipher.open(&parsed.sid, parsed.seq, &sealed) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::warn!("drive client: r2c {} AEAD open failed: {}", file.name, e);
            // Don't delete — could be a corrupted listing entry the
            // relay's orphan reaper will sweep by modifiedTime. Don't
            // advance the replay window either — leaves the window
            // open for the next-poll retry to succeed.
            return Ok(());
        }
    };
    let wire = match WireFrame::decode(&plaintext) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("drive client: r2c {} wire decode failed: {}", file.name, e);
            return Ok(());
        }
    };
    // Defense in depth: filename (sid, seq) must match wire frame
    // (sid, seq). Already bound in AAD; this is a belt-and-suspenders
    // check that would catch a future encoding bug loudly.
    if wire.sid != parsed.sid || wire.seq != parsed.seq {
        tracing::warn!(
            "drive client: r2c {} sid/seq mismatch (filename vs wire frame)",
            file.name
        );
        return Ok(());
    }

    let inbound = match wire_to_inbound(wire) {
        Some(i) => i,
        None => {
            tracing::warn!(
                "drive client: r2c {} carried an unexpected frame kind; ignoring",
                file.name
            );
            return Ok(());
        }
    };
    if let Err(e) = inbound_tx.send(inbound).await {
        tracing::debug!(
            "drive client: r2c {}: session driver gone, dropping inbound: {}",
            file.name,
            e
        );
    }

    // Advance the replay window now that the frame has been fully
    // decoded + dispatched to the per-session driver. Doing this
    // BEFORE delivery would let a transient failure permanently
    // consume the seq; see `ReplayWindow::check` for the rationale.
    {
        let mut window = replay.lock().await;
        window.commit(parsed.seq);
    }

    if let Err(e) = inner.drive_api.delete_file(access_token, &file.id).await {
        tracing::debug!("drive client: r2c {} delete failed: {}", file.name, e);
    }
    Ok(())
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
        let next = adapt_interval(300, true, &mut streak);
        assert_eq!(next, PIPELINE_INTERVAL_MS);
        assert_eq!(streak, 0);
    }

    #[test]
    fn adapt_interval_ramps_on_empty() {
        let mut streak = 0;
        let n1 = adapt_interval(300, false, &mut streak);
        assert_eq!(streak, 1);
        assert_eq!(n1, 300 + IDLE_BACKOFF_STEP_MS);
        let n2 = adapt_interval(300, false, &mut streak);
        assert_eq!(streak, 2);
        assert_eq!(n2, 300 + 2 * IDLE_BACKOFF_STEP_MS);
    }

    #[test]
    fn adapt_interval_caps_at_max_idle() {
        let mut streak = 0;
        for _ in 0..100 {
            let v = adapt_interval(300, false, &mut streak);
            assert!(v <= MAX_IDLE_INTERVAL_MS, "exceeded cap: {}", v);
        }
        // After many empty cycles we MUST land exactly on the cap.
        assert_eq!(
            adapt_interval(300, false, &mut streak),
            MAX_IDLE_INTERVAL_MS
        );
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
        let sealed = seal_frame(&cipher, &frame);

        // Simulate the relay's process_frame: open with k_c2r, then
        // verify the wire bytes decode back to the expected frame.
        let relay_cipher = AeadCipher::new(&relay_keys.k_c2r);
        let opened = relay_cipher
            .open(&sid, 1, &sealed)
            .expect("relay must open client's Data frame");
        let opened_frame = WireFrame::decode(&opened).expect("wire decode");
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
        let sealed = seal_frame(&cipher, &frame);

        let relay_cipher = AeadCipher::new(&relay_keys.k_c2r);
        let opened = relay_cipher.open(&sid, 0, &sealed).unwrap();
        let opened_frame = WireFrame::decode(&opened).unwrap();
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
        let plaintext = frame.encode().freeze();
        let sealed = relay_cipher.seal(&sid, 0, &plaintext);

        let client_cipher = AeadCipher::new(&client_keys.k_r2c);
        let opened = client_cipher.open(&sid, 0, &sealed).unwrap();
        let opened_frame = WireFrame::decode(&opened).unwrap();
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
