//! Per-session driver task.
//!
//! One task per active session. Owns the dialed `TcpStream`, the
//! inbound mailbox from the poll worker, and the seal+upload path
//! for outbound r2c frames.
//!
//! Lifecycle:
//!
//! ```text
//!  start
//!    │
//!    │  await first inbound  ──► must be Connect; else exit
//!    ▼
//!  dial destination
//!    │
//!    │  on dial failure: upload an Error frame, exit
//!    ▼
//!  steady state — select! between:
//!    • inbound recv:   Data → write to TCP;  Eof → shutdown(WR); Close → exit
//!    • tcp.read:       n>0  → seal + upload r2c;  EOF → upload Eof, keep accepting c2r until both directions end
//!
//!  exit
//!    │  (driver task terminating; orphan reaper later evicts the
//!    │  SessionHandle from the table — driver doesn't self-remove
//!    │  to keep the table lock off the hot path)
//!    ▼
//! ```
//!
//! The seal+upload path consumes the next monotonic r2c sequence
//! number per outbound frame; replay protection on the client
//! side relies on this counter being strictly increasing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use drive_wire::filename::{Direction, DriveFilename, FilenameKind};
use drive_wire::frame::{Batch, FrameKind, SessionId, WireFrame, WIRE_VERSION};
use rahgozar::drive_crypto::{AeadCipher, SessionKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::state::{InboundFrame, RelayState};

/// 16 KiB read buffer per session. Each TCP read produces one
/// r2c Data frame — small reads mean small frames mean low
/// latency per RTT; the Drive upload itself is the bottleneck,
/// not the buffer size.
const TCP_READ_BUFFER: usize = 16 * 1024;

// ── r2c batching (mirror of client's c2r batching) ──────────────────
//
// Multiple Data frames coalesce into one Drive file upload via a
// size-tiered wait window, matching the client's policy. The client
// poller parses each Drive file as a multi-frame Batch.
const R2C_COALESCE_INTERACTIVE_BYTES: usize = 8 * 1024;
const R2C_COALESCE_INTERACTIVE_DELAY: Duration = Duration::from_millis(5);
const R2C_COALESCE_MEDIUM_BYTES: usize = 64 * 1024;
const R2C_COALESCE_MEDIUM_DELAY: Duration = Duration::from_millis(50);
const R2C_COALESCE_BULK_DELAY: Duration = Duration::from_millis(100);
const R2C_BATCH_FLUSH_BYTES: usize = 1024 * 1024;
const R2C_BATCH_MAX_FRAMES: usize = 200;

/// Run one session to completion. Spawned per-Hello by the poll
/// worker; the spawned `JoinHandle` lives in
/// [`crate::state::SessionHandle::task`].
#[allow(unused_assignments)] // `next_r2c_seq += 1` before some returns is intentional bookkeeping
pub async fn session_driver(
    sid: SessionId,
    keys: Arc<SessionKeys>,
    state: Arc<RelayState>,
    mut inbound_rx: mpsc::Receiver<InboundFrame>,
    last_seen: Arc<Mutex<Instant>>,
) {
    let send_cipher = AeadCipher::new(&keys.k_r2c);
    let mut next_r2c_seq: u64 = 0;

    // ---- Phase 1: wait for Connect --------------------------------
    let (host, port) = match inbound_rx.recv().await {
        Some(InboundFrame::Connect { host, port }) => (host, port),
        Some(other) => {
            tracing::warn!(
                "session {:?}: first inbound was {:?}, not Connect — exiting",
                sid,
                std::mem::discriminant(&other)
            );
            return;
        }
        None => {
            // Channel closed before any frame arrived — caller dropped
            // the SessionHandle (shutdown, or orphan reaper). Exit
            // quietly.
            return;
        }
    };
    bump_last_seen(&last_seen).await;

    if !destination_allowed(&state, &host) {
        tracing::warn!(
            "session {:?}: destination {}:{} not in allow_destinations; refusing",
            sid,
            host,
            port,
        );
        upload_error_frame(
            &state,
            &sid,
            next_r2c_seq,
            &send_cipher,
            "destination not on allow list",
        )
        .await;
        return;
    }

    let dial_permit = match state.dial_permits.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("session {:?}: dial semaphore closed", sid);
            upload_error_frame(
                &state,
                &sid,
                next_r2c_seq,
                &send_cipher,
                "relay shutting down",
            )
            .await;
            return;
        }
    };
    let mut tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => {
            tracing::info!("session {:?}: dialed {}:{}", sid, host, port);
            s
        }
        Err(e) => {
            tracing::warn!("session {:?}: dial {}:{} failed: {}", sid, host, port, e);
            upload_error_frame(
                &state,
                &sid,
                next_r2c_seq,
                &send_cipher,
                &format!("dial failed: {e}"),
            )
            .await;
            return;
        }
    };
    drop(dial_permit);
    let _ = tcp.set_nodelay(true);

    // ---- Phase 2: steady-state pump -------------------------------
    let mut read_buf = vec![0u8; TCP_READ_BUFFER];
    let mut peer_writable = true; // false after we receive Eof from client
    let mut tcp_read_closed = false; // false until destination half-closes its write side

    // Outbound r2c batch state. See client pump_session for the
    // mirror-image accumulator on the c2r side.
    let mut pending: Vec<WireFrame> = Vec::new();
    let mut pending_bytes: usize = 0;
    let mut flush_deadline: Option<tokio::time::Instant> = None;
    // Prioritize the first bytes after each client write burst. TLS
    // hides HTTP response boundaries from the relay, but inbound c2r
    // Data is a good signal that the next destination bytes are a
    // response start. Flush the first couple of r2c frames eagerly so
    // TTFB is not trapped behind a megabyte-sized bulk object.
    let mut eager_response_burst = true;
    loop {
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
                    Some(InboundFrame::Connect { .. }) => {
                        tracing::warn!("session {:?}: redundant Connect frame ignored", sid);
                    }
                    Some(InboundFrame::Data(bytes)) => {
                        bump_last_seen(&last_seen).await;
                        if !peer_writable {
                            tracing::warn!(
                                "session {:?}: Data received after Eof; dropping {} bytes",
                                sid,
                                bytes.len()
                            );
                            continue;
                        }
                        if let Err(e) = tcp.write_all(&bytes).await {
                            tracing::warn!(
                                "session {:?}: tcp write failed: {} ({} bytes dropped)",
                                sid,
                                e,
                                bytes.len()
                            );
                            flush_r2c_batch(
                                &state, &sid, &send_cipher,
                                &mut pending, &mut pending_bytes, &mut flush_deadline,
                                &mut eager_response_burst,
                            );
                            return;
                        }
                        if !pending.is_empty() {
                            flush_r2c_batch(
                                &state, &sid, &send_cipher,
                                &mut pending, &mut pending_bytes, &mut flush_deadline,
                                &mut eager_response_burst,
                            );
                        }
                        eager_response_burst = true;
                    }
                    Some(InboundFrame::Eof) => {
                        bump_last_seen(&last_seen).await;
                        if let Err(e) = tcp.shutdown().await {
                            tracing::debug!("session {:?}: tcp shutdown failed: {}", sid, e);
                        }
                        peer_writable = false;
                        if tcp_read_closed {
                            let close_seq = next_r2c_seq;
                            next_r2c_seq += 1;
                            push_r2c_frame(
                                &state, &sid, &send_cipher,
                                &mut pending, &mut pending_bytes, &mut flush_deadline,
                                &mut eager_response_burst,
                                FrameKind::Close, close_seq, Bytes::new(), true,
                            );
                            return;
                        }
                    }
                    Some(InboundFrame::Close) | None => {
                        // Flush any pending r2c before exiting so the
                        // client sees the trailing bytes from the
                        // destination before we vanish.
                        flush_r2c_batch(
                            &state, &sid, &send_cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                            &mut eager_response_burst,
                        );
                        return;
                    }
                }
            }
            _ = &mut timer_future => {
                flush_r2c_batch(
                    &state, &sid, &send_cipher,
                    &mut pending, &mut pending_bytes, &mut flush_deadline,
                    &mut eager_response_burst,
                );
            }
            read_result = tcp.read(&mut read_buf), if !tcp_read_closed => {
                match read_result {
                    Ok(0) => {
                        // Remote EOF: half-close. Send Eof (flush_now=true).
                        // If peer already half-closed its write, send Close too.
                        let eof_seq = next_r2c_seq;
                        next_r2c_seq += 1;
                        push_r2c_frame(
                            &state, &sid, &send_cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                            &mut eager_response_burst,
                            FrameKind::Eof, eof_seq, Bytes::new(), true,
                        );
                        tcp_read_closed = true;
                        if !peer_writable {
                            let close_seq = next_r2c_seq;
                            next_r2c_seq += 1;
                            push_r2c_frame(
                                &state, &sid, &send_cipher,
                                &mut pending, &mut pending_bytes, &mut flush_deadline,
                                &mut eager_response_burst,
                                FrameKind::Close, close_seq, Bytes::new(), true,
                            );
                            return;
                        }
                    }
                    Ok(n) => {
                        bump_last_seen(&last_seen).await;
                        let payload = Bytes::copy_from_slice(&read_buf[..n]);
                        let seq = next_r2c_seq;
                        next_r2c_seq += 1;
                        push_r2c_frame(
                            &state, &sid, &send_cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                            &mut eager_response_burst,
                            FrameKind::Data, seq, payload, false,
                        );
                    }
                    Err(e) => {
                        tracing::warn!("session {:?}: tcp read failed: {}", sid, e);
                        flush_r2c_batch(
                            &state, &sid, &send_cipher,
                            &mut pending, &mut pending_bytes, &mut flush_deadline,
                            &mut eager_response_burst,
                        );
                        return;
                    }
                }
            }
        }
    }
}

/// Filter Connect-target hosts against `cfg.allow_destinations` and
/// the SSRF guard:
///
///   - **Allowlist match** (any non-empty entry matches): allow.
///     This is the operator's final say. An operator who wants to
///     dial internal IPs (e.g. relay running on a corporate VPN
///     exit node) can list them explicitly.
///   - **Empty allowlist + IP literal pointing at internal network**:
///     refuse. This is the SSRF guard — a malicious local app on the
///     client (browser extension, hostile Android app talking to the
///     local HTTP proxy at `127.0.0.1:8085`) could write Connect
///     frames for `127.0.0.1:22`, `192.168.x.x`, `169.254.169.254`
///     (cloud metadata service), `[::1]`, etc. and pivot through
///     the relay into the operator's VPS internal network.
///   - **Empty allowlist + everything else**: allow (Drive Mode's
///     documented default).
///
/// Hostname targets that DNS-resolve to internal IPs need check-at-
/// dial-time which is more invasive; the IP-literal cut catches the
/// obvious attack surface for a few lines of code.
fn destination_allowed(state: &RelayState, host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if !state.cfg.allow_destinations.is_empty() {
        let listed = state.cfg.allow_destinations.iter().any(|entry| {
            let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
            if e.is_empty() {
                return false;
            }
            if let Some(suffix) = e.strip_prefix('.') {
                h == suffix || h.ends_with(&format!(".{suffix}"))
            } else {
                h == e
            }
        });
        // Allowlist is the final say — internal IPs explicitly
        // listed are allowed; everything else (including internal
        // IPs not listed) is refused.
        return listed;
    }
    // Default-deny IP literals pointing at the relay's own network.
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        if crate::state::is_internal_ip(&ip) {
            return false;
        }
    }
    true
}

async fn bump_last_seen(last_seen: &Arc<Mutex<Instant>>) {
    *last_seen.lock().await = Instant::now();
}

/// Seal a [`Batch`] of N r2c frames into a single Drive upload. The
/// nonce + AAD bind to the FIRST frame's seq + sid (the filename
/// the client polls under is `r2c_<sid>_<first_seq>`).
async fn upload_batch(
    state: &RelayState,
    sid: &SessionId,
    cipher: &AeadCipher,
    batch: Batch,
) -> Result<(), UploadError> {
    debug_assert!(!batch.frames.is_empty(), "Batch must contain ≥1 frame");
    let first_seq = batch.frames[0].seq;
    let frame_count = batch.frames.len();
    let plaintext = batch.encode().freeze();
    let sealed = cipher.seal(sid, first_seq, &plaintext);
    let body_len = sealed.len();
    let name = DriveFilename {
        kind: FilenameKind::Frame(Direction::RelayToClient),
        sid: *sid,
        seq: first_seq,
    }
    .format();
    let started = Instant::now();
    let access_token = state.token_cache.get().await?;
    state
        .drive_api
        .upload_file(
            &access_token,
            &state.cfg.folder_id,
            &name,
            Bytes::from(sealed),
        )
        .await?;
    if first_seq <= 4 || frame_count > 1 {
        tracing::info!(
            "session {:?}: uploaded r2c first_seq={} count={} bytes={} in {}ms",
            sid,
            first_seq,
            frame_count,
            body_len,
            started.elapsed().as_millis()
        );
    }
    Ok(())
}

/// Pick the coalesce wait window based on currently-accumulated batch
/// payload bytes. Mirrors the client side.
fn pick_r2c_coalesce_delay(pending_bytes: usize) -> Duration {
    if pending_bytes < R2C_COALESCE_INTERACTIVE_BYTES {
        R2C_COALESCE_INTERACTIVE_DELAY
    } else if pending_bytes < R2C_COALESCE_MEDIUM_BYTES {
        R2C_COALESCE_MEDIUM_DELAY
    } else {
        R2C_COALESCE_BULK_DELAY
    }
}

/// Build, push, and possibly-flush an r2c frame. Synchronous: a flush
/// here spawns the upload as a detached task and returns immediately,
/// so the session driver's select! loop keeps reading from the dialed
/// TCP socket while previous uploads are in flight. Bounded by the
/// existing `inner.upload_permits` semaphore inside `upload_batch`'s
/// caller path; failures log at warn but don't propagate.
fn push_r2c_frame(
    state: &Arc<RelayState>,
    sid: &SessionId,
    cipher: &AeadCipher,
    pending: &mut Vec<WireFrame>,
    pending_bytes: &mut usize,
    flush_deadline: &mut Option<tokio::time::Instant>,
    eager_response_burst: &mut bool,
    kind: FrameKind,
    seq: u64,
    payload: Bytes,
    flush_now: bool,
) {
    let payload_len = payload.len();
    let frame = WireFrame {
        version: WIRE_VERSION,
        kind,
        sid: *sid,
        seq,
        payload,
    };
    *pending_bytes += payload_len;
    pending.push(frame);
    // EAGER FLUSH on response starts. Splitting an entire download
    // into 2-frame Drive files makes Drive visibility dominate body
    // time; after the first response bytes are in flight, let the
    // size/timer policy pack bulk data into larger batches.
    let eager_second_frame = pending.len() >= 2 && *eager_response_burst;
    let should_flush = flush_now
        || eager_second_frame
        || pending.len() >= R2C_BATCH_MAX_FRAMES
        || *pending_bytes >= R2C_BATCH_FLUSH_BYTES;
    if should_flush {
        flush_r2c_batch(
            state,
            sid,
            cipher,
            pending,
            pending_bytes,
            flush_deadline,
            eager_response_burst,
        );
        return;
    }
    let delay = pick_r2c_coalesce_delay(*pending_bytes);
    let deadline = tokio::time::Instant::now() + delay;
    match flush_deadline {
        Some(existing) if *existing <= deadline => {}
        _ => *flush_deadline = Some(deadline),
    }
}

/// Synchronously seal the accumulated batch + spawn the HTTP upload
/// as a detached task. No-op if pending is empty. Matches the
/// client's `flush_c2r_batch` shape — see that function's doc for
/// the pipelining rationale (the load-bearing change vs plain
/// batching: while the previous upload is in flight to Drive, the
/// session driver keeps reading from the destination socket).
fn flush_r2c_batch(
    state: &Arc<RelayState>,
    sid: &SessionId,
    cipher: &AeadCipher,
    pending: &mut Vec<WireFrame>,
    pending_bytes: &mut usize,
    flush_deadline: &mut Option<tokio::time::Instant>,
    eager_response_burst: &mut bool,
) {
    if pending.is_empty() {
        return;
    }
    let frame_count = pending.len();
    let first_seq = pending[0].seq;
    let was_eager_response_burst = *eager_response_burst;
    let batch = Batch {
        frames: std::mem::take(pending),
    };
    *pending_bytes = 0;
    *flush_deadline = None;
    *eager_response_burst = false;
    if frame_count > 1 {
        tracing::info!(
            "session {:?}: flushing r2c batch first_seq={} count={} eager_response_burst={}",
            sid,
            first_seq,
            frame_count,
            was_eager_response_burst
        );
    }
    let state_for_task = state.clone();
    let cipher = cipher.clone();
    let sid_copy = *sid;
    tokio::spawn(async move {
        if let Err(e) = upload_batch(&state_for_task, &sid_copy, &cipher, batch).await {
            tracing::warn!(
                "session {:?}: pipelined r2c upload failed at first_seq={}: {}",
                sid_copy,
                first_seq,
                e
            );
        }
    });
}

// The unbatched `upload_eof_frame` / `upload_close_frame` helpers
// were retired when the r2c side switched to batched uploads.
// Eof/Close are now pushed via `push_r2c_frame(..., flush_now=true)`
// so they share the batch envelope with any preceding Data and flush
// the whole thing in one Drive upload.

/// Best-effort Error frame upload, used on Connect failure / dial
/// rejection. Sealed as a single-frame batch so the client's batch
/// parser handles it the same way as any other r2c file.
async fn upload_error_frame(
    state: &RelayState,
    sid: &SessionId,
    seq: u64,
    cipher: &AeadCipher,
    reason: &str,
) {
    let payload = Bytes::copy_from_slice(reason.as_bytes());
    let frame = WireFrame {
        version: WIRE_VERSION,
        kind: FrameKind::Error,
        sid: *sid,
        seq,
        payload,
    };
    let batch = Batch::single(frame);
    if let Err(e) = upload_batch(state, sid, cipher, batch).await {
        tracing::debug!(
            "session {:?}: Error upload failed at seq={}: {}",
            sid,
            seq,
            e
        );
    }
}

#[derive(Debug, thiserror::Error)]
enum UploadError {
    #[error("OAuth refresh failed: {0}")]
    Oauth(#[from] rahgozar::drive_oauth::OAuthError),
    #[error("Drive upload failed: {0}")]
    Api(#[from] rahgozar::drive_api::DriveApiError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use rahgozar::drive_api::{build_drive_http_client, DriveApiClient};
    use rahgozar::drive_crypto::RelaySecret;
    use std::path::PathBuf;

    fn dummy_state(allow_destinations: Vec<String>) -> RelayState {
        let http = build_drive_http_client(None).expect("build client");
        let drive_api = DriveApiClient::new(http.clone(), "https://example.invalid".into());
        let cfg = RelayConfig {
            oauth_client_id: "CID".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "R".into(),
            folder_id: "F".into(),
            x25519_secret_key_path: PathBuf::from("/dev/null"),
            poll_interval_ms: 300,
            max_concurrent_dials: 8,
            idle_timeout_secs: 120,
            allow_destinations,
            metrics_bind: None,
        };
        let token_cache = crate::token::TokenCache::new("R".into(), "CID".into(), "S".into(), http);
        RelayState::new(
            Arc::new(cfg),
            Arc::new(RelaySecret::generate(rand::rngs::OsRng)),
            drive_api,
            token_cache,
        )
    }

    #[test]
    fn destination_allowed_empty_list_allows_public_destinations() {
        // Empty allowlist = default-allow for everything EXCEPT
        // IP literals pointing at the relay's own network (SSRF
        // guard). Hostnames and public IPs pass.
        let s = dummy_state(vec![]);
        assert!(destination_allowed(&s, "anything.example.com"));
        assert!(destination_allowed(&s, "8.8.8.8"));
        assert!(destination_allowed(&s, "1.1.1.1"));
        assert!(destination_allowed(&s, "142.250.80.46"));
    }

    #[test]
    fn destination_allowed_empty_list_blocks_internal_ipv4_literals() {
        // SSRF guard: even with the default empty allowlist, internal
        // IP literals are refused so the relay can't be pivoted into
        // the operator's VPS internal network.
        let s = dummy_state(vec![]);
        for bad in [
            "127.0.0.1",       // loopback
            "10.0.0.5",        // RFC1918
            "172.16.0.1",      // RFC1918 lower
            "172.31.255.254",  // RFC1918 upper
            "192.168.1.1",     // RFC1918
            "169.254.169.254", // cloud metadata
            "169.254.0.1",     // link-local
            "0.0.0.0",         // unspecified
            "100.64.0.1",      // CGNAT
            "255.255.255.255", // broadcast
        ] {
            assert!(
                !destination_allowed(&s, bad),
                "expected SSRF guard to reject {bad}"
            );
        }
    }

    #[test]
    fn destination_allowed_empty_list_blocks_internal_ipv6_literals() {
        let s = dummy_state(vec![]);
        for bad in [
            "::1",                // loopback
            "::",                 // unspecified
            "fe80::1",            // link-local
            "fc00::1",            // unique-local
            "fd00::1",            // unique-local upper
            "::ffff:127.0.0.1",   // IPv4-mapped loopback
            "::ffff:192.168.1.1", // IPv4-mapped RFC1918
        ] {
            assert!(
                !destination_allowed(&s, bad),
                "expected SSRF guard to reject {bad}"
            );
        }
    }

    #[test]
    fn destination_allowed_explicit_internal_ip_in_allowlist_passes() {
        // Operator opt-in: if the operator explicitly lists an
        // internal IP in `allow_destinations`, allow it (the
        // allowlist is the final say). Use case: relay running on
        // a corporate VPN exit node where the real destinations
        // are internal.
        let s = dummy_state(vec!["10.0.0.5".into(), "127.0.0.1".into()]);
        assert!(destination_allowed(&s, "10.0.0.5"));
        assert!(destination_allowed(&s, "127.0.0.1"));
        // But unlisted internal IPs are still refused.
        assert!(!destination_allowed(&s, "192.168.1.1"));
        // And hostnames not in the list are refused (existing
        // allowlist semantics).
        assert!(!destination_allowed(&s, "evil.example.com"));
    }

    #[test]
    fn destination_allowed_exact_match() {
        let s = dummy_state(vec!["example.com".into(), "google.com".into()]);
        assert!(destination_allowed(&s, "example.com"));
        assert!(destination_allowed(&s, "google.com"));
        // No subdomain match on bare entries (matches `passthrough_hosts`
        // semantics elsewhere in the codebase — bare entries are
        // exact-match only).
        assert!(!destination_allowed(&s, "sub.example.com"));
        assert!(!destination_allowed(&s, "google.com.evil.com"));
    }

    #[test]
    fn destination_allowed_dot_prefix_subdomain_match() {
        let s = dummy_state(vec![".example.com".into()]);
        // Leading `.` → matches `example.com` AND any subdomain.
        assert!(destination_allowed(&s, "example.com"));
        assert!(destination_allowed(&s, "api.example.com"));
        assert!(destination_allowed(&s, "deep.nested.example.com"));
        // Not a different domain that happens to end with the same chars.
        assert!(!destination_allowed(&s, "evilexample.com"));
        assert!(!destination_allowed(&s, "anotherexample.com"));
    }

    #[test]
    fn destination_allowed_is_case_insensitive_and_trims_dot() {
        let s = dummy_state(vec!["Example.COM".into()]);
        assert!(destination_allowed(&s, "example.com"));
        assert!(destination_allowed(&s, "EXAMPLE.COM"));
        // Trailing dot on FQDN form normalises to the same bare form.
        assert!(destination_allowed(&s, "example.com."));
    }

    #[test]
    fn destination_allowed_rejects_unlisted() {
        let s = dummy_state(vec!["example.com".into()]);
        assert!(!destination_allowed(&s, "evil.com"));
        assert!(!destination_allowed(&s, "8.8.8.8"));
    }

    #[test]
    fn destination_allowed_skips_blank_entries() {
        // Defensive: a hand-edited config with stray empty strings
        // shouldn't silently match every host.
        let s = dummy_state(vec!["".into(), "   ".into(), "example.com".into()]);
        assert!(destination_allowed(&s, "example.com"));
        assert!(!destination_allowed(&s, "anything.else"));
    }
}
