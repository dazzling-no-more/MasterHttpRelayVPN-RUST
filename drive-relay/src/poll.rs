//! Shared adaptive Drive poller.
//!
//! ## Architecture
//!
//! Single task per `RelayState`. Wakes on a tunable interval,
//! lists `h_*` (new Hellos) + `c2r_*` (in-session frames) in
//! parallel, hands each file off to a worker, then sleeps until
//! the next tick.
//!
//! The worker pool is a `JoinSet` drained at the end of each
//! poll cycle — so cycles never overlap and a slow worker can't
//! pile up unbounded work. The same configured cap also seeds a
//! dial semaphore on [`RelayState`], so bursts of Connect frames
//! cannot fan out unbounded TCP connect attempts.
//!
//! ## Adaptive interval
//!
//! - **Baseline**: `cfg.poll_interval_ms` (default 300 ms). The
//!   round-trip to Drive's edge is ~80-200 ms from a typical VPS,
//!   so 300 ms baseline keeps us well below the 10 QPS Drive quota
//!   while staying responsive.
//! - **Pipeline mode**: after any non-empty cycle, drop the
//!   interval to 100 ms for the next cycle. Catches burst traffic
//!   without paying the baseline latency.
//! - **Idle backoff**: each consecutive empty cycle adds 200 ms,
//!   capped at 5 s. An idle session-less relay polls Drive twice
//!   per 10 s instead of three times per second — saves quota
//!   for the next active session that lands.
//!
//! ## Ordering
//!
//! Drive's `files.list` sorts by `createdTime` (lexicographic on
//! filenames), which is wrong for `seq >= 10`. Frames are
//! re-sorted numerically by `(sid, seq)` inside the poll cycle
//! before being handed to workers. Workers within a cycle run
//! concurrently; per-session ordering is preserved by the
//! session's mpsc channel (frames for one session always queue
//! in arrival order at the inbound side).

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use drive_wire::filename::{parse_filename, Direction, DriveFilename, FilenameKind};
use drive_wire::frame::WireFrame;
use rahgozar::drive_api::{DriveApiError, DriveFile, MAX_SEALED_FRAME_BODY_BYTES};
use rahgozar::drive_crypto::{
    AeadCipher, HelloBody, ReplayWindow, SessionKeys, StrictSeqError, HELLO_BODY_LEN,
};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::state::{frame_to_inbound, RelayState, SessionHandle};

/// 100 ms after a non-empty cycle — catches bursts without paying
/// the baseline latency on the next inbound batch.
const PIPELINE_INTERVAL_MS: u64 = 100;
/// Each empty cycle adds 200 ms to the next sleep.
const IDLE_BACKOFF_STEP_MS: u64 = 200;
/// Max idle sleep — caps the worst-case "no traffic" wake-up cost.
const MAX_IDLE_INTERVAL_MS: u64 = 5_000;

/// Mailbox depth between the poll worker and a per-session driver
/// task. Small enough to apply back-pressure if the driver falls
/// behind, large enough that a one-cycle burst doesn't stall the
/// worker on the channel send.
const SESSION_MAILBOX_DEPTH: usize = 64;

pub async fn poll_loop(state: Arc<RelayState>) {
    let baseline_ms = state.cfg.poll_interval_ms as u64;
    let work_permits = Arc::new(Semaphore::new(state.cfg.max_concurrent_dials as usize));
    let mut interval_ms = baseline_ms;
    let mut empty_streak: u64 = 0;

    tracing::info!(
        "poll loop starting (baseline={}ms, max_concurrent={})",
        baseline_ms,
        state.cfg.max_concurrent_dials,
    );

    loop {
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        let found_work = run_one_cycle(state.clone(), work_permits.clone()).await;
        interval_ms = adapt_interval(baseline_ms, found_work, &mut empty_streak);
    }
}

/// Adaptive-interval computation, factored out for unit testing.
/// On `found_work`: drop to pipeline interval. On empty: ramp
/// `baseline + step * empty_streak`, capped.
pub(crate) fn adapt_interval(baseline_ms: u64, found_work: bool, empty_streak: &mut u64) -> u64 {
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

/// Run one poll iteration. Returns true iff at least one Hello or
/// frame file was processed (used by the caller to drive the
/// adaptive interval).
async fn run_one_cycle(state: Arc<RelayState>, permits: Arc<Semaphore>) -> bool {
    let access_token = match state.token_cache.get().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("token refresh failed (will retry next cycle): {}", e);
            return false;
        }
    };

    // Parallel list: Hellos + frames. Each call costs 1 QPS; running
    // them concurrently halves wall-clock per cycle.
    let (hello_result, frame_result) = tokio::join!(
        state
            .drive_api
            .list_files_in_folder(&access_token, &state.cfg.folder_id, "h_"),
        state
            .drive_api
            .list_files_in_folder(&access_token, &state.cfg.folder_id, "c2r_"),
    );

    // Drive's `name contains 'X'` query uses Google's full-text
    // index, which tokenises on non-alphanumeric chars and indexes
    // individual letters/digits — NOT strict substring. So a query
    // for `c2r_` also returns `r2c_*` files (both contain c, 2, r)
    // and an `h_` query returns hellos plus anything with `h` in
    // its name. We filter client-side to the exact prefix + kind
    // we asked for, otherwise `process_frame` warns on every
    // mismatched entry and floods the log under load.
    let hello_files: Vec<DriveFile> = match hello_result {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("list h_* failed: {}", e);
            Vec::new()
        }
    }
    .into_iter()
    .filter(|f| parse_filename(&f.name).is_some_and(|p| matches!(p.kind, FilenameKind::Hello)))
    .collect();
    let mut frame_files: Vec<(DriveFile, DriveFilename)> = match frame_result {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("list c2r_* failed: {}", e);
            Vec::new()
        }
    }
    .into_iter()
    .filter_map(|f| {
        let parsed = parse_filename(&f.name)?;
        // Reject anything that isn't a `c2r_*` frame — see the FTS
        // tokenisation note above. The `process_frame` arm that
        // catches non-c2r is now defensive only.
        if !matches!(parsed.kind, FilenameKind::Frame(Direction::ClientToRelay)) {
            return None;
        }
        Some((f, parsed))
    })
    .collect();
    // Re-sort numerically by (sid, seq). Drive's lex order puts
    // ..._10 before ..._2; this fixes it before the workers dispatch.
    frame_files.sort_by_key(|(_, p)| (p.sid, p.seq));

    if hello_files.is_empty() && frame_files.is_empty() {
        return false;
    }

    // Two-phase: process every Hello to completion BEFORE any
    // frame worker spawns. Frames for a session whose Hello is in
    // the same cycle would otherwise race the Hello's
    // `spawn_session` insert into the table; `process_frame` would
    // see no entry and leave the frame for a later poll. That is
    // safe, but it adds latency to the first Connect frame.
    //
    // Cycles with no Hellos skip phase 1 cleanly. Frames whose
    // Hello arrived in an EARLIER cycle still race-free here
    // because the session is already in the table when the frame
    // worker checks.
    let mut hello_workers: JoinSet<()> = JoinSet::new();
    for hello in hello_files {
        let state = state.clone();
        let access_token = access_token.clone();
        let permit = match permits.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return true, // semaphore closed → shutdown
        };
        hello_workers.spawn(async move {
            let _permit = permit; // released when this task drops
            if let Err(e) = process_hello(state, access_token, hello).await {
                tracing::warn!("hello processing failed: {}", e);
            }
        });
    }
    while hello_workers.join_next().await.is_some() {}

    // Group frames by sid + process each sid SERIALLY in its own
    // worker. Different sids still run in parallel (bounded by the
    // semaphore).
    //
    // Why this matters: `process_frame` does
    //   1. replay-window check (per-sid lock)
    //   2. Drive download (await)
    //   3. AEAD-open (sync)
    //   4. inbound_tx.send (await — the session driver's mpsc)
    //   5. Drive delete (await)
    // The replay-window mutex serialises step 1 across workers for
    // the same sid, but steps 2-4 run concurrently. Two workers
    // for c2r_0 + c2r_1 can both pass the window check (each gets
    // a distinct seq), both finish their downloads, then race
    // step 4 — delivering c2r_1's Data to the session driver
    // BEFORE c2r_0's Connect. The driver then exits with "first
    // inbound was Data, not Connect" and the session is dead.
    //
    // Grouping by sid + serial-within-group preserves per-session
    // ordering on the wire. The seq sort earlier (before the
    // HashMap collapse) means each sid's worker walks its frames
    // in numerical order.
    let mut frames_by_sid: std::collections::HashMap<
        drive_wire::frame::SessionId,
        Vec<(DriveFile, DriveFilename)>,
    > = std::collections::HashMap::new();
    for entry in frame_files {
        frames_by_sid.entry(entry.1.sid).or_default().push(entry);
    }
    let mut frame_workers: JoinSet<()> = JoinSet::new();
    for (sid, group) in frames_by_sid {
        let state = state.clone();
        let access_token = access_token.clone();
        let permit = match permits.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return true,
        };
        frame_workers.spawn(async move {
            let _permit = permit;
            for (file, parsed) in group {
                if let Err(e) =
                    process_frame(state.clone(), access_token.clone(), file, parsed).await
                {
                    tracing::warn!("frame processing failed for sid {:?}: {}", sid, e);
                }
            }
        });
    }

    // Drain the JoinSet before returning — guarantees one cycle's
    // workers don't overlap the next cycle's listings.
    while frame_workers.join_next().await.is_some() {}
    true
}

// --------------------------------------------------------------------
// Hello processing
// --------------------------------------------------------------------

async fn process_hello(
    state: Arc<RelayState>,
    access_token: String,
    file: DriveFile,
) -> Result<(), WorkerError> {
    // Filename SHOULD be `h_<sid_b32>_0`; reject anything else.
    let parsed = match parse_filename(&file.name) {
        Some(p) if matches!(p.kind, FilenameKind::Hello) && p.seq == 0 => p,
        Some(_) | None => {
            tracing::debug!("ignoring foreign/non-hello Drive filename: {}", file.name);
            return Ok(());
        }
    };

    if let Some(size) = file.size {
        if size > HELLO_BODY_LEN as u64 {
            tracing::warn!(
                "hello {} is {} bytes; expected at most {}; deleting",
                file.name,
                size,
                HELLO_BODY_LEN
            );
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(());
        }
    }

    let body_bytes = match state
        .drive_api
        .download_file(&access_token, &file.id, HELLO_BODY_LEN as u64)
        .await
    {
        Ok(bytes) => bytes,
        Err(DriveApiError::ResponseTooLarge { .. }) => {
            tracing::warn!(
                "hello {} exceeded the protocol size cap; deleting",
                file.name
            );
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let hello = match HelloBody::decode(&body_bytes) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("hello {} body decode failed: {}", file.name, e);
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(());
        }
    };

    let keys = match SessionKeys::relay_accept(&state.relay_secret, parsed.sid, &hello) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            tracing::warn!("hello {} key agreement failed: {}", file.name, e);
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(());
        }
    };
    let _inserted = spawn_session(state.clone(), keys).await;

    // Best-effort delete; if it fails, the orphan reaper sweeps later.
    if let Err(e) = state.drive_api.delete_file(&access_token, &file.id).await {
        tracing::debug!("hello {} delete failed: {}", file.name, e);
    }
    Ok(())
}

/// Insert a fresh session into the table and spawn its driver task.
/// If a session with this sid already exists, the Hello is stale
/// (usually a Drive delete/listing race) and is ignored rather than
/// resetting the active tunnel.
async fn spawn_session(state: Arc<RelayState>, keys: Arc<SessionKeys>) -> bool {
    let sid = keys.sid;
    let mut sessions = state.sessions.write().await;
    if sessions.contains_key(&sid) {
        tracing::debug!("session {:?}: duplicate Hello ignored", sid);
        return false;
    }

    let (inbound_tx, inbound_rx) = mpsc::channel(SESSION_MAILBOX_DEPTH);
    let replay = Arc::new(Mutex::new(ReplayWindow::new()));
    let last_seen = Arc::new(Mutex::new(Instant::now()));

    let task = tokio::spawn(crate::session::session_driver(
        sid,
        keys.clone(),
        state.clone(),
        inbound_rx,
        last_seen.clone(),
    ));

    let handle = SessionHandle {
        keys,
        replay,
        inbound_tx,
        last_seen,
        task,
    };

    sessions.insert(sid, handle);
    tracing::info!(
        "session {:?}: established (sessions now in table: {})",
        sid,
        sessions.len()
    );
    true
}

// --------------------------------------------------------------------
// Frame processing
// --------------------------------------------------------------------

async fn process_frame(
    state: Arc<RelayState>,
    access_token: String,
    file: DriveFile,
    parsed: DriveFilename,
) -> Result<(), WorkerError> {
    let direction = match parsed.kind {
        FilenameKind::Frame(Direction::ClientToRelay) => Direction::ClientToRelay,
        // The poll-cycle filter above (run_one_cycle) already drops
        // non-c2r entries that Drive's FTS-based `name contains`
        // query returned despite the c2r_ prefix. This arm is
        // defensive only — debug-level so a future code change
        // that bypasses the cycle filter doesn't go unnoticed.
        _ => {
            tracing::debug!("ignoring non-c2r frame filename: {}", file.name);
            return Ok(());
        }
    };
    debug_assert_eq!(direction, Direction::ClientToRelay);

    // Snapshot the session before downloading — drops the read
    // lock before any await on Drive.
    let session_view = {
        let sessions = state.sessions.read().await;
        sessions.get(&parsed.sid).map(|h| {
            (
                h.keys.clone(),
                h.replay.clone(),
                h.inbound_tx.clone(),
                h.last_seen.clone(),
            )
        })
    };
    let (keys, replay, inbound_tx, last_seen) = match session_view {
        Some(v) => v,
        None => {
            // No session for this sid. This can be a genuine stale
            // leftover, but Drive listings are eventually consistent:
            // c2r_<sid>_0 can surface one poll before h_<sid>_0 even
            // though the client uploaded Hello first. Leave it in the
            // folder so the next cycle can process it after Hello; the
            // orphan reaper deletes truly stale files by modifiedTime.
            tracing::debug!(
                "frame {} has no active session for sid {:?}; leaving for a later poll",
                file.name,
                parsed.sid
            );
            return Ok(());
        }
    };

    // Strict replay/ordering check on filename seq BEFORE downloading
    // the body. Pure *check* — we deliberately do NOT advance the
    // window here. Advance happens after delivery completes
    // successfully (`commit` below). A transient download / AEAD /
    // dispatch failure would otherwise permanently consume the seq
    // and the redelivered file would be wrongly rejected as a
    // replay next poll. Future frames are left in Drive until the
    // missing earlier seq becomes visible.
    {
        let window = replay.lock().await;
        match window.check_next(parsed.seq) {
            Ok(()) => {}
            Err(StrictSeqError::Replay(e)) => {
                tracing::debug!("frame {} rejected by replay window: {}", file.name, e);
                let _ = state.drive_api.delete_file(&access_token, &file.id).await;
                return Ok(());
            }
            Err(StrictSeqError::Future { expected, .. }) => {
                tracing::debug!(
                    "frame {} arrived before seq {}; leaving for a later poll",
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
                "frame {} is {} bytes; maximum accepted is {}; deleting",
                file.name,
                size,
                MAX_SEALED_FRAME_BODY_BYTES
            );
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(());
        }
    }

    let sealed = match state
        .drive_api
        .download_file(&access_token, &file.id, MAX_SEALED_FRAME_BODY_BYTES)
        .await
    {
        Ok(bytes) => bytes,
        Err(DriveApiError::ResponseTooLarge { .. }) => {
            tracing::warn!(
                "frame {} exceeded the protocol size cap; deleting",
                file.name
            );
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let cipher = AeadCipher::new(&keys.k_c2r);
    let plaintext = match cipher.open(&parsed.sid, parsed.seq, &sealed) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::warn!("frame {} AEAD open failed: {}", file.name, e);
            // Don't delete — could be a corrupted listing entry the
            // orphan reaper will catch by modifiedTime. Don't advance
            // the replay window either; leaves the window open for
            // the next-poll retry to succeed.
            return Ok(());
        }
    };
    let wire = match WireFrame::decode(&plaintext) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("frame {} wire decode failed: {}", file.name, e);
            return Ok(());
        }
    };

    // Defense in depth: filename sid/seq must match WireFrame
    // sid/seq. The AAD already binds them; this is a belt-and-
    // suspenders check that fails loudly on a future encoding bug.
    if wire.sid != parsed.sid || wire.seq != parsed.seq {
        tracing::warn!(
            "frame {} sid/seq mismatch: filename ({:?},{}) vs wire ({:?},{})",
            file.name,
            parsed.sid,
            parsed.seq,
            wire.sid,
            wire.seq,
        );
        return Ok(());
    }

    *last_seen.lock().await = Instant::now();

    let inbound = match frame_to_inbound(wire) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!("frame {} dispatch error: {}", file.name, e);
            return Ok(());
        }
    };

    // If the driver task already exited, the receiver is dropped
    // and `send` returns Err — log at debug and move on.
    if let Err(e) = inbound_tx.send(inbound).await {
        tracing::debug!(
            "frame {}: session driver gone, dropping inbound: {}",
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

    // Delete the consumed file; the next cycle's listing won't
    // re-see it.
    if let Err(e) = state.drive_api.delete_file(&access_token, &file.id).await {
        tracing::debug!("frame {} delete failed: {}", file.name, e);
    }

    let _ = body_drop(sealed);
    Ok(())
}

// Forces the compiler to drop `sealed` AFTER the AEAD open above
// (rustc already drops at the right point — this is purely a
// readability marker for the rg-greppable lifecycle).
#[inline]
fn body_drop(_: Bytes) {}

#[derive(Debug, thiserror::Error)]
enum WorkerError {
    #[error("Drive API error: {0}")]
    Api(#[from] rahgozar::drive_api::DriveApiError),
    #[error("OAuth error: {0}")]
    Oauth(#[from] rahgozar::drive_oauth::OAuthError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use rahgozar::drive_api::{build_drive_http_client, DriveApiClient, DriveFile};
    use rahgozar::drive_crypto::RelaySecret;
    use rand::rngs::OsRng;

    use crate::config::RelayConfig;
    use crate::state::RelayState;
    use crate::token::TokenCache;

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
        // After many empty cycles we MUST land exactly on the cap,
        // not below — proves the saturating math + min() compose
        // correctly.
        assert_eq!(
            adapt_interval(300, false, &mut streak),
            MAX_IDLE_INTERVAL_MS
        );
    }

    #[test]
    fn adapt_interval_does_not_underflow_with_zero_baseline() {
        // Defensive: a hand-edited config with poll_interval_ms=0
        // is rejected by validate(), but if somehow it slipped
        // through, adapt_interval must not panic.
        let mut streak = 0;
        let v = adapt_interval(0, false, &mut streak);
        assert_eq!(v, IDLE_BACKOFF_STEP_MS);
        let v = adapt_interval(0, true, &mut streak);
        assert_eq!(v, PIPELINE_INTERVAL_MS);
    }

    #[test]
    fn adapt_interval_pipeline_does_not_grow_streak() {
        let mut streak = 7;
        let _ = adapt_interval(300, true, &mut streak);
        assert_eq!(streak, 0, "found_work resets the streak");
    }

    #[tokio::test]
    async fn process_frame_without_session_leaves_file_for_later_poll() {
        let http = build_drive_http_client(None).expect("build client");
        let drive_api = DriveApiClient::new(http.clone(), "http://127.0.0.1:9".into());
        let cfg = Arc::new(RelayConfig {
            oauth_client_id: "CID".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "T".into(),
            folder_id: "FOLDER".into(),
            x25519_secret_key_path: PathBuf::from("unused.key"),
            poll_interval_ms: 50,
            max_concurrent_dials: 4,
            idle_timeout_secs: 60,
            allow_destinations: Vec::new(),
            metrics_bind: None,
        });
        let state = Arc::new(RelayState::new(
            cfg,
            Arc::new(RelaySecret::generate(OsRng)),
            drive_api,
            TokenCache::new("T".into(), "CID".into(), "S".into(), http),
        ));
        let sid = [0x42u8; 16];
        let parsed = DriveFilename {
            kind: FilenameKind::Frame(Direction::ClientToRelay),
            sid,
            seq: 0,
        };
        let file = DriveFile {
            id: "would-have-been-deleted".into(),
            name: parsed.format(),
            modified_time: None,
            size: None,
        };

        process_frame(state, "unused-access-token".into(), file, parsed)
            .await
            .expect("no-session frame should be left for a later poll");
    }

    #[tokio::test]
    async fn spawn_session_ignores_duplicate_sid() {
        let http = build_drive_http_client(None).expect("build client");
        let drive_api = DriveApiClient::new(http.clone(), "http://127.0.0.1:9".into());
        let relay_secret = Arc::new(RelaySecret::generate(OsRng));
        let cfg = Arc::new(RelayConfig {
            oauth_client_id: "CID".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "T".into(),
            folder_id: "FOLDER".into(),
            x25519_secret_key_path: PathBuf::from("unused.key"),
            poll_interval_ms: 50,
            max_concurrent_dials: 4,
            idle_timeout_secs: 60,
            allow_destinations: Vec::new(),
            metrics_bind: None,
        });
        let state = Arc::new(RelayState::new(
            cfg,
            relay_secret.clone(),
            drive_api,
            TokenCache::new("T".into(), "CID".into(), "S".into(), http),
        ));
        let sid = [0x24u8; 16];
        let relay_pubkey = relay_secret.public_key();
        let (_, hello1) =
            SessionKeys::client_initiate(&relay_pubkey, sid, OsRng).expect("client 1");
        let (_, hello2) =
            SessionKeys::client_initiate(&relay_pubkey, sid, OsRng).expect("client 2");
        let keys1 =
            Arc::new(SessionKeys::relay_accept(&relay_secret, sid, &hello1).expect("relay 1"));
        let keys2 =
            Arc::new(SessionKeys::relay_accept(&relay_secret, sid, &hello2).expect("relay 2"));

        assert!(spawn_session(state.clone(), keys1.clone()).await);
        assert!(!spawn_session(state.clone(), keys2).await);

        let mut sessions = state.sessions.write().await;
        assert_eq!(sessions.len(), 1);
        let handle = sessions.get(&sid).expect("first session remains active");
        assert_eq!(handle.keys.k_c2r, keys1.k_c2r);
        for (_, handle) in sessions.drain() {
            handle.task.abort();
        }
    }
}
