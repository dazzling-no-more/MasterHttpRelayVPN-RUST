//! Shared adaptive Drive poller.
//!
//! ## Architecture
//!
//! Single task per `RelayState`. Wakes on a tunable interval, lists
//! `c2r_*` files, hands each file off to a worker, then sleeps until
//! the next tick. v3 protocol: the seq=0 c2r body carries the
//! unsealed 64-byte Hello prefix used to bootstrap the session
//! (`try_bootstrap_session_from_c2r_0`), so one list call covers both
//! new-session opens and in-session traffic.
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
//!   interval to 25 ms for the next cycle (matches the client
//!   side). The bottleneck during active traffic is Drive's
//!   `files.list` latency (~200-500 ms) and listing eventual
//!   consistency (~500 ms-1.5 s), not our sleep gap — so we want
//!   the relay to re-list as soon as the runtime gets back to it.
//! - **Idle backoff**: only applies when the session table is
//!   empty. Each consecutive empty session-less cycle adds 100 ms,
//!   capped at 500 ms — saves Drive quota while still picking up a
//!   fresh Hello within ~500 ms of it landing on Drive. With at
//!   least one active session, every empty cycle stays at baseline
//!   so c2r traffic doesn't pay multi-second tail latency for the
//!   first frame after a brief lull.
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
use drive_wire::frame::Batch;
use rahgozar::drive_api::{DriveApiError, DriveFile, MAX_SEALED_FRAME_BODY_BYTES};
use rahgozar::drive_crypto::{
    AeadCipher, HelloBody, ReplayWindow, SessionKeys, StrictSeqError, HELLO_BODY_LEN,
};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::state::{frame_to_inbound, InboundFrame, RelayState, SessionHandle};

/// 25 ms after a non-empty cycle — catches bursts without paying
/// the baseline latency on the next inbound batch. Matches the
/// client's pipeline interval; the next list call's wire latency
/// is the real floor, not this sleep.
const PIPELINE_INTERVAL_MS: u64 = 25;
/// Each empty cycle adds 100 ms to the next sleep.
const IDLE_BACKOFF_STEP_MS: u64 = 100;
/// Cap on the idle sleep. Only reached when the session table is
/// empty (no in-flight CONNECTs) — see `adapt_interval`. Was 5 s
/// originally, then 1.5 s; lowered to 500 ms because the cold-start
/// tax it imposes on the first Hello after an idle period is
/// effectively wasted time (the Drive listing call is what we're
/// waiting on, not the sleep). Idle QPS at 500 ms cap is 2/s,
/// comfortably under Drive's 10 QPS budget.
const MAX_IDLE_INTERVAL_MS: u64 = 500;
/// fresh-list lookback so delayed Drive visibility cannot strand
/// an older missing seq behind an exact modifiedTime cursor.
const MODIFIED_CURSOR_LOOKBACK_SECS: i64 = 8;

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
    // Sliding modifiedTime cursor for the single c2r_* listing query.
    // Pre-v3 we listed h_* + c2r_* in parallel; v3 folded the Hello
    // into the c2r_<sid>_0 body, so one list call covers both kinds
    // of session-relevant input.
    let mut frame_cursor: Option<String> = None;

    tracing::info!(
        "poll loop starting (baseline={}ms, max_concurrent={})",
        baseline_ms,
        state.cfg.max_concurrent_dials,
    );

    loop {
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        let found_work =
            run_one_cycle(state.clone(), work_permits.clone(), &mut frame_cursor).await;
        // While ≥1 session is registered, c2r traffic is expected —
        // back-off would just add per-frame tail latency. The ramp
        // only fires when the relay is genuinely idle (no sessions);
        // a fresh session-open c2r_0 still gets picked up within
        // MAX_IDLE_INTERVAL_MS.
        let sessions_present = !state.sessions.read().await.is_empty();
        interval_ms = adapt_interval(baseline_ms, found_work, &mut empty_streak, sessions_present);
    }
}

/// Advance a sliding `modifiedTime >= since` cursor.
///
/// `now` is the wall-clock timestamp captured BEFORE the list call.
/// It lets us move the cursor forward even on empty listings, which
/// is load-bearing: with `since=None` the query path falls back to
/// Drive's slow `name contains` full-text index (multi-second
/// visibility lag for newly uploaded mailbox files). Once a cursor
/// is set, subsequent calls use the much-faster `modifiedTime >= ...`
/// recently-modified-children query. The 8s lookback preserves
/// safety margin against out-of-order Drive visibility.
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

/// Adaptive-interval computation, factored out for unit testing.
/// - `found_work`: drop to pipeline interval, reset the streak.
/// - empty cycle with `sessions_present`: stay at baseline. Active
///   sessions expect c2r traffic; idle backoff would add seconds of
///   tail latency for nothing.
/// - empty cycle with no sessions: ramp `baseline + step * streak`,
///   capped at `MAX_IDLE_INTERVAL_MS`. Fresh Hellos still land in
///   at most one cap-length poll.
pub(crate) fn adapt_interval(
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

/// Run one poll iteration. Returns true iff at least one c2r frame
/// was processed (used by the caller to drive the adaptive interval).
async fn run_one_cycle(
    state: Arc<RelayState>,
    permits: Arc<Semaphore>,
    frame_cursor: &mut Option<String>,
) -> bool {
    let access_token = match state.token_cache.get().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("token refresh failed (will retry next cycle): {}", e);
            return false;
        }
    };

    // One list call per cycle: every session-relevant input is a
    // `c2r_*` file in v3 (the seq=0 entry carries the Hello prefix
    // inline; seq>0 entries are sealed batches as before).
    //
    // Capture `now` BEFORE the call so `advance_modified_cursor` can
    // safely move forward when the listing returns empty.
    let call_start = time::OffsetDateTime::now_utc();
    let frame_result = state
        .drive_api
        .list_files_in_folder_since(
            &access_token,
            &state.cfg.folder_id,
            "c2r_",
            frame_cursor.as_deref(),
        )
        .await;

    let frame_files_raw: Vec<DriveFile> = match frame_result {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("list c2r_* failed: {}", e);
            Vec::new()
        }
    };
    // Advance the cursor against the raw (pre-filter) listing so
    // subsequent cycles fetch only recent files via lookback.
    // See `advance_modified_cursor` for the empty-listing rationale.
    advance_modified_cursor(&frame_files_raw, frame_cursor, call_start);
    let mut frame_files: Vec<(DriveFile, DriveFilename)> = frame_files_raw
        .into_iter()
        .filter_map(|f| {
            let parsed = parse_filename(&f.name)?;
            // Drive's `name contains 'c2r_'` query (used at cold start
            // when `frame_cursor` is None) returns `r2c_*` too via
            // Google's FTS tokenisation. Filter to c2r_ only. The
            // cursor-mode query already trimmed the cross-direction
            // noise; this guard handles the bootstrap path.
            if !matches!(parsed.kind, FilenameKind::Frame(Direction::ClientToRelay)) {
                return None;
            }
            Some((f, parsed))
        })
        .collect();
    // Re-sort numerically by (sid, seq). Drive's lex order puts
    // ..._10 before ..._2; this fixes it before the workers dispatch.
    frame_files.sort_by_key(|(_, p)| (p.sid, p.seq));

    if frame_files.is_empty() {
        return false;
    }

    // Group by sid so per-session delivery stays strictly ordered,
    // then prefetch each group's Drive bodies concurrently. The
    // network-bound work can race; replay-window commit and mpsc
    // delivery are sorted and sequential. For new sessions, the
    // seq=0 frame in each group carries the Hello prefix used to
    // derive keys + spawn the session driver.
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
        let permits = permits.clone();
        frame_workers.spawn(async move {
            if let Err(e) = process_frame_group(state, access_token, permits, group).await {
                tracing::warn!("frame group processing failed for sid {:?}: {}", sid, e);
            }
        });
    }

    // Drain the JoinSet before returning — guarantees one cycle's
    // workers don't overlap the next cycle's listings.
    while frame_workers.join_next().await.is_some() {}
    true
}

// --------------------------------------------------------------------
// Session bootstrap (c2r_<sid>_0 carries the Hello prefix)
// --------------------------------------------------------------------

/// Sentinel returned from the bootstrap path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BootstrapOutcome {
    /// Session is registered in the table (newly inserted, or already
    /// present because the same c2r_0 hit a previous cycle). Carries
    /// the downloaded body so normal frame processing can reuse it
    /// instead of issuing a second Drive GET for seq=0.
    Registered(Bytes),
    /// The c2r_0 body was malformed enough that we deleted it; the
    /// caller should drop any related seq>0 frames from this cycle.
    Discarded,
}

/// Bootstrap a session from a `c2r_<sid>_0` file. Downloads the body,
/// parses the unsealed 64-byte Hello prefix, runs the relay-side
/// X25519 agreement + HKDF, and inserts a fresh session driver into
/// the table. Returns `Registered` whether the session was just
/// inserted or already present (a same-cycle duplicate is idempotent).
/// On Hello-decode / key-agreement failure the c2r_0 file is deleted
/// and `Discarded` is returned.
async fn try_bootstrap_session_from_c2r_0(
    state: &Arc<RelayState>,
    access_token: &str,
    file: &DriveFile,
    parsed: &DriveFilename,
) -> Result<BootstrapOutcome, WorkerError> {
    debug_assert!(parsed.seq == 0);

    // The combined-upload body is HelloBody(64) || sealed Batch(>=tag).
    // Validate against the same total cap normal seq=0 processing uses;
    // we reuse this downloaded body below to avoid a duplicate GET.
    let max_total = MAX_SEALED_FRAME_BODY_BYTES.saturating_add(HELLO_BODY_LEN as u64);
    if let Some(size) = file.size {
        if size < HELLO_BODY_LEN as u64 {
            tracing::warn!(
                "c2r {} is {} bytes; expected at least {} for the Hello prefix; deleting",
                file.name,
                size,
                HELLO_BODY_LEN
            );
            let _ = state.drive_api.delete_file(access_token, &file.id).await;
            return Ok(BootstrapOutcome::Discarded);
        }
        if size > max_total {
            tracing::warn!(
                "c2r {} is {} bytes; maximum accepted is {}; deleting",
                file.name,
                size,
                max_total
            );
            let _ = state.drive_api.delete_file(access_token, &file.id).await;
            return Ok(BootstrapOutcome::Discarded);
        }
    }

    let body_bytes = match state
        .drive_api
        .download_file(access_token, &file.id, max_total)
        .await
    {
        Ok(bytes) => bytes,
        Err(DriveApiError::ResponseTooLarge { .. }) => {
            tracing::warn!("c2r {} exceeded the protocol size cap; deleting", file.name);
            let _ = state.drive_api.delete_file(access_token, &file.id).await;
            return Ok(BootstrapOutcome::Discarded);
        }
        Err(e) => return Err(e.into()),
    };
    if body_bytes.len() < HELLO_BODY_LEN {
        tracing::warn!(
            "c2r {} downloaded body is {} bytes; need at least {} for Hello prefix; deleting",
            file.name,
            body_bytes.len(),
            HELLO_BODY_LEN
        );
        let _ = state.drive_api.delete_file(access_token, &file.id).await;
        return Ok(BootstrapOutcome::Discarded);
    }

    let hello = match HelloBody::decode(&body_bytes[..HELLO_BODY_LEN]) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("c2r {} Hello prefix decode failed: {}", file.name, e);
            let _ = state.drive_api.delete_file(access_token, &file.id).await;
            return Ok(BootstrapOutcome::Discarded);
        }
    };

    let keys = match SessionKeys::relay_accept(&state.relay_secret, parsed.sid, &hello) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            tracing::warn!("c2r {} key agreement failed: {}", file.name, e);
            let _ = state.drive_api.delete_file(access_token, &file.id).await;
            return Ok(BootstrapOutcome::Discarded);
        }
    };
    let _inserted = spawn_session(state.clone(), keys).await;
    Ok(BootstrapOutcome::Registered(body_bytes))
}

/// Insert a fresh session into the table and spawn its driver task.
/// If a session with this sid already exists, the bootstrap was
/// redundant (usually a same-cycle race, or the c2r_0 visibility
/// raced our own delete) and the existing entry is preserved.
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

struct PreparedFrameBatch {
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

#[cfg(test)]
async fn process_frame(
    state: Arc<RelayState>,
    access_token: String,
    file: DriveFile,
    parsed: DriveFilename,
) -> Result<(), WorkerError> {
    let permits = Arc::new(Semaphore::new(1));
    process_frame_group(state, access_token, permits, vec![(file, parsed)]).await
}

/// Process one sid's c2r files with parallel Drive-body prefetch,
/// then ordered commit to the per-session driver. If the session
/// isn't in the table yet, the seq=0 frame's unsealed Hello prefix
/// is used to derive the keys + insert the session; the same
/// downloaded body is then reused for normal AEAD-open processing so
/// cold starts do not pay a duplicate Drive GET for c2r_0.
async fn process_frame_group(
    state: Arc<RelayState>,
    access_token: String,
    download_permits: Arc<Semaphore>,
    group: Vec<(DriveFile, DriveFilename)>,
) -> Result<(), WorkerError> {
    if group.is_empty() {
        return Ok(());
    }

    let sid = group[0].1.sid;

    // If the session isn't in the table yet, only the seq=0 frame can
    // bootstrap it (carries the unsealed Hello prefix). If the lowest
    // seq we see in this group is >0, the c2r_0 hasn't become visible
    // yet — leave everything for a later poll. The replay-window
    // "future seq" guard would catch this later too, but doing it
    // here avoids a wasted download cycle.
    let session_exists_before = state.sessions.read().await.contains_key(&sid);
    let mut bootstrapped_seq0_body: Option<Bytes> = None;
    if !session_exists_before {
        if group[0].1.seq != 0 {
            for (file, parsed) in group {
                tracing::debug!(
                    "frame {} has no active session for sid {:?} and seq={}>0; leaving for a later poll",
                    file.name, parsed.sid, parsed.seq,
                );
            }
            return Ok(());
        }
        let (file, parsed) = &group[0];
        match try_bootstrap_session_from_c2r_0(&state, &access_token, file, parsed).await? {
            BootstrapOutcome::Registered(body) => {
                bootstrapped_seq0_body = Some(body);
            }
            BootstrapOutcome::Discarded => {
                // Hello decode / key-agreement failed for the seq=0
                // frame. The body was already deleted; the orphan
                // reaper will sweep any seq>0 stragglers.
                return Ok(());
            }
        }
    }

    let session_view = {
        let sessions = state.sessions.read().await;
        sessions.get(&sid).map(|h| {
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
            // Defensive: bootstrap claimed Registered but the entry
            // is gone — must have been evicted by the orphan reaper
            // between the spawn_session call and this read. Drop the
            // group; a future c2r_0 retry would re-bootstrap.
            for (file, parsed) in group {
                tracing::debug!(
                    "frame {} has no active session for sid {:?} after bootstrap (raced eviction); leaving for a later poll",
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
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
        }
        return Ok(());
    };

    let mut downloads: JoinSet<Result<Option<PreparedFrameBatch>, WorkerError>> = JoinSet::new();
    let mut saw_expected_seq = false;
    for (file, parsed) in group {
        if !matches!(parsed.kind, FilenameKind::Frame(Direction::ClientToRelay)) {
            tracing::debug!("ignoring non-c2r frame filename: {}", file.name);
            continue;
        }
        if parsed.seq < next_expected {
            tracing::debug!(
                "frame {} rejected by replay window: seq {} < expected {}",
                file.name,
                parsed.seq,
                next_expected
            );
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            continue;
        }
        if parsed.seq == next_expected {
            saw_expected_seq = true;
        } else if !saw_expected_seq {
            tracing::debug!(
                "frame {} arrived before seq {}; leaving for a later poll",
                file.name,
                next_expected
            );
            break;
        }

        let permit = download_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| WorkerError::WorkerSemaphoreClosed)?;
        let state = state.clone();
        let access_token = access_token.clone();
        let keys = keys.clone();
        let cached_body = if parsed.seq == 0 {
            bootstrapped_seq0_body.take()
        } else {
            None
        };
        downloads.spawn(async move {
            let _permit = permit;
            prepare_frame_batch(state, access_token, keys, file, parsed, cached_body).await
        });
    }

    let mut prepared = Vec::new();
    while let Some(joined) = downloads.join_next().await {
        match joined {
            Ok(Ok(Some(batch))) => prepared.push(batch),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("frame prefetch failed: {}", e),
            Err(e) => tracing::warn!("frame prefetch task failed: {}", e),
        }
    }
    prepared.sort_by_key(|p| p.parsed.seq);

    for prepared in prepared {
        match deliver_prepared_frame_batch(
            &state,
            &access_token,
            &replay,
            &inbound_tx,
            &last_seen,
            prepared,
        )
        .await?
        {
            DeliveryOutcome::Consumed | DeliveryOutcome::Duplicate => {}
            DeliveryOutcome::Blocked => break,
        }
    }

    Ok(())
}

async fn prepare_frame_batch(
    state: Arc<RelayState>,
    access_token: String,
    keys: Arc<SessionKeys>,
    file: DriveFile,
    parsed: DriveFilename,
    cached_body: Option<Bytes>,
) -> Result<Option<PreparedFrameBatch>, WorkerError> {
    // `seq=0` carries an unsealed 64-byte HelloBody before the sealed
    // batch (see `try_bootstrap_session_from_c2r_0`). Account for that
    // in the upper-bound check so a legitimate session-open isn't
    // rejected for being slightly larger than the per-frame cap.
    let unsealed_prefix_len = if parsed.seq == 0 { HELLO_BODY_LEN } else { 0 };
    let max_total = MAX_SEALED_FRAME_BODY_BYTES.saturating_add(unsealed_prefix_len as u64);
    if let Some(size) = file.size {
        if size > max_total {
            tracing::warn!(
                "frame {} is {} bytes; maximum accepted is {}; deleting",
                file.name,
                size,
                max_total
            );
            let _ = state.drive_api.delete_file(&access_token, &file.id).await;
            return Ok(None);
        }
    }

    let body = match cached_body {
        Some(bytes) => bytes,
        None => match state
            .drive_api
            .download_file(&access_token, &file.id, max_total)
            .await
        {
            Ok(bytes) => bytes,
            Err(DriveApiError::ResponseTooLarge { .. }) => {
                tracing::warn!(
                    "frame {} exceeded the protocol size cap; deleting",
                    file.name
                );
                let _ = state.drive_api.delete_file(&access_token, &file.id).await;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        },
    };
    if body.len() < unsealed_prefix_len {
        tracing::warn!(
            "frame {} downloaded body is {} bytes; need at least {} for the seq=0 Hello prefix; dropping",
            file.name,
            body.len(),
            unsealed_prefix_len,
        );
        return Ok(None);
    }
    let sealed = body.slice(unsealed_prefix_len..);
    let cipher = AeadCipher::new(&keys.k_c2r);
    let plaintext = match cipher.open(&parsed.sid, parsed.seq, &sealed) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::warn!("frame {} AEAD open failed: {}", file.name, e);
            return Ok(None);
        }
    };
    let batch = match Batch::decode(&plaintext) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("frame {} batch decode failed: {}", file.name, e);
            return Ok(None);
        }
    };
    if batch.frames.is_empty() {
        tracing::warn!("frame {} decoded to empty batch (no frames)", file.name);
        return Ok(None);
    }
    if batch.frames[0].seq != parsed.seq {
        tracing::warn!(
            "frame {} first-frame seq mismatch: filename={} first_frame={}",
            file.name,
            parsed.seq,
            batch.frames[0].seq,
        );
        return Ok(None);
    }

    Ok(Some(PreparedFrameBatch {
        file,
        parsed,
        batch,
    }))
}

async fn deliver_prepared_frame_batch(
    state: &RelayState,
    access_token: &str,
    replay: &Arc<Mutex<ReplayWindow>>,
    inbound_tx: &mpsc::Sender<InboundFrame>,
    last_seen: &Arc<Mutex<Instant>>,
    prepared: PreparedFrameBatch,
) -> Result<DeliveryOutcome, WorkerError> {
    let PreparedFrameBatch {
        file,
        parsed,
        batch,
    } = prepared;
    let frame_count = batch.frames.len();
    let mut committed_through: Option<u64> = None;

    for (idx, wire) in batch.frames.into_iter().enumerate() {
        if wire.sid != parsed.sid {
            tracing::warn!(
                "frame {} batch index {} sid mismatch: filename {:?} vs wire {:?}",
                file.name,
                idx,
                parsed.sid,
                wire.sid
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
                    "frame {} batch index {} seq {} rejected by replay: {}",
                    file.name,
                    idx,
                    wire.seq,
                    e,
                );
                if committed_through.is_none() {
                    delete_c2r_file_detached(&state.drive_api, access_token, &file);
                    return Ok(DeliveryOutcome::Duplicate);
                }
                break;
            }
            Err(StrictSeqError::Future { expected, .. }) => {
                tracing::debug!(
                    "frame {} batch index {} arrived before seq {}; leaving for a later poll",
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
        let inbound = match frame_to_inbound(wire) {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(
                    "frame {} batch index {} dispatch error: {}",
                    file.name,
                    idx,
                    e
                );
                break;
            }
        };
        *last_seen.lock().await = Instant::now();
        if let Err(e) = inbound_tx.send(inbound).await {
            tracing::debug!(
                "frame {} batch index {}: session driver gone, dropping inbound: {}",
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
            "frame {}: consumed batch first_seq={} through={} ({} frames)",
            file.name,
            parsed.seq,
            committed_through,
            frame_count
        );
    }

    delete_c2r_file_detached(&state.drive_api, access_token, &file);

    Ok(DeliveryOutcome::Consumed)
}

fn delete_c2r_file_detached(
    drive_api: &rahgozar::drive_api::DriveApiClient,
    access_token: &str,
    file: &DriveFile,
) {
    let drive_api = drive_api.clone();
    let access_token = access_token.to_string();
    let file_id = file.id.clone();
    let file_name = file.name.clone();
    tokio::spawn(async move {
        if let Err(e) = drive_api.delete_file(&access_token, &file_id).await {
            tracing::debug!("frame {} delete failed: {}", file_name, e);
        }
    });
}

#[derive(Debug, thiserror::Error)]
enum WorkerError {
    #[error("Drive API error: {0}")]
    Api(#[from] rahgozar::drive_api::DriveApiError),
    #[error("OAuth error: {0}")]
    Oauth(#[from] rahgozar::drive_oauth::OAuthError),
    #[error("worker semaphore closed")]
    WorkerSemaphoreClosed,
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
        // After many empty cycles we MUST land exactly on the cap,
        // not below — proves the saturating math + min() compose
        // correctly.
        assert_eq!(
            adapt_interval(300, false, &mut streak, false),
            MAX_IDLE_INTERVAL_MS
        );
    }

    #[test]
    fn adapt_interval_does_not_underflow_with_zero_baseline() {
        // Defensive: a hand-edited config with poll_interval_ms=0
        // is rejected by validate(), but if somehow it slipped
        // through, adapt_interval must not panic.
        let mut streak = 0;
        let v = adapt_interval(0, false, &mut streak, false);
        assert_eq!(v, IDLE_BACKOFF_STEP_MS);
        let v = adapt_interval(0, true, &mut streak, false);
        assert_eq!(v, PIPELINE_INTERVAL_MS);
    }

    #[test]
    fn adapt_interval_pipeline_does_not_grow_streak() {
        let mut streak = 7;
        let _ = adapt_interval(300, true, &mut streak, false);
        assert_eq!(streak, 0, "found_work resets the streak");
    }

    #[test]
    fn adapt_interval_stays_at_baseline_when_sessions_present() {
        // With ≥1 session in the table, an empty cycle MUST stay
        // at baseline. Idle backoff would otherwise delay the next
        // c2r frame by up to MAX_IDLE_INTERVAL_MS after a brief lull
        // in client uploads.
        let mut streak = 7;
        let next = adapt_interval(300, false, &mut streak, true);
        assert_eq!(next, 300);
        assert_eq!(streak, 0);
    }

    #[test]
    fn adapt_interval_resumes_ramp_when_sessions_drop() {
        // Sessions present → no ramp. Sessions then empty → ramp
        // resumes from a fresh streak. Pins the transition so a
        // future refactor that forgets to reset streak can't
        // accidentally re-introduce a long first-Hello latency.
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
        let mt = parse_rfc3339("2026-05-24T12:00:08Z");
        let files = vec![DriveFile {
            id: "id".into(),
            name: "c2r_x_1".into(),
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
            name: "c2r_x_1".into(),
            modified_time: Some(older),
            size: Some(1),
        }];
        let mut cursor = Some("2026-05-24T12:00:00Z".to_string());
        advance_modified_cursor(&files, &mut cursor, older);
        assert_eq!(cursor.as_deref(), Some("2026-05-24T12:00:00Z"));
    }

    #[test]
    fn modified_cursor_advances_on_empty_listing() {
        // Empty listing must still bootstrap the cursor — otherwise
        // a folder with no active sessions keeps polling via Drive's
        // slow full-text `name contains` index forever.
        let now = parse_rfc3339("2026-05-24T12:00:08Z");
        let mut cursor: Option<String> = None;
        advance_modified_cursor(&[], &mut cursor, now);
        assert_eq!(cursor.as_deref(), Some("2026-05-24T12:00:00Z"));
    }

    #[test]
    fn modified_cursor_uses_wall_clock_when_files_older_than_now() {
        let stale_mt = parse_rfc3339("2026-05-24T11:00:00Z");
        let now = parse_rfc3339("2026-05-24T12:00:08Z");
        let files = vec![DriveFile {
            id: "id".into(),
            name: "c2r_x_1".into(),
            modified_time: Some(stale_mt),
            size: Some(1),
        }];
        let mut cursor: Option<String> = None;
        advance_modified_cursor(&files, &mut cursor, now);
        assert_eq!(cursor.as_deref(), Some("2026-05-24T12:00:00Z"));
    }

    #[tokio::test]
    async fn process_frame_seq_gt_zero_without_session_is_left_for_later_poll() {
        // v3 protocol: seq=0 carries the unsealed Hello prefix and
        // bootstraps the session. Only seq>0 frames with no matching
        // session are deferred to a later cycle — they can't tell us
        // the keys, so we have to wait for c2r_0 to land. The test
        // points at an unreachable Drive base URL; if `process_frame`
        // attempted any Drive RPC for this case it would error out,
        // so a clean `Ok(())` proves we returned before any I/O.
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
            seq: 7,
        };
        let file = DriveFile {
            id: "would-have-been-deleted".into(),
            name: parsed.format(),
            modified_time: None,
            size: None,
        };

        process_frame(state, "unused-access-token".into(), file, parsed)
            .await
            .expect("seq>0 with no session should be left for a later poll");
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
