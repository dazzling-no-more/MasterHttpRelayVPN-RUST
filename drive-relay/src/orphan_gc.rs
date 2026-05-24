//! Orphan reaper task.
//!
//! Runs once every 2 minutes. Three jobs:
//!
//! 1. **Drive file sweep**: list `h_*` / `c2r_*` / `r2c_*`
//!    candidates, parse them with the rahgozar filename grammar,
//!    and delete only protocol files older than
//!    `5 * idle_timeout_secs`. Catches the case where one side dies
//!    mid-session without touching foreign files in the same folder.
//!
//! 2. **Finished-session removal**: walk the session table,
//!    remove any entry whose driver `JoinHandle::is_finished()`.
//!    Driver tasks exit on Close / TCP error / channel drop;
//!    they deliberately don't self-remove from the table (would
//!    require lock acquisition on a hot path), so this reaper is
//!    where finished sessions actually leave the map.
//!
//! 3. **Idle-session eviction**: any session whose
//!    `last_seen` is older than `idle_timeout_secs` is treated
//!    as dead — abort the driver task, remove the entry. Defends
//!    against a wedged session (e.g. driver stuck on a slow
//!    upload) that's no longer seeing client traffic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use drive_wire::filename::{
    parse_filename, Direction, FilenameKind, PREFIX_C2R, PREFIX_HELLO, PREFIX_R2C,
};
use rahgozar::drive_api::DriveFile;
use time::OffsetDateTime;

use crate::state::RelayState;

/// How often the reaper wakes up. Drive's listing cost is one
/// call per prefix (3 calls per sweep), so a 2-minute cadence
/// budgets ~1 QPS of reaper traffic in the worst case — well
/// below the per-session traffic.
const REAPER_INTERVAL: Duration = Duration::from_secs(120);

/// Multiplier on `idle_timeout_secs` to decide which Drive files
/// are stale enough to delete. Five times the idle timeout means
/// a fresh file uploaded right before a session went idle still
/// gets the full idle window plus a generous grace period to be
/// processed by either side before the reaper sweeps it.
const STALE_FILE_MULTIPLIER: u32 = 5;

pub async fn orphan_loop(state: Arc<RelayState>) {
    tracing::info!(
        "orphan reaper starting (interval={}s, stale_threshold={}s)",
        REAPER_INTERVAL.as_secs(),
        STALE_FILE_MULTIPLIER * state.cfg.idle_timeout_secs,
    );
    loop {
        tokio::time::sleep(REAPER_INTERVAL).await;
        if let Err(e) = run_one_sweep(state.clone()).await {
            tracing::warn!("orphan sweep failed (will retry next interval): {}", e);
        }
    }
}

async fn run_one_sweep(state: Arc<RelayState>) -> Result<(), SweepError> {
    let access_token = state.token_cache.get().await?;
    let stale_threshold =
        Duration::from_secs((STALE_FILE_MULTIPLIER * state.cfg.idle_timeout_secs) as u64);

    // ---- 1. Drive file sweep --------------------------------------
    let now = OffsetDateTime::now_utc();
    let mut deleted_files: usize = 0;
    for prefix in ["h_", "c2r_", "r2c_"] {
        let files = match state
            .drive_api
            .list_files_in_folder(&access_token, &state.cfg.folder_id, prefix)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("orphan list {prefix} failed: {}", e);
                continue;
            }
        };
        for f in files {
            if !is_protocol_file_for_prefix(&f.name, prefix) {
                tracing::debug!("orphan reaper: leaving foreign Drive file {}", f.name);
                continue;
            }
            if is_stale(&f, now, stale_threshold) {
                match state.drive_api.delete_file(&access_token, &f.id).await {
                    Ok(()) => {
                        deleted_files += 1;
                        tracing::debug!("reaped stale Drive file {}", f.name);
                    }
                    Err(e) => {
                        tracing::debug!("orphan delete {} failed: {}", f.name, e);
                    }
                }
            }
        }
    }
    if deleted_files > 0 {
        tracing::info!("orphan reaper: deleted {} stale Drive files", deleted_files);
    }

    // ---- 2 + 3. Session table sweep -------------------------------
    let idle_threshold = Duration::from_secs(state.cfg.idle_timeout_secs as u64);
    let now_i = Instant::now();
    // Collect doomed sids under the read lock so we don't hold the
    // write lock across the `Mutex<Instant>` async lock probes for
    // every entry.
    let mut to_evict: Vec<drive_wire::frame::SessionId> = Vec::new();
    {
        let sessions = state.sessions.read().await;
        for (sid, handle) in sessions.iter() {
            if handle.task.is_finished() {
                to_evict.push(*sid);
                continue;
            }
            let last = *handle.last_seen.lock().await;
            if now_i.saturating_duration_since(last) > idle_threshold {
                to_evict.push(*sid);
            }
        }
    }
    if !to_evict.is_empty() {
        let mut sessions = state.sessions.write().await;
        let mut removed: usize = 0;
        for sid in &to_evict {
            if let Some(handle) = sessions.remove(sid) {
                handle.task.abort();
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::info!(
                "orphan reaper: evicted {} session{} (remaining: {})",
                removed,
                if removed == 1 { "" } else { "s" },
                sessions.len()
            );
        }
    }

    Ok(())
}

fn is_protocol_file_for_prefix(name: &str, prefix: &str) -> bool {
    let parsed = match parse_filename(name) {
        Some(p) => p,
        None => return false,
    };
    matches!(
        (prefix, parsed.kind),
        (PREFIX_HELLO, FilenameKind::Hello)
            | (PREFIX_C2R, FilenameKind::Frame(Direction::ClientToRelay))
            | (PREFIX_R2C, FilenameKind::Frame(Direction::RelayToClient))
    )
}

/// True iff `file.modified_time` is older than `now -
/// stale_threshold`. Files with no modified_time (parser was
/// lenient) are NOT swept — better to leave a stuck file than
/// to nuke a freshly-uploaded one whose timestamp the listing
/// happened to omit.
fn is_stale(file: &DriveFile, now: OffsetDateTime, stale_threshold: Duration) -> bool {
    let mtime = match file.modified_time {
        Some(t) => t,
        None => return false,
    };
    // `time::OffsetDateTime` subtraction yields a `time::Duration`
    // — convert to `std::time::Duration` for the comparison.
    // `try_into` is fallible on negative durations (clock skew /
    // mtime in the future): we leave such files alone.
    let age: Duration = match (now - mtime).try_into() {
        Ok(d) => d,
        Err(_) => return false,
    };
    age > stale_threshold
}

#[derive(Debug, thiserror::Error)]
enum SweepError {
    #[error("OAuth refresh failed: {0}")]
    Oauth(#[from] rahgozar::drive_oauth::OAuthError),
    #[error("Drive API error: {0}")]
    Api(#[from] rahgozar::drive_api::DriveApiError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{format_description::well_known::Rfc3339, Duration as TimeDuration};

    fn drive_file_at(name: &str, modified: Option<OffsetDateTime>) -> DriveFile {
        DriveFile {
            id: format!("ID-{name}"),
            name: name.to_string(),
            modified_time: modified,
            size: None,
        }
    }

    #[test]
    fn is_stale_fires_past_threshold() {
        let now = OffsetDateTime::parse("2026-05-23T12:00:00Z", &Rfc3339).unwrap();
        // File modified 10 minutes ago, threshold 5 minutes → stale.
        let f = drive_file_at("c2r_a_0", Some(now - TimeDuration::minutes(10)));
        assert!(is_stale(&f, now, Duration::from_secs(5 * 60)));
    }

    #[test]
    fn is_stale_does_not_fire_within_threshold() {
        let now = OffsetDateTime::parse("2026-05-23T12:00:00Z", &Rfc3339).unwrap();
        // File modified 30 seconds ago, threshold 5 minutes → not stale.
        let f = drive_file_at("c2r_a_0", Some(now - TimeDuration::seconds(30)));
        assert!(!is_stale(&f, now, Duration::from_secs(5 * 60)));
    }

    #[test]
    fn is_stale_handles_clock_skew_gracefully() {
        let now = OffsetDateTime::parse("2026-05-23T12:00:00Z", &Rfc3339).unwrap();
        // File's modifiedTime is in the future (impossible normally,
        // but happens with clock skew between Drive and the relay).
        // Don't sweep — wait for the clock to catch up.
        let f = drive_file_at("c2r_a_0", Some(now + TimeDuration::seconds(30)));
        assert!(!is_stale(&f, now, Duration::from_secs(60)));
    }

    #[test]
    fn is_stale_skips_files_with_no_modified_time() {
        let now = OffsetDateTime::parse("2026-05-23T12:00:00Z", &Rfc3339).unwrap();
        // Listing returned a file without modifiedTime — could be
        // an artifact of partial response, NOT a stale file. Better
        // to keep than risk nuking fresh data.
        let f = drive_file_at("c2r_a_0", None);
        assert!(!is_stale(&f, now, Duration::from_secs(60)));
    }

    #[test]
    fn protocol_filter_accepts_only_matching_filename_grammar() {
        let sid = [0x11; 16];
        let hello = drive_wire::filename::DriveFilename {
            kind: FilenameKind::Hello,
            sid,
            seq: 0,
        }
        .format();
        let c2r = drive_wire::filename::DriveFilename {
            kind: FilenameKind::Frame(Direction::ClientToRelay),
            sid,
            seq: 1,
        }
        .format();
        let r2c = drive_wire::filename::DriveFilename {
            kind: FilenameKind::Frame(Direction::RelayToClient),
            sid,
            seq: 1,
        }
        .format();

        assert!(is_protocol_file_for_prefix(&hello, PREFIX_HELLO));
        assert!(is_protocol_file_for_prefix(&c2r, PREFIX_C2R));
        assert!(is_protocol_file_for_prefix(&r2c, PREFIX_R2C));
        assert!(!is_protocol_file_for_prefix(
            "notes_h_old.txt",
            PREFIX_HELLO
        ));
        assert!(!is_protocol_file_for_prefix(&r2c, PREFIX_C2R));
    }
}
