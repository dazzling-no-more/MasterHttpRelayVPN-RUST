//! Library surface for `rahgozar-drive-relay`. Lets the binary
//! entry point (`src/main.rs`), integration tests, and the
//! forthcoming `wiremock` e2e test slice all spawn the run loop in
//! the same shape.
//!
//! [`run`] orchestrates:
//!   - Config + key validation (fail-fast on bad credentials).
//!   - HTTP client + Drive REST + OAuth token cache setup.
//!   - One [`poll::poll_loop`] task — the adaptive Drive poller
//!     that lists `c2r_*` and dispatches inbound frames to per-
//!     session driver tasks. The seq=0 c2r body carries the
//!     unsealed Hello prefix used to bootstrap new sessions.
//!   - One [`orphan_gc::orphan_loop`] task — sweeps stale Drive
//!     files + finished / idle sessions every 2 minutes.
//!   - A signal handler that drains both background tasks +
//!     aborts every per-session task on SIGINT / SIGTERM.
//!
//! The CLI wraps [`run`] in `src/main.rs`; the `keygen` and
//! `oauth device-code` subcommands delegate to [`keygen_to_file`]
//! and [`save_oauth_credentials`] respectively so the same logic is
//! unit-testable without spawning a subprocess.

pub mod config;
pub mod metrics;
pub mod orphan_gc;
pub mod poll;
pub mod session;
pub mod state;
pub mod token;

use std::path::Path;
use std::sync::Arc;

use rahgozar::drive_api::{build_drive_http_client, DriveApiClient};
use rahgozar::drive_crypto::RelaySecret;

use crate::config::RelayConfig;
use crate::state::RelayState;
use crate::token::TokenCache;

/// Run the relay daemon.
///
/// Validates config + loads the keypair, sets up the Drive HTTP
/// client + OAuth token cache (triggering one refresh to
/// fail-fast on bad credentials), spawns the poll loop + orphan
/// reaper, then awaits SIGINT / SIGTERM. On signal, aborts the
/// background tasks and every active session's driver task before
/// returning.
///
/// Wired so the CLI / systemd unit / e2e test scaffolding can all
/// call it the same way: pass a parsed [`RelayConfig`], await,
/// expect `Ok(())` on clean shutdown.
pub async fn run(cfg: RelayConfig) -> Result<(), Error> {
    cfg.validate().map_err(Error::Config)?;

    // Load the keypair eagerly so a missing / malformed key file
    // fails at startup with a clear error rather than deep inside
    // the first Hello handler.
    let relay_secret = Arc::new(load_relay_secret(&cfg.x25519_secret_key_path)?);

    // One reqwest client serves both OAuth refresh and Drive REST
    // calls — connection pooling for free. The relay sits on a
    // free-internet VPS so no `google_ip` override is needed.
    let http = build_drive_http_client(None).map_err(Error::HttpClient)?;
    let drive_api = DriveApiClient::with_default_base_url(http.clone());
    let token_cache = TokenCache::new(
        cfg.oauth_refresh_token.clone(),
        cfg.oauth_client_id.clone(),
        cfg.oauth_client_secret.clone(),
        http,
    );

    // Trigger one refresh at startup so a bad `oauth_refresh_token`
    // fails here, not later during the first inbound batch.
    let access_token = token_cache.get().await.map_err(Error::Oauth)?;
    tracing::info!("OAuth refresh token verified");

    // Pre-warm the TLS pool to `www.googleapis.com`. The OAuth
    // refresh above hits `oauth2.googleapis.com` (different host),
    // so without this the first poll cycle pays the full TLS
    // handshake to a cold Drive host. A no-op cursor-mode list call
    // (`since = now`, no files match) is the cheapest way to open
    // the h2 connection + complete TLS so the steady-state polling
    // loop finds a warm pool. Failure is logged at warn but never
    // fatal — the poll loop retries every cycle either way.
    let prewarm_cursor = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .ok();
    if let Err(e) = drive_api
        .list_files_in_folder_since(&access_token, &cfg.folder_id, "", prewarm_cursor.as_deref())
        .await
    {
        tracing::warn!(
            "drive-relay: TLS pre-warm list call failed (non-fatal): {}",
            e
        );
    }

    let cfg = Arc::new(cfg);
    let state = Arc::new(RelayState::new(
        cfg.clone(),
        relay_secret,
        drive_api,
        token_cache,
    ));

    tracing::info!(
        "drive-relay starting: folder_id={}, poll={}ms, max_concurrent_dials={}",
        cfg.folder_id,
        cfg.poll_interval_ms,
        cfg.max_concurrent_dials,
    );

    let metrics_handle = match cfg.metrics_bind.clone() {
        Some(bind) => Some(
            metrics::spawn_metrics_server(state.clone(), bind)
                .await
                .map_err(Error::Metrics)?,
        ),
        None => None,
    };
    let poll_handle = tokio::spawn(poll::poll_loop(state.clone()));
    let orphan_handle = tokio::spawn(orphan_gc::orphan_loop(state.clone()));

    wait_for_shutdown().await.map_err(Error::Signal)?;
    tracing::info!("shutdown signal received; draining tasks");

    // Abort the background loops first so they don't spawn any new
    // session drivers / kick off new Drive RPCs during the drain.
    poll_handle.abort();
    orphan_handle.abort();
    if let Some(handle) = &metrics_handle {
        handle.abort();
    }
    let _ = poll_handle.await;
    let _ = orphan_handle.await;
    if let Some(handle) = metrics_handle {
        let _ = handle.await;
    }

    // Abort every active session's driver task. Drop the
    // SessionHandles so their mpsc::Sender halves drop and the
    // driver tasks that were select!'d on inbound_rx wake up.
    let mut sessions = state.sessions.write().await;
    let count = sessions.len();
    for (_, handle) in sessions.drain() {
        handle.task.abort();
    }
    if count > 0 {
        tracing::info!("aborted {count} active session(s)");
    }

    Ok(())
}

/// Generate a fresh X25519 keypair, write the 32-byte secret to
/// `out_path` (mode 0600 on unix), and return the bech32m-encoded
/// public key for the operator to paste into the client's
/// `drive.relay_pubkey` config field.
///
/// Refuses to overwrite an existing file: a fat-fingered `keygen`
/// invocation MUST NOT clobber an in-use key (doing so would
/// permanently break every connected client whose pinned pubkey no
/// longer matches the relay's secret).
pub fn keygen_to_file(out_path: &Path) -> Result<String, Error> {
    use rand::rngs::OsRng;
    if out_path.exists() {
        return Err(Error::KeyFileAlreadyExists(out_path.to_path_buf()));
    }
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
    }
    let secret = RelaySecret::generate(OsRng);
    let pubkey = secret.public_key();
    let priv_bytes = secret.to_bytes();
    write_secret_bytes(out_path, &priv_bytes)?;
    Ok(pubkey.to_bech32m())
}

/// Update the three OAuth credential fields
/// (`oauth_client_id`, `oauth_client_secret`, `oauth_refresh_token`)
/// in the on-disk config, preserving every other field. Creates a
/// placeholder config if none exists. Atomic write (temp + rename)
/// so a crash mid-write doesn't leave an unparseable file behind.
///
/// All three values are persisted together because they're all
/// supplied at the `oauth device-code` subcommand call: the
/// operator provides client_id + client_secret via CLI flags, and
/// Google returns the refresh_token at the end of the flow. Saving
/// them as a unit keeps config.json self-consistent — a partial
/// write would leave a refresh token without a matching client.
pub fn save_oauth_credentials(
    path: &Path,
    oauth_client_id: &str,
    oauth_client_secret: &str,
    refresh_token: &str,
) -> Result<(), Error> {
    let mut cfg = match RelayConfig::load(path) {
        Ok(c) => c,
        Err(crate::config::ConfigError::Read(_, e)) if e.kind() == std::io::ErrorKind::NotFound => {
            RelayConfig::placeholder()
        }
        Err(e) => return Err(Error::Config(e)),
    };
    cfg.oauth_client_id = oauth_client_id.to_string();
    cfg.oauth_client_secret = oauth_client_secret.to_string();
    cfg.oauth_refresh_token = refresh_token.to_string();
    cfg.save(path).map_err(Error::Io)
}

// --------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------

/// Load the relay's long-lived X25519 secret from disk. The file
/// must be exactly 32 bytes — anything else is a malformed key file
/// and rejected (rather than silently truncated / padded, which
/// would produce a different DH agreement and silently break
/// every session).
fn load_relay_secret(path: &Path) -> Result<RelaySecret, Error> {
    let bytes = std::fs::read(path).map_err(|e| Error::ReadKey(path.to_path_buf(), e))?;
    if bytes.len() != 32 {
        return Err(Error::MalformedKey {
            path: path.to_path_buf(),
            got: bytes.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(RelaySecret::from_bytes(arr))
}

/// Atomically write a 32-byte secret file with restrictive
/// permissions (`0600` on unix). Uses `create_new` so an existing
/// file at the path is preserved (the caller already checks this,
/// but the syscall-level guard is the authoritative one against
/// any TOCTOU window).
fn write_secret_bytes(path: &Path, bytes: &[u8; 32]) -> Result<(), Error> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(Error::Io)?;
    f.write_all(bytes).map_err(Error::Io)?;
    f.sync_all().map_err(Error::Io)?;
    Ok(())
}

/// Wait for SIGINT (Ctrl-C) or, on unix, SIGTERM (the signal
/// systemd sends on `systemctl stop`). On non-unix platforms only
/// SIGINT is supported; Windows-side relay deployments are not
/// expected (the relay runs on Linux VPS only per the plan).
#[cfg(unix)]
async fn wait_for_shutdown() -> std::io::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        biased;
        r = tokio::signal::ctrl_c() => r,
        _ = term.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("filesystem error: {0}")]
    Io(#[source] std::io::Error),
    #[error("failed to read key file {0}: {1}")]
    ReadKey(std::path::PathBuf, #[source] std::io::Error),
    #[error("key file {path} must be exactly 32 bytes; got {got}")]
    MalformedKey {
        path: std::path::PathBuf,
        got: usize,
    },
    #[error(
        "{0} already exists — delete it explicitly if you want to mint a new keypair (\
         doing so will invalidate every client's pinned relay_pubkey)"
    )]
    KeyFileAlreadyExists(std::path::PathBuf),
    #[error("signal handler failed: {0}")]
    Signal(std::io::Error),
    #[error("failed to bind metrics endpoint: {0}")]
    Metrics(std::io::Error),
    #[error("failed to build HTTP client: {0}")]
    HttpClient(reqwest::Error),
    #[error("OAuth refresh failed at startup: {0}")]
    Oauth(rahgozar::drive_oauth::OAuthError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rahgozar::drive_crypto::RelayPubkey;

    // ---- keygen_to_file --------------------------------------------

    #[test]
    fn keygen_to_file_writes_32_bytes_and_returns_matching_bech32m() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/relay.key");
        let bech = keygen_to_file(&path).expect("keygen");
        // Parent dir was created.
        assert!(path.parent().unwrap().exists());
        // Key file is exactly 32 bytes.
        let written = std::fs::read(&path).unwrap();
        assert_eq!(written.len(), 32);
        // Returned bech32m parses back to a pubkey that matches the
        // pubkey of the secret on disk. This is the round-trip that
        // proves the client's `drive.relay_pubkey` field will line
        // up with what the relay loads at startup.
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&written);
        let secret = RelaySecret::from_bytes(secret_bytes);
        let derived = secret.public_key();
        let parsed = RelayPubkey::from_bech32m(&bech).expect("parse bech32m");
        assert_eq!(derived.to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn keygen_refuses_to_overwrite_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.key");
        std::fs::write(&path, b"existing data").unwrap();
        let err = keygen_to_file(&path).unwrap_err();
        assert!(matches!(err, Error::KeyFileAlreadyExists(_)));
        // Existing content untouched.
        assert_eq!(std::fs::read(&path).unwrap(), b"existing data");
    }

    #[test]
    #[cfg(unix)]
    fn keygen_sets_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.key");
        keygen_to_file(&path).expect("keygen");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // Lower 9 bits are the rwx triple; the relay key MUST be
        // 0600 (user-only read/write) or the file watch hardening
        // of the systemd unit's `ConfigurationDirectoryMode=0700`
        // doesn't actually keep other users out.
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    // ---- save_oauth_credentials ------------------------------------

    #[test]
    fn save_oauth_credentials_creates_placeholder_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        save_oauth_credentials(
            &path,
            "CID.apps.googleusercontent.com",
            "SECRET",
            "1//04new",
        )
        .expect("save");
        let loaded = RelayConfig::load(&path).expect("load");
        assert_eq!(loaded.oauth_client_id, "CID.apps.googleusercontent.com");
        assert_eq!(loaded.oauth_client_secret, "SECRET");
        assert_eq!(loaded.oauth_refresh_token, "1//04new");
        // Defaults survived.
        assert_eq!(loaded.poll_interval_ms, 300);
        // Other sentinel fields are empty (placeholder shape).
        assert!(loaded.folder_id.is_empty());
    }

    #[test]
    fn save_oauth_credentials_preserves_other_fields_when_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let existing = RelayConfig {
            oauth_client_id: "OLD_CID".into(),
            oauth_client_secret: "OLD_SECRET".into(),
            oauth_refresh_token: "OLD".into(),
            folder_id: "MY_FOLDER".into(),
            x25519_secret_key_path: dir.path().join("relay.key"),
            poll_interval_ms: 500,
            max_concurrent_dials: 12,
            idle_timeout_secs: 60,
            allow_destinations: vec!["example.com".into()],
            metrics_bind: Some("127.0.0.1:9090".into()),
        };
        existing.save(&path).unwrap();
        save_oauth_credentials(&path, "NEW_CID", "NEW_SECRET", "NEW").expect("save");
        let loaded = RelayConfig::load(&path).expect("load");
        // All three credential fields replaced.
        assert_eq!(loaded.oauth_client_id, "NEW_CID");
        assert_eq!(loaded.oauth_client_secret, "NEW_SECRET");
        assert_eq!(loaded.oauth_refresh_token, "NEW");
        // Everything else preserved verbatim.
        assert_eq!(loaded.folder_id, "MY_FOLDER");
        assert_eq!(loaded.poll_interval_ms, 500);
        assert_eq!(loaded.max_concurrent_dials, 12);
        assert_eq!(loaded.allow_destinations, vec!["example.com".to_string()]);
        assert_eq!(loaded.metrics_bind.as_deref(), Some("127.0.0.1:9090"));
    }

    #[test]
    fn save_oauth_credentials_refuses_to_overwrite_malformed_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, b"{ not valid json").unwrap();

        let err = save_oauth_credentials(&path, "NEW_CID", "NEW_SECRET", "NEW").unwrap_err();
        assert!(matches!(
            err,
            Error::Config(crate::config::ConfigError::Parse(_))
        ));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{ not valid json",
            "malformed config must be left untouched for operator recovery"
        );
    }

    // ---- load_relay_secret -----------------------------------------

    #[test]
    fn load_relay_secret_rejects_wrong_length() {
        // `RelaySecret` deliberately doesn't `derive(Debug)` (would
        // expose the secret in log lines), so `unwrap_err()` doesn't
        // type-check here. Match on the result directly instead.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        std::fs::write(&path, b"too short").unwrap();
        let result = load_relay_secret(&path);
        assert!(matches!(result, Err(Error::MalformedKey { got: 9, .. })));
    }

    #[test]
    fn load_relay_secret_accepts_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("good.key");
        std::fs::write(&path, [0x42u8; 32]).unwrap();
        assert!(load_relay_secret(&path).is_ok());
    }

    #[test]
    fn load_relay_secret_returns_clear_error_on_missing_file() {
        let result = load_relay_secret(Path::new("/definitely/does/not/exist.key"));
        assert!(matches!(result, Err(Error::ReadKey(_, _))));
    }

    // ---- run() stub ------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn run_validates_config_and_fails_clearly_on_missing_key() {
        // Smoke: run() should reject a config that points at a
        // non-existent key file BEFORE the SIGINT block — otherwise
        // the daemon would sit there waiting on a signal while the
        // operator sees no error.
        let dir = tempfile::tempdir().unwrap();
        let cfg = RelayConfig {
            oauth_client_id: "CID".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "T".into(),
            folder_id: "F".into(),
            x25519_secret_key_path: dir.path().join("does-not-exist.key"),
            poll_interval_ms: 300,
            max_concurrent_dials: 8,
            idle_timeout_secs: 120,
            allow_destinations: vec![],
            metrics_bind: None,
        };
        let err = run(cfg).await.unwrap_err();
        // Could surface as Config (validate caught it) or ReadKey
        // (filesystem layer). Either is acceptable — both fail fast
        // before the SIGINT block.
        assert!(matches!(err, Error::Config(_) | Error::ReadKey(_, _)));
    }
}
