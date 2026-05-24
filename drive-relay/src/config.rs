//! On-disk JSON config for the relay daemon.
//!
//! The schema mirrors the client-side [`rahgozar::config::DriveConfig`]
//! shape closely (`oauth_refresh_token`, `folder_id`, polling knobs)
//! but adds relay-specific fields: a path to the X25519 secret key
//! (minted by `rahgozar-drive-relay keygen`), per-session idle
//! timeout, optional destination allowlist, and an optional metrics
//! bind address.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Sensible default file location for the on-disk config. Used by
/// the systemd unit and the install script; the CLI `--config` flag
/// can override.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/rahgozar-drive-relay/config.json";

/// Sensible default file location for the X25519 secret key.
pub const DEFAULT_KEY_PATH: &str = "/etc/rahgozar-drive-relay/relay.key";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RelayConfig {
    /// OAuth 2.0 client_id from the operator's own Google Cloud
    /// project — see `docs/drive_oauth_setup.md`. rahgozar is BYO
    /// OAuth, so this MUST be set; there is no compile-time
    /// default. The relay normally uses a device-code-capable client;
    /// desktop clients can use a different Desktop OAuth client, but
    /// both clients must live in the same Google Cloud project /
    /// consent screen so `drive.file` app-scoped access lines up.
    #[serde(default)]
    pub oauth_client_id: String,

    /// OAuth 2.0 client_secret paired with
    /// [`Self::oauth_client_id`]. Stored plaintext alongside
    /// `oauth_refresh_token`; per RFC 8252 §8.6 not actually secret
    /// for installed apps. MUST be set — no compile-time default.
    #[serde(default)]
    pub oauth_client_secret: String,

    /// OAuth 2.0 refresh token obtained via `oauth device-code`.
    /// Stored plaintext under the relay user's `0700`-mode config
    /// directory — same trade-off documented in
    /// `rahgozar::config::DriveConfig`.
    pub oauth_refresh_token: String,

    /// Shared Drive folder ID (the bare ID, not a URL — what
    /// `files.create(mimeType=folder)` returns on the client side).
    /// Both client and relay must use the same folder ID;
    /// session-isolation happens via the per-frame `sid` prefix in
    /// the filename grammar, not via per-session folders.
    pub folder_id: String,

    /// Filesystem path to the 32-byte raw X25519 secret key minted
    /// by `rahgozar-drive-relay keygen`. Permissions are enforced
    /// by the keygen subcommand (`0600` on unix) and SHOULD be
    /// owned by the relay user.
    pub x25519_secret_key_path: PathBuf,

    /// Baseline poll interval (milliseconds) for the shared Drive
    /// `files.list` poller. The poller adapts: drops to a faster
    /// floor after a non-empty batch, ramps up after consecutive
    /// empty polls.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u32,

    /// Maximum concurrent outbound dials across all active sessions.
    /// Bounded so a burst of Connect frames doesn't exhaust the
    /// VPS's file-descriptor or ephemeral-port budget.
    #[serde(default = "default_max_concurrent_dials")]
    pub max_concurrent_dials: u8,

    /// Seconds after which an idle session (no inbound c2r_* frames,
    /// no outbound r2c_* frames) is considered dead. The orphan
    /// reaper sweeps Drive files older than `5 * idle_timeout_secs`
    /// to recover storage from clients that died mid-session.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u32,

    /// Optional destination allowlist. If non-empty, the relay
    /// refuses Connect frames whose target host isn't in this list.
    /// Useful for "this relay only forwards to X" deployments where
    /// the operator wants tighter scoping than the OAuth scope
    /// provides. Empty (default) → allow any destination, per the
    /// "self-hosted single-user VPS" model.
    #[serde(default)]
    pub allow_destinations: Vec<String>,

    /// Optional `host:port` to bind a Prometheus-style metrics
    /// endpoint on. `None` (default) → no metrics exposed.
    /// Recommendation: bind to `127.0.0.1:9090` and reverse-proxy
    /// behind WireGuard / SSH tunnel rather than exposing publicly.
    #[serde(default)]
    pub metrics_bind: Option<String>,
}

impl RelayConfig {
    /// Load + parse a config file. Returns a typed [`ConfigError`]
    /// distinguishing read failures from parse failures.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        serde_json::from_str(&raw).map_err(ConfigError::Parse)
    }

    /// Write the config file atomically (temp + rename). Creates
    /// the parent directory if absent.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp = match path.file_name() {
            Some(name) => {
                let mut tmp = path.to_path_buf();
                let mut name = name.to_os_string();
                name.push(".tmp");
                tmp.set_file_name(name);
                tmp
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "config path must end in a filename",
                ));
            }
        };
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        write_private_file(&tmp, json.as_bytes())?;
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        // Crash-safety: sync the parent directory so the rename hits
        // disk even if the VPS power-cycles right after `save` returns.
        // The file's own contents were already fsync'd by
        // `write_private_file`; this covers the directory entry update.
        // Best-effort — a sync failure here is far less actionable than
        // the save itself, and on tmpfs/etc. the open(parent) may fail
        // entirely; don't surface those to callers.
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::File::open(parent).and_then(|f| f.sync_all());
            }
        }
        Ok(())
    }

    /// Build a minimal config with sentinel values the operator must
    /// fill in before `run`. Used by the `oauth device-code`
    /// subcommand when no config file exists yet — it writes a
    /// placeholder with only the freshly-obtained refresh token.
    pub fn placeholder() -> Self {
        Self {
            oauth_client_id: String::new(),
            oauth_client_secret: String::new(),
            oauth_refresh_token: String::new(),
            folder_id: String::new(),
            x25519_secret_key_path: PathBuf::from(DEFAULT_KEY_PATH),
            poll_interval_ms: default_poll_interval_ms(),
            max_concurrent_dials: default_max_concurrent_dials(),
            idle_timeout_secs: default_idle_timeout_secs(),
            allow_destinations: Vec::new(),
            metrics_bind: None,
        }
    }

    /// Surface user-actionable misconfiguration before the run loop
    /// starts. Called by the `run` subcommand right after load — a
    /// missing refresh token / empty folder ID / unreachable key
    /// file fails here with a clear message, not deep inside the
    /// poller as a confusing transport error.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.oauth_client_id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "oauth_client_id is empty — rahgozar is BYO OAuth: register your own \
                 installed-app client in Google Cloud Console (see docs/drive_oauth_setup.md), \
                 then re-run `rahgozar-drive-relay oauth device-code --client-id <id> \
                 --client-secret <secret>`"
                    .into(),
            ));
        }
        if self.oauth_client_secret.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "oauth_client_secret is empty — pair it with oauth_client_id via the \
                 `oauth device-code --client-id <id> --client-secret <secret>` subcommand. \
                 See docs/drive_oauth_setup.md."
                    .into(),
            ));
        }
        if self.oauth_refresh_token.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "oauth_refresh_token is empty — run `rahgozar-drive-relay oauth device-code` first"
                    .into(),
            ));
        }
        if self.folder_id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "folder_id is empty — create the shared Drive folder in the desktop client UI, then paste the bare folder ID here"
                    .into(),
            ));
        }
        if !self.x25519_secret_key_path.exists() {
            return Err(ConfigError::Invalid(format!(
                "x25519_secret_key_path {} does not exist — run `rahgozar-drive-relay keygen` first",
                self.x25519_secret_key_path.display(),
            )));
        }
        if self.poll_interval_ms == 0 {
            return Err(ConfigError::Invalid(
                "poll_interval_ms must be > 0 (would otherwise busy-loop the poller)".into(),
            ));
        }
        if self.max_concurrent_dials == 0 {
            return Err(ConfigError::Invalid(
                "max_concurrent_dials must be > 0 (would otherwise stall every Connect frame)"
                    .into(),
            ));
        }
        if self.idle_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "idle_timeout_secs must be > 0 (would otherwise reap every protocol file and \
                 evict every session on each orphan-reaper sweep)"
                    .into(),
            ));
        }
        Ok(())
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Read(PathBuf, #[source] std::io::Error),
    #[error("failed to parse config JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("config invalid: {0}")]
    Invalid(String),
}

fn default_poll_interval_ms() -> u32 {
    300
}

fn default_max_concurrent_dials() -> u8 {
    8
}

fn default_idle_timeout_secs() -> u32 {
    120
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_has_expected_defaults() {
        let cfg = RelayConfig::placeholder();
        assert_eq!(cfg.poll_interval_ms, 300);
        assert_eq!(cfg.max_concurrent_dials, 8);
        assert_eq!(cfg.idle_timeout_secs, 120);
        assert!(cfg.allow_destinations.is_empty());
        assert_eq!(cfg.metrics_bind, None);
        // Sentinel values that validate() will reject.
        assert!(cfg.oauth_client_id.is_empty());
        assert!(cfg.oauth_client_secret.is_empty());
        assert!(cfg.oauth_refresh_token.is_empty());
        assert!(cfg.folder_id.is_empty());
    }

    #[test]
    fn serde_round_trip_preserves_all_fields() {
        let cfg = RelayConfig {
            oauth_client_id: "1234-test.apps.googleusercontent.com".into(),
            oauth_client_secret: "GOCSPX-test-secret".into(),
            oauth_refresh_token: "1//04xxxxxxxxxx".into(),
            folder_id: "0AABBccDDeeFFgg".into(),
            x25519_secret_key_path: PathBuf::from("/etc/rahgozar-drive-relay/relay.key"),
            poll_interval_ms: 500,
            max_concurrent_dials: 10,
            idle_timeout_secs: 60,
            allow_destinations: vec!["example.com".into(), "google.com".into()],
            metrics_bind: Some("127.0.0.1:9090".into()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: RelayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.oauth_client_id, cfg.oauth_client_id);
        assert_eq!(parsed.oauth_client_secret, cfg.oauth_client_secret);
        assert_eq!(parsed.oauth_refresh_token, cfg.oauth_refresh_token);
        assert_eq!(parsed.folder_id, cfg.folder_id);
        assert_eq!(parsed.poll_interval_ms, 500);
        assert_eq!(parsed.allow_destinations.len(), 2);
        assert_eq!(parsed.metrics_bind.as_deref(), Some("127.0.0.1:9090"));
    }

    #[test]
    fn deserializes_minimal_config_with_defaults() {
        let json = r#"{
            "oauth_client_id": "CID.apps.googleusercontent.com",
            "oauth_client_secret": "S",
            "oauth_refresh_token": "T",
            "folder_id": "F",
            "x25519_secret_key_path": "/tmp/k"
        }"#;
        let cfg: RelayConfig = serde_json::from_str(json).unwrap();
        // Defaults filled in for the absent fields.
        assert_eq!(cfg.poll_interval_ms, 300);
        assert_eq!(cfg.max_concurrent_dials, 8);
        assert_eq!(cfg.idle_timeout_secs, 120);
        assert!(cfg.allow_destinations.is_empty());
        assert_eq!(cfg.metrics_bind, None);
    }

    #[test]
    fn load_and_save_atomic_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let original = RelayConfig {
            oauth_client_id: "CID.apps.googleusercontent.com".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "T".into(),
            folder_id: "F".into(),
            x25519_secret_key_path: dir.path().join("relay.key"),
            poll_interval_ms: 250,
            max_concurrent_dials: 4,
            idle_timeout_secs: 90,
            allow_destinations: vec![],
            metrics_bind: None,
        };
        original.save(&path).expect("save");
        assert!(path.exists());
        // Save leaves no stale temp file behind.
        let tmp = path.with_file_name("config.json.tmp");
        assert!(
            !tmp.exists(),
            "temp file must be renamed away, not left behind"
        );
        let parsed = RelayConfig::load(&path).expect("load");
        assert_eq!(parsed.oauth_refresh_token, "T");
        assert_eq!(parsed.poll_interval_ms, 250);
    }

    #[test]
    fn validate_rejects_empty_client_id() {
        let mut cfg = RelayConfig::placeholder();
        cfg.oauth_client_secret = "S".into();
        cfg.oauth_refresh_token = "T".into();
        cfg.folder_id = "F".into();
        cfg.x25519_secret_key_path = PathBuf::from("Cargo.toml");
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("oauth_client_id"));
    }

    #[test]
    fn validate_rejects_empty_client_secret() {
        let mut cfg = RelayConfig::placeholder();
        cfg.oauth_client_id = "CID".into();
        cfg.oauth_refresh_token = "T".into();
        cfg.folder_id = "F".into();
        cfg.x25519_secret_key_path = PathBuf::from("Cargo.toml");
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("oauth_client_secret"));
    }

    #[test]
    fn validate_rejects_empty_refresh_token() {
        let mut cfg = RelayConfig::placeholder();
        cfg.oauth_client_id = "CID".into();
        cfg.oauth_client_secret = "S".into();
        cfg.folder_id = "F".into();
        cfg.x25519_secret_key_path = PathBuf::from("Cargo.toml"); // any existing file
                                                                  // oauth_refresh_token still empty (placeholder default).
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("oauth_refresh_token"));
    }

    #[test]
    fn validate_rejects_empty_folder_id() {
        let mut cfg = RelayConfig::placeholder();
        cfg.oauth_client_id = "CID".into();
        cfg.oauth_client_secret = "S".into();
        cfg.oauth_refresh_token = "T".into();
        cfg.x25519_secret_key_path = PathBuf::from("Cargo.toml");
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("folder_id"));
    }

    #[test]
    fn validate_rejects_missing_key_file() {
        let mut cfg = RelayConfig::placeholder();
        cfg.oauth_client_id = "CID".into();
        cfg.oauth_client_secret = "S".into();
        cfg.oauth_refresh_token = "T".into();
        cfg.folder_id = "F".into();
        cfg.x25519_secret_key_path = PathBuf::from("/definitely/does/not/exist/relay.key");
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn validate_rejects_zero_intervals() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("relay.key");
        std::fs::write(&key_path, [0u8; 32]).unwrap();
        let mut cfg = RelayConfig {
            oauth_client_id: "CID".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "T".into(),
            folder_id: "F".into(),
            x25519_secret_key_path: key_path.clone(),
            poll_interval_ms: 0,
            max_concurrent_dials: 8,
            idle_timeout_secs: 120,
            allow_destinations: vec![],
            metrics_bind: None,
        };
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("poll_interval_ms"));

        cfg.poll_interval_ms = 300;
        cfg.max_concurrent_dials = 0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_concurrent_dials"));

        cfg.max_concurrent_dials = 8;
        cfg.idle_timeout_secs = 0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("idle_timeout_secs"));
    }

    #[test]
    fn validate_accepts_well_formed_config() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("relay.key");
        std::fs::write(&key_path, [0u8; 32]).unwrap();
        let cfg = RelayConfig {
            oauth_client_id: "CID".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "T".into(),
            folder_id: "F".into(),
            x25519_secret_key_path: key_path,
            poll_interval_ms: 300,
            max_concurrent_dials: 8,
            idle_timeout_secs: 120,
            allow_destinations: vec![],
            metrics_bind: None,
        };
        cfg.validate().expect("well-formed config must validate");
    }
}
