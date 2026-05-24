//! `rahgozar-drive-relay` — the VPS-side server binary for
//! rahgozar's Drive-mode transport.
//!
//! Subcommands:
//!
//!   - `run`               — start the daemon. Validates config +
//!                           key file, runs the OAuth refresh, then
//!                           spawns the shared Drive poller +
//!                           per-session forwarder + orphan reaper.
//!                           Blocks on SIGINT/SIGTERM.
//!   - `oauth device-code` — RFC 8628 device-code OAuth flow.
//!                           Requires `--client-id` + `--client-secret`
//!                           (BYO; see `docs/drive_oauth_setup.md`).
//!                           Prints `user_code` + `verification_url`,
//!                           polls Google, saves all three OAuth
//!                           credentials into the relay's config.json.
//!   - `keygen`            — mint a fresh X25519 keypair. Writes
//!                           the 32-byte secret to disk (mode 0600
//!                           on unix); prints the bech32m public key
//!                           for the operator to paste into the
//!                           client's `drive.relay_pubkey` config.
//!
//! See `drive-relay/scripts/install-drive-relay.sh` for the
//! end-to-end deployment guide (user, systemd, SELinux/AppArmor
//! considerations).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rahgozar::drive_api;
use rahgozar::drive_oauth;

use rahgozar_drive_relay::config::{RelayConfig, DEFAULT_CONFIG_PATH, DEFAULT_KEY_PATH};
use rahgozar_drive_relay::{keygen_to_file, run as run_relay, save_oauth_credentials};

#[derive(Parser)]
#[command(name = "rahgozar-drive-relay", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the relay daemon (polls Drive, dials destinations,
    /// forwards bytes).
    Run {
        #[arg(long, short, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// OAuth 2.0 flows for obtaining a refresh token.
    Oauth {
        #[command(subcommand)]
        cmd: OauthCmd,
    },
    /// Mint a fresh X25519 keypair for this relay.
    Keygen {
        /// Path to write the 32-byte secret key (mode 0600 on unix).
        /// Refuses to overwrite an existing file.
        #[arg(long, default_value = DEFAULT_KEY_PATH)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum OauthCmd {
    /// RFC 8628 device-code flow. Prints user_code + URL, polls,
    /// saves the OAuth credentials + refresh token into the relay's
    /// config.json (preserving every other field if the file
    /// already exists).
    ///
    /// Requires `--client-id` and `--client-secret` because rahgozar
    /// is BYO OAuth — register a "TVs and Limited Input devices"
    /// OAuth client in Google Cloud Console first (see
    /// `docs/drive_oauth_setup.md`).
    DeviceCode {
        /// OAuth 2.0 client_id from your Google Cloud project
        /// (BYO — see `docs/drive_oauth_setup.md`). Either pass on
        /// the CLI or set env var `RAHGOZAR_OAUTH_CLIENT_ID`.
        #[arg(long, env = "RAHGOZAR_OAUTH_CLIENT_ID")]
        client_id: String,
        /// OAuth 2.0 client_secret paired with `--client-id`.
        /// Either pass on the CLI or set env var
        /// `RAHGOZAR_OAUTH_CLIENT_SECRET`.
        #[arg(long, env = "RAHGOZAR_OAUTH_CLIENT_SECRET")]
        client_secret: String,
        /// Path to write the resulting config.json. If the file
        /// already exists, only the OAuth credentials + refresh
        /// token fields are updated; other fields stay as they were.
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { config } => cmd_run(config).await,
        Cmd::Oauth {
            cmd:
                OauthCmd::DeviceCode {
                    client_id,
                    client_secret,
                    out,
                },
        } => cmd_oauth_device_code(client_id, client_secret, out).await,
        Cmd::Keygen { out } => cmd_keygen(out),
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

async fn cmd_run(config_path: PathBuf) -> ExitCode {
    let cfg = match RelayConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                "failed to load config from {}: {}",
                config_path.display(),
                e
            );
            return ExitCode::FAILURE;
        }
    };
    tracing::warn!(
        "rahgozar-drive-relay starting (folder_id={}, key={})",
        cfg.folder_id,
        cfg.x25519_secret_key_path.display(),
    );
    match run_relay(cfg).await {
        Ok(()) => {
            tracing::info!("rahgozar-drive-relay exited cleanly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!("relay exited with error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn cmd_oauth_device_code(
    client_id: String,
    client_secret: String,
    out_path: PathBuf,
) -> ExitCode {
    // Build a Drive-compatible HTTP client. No `google_ip` override —
    // the relay sits on a free-internet VPS so the system DNS
    // resolves `oauth2.googleapis.com` directly.
    let client = match drive_api::build_drive_http_client(None) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to build HTTP client: {}", e);
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("requesting device code from Google...");
    let flow = match drive_oauth::device_code_start(&client, &client_id).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("device_code_start failed: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // User-facing instructions to stderr so they remain readable
    // even when stdout is being captured or piped.
    eprintln!();
    eprintln!("==============================================================");
    eprintln!("  Open this URL in any browser and enter the code below:");
    eprintln!();
    eprintln!("    {}", flow.verification_url);
    eprintln!("    code: {}", flow.user_code);
    eprintln!();
    eprintln!(
        "  This flow expires in {} seconds.",
        flow.expires_in.as_secs()
    );
    eprintln!("==============================================================");
    eprintln!();

    let mut interval = flow.interval;
    loop {
        tokio::time::sleep(interval).await;
        match drive_oauth::device_code_poll(&client, &flow.device_code, &client_id, &client_secret)
            .await
        {
            Ok(drive_oauth::DevicePollOutcome::Pending) => {
                tracing::debug!("device-code: pending");
            }
            Ok(drive_oauth::DevicePollOutcome::SlowDown) => {
                // RFC 8628 §3.5: bump the poll interval by at least
                // 5 seconds on each slow_down response.
                interval += Duration::from_secs(5);
                tracing::warn!(
                    "device-code: slow_down received; bumped interval to {:?}",
                    interval
                );
            }
            Ok(drive_oauth::DevicePollOutcome::AccessDenied) => {
                tracing::error!("device-code: user denied access");
                return ExitCode::FAILURE;
            }
            Ok(drive_oauth::DevicePollOutcome::ExpiredToken) => {
                tracing::error!("device-code: device_code expired; re-run the subcommand");
                return ExitCode::FAILURE;
            }
            Ok(drive_oauth::DevicePollOutcome::Tokens(tokens)) => {
                let refresh = match tokens.refresh_token {
                    Some(t) => t,
                    None => {
                        tracing::error!(
                            "device-code: success but Google did not return a refresh_token \
                             (this is unexpected — check OAuth client configuration)"
                        );
                        return ExitCode::FAILURE;
                    }
                };
                tracing::info!("device-code: authorized");
                if let Err(e) =
                    save_oauth_credentials(&out_path, &client_id, &client_secret, &refresh)
                {
                    tracing::error!(
                        "failed to save OAuth credentials to {}: {}",
                        out_path.display(),
                        e
                    );
                    return ExitCode::FAILURE;
                }
                eprintln!();
                eprintln!(
                    "Saved OAuth client_id, client_secret, and refresh token to {}.",
                    out_path.display()
                );
                eprintln!(
                    "Now edit that file to set `folder_id` (created in the desktop client UI) \
                     and `x25519_secret_key_path` (run `keygen` first)."
                );
                eprintln!();
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                // Mirror the JNI classification at android_jni.rs:1125-1146:
                // Transport / BadResponse are transient (DNS hiccup, gateway
                // returning HTML mid-flow, etc.) and the device_code is
                // still valid for its full expires_in (typically 1800 s),
                // so there's no reason to abandon a half-completed flow and
                // make the operator paste a fresh user_code on every blip.
                // Endpoint and MissingField are server-state failures —
                // continuing to poll won't help.
                let transient = matches!(
                    &e,
                    drive_oauth::OAuthError::Transport(_) | drive_oauth::OAuthError::BadResponse(_)
                );
                if transient {
                    tracing::warn!("device_code_poll transient error (retrying): {}", e);
                } else {
                    tracing::error!("device_code_poll failed: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        }
    }
}

fn cmd_keygen(out_path: PathBuf) -> ExitCode {
    let bech = match keygen_to_file(&out_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("keygen failed: {}", e);
            return ExitCode::FAILURE;
        }
    };
    eprintln!();
    eprintln!("Saved relay private key to {}.", out_path.display());
    eprintln!("Public key (paste into client's `drive.relay_pubkey`):");
    eprintln!();
    // Public key goes to stdout — single line, easy to capture with
    // `$(rahgozar-drive-relay keygen ... | tail -1)` in scripts.
    println!("{bech}");
    eprintln!();
    ExitCode::SUCCESS
}
