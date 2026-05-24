//! Minimal Prometheus-style metrics endpoint for the Drive relay.
//!
//! The relay intentionally avoids pulling in an HTTP framework for this:
//! metrics is a local-ops endpoint with two tiny routes, so a small
//! Tokio TCP listener keeps the VPS binary lean.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::state::RelayState;

pub async fn spawn_metrics_server(
    state: Arc<RelayState>,
    bind: String,
) -> std::io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(&bind).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!("metrics endpoint listening on {}", local_addr);

    Ok(tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    // Transient errors here (EMFILE on the VPS, ECONNABORTED
                    // from a scraper that hung up mid-handshake) used to
                    // terminate the spawned task and permanently kill the
                    // metrics endpoint. Log + back off briefly + keep
                    // serving. The sleep is enough to avoid busy-looping
                    // on persistent fd exhaustion; metrics is low-QPS so
                    // fast recovery isn't worth the proxy's exponential
                    // accept_backoff machinery.
                    tracing::warn!("metrics accept failed (continuing): {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_one(stream, state).await {
                    tracing::debug!("metrics request from {} failed: {}", peer, e);
                }
            });
        }
    }))
}

async fn serve_one(mut stream: TcpStream, state: Arc<RelayState>) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("GET"), Some(path)) => Some(path),
                _ => None,
            }
        })
        .unwrap_or("/");

    let (status, content_type, body) = match path {
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_metrics(&state).await,
        ),
        "/healthz" => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await
}

async fn render_metrics(state: &RelayState) -> String {
    let active_sessions = state.sessions.read().await.len();
    let max_dials = state.cfg.max_concurrent_dials as usize;
    let available_dials = state.dial_permits.available_permits();
    let in_use_dials = max_dials.saturating_sub(available_dials);

    format!(
        concat!(
            "# HELP rahgozar_drive_relay_active_sessions Active Drive sessions in the relay table.\n",
            "# TYPE rahgozar_drive_relay_active_sessions gauge\n",
            "rahgozar_drive_relay_active_sessions {active_sessions}\n",
            "# HELP rahgozar_drive_relay_dial_permits_in_use Outbound dial permits currently in use.\n",
            "# TYPE rahgozar_drive_relay_dial_permits_in_use gauge\n",
            "rahgozar_drive_relay_dial_permits_in_use {in_use_dials}\n",
            "# HELP rahgozar_drive_relay_dial_permits_total Configured outbound dial permit capacity.\n",
            "# TYPE rahgozar_drive_relay_dial_permits_total gauge\n",
            "rahgozar_drive_relay_dial_permits_total {max_dials}\n",
            "# HELP rahgozar_drive_relay_poll_interval_ms Configured baseline Drive poll interval in milliseconds.\n",
            "# TYPE rahgozar_drive_relay_poll_interval_ms gauge\n",
            "rahgozar_drive_relay_poll_interval_ms {poll_interval}\n",
            "# HELP rahgozar_drive_relay_idle_timeout_secs Configured idle session timeout in seconds.\n",
            "# TYPE rahgozar_drive_relay_idle_timeout_secs gauge\n",
            "rahgozar_drive_relay_idle_timeout_secs {idle_timeout}\n",
        ),
        active_sessions = active_sessions,
        in_use_dials = in_use_dials,
        max_dials = max_dials,
        poll_interval = state.cfg.poll_interval_ms,
        idle_timeout = state.cfg.idle_timeout_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::state::RelayState;
    use crate::token::TokenCache;
    use rahgozar::drive_api::{build_drive_http_client, DriveApiClient};
    use rahgozar::drive_crypto::RelaySecret;
    use std::path::PathBuf;

    #[tokio::test]
    async fn render_metrics_includes_session_and_config_gauges() {
        let http = build_drive_http_client(None).expect("build client");
        let drive_api = DriveApiClient::new(http.clone(), "https://example.invalid".into());
        let cfg = Arc::new(RelayConfig {
            oauth_client_id: "CID".into(),
            oauth_client_secret: "S".into(),
            oauth_refresh_token: "R".into(),
            folder_id: "F".into(),
            x25519_secret_key_path: PathBuf::from("/dev/null"),
            poll_interval_ms: 250,
            max_concurrent_dials: 7,
            idle_timeout_secs: 45,
            allow_destinations: Vec::new(),
            metrics_bind: Some("127.0.0.1:0".into()),
        });
        let state = RelayState::new(
            cfg,
            Arc::new(RelaySecret::generate(rand::rngs::OsRng)),
            drive_api,
            TokenCache::new("R".into(), "CID".into(), "S".into(), http),
        );

        let body = render_metrics(&state).await;
        assert!(body.contains("rahgozar_drive_relay_active_sessions 0"));
        assert!(body.contains("rahgozar_drive_relay_dial_permits_total 7"));
        assert!(body.contains("rahgozar_drive_relay_poll_interval_ms 250"));
        assert!(body.contains("rahgozar_drive_relay_idle_timeout_secs 45"));
    }
}
