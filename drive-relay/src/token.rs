//! Cached OAuth access token with proactive refresh.
//!
//! Every Drive REST call needs a Bearer access token. Tokens
//! expire ~1 hour after issue. The relay holds one long-lived
//! refresh token (loaded from config at startup) and the current
//! access token; calls to [`TokenCache::get`] return the cached
//! access token if it has >60 seconds of life left, otherwise
//! refresh against `oauth2.googleapis.com/token` and return the
//! fresh one.
//!
//! Mutex around the cached token serialises concurrent refreshes:
//! ten parallel polling-worker calls won't fire ten refresh
//! requests; the first call refreshes, the rest see the updated
//! cache.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rahgozar::drive_oauth::{self, OAuthError, OAuthTokens};
use tokio::sync::Mutex;

pub struct TokenCache {
    /// Long-lived OAuth refresh token. Loaded from the relay's
    /// config.json once at startup; immutable after.
    refresh_token: String,
    /// User-supplied BYO OAuth client_id. Same value goes into
    /// the matching rahgozar client's `Config::drive.oauth_client_id`.
    /// See [`crate::config::RelayConfig::oauth_client_id`].
    oauth_client_id: String,
    /// User-supplied BYO OAuth client_secret. Pairs with
    /// [`Self::oauth_client_id`].
    oauth_client_secret: String,
    /// Currently-cached access token + expiry. `None` until the
    /// first successful refresh.
    cached: Mutex<Option<OAuthTokens>>,
    /// HTTP client used for refresh requests. Reused across calls
    /// for connection pooling.
    http: reqwest::Client,
    /// Latches when Google returns `invalid_grant` (refresh token
    /// revoked: user signed out, password rotated, sanctions, etc.).
    /// Once set, every subsequent `get()` call short-circuits to a
    /// cached error WITHOUT contacting Google — per RFC 6749 §5.2 the
    /// client MUST stop retrying a known-revoked token; repeated
    /// invalid_grant posts can trip Google's fraud heuristics and lock
    /// the OAuth account. The daemon stays up so systemd doesn't
    /// enter a restart loop; the poll loop logs the dead-token error
    /// on each tick and the operator re-runs `rahgozar-drive-relay
    /// oauth device-code` to mint a fresh token.
    revoked: AtomicBool,
}

impl TokenCache {
    pub fn new(
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
            revoked: AtomicBool::new(false),
        })
    }

    /// True iff the cache has latched in the revoked state. Used by
    /// the orphan reaper and metrics to surface this fact to the
    /// operator without busy-calling `get()`.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }

    /// Return a valid Bearer-eligible access token, refreshing
    /// against Google if the cache is empty or near expiry.
    ///
    /// Holding the mutex across the HTTP refresh is intentional:
    /// concurrent callers that race here block until the first
    /// refresh completes, then read the updated cache — so we
    /// don't burn a refresh quota fanning out N parallel requests
    /// for the same expired token.
    pub async fn get(&self) -> Result<String, OAuthError> {
        // Short-circuit on the latched-revoked state. No network call.
        // Repeated callers (poll loop, orphan reaper) all see the same
        // synthetic error, which keeps the per-poll log lines tight.
        if self.revoked.load(Ordering::SeqCst) {
            return Err(revoked_token_error());
        }
        let mut guard = self.cached.lock().await;
        let now = Instant::now();
        if let Some(tokens) = guard.as_ref() {
            if !tokens.is_near_expiry(now) {
                return Ok(tokens.access_token.clone());
            }
        }
        let fresh = match drive_oauth::refresh_access_token(
            &self.http,
            &self.refresh_token,
            &self.oauth_client_id,
            &self.oauth_client_secret,
        )
        .await
        {
            Ok(t) => t,
            Err(e) if e.is_refresh_token_revoked() => {
                // Latch. We compare_exchange so only the FIRST caller
                // logs the loud "operator action required" line —
                // subsequent callers short-circuit at the top of get().
                if !self.revoked.swap(true, Ordering::SeqCst) {
                    tracing::error!(
                        "OAuth refresh token is REVOKED ({}). Relay can no longer reach Drive. \
                         Run `rahgozar-drive-relay oauth device-code --client-id <id> \
                         --client-secret <secret>` on this host to mint a fresh token, then \
                         restart the daemon. Will NOT retry — repeated requests with a revoked \
                         token can trip Google's fraud heuristics and lock the account.",
                        e
                    );
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        let access = fresh.access_token.clone();
        *guard = Some(fresh);
        Ok(access)
    }

    /// True iff the cache currently holds a valid token. Used by
    /// the orphan reaper / metrics endpoint when polling — never
    /// triggers a refresh.
    pub async fn is_warm(&self) -> bool {
        match self.cached.lock().await.as_ref() {
            Some(t) => !t.is_near_expiry(Instant::now()),
            None => false,
        }
    }

    /// Test-only constructor that pre-populates the cache with a
    /// known `OAuthTokens`. Lets unit tests verify the cache-hit
    /// path without spinning up an HTTP mock.
    #[cfg(test)]
    pub(crate) fn with_cached(
        refresh_token: String,
        http: reqwest::Client,
        tokens: OAuthTokens,
    ) -> Arc<Self> {
        Arc::new(Self {
            refresh_token,
            oauth_client_id: "test-client.apps.googleusercontent.com".into(),
            oauth_client_secret: "test-client-secret".into(),
            cached: Mutex::new(Some(tokens)),
            http,
            revoked: AtomicBool::new(false),
        })
    }
}

/// Synthetic `OAuthError::Endpoint` returned by `get()` once the
/// revoked latch is set. Lets callers continue using their existing
/// `OAuthError::is_refresh_token_revoked()` classification path
/// without a separate error variant.
fn revoked_token_error() -> OAuthError {
    OAuthError::Endpoint {
        endpoint: "token refresh (latched revoked)",
        status: 400,
        body: r#"{"error":"invalid_grant","error_description":"refresh token revoked; daemon stopped retrying. Run `rahgozar-drive-relay oauth device-code` to re-auth."}"#.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rahgozar::drive_api::build_drive_http_client;
    use std::time::Duration;

    fn fixed_tokens(expires_at: Instant) -> OAuthTokens {
        OAuthTokens {
            access_token: "ya29.fresh".into(),
            refresh_token: None,
            expires_at,
            scope: String::new(),
        }
    }

    #[tokio::test]
    async fn get_returns_cached_when_fresh() {
        let http = build_drive_http_client(None).expect("build client");
        let cache = TokenCache::with_cached(
            "REFRESH".into(),
            http,
            fixed_tokens(Instant::now() + Duration::from_secs(3600)),
        );
        // Fresh cached → returned verbatim without an HTTP call.
        // If a refresh fired, it would hit the live `/token`
        // endpoint and either fail (no network) or return a
        // different access token; either way the assert below
        // would break.
        assert_eq!(cache.get().await.unwrap(), "ya29.fresh");
    }

    #[tokio::test]
    async fn is_warm_reports_fresh_state() {
        let http = build_drive_http_client(None).expect("build client");
        let fresh = TokenCache::with_cached(
            "R".into(),
            http.clone(),
            fixed_tokens(Instant::now() + Duration::from_secs(3600)),
        );
        assert!(fresh.is_warm().await);

        let stale = TokenCache::with_cached("R".into(), http, fixed_tokens(Instant::now()));
        // expires_at <= now + 60s → is_near_expiry → not warm.
        assert!(!stale.is_warm().await);
    }

    #[tokio::test]
    async fn cold_cache_is_not_warm() {
        let http = build_drive_http_client(None).expect("build client");
        let cache = TokenCache::new("R".into(), "CID".into(), "SECRET".into(), http);
        // Never refreshed → no cached tokens → cold.
        assert!(!cache.is_warm().await);
    }

    #[tokio::test]
    async fn revoked_latch_short_circuits_without_network() {
        // Build a cache with no live HTTP setup. If the revoked latch
        // didn't short-circuit, `get()` would attempt a refresh against
        // the real Google endpoint and either hang or fail with a
        // transport error — instead we expect an immediate
        // `Endpoint{..invalid_grant..}`, classifiable as revoked.
        let http = build_drive_http_client(None).expect("build client");
        let cache = TokenCache::new("R".into(), "CID".into(), "SECRET".into(), http);
        assert!(!cache.is_revoked());
        cache.revoked.store(true, Ordering::SeqCst);
        assert!(cache.is_revoked());

        let err = cache.get().await.unwrap_err();
        assert!(
            err.is_refresh_token_revoked(),
            "expected revoked-token error from latch, got {err:?}"
        );
        // Calling again still short-circuits and produces the same
        // shape of error — proves we're not retrying against Google
        // on every poll cycle.
        let err2 = cache.get().await.unwrap_err();
        assert!(err2.is_refresh_token_revoked());
    }
}
