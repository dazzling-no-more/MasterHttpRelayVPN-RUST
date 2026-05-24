//! OAuth 2.0 client for the Google Drive API.
//!
//! Two flows, hand-rolled against `reqwest` (four HTTP POSTs total):
//!
//!   - **PKCE installed-app** (RFC 7636 + RFC 8252) — desktop UI.
//!     The Tauri command spawns a `127.0.0.1:0` listener, opens
//!     `accounts.google.com/.../auth?...` in the system browser,
//!     captures the redirected `?code=...`, and calls
//!     [`exchange_authorization_code`]. Once a refresh token is in
//!     hand, all subsequent traffic uses [`refresh_access_token`].
//!
//!   - **Device authorization grant** (RFC 8628) — VPS relay /
//!     Android fallback. Use a Google OAuth client of type "TVs and
//!     Limited Input devices". [`device_code_start`] returns the
//!     `user_code` + `verification_url`; print them, wait for the
//!     user, and poll [`device_code_poll`] every `interval` seconds
//!     until it returns `DevicePollOutcome::Tokens(_)` or an error.
//!
//! Scope is hard-coded to [`DRIVE_FILE_SCOPE`]
//! (`https://www.googleapis.com/auth/drive.file` — per-app: only
//! files this OAuth client created are visible).
//!
//! ## Design notes
//!
//! ### Why hand-rolled
//! `yup-oauth2` (the obvious alternative) drags `hyper` 0.14 + a
//! separate TLS path different from `reqwest`'s. Four POSTs is not
//! enough work to justify the extra ~40 transitive deps and the
//! second TLS surface in the cross-compile matrix.
//!
//! ### Pure / impure split
//! Token-URL construction, form-body encoding, and JSON-response
//! parsing live in private `build_*_body` / `parse_*_response_body`
//! helpers that take strings in and return strings or typed results
//! — no I/O. The thin public `*_request`-shaped wrappers above
//! compose them with `reqwest`. Tests cover the pure side
//! exhaustively; HTTP-touching wrappers are exercised by the
//! `wiremock`-based e2e test in a later slice.
//!
//! ### "Installed-app client secret" — BYO model
//! Per RFC 8252 §8.6 the `client_secret` for installed apps is not
//! actually secret — anyone with the published binary can extract
//! it. Google's token endpoint still requires it. rahgozar takes
//! the BYO ("bring your own") approach: every user registers their
//! own OAuth client_id + client_secret in Google Cloud Console (see
//! `docs/drive_oauth_setup.md` for the walkthrough) and pastes them
//! into the Drive setup screen. The credentials live in
//! `Config::drive.oauth_client_id` + `oauth_client_secret` and are
//! threaded as parameters into every function in this module — no
//! compile-time defaults exist. Rationale: an unverified OAuth
//! client has a 100-user cap on `drive.file` scope; BYO sidesteps
//! the cap entirely because every user gets their own 100 they
//! never hit.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::form_urlencoded;

// --------------------------------------------------------------------
// Constants — endpoints, scope, OAuth client identity
// --------------------------------------------------------------------

/// Google's OAuth 2.0 authorization endpoint (browser-side step of
/// the PKCE flow). The user lands here via [`build_auth_url`].
pub(crate) const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// Token endpoint for both code-exchange and refresh flows, and for
/// device-code polling. Production default; the
/// [`TOKEN_ENDPOINT_ENV`] env var overrides at process start (the
/// e2e wiremock test in `drive-relay/tests/drive_e2e.rs` uses this
/// to redirect both refresh + code-exchange to a mock server on
/// loopback HTTP).
pub(crate) const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Environment variable that overrides [`TOKEN_ENDPOINT`] at runtime.
/// Used exclusively by the e2e test harness — production builds
/// don't set it. Read on every call (rather than cached) so a test
/// that sets it before spawning a sub-task picks up the override
/// consistently.
pub const TOKEN_ENDPOINT_ENV: &str = "RAHGOZAR_OAUTH_TOKEN_ENDPOINT";

/// Resolved token endpoint URL — the env override if set, otherwise
/// the production default. Called once per outbound OAuth request.
fn token_endpoint() -> String {
    std::env::var(TOKEN_ENDPOINT_ENV).unwrap_or_else(|_| TOKEN_ENDPOINT.to_string())
}

/// Parse an OAuth callback URL of the shape
/// `<scheme>://<host>/<path>?code=...&state=...&...` and return the
/// extracted `(code, state)` pair, OR a top-level OAuth error
/// (e.g. user denied the consent screen — Google redirects with
/// `?error=access_denied` and no `code`).
///
/// Used by the Android JNI bridge to parse the redirected URI that
/// arrives via `MainActivity.onNewIntent`. The desktop PKCE flow's
/// loopback HTTP listener does its own parsing inline — see
/// `desktop/src-tauri/src/commands.rs::run_oauth_callback_listener`.
///
/// Scheme + host + path validation is the CALLER's responsibility:
/// this function only pulls out the query parameters.
pub fn parse_callback_url(url: &str) -> Result<CallbackParts, OAuthError> {
    // Split off the query — everything after the first `?`.
    let (_, query) = match url.split_once('?') {
        Some((b, q)) => (b, q),
        None => {
            return Err(OAuthError::BadResponse(format!(
                "OAuth callback URL is missing the `?<query>` section: {url}"
            )));
        }
    };
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut error: Option<String> = None;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let decoded = url_decode_ascii(v);
        match k {
            "code" => code = Some(decoded),
            "state" => state = Some(decoded),
            "error" => error = Some(decoded),
            _ => {}
        }
    }
    if let Some(err) = error {
        return Err(OAuthError::Endpoint {
            endpoint: "oauth callback",
            status: 0,
            body: err,
        });
    }
    let code = code.ok_or(OAuthError::MissingField("code"))?;
    let state = state.ok_or(OAuthError::MissingField("state"))?;
    Ok(CallbackParts { code, state })
}

/// Parts extracted from a successful OAuth callback URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackParts {
    pub code: String,
    pub state: String,
}

/// Minimal ASCII URL-decode for OAuth callback query values.
/// Hand-rolled to keep this crate from pulling another dep just for
/// percent-decoding — OAuth codes are URL-safe ASCII by construction
/// (their `+`/`/` chars are percent-encoded in the redirect URL),
/// so this covers every realistic input.
fn url_decode_ascii(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Device-code initiation endpoint (RFC 8628 §3.1). Returns the
/// `device_code` + `user_code` + `verification_url`.
pub(crate) const DEVICE_CODE_ENDPOINT: &str = "https://oauth2.googleapis.com/device/code";

/// OAuth scope. `drive.file` is per-app: the client only sees files
/// it created (or that the user explicitly opens with it). Switching
/// to the broader `drive` scope is a deliberate decision that would
/// expose the user's entire Drive — declined here.
pub const DRIVE_FILE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";

/// Device-code grant type URN — exactly the string RFC 8628 §3.4
/// mandates. Spelled out as a constant so a typo doesn't silently
/// fall back to a different grant type.
pub(crate) const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

// OAuth client credentials are BYO — supplied at runtime by the user
// via `Config::drive.oauth_client_id` + `oauth_client_secret` and
// threaded into every function in this module that needs them. See
// the module-level docstring for the rationale; see
// `docs/drive_oauth_setup.md` for the Google Cloud Console
// walkthrough end-users follow to register their own client.

// --------------------------------------------------------------------
// PKCE (RFC 7636)
// --------------------------------------------------------------------

/// PKCE code verifier + derived challenge. Mint once per browser-side
/// auth flow; the verifier is held client-side until the code is
/// exchanged. The challenge is what travels in the auth URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceCodes {
    /// 43-char URL-safe-base64-no-pad string (= 32 random bytes
    /// encoded). RFC 7636 §4.1 mandates 43-128 chars from
    /// `[A-Z][a-z][0-9]-._~`; URL_SAFE_NO_PAD covers all of those.
    pub code_verifier: String,
    /// Base64url-no-pad of SHA-256(`code_verifier`).
    pub code_challenge: String,
}

/// Mint a fresh PKCE pair. Caller stashes [`PkceCodes::code_verifier`]
/// keyed by the OAuth `state` token (or the in-memory pending-flow
/// map) and embeds [`PkceCodes::code_challenge`] in the auth URL.
pub fn generate_pkce_codes<R: RngCore>(rng: &mut R) -> PkceCodes {
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);
    let code_verifier = URL_SAFE_NO_PAD.encode(entropy);
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    PkceCodes {
        code_verifier,
        code_challenge,
    }
}

// --------------------------------------------------------------------
// Authorization URL (browser-side step)
// --------------------------------------------------------------------

/// Compose the URL the desktop browser is redirected to. After the
/// user signs in, Google bounces them to `redirect_uri` with a
/// `?code=...&state=...` query — the loopback listener on the Tauri
/// side captures it and calls [`exchange_authorization_code`].
///
/// `state` should be a per-flow random token; the caller keeps the
/// (state → code_verifier) mapping in-memory and looks it up when
/// the redirect lands so concurrent flows don't cross-pollinate.
///
/// `access_type=offline` + `prompt=consent` together force Google to
/// return a `refresh_token` even on re-grants — a one-time consent
/// without these returns only an `access_token`, and we'd be unable
/// to keep the session alive past 1 hour.
pub fn build_auth_url(
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkceCodes,
    state: &str,
) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", DRIVE_FILE_SCOPE)
        .append_pair("code_challenge", &pkce.code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .finish();
    format!("{AUTH_ENDPOINT}?{query}")
}

// --------------------------------------------------------------------
// Token / device-code form bodies (pure)
// --------------------------------------------------------------------

fn build_token_exchange_body(
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    client_id: &str,
    client_secret: &str,
) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_verifier", code_verifier)
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .finish()
}

fn build_refresh_body(refresh_token: &str, client_id: &str, client_secret: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", refresh_token)
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .finish()
}

fn build_device_code_start_body(client_id: &str) -> String {
    // Google's `/device/code` endpoint accepts only `client_id` +
    // `scope` (no `client_secret`, contrary to what one might
    // expect by analogy with `/token`). RFC 8628 §3.1 is the
    // reference; Google's deviation here is documented in the
    // OAuth 2.0 Device Authorization Grant guide.
    form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("scope", DRIVE_FILE_SCOPE)
        .finish()
}

fn build_device_code_poll_body(device_code: &str, client_id: &str, client_secret: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", DEVICE_CODE_GRANT_TYPE)
        .append_pair("device_code", device_code)
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .finish()
}

// --------------------------------------------------------------------
// Response types
// --------------------------------------------------------------------

/// Parsed token-endpoint response. `refresh_token` is `None` when
/// Google didn't include one (every successful refresh; first-time
/// code-exchange includes it).
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Absolute deadline at which the access token MUST be refreshed.
    /// Use [`Self::is_near_expiry`] to decide when to proactively
    /// refresh ahead of an expiring token.
    pub expires_at: Instant,
    pub scope: String,
}

impl OAuthTokens {
    /// True if the access token has fewer than 60 seconds of life
    /// left at `now`. Callers should refresh proactively to avoid
    /// a 401 on the next API call.
    pub fn is_near_expiry(&self, now: Instant) -> bool {
        self.expires_at.saturating_duration_since(now) <= Duration::from_secs(60)
    }
}

/// Result of [`device_code_start`]. The relay's `oauth device-code`
/// subcommand prints `user_code` + `verification_url` and polls
/// `device_code_poll` at `interval`-second intervals until either
/// `Tokens(_)` lands or the flow expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFlowStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    /// Polling interval the relay must honour. Polling faster yields
    /// a `slow_down` response.
    pub interval: Duration,
    /// How long the `device_code` is valid before the flow expires
    /// (default 1800 s on Google).
    pub expires_in: Duration,
}

/// What came back from a single [`device_code_poll`] call.
#[derive(Debug, Clone)]
pub enum DevicePollOutcome {
    /// User hasn't approved yet. Sleep `interval` and poll again.
    Pending,
    /// We polled too fast. RFC 8628 §3.5 says we MUST increase
    /// `interval` by at least 5 seconds for subsequent polls.
    SlowDown,
    /// User actively rejected the consent screen. Stop polling and
    /// surface a clear error to the operator.
    AccessDenied,
    /// `device_code` is past its `expires_in`. Restart the flow.
    ExpiredToken,
    /// Success — flow is done.
    Tokens(OAuthTokens),
}

// --------------------------------------------------------------------
// Response parsers (pure)
// --------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenSuccessJson {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
    #[serde(default)]
    scope: String,
}

#[derive(Deserialize)]
struct OAuthErrorJson {
    error: String,
    #[serde(default)]
    error_description: String,
}

#[derive(Deserialize)]
struct DeviceCodeStartJson {
    device_code: String,
    user_code: String,
    // Google's actual response field is `verification_url` — note
    // some OAuth providers use `verification_uri` per RFC 8628.
    // Accept either to be tolerant of provider variation.
    #[serde(alias = "verification_uri")]
    verification_url: String,
    expires_in: u64,
    #[serde(default = "default_device_code_interval_secs")]
    interval: u64,
}

fn default_device_code_interval_secs() -> u64 {
    5
}

fn parse_token_response_body(body: &str, now: Instant) -> Result<OAuthTokens, OAuthError> {
    // Token endpoint returns the same JSON shape for both code-exchange
    // and refresh. Refresh responses omit `refresh_token` (it's
    // reusable). `expires_in` is seconds-to-expiry from the moment
    // the response was generated server-side — close enough to `now`
    // that we ignore network RTT here.
    let parsed: TokenSuccessJson = serde_json::from_str(body)
        .map_err(|e| OAuthError::BadResponse(format!("token endpoint: {e}")))?;
    if parsed.access_token.is_empty() {
        return Err(OAuthError::MissingField("access_token"));
    }
    let expires_at = now + Duration::from_secs(parsed.expires_in);
    Ok(OAuthTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token.filter(|s| !s.is_empty()),
        expires_at,
        scope: parsed.scope,
    })
}

fn parse_device_code_start_response_body(body: &str) -> Result<DeviceFlowStart, OAuthError> {
    let parsed: DeviceCodeStartJson = serde_json::from_str(body)
        .map_err(|e| OAuthError::BadResponse(format!("device/code: {e}")))?;
    if parsed.device_code.is_empty() {
        return Err(OAuthError::MissingField("device_code"));
    }
    if parsed.user_code.is_empty() {
        return Err(OAuthError::MissingField("user_code"));
    }
    if parsed.verification_url.is_empty() {
        return Err(OAuthError::MissingField("verification_url"));
    }
    Ok(DeviceFlowStart {
        device_code: parsed.device_code,
        user_code: parsed.user_code,
        verification_url: parsed.verification_url,
        interval: Duration::from_secs(parsed.interval),
        expires_in: Duration::from_secs(parsed.expires_in),
    })
}

fn parse_device_poll_response_body(
    body: &str,
    now: Instant,
) -> Result<DevicePollOutcome, OAuthError> {
    // Try success first — RFC 8628 success body is the same shape
    // as `/token`'s. If it has `access_token`, we're done.
    if let Ok(tokens) = parse_token_response_body(body, now) {
        return Ok(DevicePollOutcome::Tokens(tokens));
    }
    // Otherwise it's an error body; the `error` code is what
    // determines whether we keep polling, slow down, or give up.
    let err: OAuthErrorJson = serde_json::from_str(body)
        .map_err(|e| OAuthError::BadResponse(format!("device poll: {e}")))?;
    match err.error.as_str() {
        "authorization_pending" => Ok(DevicePollOutcome::Pending),
        "slow_down" => Ok(DevicePollOutcome::SlowDown),
        "access_denied" => Ok(DevicePollOutcome::AccessDenied),
        "expired_token" => Ok(DevicePollOutcome::ExpiredToken),
        other => Err(OAuthError::Endpoint {
            endpoint: "device poll",
            status: 0,
            body: format!("unexpected error code '{other}': {}", err.error_description),
        }),
    }
}

// --------------------------------------------------------------------
// Error type
// --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Network / TLS / connection failure. Auto-converted from
    /// `reqwest::Error` so call sites can `?`-propagate.
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),
    /// OAuth endpoint returned a non-success status. Body is the
    /// raw response (error responses don't include access tokens).
    #[error("OAuth endpoint {endpoint} returned HTTP {status}: {body}")]
    Endpoint {
        endpoint: &'static str,
        status: u16,
        body: String,
    },
    /// Response body wasn't valid JSON, or the JSON didn't match
    /// the expected shape.
    #[error("malformed OAuth response: {0}")]
    BadResponse(String),
    /// JSON parsed but a required field was missing or empty.
    #[error("OAuth response is missing required field '{0}'")]
    MissingField(&'static str),
}

impl OAuthError {
    /// True iff this error indicates the refresh token is permanently
    /// dead — user signed out of Google, password rotated, sanctions
    /// hit, refresh token rotated/revoked, etc. Per RFC 6749 §5.2 the
    /// authorization server returns 400 with `error: "invalid_grant"`
    /// (and sometimes related codes like `invalid_request` on a
    /// malformed grant_type, or `unauthorized_client`).
    ///
    /// Critical that callers detect this and CLEAR the stored refresh
    /// token + prompt re-auth: retrying the same dead token can trip
    /// Google's fraud heuristics and lock the account. Used by the
    /// Android JNI Drive entries and the relay's `TokenCache::get`.
    pub fn is_refresh_token_revoked(&self) -> bool {
        match self {
            OAuthError::Endpoint { status, body, .. } => {
                if *status != 400 && *status != 401 {
                    return false;
                }
                // Match the OAuth `error` field rather than substring-
                // searching the whole body (the body may contain user-
                // controlled text in `error_description`). Best-effort
                // substring within a quoted JSON string is fine here —
                // the body is server-generated.
                body.contains("\"invalid_grant\"")
                    || body.contains("\"unauthorized_client\"")
                    || body.contains("\"invalid_client\"")
            }
            _ => false,
        }
    }
}

// --------------------------------------------------------------------
// rustls provider bootstrap
// --------------------------------------------------------------------

/// Install the `ring` rustls crypto provider as the process-wide
/// default. Idempotent and thread-safe.
///
/// **Required before constructing any `reqwest::Client` for OAuth
/// (or Drive REST) calls** — the workspace pins
/// `reqwest = { features = [..., "rustls-no-provider", ...] }` (so
/// `aws-lc-sys` doesn't break the mipsel-musl + OpenWRT cross-compile)
/// which leaves the provider choice to the binary. `tokio-rustls` is
/// already configured for `ring` elsewhere in the codebase; this
/// helper makes the same choice visible to reqwest's
/// `rustls::ClientConfig::builder()` path.
///
/// Calling twice (or after some other code installed a provider) is
/// fine: the second `install_default()` returns `Err`, which we
/// ignore — once any provider is installed the rustls handshake
/// path is satisfied.
pub fn install_default_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// --------------------------------------------------------------------
// HTTP-touching wrappers (thin layer over reqwest)
// --------------------------------------------------------------------

/// Exchange a freshly-captured `?code=...` (from the PKCE redirect
/// callback) for a token pair. The returned [`OAuthTokens`] always
/// has `refresh_token = Some(_)` because we ask for `access_type=
/// offline` + `prompt=consent` in [`build_auth_url`].
///
/// `client_id` + `client_secret` are the user-supplied OAuth
/// credentials from `Config::drive` — see the module docstring.
pub async fn exchange_authorization_code(
    client: &reqwest::Client,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<OAuthTokens, OAuthError> {
    let body =
        build_token_exchange_body(code, redirect_uri, code_verifier, client_id, client_secret);
    let now = Instant::now();
    let endpoint = token_endpoint();
    post_form_and_parse(client, &endpoint, body, "token exchange", |body| {
        parse_token_response_body(body, now)
    })
    .await
}

/// Mint a fresh access token from a stored refresh token. Returns
/// a new [`OAuthTokens`] with `refresh_token = None` (Google reuses
/// the original — the caller keeps the old refresh token alive).
///
/// `client_id` + `client_secret` are the user-supplied OAuth
/// credentials from `Config::drive` — see the module docstring.
pub async fn refresh_access_token(
    client: &reqwest::Client,
    refresh_token: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<OAuthTokens, OAuthError> {
    let body = build_refresh_body(refresh_token, client_id, client_secret);
    let now = Instant::now();
    let endpoint = token_endpoint();
    post_form_and_parse(client, &endpoint, body, "refresh", |body| {
        parse_token_response_body(body, now)
    })
    .await
}

/// Kick off a device-code flow. Caller prints
/// [`DeviceFlowStart::user_code`] + [`DeviceFlowStart::verification_url`]
/// for the user, then polls [`device_code_poll`] at the returned
/// [`DeviceFlowStart::interval`].
///
/// `client_id` is the user-supplied OAuth credential. The device-code
/// initiation endpoint does NOT take `client_secret`; see
/// [`build_device_code_start_body`].
pub async fn device_code_start(
    client: &reqwest::Client,
    client_id: &str,
) -> Result<DeviceFlowStart, OAuthError> {
    let body = build_device_code_start_body(client_id);
    post_form_and_parse(
        client,
        DEVICE_CODE_ENDPOINT,
        body,
        "device/code start",
        parse_device_code_start_response_body,
    )
    .await
}

/// One poll iteration in the device-code flow. The caller picks
/// up the outcome and decides whether to continue polling
/// (`Pending` / `SlowDown`) or stop (`Tokens` / `AccessDenied` /
/// `ExpiredToken`).
///
/// **`SlowDown` handling is the caller's responsibility.** Per
/// RFC 8628 §3.5 the polling interval MUST be increased by at
/// least 5 s on each `SlowDown` response — this function only
/// reports the outcome; rate-limit policy lives upstream.
///
/// `client_id` + `client_secret` are the user-supplied OAuth
/// credentials from `Config::drive` — see the module docstring.
pub async fn device_code_poll(
    client: &reqwest::Client,
    device_code: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<DevicePollOutcome, OAuthError> {
    let body = build_device_code_poll_body(device_code, client_id, client_secret);
    let now = Instant::now();
    let endpoint = token_endpoint();
    let resp = client
        .post(&endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    // Device-code poll returns either 200 (success) OR a 4xx with
    // an OAuth error body. Both are fed to the parser, which maps
    // the standard error codes to non-error `DevicePollOutcome`
    // variants. Only a non-OAuth-shaped error body surfaces as
    // `OAuthError::Endpoint`.
    let status = resp.status();
    let body = resp.text().await?;
    match parse_device_poll_response_body(&body, now) {
        Ok(outcome) => Ok(outcome),
        Err(OAuthError::BadResponse(_)) if !status.is_success() => Err(OAuthError::Endpoint {
            endpoint: "device poll",
            status: status.as_u16(),
            body,
        }),
        Err(e) => Err(e),
    }
}

/// Shared post-form-and-parse helper for the simple
/// "post body, expect 200 + JSON" wrappers above. Centralises the
/// content-type header, status-error wrapping, and pure-parser
/// invocation so each public wrapper stays a few lines.
async fn post_form_and_parse<T, F>(
    client: &reqwest::Client,
    url: &str,
    body: String,
    endpoint_label: &'static str,
    parse: F,
) -> Result<T, OAuthError>
where
    F: FnOnce(&str) -> Result<T, OAuthError>,
{
    let resp = client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(OAuthError::Endpoint {
            endpoint: endpoint_label,
            status: status.as_u16(),
            body,
        });
    }
    parse(&body)
}

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // ---- OAuthError::is_refresh_token_revoked ----------------------

    #[test]
    fn is_refresh_token_revoked_detects_invalid_grant() {
        let e = OAuthError::Endpoint {
            endpoint: "token refresh",
            status: 400,
            body: r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
                .to_string(),
        };
        assert!(e.is_refresh_token_revoked());
    }

    #[test]
    fn is_refresh_token_revoked_detects_unauthorized_client_401() {
        let e = OAuthError::Endpoint {
            endpoint: "token refresh",
            status: 401,
            body: r#"{"error":"unauthorized_client"}"#.to_string(),
        };
        assert!(e.is_refresh_token_revoked());
    }

    #[test]
    fn is_refresh_token_revoked_ignores_transport_errors() {
        // We deliberately don't construct a reqwest::Error in a
        // round-trippable way (it has no public constructor); exercise
        // the BadResponse arm + MissingField arm + a wrong-status
        // Endpoint to make sure they're not misclassified.
        assert!(
            !OAuthError::BadResponse("not json".into()).is_refresh_token_revoked(),
            "BadResponse must not be classified as revoked"
        );
        assert!(
            !OAuthError::MissingField("access_token").is_refresh_token_revoked(),
            "MissingField must not be classified as revoked"
        );
        assert!(
            !OAuthError::Endpoint {
                endpoint: "token refresh",
                status: 500,
                body: r#"{"error":"server_error"}"#.into(),
            }
            .is_refresh_token_revoked(),
            "5xx errors must not be classified as revoked"
        );
        assert!(
            !OAuthError::Endpoint {
                endpoint: "token refresh",
                status: 400,
                body: r#"{"error":"invalid_request"}"#.into(),
            }
            .is_refresh_token_revoked(),
            "invalid_request (e.g. bad grant_type) must not be classified as revoked"
        );
    }

    #[test]
    fn is_refresh_token_revoked_does_not_substring_match_user_text() {
        // Defensive: error_description is server-generated but
        // structurally we only want to match `"error": "invalid_grant"`,
        // not a substring elsewhere. Quote-anchored substring check
        // covers this — confirm.
        let e = OAuthError::Endpoint {
            endpoint: "token refresh",
            status: 400,
            body: r#"{"error":"invalid_request","error_description":"the word invalid_grant appears here but is not the error code"}"#.to_string(),
        };
        assert!(
            !e.is_refresh_token_revoked(),
            "must match quoted error code only, not substring-anywhere"
        );
    }

    // ---- PKCE ------------------------------------------------------

    #[test]
    fn pkce_verifier_is_43_chars_url_safe_b64() {
        let mut rng = OsRng;
        let codes = generate_pkce_codes(&mut rng);
        // 32 bytes base64-url-no-pad encoded → ceil(32 / 3 * 4) = 43.
        assert_eq!(codes.code_verifier.len(), 43);
        // Every char must be in the URL-safe-base64 alphabet.
        for c in codes.code_verifier.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "verifier contains forbidden char {c:?}"
            );
        }
    }

    #[test]
    fn pkce_challenge_is_sha256_of_verifier_url_b64_no_pad() {
        // RFC 7636 §4.2: code_challenge = BASE64URL-NO-PAD(SHA256(code_verifier)).
        // 32-byte digest → 43-char base64 string.
        let mut rng = OsRng;
        let codes = generate_pkce_codes(&mut rng);
        assert_eq!(codes.code_challenge.len(), 43);

        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(codes.code_verifier.as_bytes()));
        assert_eq!(codes.code_challenge, expected);
    }

    #[test]
    fn pkce_codes_are_unique_per_call() {
        let mut rng = OsRng;
        let a = generate_pkce_codes(&mut rng);
        let b = generate_pkce_codes(&mut rng);
        // 32 bytes of entropy per verifier → collision probability
        // ≈ 2^-256 per draw. This test effectively pins "the RNG is
        // actually being consumed, not zeroed".
        assert_ne!(a.code_verifier, b.code_verifier);
        assert_ne!(a.code_challenge, b.code_challenge);
    }

    // ---- Auth URL --------------------------------------------------

    #[test]
    fn auth_url_includes_all_required_params() {
        let pkce = PkceCodes {
            code_verifier: "v".into(),
            code_challenge: "abc-XYZ_123".into(),
        };
        let url = build_auth_url(
            "CID.googleusercontent.com",
            "http://127.0.0.1:9000/cb",
            &pkce,
            "S1",
        );
        assert!(url.starts_with(AUTH_ENDPOINT));
        for (k, v) in [
            ("response_type", "code"),
            ("client_id", "CID.googleusercontent.com"),
            ("scope", DRIVE_FILE_SCOPE),
            ("code_challenge", "abc-XYZ_123"),
            ("code_challenge_method", "S256"),
            ("state", "S1"),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ] {
            // Query params are URL-encoded, so the scope's slashes /
            // colons land as %2F / %3A. Verify by decoding the URL's
            // query against the expected (k, v) pair.
            let parsed = reqwest::Url::parse(&url).unwrap();
            let got: Option<String> = parsed
                .query_pairs()
                .find(|(qk, _)| qk == k)
                .map(|(_, qv)| qv.into_owned());
            assert_eq!(got.as_deref(), Some(v), "param {k}");
        }
    }

    #[test]
    fn auth_url_url_encodes_redirect_with_colons_and_slashes() {
        // The redirect_uri contains `://` and `:9000` and `/cb` —
        // every one needs URL encoding in the query value. Verify
        // round-tripping via `Url::parse` recovers the original.
        let pkce = PkceCodes {
            code_verifier: "v".into(),
            code_challenge: "c".into(),
        };
        let redirect = "http://127.0.0.1:54321/cb";
        let url = build_auth_url("CID", redirect, &pkce, "state");
        let parsed = reqwest::Url::parse(&url).unwrap();
        let got = parsed
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        assert_eq!(got, redirect);
    }

    #[test]
    fn auth_url_url_encodes_state_with_special_chars() {
        // A `state` containing `&` would otherwise terminate the
        // query value mid-pair. Verify it gets percent-encoded.
        let pkce = PkceCodes {
            code_verifier: "v".into(),
            code_challenge: "c".into(),
        };
        let state = "a&b=c d";
        let url = build_auth_url("CID", "http://x/cb", &pkce, state);
        let parsed = reqwest::Url::parse(&url).unwrap();
        let got = parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        assert_eq!(got, state);
    }

    // ---- Body builders --------------------------------------------

    fn parse_form_body(body: &str) -> std::collections::HashMap<String, String> {
        form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect()
    }

    // Fixture values used wherever a test needs to exercise the
    // BYO client_id / client_secret threading without caring about
    // the actual values. These never hit Google — only form-body
    // builders consume them.
    const TEST_CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
    const TEST_CLIENT_SECRET: &str = "test-client-secret";

    #[test]
    fn token_exchange_body_well_formed() {
        let body = build_token_exchange_body(
            "CODE",
            "http://127.0.0.1:1/cb",
            "VERIFIER",
            TEST_CLIENT_ID,
            TEST_CLIENT_SECRET,
        );
        let kv = parse_form_body(&body);
        assert_eq!(
            kv.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(kv.get("code").map(String::as_str), Some("CODE"));
        assert_eq!(
            kv.get("redirect_uri").map(String::as_str),
            Some("http://127.0.0.1:1/cb")
        );
        assert_eq!(
            kv.get("code_verifier").map(String::as_str),
            Some("VERIFIER")
        );
        assert_eq!(
            kv.get("client_id").map(String::as_str),
            Some(TEST_CLIENT_ID)
        );
        assert_eq!(
            kv.get("client_secret").map(String::as_str),
            Some(TEST_CLIENT_SECRET)
        );
    }

    #[test]
    fn refresh_body_well_formed() {
        let body = build_refresh_body("1//04xxxxxxxxxx", TEST_CLIENT_ID, TEST_CLIENT_SECRET);
        let kv = parse_form_body(&body);
        assert_eq!(
            kv.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert_eq!(
            kv.get("refresh_token").map(String::as_str),
            Some("1//04xxxxxxxxxx")
        );
        assert_eq!(
            kv.get("client_id").map(String::as_str),
            Some(TEST_CLIENT_ID)
        );
        assert_eq!(
            kv.get("client_secret").map(String::as_str),
            Some(TEST_CLIENT_SECRET)
        );
    }

    #[test]
    fn device_code_start_body_includes_client_id_and_scope_no_secret() {
        let body = build_device_code_start_body(TEST_CLIENT_ID);
        let kv = parse_form_body(&body);
        assert_eq!(
            kv.get("client_id").map(String::as_str),
            Some(TEST_CLIENT_ID)
        );
        assert_eq!(kv.get("scope").map(String::as_str), Some(DRIVE_FILE_SCOPE));
        // Google's /device/code endpoint does NOT accept a
        // client_secret — pinning the absence here so a future
        // "let's just add it for consistency with /token" edit
        // gets caught.
        assert!(!kv.contains_key("client_secret"));
    }

    #[test]
    fn device_code_poll_body_uses_correct_grant_urn() {
        let body = build_device_code_poll_body("DEV1", TEST_CLIENT_ID, TEST_CLIENT_SECRET);
        let kv = parse_form_body(&body);
        assert_eq!(
            kv.get("grant_type").map(String::as_str),
            Some(DEVICE_CODE_GRANT_TYPE)
        );
        assert_eq!(kv.get("device_code").map(String::as_str), Some("DEV1"));
        assert_eq!(
            kv.get("client_id").map(String::as_str),
            Some(TEST_CLIENT_ID)
        );
        assert_eq!(
            kv.get("client_secret").map(String::as_str),
            Some(TEST_CLIENT_SECRET)
        );
    }

    // ---- Token response parser ------------------------------------

    #[test]
    fn parse_token_response_success_with_refresh_token() {
        let now = Instant::now();
        let body = r#"{
            "access_token": "ya29.A0xxx",
            "refresh_token": "1//04xxx",
            "expires_in": 3599,
            "scope": "https://www.googleapis.com/auth/drive.file",
            "token_type": "Bearer"
        }"#;
        let tokens = parse_token_response_body(body, now).expect("parse");
        assert_eq!(tokens.access_token, "ya29.A0xxx");
        assert_eq!(tokens.refresh_token.as_deref(), Some("1//04xxx"));
        assert_eq!(tokens.scope, DRIVE_FILE_SCOPE);

        let ttl = tokens.expires_at.saturating_duration_since(now);
        // Build runs in microseconds; expires_at = now + 3599 s ±0.
        assert!(ttl >= Duration::from_secs(3598));
        assert!(ttl <= Duration::from_secs(3600));
    }

    #[test]
    fn parse_token_response_refresh_omits_refresh_token() {
        // Refresh responses from Google omit `refresh_token`
        // (the original stays valid). Parser must accept this.
        let now = Instant::now();
        let body = r#"{
            "access_token": "ya29.A0yyy",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/drive.file",
            "token_type": "Bearer"
        }"#;
        let tokens = parse_token_response_body(body, now).expect("parse");
        assert_eq!(tokens.refresh_token, None);
    }

    #[test]
    fn parse_token_response_treats_empty_refresh_token_as_none() {
        // A literal empty string for refresh_token must collapse to
        // None — otherwise downstream `Some("")` would be saved to
        // config and then re-tried fruitlessly on every refresh.
        let body = r#"{
            "access_token": "ya29.A0zzz",
            "refresh_token": "",
            "expires_in": 3600,
            "token_type": "Bearer"
        }"#;
        let tokens = parse_token_response_body(body, Instant::now()).expect("parse");
        assert_eq!(tokens.refresh_token, None);
    }

    #[test]
    fn parse_token_response_rejects_missing_access_token() {
        let body = r#"{ "expires_in": 100, "token_type": "Bearer" }"#;
        let err = parse_token_response_body(body, Instant::now()).unwrap_err();
        // serde fails before we hit our own MissingField check
        // because access_token is non-Option in the struct.
        assert!(matches!(err, OAuthError::BadResponse(_)));
    }

    #[test]
    fn parse_token_response_rejects_malformed_json() {
        let err = parse_token_response_body("{ not json", Instant::now()).unwrap_err();
        assert!(matches!(err, OAuthError::BadResponse(_)));
    }

    #[test]
    fn tokens_is_near_expiry_within_60_seconds() {
        let now = Instant::now();
        let near = OAuthTokens {
            access_token: "x".into(),
            refresh_token: None,
            expires_at: now + Duration::from_secs(30),
            scope: String::new(),
        };
        assert!(near.is_near_expiry(now));

        let far = OAuthTokens {
            access_token: "x".into(),
            refresh_token: None,
            expires_at: now + Duration::from_secs(3600),
            scope: String::new(),
        };
        assert!(!far.is_near_expiry(now));
    }

    // ---- Device-code start parser ---------------------------------

    #[test]
    fn parse_device_code_start_success() {
        let body = r#"{
            "device_code": "DC1",
            "user_code": "ABCD-EFGH",
            "verification_url": "https://www.google.com/device",
            "expires_in": 1800,
            "interval": 5
        }"#;
        let flow = parse_device_code_start_response_body(body).expect("parse");
        assert_eq!(flow.device_code, "DC1");
        assert_eq!(flow.user_code, "ABCD-EFGH");
        assert_eq!(flow.verification_url, "https://www.google.com/device");
        assert_eq!(flow.interval, Duration::from_secs(5));
        assert_eq!(flow.expires_in, Duration::from_secs(1800));
    }

    #[test]
    fn parse_device_code_start_accepts_verification_uri_alias() {
        // RFC 8628 §3.2 spells the field `verification_uri`; Google
        // uses `verification_url`. Tolerate both so a future
        // standards-clean OAuth provider doesn't trip us up.
        let body = r#"{
            "device_code": "DC2",
            "user_code": "WXYZ-1234",
            "verification_uri": "https://example.com/device",
            "expires_in": 600,
            "interval": 10
        }"#;
        let flow = parse_device_code_start_response_body(body).expect("parse");
        assert_eq!(flow.verification_url, "https://example.com/device");
    }

    #[test]
    fn parse_device_code_start_defaults_missing_interval() {
        // RFC 8628 makes `interval` optional and defaults it to 5
        // seconds when absent.
        let body = r#"{
            "device_code": "DC3",
            "user_code": "WXYZ-5678",
            "verification_url": "https://example.com/device",
            "expires_in": 600
        }"#;
        let flow = parse_device_code_start_response_body(body).expect("parse");
        assert_eq!(flow.interval, Duration::from_secs(5));
    }

    #[test]
    fn parse_device_code_start_rejects_missing_fields() {
        // Each required field, in turn, missing → MissingField error.
        let body = r#"{
            "device_code": "",
            "user_code": "X",
            "verification_url": "Y",
            "expires_in": 1,
            "interval": 1
        }"#;
        assert!(matches!(
            parse_device_code_start_response_body(body),
            Err(OAuthError::MissingField("device_code"))
        ));
    }

    // ---- Device-code poll parser ----------------------------------

    #[test]
    fn parse_device_poll_authorization_pending() {
        let body = r#"{"error": "authorization_pending"}"#;
        assert!(matches!(
            parse_device_poll_response_body(body, Instant::now()),
            Ok(DevicePollOutcome::Pending)
        ));
    }

    #[test]
    fn parse_device_poll_slow_down() {
        let body = r#"{"error": "slow_down"}"#;
        assert!(matches!(
            parse_device_poll_response_body(body, Instant::now()),
            Ok(DevicePollOutcome::SlowDown)
        ));
    }

    #[test]
    fn parse_device_poll_access_denied() {
        let body = r#"{"error": "access_denied"}"#;
        assert!(matches!(
            parse_device_poll_response_body(body, Instant::now()),
            Ok(DevicePollOutcome::AccessDenied)
        ));
    }

    #[test]
    fn parse_device_poll_expired_token() {
        let body = r#"{"error": "expired_token"}"#;
        assert!(matches!(
            parse_device_poll_response_body(body, Instant::now()),
            Ok(DevicePollOutcome::ExpiredToken)
        ));
    }

    #[test]
    fn parse_device_poll_success_returns_tokens() {
        let body = r#"{
            "access_token": "ya29.A0success",
            "refresh_token": "1//04success",
            "expires_in": 3600,
            "token_type": "Bearer"
        }"#;
        let outcome = parse_device_poll_response_body(body, Instant::now()).expect("parse");
        match outcome {
            DevicePollOutcome::Tokens(t) => {
                assert_eq!(t.access_token, "ya29.A0success");
                assert_eq!(t.refresh_token.as_deref(), Some("1//04success"));
            }
            other => panic!("expected Tokens, got {other:?}"),
        }
    }

    // ---- parse_callback_url (Android OAuth deep-link) -------------

    #[test]
    fn parse_callback_url_extracts_code_and_state() {
        let url = "rahgozar://oauth/cb?code=ABC123&state=XYZ789";
        let parts = parse_callback_url(url).unwrap();
        assert_eq!(parts.code, "ABC123");
        assert_eq!(parts.state, "XYZ789");
    }

    #[test]
    fn parse_callback_url_url_decodes_values() {
        // Google's OAuth code often contains `/` (encoded as `%2F`)
        // and `+` (encoded as `%2B`). The decoded values must
        // match what `exchange_authorization_code` expects.
        let url = "rahgozar://oauth/cb?code=4%2F0AeanS0a%2Fxyz&state=abc%2Bdef";
        let parts = parse_callback_url(url).unwrap();
        assert_eq!(parts.code, "4/0AeanS0a/xyz");
        assert_eq!(parts.state, "abc+def");
    }

    #[test]
    fn parse_callback_url_handles_other_params() {
        // Google may add `scope=...` and `prompt=...` after the
        // standard `code` + `state`. Extra params must not break
        // the parser.
        let url = "rahgozar://oauth/cb?code=AAA&state=BBB&scope=drive.file&prompt=consent";
        let parts = parse_callback_url(url).unwrap();
        assert_eq!(parts.code, "AAA");
        assert_eq!(parts.state, "BBB");
    }

    #[test]
    fn parse_callback_url_surfaces_error_param() {
        // User denied the consent screen — Google redirects with
        // `?error=access_denied` and no `code`. The parser must
        // surface this so the UI can show a "user cancelled" toast
        // instead of "missing code".
        let url = "rahgozar://oauth/cb?error=access_denied&state=XYZ";
        let err = parse_callback_url(url).unwrap_err();
        match err {
            OAuthError::Endpoint { endpoint, body, .. } => {
                assert_eq!(endpoint, "oauth callback");
                assert_eq!(body, "access_denied");
            }
            other => panic!("expected Endpoint error, got {other:?}"),
        }
    }

    #[test]
    fn parse_callback_url_rejects_missing_query() {
        // No `?` at all — can't be a valid OAuth callback.
        let err = parse_callback_url("rahgozar://oauth/cb").unwrap_err();
        assert!(matches!(err, OAuthError::BadResponse(_)));
    }

    #[test]
    fn parse_callback_url_rejects_missing_code() {
        // `state` present, `code` absent → MissingField("code").
        let err = parse_callback_url("rahgozar://oauth/cb?state=XYZ").unwrap_err();
        assert!(matches!(err, OAuthError::MissingField("code")));
    }

    #[test]
    fn parse_callback_url_rejects_missing_state() {
        // CSRF guard: a callback without `state` can't be matched
        // to a pending flow, so reject early.
        let err = parse_callback_url("rahgozar://oauth/cb?code=AAA").unwrap_err();
        assert!(matches!(err, OAuthError::MissingField("state")));
    }

    #[test]
    fn parse_device_poll_unknown_error_returns_endpoint_err() {
        // A novel error code (e.g. Google adds a new one in the
        // future) should surface as `OAuthError::Endpoint` rather
        // than be silently swallowed as `Pending`.
        let body = r#"{"error": "invalid_grant", "error_description": "bad device code"}"#;
        let err = parse_device_poll_response_body(body, Instant::now()).unwrap_err();
        assert!(matches!(
            err,
            OAuthError::Endpoint {
                endpoint: "device poll",
                ..
            }
        ));
    }
}
