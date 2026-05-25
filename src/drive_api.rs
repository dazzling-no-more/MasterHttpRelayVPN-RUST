//! Google Drive REST v3 client — the 4 endpoints rahgozar's
//! Drive-mode transport touches.
//!
//! ## Endpoints
//!
//! | Method | Path                                              | Purpose
//! | ------ | ------------------------------------------------- | -------
//! | GET    | `/drive/v3/files?q=...&fields=...`                | List mailbox files for the active direction prefix.
//! | GET    | `/drive/v3/files/<id>?alt=media`                  | Download the raw body of one file (the AEAD-sealed [`drive_wire::frame::WireFrame`]).
//! | POST   | `/upload/drive/v3/files?uploadType=multipart`     | Upload one file (metadata JSON + binary body in a single multipart/related POST).
//! | DELETE | `/drive/v3/files/<id>`                            | Remove a processed file from the mailbox.
//!
//! Plus a fifth, used only at first-setup time:
//!
//! | POST   | `/drive/v3/files`                                 | Create a folder (`mimeType=application/vnd.google-apps.folder`). Called by the Tauri `drive_create_folder` command and the relay's `keygen --create-folder` helper.
//!
//! ## Design
//!
//! ### Hand-rolled, not `google-drive3`
//! Same rationale as `drive_oauth` (sibling module): four endpoints
//! aren't worth ~80 transitive deps + a parallel HTTP/TLS path.
//! Pure `reqwest` calls; ~300 lines for the impure side.
//!
//! ### Domain-fronting the Drive API
//! [`build_drive_http_client`] is the canonical constructor: it
//! installs the `ring` rustls provider (required by the
//! `rustls-no-provider` feature pin on reqwest) and, if `google_ip`
//! is set, pins `www.googleapis.com` / `oauth2.googleapis.com` /
//! `accounts.google.com` to that IP. The TLS SNI still goes out as
//! the real hostname (so the cert verifies), but the TCP connection
//! lands on rahgozar's existing Iran-tested Google edge IP — the
//! same SNI-rewrite trick the rest of the codebase uses for
//! `script.google.com`, turned on for the Drive endpoints too.
//!
//! ### Test-mode endpoint override
//! Setting the env var `RAHGOZAR_DRIVE_API_BASE` (e.g. via
//! `wiremock`'s `MockServer::uri()` in the forthcoming e2e test
//! slice) replaces the production `https://www.googleapis.com`
//! base URL with the mock's address. Read once at
//! [`DriveApiClient::with_default_base_url`] construction time —
//! changing the env var mid-process has no effect on already-built
//! clients.
//!
//! ### Pure / impure split
//! Query-string + multipart-body construction and JSON response
//! parsing live in private helpers that take strings/bytes in and
//! return strings or typed results — no I/O. The thin
//! `*_request`-shaped wrappers below compose them with `reqwest`.
//! Tests cover the pure side; HTTP-touching wrappers are exercised
//! by the `wiremock` e2e test slice.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use rand::RngCore;
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// --------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------

/// Production base URL for the Drive REST API. Test scaffolding
/// overrides via the env var below.
pub const DEFAULT_DRIVE_API_BASE: &str = "https://www.googleapis.com";

/// Environment variable that overrides the base URL at client-build
/// time. Used exclusively by the `wiremock` e2e test slice to point
/// both client and relay at a mock Drive server.
pub const DRIVE_API_BASE_ENV: &str = "RAHGOZAR_DRIVE_API_BASE";

/// MIME type Google uses for folder entries. Setting this in the
/// upload metadata is what makes `files.create` produce a folder
/// rather than a regular file.
const DRIVE_FOLDER_MIME: &str = "application/vnd.google-apps.folder";

/// MIME type for the AEAD-sealed frame bodies. Hard-coded to
/// `application/octet-stream` — the body is opaque ciphertext, so
/// no Drive-side preview / OCR / etc. should attempt to interpret it.
const FRAME_BODY_MIME: &str = "application/octet-stream";

/// Default per-page list size. Drive's hard cap is 1000; 100 fits in
/// one short HTTP body and matches the typical c2r_*/r2c_* burst we
/// expect per poll.
pub const DEFAULT_LIST_PAGE_SIZE: u32 = 100;

/// ChaCha20-Poly1305 appends a 16-byte authentication tag to every
/// sealed WireFrame body. Nonce and AAD are derived from the filename
/// grammar and are not stored in the Drive file.
const AEAD_TAG_LEN: u64 = 16;

/// Maximum Drive body size for an AEAD-sealed frame file.
///
/// Plaintext is `WireFrame::encode()` (`HEADER_LEN + payload`) and the
/// ciphertext adds the 16-byte AEAD tag.
pub const MAX_SEALED_FRAME_BODY_BYTES: u64 =
    drive_wire::frame::HEADER_LEN as u64 + drive_wire::frame::MAX_PAYLOAD as u64 + AEAD_TAG_LEN;

// --------------------------------------------------------------------
// Public types
// --------------------------------------------------------------------

/// One entry returned by [`DriveApiClient::list_files_in_folder`].
/// `modified_time` and `size` are `Option`s because Drive marks them
/// as nullable in the schema (the parser is lenient to keep listings
/// flowing on malformed individual entries — bad rows are dropped,
/// not the whole batch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveFile {
    pub id: String,
    pub name: String,
    pub modified_time: Option<OffsetDateTime>,
    pub size: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum DriveApiError {
    /// Network / TLS / connection failure. Auto-converted from
    /// `reqwest::Error` so call sites can `?`-propagate.
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),
    /// Drive endpoint returned a non-2xx status. `reason` is the
    /// `error.errors[0].reason` field (e.g. `userRateLimitExceeded`,
    /// `notFound`, `forbidden`, `authError`) when the body matched
    /// Drive's standard error shape; `None` otherwise.
    #[error("Drive endpoint returned HTTP {status}: {message}")]
    Endpoint {
        status: u16,
        reason: Option<String>,
        message: String,
    },
    /// Response body wasn't valid JSON, or the JSON didn't match
    /// the expected shape for this endpoint.
    #[error("malformed Drive response: {0}")]
    BadResponse(String),
    /// File body exceeded the caller's protocol cap before the full
    /// response was buffered.
    #[error("Drive file {file_id} is {actual} bytes; maximum accepted is {limit} bytes")]
    ResponseTooLarge {
        file_id: String,
        actual: u64,
        limit: u64,
    },
    /// JSON parsed but a required field was missing or empty.
    #[error("Drive response is missing required field '{0}'")]
    MissingField(&'static str),
}

// --------------------------------------------------------------------
// reqwest client builder
// --------------------------------------------------------------------

/// Build a `reqwest::Client` configured for Drive API use:
///   1. Installs the `ring` rustls crypto provider (required by the
///      `rustls-no-provider` feature pin on reqwest).
///   2. Pins the three Google host names (`www.googleapis.com`,
///      `oauth2.googleapis.com`, `accounts.google.com`) to
///      `google_ip:443` if provided — domain-fronting the Drive API
///      through whatever Iran-tested IP `Config::google_ip` carries.
///   3. Enables transparent gzip (Drive sometimes returns
///      gzip-compressed `files.list` bodies; the `gzip` feature is
///      already pinned in `Cargo.toml`).
///
/// The same `reqwest::Client` is intentionally reused for OAuth calls
/// (`drive_oauth`) so the three OAuth endpoints get the same SNI
/// rewrite + connection pooling as the four Drive endpoints. One
/// client per [`DriveApiClient`] is the expected lifetime — building
/// a new one per request would forfeit connection pooling.
pub fn build_drive_http_client(google_ip: Option<&str>) -> Result<reqwest::Client, reqwest::Error> {
    crate::drive_oauth::install_default_crypto_provider();
    let mut builder = reqwest::Client::builder()
        .gzip(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        // Aggressive connection reuse. Drive Mode's per-cycle cost is
        // dominated by per-request TLS handshake + TCP round-trip; one
        // warm H2 connection multiplexes every upload/download/list
        // across the same TCP stream and avoids paying the handshake
        // cost again. The keep-alive ping interval (30 s) is short
        // enough that Google's edge doesn't drop the H2 connection
        // during the typical browsing idle window.
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_while_idle(true)
        .tcp_keepalive(Duration::from_secs(60))
        .pool_idle_timeout(Some(Duration::from_secs(300)));
    if let Some(ip_str) = google_ip {
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            let addr = std::net::SocketAddr::new(ip, 443);
            // Listed individually rather than via a wildcard because
            // reqwest's `resolve()` is exact-host (no glob) by design.
            for host in [
                "www.googleapis.com",
                "oauth2.googleapis.com",
                "accounts.google.com",
            ] {
                builder = builder.resolve(host, addr);
            }
        } else {
            // Malformed google_ip. `Config::validate` rejects this for
            // mode=drive (see config.rs `uses_drive_relay()` block) so
            // the primary defense is at config-load time. JNI paths
            // that bypass `validate` (loading raw fields from disk)
            // still reach here — upgrade to ERROR so a hand-edited
            // config.json doesn't silently fall back to system DNS
            // unnoticed. The transport will still work cosmetically
            // (TLS to whatever the ISP resolver returns) but it
            // defeats the point of Drive Mode on an Iran ISP.
            tracing::error!(
                "drive_api: google_ip {ip_str:?} is not a valid IP address — falling back to \
                 system DNS for Drive endpoints. This LEAKS the Drive transport to your ISP \
                 (Drive Mode exists precisely to bypass ISP DNS). Fix google_ip in config.json.",
            );
        }
    }
    builder.build()
}

// --------------------------------------------------------------------
// Drive API client
// --------------------------------------------------------------------

/// Thin wrapper around `reqwest::Client` that knows the Drive REST
/// endpoint paths + response shapes. Cheap to clone (the inner
/// `reqwest::Client` is already `Arc`-internal). No auth state held
/// here — `access_token` is passed per-call so the same client can
/// serve multiple OAuth identities (relay-side: multi-tenant) and
/// the caller can refresh tokens without rebuilding the client.
#[derive(Clone)]
pub struct DriveApiClient {
    http: reqwest::Client,
    base_url: Arc<str>,
}

impl DriveApiClient {
    /// New client using [`DEFAULT_DRIVE_API_BASE`] (or whatever the
    /// `RAHGOZAR_DRIVE_API_BASE` env var holds, if set). Read once
    /// at construction time.
    pub fn with_default_base_url(http: reqwest::Client) -> Self {
        let base = std::env::var(DRIVE_API_BASE_ENV)
            .unwrap_or_else(|_| DEFAULT_DRIVE_API_BASE.to_string());
        Self::new(http, base)
    }

    /// New client pointed at an explicit base URL. Used directly by
    /// the wiremock e2e test (when injecting the mock's address) and
    /// indirectly by [`Self::with_default_base_url`].
    pub fn new(http: reqwest::Client, base_url: String) -> Self {
        let trimmed = base_url.trim_end_matches('/').to_string();
        Self {
            http,
            base_url: Arc::from(trimmed),
        }
    }

    /// Underlying base URL (for diagnostics / logs).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // ---- files.list -----------------------------------------------

    /// List files in `folder_id`, optionally narrowing by names that
    /// contain `name_prefix`.
    /// Google Drive query syntax has `name contains` but no true
    /// starts-with operator. For unbounded startup lists we still use
    /// the marker because it cuts stale folder backlog dramatically.
    /// For cursor-based hot polling, the query relies on
    /// `modifiedTime >= since` only and callers filter names locally;
    /// this avoids Drive's full-text name index becoming the
    /// freshness bottleneck for newly uploaded mailbox files.
    /// Used by the Drive shared poller to scan one direction's
    /// inbound queue (`c2r_*` on the relay, `r2c_*` on the client)
    /// plus the Hello opener prefix (`h_*` on the relay).
    ///
    /// **The returned list is not numerically sorted by parsed `seq`.**
    /// Drive sorts by `createdTime` (lex order on filenames), so
    /// `..._10` lands before `..._2` lex-wise. Callers MUST parse
    /// filenames via [`drive_wire::filename::parse_filename`] and
    /// re-sort numerically before applying frames.
    pub async fn list_files_in_folder(
        &self,
        access_token: &str,
        folder_id: &str,
        name_prefix: &str,
    ) -> Result<Vec<DriveFile>, DriveApiError> {
        self.list_files_in_folder_since(access_token, folder_id, name_prefix, None)
            .await
    }

    /// Like [`Self::list_files_in_folder`] but with an optional
    /// `modifiedTime >= <since>` predicate (RFC 3339 timestamp string,
    /// passed verbatim into the Drive query). Caller advances `since`
    /// after each successful poll cycle so subsequent cycles return
    /// only files newer than the previous high-water mark — a huge
    /// per-call latency win once a Drive folder has accumulated even
    /// a few hundred frames, since the server returns the bounded
    /// delta instead of the full folder.
    ///
    /// `since=None` is equivalent to the unbounded list; useful for
    /// startup or test connection.
    pub async fn list_files_in_folder_since(
        &self,
        access_token: &str,
        folder_id: &str,
        name_prefix: &str,
        since: Option<&str>,
    ) -> Result<Vec<DriveFile>, DriveApiError> {
        let url = format!("{}/drive/v3/files", self.base_url);
        let q = build_list_query_since(folder_id, name_prefix, since);
        let page_size = DEFAULT_LIST_PAGE_SIZE.to_string();
        // Page through every `nextPageToken` Drive returns. A folder
        // with more than `DEFAULT_LIST_PAGE_SIZE` (100) matching
        // entries — common under burst traffic before the orphan
        // reaper catches up, or when the setup UI's "test
        // connection" counts a populated mailbox — would otherwise
        // silently truncate. Loop is bounded by Drive's own
        // pagination (no infinite-tail risk: each page must shrink
        // or omit `nextPageToken`); the safety cap below protects
        // against a misbehaving mock.
        let mut all: Vec<DriveFile> = Vec::new();
        let mut page_token: Option<String> = None;
        const MAX_PAGES: usize = 1_000;
        for _ in 0..MAX_PAGES {
            // The `query` builder eats `&[(k, &str)]` so build the
            // param slice with the optional pageToken in place.
            let mut params: Vec<(&str, &str)> = vec![
                ("q", q.as_str()),
                // `nextPageToken` MUST appear in `fields` or Drive
                // omits it from the response even when there are
                // more pages — silent truncation.
                ("fields", "nextPageToken,files(id,name,modifiedTime,size)"),
                ("pageSize", page_size.as_str()),
                // Runtime pollers use a sliding `modifiedTime >= since`
                // cursor.
                ("orderBy", "modifiedTime desc"),
                ("spaces", "drive"),
            ];
            if let Some(tok) = page_token.as_deref() {
                params.push(("pageToken", tok));
            }
            let resp = self
                .http
                .get(&url)
                .bearer_auth(access_token)
                .query(&params)
                .send()
                .await?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                return Err(parse_error_response(status.as_u16(), &body));
            }
            let (files, next) = parse_list_response_paged(&body)?;
            all.extend(files);
            match next {
                Some(t) if !t.is_empty() => page_token = Some(t),
                _ => return Ok(all),
            }
        }
        Err(DriveApiError::BadResponse(format!(
            "files.list: aborted after {MAX_PAGES} pages — Drive appears to be returning a \
             non-terminating nextPageToken chain"
        )))
    }

    // ---- files.get?alt=media --------------------------------------

    /// Download the raw bytes of one file, bounded by `max_bytes`.
    /// The returned `Bytes` is the AEAD-sealed
    /// [`drive_wire::frame::WireFrame`] (for c2r_* and r2c_*) or the
    /// unsealed Hello body (for h_*).
    pub async fn download_file(
        &self,
        access_token: &str,
        file_id: &str,
        max_bytes: u64,
    ) -> Result<Bytes, DriveApiError> {
        let url = format!("{}/drive/v3/files/{}", self.base_url, file_id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .query(&[("alt", "media")])
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await?;
            return Err(parse_error_response(status.as_u16(), &body));
        }
        if let Some(len) = resp.content_length() {
            ensure_body_within_limit(file_id, len, max_bytes)?;
        }

        let mut body = BytesMut::new();
        let mut total: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            total = total.saturating_add(chunk.len() as u64);
            ensure_body_within_limit(file_id, total, max_bytes)?;
            body.extend_from_slice(&chunk);
        }
        Ok(body.freeze())
    }

    // ---- files.create (multipart upload) --------------------------

    /// Upload `body` as a new file named `name` inside `folder_id`.
    /// Returns the new file's Drive ID — typically logged for
    /// debugging but otherwise discarded (the file is looked up by
    /// name on the receiver's next list).
    pub async fn upload_file(
        &self,
        access_token: &str,
        folder_id: &str,
        name: &str,
        body: Bytes,
    ) -> Result<String, DriveApiError> {
        let url = format!("{}/upload/drive/v3/files", self.base_url);
        let boundary = generate_boundary(&mut rand::thread_rng());
        let metadata = build_upload_metadata_json(folder_id, name, None);
        let multipart_body =
            build_multipart_related_body(metadata.as_bytes(), FRAME_BODY_MIME, &body, &boundary);
        let content_type = format!("multipart/related; boundary={boundary}");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .query(&[("uploadType", "multipart"), ("fields", "id")])
            .header("Content-Type", content_type)
            .body(multipart_body)
            .send()
            .await?;
        let status = resp.status();
        let resp_body = resp.text().await?;
        if !status.is_success() {
            return Err(parse_error_response(status.as_u16(), &resp_body));
        }
        let parsed = parse_file_create_response(&resp_body)?;
        Ok(parsed.id)
    }

    // ---- files.delete ---------------------------------------------

    /// Delete a file by ID. Returns `Ok(())` on either 204
    /// (no-content success) or 404 (already deleted — treat as
    /// success because the orphan reaper races against the per-frame
    /// cleanup deletes, and double-delete is the normal outcome).
    pub async fn delete_file(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<(), DriveApiError> {
        let url = format!("{}/drive/v3/files/{}", self.base_url, file_id);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let body = resp.text().await?;
        Err(parse_error_response(status.as_u16(), &body))
    }

    // ---- files.create (folder) ------------------------------------

    /// Create a new folder named `name` (at the user's Drive root).
    /// Used at first-time setup by the Tauri `drive_create_folder`
    /// command. Returns the new folder's Drive ID, which the user
    /// pastes into `Config::drive::folder_id`.
    ///
    /// No multipart upload — folder creation is a plain JSON POST
    /// with the special folder MIME type. Both client and relay
    /// need write access to the folder; this is created by the
    /// client side once and shared with the relay out-of-band (the
    /// relay's OAuth identity must be granted access, OR the
    /// simpler "single OAuth account for both ends" path is used).
    pub async fn create_folder(
        &self,
        access_token: &str,
        name: &str,
    ) -> Result<String, DriveApiError> {
        let url = format!("{}/drive/v3/files", self.base_url);
        let body = build_folder_create_body(name);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .header("Content-Type", "application/json; charset=UTF-8")
            .query(&[("fields", "id")])
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let resp_body = resp.text().await?;
        if !status.is_success() {
            return Err(parse_error_response(status.as_u16(), &resp_body));
        }
        let parsed = parse_file_create_response(&resp_body)?;
        Ok(parsed.id)
    }
}

// --------------------------------------------------------------------
// Pure helpers — query building
// --------------------------------------------------------------------

/// Compose Drive's `q` parameter for our list call. When
/// `name_prefix` is non-empty, use:
/// `'<folder>' in parents and name contains '<prefix>' and trashed = false`.
/// When it is empty, list the folder contents without relying on an
/// empty Drive string literal:
/// `'<folder>' in parents and trashed = false`.
///
/// Drive's query language uses single-quoted string literals with
/// backslash escapes (`\'` for literal quote, `\\` for backslash).
/// `folder_id` is a Drive-issued opaque string; `name_prefix` is our
/// own (`c2r_`, `r2c_`, `h_`). Neither realistically contains
/// quotes or backslashes — but the escaping defends against a
/// future caller passing user input straight in.
fn build_list_query(folder_id: &str, name_prefix: &str) -> String {
    build_list_query_since(folder_id, name_prefix, None)
}

/// Same as `build_list_query` but with an optional `modifiedTime >=
/// '<since>'` predicate. `since` must already be an RFC 3339 string;
/// it's wrapped in single quotes and embedded literally in the
/// query. When `since` is present, omit `name contains`: active
/// polling wants Drive's recently-modified folder listing, not its
/// slower full-text name index. Callers already filter by parsed
/// filename after the list call.
fn build_list_query_since(folder_id: &str, name_prefix: &str, since: Option<&str>) -> String {
    let folder = escape_query_literal(folder_id);
    let mut q = if name_prefix.is_empty() || since.is_some() {
        format!("'{folder}' in parents and trashed = false")
    } else {
        format!(
            "'{folder}' in parents and name contains '{}' and trashed = false",
            escape_query_literal(name_prefix),
        )
    };
    if let Some(s) = since {
        q.push_str(" and modifiedTime >= '");
        q.push_str(&escape_query_literal(s));
        q.push('\'');
    }
    q
}

fn escape_query_literal(s: &str) -> String {
    // Order matters: escape `\` first, otherwise the quotes we add
    // later would themselves get re-escaped.
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn ensure_body_within_limit(file_id: &str, actual: u64, limit: u64) -> Result<(), DriveApiError> {
    if actual > limit {
        return Err(DriveApiError::ResponseTooLarge {
            file_id: file_id.to_string(),
            actual,
            limit,
        });
    }
    Ok(())
}

// --------------------------------------------------------------------
// Pure helpers — multipart body construction
// --------------------------------------------------------------------

/// Mint a fresh 32-hex-char boundary token. Random per upload so a
/// (vanishingly unlikely) collision with the body bytes doesn't
/// prematurely terminate the multipart parsing on Drive's side.
/// Collision probability per upload: ~2^-128. The boundary is also
/// a valid `Content-Type` parameter value (no special characters).
fn generate_boundary<R: RngCore>(rng: &mut R) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Compose the metadata JSON for the file-upload step.
/// `mime_type = None` → omit the field (Drive defaults to whatever
/// the Content-Type of the body part declares). `mime_type =
/// Some(DRIVE_FOLDER_MIME)` is what makes a `files.create` produce
/// a folder.
fn build_upload_metadata_json(folder_id: &str, name: &str, mime_type: Option<&str>) -> String {
    let folder_id_json = serde_json::Value::String(folder_id.to_string());
    let name_json = serde_json::Value::String(name.to_string());
    let mut obj = serde_json::Map::new();
    obj.insert("name".into(), name_json);
    obj.insert(
        "parents".into(),
        serde_json::Value::Array(vec![folder_id_json]),
    );
    if let Some(mt) = mime_type {
        obj.insert("mimeType".into(), serde_json::Value::String(mt.to_string()));
    }
    serde_json::Value::Object(obj).to_string()
}

/// Compose the folder-create JSON body. Uses Drive's special
/// folder MIME type; no `parents` field, so the new folder lands
/// at the user's Drive root.
fn build_folder_create_body(name: &str) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("name".into(), serde_json::Value::String(name.to_string()));
    obj.insert(
        "mimeType".into(),
        serde_json::Value::String(DRIVE_FOLDER_MIME.to_string()),
    );
    serde_json::Value::Object(obj).to_string()
}

/// Assemble a `multipart/related` body per RFC 2387. Two parts:
/// the metadata JSON (`Content-Type: application/json`) then the
/// binary body (`Content-Type: <body_mime>`). The trailing
/// `--<boundary>--\r\n` terminates the message.
fn build_multipart_related_body(
    metadata_json: &[u8],
    body_mime: &str,
    body: &[u8],
    boundary: &str,
) -> Vec<u8> {
    // Pre-size to avoid reallocations: two delimiter lines + two
    // headers + the metadata + the body + the terminator. The
    // headers are ~60 bytes each; boundary is 32 chars; metadata
    // is a few hundred bytes; body is up to 4 MiB.
    let estimated = metadata_json.len() + body.len() + boundary.len() * 4 + 200;
    let mut out = Vec::with_capacity(estimated);
    // Part 1: metadata JSON.
    out.extend_from_slice(b"--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
    out.extend_from_slice(metadata_json);
    out.extend_from_slice(b"\r\n");
    // Part 2: binary body.
    out.extend_from_slice(b"--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(body_mime.as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n");
    // Terminator.
    out.extend_from_slice(b"--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"--\r\n");
    out
}

// --------------------------------------------------------------------
// Pure helpers — JSON response parsing
// --------------------------------------------------------------------

#[derive(Deserialize)]
struct ListResponseJson {
    #[serde(default)]
    files: Vec<FileEntryJson>,
    /// Continuation token Drive returns when the result set exceeds
    /// `pageSize`. Empty / absent means there are no more pages.
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct FileEntryJson {
    id: String,
    name: String,
    #[serde(default, rename = "modifiedTime")]
    modified_time: Option<String>,
    /// Drive emits `size` as a string-encoded integer (JS-safe int64
    /// representation). Optional because folder entries omit it.
    #[serde(default)]
    size: Option<String>,
}

/// Parse one page of `files.list` and return the page-token alongside
/// the rows. Used by the paginating `list_files_in_folder` loop. The
/// single-page-only `parse_list_response` below is kept for backward
/// compat with existing tests that don't care about pagination.
fn parse_list_response_paged(
    body: &str,
) -> Result<(Vec<DriveFile>, Option<String>), DriveApiError> {
    let parsed: ListResponseJson = serde_json::from_str(body)
        .map_err(|e| DriveApiError::BadResponse(format!("files.list: {e}")))?;
    let next = parsed.next_page_token.clone();
    let files = list_response_rows(parsed);
    Ok((files, next))
}

fn list_response_rows(parsed: ListResponseJson) -> Vec<DriveFile> {
    parsed
        .files
        .into_iter()
        .filter_map(|entry| {
            // Drop entries with empty id/name — they can't be acted
            // on by `download_file` / `delete_file` anyway. Don't
            // error the whole batch; just skip the row.
            if entry.id.is_empty() || entry.name.is_empty() {
                return None;
            }
            let modified_time = entry
                .modified_time
                .and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok());
            let size = entry.size.and_then(|s| s.parse::<u64>().ok());
            Some(DriveFile {
                id: entry.id,
                name: entry.name,
                modified_time,
                size,
            })
        })
        .collect()
}

/// Single-page parser kept for backward compat with existing tests
/// (and any future caller that knows pageSize is sufficient).
#[cfg(test)]
fn parse_list_response(body: &str) -> Result<Vec<DriveFile>, DriveApiError> {
    let parsed: ListResponseJson = serde_json::from_str(body)
        .map_err(|e| DriveApiError::BadResponse(format!("files.list: {e}")))?;
    Ok(list_response_rows(parsed))
}

#[derive(Debug, Deserialize)]
struct FileCreateResponseJson {
    id: String,
}

fn parse_file_create_response(body: &str) -> Result<FileCreateResponseJson, DriveApiError> {
    let parsed: FileCreateResponseJson = serde_json::from_str(body)
        .map_err(|e| DriveApiError::BadResponse(format!("files.create: {e}")))?;
    if parsed.id.is_empty() {
        return Err(DriveApiError::MissingField("id"));
    }
    Ok(parsed)
}

#[derive(Deserialize)]
struct ErrorBodyJson {
    error: ErrorInnerJson,
}

#[derive(Deserialize)]
struct ErrorInnerJson {
    #[serde(default)]
    code: u16,
    #[serde(default)]
    message: String,
    #[serde(default)]
    errors: Vec<ErrorDetailJson>,
}

#[derive(Deserialize)]
struct ErrorDetailJson {
    #[serde(default)]
    reason: String,
}

/// Convert a non-2xx response body into a typed [`DriveApiError`].
/// `status` is the HTTP status code, `body` is the raw response. If
/// the body parses as Drive's standard error shape, the reason +
/// message are surfaced; otherwise the raw body lands in `message`.
fn parse_error_response(status: u16, body: &str) -> DriveApiError {
    match serde_json::from_str::<ErrorBodyJson>(body) {
        Ok(parsed) => {
            let reason = parsed
                .error
                .errors
                .into_iter()
                .map(|d| d.reason)
                .find(|r| !r.is_empty());
            let message = if parsed.error.message.is_empty() {
                format!("HTTP {status}")
            } else {
                parsed.error.message
            };
            DriveApiError::Endpoint {
                status,
                reason,
                message,
            }
        }
        Err(_) => DriveApiError::Endpoint {
            status,
            reason: None,
            message: body.to_string(),
        },
    }
}

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // ---- Query builder ---------------------------------------------

    #[test]
    fn build_list_query_canonical_shape() {
        let q = build_list_query("0AABBccDD", "c2r_");
        assert_eq!(
            q,
            "'0AABBccDD' in parents and name contains 'c2r_' and trashed = false"
        );
    }

    #[test]
    fn build_list_query_omits_name_predicate_for_empty_prefix() {
        let q = build_list_query("0AABBccDD", "");
        assert_eq!(q, "'0AABBccDD' in parents and trashed = false");
    }

    #[test]
    fn build_list_query_since_adds_modified_time_lower_bound() {
        // When `since` is supplied, the query MUST NOT include
        // `name contains` — that path uses Drive's slow full-text
        // name index. Active polling instead asks for the folder's
        // recently-modified children, and callers filter by parsed
        // filename locally. Pins the optimisation against accidental
        // regression.
        let q = build_list_query_since("0AABBccDD", "r2c_", Some("2026-05-24T10:11:12.123Z"));
        assert_eq!(
            q,
            "'0AABBccDD' in parents and trashed = false and modifiedTime >= '2026-05-24T10:11:12.123Z'"
        );
    }

    #[test]
    fn build_list_query_since_without_prefix_matches_with_prefix() {
        // With a `since` cursor, the prefix is ignored — both calls
        // must produce the same query, since the prefix predicate is
        // dropped on the cursor path. Locks in the equivalence so a
        // future caller that passes "" by mistake doesn't silently
        // change behaviour.
        let a = build_list_query_since("F", "r2c_", Some("2026-05-24T10:11:12Z"));
        let b = build_list_query_since("F", "", Some("2026-05-24T10:11:12Z"));
        assert_eq!(a, b);
    }

    #[test]
    fn build_list_query_without_since_still_uses_name_contains() {
        // Startup path (`since = None`) keeps the `name contains`
        // narrowing — folder bootstrap legitimately needs to filter
        // out the other direction's frames before paging.
        let q = build_list_query_since("F", "r2c_", None);
        assert_eq!(
            q,
            "'F' in parents and name contains 'r2c_' and trashed = false"
        );
    }

    #[test]
    fn escape_query_literal_escapes_quotes_and_backslashes() {
        // Quote in folder id (hypothetical hostile input).
        assert_eq!(escape_query_literal("a'b"), "a\\'b");
        // Backslash in name prefix.
        assert_eq!(escape_query_literal("a\\b"), "a\\\\b");
        // Both — backslash must escape first so the later quote-escape
        // doesn't double-escape the backslashes it just added.
        assert_eq!(escape_query_literal("a\\'b"), "a\\\\\\'b");
        // Normal printable inputs pass through unchanged.
        assert_eq!(escape_query_literal("0AABBccDD"), "0AABBccDD");
        assert_eq!(escape_query_literal("c2r_"), "c2r_");
    }

    // ---- Multipart builder -----------------------------------------

    #[test]
    fn boundary_is_32_hex_chars() {
        let b = generate_boundary(&mut OsRng);
        assert_eq!(b.len(), 32);
        assert!(b
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn boundaries_are_unique_per_call() {
        // ~2^-128 collision probability per pair; effectively pins
        // "the RNG is actually being consumed".
        let a = generate_boundary(&mut OsRng);
        let b = generate_boundary(&mut OsRng);
        assert_ne!(a, b);
    }

    #[test]
    fn upload_metadata_json_well_formed() {
        let json = build_upload_metadata_json("FOLDER123", "c2r_abc_1", None);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["name"], "c2r_abc_1");
        assert_eq!(v["parents"][0], "FOLDER123");
        // No mimeType when None — Drive infers from the body part.
        assert!(v.get("mimeType").is_none());
    }

    #[test]
    fn upload_metadata_json_with_mime_type_includes_it() {
        let json = build_upload_metadata_json("F", "n", Some(DRIVE_FOLDER_MIME));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["mimeType"], DRIVE_FOLDER_MIME);
    }

    #[test]
    fn folder_create_body_omits_parents_so_it_lands_at_root() {
        let json = build_folder_create_body("rahgozar drive mailbox");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["name"], "rahgozar drive mailbox");
        assert_eq!(v["mimeType"], DRIVE_FOLDER_MIME);
        // `parents` absent → Drive places the folder at the user's
        // root. Pinning this so a future "add a parents field for
        // convenience" edit gets caught.
        assert!(v.get("parents").is_none());
    }

    #[test]
    fn multipart_body_has_expected_structure() {
        let metadata = br#"{"name":"x","parents":["F"]}"#;
        let body = b"\x01\x02\x03binary";
        let boundary = "BOUNDARY01234567";
        let out =
            build_multipart_related_body(metadata, "application/octet-stream", body, boundary);
        let as_str = String::from_utf8_lossy(&out);

        // Required structural markers.
        assert!(as_str.contains("--BOUNDARY01234567\r\n"));
        assert!(as_str.contains("Content-Type: application/json; charset=UTF-8\r\n\r\n"));
        assert!(as_str.contains(r#"{"name":"x","parents":["F"]}"#));
        assert!(as_str.contains("Content-Type: application/octet-stream\r\n\r\n"));
        assert!(as_str.ends_with("--BOUNDARY01234567--\r\n"));

        // The binary body's bytes survive verbatim (they're not in
        // the UTF-8 `as_str` due to the \x01-\x03, so check the
        // raw Vec).
        let body_pos = out
            .windows(body.len())
            .position(|w| w == body)
            .expect("binary body bytes must be present verbatim");
        // The terminator must appear AFTER the body.
        let term_pos = out
            .windows(b"--BOUNDARY01234567--".len())
            .rposition(|w| w == b"--BOUNDARY01234567--")
            .expect("terminator present");
        assert!(
            body_pos < term_pos,
            "body must precede the multipart terminator"
        );
    }

    // ---- List response parser --------------------------------------

    #[test]
    fn parse_list_response_empty() {
        let body = r#"{"files": []}"#;
        let out = parse_list_response(body).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_list_response_with_all_fields() {
        let body = r#"{
            "files": [
                {
                    "id": "F1",
                    "name": "c2r_aaaa_1",
                    "modifiedTime": "2026-05-23T12:34:56.789Z",
                    "size": "1234"
                },
                {
                    "id": "F2",
                    "name": "c2r_aaaa_2",
                    "modifiedTime": "2026-05-23T12:35:01Z",
                    "size": "5678"
                }
            ]
        }"#;
        let out = parse_list_response(body).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "F1");
        assert_eq!(out[0].name, "c2r_aaaa_1");
        assert!(out[0].modified_time.is_some());
        assert_eq!(out[0].size, Some(1234));
        assert_eq!(out[1].size, Some(5678));
    }

    #[test]
    fn parse_list_response_tolerates_missing_optional_fields() {
        // Folder entries omit `size`; some Drive responses also omit
        // `modifiedTime` on synthetic / system files. Parser must
        // not drop these — `id` + `name` are sufficient.
        let body = r#"{
            "files": [
                { "id": "F1", "name": "h_aaaa_0" }
            ]
        }"#;
        let out = parse_list_response(body).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].modified_time, None);
        assert_eq!(out[0].size, None);
    }

    #[test]
    fn parse_list_response_drops_rows_with_empty_id_or_name() {
        // Defensive: if Drive ever returns a partially-filled row,
        // skip it rather than letting the whole batch fail or
        // surfacing an unusable entry to the mux.
        let body = r#"{
            "files": [
                { "id": "", "name": "x" },
                { "id": "F2", "name": "" },
                { "id": "F3", "name": "c2r_aaaa_1" }
            ]
        }"#;
        let out = parse_list_response(body).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "F3");
    }

    #[test]
    fn parse_list_response_tolerates_unparseable_size_and_time() {
        // Lenient on bad individual field values — keep id + name,
        // drop the unparseable fields to None.
        let body = r#"{
            "files": [
                {
                    "id": "F1",
                    "name": "c2r_aaaa_1",
                    "modifiedTime": "garbage",
                    "size": "not-a-number"
                }
            ]
        }"#;
        let out = parse_list_response(body).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].modified_time, None);
        assert_eq!(out[0].size, None);
    }

    #[test]
    fn parse_list_response_rejects_malformed_json() {
        let err = parse_list_response("not json").unwrap_err();
        assert!(matches!(err, DriveApiError::BadResponse(_)));
    }

    #[test]
    fn parse_list_response_empty_object_treated_as_no_files() {
        // Drive returns `{}` for an empty page in some edge cases;
        // `#[serde(default)]` on `files` makes that parse as no
        // entries rather than failing.
        let out = parse_list_response("{}").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ensure_body_within_limit_rejects_oversize_downloads() {
        ensure_body_within_limit("F1", 100, 100).expect("at the limit is allowed");
        let err = ensure_body_within_limit("F1", 101, 100).unwrap_err();
        match err {
            DriveApiError::ResponseTooLarge {
                file_id,
                actual,
                limit,
            } => {
                assert_eq!(file_id, "F1");
                assert_eq!(actual, 101);
                assert_eq!(limit, 100);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ---- Pagination parser (parse_list_response_paged) -------------

    #[test]
    fn parse_list_response_paged_returns_token_when_present() {
        // Drive emits `nextPageToken` only when there are more pages.
        // The paginating loop in `list_files_in_folder` relies on
        // this being surfaced to know whether to continue.
        let body = r#"{
            "nextPageToken": "PAGE2_TOKEN",
            "files": [
                { "id": "F1", "name": "c2r_aaaa_1" },
                { "id": "F2", "name": "c2r_aaaa_2" }
            ]
        }"#;
        let (files, next) = parse_list_response_paged(body).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(next.as_deref(), Some("PAGE2_TOKEN"));
    }

    #[test]
    fn parse_list_response_paged_returns_none_when_absent() {
        // Final page (no more results) has no `nextPageToken` key.
        // The loop terminates here.
        let body = r#"{
            "files": [
                { "id": "F1", "name": "c2r_aaaa_1" }
            ]
        }"#;
        let (files, next) = parse_list_response_paged(body).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(next, None);
    }

    #[test]
    fn parse_list_response_paged_empty_token_terminates_loop() {
        // Some mock implementations and edge-case real responses
        // emit an empty `nextPageToken` string. The caller's loop
        // treats `Some("")` as "no more pages" (via the
        // `Some(t) if !t.is_empty()` guard), so make sure the
        // parser surfaces the value verbatim rather than swallowing
        // it — the termination decision lives in the loop.
        let body = r#"{
            "nextPageToken": "",
            "files": []
        }"#;
        let (files, next) = parse_list_response_paged(body).unwrap();
        assert!(files.is_empty());
        // Empty string is preserved here; the loop guard handles it.
        assert_eq!(next.as_deref(), Some(""));
    }

    #[test]
    fn parse_list_response_paged_handles_empty_response_object() {
        // `{}` is the eventual-final-page shape Drive falls back to
        // when listing a folder with no matching files.
        let (files, next) = parse_list_response_paged("{}").unwrap();
        assert!(files.is_empty());
        assert_eq!(next, None);
    }

    #[test]
    fn parse_list_response_paged_rejects_malformed_json() {
        let err = parse_list_response_paged("{ not json").unwrap_err();
        assert!(matches!(err, DriveApiError::BadResponse(_)));
    }

    // ---- File-create response parser -------------------------------

    #[test]
    fn parse_file_create_response_success() {
        let body = r#"{ "id": "NEWFILE123" }"#;
        let r = parse_file_create_response(body).unwrap();
        assert_eq!(r.id, "NEWFILE123");
    }

    #[test]
    fn parse_file_create_response_rejects_missing_id() {
        let body = r#"{ "id": "" }"#;
        let err = parse_file_create_response(body).unwrap_err();
        assert!(matches!(err, DriveApiError::MissingField("id")));
    }

    #[test]
    fn parse_file_create_response_rejects_malformed_json() {
        let err = parse_file_create_response("{").unwrap_err();
        assert!(matches!(err, DriveApiError::BadResponse(_)));
    }

    // ---- Error-response parser -------------------------------------

    #[test]
    fn parse_error_response_standard_shape() {
        let body = r#"{
            "error": {
                "code": 403,
                "message": "User Rate Limit Exceeded",
                "errors": [
                    { "domain": "usageLimits", "reason": "userRateLimitExceeded", "message": "User Rate Limit Exceeded" }
                ]
            }
        }"#;
        let err = parse_error_response(403, body);
        match err {
            DriveApiError::Endpoint {
                status,
                reason,
                message,
            } => {
                assert_eq!(status, 403);
                assert_eq!(reason.as_deref(), Some("userRateLimitExceeded"));
                assert_eq!(message, "User Rate Limit Exceeded");
            }
            other => panic!("expected Endpoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_response_minimal_shape() {
        // Error body with `error.message` but no `errors` array.
        let body = r#"{ "error": { "code": 401, "message": "Invalid Credentials" } }"#;
        let err = parse_error_response(401, body);
        match err {
            DriveApiError::Endpoint {
                status,
                reason,
                message,
            } => {
                assert_eq!(status, 401);
                assert_eq!(reason, None);
                assert_eq!(message, "Invalid Credentials");
            }
            other => panic!("expected Endpoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_response_falls_back_to_raw_body_on_non_json() {
        // Drive sometimes returns plain-text bodies for proxy / gateway
        // errors (502 from an upstream load balancer, e.g.). Surface
        // the raw text so logs aren't useless.
        let body = "503 Service Unavailable\n";
        let err = parse_error_response(503, body);
        match err {
            DriveApiError::Endpoint {
                status,
                reason,
                message,
            } => {
                assert_eq!(status, 503);
                assert_eq!(reason, None);
                assert!(message.contains("503 Service Unavailable"));
            }
            other => panic!("expected Endpoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_response_keeps_empty_message_distinguishable() {
        // Even when `error.message` is empty, the parser must produce
        // a non-empty `message` so callers logging via `Display` get
        // some signal — fall back to `HTTP {status}`.
        let body = r#"{ "error": { "code": 500, "message": "" } }"#;
        let err = parse_error_response(500, body);
        match err {
            DriveApiError::Endpoint { message, .. } => assert_eq!(message, "HTTP 500"),
            other => panic!("expected Endpoint, got {other:?}"),
        }
    }

    // ---- Client construction ---------------------------------------

    /// `reqwest::Client::new()` panics with "No provider set" under
    /// our `rustls-no-provider` feature pin (see Cargo.toml comment).
    /// Tests that need an http client construct it via the public
    /// `build_drive_http_client` helper, which installs the `ring`
    /// provider on first call (and is idempotent on subsequent
    /// calls).
    fn http_for_tests() -> reqwest::Client {
        build_drive_http_client(None).expect("client build")
    }

    #[test]
    fn drive_api_client_strips_trailing_slash() {
        // Ensure base_url is always normalised so concatenation with
        // `/drive/v3/files` produces exactly one separator.
        let client = DriveApiClient::new(http_for_tests(), "https://example.com/".into());
        assert_eq!(client.base_url(), "https://example.com");
    }

    #[test]
    fn drive_api_client_with_default_base_url_uses_env_override() {
        // `with_default_base_url` reads the env var at construction.
        // std::env is process-global; the harness runs tests in
        // parallel by default, but the env var is restored before
        // returning so other tests' subsequent reads see the prior
        // value.
        const MARKER: &str = "https://wiremock-marker.example/test";
        let prev = std::env::var(DRIVE_API_BASE_ENV).ok();
        // SAFETY: `std::env::set_var` is `unsafe` on edition 2024
        // (potential UB if other threads read concurrently). Cargo
        // test runs lib-tests in a thread pool, but no other test
        // in this crate reads `DRIVE_API_BASE_ENV` — the surface
        // is one constant accessed only here.
        unsafe {
            std::env::set_var(DRIVE_API_BASE_ENV, MARKER);
        }
        let client = DriveApiClient::with_default_base_url(http_for_tests());
        assert_eq!(client.base_url(), MARKER);
        // SAFETY: see comment above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(DRIVE_API_BASE_ENV, v),
                None => std::env::remove_var(DRIVE_API_BASE_ENV),
            }
        }
    }

    #[test]
    fn build_drive_http_client_with_no_google_ip_succeeds() {
        // Smoke: the no-IP path is the desktop default; constructing
        // a client without an IP override must not panic on the
        // `rustls-no-provider` install step.
        let _client = build_drive_http_client(None).expect("client build");
    }

    #[test]
    fn build_drive_http_client_with_garbage_google_ip_still_returns_client() {
        // A hand-edited config with a malformed `google_ip` falls
        // back to the system DNS (with a warning log) — we still
        // get a usable client back, so the Drive transport doesn't
        // hard-fail on a typo. The config validator is the right
        // place to reject this at load time.
        let _client = build_drive_http_client(Some("not-an-ip")).expect("client build");
    }

    #[test]
    fn build_drive_http_client_with_valid_google_ip_succeeds() {
        // Smoke: the resolver override path with a real-looking IP
        // produces a usable client. We don't actually connect, so
        // any routable-shaped IP works.
        let _client = build_drive_http_client(Some("216.239.38.120")).expect("client build");
    }
}
