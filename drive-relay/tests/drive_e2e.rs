//! End-to-end Drive-mode wire-compatibility test.
//!
//! Spawns the relay (`rahgozar_drive_relay::run`) + a client
//! [`DriveMux`] (`rahgozar::drive_client::DriveMux::start`) against
//! a wiremock-based stateful mock of the Drive REST + OAuth token
//! endpoints. The client opens a [`tunnel_connection`] aimed at a
//! local echo TCP server. The test writes bytes through the client
//! side and asserts the echo response arrives byte-identical.
//!
//! Every wire decision is exercised:
//!   - Combined c2r_<sid>_0 upload: unsealed 64-byte Hello prefix +
//!     AEAD-sealed Connect batch. Relay strips, decodes, derives keys.
//!   - c2r AEAD seal (client) + AEAD open (relay).
//!   - r2c AEAD seal (relay) + AEAD open (client).
//!   - Filename grammar (`c2r_<sid>_<seq>`, `r2c_<sid>_<seq>`).
//!   - Numeric sort fix for Drive's lex-ordered list.
//!   - Replay window monotonicity (every frame's seq is checked).
//!   - Frame-kind dispatch (Connect → dial; Data → forward; EOF as
//!     half-close; Close → tear down).
//!
//! ## Wiremock store
//!
//! [`MockDriveStore`] is the single source of truth: every
//! `files.create` adds an entry; `files.list` queries by parent +
//! name prefix; `files.get?alt=media` returns the raw bytes; DELETE
//! removes. State lives behind `std::sync::Mutex` (wiremock's
//! `Respond` is sync — we can't `.await` while serving a request).
//!
//! ## Endpoint redirection
//!
//! Two env vars (`RAHGOZAR_DRIVE_API_BASE` from slice 4 and
//! `RAHGOZAR_OAUTH_TOKEN_ENDPOINT` from this slice) point the
//! production code at the mock server's loopback HTTP URL. The
//! mock serves both Drive REST paths and the OAuth `/token`
//! endpoint from the same `MockServer`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use rahgozar::config::Config;
use rahgozar::drive_api::DRIVE_API_BASE_ENV;
use rahgozar::drive_client::{tunnel_connection_with_preface, DriveMux};
use rahgozar::drive_oauth::TOKEN_ENDPOINT_ENV;
use rahgozar_drive_relay::config::RelayConfig;
use rahgozar_drive_relay::keygen_to_file;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// =====================================================================
// Mock Drive store
// =====================================================================

/// One stored file. Mirrors the subset of Drive's file metadata
/// rahgozar actually reads (id + name + parent + body + modified
/// time). `mime_type` is preserved but unused.
struct MockFile {
    name: String,
    parent: String,
    body: Bytes,
    modified_time: OffsetDateTime,
}

/// In-memory mock of the Drive folder. Each entry is keyed by a
/// monotonic synthetic file ID; the production code stores the IDs
/// (not the names) once a file has been listed/created.
#[derive(Default)]
struct MockDriveStore {
    files: HashMap<String, MockFile>,
    next_id: u64,
    /// Counter for assertions in the test body — useful for "did
    /// the relay actually delete files it consumed?" sanity checks.
    deletes_observed: u64,
}

impl MockDriveStore {
    fn insert(&mut self, name: String, parent: String, body: Bytes) -> String {
        let id = format!("mock-file-{:08}", self.next_id);
        self.next_id += 1;
        self.files.insert(
            id.clone(),
            MockFile {
                name,
                parent,
                body,
                modified_time: OffsetDateTime::now_utc(),
            },
        );
        id
    }

    /// Files matching a (parent, optional name-prefix) pair. Equivalent to
    /// Drive's `q = "'<parent>' in parents and name contains
    /// '<prefix>' and trashed = false"` for protocol polls, or
    /// `q = "'<parent>' in parents and trashed = false"` for setup-time
    /// folder checks. The prefix is always at the start of the name in
    /// production, so `contains` and `starts_with` behave the same here.
    fn list_by_prefix(&self, parent: &str, prefix: &str) -> Vec<(String, &MockFile)> {
        self.files
            .iter()
            .filter(|(_, f)| f.parent == parent && f.name.starts_with(prefix))
            .map(|(id, f)| (id.clone(), f))
            .collect()
    }
}

// =====================================================================
// Responders
// =====================================================================

/// OAuth `/token` endpoint. Returns a long-lived fake access token;
/// the production [`TokenCache`] caches it for ~1 hour, so even a
/// long-running test only hits this once.
struct OAuthTokenResponder;

impl Respond for OAuthTokenResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "https://www.googleapis.com/auth/drive.file",
        }))
    }
}

/// `POST /upload/drive/v3/files?uploadType=multipart`.
///
/// Parses the `multipart/related` body, extracts the JSON metadata
/// (for `name` + `parents[0]`) and the binary part, stores both,
/// returns `{"id": "<new_id>"}`. Any parse failure surfaces as a
/// 400 with a message — easier to debug than a silent ignore.
struct DriveUploadResponder {
    store: Arc<Mutex<MockDriveStore>>,
}

impl Respond for DriveUploadResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let content_type = request
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let boundary = match parse_multipart_boundary(content_type) {
            Some(b) => b,
            None => {
                return ResponseTemplate::new(400)
                    .set_body_string("missing or unparseable multipart boundary");
            }
        };
        let (metadata, body) = match parse_multipart_drive_upload(&request.body, &boundary) {
            Some(parts) => parts,
            None => {
                return ResponseTemplate::new(400)
                    .set_body_string("could not parse multipart body shape");
            }
        };
        let name = metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let parent = metadata
            .get("parents")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() || parent.is_empty() {
            return ResponseTemplate::new(400)
                .set_body_string("metadata missing name or parents[0]");
        }
        let id = self.store.lock().unwrap().insert(name, parent, body);
        ResponseTemplate::new(200).set_body_json(json!({ "id": id }))
    }
}

/// `GET /drive/v3/files?q=...&fields=...`.
///
/// Parses the `q` parameter using a thin pattern matcher (we know
/// the exact shapes rahgozar's `drive_api::build_list_query` emits),
/// returns the matching files. The response shape mirrors what
/// `drive_api::parse_list_response` expects.
struct DriveListResponder {
    store: Arc<Mutex<MockDriveStore>>,
}

impl Respond for DriveListResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let query_pairs: HashMap<String, String> = request
            .url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let q = query_pairs.get("q").cloned().unwrap_or_default();
        let (parent, prefix) = match parse_drive_list_query(&q) {
            Some(t) => t,
            None => {
                return ResponseTemplate::new(400).set_body_string(format!(
                    "could not parse 'q' parameter (expected canonical Drive \
                     list query shape): got {q}"
                ));
            }
        };
        let store = self.store.lock().unwrap();
        let matches = store.list_by_prefix(&parent, &prefix);
        let files: Vec<serde_json::Value> = matches
            .into_iter()
            .map(|(id, f)| {
                json!({
                    "id": id,
                    "name": f.name.clone(),
                    "modifiedTime": f
                        .modified_time
                        .format(&Rfc3339)
                        .unwrap_or_default(),
                    "size": f.body.len().to_string(),
                })
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({ "files": files }))
    }
}

/// `GET /drive/v3/files/<id>?alt=media`.
///
/// Returns the raw body bytes; the path-regex matcher already
/// narrowed to a valid `/drive/v3/files/<id>` shape so we just
/// extract the trailing segment as the file ID.
struct DriveGetResponder {
    store: Arc<Mutex<MockDriveStore>>,
}

impl Respond for DriveGetResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let id = match request.url.path().rsplit('/').next() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => {
                return ResponseTemplate::new(400).set_body_string("missing file id");
            }
        };
        let store = self.store.lock().unwrap();
        match store.files.get(&id) {
            Some(f) => ResponseTemplate::new(200).set_body_bytes(f.body.to_vec()),
            None => ResponseTemplate::new(404).set_body_string(format!(
                r#"{{"error":{{"code":404,"message":"file not found: {id}"}}}}"#
            )),
        }
    }
}

/// `DELETE /drive/v3/files/<id>`.
///
/// Returns 204 on success (matches Drive's actual contract).
/// rahgozar treats a 404-on-delete as success too (idempotent reap),
/// so a slow test where the file already got swept doesn't fail.
struct DriveDeleteResponder {
    store: Arc<Mutex<MockDriveStore>>,
}

impl Respond for DriveDeleteResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let id = match request.url.path().rsplit('/').next() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => {
                return ResponseTemplate::new(400).set_body_string("missing file id");
            }
        };
        let mut store = self.store.lock().unwrap();
        match store.files.remove(&id) {
            Some(_) => {
                store.deletes_observed += 1;
                ResponseTemplate::new(204)
            }
            None => ResponseTemplate::new(404).set_body_string("not found"),
        }
    }
}

// =====================================================================
// Multipart + Drive query parsing helpers
// =====================================================================

/// Extract the `boundary=...` value from a multipart/related
/// Content-Type header. Drive uploads always carry the boundary
/// inline (per `drive_api::upload_file`).
fn parse_multipart_boundary(content_type: &str) -> Option<String> {
    for piece in content_type.split(';') {
        let p = piece.trim();
        if let Some(b) = p.strip_prefix("boundary=") {
            return Some(b.trim_matches('"').to_string());
        }
    }
    None
}

/// Hand-rolled parser for the exact two-part multipart shape
/// `drive_api::build_multipart_related_body` emits. Looks for the
/// JSON metadata part first, then the binary body part; returns
/// both. Tolerant on minor formatting variation (different
/// whitespace inside Content-Type lines) but assumes the two-part
/// structure.
fn parse_multipart_drive_upload(body: &[u8], boundary: &str) -> Option<(serde_json::Value, Bytes)> {
    let part_separator_first = format!("--{}\r\n", boundary);
    let part_separator_mid = format!("\r\n--{}\r\n", boundary);
    let part_terminator = format!("\r\n--{}--", boundary);
    let header_body_sep = b"\r\n\r\n";

    // Strip the leading `--BOUNDARY\r\n` if present.
    let after_leading = if body.starts_with(part_separator_first.as_bytes()) {
        &body[part_separator_first.len()..]
    } else {
        body
    };

    // Part 1: skip headers, capture body up to the mid-separator.
    let hb1 = find_subsequence(after_leading, header_body_sep)?;
    let part1_body_start = hb1 + header_body_sep.len();
    let mid = find_subsequence_from(
        after_leading,
        part_separator_mid.as_bytes(),
        part1_body_start,
    )?;
    let metadata_bytes = &after_leading[part1_body_start..mid];
    let metadata: serde_json::Value = serde_json::from_slice(metadata_bytes).ok()?;

    // Part 2: skip headers (after the mid-separator + `\r\n--BOUNDARY\r\n`),
    // capture body up to the terminator.
    let after_mid = mid + part_separator_mid.len();
    let hb2 = find_subsequence_from(after_leading, header_body_sep, after_mid)?;
    let part2_body_start = hb2 + header_body_sep.len();
    let term = find_subsequence_from(after_leading, part_terminator.as_bytes(), part2_body_start)?;
    let body_bytes = Bytes::copy_from_slice(&after_leading[part2_body_start..term]);

    Some((metadata, body_bytes))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_subsequence_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// Parse the canonical `q` shapes:
/// `'<folder>' in parents and name contains '<prefix>' and trashed = false`
/// or `'<folder>' in parents and trashed = false`.
/// Returns (folder, prefix). An empty prefix means "all files in this
/// folder". Returns `None` on any divergence so a future change to
/// `drive_api::build_list_query` doesn't silently mismatch.
fn parse_drive_list_query(q: &str) -> Option<(String, String)> {
    // Pattern: `'X' in parents [and name contains 'Y'] and trashed = false`
    let rest = q.strip_prefix('\'')?;
    let (folder, rest) = rest.split_once("' in parents")?;
    let rest = rest.trim_start();
    let (prefix, rest) = if let Some(rest) = rest.strip_prefix("and name contains '") {
        let (prefix, rest) = rest.split_once('\'')?;
        (prefix.to_string(), rest.trim_start())
    } else {
        (String::new(), rest)
    };
    if !rest.starts_with("and trashed") {
        return None;
    }
    Some((folder.to_string(), prefix))
}

#[test]
fn parse_drive_list_query_accepts_prefix_filter() {
    assert_eq!(
        parse_drive_list_query(
            "'folder-1' in parents and name contains 'c2r_' and trashed = false"
        ),
        Some(("folder-1".to_string(), "c2r_".to_string()))
    );
}

#[test]
fn parse_drive_list_query_accepts_parent_only_filter() {
    assert_eq!(
        parse_drive_list_query("'folder-1' in parents and trashed = false"),
        Some(("folder-1".to_string(), String::new()))
    );
}

// =====================================================================
// Echo TCP server
// =====================================================================

/// Bind a TCP listener on `127.0.0.1:0`, accept any number of
/// connections, and echo bytes back verbatim. Returns the bound
/// port. The listener task is leaked — the runtime drops it when
/// the test ends.
async fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo: bind 127.0.0.1:0");
    let port = listener.local_addr().expect("echo: local_addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4 * 1024];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

// =====================================================================
// Loopback TcpStream pair for tunnel_connection
// =====================================================================

/// Create a pair of connected `TcpStream`s on loopback. Used as the
/// "browser ↔ proxy" socket — one side is handed to
/// `tunnel_connection` (playing the role of the post-CONNECT
/// socket); the other is the test's I/O handle for writing input
/// bytes and reading back the echoed response.
async fn loopback_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("pair: bind 127.0.0.1:0");
    let port = listener.local_addr().expect("pair: local_addr").port();
    let connect_fut = TcpStream::connect(("127.0.0.1", port));
    let accept_fut = listener.accept();
    let (a, b) = tokio::join!(connect_fut, accept_fut);
    let client_side = a.expect("pair: connect");
    let (server_side, _) = b.expect("pair: accept");
    let _ = client_side.set_nodelay(true);
    let _ = server_side.set_nodelay(true);
    (client_side, server_side)
}

// =====================================================================
// Wiremock setup helper
// =====================================================================

/// Build the mock Drive HTTP server with all five endpoint
/// responders mounted, sharing one [`MockDriveStore`].
async fn spawn_mock_drive() -> (MockServer, Arc<Mutex<MockDriveStore>>) {
    let server = MockServer::start().await;
    let store = Arc::new(Mutex::new(MockDriveStore::default()));

    // OAuth `/token` — used by `refresh_access_token` on relay
    // startup and by the client's TokenCache on first access.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(OAuthTokenResponder)
        .mount(&server)
        .await;

    // Drive: upload / list / get-by-id / delete-by-id.
    Mock::given(method("POST"))
        .and(path("/upload/drive/v3/files"))
        .respond_with(DriveUploadResponder {
            store: store.clone(),
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .respond_with(DriveListResponder {
            store: store.clone(),
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/drive/v3/files/[^/]+$"))
        .respond_with(DriveGetResponder {
            store: store.clone(),
        })
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/drive/v3/files/[^/]+$"))
        .respond_with(DriveDeleteResponder {
            store: store.clone(),
        })
        .mount(&server)
        .await;

    (server, store)
}

// =====================================================================
// Test
// =====================================================================

/// One CONNECT through Drive mode, hitting a local echo server.
///
/// Walks the full pipeline end-to-end:
///   1. Mock Drive + OAuth set up on loopback HTTP.
///   2. Relay spawned with its keypair, polling the mock folder.
///   3. Client `DriveMux` polling the same folder.
///   4. `tunnel_connection` opens a session toward
///      `127.0.0.1:<echo_port>` via Drive.
///   5. Test writes "hello world" through the client side.
///   6. Echo server bounces it back.
///   7. Test reads "hello world" back through the client side.
///   8. Assert byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_round_trip_through_mock_drive_and_echo() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // 1. Mock Drive HTTP server.
    let (mock_drive, store) = spawn_mock_drive().await;
    let mock_uri = mock_drive.uri();

    // 2. Point production code at the mock. Both env vars are read
    //    inside `DriveApiClient::with_default_base_url` /
    //    `drive_oauth::token_endpoint` per-call, so setting them
    //    here before spawning the relay + building the client
    //    suffices.
    //
    //    SAFETY: `std::env::set_var` is `unsafe` on edition 2024
    //    (potential UB if other threads read concurrently). This
    //    test is a dedicated integration binary so no other test
    //    runs in the same process; the env vars are only ever
    //    read by code we control here.
    unsafe {
        std::env::set_var(DRIVE_API_BASE_ENV, &mock_uri);
        std::env::set_var(TOKEN_ENDPOINT_ENV, format!("{}/token", mock_uri));
    }

    // 3. Echo TCP server. The relay will dial this on Connect.
    let echo_port = spawn_echo_server().await;

    // 4. Mint the relay's X25519 keypair to a tempdir. The bech32m
    //    pubkey is what the client's config carries.
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let key_path = tmpdir.path().join("relay.key");
    let relay_pubkey_bech32 = keygen_to_file(&key_path).expect("keygen");

    // 5. Spawn the relay. Same shape as the systemd unit: load
    //    config, do startup OAuth refresh, run forever (poll +
    //    orphan reaper). Use a device-code-flavoured fake OAuth
    //    client here and a different desktop-flavoured fake below to
    //    pin the documented "different client types, same Cloud
    //    project/app" topology. The mock Drive server intentionally
    //    does not enforce Google's drive.file app scoping; the docs
    //    call out that real deployments must keep both clients in
    //    the same Cloud project / consent screen.
    let relay_cfg = RelayConfig {
        oauth_client_id: "test-device-client.apps.googleusercontent.com".into(),
        oauth_client_secret: "test-device-client-secret".into(),
        oauth_refresh_token: "fake-refresh-token-for-test".into(),
        folder_id: "TEST_FOLDER".into(),
        x25519_secret_key_path: key_path.clone(),
        // Fast polling so the test doesn't sit on baseline 300 ms
        // sleeps for every round-trip step.
        poll_interval_ms: 50,
        max_concurrent_dials: 4,
        idle_timeout_secs: 60,
        // The echo server below runs on 127.0.0.1; the SSRF guard in
        // `destination_allowed` default-denies internal IP literals,
        // so opt the loopback IP into the allowlist for this test.
        // Production operators never need this — Drive Mode targets
        // real internet destinations.
        allow_destinations: vec!["127.0.0.1".into()],
        metrics_bind: None,
    };
    let relay_handle = tokio::spawn(async move { rahgozar_drive_relay::run(relay_cfg).await });

    // Brief warm-up so the startup OAuth refresh + first poll
    // cycle land before we kick off the client.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. Build the client's Config. Minimal — Drive mode only
    //    consults `drive.*`, `google_ip`, and (indirectly via
    //    DriveMux) the listen host/port for the local proxy
    //    bind, but we don't actually bind the proxy here; we
    //    only build the DriveMux directly.
    let client_cfg_json = format!(
        r#"{{
            "mode": "drive",
            "auth_key": "",
            "google_ip": "",
            "front_domain": "www.google.com",
            "listen_host": "127.0.0.1",
            "listen_port": 9999,
            "drive": {{
                "oauth_client_id": "test-desktop-client.apps.googleusercontent.com",
                "oauth_client_secret": "test-desktop-client-secret",
                "oauth_refresh_token": "fake-refresh-token-for-test",
                "folder_id": "TEST_FOLDER",
                "relay_pubkey": "{}",
                "poll_interval_ms": 50,
                "max_concurrent_uploads": 4
            }}
        }}"#,
        relay_pubkey_bech32
    );
    let client_cfg: Config = serde_json::from_str(&client_cfg_json).expect("client cfg parse");
    let mux = DriveMux::start(&client_cfg).await.expect("mux start");

    // 7. Loopback TCP pair playing browser ↔ proxy.
    let (mut browser_side, proxy_side) = loopback_tcp_pair().await;

    // 8. Spawn the per-session driver (`tunnel_connection` runs on
    //    the dispatcher's call frame in production — same shape
    //    here).
    let mux_for_session = mux.clone();
    let prefaced_payload = Bytes::from_static(b"prefaced hello through drive");
    let prefaced_len = prefaced_payload.len();
    let session = tokio::spawn(async move {
        tunnel_connection_with_preface(
            proxy_side,
            "127.0.0.1",
            echo_port,
            &mux_for_session,
            prefaced_payload,
        )
        .await
    });

    let mut got_prefaced = vec![0u8; prefaced_len];
    tokio::time::timeout(
        Duration::from_secs(15),
        browser_side.read_exact(&mut got_prefaced),
    )
    .await
    .expect("read_exact timed out for prefaced payload")
    .expect("read_exact failed for prefaced payload");
    assert_eq!(
        got_prefaced, b"prefaced hello through drive",
        "prefaced payload should be echoed before live socket reads"
    );

    // 9. Write a payload through the tunnel. The session's
    //    pump_session loop reads from `proxy_side` and seals +
    //    uploads c2r frames; the relay polls, decrypts, dials
    //    the echo server, writes; echo writes back; relay polls
    //    the destination TcpStream, seals + uploads r2c frames;
    //    client polls + writes back to `proxy_side` → we read
    //    from `browser_side`.
    let payload = b"hello world, via the drive mailbox";
    browser_side
        .write_all(payload)
        .await
        .expect("write payload");
    browser_side
        .shutdown()
        .await
        .expect("half-close browser write side");

    // 10. Read back after a local write-side half-close. This pins
    //     EOF semantics: the client must upload Eof without an
    //     immediate Close so the relay can still return the echoed
    //     response. Generous timeout — Drive polling adds round-trips
    //     that take 5-6 cycles at 50 ms each + AEAD ops + mock HTTP
    //     serving.
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(15), browser_side.read_exact(&mut got))
        .await
        .expect("read_exact timed out — Drive transport stalled?")
        .expect("read_exact failed");
    assert_eq!(
        got, payload,
        "echo response should be byte-identical to the input"
    );

    // 11. Sanity check the mock saw activity. We don't pin exact
    //     counts (the relay's orphan reaper + per-frame cleanup
    //     deletes vary by timing), but at least one delete + at
    //     least one file should have been processed.
    {
        let s = store.lock().unwrap();
        assert!(
            s.deletes_observed >= 1,
            "expected at least one Drive delete during the round-trip; got {}",
            s.deletes_observed
        );
        // Files in store after the round-trip: at most a few in
        // flight (Eof + Close uploaded by the client on local
        // EOF below, before the relay or its reaper consumes
        // them). Don't pin the count — too timing-dependent.
        // The leak risk is bounded by the orphan reaper anyway.
        let _ = s.files.len();
    }

    // 12. Drop the local side cleanly. The write half was already
    //     closed above; once the echo server returns its EOF, both
    //     directions complete and `tunnel_connection` returns Ok.
    drop(browser_side);
    let session_result = tokio::time::timeout(Duration::from_secs(5), session)
        .await
        .expect("session task didn't exit after local close")
        .expect("session task panicked");
    session_result.expect("session task returned Err");

    // 13. Cleanup: abort the relay. Its `run()` is a forever-loop
    //     unless interrupted; aborting drops the SessionTable +
    //     poller + orphan-reaper handles.
    relay_handle.abort();

    // 14. Undo the env-var override so a subsequent test run in
    //     the same `cargo test` invocation (extremely unlikely
    //     for an integration test, but defensive) starts clean.
    //     SAFETY: same justification as the set_var above.
    unsafe {
        std::env::remove_var(DRIVE_API_BASE_ENV);
        std::env::remove_var(TOKEN_ENDPOINT_ENV);
    }
}
