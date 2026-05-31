//! Poison-safe DNS resolution over a camouflaged DoH connection.
//!
//! `force_ip` fronting (see `proxy_server::do_sni_rewrite_tunnel_from_tcp`)
//! dials the destination's *own* IP. In Iran the system resolver is
//! DNS-poisoned for exactly the hosts we care about (Instagram, Meta,
//! googlevideo), so we cannot trust it to find the real IP. patterniha's
//! Xray config solves this by routing DNS through a DoH endpoint reached
//! over a camouflaged TLS connection (their `tls-repack-dns` outbound →
//! 1.1.1.1 with SNI `www.microsoft.com`). This module is the rahgozar
//! port: a tiny JSON-DoH client whose own TLS handshake is camouflaged
//! via [`crate::camouflage`], so the lookups themselves aren't blockable
//! by SNI DPI.
//!
//! Safety note: a wrong (poisoned) answer can never cause a downgrade,
//! because the `force_ip` dial still verifies the destination's real
//! certificate (`CamouflageVerifier`). The worst a bad DNS answer can do
//! is make a connection fail to handshake. That's why the optional
//! system-DNS fallback is safe to enable.
//!
//! JSON DoH (RFC 8484 has a wire format too, but the JSON API —
//! `application/dns-json` — is far simpler to parse and supported by both
//! Cloudflare `/dns-query` and Google `/resolve`).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures_util::future::select_ok;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// Cloudflare's anycast resolver — reachable from most Iranian ISPs and
/// serves the JSON DoH API at `/dns-query`.
pub const DEFAULT_RESOLVER_IP: &str = "1.1.1.1";
pub const DEFAULT_RESOLVER_HOST: &str = "cloudflare-dns.com";
/// Camouflage SNI put on the wire for the DoH handshake. A benign,
/// universally-allow-listed Microsoft host — matches patterniha's choice.
pub const DEFAULT_CAMOUFLAGE_SNI: &str = "www.microsoft.com";

/// Per-query wall-clock budget (connect + handshake + request + read).
const QUERY_TIMEOUT: Duration = Duration::from_secs(6);
/// Cache TTL clamps. Real RRs carry their own TTL; we bound it so a
/// 5-second TTL doesn't hammer the resolver and a multi-day TTL doesn't
/// pin us to an edge IP that rotated.
const MIN_TTL: Duration = Duration::from_secs(60);
const MAX_TTL: Duration = Duration::from_secs(3600);
const DEFAULT_TTL: Duration = Duration::from_secs(300);
/// TTL for results that came from the system-DNS fallback (DoH was
/// unreachable). Short on purpose: long enough to avoid paying the full
/// `QUERY_TIMEOUT` on every CONNECT while DoH is down, short enough that
/// a possibly-poisoned system answer self-heals quickly once DoH
/// recovers. (A poisoned answer fails the downstream cert check anyway —
/// see the module safety note — so this only bounds the retry cadence.)
const FALLBACK_TTL: Duration = Duration::from_secs(30);
/// TTL for a *negative* cache entry (empty IP set). Without it, a host
/// whose DoH query keeps failing (resolver blocked / down) would pay the
/// full `QUERY_TIMEOUT` on every matching force_ip CONNECT before falling
/// through. Short so the host recovers quickly once DoH is reachable
/// again.
const NEG_TTL: Duration = Duration::from_secs(30);
/// Hard cap on a DoH response body we'll buffer. Cloudflare's JSON
/// answers are a few hundred bytes; this just bounds a misbehaving /
/// hostile responder from making us allocate without limit.
const MAX_DOH_RESP: u64 = 64 * 1024;

struct CacheEntry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

/// A single DoH endpoint: a (resolver IP, host, decoy/real SNI, JSON
/// path) tuple with its own verifier-bound connector.
struct DohEndpoint {
    connector: TlsConnector,
    /// SNI sent on the wire — a decoy for the camouflaged Cloudflare
    /// endpoints, the real `dns.google` for the Google one.
    server_name: ServerName<'static>,
    /// IP literal to TCP-connect to.
    resolver_ip: String,
    /// HTTP `Host` header (the resolver's real name).
    resolver_host: String,
    /// JSON DoH path: `/dns-query` (Cloudflare) or `/resolve` (Google).
    path: &'static str,
}

impl DohEndpoint {
    fn new(
        resolver_ip: &str,
        resolver_host: &str,
        sni: &str,
        verify_names: &[String],
        path: &'static str,
    ) -> Result<Self, String> {
        // No ALPN: DoH is a plain HTTP/1.1 GET, and we read to EOF.
        let connector = crate::camouflage::build_camouflage_connector(verify_names)?;
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| format!("invalid sni '{}': {}", sni, e))?;
        Ok(Self {
            connector,
            server_name,
            resolver_ip: resolver_ip.to_string(),
            resolver_host: resolver_host.to_string(),
            path,
        })
    }

    /// One DoH lookup against this endpoint. Fires A and AAAA
    /// concurrently, merges A-first, returns the minimum TTL. Returns
    /// `Err` when the A query fails OR no address records came back, so
    /// the `select_ok` race in `DohResolver::resolve` skips this endpoint
    /// and takes a healthy one.
    async fn query(&self, host: &str) -> std::io::Result<(Vec<IpAddr>, Duration)> {
        let (a_res, aaaa_res) =
            tokio::join!(self.query_one(host, "A"), self.query_one(host, "AAAA"));

        let mut min_ttl: Option<u64> = None;
        let mut ips: Vec<IpAddr> = Vec::new();
        let (a_ips, a_ttl) = a_res?;
        if let Some(t) = a_ttl {
            min_ttl = Some(min_ttl.map_or(t, |m| m.min(t)));
        }
        ips.extend(a_ips);
        if let Ok((aaaa_ips, aaaa_ttl)) = aaaa_res {
            if let Some(t) = aaaa_ttl {
                min_ttl = Some(min_ttl.map_or(t, |m| m.min(t)));
            }
            ips.extend(aaaa_ips);
        }

        let ips = stable_dedup(ips);
        if ips.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address records",
            ));
        }
        let ttl = min_ttl.map(Duration::from_secs).unwrap_or(DEFAULT_TTL);
        Ok((ips, ttl))
    }

    async fn query_one(
        &self,
        host: &str,
        qtype: &str,
    ) -> std::io::Result<(Vec<IpAddr>, Option<u64>)> {
        let tcp = TcpStream::connect((self.resolver_ip.as_str(), 443)).await?;
        let _ = tcp.set_nodelay(true);
        let mut tls = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| std::io::Error::other(format!("DoH TLS handshake failed: {}", e)))?;

        let req = format!(
            "GET {path}?name={host}&type={qtype} HTTP/1.1\r\n\
             Host: {hostname}\r\n\
             accept: application/dns-json\r\n\
             user-agent: rahgozar-doh\r\n\
             connection: close\r\n\r\n",
            path = self.path,
            host = host,
            qtype = qtype,
            hostname = self.resolver_host,
        );
        tls.write_all(req.as_bytes()).await?;
        tls.flush().await?;

        // Bounded read: `Connection: close` means read-to-EOF, but cap
        // it so a hostile/broken responder can't make us buffer without
        // limit.
        let mut buf = Vec::with_capacity(2048);
        (&mut tls).take(MAX_DOH_RESP).read_to_end(&mut buf).await?;
        if !response_status_ok(&buf) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DoH response was not 2xx",
            ));
        }
        let body = http_response_body(&buf).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed DoH HTTP response",
            )
        })?;
        parse_dns_json(&body)
    }
}

/// A JSON-DoH resolver that races several endpoints and caches results.
pub struct DohResolver {
    /// Tried concurrently per lookup; the first healthy answer wins.
    endpoints: Vec<DohEndpoint>,
    /// Fall back to the system resolver when every DoH endpoint is
    /// unreachable. Safe because the downstream `force_ip` dial still
    /// verifies the real certificate; a poisoned fallback answer fails
    /// the handshake, it can't MITM. Off for the force_ip routing path
    /// (see `proxy_server`), on only where a caller opts in.
    fallback_system_dns: bool,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl DohResolver {
    /// Default endpoint set, raced per lookup:
    ///   * Cloudflare `1.1.1.1` and `1.0.0.1` — camouflaged (decoy SNI
    ///     `www.microsoft.com`), cert verified against Cloudflare's real
    ///     names. Two anycast IPs so one degraded path doesn't sink DoH
    ///     (matches patterniha's `dns.redirect` = `[1.1.1.1, 1.0.0.1]`).
    ///   * Google `dns.google` (`8.8.8.8`) — its *real* SNI (no
    ///     camouflage: dialing `8.8.8.8` with a decoy SNI returns the
    ///     wrong cert). Provider diversity; if `dns.google` is SNI-blocked
    ///     the Cloudflare paths carry the lookup, and Google reachability
    ///     is rahgozar's core assumption so when it's up it's a fast,
    ///     independent fallback.
    pub fn with_default_resolvers(fallback_system_dns: bool) -> Result<Self, String> {
        let cf_verify = [
            "cloudflare-dns.com".to_string(),
            "one.one.one.one".to_string(),
        ];
        let endpoints = vec![
            DohEndpoint::new(
                DEFAULT_RESOLVER_IP,
                DEFAULT_RESOLVER_HOST,
                DEFAULT_CAMOUFLAGE_SNI,
                &cf_verify,
                "/dns-query",
            )?,
            DohEndpoint::new(
                "1.0.0.1",
                DEFAULT_RESOLVER_HOST,
                DEFAULT_CAMOUFLAGE_SNI,
                &cf_verify,
                "/dns-query",
            )?,
            DohEndpoint::new(
                "8.8.8.8",
                "dns.google",
                "dns.google",
                &["dns.google".to_string()],
                "/resolve",
            )?,
        ];
        Ok(Self {
            endpoints,
            fallback_system_dns,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Resolve `host` to one or more IPs. Returns cached results when
    /// fresh; otherwise races every endpoint (first healthy answer wins)
    /// and, on total failure, the system resolver if `fallback_system_dns`
    /// is set.
    pub async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if key.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty host",
            ));
        }
        // A literal IP needs no resolution.
        if let Ok(ip) = key.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // Reject anything that isn't a plain DNS name before it reaches
        // the request line. `key` is interpolated into
        // `GET /dns-query?name=<key>` — a CONNECT target like
        // `evil\r\nFoo: bar.googlevideo.com` can suffix-match a
        // configured force_ip domain (the matcher only checks the
        // suffix) and would otherwise smuggle headers / query params
        // into the resolver request. Whitelist the DNS charset; the
        // caller falls through to normal routing on the error.
        if !is_plain_dns_name(&key) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("not a plain DNS name: {:?}", key),
            ));
        }

        {
            let cache = self.cache.lock().await;
            if let Some(e) = cache.get(&key) {
                if Instant::now() < e.expires {
                    if e.ips.is_empty() {
                        // Negative cache hit — fail fast so the caller
                        // falls through without paying the query timeout.
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("DoH negative-cached miss for '{}'", key),
                        ));
                    }
                    return Ok(e.ips.clone());
                }
            }
        }

        // Race every endpoint; the first healthy (non-empty) answer wins
        // and cancels the rest. `select_ok` skips endpoints that error
        // (blocked IP, wrong cert, NODATA — `query` returns `Err` on an
        // empty answer) and only resolves to `Err` when they all fail, so
        // a single blocked Cloudflare IP doesn't sink the lookup.
        let attempts: Vec<_> = self
            .endpoints
            .iter()
            .map(|e| Box::pin(e.query(&key)))
            .collect();
        // Bind to a local so the `select_ok` result (which carries the
        // not-yet-resolved leftover futures, each borrowing `key`) is
        // dropped before `key` at end of scope rather than after it.
        let raced = tokio::time::timeout(QUERY_TIMEOUT, select_ok(attempts)).await;
        match raced {
            Ok(Ok(((ips, ttl), _rest))) => {
                self.cache_insert(&key, &ips, ttl.clamp(MIN_TTL, MAX_TTL))
                    .await;
                Ok(ips)
            }
            outcome => {
                match &outcome {
                    Ok(Err(e)) => {
                        tracing::debug!("DoH resolve for '{}' failed on all endpoints: {}", key, e)
                    }
                    Err(_) => tracing::debug!("DoH resolve for '{}' timed out", key),
                    _ => {}
                }
                if self.fallback_system_dns {
                    tracing::debug!("DoH miss for '{}', falling back to system DNS", key);
                    match system_resolve(&key).await {
                        Ok(ips) => {
                            // Cache the fallback briefly so a sustained DoH
                            // outage doesn't pay the full timeout each time.
                            self.cache_insert(&key, &ips, FALLBACK_TTL).await;
                            return Ok(ips);
                        }
                        Err(e) => {
                            tracing::debug!("system DNS fallback for '{}' failed: {}", key, e);
                            // fall through to negative-cache + error
                        }
                    }
                }
                // Negative-cache the miss so repeated CONNECTs to this
                // host fall through immediately instead of re-timing-out.
                self.cache_insert(&key, &[], NEG_TTL).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("DoH could not resolve '{}'", key),
                ))
            }
        }
    }

    async fn cache_insert(&self, key: &str, ips: &[IpAddr], ttl: Duration) {
        self.cache.lock().await.insert(
            key.to_string(),
            CacheEntry {
                ips: ips.to_vec(),
                expires: Instant::now() + ttl,
            },
        );
    }
}

/// Resolve via the OS resolver. Last-resort fallback; see the safety note
/// in [`DohResolver`].
async fn system_resolve(host: &str) -> std::io::Result<Vec<IpAddr>> {
    let mut ips: Vec<IpAddr> = tokio::net::lookup_host((host, 443))
        .await?
        .map(|sa| sa.ip())
        .collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("system DNS returned no records for '{}'", host),
        ));
    }
    Ok(ips)
}

/// Extract the HTTP body from a full `Connection: close` response,
/// decoding `Transfer-Encoding: chunked` if present. Returns `None` on a
/// response with no header terminator.
fn http_response_body(resp: &[u8]) -> Option<Vec<u8>> {
    let sep = find_subslice(resp, b"\r\n\r\n")?;
    let header_block = &resp[..sep];
    let body = &resp[sep + 4..];
    let chunked = header_is_chunked(header_block);
    if chunked {
        decode_chunked(body)
    } else {
        Some(body.to_vec())
    }
}

fn header_is_chunked(header_block: &[u8]) -> bool {
    // Case-insensitive scan for a `Transfer-Encoding: chunked` line. The
    // header block is tiny (a DoH response), so a lowercase copy is fine.
    let lower = header_block.to_ascii_lowercase();
    find_subslice(&lower, b"transfer-encoding:").is_some()
        && find_subslice(&lower, b"chunked").is_some()
}

/// Minimal HTTP/1.1 chunked-body decoder. Tolerant: stops cleanly at the
/// zero-length terminating chunk or at end of input.
fn decode_chunked(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    loop {
        let line_end = find_subslice(body, b"\r\n")?;
        let size_str = std::str::from_utf8(&body[..line_end]).ok()?.trim();
        // Chunk-size may carry extensions after a ';'; ignore them.
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        let data_start = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        let data_end = data_start.checked_add(size)?;
        if data_end > body.len() {
            return None;
        }
        out.extend_from_slice(&body[data_start..data_end]);
        // Skip the trailing CRLF after the chunk data.
        let next = data_end.checked_add(2)?;
        if next > body.len() {
            return Some(out);
        }
        body = &body[next..];
    }
}

/// Parse a Cloudflare/Google `application/dns-json` body into IPs + the
/// minimum answer TTL. Answer types: 1 = A, 28 = AAAA. Other types
/// (CNAME=5 etc.) are skipped — the resolver chases CNAMEs and still
/// returns A/AAAA in the same `Answer` array.
fn parse_dns_json(body: &[u8]) -> std::io::Result<(Vec<IpAddr>, Option<u64>)> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("DoH JSON parse: {}", e),
        )
    })?;
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut min_ttl: Option<u64> = None;
    if let Some(answers) = v.get("Answer").and_then(|a| a.as_array()) {
        for ans in answers {
            let typ = ans.get("type").and_then(|t| t.as_u64());
            if !matches!(typ, Some(1) | Some(28)) {
                continue;
            }
            if let Some(data) = ans.get("data").and_then(|d| d.as_str()) {
                if let Ok(ip) = data.trim().parse::<IpAddr>() {
                    ips.push(ip);
                    if let Some(ttl) = ans.get("TTL").and_then(|t| t.as_u64()) {
                        min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
                    }
                }
            }
        }
    }
    Ok((ips, min_ttl))
}

/// True for a syntactically plausible DNS name: 1..=253 chars, every
/// char in the LDH set plus `_` (some real RRs use it) and `.`. This is
/// a *safety* filter for the request line, not full RFC-1035 validation
/// — it just guarantees the name carries no characters that could break
/// out of the `?name=` parameter (CR, LF, space, `?`, `&`, `#`, `/`,
/// NUL). Input is already lowercased + trailing-dot trimmed by the
/// caller.
fn is_plain_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Dedup preserving first-seen order (unlike `Vec::dedup`, which only
/// collapses *adjacent* duplicates and which we'd otherwise have to sort
/// for — destroying the resolver's edge ordering).
fn stable_dedup(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen: HashSet<IpAddr> = HashSet::new();
    ips.into_iter().filter(|ip| seen.insert(*ip)).collect()
}

/// True if the HTTP status line reports a 2xx code. Guards against
/// treating a 4xx/5xx error page (or a captive-portal redirect) as a
/// DoH answer.
fn response_status_ok(resp: &[u8]) -> bool {
    let line_end = find_subslice(resp, b"\r\n").unwrap_or(resp.len());
    let line = &resp[..line_end];
    // Expect `HTTP/1.x <code> ...`; the code is the 2nd space-delimited
    // token.
    let mut parts = line.split(|&b| b == b' ');
    let _http = parts.next();
    match parts.next() {
        Some(code) => matches!(code, [b'2', _, _]),
        None => false,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cloudflare_a_records() {
        let body = br#"{"Status":0,"Answer":[
            {"name":"x.com","type":5,"TTL":100,"data":"cdn.x.com."},
            {"name":"cdn.x.com","type":1,"TTL":42,"data":"1.2.3.4"},
            {"name":"cdn.x.com","type":1,"TTL":99,"data":"5.6.7.8"}
        ]}"#;
        let (ips, ttl) = parse_dns_json(body).unwrap();
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse().unwrap()));
        assert_eq!(ttl, Some(42)); // minimum across A records
    }

    #[test]
    fn parses_aaaa_records() {
        let body = br#"{"Answer":[{"type":28,"TTL":300,"data":"2606:4700::1111"}]}"#;
        let (ips, _) = parse_dns_json(body).unwrap();
        assert_eq!(ips, vec!["2606:4700::1111".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn empty_answer_yields_no_ips() {
        let (ips, ttl) = parse_dns_json(br#"{"Status":3,"Answer":[]}"#).unwrap();
        assert!(ips.is_empty());
        assert!(ttl.is_none());
    }

    #[test]
    fn extracts_body_content_length_style() {
        let resp =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(http_response_body(resp).unwrap(), b"{}");
    }

    #[test]
    fn extracts_body_chunked() {
        // Two chunks "{}" then "[]" then terminator.
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n2\r\n[]\r\n0\r\n\r\n";
        assert_eq!(http_response_body(resp).unwrap(), b"{}[]");
    }

    #[test]
    fn missing_header_terminator_is_none() {
        assert!(http_response_body(b"HTTP/1.1 200 OK\r\nNo terminator").is_none());
    }

    #[test]
    fn dns_name_validation_rejects_injection() {
        assert!(is_plain_dns_name("r1---sn-aigl6n7e.googlevideo.com"));
        assert!(is_plain_dns_name("www.instagram.com"));
        assert!(is_plain_dns_name("1.2.3.4")); // harmless even though IPs short-circuit earlier
                                               // CRLF / header smuggling, query-param breakout, spaces, NUL.
        assert!(!is_plain_dns_name("evil\r\nhost: x.googlevideo.com"));
        assert!(!is_plain_dns_name("a&type=A&name=evil.com"));
        assert!(!is_plain_dns_name("a b.googlevideo.com"));
        assert!(!is_plain_dns_name("a\u{0}.com"));
        assert!(!is_plain_dns_name(""));
        assert!(!is_plain_dns_name(&"a".repeat(254)));
    }

    #[tokio::test]
    async fn resolve_rejects_non_dns_name_without_network() {
        // A suffix-matching-but-malformed CONNECT target must error
        // (→ dispatcher falls through) and never reach the resolver.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let r = DohResolver::with_default_resolvers(false).unwrap();
        let got = r.resolve("evil\r\nfoo: bar.googlevideo.com").await;
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn ip_literal_resolves_without_network() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let r = DohResolver::with_default_resolvers(false).unwrap();
        assert_eq!(
            r.resolve("1.2.3.4").await.unwrap(),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn stable_dedup_preserves_first_seen_order() {
        let v: Vec<IpAddr> = ["3.3.3.3", "1.1.1.1", "3.3.3.3", "2.2.2.2", "1.1.1.1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let got = stable_dedup(v);
        let want: Vec<IpAddr> = ["3.3.3.3", "1.1.1.1", "2.2.2.2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn status_line_validation() {
        assert!(response_status_ok(b"HTTP/1.1 200 OK\r\n\r\n{}"));
        assert!(response_status_ok(b"HTTP/2 204 No Content\r\n\r\n"));
        assert!(!response_status_ok(b"HTTP/1.1 404 Not Found\r\n\r\n"));
        assert!(!response_status_ok(b"HTTP/1.1 500 err\r\n\r\n"));
        assert!(!response_status_ok(b"garbage"));
    }

    #[tokio::test]
    async fn negative_cache_entry_fails_fast() {
        // An empty cache entry (negative) must short-circuit resolve to
        // an error so the dispatcher falls through — without any network.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let r = DohResolver::with_default_resolvers(false).unwrap();
        r.cache_insert("blocked.example", &[], Duration::from_secs(30))
            .await;
        assert!(r.resolve("blocked.example").await.is_err());
    }

    #[tokio::test]
    async fn fresh_cache_entry_is_served_without_query() {
        // `resolve` checks the cache before any network I/O, so a fresh
        // entry is returned verbatim — this pins the cache-read path
        // (incl. the fallback-cache path, which uses the same insert)
        // without needing a reachable resolver.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let r = DohResolver::with_default_resolvers(false).unwrap();
        let ips = vec!["93.184.216.34".parse::<IpAddr>().unwrap()];
        r.cache_insert("example.com", &ips, Duration::from_secs(300))
            .await;
        assert_eq!(r.resolve("example.com").await.unwrap(), ips);
    }
}
