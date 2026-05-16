//! Detect bot-block / anti-bot responses from CDNs that flag traffic
//! originating from Google datacenter IPs (Apps Script's outbound IP
//! space).
//!
//! Two CDNs are responsible for the bulk of "site doesn't load through
//! rahgozar" reports:
//!
//! - **Cloudflare** — serves Turnstile / `Just a moment...` / hard 403
//!   on requests from non-residential IP ranges (GCP/AWS/Azure
//!   datacenters). Pattern documented in `assets/exit_node/README.md`.
//! - **Akamai** — serves the "Access Denied" error page (linking to
//!   `errors.edgesuite.net`, `Server: AkamaiGHost`) on the same
//!   heuristic. unity.com is the canonical example.
//!
//! The fix is always the same: route the host through `exit_node.hosts`
//! so the destination sees an exit-node IP. This module surfaces the
//! hint at log-level WARN once per host per process, so a user reading
//! their own log can self-diagnose without filing a ticket.
//!
//! Hooked into the relay path at exactly one point —
//! `domain_fronter::DomainFronter::relay_uncoalesced` — so every
//! Apps Script response that returns bytes to a caller is scanned.
//! The exit-node short-circuit upstream of `relay_uncoalesced` skips
//! detection on intentionally-routed-around hosts, which is the
//! correct behaviour: a CF challenge through the user's own exit node
//! is a different problem class and shouldn't be conflated with the
//! Apps-Script-outbound block heuristic.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

/// Best-effort detection of a bot-block / anti-bot response body.
/// Returns the CDN name when a known signature is found.
///
/// Inspects only the first 16 KiB of the raw HTTP/1.x response
/// (status + headers + body prefix). CDN block pages put the
/// giveaways within the first few hundred bytes — Akamai's
/// `errors.edgesuite.net` link is in the `<title>` area; Cloudflare's
/// `cf-mitigated` header sits at the top of the response head. The
/// bounded scan keeps this cheap enough to call on every relayed
/// response.
pub fn detect(response: &[u8]) -> Option<&'static str> {
    let prefix_len = response.len().min(16 * 1024);
    let prefix = &response[..prefix_len];

    // Akamai. Most-specific signal first: `errors.edgesuite.net` is
    // the host Akamai uses in its "Access Denied" body, so its
    // presence is itself a strong block indicator regardless of
    // status. The `AkamaiGHost` Server header alone is NOT — every
    // Akamai-fronted response (200s, 30x redirects, ordinary 4xx
    // errors) sets it. Gate that signal on a deny-like status code so
    // a legit Akamai site flowing through the relay doesn't trigger
    // a false-positive hint.
    if contains_ascii_ci(prefix, b"errors.edgesuite.net") {
        return Some("Akamai");
    }
    if contains_ascii_ci(prefix, b"AkamaiGHost") {
        if let Some(code) = parse_status_code(prefix) {
            if is_deny_status(code) {
                return Some("Akamai");
            }
        }
    }

    // Cloudflare's anti-bot path. Each of these markers is specific
    // to a CF mitigation response (cf-mitigated header on hard
    // blocks + interactive challenges; the canonical "Just a
    // moment..." body; the `__cf_chl_` challenge JS variable; the
    // `/cdn-cgi/challenge-platform/` script path). They don't appear
    // in legitimate content, so no status gate is needed.
    if contains_ascii_ci(prefix, b"cf-mitigated:")
        || contains_ascii_ci(prefix, b"Just a moment...")
        || contains_ascii_ci(prefix, b"__cf_chl_")
        || contains_ascii_ci(prefix, b"challenge-platform")
    {
        return Some("Cloudflare");
    }

    None
}

/// Parse the HTTP status code from the start of the response buffer.
/// Returns `None` if the buffer doesn't start with a recognisable
/// `HTTP/1.x NNN ` status line — defensive against the rare malformed
/// upstream and against being called on a body fragment.
fn parse_status_code(response: &[u8]) -> Option<u16> {
    let line_end = response.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let first_line = &response[..line_end];
    // "HTTP/1.x NNN <reason>" — the status code sits between the
    // first and second spaces.
    let after_version = first_line.split(|&b| b == b' ').nth(1)?;
    std::str::from_utf8(after_version).ok()?.parse().ok()
}

/// Status codes Akamai (and most CDN bot-detection layers) use for
/// outright denials: Unauthorized, Forbidden, Too Many Requests,
/// Unavailable For Legal Reasons, Service Unavailable. 5xx-other and
/// 30x deliberately excluded — those are operational responses, not
/// access decisions.
fn is_deny_status(code: u16) -> bool {
    matches!(code, 401 | 403 | 429 | 451 | 503)
}

/// Dedupe-and-log: emit a WARN hint at most once per `host` per
/// process. A single page load typically triggers many sub-requests
/// (HTML, favicon, analytics) all hitting the same block — without
/// deduplication the log would be unreadable.
pub fn note_if_blocked(host: &str, response: &[u8]) {
    let Some(cdn) = detect(response) else {
        return;
    };
    let host = normalize_host(host);
    if !mark_first_seen(seen_set(), &host) {
        return;
    }
    tracing::warn!(
        "{} responded with a {} bot-block — add \"{}\" to exit_node.hosts \
         in config.json to route via your exit node \
         (see assets/exit_node/README.md)",
        host,
        cdn,
        host,
    );
}

/// Lowercase + strip the trailing FQDN dot. The dispatcher elsewhere
/// in the codebase normalises hosts the same way; without this,
/// `example.com` and `example.com.` would warn separately.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Returns `true` iff `host` was newly inserted (i.e. this is the
/// first time we've seen it). Split out from `note_if_blocked` so
/// tests can drive the dedupe logic against a private set rather than
/// the process-wide global.
fn mark_first_seen(set: &Mutex<HashSet<String>>, host: &str) -> bool {
    set.lock().unwrap().insert(host.to_string())
}

fn seen_set() -> &'static Mutex<HashSet<String>> {
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashSet::new()))
}

fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_akamai_access_denied_body() {
        let body = b"HTTP/1.1 403 Forbidden\r\n\
                     Server: AkamaiGHost\r\n\
                     Content-Type: text/html\r\n\r\n\
                     <html><head><title>Access Denied</title></head>\
                     <body>You don't have permission to access ... \
                     Reference #18.910f3417.1778431182.c1e32223 \
                     https://errors.edgesuite.net/...</body></html>";
        assert_eq!(detect(body), Some("Akamai"));
    }

    #[test]
    fn detects_akamai_via_server_header_when_status_is_deny() {
        // Some Akamai-protected origins return a customised body but
        // keep the Server header — when status is a deny code,
        // AkamaiGHost is enough.
        let body = b"HTTP/1.1 403 Forbidden\r\n\
                     Server: AkamaiGHost\r\n\r\n\
                     <html>custom error page</html>";
        assert_eq!(detect(body), Some("Akamai"));
    }

    #[test]
    fn ignores_akamai_server_header_on_200_ok() {
        // Every Akamai-fronted response carries `Server: AkamaiGHost`
        // — including legitimate 200s. The detector must not warn
        // on those, or every Akamai-fronted site relayed through
        // rahgozar would log a spurious hint.
        let body = b"HTTP/1.1 200 OK\r\n\
                     Server: AkamaiGHost\r\n\
                     Content-Type: text/html\r\n\r\n\
                     <html><body>normal page body</body></html>";
        assert_eq!(detect(body), None);
    }

    #[test]
    fn ignores_akamai_server_header_on_redirect() {
        // 302/301/etc. are operational responses, not block decisions.
        let body = b"HTTP/1.1 302 Found\r\n\
                     Server: AkamaiGHost\r\n\
                     Location: https://example.com/new\r\n\r\n";
        assert_eq!(detect(body), None);
    }

    #[test]
    fn ignores_akamai_server_header_on_404() {
        // 404 isn't a deny — it's "this resource doesn't exist."
        // Akamai serves these too without involving bot-detection.
        let body = b"HTTP/1.1 404 Not Found\r\n\
                     Server: AkamaiGHost\r\n\r\n\
                     <html>page not found</html>";
        assert_eq!(detect(body), None);
    }

    #[test]
    fn detects_akamai_edgesuite_body_regardless_of_status() {
        // The errors.edgesuite.net link is specific to Akamai's
        // standard block page, so its presence alone is enough even
        // if the upstream didn't set a status the detector recognises
        // as a deny code (some Akamai configs surface their block
        // page through a 200 wrapper).
        let body = b"HTTP/1.1 200 OK\r\n\r\n\
                     <html><head><title>Access Denied</title></head>\
                     <body>Reference https://errors.edgesuite.net/...</body></html>";
        assert_eq!(detect(body), Some("Akamai"));
    }

    #[test]
    fn detects_cloudflare_just_a_moment() {
        let body = b"HTTP/1.1 403 Forbidden\r\n\
                     Server: cloudflare\r\n\
                     cf-mitigated: challenge\r\n\r\n\
                     <html><body>Just a moment...</body></html>";
        assert_eq!(detect(body), Some("Cloudflare"));
    }

    #[test]
    fn detects_cloudflare_via_body_only() {
        let body = b"HTTP/1.1 200 OK\r\n\r\n\
                     <html><body>\
                     <script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1\">\
                     </script></body></html>";
        assert_eq!(detect(body), Some("Cloudflare"));
    }

    #[test]
    fn ignores_normal_html() {
        let body = b"HTTP/1.1 200 OK\r\n\r\n<html><body>hello world</body></html>";
        assert_eq!(detect(body), None);
    }

    #[test]
    fn ignores_unrelated_403() {
        let body = b"HTTP/1.1 403 Forbidden\r\n\
                     Server: nginx\r\n\r\n\
                     <html>your IP is rate limited</html>";
        assert_eq!(detect(body), None);
    }

    #[test]
    fn case_insensitive_match() {
        let body = b"HTTP/1.1 403\r\nServer: akamaighost\r\n\r\n";
        assert_eq!(detect(body), Some("Akamai"));
    }

    #[test]
    fn normalize_host_strips_trailing_dot_and_lowercases() {
        assert_eq!(normalize_host("Example.COM."), "example.com");
        assert_eq!(normalize_host("unity.com"), "unity.com");
        assert_eq!(normalize_host("Unity.Com"), "unity.com");
        // Double trailing dot is degenerate but shouldn't blow up.
        assert_eq!(normalize_host("example.com.."), "example.com");
    }

    #[test]
    fn mark_first_seen_dedupes_within_a_set() {
        let set = Mutex::new(HashSet::new());
        assert!(mark_first_seen(&set, "a.example"));
        assert!(!mark_first_seen(&set, "a.example"));
        assert!(mark_first_seen(&set, "b.example"));
        assert!(!mark_first_seen(&set, "b.example"));
    }

    #[test]
    fn mark_first_seen_distinguishes_after_normalize() {
        // The public path always normalizes before inserting, so
        // tests exercise the same pre-normalised keys to mirror the
        // production contract.
        let set = Mutex::new(HashSet::new());
        assert!(mark_first_seen(&set, &normalize_host("UNITY.com.")));
        assert!(!mark_first_seen(&set, &normalize_host("unity.com")));
    }
}
