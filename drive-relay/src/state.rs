//! Shared runtime state for the relay's poll loop, per-session
//! driver tasks, and orphan reaper.
//!
//! The poll loop, the orphan reaper, and every per-session driver
//! task all hold an `Arc<RelayState>`. The state itself contains
//! `Arc`s for the heavy pieces (drive-api client, token cache,
//! session table), so cloning the outer `Arc<RelayState>` into a
//! task spawn is one refcount bump.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use drive_wire::frame::{FrameKind, SessionId, WireFrame};
use rahgozar::drive_api::DriveApiClient;
use rahgozar::drive_crypto::{ReplayWindow, SessionKeys};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};

use crate::config::RelayConfig;
use crate::token::TokenCache;

/// State shared across the poll loop, the per-session driver
/// tasks, and the orphan reaper. Every long-lived task owns one
/// `Arc<RelayState>`.
pub struct RelayState {
    pub cfg: Arc<RelayConfig>,
    /// The relay's long-lived X25519 secret. Loaded once at
    /// startup; immutable after. Used by [`crate::poll`] when a
    /// new Hello arrives.
    pub relay_secret: Arc<rahgozar::drive_crypto::RelaySecret>,
    /// Drive REST client. Cheap to clone; the inner `reqwest::Client`
    /// is Arc-internal already.
    pub drive_api: DriveApiClient,
    /// Cached OAuth access token with proactive refresh.
    pub token_cache: Arc<TokenCache>,
    /// All currently-active sessions, keyed by `sid`. Read-locked
    /// for lookups (hot path: every inbound c2r frame); write-locked
    /// for insert/remove (cold path: new Hellos + closes).
    pub sessions: Arc<RwLock<HashMap<SessionId, SessionHandle>>>,
    /// Global cap on simultaneous outbound TCP connect attempts.
    /// The poll loop may accept many Connect frames in one burst; this
    /// semaphore keeps those dials from exhausting the VPS's ephemeral
    /// ports or file-descriptor budget.
    pub dial_permits: Arc<Semaphore>,
}

impl RelayState {
    pub fn new(
        cfg: Arc<RelayConfig>,
        relay_secret: Arc<rahgozar::drive_crypto::RelaySecret>,
        drive_api: DriveApiClient,
        token_cache: Arc<TokenCache>,
    ) -> Self {
        let dial_cap = std::cmp::max(1, cfg.max_concurrent_dials as usize);
        Self {
            cfg,
            relay_secret,
            drive_api,
            token_cache,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            dial_permits: Arc::new(Semaphore::new(dial_cap)),
        }
    }
}

/// Handle to one in-flight session. Lives in the
/// `RelayState::sessions` map; the per-session driver task owns the
/// `mpsc::Receiver` half of `inbound_tx`. Dropping the handle
/// (during shutdown / orphan-reaper removal) closes the channel
/// and signals the driver task to exit.
pub struct SessionHandle {
    /// Derived directional AEAD keys + sid. `Arc` because the poll
    /// worker needs to open inbound c2r frames (k_c2r) while the
    /// driver task simultaneously seals outbound r2c frames
    /// (k_r2c). Keys are immutable after `relay_accept`.
    pub keys: Arc<SessionKeys>,
    /// Inbound replay tracker for `c2r_*` frames. Mutated by the
    /// poll worker on every inbound frame (rejecting duplicates +
    /// out-of-order). Worker holds the lock briefly; driver task
    /// does not touch this field.
    pub replay: Arc<Mutex<ReplayWindow>>,
    /// Channel the poll worker uses to hand off opened+verified
    /// inbound events to the per-session driver task.
    pub inbound_tx: mpsc::Sender<InboundFrame>,
    /// Most-recent activity timestamp (inbound OR outbound).
    /// Mutated by the poll worker (on inbound) and by the driver
    /// task (on outbound). The orphan reaper reads this to decide
    /// whether to evict an idle session.
    pub last_seen: Arc<Mutex<Instant>>,
    /// Driver task handle. Aborted on shutdown / orphan eviction;
    /// also checked via `is_finished()` so the reaper can remove
    /// naturally-exited sessions promptly.
    pub task: tokio::task::JoinHandle<()>,
}

/// Mailbox shape between the poll worker (decoder) and the
/// per-session driver task (executor). Crucially, the AEAD-opened
/// wire frame is converted to this enum INSIDE the poll worker, so
/// the driver task never sees ciphertext — it just executes
/// already-validated semantic events.
#[derive(Debug)]
pub enum InboundFrame {
    /// First non-Hello frame; payload carried `host:port` (or
    /// `[ipv6]:port`). Driver task dials the destination and only
    /// then starts accepting `Data`.
    Connect { host: String, port: u16 },
    /// Application data — write verbatim to the dialed TcpStream.
    Data(Bytes),
    /// Half-close (writer-side EOF). Driver shuts down the TCP
    /// write half but keeps reading for any r2c traffic still in
    /// flight.
    Eof,
    /// Full close. Driver shuts down the TCP stream and exits.
    Close,
}

/// Parse a `host:port` or `[ipv6]:port` address string out of a
/// `Connect` frame's payload.
///
/// Strict: rejects empty host, rejects port = 0, rejects malformed
/// shapes. The driver task surfaces parse failures by uploading an
/// `Error` frame back to the client; if we accepted garbage here
/// we'd panic deep inside `TcpStream::connect`'s resolver instead.
pub fn parse_connect_addr(s: &str) -> Result<(String, u16), ConnectAddrError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ConnectAddrError::Empty);
    }
    let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal: `[2001:db8::1]:443`. Split on `]:` so
        // colons inside the address don't trip us up.
        let (h, p) = rest
            .split_once("]:")
            .ok_or_else(|| ConnectAddrError::Malformed(s.to_string()))?;
        (h, p)
    } else {
        // Hostname or IPv4: split on the LAST `:` so a hostname
        // never confuses the split (DNS labels can't contain `:`).
        s.rsplit_once(':')
            .ok_or_else(|| ConnectAddrError::Malformed(s.to_string()))?
    };
    if host.is_empty() {
        return Err(ConnectAddrError::Empty);
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| ConnectAddrError::BadPort(port_str.to_string()))?;
    if port == 0 {
        return Err(ConnectAddrError::BadPort(port_str.to_string()));
    }
    Ok((host.to_string(), port))
}

/// True iff the IP address points at the relay's own network: loopback,
/// link-local (incl. cloud-metadata 169.254.169.254), private RFC1918,
/// IPv6 unique-local, or the unspecified address. The session-side
/// destination guard rejects Connect frames targeting these to prevent
/// the relay being used as an SSRF pivot into the VPS internal network.
/// Hostname targets that DNS-resolve to internal IPs need check-at-
/// dial-time which is more invasive; the IP-literal cut catches the
/// obvious attack surface for a few lines of code.
///
/// Operators who legitimately want to dial internal IPs (e.g. relay
/// running on a corporate VPN exit node) can opt in by adding the
/// specific IP to `allow_destinations` — the allowlist is the final
/// say and bypasses this guard.
pub fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // CGNAT / shared address space (RFC 6598) — also used
                // for AWS/GCP internal NAT. Not flagged by std's
                // `is_private`, hence the explicit cut.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Link-local fe80::/10. `Ipv6Addr::is_unicast_link_local`
                // is unstable; check the prefix manually.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // Unique-local fc00::/7.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // IPv4-mapped: route the check through the embedded v4.
                || v6
                    .to_ipv4_mapped()
                    .map(|v4| is_internal_ip(&std::net::IpAddr::V4(v4)))
                    .unwrap_or(false)
        }
    }
}

/// Translate an AEAD-opened, verified [`WireFrame`] into the
/// semantic [`InboundFrame`] the per-session driver task consumes.
/// Pure function — no I/O — so the conversion logic is testable
/// without spinning up a session.
///
/// Returns `Err` if the wire frame's `kind` isn't valid for the
/// `c2r` direction (e.g. a Hello showing up on the frame channel
/// when Hellos use their own filename prefix).
pub fn frame_to_inbound(frame: WireFrame) -> Result<InboundFrame, FrameDispatchError> {
    match frame.kind {
        FrameKind::Connect => {
            let addr_str = std::str::from_utf8(&frame.payload)
                .map_err(|_| FrameDispatchError::ConnectPayloadNotUtf8)?;
            let (host, port) =
                parse_connect_addr(addr_str).map_err(FrameDispatchError::ConnectAddr)?;
            Ok(InboundFrame::Connect { host, port })
        }
        FrameKind::Data => Ok(InboundFrame::Data(frame.payload)),
        FrameKind::Eof => Ok(InboundFrame::Eof),
        FrameKind::Close => Ok(InboundFrame::Close),
        FrameKind::Error => {
            // Treat client-side errors as a close request — the
            // remote peer is signalling something's wrong on their
            // end and they don't want more bytes. Log first so the
            // operator can debug.
            let reason = String::from_utf8_lossy(&frame.payload).into_owned();
            tracing::warn!("session received Error frame from client: {}", reason);
            Ok(InboundFrame::Close)
        }
        FrameKind::Hello => Err(FrameDispatchError::HelloOnFrameChannel),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectAddrError {
    #[error("connect address is empty")]
    Empty,
    #[error("connect address is malformed: {0:?}")]
    Malformed(String),
    #[error("connect port {0:?} is not a valid u16 > 0")]
    BadPort(String),
}

#[derive(Debug, thiserror::Error)]
pub enum FrameDispatchError {
    #[error("Connect frame payload is not valid UTF-8")]
    ConnectPayloadNotUtf8,
    #[error("Connect frame addr error: {0}")]
    ConnectAddr(#[source] ConnectAddrError),
    #[error("Hello frame received on c2r_ frame channel (Hellos use h_ prefix)")]
    HelloOnFrameChannel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use drive_wire::frame::WIRE_VERSION;

    fn frame(kind: FrameKind, payload: &[u8]) -> WireFrame {
        WireFrame {
            version: WIRE_VERSION,
            kind,
            sid: [0u8; 16],
            seq: 0,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    // ---- parse_connect_addr ----------------------------------------

    #[test]
    fn parse_connect_addr_hostname_port() {
        assert_eq!(
            parse_connect_addr("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn parse_connect_addr_ipv4_port() {
        assert_eq!(
            parse_connect_addr("8.8.8.8:53").unwrap(),
            ("8.8.8.8".to_string(), 53)
        );
    }

    #[test]
    fn parse_connect_addr_ipv6_bracketed() {
        // Bracketed IPv6: colons inside the address must NOT confuse
        // the split — that's what the `[...]:port` shape exists for.
        assert_eq!(
            parse_connect_addr("[2001:db8::1]:8443").unwrap(),
            ("2001:db8::1".to_string(), 8443)
        );
    }

    #[test]
    fn parse_connect_addr_hostname_with_dashes() {
        assert_eq!(
            parse_connect_addr("api-v2.example.com:80").unwrap(),
            ("api-v2.example.com".to_string(), 80)
        );
    }

    #[test]
    fn parse_connect_addr_trims_whitespace() {
        // Defensive: payload comes from the wire, could carry a
        // trailing newline from a sloppy client implementation.
        assert_eq!(
            parse_connect_addr("  example.com:443\n").unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn parse_connect_addr_rejects_empty() {
        assert_eq!(parse_connect_addr(""), Err(ConnectAddrError::Empty));
        assert_eq!(parse_connect_addr("   "), Err(ConnectAddrError::Empty));
    }

    #[test]
    fn parse_connect_addr_rejects_no_port() {
        // No colon at all → malformed.
        assert!(matches!(
            parse_connect_addr("example.com"),
            Err(ConnectAddrError::Malformed(_))
        ));
    }

    #[test]
    fn parse_connect_addr_rejects_empty_host() {
        assert!(matches!(
            parse_connect_addr(":443"),
            Err(ConnectAddrError::Empty)
        ));
        // Empty host inside IPv6 brackets.
        assert!(matches!(
            parse_connect_addr("[]:443"),
            Err(ConnectAddrError::Empty)
        ));
    }

    #[test]
    fn parse_connect_addr_rejects_bad_port() {
        // Non-numeric.
        assert!(matches!(
            parse_connect_addr("example.com:notaport"),
            Err(ConnectAddrError::BadPort(_))
        ));
        // Port = 0 is a special-meaning "any-port" placeholder; we
        // reject it because a CONNECT to port 0 cannot actually
        // succeed.
        assert!(matches!(
            parse_connect_addr("example.com:0"),
            Err(ConnectAddrError::BadPort(_))
        ));
        // Port > u16::MAX overflows the parse.
        assert!(matches!(
            parse_connect_addr("example.com:99999"),
            Err(ConnectAddrError::BadPort(_))
        ));
    }

    #[test]
    fn parse_connect_addr_rejects_malformed_ipv6() {
        // Opening bracket but no closing `]:` separator.
        assert!(matches!(
            parse_connect_addr("[2001:db8::1:443"),
            Err(ConnectAddrError::Malformed(_))
        ));
    }

    // SSRF guard for internal-IP Connect targets lives in
    // session::destination_allowed so it composes with the operator's
    // `allow_destinations` allowlist (an operator who legitimately
    // wants to dial e.g. 10.0.0.5:80 can opt in by listing the IP).
    // Coverage is in session.rs's tests.

    // ---- frame_to_inbound ------------------------------------------

    #[test]
    fn frame_to_inbound_connect() {
        let f = frame(FrameKind::Connect, b"example.com:443");
        match frame_to_inbound(f).unwrap() {
            InboundFrame::Connect { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn frame_to_inbound_data_preserves_bytes() {
        let payload = b"\x00\x01\x02hello\xff\xfe";
        let f = frame(FrameKind::Data, payload);
        match frame_to_inbound(f).unwrap() {
            InboundFrame::Data(bytes) => assert_eq!(&bytes[..], payload),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn frame_to_inbound_eof_and_close_have_empty_payload() {
        for kind in [FrameKind::Eof, FrameKind::Close] {
            let f = frame(kind, b"");
            assert!(matches!(
                frame_to_inbound(f).unwrap(),
                InboundFrame::Eof | InboundFrame::Close
            ));
        }
    }

    #[test]
    fn frame_to_inbound_error_maps_to_close() {
        // Client-side Error → relay treats as Close (and logs the
        // reason). This matches the doc comment + lets the driver
        // task's normal Close path do the cleanup.
        let f = frame(FrameKind::Error, b"client gave up");
        assert!(matches!(frame_to_inbound(f).unwrap(), InboundFrame::Close));
    }

    #[test]
    fn frame_to_inbound_hello_on_frame_channel_is_error() {
        // Hellos travel on the `h_` filename prefix, not `c2r_`.
        // A Hello arriving here means the client uploaded under
        // the wrong prefix — surface as an error rather than
        // silently accepting (which would skip the relay_accept
        // key-derivation step).
        let f = frame(FrameKind::Hello, b"");
        assert!(matches!(
            frame_to_inbound(f),
            Err(FrameDispatchError::HelloOnFrameChannel)
        ));
    }

    #[test]
    fn frame_to_inbound_connect_rejects_non_utf8_payload() {
        // Random binary in a Connect payload is a protocol violation.
        let f = frame(FrameKind::Connect, &[0xff, 0xfe, 0xfd]);
        assert!(matches!(
            frame_to_inbound(f),
            Err(FrameDispatchError::ConnectPayloadNotUtf8)
        ));
    }

    #[test]
    fn frame_to_inbound_connect_propagates_addr_error() {
        let f = frame(FrameKind::Connect, b"no-port-here");
        match frame_to_inbound(f) {
            Err(FrameDispatchError::ConnectAddr(_)) => {}
            other => panic!("expected ConnectAddr error, got {other:?}"),
        }
    }
}
