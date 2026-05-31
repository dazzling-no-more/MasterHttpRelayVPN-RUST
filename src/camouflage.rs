//! Camouflage-SNI TLS: dial with a benign `serverName` on the wire but
//! verify the peer certificate against the *real* destination name(s).
//!
//! This is the [`verifyPeerCertByName`] primitive from
//! patterniha/MITM-DomainFronting (Xray), ported to rustls. The ISP's
//! DPI sees a ClientHello whose SNI is a harmless allow-listed host
//! (e.g. `www.microsoft.com` / `www.google.com`) and lets it pass; the
//! TCP connection, however, goes to the *real* destination IP (resolved
//! out-of-band via [`crate::doh`]), which returns its own real
//! certificate (e.g. `*.facebook.com`). Standard rustls verification
//! would reject that — the cert doesn't match the SNI we sent. The
//! [`CamouflageVerifier`] instead checks the chain against a fixed
//! allow-list of the destination's real names, so a genuine
//! ISP-DNS-poisoned IP (which can't present a valid cert for the real
//! host) still fails closed.
//!
//! Why this is safe even with the spoofed SNI: the security boundary is
//! the certificate, not the SNI. We validate a full chain to a webpki
//! trust root for the *real* host name, exactly as a browser would. The
//! SNI is cosmetic — purely to blind the on-path censor. An attacker who
//! redirects us to a wrong IP (DNS poisoning, BGP) cannot produce a cert
//! that chains to a public root for `facebook.com`, so the handshake is
//! rejected. This is strictly stronger than the `NoVerify` path used for
//! the relay tunnel.
//!
//! Contrast with the pinned-IP `fronting_groups` path
//! (`do_sni_rewrite_tunnel_from_tcp` without `force_ip`): there the edge
//! is a shared CDN that genuinely serves a cert for the SNI we send
//! (`react.dev` on Vercel's edge), so the default verifier-against-SNI is
//! correct and this module isn't used. Camouflage mode is for
//! destinations with no frontable shared edge — Google video (the EVA
//! edge) and Meta — where we must hit the real IP.

use std::sync::{Arc, OnceLock};

use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use tokio_rustls::TlsConnector;

/// A `ServerCertVerifier` that ignores the SNI/`server_name` rustls
/// passes in and instead validates the presented chain against a fixed
/// list of *expected* names — succeeding if the cert is valid for any
/// one of them. Wraps the stock webpki verifier so chain-building,
/// expiry, and signature checks are byte-for-byte the same as the
/// default path; only the name being matched is substituted.
///
/// `expected` must be non-empty (enforced by [`build_camouflage_connector`]).
#[derive(Debug)]
pub struct CamouflageVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected: Vec<ServerName<'static>>,
}

impl ServerCertVerifier for CamouflageVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        // Deliberately ignored: this is the camouflage SNI we put on the
        // wire, NOT the identity we trust. We verify against `expected`.
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Try each acceptable real name. The webpki verifier does full
        // chain construction + validity + name matching per call; the
        // first name the cert is actually valid for wins. Keep the last
        // error so a total failure surfaces a real reason (expired,
        // untrusted root, wrong host) rather than a generic message.
        let mut last_err: Option<TlsError> = None;
        for name in &self.expected {
            match self
                .inner
                .verify_server_cert(end_entity, intermediates, name, ocsp_response, now)
            {
                Ok(v) => return Ok(v),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(TlsError::General(
            "camouflage verifier has no expected names".into(),
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Webpki root store seeded from the bundled `webpki-roots` (same set
/// the `verify_ssl` path uses in `proxy_server`).
fn webpki_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Process-wide webpki verifier built once over the bundled roots.
/// Building it parses the full root set (~150 certs), so we cache it:
/// `force_ip` fronting builds a fresh connector *per connection* (the
/// verify name is the per-request destination host), and we don't want
/// to re-parse roots on every CONNECT. `None` only if the root set is
/// somehow unbuildable, which would also break the rest of TLS.
fn shared_inner_verifier() -> Option<Arc<WebPkiServerVerifier>> {
    static CELL: OnceLock<Option<Arc<WebPkiServerVerifier>>> = OnceLock::new();
    CELL.get_or_init(|| {
        WebPkiServerVerifier::builder(Arc::new(webpki_root_store()))
            .build()
            .map_err(|e| tracing::error!("webpki verifier build failed: {}", e))
            .ok()
    })
    .clone()
}

/// Build a `TlsConnector` whose verifier accepts a cert valid for any of
/// `verify_names`, offering no ALPN. Convenience wrapper over
/// [`build_camouflage_connector_with_alpn`] for callers that don't splice
/// (the DoH client, startup validation).
pub fn build_camouflage_connector(verify_names: &[String]) -> Result<TlsConnector, String> {
    build_camouflage_connector_with_alpn(verify_names, &[])
}

/// Build a `TlsConnector` whose verifier accepts a cert valid for any of
/// `verify_names`, regardless of the SNI the caller later passes to
/// `connect()`. The SNI is the caller's camouflage choice; `verify_names`
/// is the trust anchor.
///
/// `alpn` is the ALPN protocol list offered on the outbound handshake
/// (e.g. `[b"h2", b"http/1.1"]`). Pass an empty slice to offer none.
/// Callers that splice (and must stay protocol-coherent with the inbound
/// MITM leg) propagate the negotiated protocol via this.
///
/// Returns `Err` if `verify_names` is empty or contains no parseable
/// server names — a connector that trusts nothing would silently fail
/// every handshake, so we reject it at construction instead.
pub fn build_camouflage_connector_with_alpn(
    verify_names: &[String],
    alpn: &[Vec<u8>],
) -> Result<TlsConnector, String> {
    let expected: Vec<ServerName<'static>> = verify_names
        .iter()
        .filter_map(|n| {
            let n = n.trim().trim_end_matches('.');
            if n.is_empty() {
                return None;
            }
            match ServerName::try_from(n.to_string()) {
                Ok(sn) => Some(sn),
                Err(e) => {
                    tracing::warn!("camouflage verify name '{}' is not valid: {}", n, e);
                    None
                }
            }
        })
        .collect();
    if expected.is_empty() {
        return Err("no valid verify_names for camouflage connector".into());
    }

    let inner = shared_inner_verifier().ok_or("webpki verifier unavailable")?;

    let verifier = Arc::new(CamouflageVerifier { inner, expected });
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn.to_vec();
    Ok(TlsConnector::from(Arc::new(config)))
}

// ---------- ALPN coherence for the splice ----------
//
// The camouflage tunnel raw-splices the browser TLS leg to the upstream
// TLS leg, so both MUST end up speaking the same protocol. We can't pick
// the upstream's ALPN after the browser's (that's inbound-first, which
// would forfeit the upstream-first fall-through), so instead we PEEK the
// browser's ClientHello ALPN (non-consuming, fall-through preserved),
// offer the upstream only what the browser offered, and finally present
// the browser exactly the protocol the upstream chose. Every combination
// then agrees; the worst case (peek fails to capture the ClientHello)
// degrades to http/1.1 on both legs, never a mismatch.

/// Parse the ALPN protocol list a browser offered in its TLS ClientHello.
/// Returns the offered names (e.g. `[b"h2", b"http/1.1"]`), or `None` if
/// `data` isn't a parseable ClientHello or carries no ALPN extension.
/// Bounds-checked at every step — a truncated/peeked record yields `None`
/// rather than panicking.
///
/// Scope: parses a ClientHello contained in a single TLS record (the
/// normal case — the peek buffer captures the first segment). A
/// ClientHello fragmented across multiple TLS records, or one larger than
/// the caller's peek buffer (e.g. an ALPN sitting after a very large
/// post-quantum key_share), simply yields `None`, and the caller degrades
/// to http/1.1 on both splice legs — safe, never a protocol mismatch.
pub fn client_hello_alpn(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    // Uniformly overflow-safe slice helper (mirrors the `checked_add`
    // discipline below; `i`/`n` are small here but keep it consistent).
    let get = |i: usize, n: usize| i.checked_add(n).and_then(|end| data.get(i..end));
    if *data.first()? != 0x16 {
        return None; // TLS handshake record
    }
    let mut i = 5; // skip 5-byte record header
    if *data.get(i)? != 0x01 {
        return None; // ClientHello
    }
    i = i.checked_add(4)?; // handshake type (1) + length (3)
    i = i.checked_add(2 + 32)?; // legacy version (2) + random (32)
    let session_len = *data.get(i)? as usize;
    i = i.checked_add(1 + session_len)?;
    let cipher = get(i, 2)?;
    let cipher_len = u16::from_be_bytes([cipher[0], cipher[1]]) as usize;
    i = i.checked_add(2 + cipher_len)?;
    let comp_len = *data.get(i)? as usize;
    i = i.checked_add(1 + comp_len)?;
    let ext_total = get(i, 2)?;
    let ext_len = u16::from_be_bytes([ext_total[0], ext_total[1]]) as usize;
    i = i.checked_add(2)?;
    let ext_end = i.checked_add(ext_len)?;
    if ext_end > data.len() {
        return None;
    }
    while i + 4 <= ext_end {
        let hdr = get(i, 4)?;
        let typ = u16::from_be_bytes([hdr[0], hdr[1]]);
        let l = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        i = i.checked_add(4)?;
        let body_end = i.checked_add(l)?;
        if body_end > ext_end {
            return None;
        }
        if typ == 0x0010 {
            // ALPN extension
            return parse_alpn_list(data, i, body_end);
        }
        i = body_end;
    }
    None
}

/// Parse the `ProtocolNameList` inside an ALPN extension body
/// (`[start, end)`): a 2-byte list length, then `len(1)+name` entries.
fn parse_alpn_list(data: &[u8], start: usize, end: usize) -> Option<Vec<Vec<u8>>> {
    let lh = data.get(start..start + 2)?;
    let list_len = u16::from_be_bytes([lh[0], lh[1]]) as usize;
    let mut i = start + 2;
    let list_end = i.checked_add(list_len)?;
    if list_end > end {
        return None;
    }
    let mut out = Vec::new();
    while i < list_end {
        let nl = *data.get(i)? as usize;
        i += 1;
        let ne = i.checked_add(nl)?;
        if ne > list_end {
            return None;
        }
        out.push(data[i..ne].to_vec());
        i = ne;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Decide which ALPN protocols to offer the upstream, given what the
/// browser offered. We restrict to the two protocols we splice (`h2`,
/// `http/1.1`) and only ever offer the upstream protocols the browser
/// itself offered — so whatever the upstream then picks is guaranteed to
/// be something the browser will also accept. If the browser offered
/// neither (or no ALPN at all), force `http/1.1` so both legs stay on it.
pub fn choose_upstream_alpn(browser_alpn: Option<&[Vec<u8>]>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(list) = browser_alpn {
        for p in list {
            if (p.as_slice() == b"h2" || p.as_slice() == b"http/1.1") && !out.contains(p) {
                out.push(p.clone());
            }
        }
    }
    if out.is_empty() {
        out.push(b"http/1.1".to_vec());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_verify_names_is_rejected() {
        assert!(build_camouflage_connector(&[]).is_err());
        assert!(build_camouflage_connector(&["".to_string(), " . ".to_string()]).is_err());
    }

    #[test]
    fn valid_names_build_a_connector() {
        // Needs the ring default provider; install it the same way the
        // binary does. Idempotent / racey-safe: ignore the "already set"
        // error other tests may have triggered first.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let c = build_camouflage_connector_with_alpn(
            &["googlevideo.com".to_string(), "www.youtube.com".to_string()],
            &[b"h2".to_vec(), b"http/1.1".to_vec()],
        );
        assert!(c.is_ok(), "expected Ok, got {:?}", c.err());
    }

    #[test]
    fn ip_literals_parse_as_names() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        // An IP SAN name is a legitimate verify target (some edges serve
        // IP-SAN certs); make sure parsing doesn't drop it.
        let c = build_camouflage_connector(&["1.1.1.1".to_string()]);
        assert!(c.is_ok());
    }

    // ---- ClientHello ALPN parsing + upstream-offer selection ----

    /// Build a minimal but structurally valid ClientHello carrying the
    /// given ALPN protocol list (empty `protos` = include no ALPN ext).
    fn client_hello(protos: &[&[u8]]) -> Vec<u8> {
        let extensions = if protos.is_empty() {
            Vec::new()
        } else {
            let mut list = Vec::new();
            for p in protos {
                list.push(p.len() as u8);
                list.extend_from_slice(p);
            }
            let mut ext_body = Vec::new();
            ext_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ext_body.extend_from_slice(&list);
            let mut ext = Vec::new();
            ext.extend_from_slice(&0x0010u16.to_be_bytes()); // ALPN
            ext.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
            ext.extend_from_slice(&ext_body);
            ext
        };
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x00, 0x00]); // one cipher suite
        body.push(1); // compression length
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut hs = vec![0x01]; // ClientHello
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_alpn_h2_and_h1() {
        let ch = client_hello(&[b"h2", b"http/1.1"]);
        assert_eq!(
            client_hello_alpn(&ch),
            Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        );
    }

    #[test]
    fn parses_alpn_h1_only() {
        let ch = client_hello(&[b"http/1.1"]);
        assert_eq!(client_hello_alpn(&ch), Some(vec![b"http/1.1".to_vec()]));
    }

    #[test]
    fn no_alpn_extension_is_none() {
        assert_eq!(client_hello_alpn(&client_hello(&[])), None);
    }

    #[test]
    fn truncated_client_hello_is_none() {
        let ch = client_hello(&[b"h2", b"http/1.1"]);
        // A peek that captured only a prefix must not panic or misparse.
        assert_eq!(client_hello_alpn(&ch[..ch.len() / 2]), None);
        assert_eq!(client_hello_alpn(&[]), None);
        assert_eq!(client_hello_alpn(&[0x16, 0x03]), None);
    }

    #[test]
    fn alpn_present_but_extensions_overrun_is_none() {
        // The extensions_length header declares the full block, but the
        // buffer is cut just short of it (e.g. a ClientHello larger than
        // the 8 KiB peek). `ext_end > data.len()` must yield None so the
        // caller degrades to http/1.1 rather than misparsing — pins that
        // intended safe degradation.
        let ch = client_hello(&[b"h2", b"http/1.1"]);
        assert_eq!(client_hello_alpn(&ch[..ch.len() - 2]), None);
    }

    #[test]
    fn non_handshake_record_is_none() {
        // 0x17 = application data, not a handshake.
        assert_eq!(
            client_hello_alpn(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]),
            None
        );
    }

    #[test]
    fn upstream_offer_mirrors_browser() {
        let h2h1 = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let h1 = vec![b"http/1.1".to_vec()];
        let h2 = vec![b"h2".to_vec()];
        // Browser offered both → offer both (upstream's pick is in-set).
        assert_eq!(choose_upstream_alpn(Some(&h2h1)), h2h1);
        // Browser offered only one → offer only that.
        assert_eq!(choose_upstream_alpn(Some(&h1)), h1);
        assert_eq!(choose_upstream_alpn(Some(&h2)), h2);
        // No ALPN at all → force http/1.1 (both legs stay h1).
        assert_eq!(choose_upstream_alpn(None), h1);
        // Unknown-only (e.g. spdy) → nothing we splice → force http/1.1.
        assert_eq!(choose_upstream_alpn(Some(&[b"spdy/3".to_vec()])), h1);
    }
}
