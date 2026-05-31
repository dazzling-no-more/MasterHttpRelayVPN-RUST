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
/// `verify_names`, regardless of the SNI the caller later passes to
/// `connect()`. The SNI is the caller's camouflage choice; `verify_names`
/// is the trust anchor.
///
/// Returns `Err` if `verify_names` is empty or contains no parseable
/// server names — a connector that trusts nothing would silently fail
/// every handshake, so we reject it at construction instead.
pub fn build_camouflage_connector(verify_names: &[String]) -> Result<TlsConnector, String> {
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
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
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
        let c = build_camouflage_connector(&[
            "googlevideo.com".to_string(),
            "www.youtube.com".to_string(),
        ]);
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
}
