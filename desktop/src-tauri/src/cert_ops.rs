// CA-cert display helpers for the MITM card on the Status tab.
//
// The rahgozar core lib (`src/mitm.rs`, `src/cert_installer.rs`)
// already knows how to mint, load, install, and remove the CA — what
// it deliberately doesn't expose is "read the cert into a
// JSON-serialisable shape so the UI can show the user what they're
// about to trust". That introspection lives here, in the Tauri crate,
// because it's a presentation concern.
//
// What we surface:
//   - Whether the on-disk PEM (`<data_dir>/ca/ca.crt`) exists.
//   - SHA-256 fingerprint over its DER bytes, formatted as the
//     colon-separated hex pairs every cert-tooling UI uses.
//   - Subject Common Name (typically "rahgozar MITM CA") so the
//     dialog doesn't show a hex blob with no human label.
//   - Whether the OS trust store currently trusts a CA by that name
//     (delegated to `cert_installer::is_ca_trusted_by_name` so the
//     check matches what `install_ca` / `remove_ca` would actually
//     consult).

use std::path::{Path, PathBuf};

use rahgozar::data_dir;
use rahgozar::mitm::CA_CERT_FILE;

/// Resolve the path the proxy writes `ca.crt` to. Same pattern the
/// rest of the rahgozar code uses — `data_dir::data_dir()` materialises
/// `%APPDATA%\rahgozar` / `~/Library/Application Support/rahgozar` etc.
pub fn ca_cert_path() -> PathBuf {
    data_dir::data_dir().join(CA_CERT_FILE)
}

/// Read the PEM at `path` and decode the first CERTIFICATE entry into
/// DER bytes. Returns `None` if the file doesn't exist or doesn't
/// contain a parseable certificate — both are non-error cases for the
/// status card (which renders a "no CA yet" state instead of a toast).
pub fn read_ca_der(path: &Path) -> Option<Vec<u8>> {
    let bytes = std::fs::read(path).ok()?;
    let mut reader: &[u8] = &bytes;
    // `rustls_pemfile::certs` yields each CERTIFICATE block as DER.
    // We only ever write one cert into ca.crt (the root itself), so
    // the first hit is what we want.
    let mut it = rustls_pemfile::certs(&mut reader);
    let first = it.next()?;
    let cert = first.ok()?;
    Some(cert.as_ref().to_vec())
}

/// SHA-256 of the DER bytes, formatted as 32 uppercase hex pairs
/// joined by colons (`AB:CD:…:EF`). Same shape the egui dialog used
/// and what `openssl x509 -fingerprint -sha256` prints, so a savvy
/// user can re-verify with a CLI tool if they want.
pub fn fingerprint_hex(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Extract the Subject Common Name from a parsed X.509 cert. Falls
/// back to `None` if the cert lacks a CN attribute (it shouldn't —
/// `MitmCertManager::generate` always sets one — but a malformed
/// hand-edited PEM shouldn't panic the status card).
pub fn subject_cn(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::FromDer;
    // Bind the parsed cert to a `let` so it lives the full function
    // body. Without this binding the chained `.subject().iter_common_name()`
    // call below tries to borrow from a temporary that drops at the
    // semicolon — caught by E0597.
    let parsed = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let cert = parsed.1;
    let cn = cert.subject().iter_common_name().next()?;
    cn.as_str().ok().map(|s| s.to_string())
}
