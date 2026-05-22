//! "Check for updates" — fetches the latest tag (and matching platform
//! asset) from the GitHub Releases API and compares to the running version.
//!
//! Two routing modes:
//!
//! 1. **Direct**: rustls + webpki roots, straight to `api.github.com`.
//!    Used when our own proxy isn't running.
//! 2. **Via proxy**: HTTP CONNECT through our local HTTP proxy listener
//!    → MITM → Apps Script → `api.github.com`. From GitHub's POV the
//!    request comes from Apps Script's IP range, which has its own
//!    60/hour rate limit bucket — distinct from the user's ISP IP.
//!    Critical for users on shared NAT networks (very common in Iran)
//!    where the ISP IP burns through the unauthenticated API quota in
//!    seconds. When routing via proxy we load our own CA cert into the
//!    trust store so the MITM leaf is trusted.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const REPO_OWNER: &str = "dazzling-no-more";
const REPO_NAME: &str = "rahgozar";
const GITHUB_API_HOST: &str = "api.github.com";
const GITHUB_HOST: &str = "github.com";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const API_READ_LIMIT_BYTES: usize = 512 * 1024;
const BINARY_READ_LIMIT_BYTES: usize = 256 * 1024 * 1024;

/// Where to route the HTTPS GET. Direct = straight rustls to the target.
/// Proxy = HTTP CONNECT through our local MITM proxy (so GitHub sees
/// Apps Script's IP, not the user's — bypasses per-IP rate limits on
/// shared-NAT networks).
#[derive(Clone, Debug)]
pub enum Route {
    Direct,
    Proxy { host: String, port: u16 },
}

/// The user-visible outcome of an update check.
#[derive(Clone, Debug)]
pub enum UpdateCheck {
    /// Could not reach github.com at all. Likely offline or github blocked.
    Offline(String),
    /// Reached github.com but the API call or JSON parse failed.
    Error(String),
    /// Current binary is already on the latest tag.
    UpToDate { current: String, latest: String },
    /// A newer release is available.
    UpdateAvailable {
        current: String,
        latest: String,
        release_url: String,
        /// Best-guess asset for this platform/arch combo, if the API
        /// response included one we could match. `None` = no matching
        /// asset; UI should fall back to the release_url page.
        asset: Option<ReleaseAsset>,
    },
}

#[derive(Clone, Debug)]
pub struct ReleaseAsset {
    pub name: String,
    pub download_url: String,
    pub size_bytes: u64,
}

impl UpdateCheck {
    pub fn summary(&self) -> String {
        match self {
            UpdateCheck::Offline(msg) => format!("Can't reach github.com: {}", msg),
            UpdateCheck::Error(msg) => format!("Update check failed: {}", msg),
            UpdateCheck::UpToDate { current, .. } => {
                format!("Up to date (running v{}).", current)
            }
            UpdateCheck::UpdateAvailable {
                current,
                latest,
                release_url,
                ..
            } => format!(
                "Update available: v{} → v{}  ({})",
                current, latest, release_url
            ),
        }
    }
}

/// Run the full update check.
pub async fn check(route: Route) -> UpdateCheck {
    if let Route::Direct = route {
        if let Err(e) = probe_github().await {
            return UpdateCheck::Offline(e);
        }
    }

    let body = match fetch_api_body(&route).await {
        Ok(s) => s,
        Err(e) => return UpdateCheck::Error(e),
    };

    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return UpdateCheck::Error(format!("bad API JSON: {}", e)),
    };

    let latest_tag = match v.get("tag_name").and_then(|t| t.as_str()) {
        Some(s) => s.to_string(),
        None => return UpdateCheck::Error("API response missing tag_name".into()),
    };

    let latest = latest_tag.trim_start_matches('v').to_string();
    let current = CURRENT_VERSION.to_string();
    let release_url = format!(
        "https://github.com/{}/{}/releases/tag/{}",
        REPO_OWNER, REPO_NAME, latest_tag
    );

    if !is_newer(&latest, &current) {
        return UpdateCheck::UpToDate { current, latest };
    }

    // Pick a matching asset for this platform/arch.
    let asset = v
        .get("assets")
        .and_then(|a| a.as_array())
        .and_then(|arr| pick_asset_for_platform(arr));

    UpdateCheck::UpdateAvailable {
        current,
        latest,
        release_url,
        asset,
    }
}

/// Download a release asset to `out_path`. Returns Ok(bytes written) or Err(reason).
/// The body is currently buffered in memory and then written directly to
/// `out_path`; callers that expose the path to users should stage into a
/// scratch location first.
pub async fn download_asset(
    route: Route,
    asset_url: &str,
    out_path: &std::path::Path,
) -> Result<u64, String> {
    // GitHub asset URLs (api.github.com/.../assets/<id>) 302 to
    // objects.githubusercontent.com. Our https_get follows one redirect
    // already, which covers that hop. Beyond that is a bug.
    let (host, path) =
        split_url(asset_url).ok_or_else(|| format!("bad asset URL: {}", asset_url))?;
    let body = https_raw_get(&route, &host, &path, true).await?;
    // Async write so we don't stall the executor on a 50 MB-class spool.
    tokio::fs::write(out_path, &body)
        .await
        .map_err(|e| format!("write {}: {}", out_path.display(), e))?;
    Ok(body.len() as u64)
}

async fn probe_github() -> Result<(), String> {
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((GITHUB_HOST, 443u16)),
    )
    .await;
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("connect timeout".into()),
    }
}

async fn fetch_api_body(route: &Route) -> Result<String, String> {
    let path = format!("/repos/{}/{}/releases/latest", REPO_OWNER, REPO_NAME);
    let bytes = https_raw_get(route, GITHUB_API_HOST, &path, false).await?;
    String::from_utf8(bytes).map_err(|_| "non-utf8 API body".to_string())
}

/// Low-level HTTPS GET. Handles:
///   - TCP connect + TLS handshake (direct OR via HTTP CONNECT through our local proxy)
///   - A single 301/302/307/308 redirect
///   - Binary responses when `binary=true` (asset download)
async fn https_raw_get(
    route: &Route,
    host: &str,
    path: &str,
    binary: bool,
) -> Result<Vec<u8>, String> {
    let roots = build_root_store(route)?;
    let tls_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    // Raw TCP: either direct to <host>:443 or to our proxy, then CONNECT.
    let tcp = match route {
        Route::Direct => {
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, 443u16)))
                .await
                .map_err(|_| "tcp connect timeout".to_string())?
                .map_err(|e| format!("tcp connect: {}", e))?
        }
        Route::Proxy { host: ph, port: pp } => {
            let mut t = tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect((ph.as_str(), *pp)),
            )
            .await
            .map_err(|_| "proxy connect timeout".to_string())?
            .map_err(|e| format!("proxy connect: {}", e))?;
            // HTTP CONNECT to target.
            let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
            t.write_all(req.as_bytes())
                .await
                .map_err(|e| format!("proxy CONNECT write: {}", e))?;
            // Read until \r\n\r\n.
            let mut buf = [0u8; 256];
            let mut total = 0usize;
            let mut collected = Vec::new();
            loop {
                let n = tokio::time::timeout(Duration::from_secs(5), t.read(&mut buf))
                    .await
                    .map_err(|_| "proxy CONNECT read timeout".to_string())?
                    .map_err(|e| format!("proxy CONNECT read: {}", e))?;
                if n == 0 {
                    return Err("proxy CONNECT closed early".into());
                }
                collected.extend_from_slice(&buf[..n]);
                total += n;
                if collected.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if total > 4096 {
                    return Err("proxy CONNECT reply too large".into());
                }
            }
            let first_line = String::from_utf8_lossy(&collected)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            if !first_line.contains("200") {
                return Err(format!("proxy CONNECT refused: {}", first_line));
            }
            t
        }
    };
    let _ = tcp.set_nodelay(true);

    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| format!("bad host: {}", e))?;
    let mut tls = tokio::time::timeout(Duration::from_secs(8), connector.connect(server_name, tcp))
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls: {}", e))?;

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: rahgozar/{ver} (update-check)\r\n\
         Accept: {accept}\r\n\
         Connection: close\r\n\
         \r\n",
        path = path,
        host = host,
        ver = CURRENT_VERSION,
        accept = if binary {
            "*/*"
        } else {
            "application/vnd.github+json"
        },
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    tls.flush().await.ok();

    let mut buf = Vec::with_capacity(if binary { 1024 * 1024 } else { 16 * 1024 });
    let read_limit: usize = if binary {
        BINARY_READ_LIMIT_BYTES
    } else {
        API_READ_LIMIT_BYTES
    };
    let read_fut = async {
        let mut chunk = [0u8; 8192];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(format!("read: {}", e)),
            }
            if buf.len() > read_limit {
                let limit_label = if read_limit >= 1_048_576 {
                    format!("{:.0} MiB", read_limit as f64 / 1_048_576.0)
                } else {
                    format!("{} KiB", read_limit / 1024)
                };
                return Err(format!("response too large (>{} limit)", limit_label));
            }
        }
        Ok::<(), String>(())
    };
    let timeout = if binary {
        Duration::from_secs(120)
    } else {
        Duration::from_secs(10)
    };
    tokio::time::timeout(timeout, read_fut)
        .await
        .map_err(|_| "read timeout".to_string())??;

    parse_response(&buf, host, route, binary).await
}

fn parse_response<'a>(
    buf: &'a [u8],
    host: &'a str,
    route: &'a Route,
    binary: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
    Box::pin(async move {
        let sep = b"\r\n\r\n";
        let hdr_end = buf
            .windows(sep.len())
            .position(|w| w == sep)
            .ok_or_else(|| "no HTTP header terminator".to_string())?;
        let hdr =
            std::str::from_utf8(&buf[..hdr_end]).map_err(|_| "non-utf8 header".to_string())?;
        let body = &buf[hdr_end + sep.len()..];

        let first = hdr.lines().next().unwrap_or("");
        let status: u16 = first
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("bad status line: {}", first))?;

        match status {
            200 => Ok(body.to_vec()),
            301 | 302 | 307 | 308 => {
                let loc = hdr
                    .lines()
                    .find_map(|l| {
                        if l.to_ascii_lowercase().starts_with("location:") {
                            Some(l[l.find(':').unwrap() + 1..].trim().to_string())
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| "redirect without Location".to_string())?;
                let (new_host, new_path) = parse_url(&loc, host);
                https_raw_get(route, &new_host, &new_path, binary).await
            }
            other => {
                let preview = String::from_utf8_lossy(body)
                    .chars()
                    .take(240)
                    .collect::<String>();
                Err(format!("HTTP {}: {}", other, preview))
            }
        }
    })
}

fn build_root_store(route: &Route) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // If we're routing via our own proxy, also trust the MITM CA so the
    // proxy's on-the-fly leaf for api.github.com validates.
    if matches!(route, Route::Proxy { .. }) {
        let ca_path = crate::data_dir::ca_cert_path();
        if let Ok(mut pem) = std::fs::read(&ca_path) {
            let mut rdr: &[u8] = pem.as_mut_slice();
            let mut added = 0;
            while let Some(res) =
                rustls_pemfile::read_one(&mut rdr).map_err(|e| format!("read ca.crt: {}", e))?
            {
                if let rustls_pemfile::Item::X509Certificate(der) = res {
                    let cert: CertificateDer<'static> = der;
                    if roots.add(cert).is_ok() {
                        added += 1;
                    }
                }
            }
            if added == 0 {
                tracing::debug!(
                    "update_check: no certs in {} — proxy-routed MITM leaf won't validate",
                    ca_path.display()
                );
            }
        }
    }
    Ok(roots)
}

fn parse_url(url: &str, default_host: &str) -> (String, String) {
    if let Some(rest) = url.strip_prefix("https://") {
        if let Some(slash) = rest.find('/') {
            (rest[..slash].to_string(), rest[slash..].to_string())
        } else {
            (rest.to_string(), "/".to_string())
        }
    } else if url.starts_with('/') {
        (default_host.to_string(), url.to_string())
    } else {
        (default_host.to_string(), format!("/{}", url))
    }
}

fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    let slash = rest.find('/')?;
    Some((rest[..slash].to_string(), rest[slash..].to_string()))
}

/// Given the GitHub API's `assets` array, pick the one that best matches
/// this platform + arch. Returns None if nothing reasonable matched.
fn pick_asset_for_platform(assets: &[serde_json::Value]) -> Option<ReleaseAsset> {
    // `target_env` distinguishes glibc vs musl on linux and gnu/mingw vs
    // msvc on Windows — critical because a glibc binary will segfault
    // trying to dlopen ld-musl, and vice versa. `target_endian` separates
    // mipsel (LE, MT7621) from mips (BE, Atheros AR71XX). Both are baked
    // at compile time, so every built binary self-updates to its own
    // flavor and never crosses ABIs.
    //
    // We preserve the three distinct `target_env` values rustc actually
    // emits — "musl", "msvc", "gnu" — rather than collapsing non-musl
    // to "gnu". Today only `("linux", *)` routes branch on env, so the
    // Windows arm64 picker (`aarch64-pc-windows-msvc`) and the Windows
    // amd64 picker (`x86_64-pc-windows-gnu`) both fall through to the
    // env-agnostic Windows arms regardless. But preserving "msvc"
    // keeps the running picker honest to what `cfg!(target_env)`
    // reports at runtime, makes the Windows arm64 test exercise the
    // same code path as a real native binary, and leaves us a clean
    // hook for future split (e.g. if we ever ship `*-windows-msvc` vs
    // `*-windows-gnu` for the same arch).
    let env = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else {
        "gnu"
    };
    let endian = if cfg!(target_endian = "big") {
        "big"
    } else {
        "little"
    };
    pick_asset_for_target(
        assets,
        std::env::consts::OS,
        std::env::consts::ARCH,
        env,
        endian,
    )
}

fn asset_preferences(
    os: &str,
    arch: &str,
    env: &str,
    endian: &str,
) -> &'static [&'static [&'static str]] {
    // Priority-ordered preference list of name *patterns* — first pattern
    // that matches any asset wins. All matches are case-insensitive
    // substrings.
    //
    // For (os, arch) pairs where multiple ABI flavors ship (linux gnu vs
    // musl, mips little vs big endian), the match guards use `env` /
    // `endian` to route to the right artifact. Critically we DO NOT fall
    // back across ABIs — a musl arm binary that grabs raspbian-armhf
    // would crash on first dlopen against ld-linux-armhf.so.3.
    match (os, arch) {
        // macOS: .app.zip is the nicest user experience (double-click).
        ("macos", "aarch64") => &[&["macos-arm64-app", ".zip"], &["macos-arm64", ".tar.gz"]],
        ("macos", "x86_64") => &[&["macos-amd64-app", ".zip"], &["macos-amd64", ".tar.gz"]],
        // Windows arm64 is its own MSVC build (Snapdragon X / Surface Pro X+11).
        // Everything else (x86_64, x86 via WoW64) gets the GNU/MinGW amd64 zip.
        ("windows", "aarch64") => &[&["windows-arm64", ".zip"]],
        ("windows", _) => &[&["windows-amd64", ".zip"]],
        // Linux 64-bit: env picks the glibc (Debian/Ubuntu) build vs the
        // static musl (OpenWRT/Alpine) build. No cross-env fallback —
        // see top-level comment.
        ("linux", "aarch64") if env == "musl" => &[&["linux-musl-arm64", ".tar.gz"]],
        ("linux", "aarch64") => &[&["linux-arm64", ".tar.gz"]],
        ("linux", "x86_64") if env == "musl" => &[&["linux-musl-amd64", ".tar.gz"]],
        ("linux", "x86_64") => &[&["linux-amd64", ".tar.gz"]],
        // Linux 32-bit ARM: musl ⇒ static OpenWRT armv7 build (ipq40xx /
        // mt7622 / ipq806x routers); glibc ⇒ Raspbian armhf (Pi 2+).
        ("linux", "arm") if env == "musl" => &[&["openwrt-armv7-musleabihf", ".tar.gz"]],
        ("linux", "arm") => &[&["raspbian-armhf", ".tar.gz"]],
        // Linux 32-bit MIPS: endian disambiguates mipsel (MT7621, etc.)
        // from mips (Atheros AR71XX/AR9XXX). Both Rust targets emit
        // soft-float code per the target spec, hence -softfloat in both
        // artifact names. No glibc variant ships.
        ("linux", "mips") if endian == "big" => &[&["openwrt-mips-softfloat", ".tar.gz"]],
        ("linux", "mips") => &[&["openwrt-mipsel-softfloat", ".tar.gz"]],
        // Android: each per-arch APK matches its ABI. Universal is the
        // fallback when no per-arch build is published. The running
        // process's target_arch picks the right one — `Build.SUPPORTED_ABIS[0]`
        // and `target_arch` agree because the Rust cdylib was built for
        // exactly the ABI the device loaded.
        ("android", "aarch64") => &[
            &["android-arm64-v8a", ".apk"],
            &["android-universal", ".apk"],
        ],
        ("android", "arm") => &[
            &["android-armeabi-v7a", ".apk"],
            &["android-universal", ".apk"],
        ],
        ("android", "x86_64") => &[&["android-x86_64", ".apk"], &["android-universal", ".apk"]],
        ("android", "x86") => &[&["android-x86-", ".apk"], &["android-universal", ".apk"]],
        _ => &[],
    }
}

fn pick_asset_for_target(
    assets: &[serde_json::Value],
    os: &str,
    arch: &str,
    env: &str,
    endian: &str,
) -> Option<ReleaseAsset> {
    for needles in asset_preferences(os, arch, env, endian) {
        for a in assets {
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let lower = name.to_ascii_lowercase();
            if needles
                .iter()
                .all(|n| lower.contains(&n.to_ascii_lowercase()))
            {
                let url = a
                    .get("browser_download_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let size = a.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                if !url.is_empty() {
                    return Some(ReleaseAsset {
                        name: name.to_string(),
                        download_url: url.to_string(),
                        size_bytes: size,
                    });
                }
            }
        }
    }
    None
}

fn is_newer(a: &str, b: &str) -> bool {
    let parts_a: Vec<&str> = a.split(['.', '-']).collect();
    let parts_b: Vec<&str> = b.split(['.', '-']).collect();
    let n = parts_a.len().max(parts_b.len());
    for i in 0..n {
        let pa = parts_a.get(i).unwrap_or(&"0");
        let pb = parts_b.get(i).unwrap_or(&"0");
        match (pa.parse::<u64>(), pb.parse::<u64>()) {
            (Ok(na), Ok(nb)) if na != nb => return na > nb,
            (Ok(_), Ok(_)) => continue,
            _ => {
                if pa != pb {
                    return *pa > *pb;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_basic() {
        assert!(is_newer("0.8.6", "0.8.5"));
        assert!(is_newer("0.9.0", "0.8.99"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.8.5", "0.8.5"));
        assert!(!is_newer("0.8.4", "0.8.5"));
    }

    #[test]
    fn pick_asset_prefers_app_zip_on_macos() {
        let assets = serde_json::json!([
            {"name": "rahgozar-linux-amd64.tar.gz", "browser_download_url": "https://x/a", "size": 1},
            {"name": "rahgozar-macos-arm64.tar.gz", "browser_download_url": "https://x/b", "size": 2},
            {"name": "rahgozar-macos-arm64-app.zip", "browser_download_url": "https://x/c", "size": 3},
        ]);
        let arr = assets.as_array().unwrap();
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            let picked = pick_asset_for_platform(arr).expect("should pick");
            assert_eq!(picked.name, "rahgozar-macos-arm64-app.zip");
        }
    }

    #[test]
    fn pick_asset_returns_none_when_no_match() {
        let assets = serde_json::json!([
            {"name": "random-thing.txt", "browser_download_url": "https://x/q", "size": 0},
        ]);
        let arr = assets.as_array().unwrap();
        assert!(pick_asset_for_platform(arr).is_none());
    }

    #[test]
    fn pick_asset_android_picks_per_abi_apk_over_universal() {
        let assets = serde_json::json!([
            {"name": "rahgozar-android-universal-v1.9.1.apk", "browser_download_url": "https://x/universal", "size": 1},
            {"name": "rahgozar-android-arm64-v8a-v1.9.1.apk", "browser_download_url": "https://x/arm64", "size": 2},
            {"name": "rahgozar-android-armeabi-v7a-v1.9.1.apk", "browser_download_url": "https://x/armv7", "size": 3},
            {"name": "rahgozar-android-x86_64-v1.9.1.apk", "browser_download_url": "https://x/x86_64", "size": 4},
            {"name": "rahgozar-android-x86-v1.9.1.apk", "browser_download_url": "https://x/x86", "size": 5},
        ]);
        let arr = assets.as_array().unwrap();
        let cases = [
            ("aarch64", "rahgozar-android-arm64-v8a-v1.9.1.apk"),
            ("arm", "rahgozar-android-armeabi-v7a-v1.9.1.apk"),
            ("x86_64", "rahgozar-android-x86_64-v1.9.1.apk"),
            ("x86", "rahgozar-android-x86-v1.9.1.apk"),
        ];
        for (arch, expected) in cases {
            // Android cases don't depend on env/endian — pass placeholders.
            let picked =
                pick_asset_for_target(arr, "android", arch, "gnu", "little").expect("should pick");
            assert_eq!(picked.name, expected, "arch={arch}");
        }
    }

    // A canonical asset list mirroring what a real release page now
    // produces post the Windows-arm64 / OpenWRT armv7 / MIPS additions.
    // Helper so the multi-target tests below share one source of truth.
    fn release_assets_fixture() -> serde_json::Value {
        serde_json::json!([
            // Desktop / CLI archives.
            {"name": "rahgozar-linux-amd64.tar.gz", "browser_download_url": "https://x/lx-amd64", "size": 1},
            {"name": "rahgozar-linux-arm64.tar.gz", "browser_download_url": "https://x/lx-arm64", "size": 2},
            {"name": "rahgozar-linux-musl-amd64.tar.gz", "browser_download_url": "https://x/lx-musl-amd64", "size": 3},
            {"name": "rahgozar-linux-musl-arm64.tar.gz", "browser_download_url": "https://x/lx-musl-arm64", "size": 4},
            {"name": "rahgozar-raspbian-armhf.tar.gz", "browser_download_url": "https://x/raspbian", "size": 5},
            {"name": "rahgozar-openwrt-armv7-musleabihf.tar.gz", "browser_download_url": "https://x/owrt-armv7", "size": 6},
            {"name": "rahgozar-openwrt-mipsel-softfloat.tar.gz", "browser_download_url": "https://x/owrt-mipsel", "size": 7},
            {"name": "rahgozar-openwrt-mips-softfloat.tar.gz", "browser_download_url": "https://x/owrt-mips", "size": 8},
            {"name": "rahgozar-windows-amd64.zip", "browser_download_url": "https://x/win-amd64", "size": 9},
            {"name": "rahgozar-windows-arm64.zip", "browser_download_url": "https://x/win-arm64", "size": 10},
            {"name": "rahgozar-macos-amd64.tar.gz", "browser_download_url": "https://x/mac-amd64", "size": 11},
            {"name": "rahgozar-macos-arm64.tar.gz", "browser_download_url": "https://x/mac-arm64", "size": 12},
        ])
    }

    #[test]
    fn pick_asset_windows_arm64_does_not_grab_amd64() {
        let assets = release_assets_fixture();
        let arr = assets.as_array().unwrap();
        // env/endian don't affect Windows arm64 routing — pin to "msvc"/
        // "little" anyway since that's what a real aarch64-pc-windows-msvc
        // binary reports at cfg time.
        let picked = pick_asset_for_target(arr, "windows", "aarch64", "msvc", "little")
            .expect("should pick");
        assert_eq!(picked.name, "rahgozar-windows-arm64.zip");

        // And the existing x86_64 path still picks amd64 (regression
        // guard for the wildcard arm of `("windows", _)`).
        let picked =
            pick_asset_for_target(arr, "windows", "x86_64", "gnu", "little").expect("should pick");
        assert_eq!(picked.name, "rahgozar-windows-amd64.zip");
    }

    #[test]
    fn pick_asset_linux_arm_musl_picks_openwrt_not_raspbian() {
        let assets = release_assets_fixture();
        let arr = assets.as_array().unwrap();
        // A musl armv7 OpenWRT binary MUST self-update to the openwrt
        // musl artifact — replacing it with raspbian-armhf (glibc) would
        // segfault on the router.
        let picked =
            pick_asset_for_target(arr, "linux", "arm", "musl", "little").expect("should pick");
        assert_eq!(picked.name, "rahgozar-openwrt-armv7-musleabihf.tar.gz");

        // A glibc armhf (Raspberry Pi) binary still goes to raspbian.
        let picked =
            pick_asset_for_target(arr, "linux", "arm", "gnu", "little").expect("should pick");
        assert_eq!(picked.name, "rahgozar-raspbian-armhf.tar.gz");
    }

    #[test]
    fn pick_asset_linux_x86_64_respects_env() {
        let assets = release_assets_fixture();
        let arr = assets.as_array().unwrap();
        let gnu =
            pick_asset_for_target(arr, "linux", "x86_64", "gnu", "little").expect("should pick");
        assert_eq!(gnu.name, "rahgozar-linux-amd64.tar.gz");

        let musl =
            pick_asset_for_target(arr, "linux", "x86_64", "musl", "little").expect("should pick");
        assert_eq!(musl.name, "rahgozar-linux-musl-amd64.tar.gz");
    }

    #[test]
    fn pick_asset_linux_aarch64_respects_env() {
        let assets = release_assets_fixture();
        let arr = assets.as_array().unwrap();
        let gnu =
            pick_asset_for_target(arr, "linux", "aarch64", "gnu", "little").expect("should pick");
        assert_eq!(gnu.name, "rahgozar-linux-arm64.tar.gz");

        let musl =
            pick_asset_for_target(arr, "linux", "aarch64", "musl", "little").expect("should pick");
        assert_eq!(musl.name, "rahgozar-linux-musl-arm64.tar.gz");
    }

    #[test]
    fn pick_asset_mips_endianness_separates_artifacts() {
        let assets = release_assets_fixture();
        let arr = assets.as_array().unwrap();
        let little =
            pick_asset_for_target(arr, "linux", "mips", "musl", "little").expect("should pick");
        assert_eq!(little.name, "rahgozar-openwrt-mipsel-softfloat.tar.gz");

        let big = pick_asset_for_target(arr, "linux", "mips", "musl", "big").expect("should pick");
        assert_eq!(big.name, "rahgozar-openwrt-mips-softfloat.tar.gz");
    }

    // ── No-cross-ABI-fallback invariants ─────────────────────────────────
    //
    // These tests pin the *safety* property of the picker: a binary
    // built for ABI X must NEVER return an asset for ABI Y, even if Y
    // is the only artifact on the release page. The positive-selection
    // tests above prove the picker grabs the right asset when both
    // flavors are present; these prove the picker FAILS CLOSED (returns
    // None) when only the wrong flavor is available, so the updater
    // surfaces a clean "no asset matched" instead of downloading a
    // binary that would segfault on dlopen.

    #[test]
    fn pick_asset_no_fallback_musl_linux_x86_64_to_glibc() {
        // Release page is missing the musl amd64 build (build leg
        // failed); a running musl binary must NOT pick the glibc one.
        let assets = serde_json::json!([
            {"name": "rahgozar-linux-amd64.tar.gz", "browser_download_url": "https://x/glibc", "size": 1},
        ]);
        let arr = assets.as_array().unwrap();
        assert!(pick_asset_for_target(arr, "linux", "x86_64", "musl", "little").is_none());
    }

    #[test]
    fn pick_asset_no_fallback_glibc_linux_x86_64_to_musl() {
        let assets = serde_json::json!([
            {"name": "rahgozar-linux-musl-amd64.tar.gz", "browser_download_url": "https://x/musl", "size": 1},
        ]);
        let arr = assets.as_array().unwrap();
        assert!(pick_asset_for_target(arr, "linux", "x86_64", "gnu", "little").is_none());
    }

    #[test]
    fn pick_asset_no_fallback_musl_linux_aarch64_to_glibc() {
        let assets = serde_json::json!([
            {"name": "rahgozar-linux-arm64.tar.gz", "browser_download_url": "https://x/glibc", "size": 1},
        ]);
        let arr = assets.as_array().unwrap();
        assert!(pick_asset_for_target(arr, "linux", "aarch64", "musl", "little").is_none());
    }

    #[test]
    fn pick_asset_no_fallback_openwrt_arm_to_raspbian() {
        // Critical: a musl armv7 OpenWRT binary picking up the
        // Raspbian glibc armhf tarball would segfault on the router on
        // first dynamic-linker resolution. The picker must return
        // None here, not the only-available artifact.
        let assets = serde_json::json!([
            {"name": "rahgozar-raspbian-armhf.tar.gz", "browser_download_url": "https://x/raspbian", "size": 1},
        ]);
        let arr = assets.as_array().unwrap();
        assert!(pick_asset_for_target(arr, "linux", "arm", "musl", "little").is_none());
    }

    #[test]
    fn pick_asset_no_fallback_raspbian_to_openwrt_arm() {
        let assets = serde_json::json!([
            {"name": "rahgozar-openwrt-armv7-musleabihf.tar.gz", "browser_download_url": "https://x/owrt", "size": 1},
        ]);
        let arr = assets.as_array().unwrap();
        assert!(pick_asset_for_target(arr, "linux", "arm", "gnu", "little").is_none());
    }

    #[test]
    fn pick_asset_no_fallback_mips_endianness() {
        // Big-endian MIPS must not accept the little-endian artifact —
        // wrong-endian instructions are gibberish to the CPU decoder.
        let only_little = serde_json::json!([
            {"name": "rahgozar-openwrt-mipsel-softfloat.tar.gz", "browser_download_url": "https://x/le", "size": 1},
        ]);
        let arr = only_little.as_array().unwrap();
        assert!(pick_asset_for_target(arr, "linux", "mips", "musl", "big").is_none());

        // Symmetric: little-endian MIPS must not accept the BE artifact.
        let only_big = serde_json::json!([
            {"name": "rahgozar-openwrt-mips-softfloat.tar.gz", "browser_download_url": "https://x/be", "size": 1},
        ]);
        let arr = only_big.as_array().unwrap();
        assert!(pick_asset_for_target(arr, "linux", "mips", "musl", "little").is_none());
    }

    #[test]
    fn is_newer_mixed_length() {
        assert!(is_newer("1.2.3.4", "1.2.3"));
        assert!(!is_newer("1.2.3", "1.2.3.0"));
    }

    // Gated by an env var so CI doesn't hit the GitHub API on every run.
    #[tokio::test(flavor = "multi_thread")]
    async fn live_hit_github_if_enabled() {
        if std::env::var("RAHGOZAR_LIVE_UPDATE_CHECK").is_err() {
            eprintln!("skipping live update check (set RAHGOZAR_LIVE_UPDATE_CHECK=1 to run)");
            return;
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let result = check(Route::Direct).await;
        println!("live result: {:?}", result);
        let _ = result.summary();
    }
}
