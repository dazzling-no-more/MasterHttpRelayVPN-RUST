use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::config::Config;

const CANDIDATE_IPS: &[&str] = &[
    "216.239.32.120",
    "216.239.34.120",
    "216.239.36.120",
    "216.239.38.120",
    "216.58.212.142",
    "142.250.80.142",
    "142.250.80.138",
    "142.250.179.110",
    "142.250.185.110",
    "142.250.184.206",
    "142.250.190.238",
    "142.250.191.78",
    "172.217.1.206",
    "172.217.14.206",
    "172.217.16.142",
    "172.217.22.174",
    "172.217.164.110",
    "172.217.168.206",
    "172.217.169.206",
    "34.107.221.82",
    "142.251.32.110",
    "142.251.33.110",
    "142.251.46.206",
    "142.251.46.238",
    "142.250.80.170",
    "142.250.72.206",
    "142.250.64.206",
    "142.250.72.110",
];
pub const FAMOUS_GOOGLE_DOMAINS: &[&str] = &[
    // Core services
    "google.com",
    "www.google.com",
    "youtube.com",
    "www.youtube.com",
    "gmail.com",
    "www.gmail.com",
    "drive.google.com",
    "docs.google.com",
    "sheets.google.com",
    "slides.google.com",
    "maps.google.com",
    "www.maps.google.com",
    // Search & Discovery
    "search.google.com",
    "images.google.com",
    "www.images.google.com",
    "news.google.com",
    "www.news.google.com",
    "scholar.google.com",
    "www.scholar.google.com",
    "books.google.com",
    "translate.google.com",
    "www.translate.google.com",
    // Communication
    "mail.google.com",
    "chat.google.com",
    "meet.google.com",
    "hangouts.google.com",
    "voice.google.com",
    "allo.google.com",
    // Media & Entertainment
    "play.google.com",
    "music.google.com",
    "movies.google.com",
    "video.google.com",
    "videos.google.com",
    "photos.google.com",
    "picasa.google.com",
    "picasaweb.google.com",
    // Productivity
    "calendar.google.com",
    "keep.google.com",
    "contacts.google.com",
    "tasks.google.com",
    "forms.google.com",
    "sites.google.com",
    "www.sites.google.com",
    // Account & Settings
    "accounts.google.com",
    "myaccount.google.com",
    "myactivity.google.com",
    "passwords.google.com",
    "adssettings.google.com",
    // Business & Ads
    "ads.google.com",
    "adwords.google.com",
    "www.adwords.google.com",
    "adsense.google.com",
    "analytics.google.com",
    "business.google.com",
    "mybusiness.google.com",
    "merchants.google.com",
    // Developer & Cloud
    "console.cloud.google.com",
    "cloud.google.com",
    "firebase.google.com",
    "console.firebase.google.com",
    "developers.google.com",
    "console.developers.google.com",
    "apis.google.com",
    "fonts.google.com",
    // Mobile & Apps
    "android.google.com",
    "chrome.google.com",
    "chromebook.google.com",
    // Education & Learning
    "classroom.google.com",
    "edu.google.com",
    // Shopping & Payments
    "shopping.google.com",
    "pay.google.com",
    "payments.google.com",
    "wallet.google.com",
    "store.google.com",
    // Travel & Local
    "flights.google.com",
    "hotels.google.com",
    "travel.google.com",
    // Other Services
    "blogger.google.com",
    "domains.google.com",
    "trends.google.com",
    "alerts.google.com",
    "podcasts.google.com",
    "fit.google.com",
    "home.google.com",
    "assistant.google.com",
    "gemini.google.com",
    // Support & Info
    "support.google.com",
    "policies.google.com",
    "privacy.google.com",
    "about.google.com",
    "blog.google.com",
    // Legacy/Regional
    "plus.google.com",
    "www.plus.google.com",
    "orkut.google.com",
    "reader.google.com",
    "wave.google.com",
];

const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const CONCURRENCY: usize = 8;

struct Result_ {
    ip: String,
    latency_ms: Option<u128>,
    error: Option<String>,
}

pub async fn run(config: &Config) -> bool {
    let ips = fetch_google_ips(config).await;
    let google_ip_validation = config.google_ip_validation;
    let sni = config.front_domain.clone();
    println!(
        "Scanning {} Google frontend IPs (SNI={}, timeout={}s)...",
        ips.len(),
        sni,
        PROBE_TIMEOUT.as_secs()
    );
    println!();

    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = Vec::with_capacity(ips.len());
    for ip in &ips {
        let sni = sni.clone();
        let connector = connector.clone();
        let sem = sem.clone();
        let ip = ip.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit: Option<tokio::sync::SemaphorePermit<'_>> = sem.acquire().await.ok();
            probe(&ip, &sni, connector, google_ip_validation).await
        }));
    }

    let mut results: Vec<Result_> = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(r) = t.await {
            results.push(r);
        }
    }
    results.sort_by_key(|r| r.latency_ms.unwrap_or(u128::MAX));

    println!("{:<20} {:>12}   STATUS", "IP", "LATENCY");
    println!("{:-<20} {:->12}   -------", "", "");
    let mut ok_count = 0usize;
    for r in &results {
        match r.latency_ms {
            Some(ms) => {
                println!("{:<20} {:>10}ms   OK", r.ip, ms);
                ok_count += 1;
            }
            None => {
                let err = r.error.as_deref().unwrap_or("failed");
                println!("{:<20} {:>12}   {}", r.ip, "-", err);
            }
        }
    }
    println!();
    println!("{} / {} reachable. Fastest:", ok_count, results.len());
    for r in results.iter().filter(|r| r.latency_ms.is_some()).take(3) {
        println!("  {} ({} ms)", r.ip, r.latency_ms.unwrap());
    }
    println!();
    if ok_count == 0 {
        println!("No Google IPs reachable from this network.");
        false
    } else {
        println!("To use the fastest, set \"google_ip\" in config.json to the top result above.");
        true
    }
}

pub async fn fetch_google_ips(config: &Config) -> Vec<String> {
    if !config.fetch_ips_from_api {
        tracing::info!("fetch_ips_from_api disabled, using static fallback");
        return CANDIDATE_IPS.iter().map(|s| s.to_string()).collect();
    }

    match fetch_and_validate_google_ips(
        &config.front_domain,
        config.max_ips_to_scan,
        config.scan_batch_size,
        config.google_ip_validation,
    )
    .await
    {
        Ok(ips) if !ips.is_empty() => {
            tracing::info!("✓ Validated {} working IPs from goog.json", ips.len());
            ips
        }
        Ok(_) => {
            tracing::warn!("No working IPs found in goog.json, using static fallback");
            CANDIDATE_IPS.iter().map(|s| s.to_string()).collect()
        }
        Err(e) => {
            tracing::warn!(
                "Failed to fetch/validate Google IPs: {}, using static fallback",
                e
            );
            CANDIDATE_IPS.iter().map(|s| s.to_string()).collect()
        }
    }
}

/// Produce candidate Google front IPs WITHOUT validating them
/// against an SNI. Used by `rescan_and_pick`, which then runs its
/// own SNI-pool-aware validation pass — `fetch_google_ips`'s
/// implicit `validate_ips(&config.front_domain, ...)` would
/// pre-filter dynamic candidates against a SNI that may itself be
/// blocked for the user, throwing away IPs that would work against
/// their actual rotation pool. Honours the same `fetch_ips_from_api`
/// static-or-dynamic switch; falls back to the static `CANDIDATE_IPS`
/// list if dynamic discovery fails.
pub async fn fetch_google_ip_candidates(config: &Config) -> Vec<String> {
    if !config.fetch_ips_from_api {
        return CANDIDATE_IPS.iter().map(|s| s.to_string()).collect();
    }
    match discover_google_ip_candidates(config.max_ips_to_scan).await {
        Ok(ips) if !ips.is_empty() => ips,
        Ok(_) => {
            // Empty result means CIDR fetch returned but produced no
            // usable IPs (e.g. goog.json schema drift). Distinct from
            // the Err branch below so heartbeat-rescan debugging can
            // tell the two failure modes apart.
            tracing::debug!(
                "heartbeat candidate discovery returned empty CIDR set; \
                 using static CANDIDATE_IPS fallback"
            );
            CANDIDATE_IPS.iter().map(|s| s.to_string()).collect()
        }
        Err(e) => {
            // Network error reaching goog.json, DNS failure, etc.
            // Static fallback keeps the heartbeat functional even
            // when dynamic discovery is down — the user-facing
            // failure mode is "rescan picks from the 28 baked-in IPs
            // instead of the freshest CIDRs," which is far better
            // than "rescan errors out and stale IP stays active."
            tracing::debug!(
                "heartbeat candidate discovery failed: {}; \
                 using static CANDIDATE_IPS fallback",
                e
            );
            CANDIDATE_IPS.iter().map(|s| s.to_string()).collect()
        }
    }
}

/// Pure-discovery helper: pull Google CIDR blocks, expand to
/// individual IPs, shuffle, take up to `max_ips`. No validation —
/// callers decide which SNI(s) to test against.
async fn discover_google_ip_candidates(
    max_ips: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    build_candidate_ip_pool(max_ips).await
}

/// Shared discovery logic for both the user-facing `scan-ips`
/// subcommand and the background heartbeat rescan: resolve famous
/// Google IPs to map priority CIDR blocks, fetch the full CIDR list,
/// expand to individual IPs, shuffle priority + other lists, and
/// truncate to `max_ips` (priority entries first).
///
/// Intermediate progress is logged at `debug` so the heartbeat
/// rescan path stays quiet on default log levels; the user-facing
/// "Selected N IPs to test, testing in K batches..." line is logged
/// in `fetch_and_validate_google_ips` so it still shows up at info
/// level when a user runs `rahgozar scan-ips`.
async fn build_candidate_ip_pool(
    max_ips: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let famous_ips = resolve_famous_domains().await;
    tracing::debug!(
        "Resolved {} IPs from famous Google domains",
        famous_ips.len()
    );

    let cidrs = fetch_google_cidrs().await?;
    tracing::debug!("Fetched {} CIDR blocks from goog.json", cidrs.len());

    let priority_cidrs = find_matching_cidrs(&famous_ips, &cidrs);
    tracing::debug!("Found {} CIDRs containing famous IPs", priority_cidrs.len());

    let mut priority_ips = Vec::new();
    for cidr in &priority_cidrs {
        priority_ips.extend(cidr_to_ips(cidr));
    }
    let mut other_ips = Vec::new();
    for cidr in &cidrs {
        if !priority_cidrs.contains(cidr) {
            other_ips.extend(cidr_to_ips(cidr));
        }
    }
    tracing::debug!(
        "Extracted {} priority IPs and {} other IPs",
        priority_ips.len(),
        other_ips.len()
    );

    // Scope the rng so it's dropped before any subsequent `.await` — rand's
    // ThreadRng isn't Send, so holding it across an await would error out
    // the whole async fn's Send bound.
    {
        let mut rng = rand::thread_rng();
        priority_ips.shuffle(&mut rng);
        other_ips.shuffle(&mut rng);
    }

    let mut candidate_ips = Vec::new();
    candidate_ips.extend(priority_ips.into_iter().take(max_ips));
    if candidate_ips.len() < max_ips {
        let remaining = max_ips - candidate_ips.len();
        candidate_ips.extend(other_ips.into_iter().take(remaining));
    }
    if candidate_ips.is_empty() {
        return Err("No valid IPs extracted from CIDRs".into());
    }
    Ok(candidate_ips)
}

async fn fetch_and_validate_google_ips(
    sni: &str,
    max_ips: usize,
    batch_size: usize,
    google_ip_validation: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let candidate_ips = build_candidate_ip_pool(max_ips).await?;
    let total_batches = candidate_ips.len().div_ceil(batch_size);
    tracing::info!(
        "Selected {} IPs to test, testing in {} batches...",
        candidate_ips.len(),
        total_batches
    );

    let mut working_ips = Vec::new();
    let mut total_tested = 0;

    for (i, chunk) in candidate_ips.chunks(batch_size).enumerate() {
        let batch_working = validate_ips(chunk, sni, google_ip_validation).await;
        working_ips.extend(batch_working.clone());
        total_tested += chunk.len();

        tracing::info!(
            "Batch {}/{}: tested {} IPs, found {} working (total: {}/{})",
            i + 1,
            total_batches,
            chunk.len(),
            batch_working.len(),
            total_tested,
            candidate_ips.len()
        );
    }
    tracing::info!(
        "Found {} working IPs from {} tested",
        working_ips.len(),
        candidate_ips.len()
    );

    Ok(working_ips)
}

async fn resolve_famous_domains() -> Vec<String> {
    let mut ips = Vec::new();
    for domain in FAMOUS_GOOGLE_DOMAINS {
        match tokio::net::lookup_host(format!("{}:443", domain)).await {
            Ok(addrs) => {
                for addr in addrs {
                    if let SocketAddr::V4(v4) = addr {
                        ips.push(v4.ip().to_string());
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Failed to resolve {}: {}", domain, e);
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

fn find_matching_cidrs(ips: &[String], cidrs: &[String]) -> Vec<String> {
    let mut matches = Vec::new();
    for cidr in cidrs {
        for ip in ips {
            if ip_in_cidr(ip, cidr) {
                matches.push(cidr.clone());
                break;
            }
        }
    }
    matches
}

fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let base_ip = parts[0];
    let prefix_len: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let ip_num = match ip_to_u32(ip) {
        Some(n) => n,
        None => return false,
    };

    let base_num = match ip_to_u32(base_ip) {
        Some(n) => n,
        None => return false,
    };

    // Mask defends against /0 (shift-32 of u32 would panic in debug).
    let mask: u32 = if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    (ip_num & mask) == (base_num & mask)
}

fn ip_to_u32(ip: &str) -> Option<u32> {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }

    let o: Vec<u8> = octets.iter().filter_map(|s| s.parse().ok()).collect();
    if o.len() != 4 {
        return None;
    }

    Some(((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32))
}

async fn fetch_google_cidrs() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect("www.gstatic.com:443"),
    )
    .await??;

    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let server_name = ServerName::try_from("www.gstatic.com".to_string())?;

    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await??;

    let request = "GET /ipranges/goog.json HTTP/1.1\r\n\
                   Host: www.gstatic.com\r\n\
                   Connection: close\r\n\
                   \r\n";
    tls_stream.write_all(request.as_bytes()).await?;
    tls_stream.flush().await?;

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut buf = [0u8; 4096];
        loop {
            match tls_stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
    })
    .await?;

    let response_str = String::from_utf8_lossy(&response);
    let body = response_str
        .split("\r\n\r\n")
        .nth(1)
        .ok_or("No HTTP body found")?;

    let json: serde_json::Value = serde_json::from_str(body)?;
    let prefixes = json["prefixes"].as_array().ok_or("No prefixes array")?;

    let mut cidrs = Vec::new();
    for prefix in prefixes {
        if let Some(ipv4) = prefix["ipv4Prefix"].as_str() {
            cidrs.push(ipv4.to_string());
        }
    }

    Ok(cidrs)
}

fn cidr_to_ips(cidr: &str) -> Vec<String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Vec::new();
    }

    let base_ip = parts[0];
    let prefix_len: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let octets: Vec<&str> = base_ip.split('.').collect();
    if octets.len() != 4 {
        return Vec::new();
    }

    let o: Vec<u8> = match octets.iter().map(|s| s.parse()).collect() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let base = ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32);
    if prefix_len > 32 {
        return Vec::new();
    }
    let host_bits = 32 - prefix_len;
    let num_hosts: u32 = if host_bits >= 32 {
        u32::MAX
    } else {
        1u32 << host_bits
    };

    let limit = num_hosts.min(256);
    if limit < 2 {
        return Vec::new();
    }

    (1..limit - 1)
        .map(|i| {
            let ip = base + i;
            format!(
                "{}.{}.{}.{}",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF
            )
        })
        .collect()
}

async fn validate_ips(ips: &[String], sni: &str, google_ip_validation: bool) -> Vec<String> {
    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = Vec::new();

    for ip in ips {
        let ip = ip.clone();
        let sni = sni.to_string();
        let connector = connector.clone();
        let sem = sem.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            let result = quick_probe(&ip, &sni, connector, google_ip_validation).await;
            (ip, result)
        }));
    }

    let mut working = Vec::new();
    for task in tasks {
        if let Ok((ip, true)) = task.await {
            working.push(ip);
        }
    }

    working
}
/// Single-IP TCP+TLS+HEAD probe with the standard `gws` / `x-google-`
/// header validation, used by the background heartbeat loop in
/// `domain_fronter` to confirm the active front IP is still
/// reachable.
///
/// `verify_ssl` mirrors the relay's `config.verify_ssl`: when on,
/// the probe uses the system root CA store, matching what real
/// connections do — otherwise the heartbeat could mark an IP
/// healthy that fails cert validation on the relay path (e.g. an
/// ISP-injected MITM that completes the TLS handshake but presents
/// a non-Google cert). When off, the probe uses `NoVerify` to mirror
/// the relay's "skip verification" mode.
///
/// Builds a fresh TLS connector each call so callers don't have to
/// thread one through; this costs ~one alloc per probe which is well
/// below the heartbeat interval's noise floor.
pub async fn heartbeat_probe(
    ip: &str,
    sni: &str,
    google_ip_validation: bool,
    verify_ssl: bool,
) -> bool {
    let tls_cfg = if verify_ssl {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    quick_probe(ip, sni, connector, google_ip_validation).await
}

/// Re-scan candidate Google front IPs and return the first reachable
/// one, used by the background heartbeat loop when the active IP fails
/// `heartbeat_failure_threshold` consecutive probes. Mirrors the IP set
/// `run()` would scan (config-driven static fallback or goog.json
/// dynamic, whichever the config selects).
///
/// `probe_snis` is the candidate SNI pool to validate against. A
/// candidate IP counts as reachable as soon as ANY listed SNI gets a
/// healthy probe response — that mirrors what real connections do
/// (the relay rotates through `sni_hosts`), so users who configured a
/// custom SNI pool specifically because `front_domain` is blocked
/// can still recover. Pass `&[config.front_domain.clone()]` to opt
/// out of rotation. An empty slice degenerates to no-op (None).
/// Returns `None` when no candidate is reachable — caller should
/// retain the current IP and keep probing rather than swap to
/// nothing.
pub async fn rescan_and_pick(config: &Config, probe_snis: &[String]) -> Option<String> {
    if probe_snis.is_empty() {
        return None;
    }
    // Use the unvalidated candidate fetcher rather than
    // `fetch_google_ips`, which pre-validates against
    // `config.front_domain`. If the user's front_domain is itself
    // blocked (the whole reason they configured a custom
    // `sni_hosts` pool), that pre-validation throws away IPs that
    // would in fact work against their actual rotation pool. The
    // SNI-loop below is our validation step instead.
    let ips = fetch_google_ip_candidates(config).await;
    // Honour `scan_batch_size` so the heartbeat doesn't burst more
    // simultaneous handshakes than the user-tunable `scan-ips`
    // subcommand would. Users who lowered the batch size to reduce
    // network burstiness expect that to apply to the background
    // rescan too. `validate_ips` already caps concurrency at
    // CONCURRENCY within each batch, so this only affects how many
    // batches we issue back-to-back. Each batch checks all SNIs
    // before moving on, and we short-circuit as soon as any
    // (IP, SNI) pair handshakes successfully — typical case
    // terminates inside the first batch.
    let batch_size = config.scan_batch_size.max(1);
    for chunk in ips.chunks(batch_size) {
        for sni in probe_snis {
            let working = validate_ips(chunk, sni, config.google_ip_validation).await;
            if let Some(ip) = working.into_iter().next() {
                return Some(ip);
            }
        }
    }
    None
}

async fn quick_probe(
    ip: &str,
    sni: &str,
    connector: TlsConnector,
    google_ip_validation: bool,
) -> bool {
    let addr: SocketAddr = match format!("{}:443", ip).parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let tcp = match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(t)) => t,
        _ => return false,
    };

    let server_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(_) => return false,
    };

    let mut tls =
        match tokio::time::timeout(Duration::from_secs(2), connector.connect(server_name, tcp))
            .await
        {
            Ok(Ok(t)) => t,
            _ => return false,
        };

    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        sni
    );
    if tls.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let _ = tls.flush().await;

    let mut buf = [0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);

            if !response.starts_with("HTTP/") {
                return false;
            }

            if google_ip_validation {
                let lower = response.to_lowercase();
                return lower.contains("server: gws")
                    || lower.contains("x-google-")
                    || lower.contains("alt-svc: h3=");
            }
            true
        }
        _ => false,
    }
}

async fn probe(
    ip: &str,
    sni: &str,
    connector: TlsConnector,
    google_ip_validation: bool,
) -> Result_ {
    let start = Instant::now();
    let addr: SocketAddr = match format!("{}:443", ip).parse() {
        Ok(a) => a,
        Err(e) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some(e.to_string()),
            }
        }
    };

    let tcp = match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some(format!("connect: {}", e)),
            }
        }
        Err(_) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some("timeout".into()),
            }
        }
    };
    let _ = tcp.set_nodelay(true);

    let server_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(e) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some(format!("bad sni: {}", e)),
            }
        }
    };

    let mut tls =
        match tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                return Result_ {
                    ip: ip.into(),
                    latency_ms: None,
                    error: Some(format!("tls: {}", e)),
                }
            }
            Err(_) => {
                return Result_ {
                    ip: ip.into(),
                    latency_ms: None,
                    error: Some("tls timeout".into()),
                }
            }
        };

    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        sni
    );
    if tls.write_all(req.as_bytes()).await.is_err() {
        return Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some("write failed".into()),
        };
    }
    let _ = tls.flush().await;

    let mut buf = [0u8; 1024];
    match tokio::time::timeout(PROBE_TIMEOUT, tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);

            if !response.starts_with("HTTP/") {
                return Result_ {
                    ip: ip.into(),
                    latency_ms: None,
                    error: Some("bad reply".into()),
                };
            }

            let lower = response.to_lowercase();
            let mut is_google = true;
            if google_ip_validation {
                is_google = lower.contains("server: gws")
                    || lower.contains("x-google-")
                    || lower.contains("alt-svc: h3=");
            }

            if is_google {
                let elapsed = start.elapsed().as_millis();
                Result_ {
                    ip: ip.into(),
                    latency_ms: Some(elapsed),
                    error: None,
                }
            } else {
                Result_ {
                    ip: ip.into(),
                    latency_ms: None,
                    error: Some("not google frontend".into()),
                }
            }
        }
        Ok(Ok(_)) => Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some("empty reply".into()),
        },
        Ok(Err(e)) => Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some(format!("read: {}", e)),
        },
        Err(_) => Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some("read timeout".into()),
        },
    }
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
