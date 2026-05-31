use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
// AtomicU64 polyfill — same reason `cache.rs` and `domain_fronter.rs`
// use this: mipsel-unknown-linux-musl is MIPS32 without native 64-bit
// atomics, so `std::sync::atomic::AtomicU64` doesn't resolve. The
// `coalesce_*_ms` fields below need 64-bit width because that's what
// `TunnelMux::start` takes, and they need atomic interior mutability
// because `switch_mode` updates them in place when the user edits the
// values and toggles into Full mode mid-session.
use bytes::Bytes;
use portable_atomic::AtomicU64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};

use crate::config::{Config, FrontingGroup, Mode};
use crate::domain_fronter::DomainFronter;
use crate::mitm::MitmCertManager;
use crate::tunnel_client::{decode_udp_packets, TunnelMux};

// Domains that are served from Google's core frontend IP pool and therefore
// respond correctly when we connect to `google_ip` with SNI=`front_domain`
// and Host=<the real domain>. Routing these via the tunnel instead of the
// Apps Script relay also avoids Apps Script's fixed "Google-Apps-Script"
// User-Agent, which makes Google serve the bot/no-JS fallback for search.
// Kept conservative: anything on a separate CDN (googlevideo, ytimg,
// doubleclick, etc.) is DROPPED because routing to the wrong backend breaks
// rather than helps. Those fall through to MITM+relay (slower but works).
// Domains that are hosted on the Google Front End and therefore reachable via
// the same SNI-rewrite tunnel used for www.google.com itself. Adding a suffix
// here means "TLS CONNECT to google_ip, SNI = front_domain, Host = real name"
// for requests to it — bypassing the Apps Script relay entirely, so there's no
// User-Agent locking and no Apps Script quota.
// When in doubt leave it out: sites that aren't actually on GFE will 404 or
// return a wrong-cert error instead of loading.
const SNI_REWRITE_SUFFIXES: &[&str] = &[
    // Core Google
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "googleapis.com",
    "ggpht.com",
    // YouTube family
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "ytimg.com",
    // NOTE on `googlevideo.com`: v1.7.4 (#275) added this here on the
    // theory that video chunks should bypass the Apps Script relay.
    // **Reverted in v1.7.6** — multiple users (#275 amirabbas117, #281
    // mrerf) reported total YouTube breakage after v1.7.4. Root cause
    // is that googlevideo.com is served by Google's separate "EVA"
    // edge IPs, not the regular GFE IPs that the user's `google_ip`
    // typically points at. SNI-rewriting `googlevideo.com:443` to a
    // GFE IP got TLS handshake / wrong-cert errors for those users.
    // Pre-v1.7.4 behaviour (chunks via the Apps Script relay path —
    // slow but reliable on every GFE IP) is restored. If we ever want
    // direct googlevideo.com routing, it needs a separate config knob
    // that lets users specify their EVA edge IP independently.
    // Google Video Transport CDN — YouTube video chunks, Chrome
    // auto-updates, Google Play Store downloads. The single biggest
    // gap vs the upstream Python port: without these in the list
    // YouTube video playback stalls because every chunk tries to
    // traverse Apps Script instead of the direct GFE tunnel.
    "gvt1.com",
    "gvt2.com",
    // Ad + analytics infra. All on GFE, all previously broken the
    // same way YouTube was: SNI-blocked on Iranian DPI, but reachable
    // via `google_ip` with SNI rewritten.
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    // fonts.googleapis.com is technically covered by the googleapis.com
    // suffix above, but mirroring Python's explicit listing makes the
    // intent obvious at a glance.
    "fonts.googleapis.com",
    // Blogger / Blog.google
    "blogspot.com",
    "blogger.com",
];

/// YouTube hosts that should be routed through the Apps Script relay
/// when `youtube_via_relay` is enabled — the API + HTML surfaces where
/// Restricted Mode is actually enforced (via the SNI=www.google.com
/// edge looking at the request). Issue #102 / #275.
///
/// Deliberately narrower than the YouTube section of
/// `SNI_REWRITE_SUFFIXES`:
///   - `youtube.com` / `youtu.be` / `youtube-nocookie.com`: HTML pages
///     and player frames. These trigger Restricted Mode if served via
///     the SNI rewrite, so when the flag is on we relay them.
///   - `youtubei.googleapis.com`: the YouTube data API the player
///     queries for video metadata + manifest. Restricted Mode also
///     gates video availability here. Without this entry, the JSON
///     RPC layer would still hit the SNI-rewrite tunnel via the
///     broader `googleapis.com` suffix — the user-visible symptom of
///     that miss is "youtube_via_relay flips on but Restricted Mode
///     stays sticky on some videos."
///
/// **NOT** in this list (intentional, was a regression in #275):
///   - `ytimg.com`: thumbnails. No Restricted Mode logic on a static
///     image CDN; routing through Apps Script makes thumbnails slow
///     for zero gain.
///   - `googlevideo.com`: video chunk CDN. Routing through Apps Script
///     means every chunk eats Apps Script quota *and* risks the 6-min
///     execution cap aborting long videos mid-playback.
///   - `ggpht.com`: channel/profile images, same reasoning as ytimg.
const YOUTUBE_RELAY_HOSTS: &[&str] = &[
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
];

/// URL path-prefix patterns that are forced through the Apps Script relay.
/// Each entry is `host/path-prefix` (no scheme, lowercase). The host is
/// pulled out of `SNI_REWRITE_SUFFIXES` so the proxy MITMs and can inspect
/// paths; only URLs starting with the pattern go to relay, all other paths
/// on that host fall through to the SNI-rewrite HTTP forwarder
/// (`forward_via_sni_rewrite_http`) — same SNI-rewrite trick as the
/// CONNECT-tunnel path, but applied at the HTTP layer so we keep MITM
/// for the matching paths. User-supplied entries from
/// `Config::relay_url_patterns` are appended to this default.
///
/// `youtube.com/youtubei/`: YouTube's in-page RPC layer. Restricted Mode /
/// SafeSearch / live-stream gating decisions land here. Relaying just
/// this prefix recovers the SafeSearch fix that previously required the
/// full `youtube_via_relay = true` knob (which routed every static
/// asset through the relay too). Ported from upstream
/// `RELAY_URL_PATTERNS` (commit b3b9220).
const DEFAULT_RELAY_URL_PATTERNS: &[&str] = &["youtube.com/youtubei/"];

/// Built-in list of DNS-over-HTTPS endpoints. CONNECTs to these (when
/// `tunnel_doh` is left at the default of `false`, i.e. bypass enabled)
/// skip the Apps Script tunnel and exit via plain TCP. Mix of the
/// browser-pinned variants Chrome/Brave/Edge/Firefox/Safari use and the
/// well-known public DoH providers users wire up by hand. Suffix
/// matching means we don't need to enumerate every tenant subdomain
/// (e.g. `*.cloudflare-dns.com` covers Workers-hosted DoH too).
///
/// Entries are matched case-insensitively. Both exact-match (`dns.google`)
/// and dot-anchored suffix-match (a host whose suffix is `.cloudflare-dns.com`
/// or which equals `cloudflare-dns.com`) are accepted — same shape as
/// `passthrough_hosts`'s `.foo` rule.
const DEFAULT_DOH_HOSTS: &[&str] = &[
    // The base SLD covers every tenant subdomain via suffix matching;
    // the browser-pinned variants below are listed for grep/discovery
    // (so a user searching "chrome.cloudflare-dns.com" finds this list)
    // and are technically redundant under cloudflare-dns.com.
    "cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "dns11.quad9.net",
    "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    "family.adguard-dns.com",
    "dns.nextdns.io",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "doh.dns.sb",
    "dns0.eu",
    "dns.alidns.com",
    "doh.pub",
    "dns.mullvad.net",
];

fn matches_sni_rewrite(host: &str, youtube_via_relay: bool, force_mitm_hosts: &[String]) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');

    // YouTube relay carve-out runs FIRST so it wins over the broad
    // `googleapis.com` suffix that would otherwise pull
    // `youtubei.googleapis.com` into the SNI-rewrite path. The earlier
    // implementation iterated SNI_REWRITE_SUFFIXES with a filter, which
    // works for sibling entries (e.g. `youtube.com` in both lists) but
    // not for nested ones (`youtubei.googleapis.com` matches the broad
    // `googleapis.com` even when its specific entry is filtered out).
    // The short-circuit here is unconditional — we don't need to check
    // SNI rewrite once we've decided this host goes to the relay.
    if youtube_via_relay {
        for s in YOUTUBE_RELAY_HOSTS {
            if h == *s || h.ends_with(&format!(".{}", s)) {
                return false;
            }
        }
    }

    // Hosts pulled out of SNI-rewrite by `relay_url_patterns` (b3b9220).
    // We need to MITM these so the per-path matcher in
    // `handle_mitm_request` can decide between relay and the SNI-rewrite
    // HTTP forwarder. Match shape MUST match `host_in_force_mitm_list`
    // exactly — otherwise a host pulled out here wouldn't be recognised
    // at dispatch and the path filter would silently no-op, which was a
    // real bug in the first cut where this list also matched in the
    // reverse direction (`forced.ends_with(.h)`). Reverse-matching
    // pulled parent SNI suffixes for entries like `studio.youtube.com`,
    // making the entire `youtube.com` subtree skip SNI-rewrite while
    // dispatch only force-MITM-recognised the literal `studio.youtube.com`.
    // One-directional match (`h == forced || h.ends_with(.forced)`)
    // pulls only the configured host and its subdomains, leaving sibling
    // subdomains on the natural SNI-rewrite path.
    for forced in force_mitm_hosts {
        if h == *forced || h.ends_with(&format!(".{}", forced)) {
            return false;
        }
    }

    SNI_REWRITE_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

/// True if `url` matches any entry in `patterns`. Each pattern is
/// `host/path-prefix` (no scheme, lowercase). The URL host may have extra
/// subdomains — `www.youtube.com` matches `youtube.com/youtubei/`. Path
/// match is a plain prefix on the URL's path component.
///
/// Same matching shape as the upstream Python `_url_matches_relay_pattern`
/// (b3b9220): scheme stripped, lowercased, host suffix-anchored, path
/// `startswith`. Used in MITM dispatch to decide relay vs. SNI-rewrite
/// HTTP forward for hosts pulled out of SNI-rewrite.
pub(crate) fn url_matches_relay_pattern(url: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    let stripped = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let (raw_host, url_path) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]),
        None => (stripped, "/"),
    };
    // Strip an authority's port (`:443`) and any FQDN trailing dot so
    // `www.youtube.com.` and `www.youtube.com:443` canonicalise to the
    // same form that `host_in_force_mitm_list` and `extract_host` use.
    // Without this, dispatch and pattern-match disagree: the host is
    // pulled from SNI-rewrite but its `/youtubei/` URL fails the
    // pattern check and ends up routed via the SNI-HTTP forwarder.
    let host_no_port = raw_host.split(':').next().unwrap_or(raw_host);
    let url_host = host_no_port.trim_end_matches('.');
    for p in patterns {
        let (pat_host, pat_path) = match p.find('/') {
            Some(i) => (&p[..i], &p[i..]),
            None => (p.as_str(), "/"),
        };
        let host_match = url_host == pat_host || url_host.ends_with(&format!(".{}", pat_host));
        if host_match && url_path.starts_with(pat_path) {
            return true;
        }
    }
    false
}

/// True if the request's host is one we pulled out of SNI-rewrite to
/// support `relay_url_patterns`. Used in `handle_mitm_request` as the
/// gate for the SNI-rewrite-HTTP fallback path: if the host was forced
/// to MITM but the URL didn't match any pattern, we forward over a fresh
/// SNI-rewrite TLS connection instead of burning Apps Script quota.
pub(crate) fn host_in_force_mitm_list(host: &str, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    list.iter()
        .any(|forced| h == *forced || h.ends_with(&format!(".{}", forced)))
}

fn hosts_override<'a>(
    hosts: &'a std::collections::HashMap<String, String>,
    host: &str,
) -> Option<&'a str> {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if let Some(ip) = hosts.get(h) {
        return Some(ip.as_str());
    }
    let parts: Vec<&str> = h.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if let Some(ip) = hosts.get(&parent) {
            return Some(ip.as_str());
        }
    }
    None
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// `switch_mode` was called after the proxy was asked to stop. The
    /// runtime intentionally treats this as a no-op (the lifecycle is
    /// "switch ignored because the proxy is going away anyway"), so
    /// callers should *not* surface this to the user as a failure. The
    /// UI background thread, for example, suppresses the toast for
    /// this variant and only logs a debug line.
    ///
    /// Marked `#[non_exhaustive]` on the enum so downstream `match`es
    /// remain forward-compatible — every new variant becomes a wildcard
    /// for them, not a hard break.
    #[error("proxy is shutting down; operation ignored")]
    ShuttingDown,
}

pub struct ProxyServer {
    /// Shared, swappable state. The same `Arc<RuntimeState>` handed back
    /// to the UI so a live mode switch can rebuild the bundle while the
    /// listeners stay bound (see `RuntimeState::switch_mode`).
    state: Arc<RuntimeState>,
}

/// Mode-dependent state read by the accept path. Bundled into one
/// `Arc<ModeBundle>` (wrapped in [`ArcSwap`]) so each accepted connection
/// reads a self-consistent (ctx, fronter, mux) triple with one atomic op —
/// without that, a switch_mode racing an accept could pair the new
/// `RewriteCtx::mode` with the old `fronter`, and `handle_mitm_request`
/// would fall through its "apps_script mode with no fronter" defensive
/// branch.
///
/// Visibility is `pub(crate)`: callers outside this crate must go through
/// `RuntimeState::current_mode` / `RuntimeState::fronter` accessors, not
/// poke at the bundle directly. Constructing a new bundle from outside
/// would let a caller bypass `switch_lock` and `mode_tasks` cleanup —
/// every legitimate path to a new bundle runs under `switch_mode`.
pub(crate) struct ModeBundle {
    pub(crate) rewrite_ctx: Arc<RewriteCtx>,
    /// `None` in `direct` mode: no Apps Script relay is wired up,
    /// only the SNI-rewrite tunnel path (Google edge + any configured
    /// `fronting_groups`) is live.
    pub(crate) fronter: Option<Arc<DomainFronter>>,
    /// `Some` only in `full` mode — the tunnel mux is what carries
    /// end-to-end-encrypted traffic to the tunnel node.
    pub(crate) tunnel_mux: Option<Arc<TunnelMux>>,
    /// `Some` only in `drive` mode — the Drive-mailbox mux runs the
    /// shared poller against Google Drive's REST API and dispatches
    /// inbound frames to per-session queues. Mutually exclusive with
    /// `tunnel_mux` (the two modes can't both be active at once,
    /// since `Mode` is a single enum value).
    pub(crate) drive_mux: Option<Arc<crate::drive_client::DriveMux>>,
}

/// Mode-dependent background tasks tied to the *current* `fronter`/`mux`.
/// Aborted on shutdown and on every `switch_mode` so the old fronter's
/// keepalive pings don't keep hitting Apps Script after the user has
/// switched away from `apps_script` mode.
#[derive(Default)]
struct ModeTasks {
    keepalive: Option<tokio::task::JoinHandle<()>>,
    refill: Option<tokio::task::JoinHandle<()>>,
    stats: Option<tokio::task::JoinHandle<()>>,
    /// One-shot pool prewarm. Exits naturally after a few seconds, but
    /// repeated mode switches inside that window would otherwise leave
    /// overlapping warmups holding old `Arc<DomainFronter>`s. Tracking
    /// it here lets `abort_all` reap them cleanly on switch / shutdown.
    warm: Option<tokio::task::JoinHandle<()>>,
    /// Blacklist re-probe loop. Periodically HEADs `example.com`
    /// through each probe-recoverable blacklisted SID so a recovered
    /// deployment re-enters the rotation pool ahead of its static
    /// cooldown TTL. The spawn happens unconditionally for any
    /// `apps_script`-mode startup; `run_probe_loop` itself returns
    /// immediately when only one script ID is configured (probing the
    /// single deployment that already failed would just burn more of
    /// the same quota), so the JoinHandle exists but its future ends
    /// without doing any work. `abort_all` reaps it like the other
    /// optional handles.
    probe: Option<tokio::task::JoinHandle<()>>,
    /// Heartbeat loop for the active Google front IP. Probes the
    /// current `connect_host` on a fixed interval and swaps in a fresh
    /// candidate via `scan_ips::rescan_and_pick` after
    /// `heartbeat_failure_threshold` consecutive failures.
    ///
    /// Spawned for **every mode that has a `DomainFronter`** — both
    /// `apps_script` and `full`. Full mode's `TunnelMux` makes Apps
    /// Script calls through the same `connect_host` Google front IP,
    /// so an ISP-newly-filtered datacenter range breaks Full mode the
    /// same way it breaks apps_script: every tunnel batch fails until
    /// the user restarts and re-runs `scan-ips`. Sharing the heartbeat
    /// across both modes recovers Full mode users automatically
    /// instead of leaving them with the worse failure mode. `direct`
    /// mode has no fronter and no Apps Script dependency, so the task
    /// isn't spawned there.
    ///
    /// `run_ip_health` itself returns immediately when the user has
    /// set `heartbeat_enabled = false`, so the JoinHandle exists but
    /// the future ends without work.
    health: Option<tokio::task::JoinHandle<()>>,
}

impl ModeTasks {
    fn abort_all(&mut self) {
        if let Some(h) = self.keepalive.take() {
            h.abort();
        }
        if let Some(h) = self.refill.take() {
            h.abort();
        }
        if let Some(h) = self.stats.take() {
            h.abort();
        }
        if let Some(h) = self.warm.take() {
            h.abort();
        }
        if let Some(h) = self.probe.take() {
            h.abort();
        }
        if let Some(h) = self.health.take() {
            h.abort();
        }
    }
    fn is_empty(&self) -> bool {
        self.keepalive.is_none()
            && self.refill.is_none()
            && self.stats.is_none()
            && self.warm.is_none()
            && self.probe.is_none()
            && self.health.is_none()
    }
}

/// The live, runtime-mutable handle to a started proxy. Owns the swappable
/// `ModeBundle` plus the listen address and the MITM CA. The UI holds an
/// `Arc<RuntimeState>` alongside the proxy's `JoinHandle`, so a mode-switch
/// command can call `switch_mode` from outside the run task.
pub struct RuntimeState {
    host: String,
    port: u16,
    socks5_port: u16,
    /// Crate-private so external callers can't bypass `switch_lock` /
    /// `mode_tasks` cleanup by `store()`-ing a hand-rolled bundle.
    /// Read access goes through accessors (`current_mode`, `fronter`)
    /// or, on the hot path, the accept loops which load the snapshot
    /// once per accepted connection.
    pub(crate) bundle: ArcSwap<ModeBundle>,
    mitm: Arc<Mutex<MitmCertManager>>,
    mode_tasks: Mutex<ModeTasks>,
    /// Current `TunnelMux` coalesce knobs. Atomic + interior-mutable
    /// because `switch_mode` updates them from `new_config` so a live
    /// switch into Full mode picks up the latest values, not the ones
    /// captured at `RuntimeState::new` time. Read by both `run()`
    /// (startup mux init) and `switch_mode` (post-swap mux init), both
    /// under `switch_lock`, so plain `Relaxed` ordering suffices.
    coalesce_step_ms: AtomicU64,
    coalesce_max_ms: AtomicU64,
    /// Serialises the short live-state swap/cleanup critical section
    /// against the run-task's shutdown path, so a detached switch-task
    /// spawned from the UI can't race past shutdown and re-spawn fresh
    /// fronter tasks after Stop.
    switch_lock: Mutex<()>,
    /// Serialises live switch requests across their pre-build phase. A
    /// Drive switch may refresh OAuth before it is ready to swap state;
    /// keeping that wait out of `switch_lock` lets shutdown proceed, while
    /// this mutex preserves "one switch at a time" ordering.
    switch_serial_lock: Mutex<()>,
    /// Set during the shutdown arm of `run()` (under `switch_lock`). Any
    /// subsequent `switch_mode` checks this immediately after acquiring
    /// `switch_lock` and bails — guaranteeing no new tasks get spawned
    /// after Stop has aborted the current ones.
    stopped: AtomicBool,
    /// Latest config snapshot, kept so background tasks spawned via
    /// `spawn_mode_tasks` (currently `run_ip_health`) can read
    /// scan/heartbeat knobs without RuntimeState having to thread
    /// every field individually. `switch_mode` overwrites this on
    /// every successful swap so a heartbeat task spawned after a
    /// switch sees the new config; tasks spawned earlier captured
    /// the prior snapshot at spawn time and aren't retroactively
    /// updated (mirrors `run_pool_refill` / `run_probe_loop`).
    config: ArcSwap<Config>,
}

pub struct RewriteCtx {
    pub google_ip: String,
    pub front_domain: String,
    pub hosts: std::collections::HashMap<String, String>,
    pub tls_connector: TlsConnector,
    pub upstream_socks5: Option<String>,
    pub mode: Mode,
    /// If true, YouTube traffic bypasses the SNI-rewrite tunnel and
    /// goes through the Apps Script relay instead. Effective value:
    /// `config.youtube_via_relay || (apps_script + exit_node.full)` —
    /// when the exit node is in full mode it must intercept all traffic
    /// including YouTube, so YT hosts get pulled from SNI-rewrite the
    /// same way the explicit toggle does it. Ported from upstream
    /// commit 88b2767. Issue #102.
    pub youtube_via_relay: bool,
    /// Resolved URL path-prefix patterns (`host/path-prefix`, lowercase,
    /// no scheme) that force the relay path inside MITM. Built at
    /// startup from `DEFAULT_RELAY_URL_PATTERNS` plus
    /// `Config::relay_url_patterns`. Empty when
    /// `youtube_via_relay = true` because YouTube is then fully relayed
    /// already and the per-path filter would just be redundant. Used
    /// by `handle_mitm_request` to decide relay vs. SNI-rewrite HTTP
    /// forward. Ported from upstream `_relay_url_patterns` (b3b9220).
    pub relay_url_patterns: Vec<String>,
    /// Hosts derived from `relay_url_patterns` that get pulled out of
    /// `SNI_REWRITE_SUFFIXES` so the proxy MITMs them and the per-path
    /// matcher can run. Lowercase, no scheme. Empty when
    /// `relay_url_patterns` is empty. Used in `matches_sni_rewrite`
    /// and `host_in_force_mitm_list`.
    pub force_mitm_hosts: Vec<String>,
    /// Set when `mode == AppsScript && exit_node.enabled &&
    /// exit_node.mode == "full"` — the same condition that promotes
    /// `youtube_via_relay_effective` (commit 88b2767). When true,
    /// `handle_mitm_request` MUST NOT use `forward_via_sni_rewrite_http`
    /// for non-matching paths, even on hosts in `force_mitm_hosts` —
    /// the forwarder dials the Google edge directly, which would
    /// completely bypass the second-hop exit node and violate the
    /// documented "every URL routes through the exit node" contract
    /// (`DomainFronter::exit_node_matches`). User-supplied
    /// `relay_url_patterns` are still honoured: matching paths and
    /// non-matching paths both end up in `DomainFronter::relay`,
    /// which then routes through the exit node.
    pub exit_node_full_mode_active: bool,
    /// User-configured hostnames that should skip the relay entirely
    /// and pass through as plain TCP (optionally via upstream_socks5).
    /// See config.rs `passthrough_hosts` for matching rules. Issues #39, #127.
    pub passthrough_hosts: Vec<String>,
    /// If true, drop SOCKS5 UDP datagrams destined for port 443 so
    /// callers fall back to TCP/HTTPS. See config.rs `block_quic` for
    /// the trade-off. Issue #213.
    pub block_quic: bool,
    pub block_stun: bool,
    /// If true, route DoH CONNECTs around the Apps Script tunnel via
    /// plain TCP. Default false via `Config::tunnel_doh = true` (flipped
    /// in v1.9.0, issue #468). See `DEFAULT_DOH_HOSTS` and
    /// `matches_doh_host` for matching, and config.rs `tunnel_doh` for
    /// the trade-off.
    pub bypass_doh: bool,
    /// When true, immediately reject connections to known DoH hosts.
    /// Takes priority over bypass_doh.
    pub block_doh: bool,
    /// User-supplied DoH hostnames added to the built-in default list.
    /// Same matching semantics as `passthrough_hosts`.
    pub bypass_doh_hosts: Vec<String>,
    /// Multi-edge fronting groups, resolved at startup. Each group's
    /// `ServerName` is parsed once so the per-connection dial path
    /// is allocation-free. Wrapped in `Arc` so a per-CONNECT match
    /// can hand the dispatcher a refcount-clone instead of cloning
    /// the whole struct (which holds a `Vec<String>` of normalized
    /// domains used only for matching). Empty = feature off (only
    /// the built-in Google edge SNI-rewrite is active).
    pub fronting_groups: Vec<Arc<FrontingGroupResolved>>,
    /// TLS-fragmentation Direct Mode runtime context. `None` when the
    /// feature is disabled in config or there are no usable fronts.
    /// Wins over `fronting_groups` and the built-in SNI-rewrite list
    /// when the host matches its Google-suffix list — but falls back
    /// to those paths if every fragmented dial fails, so existing
    /// SNI-rewrite-only users see no regression on networks where
    /// fragmentation can't beat DPI.
    pub direct_mode: Option<Arc<crate::direct_mode::DirectModeCtx>>,
    /// Poison-safe DoH resolver used by `force_ip` (camouflage) fronting
    /// groups to find the destination's real IP without trusting the
    /// (likely poisoned) system resolver. `None` if no `force_ip` group
    /// is configured or the camouflage connector failed to build at
    /// startup. When DoH can't resolve a host (resolver `None`, query
    /// failure, empty answer) the dispatcher does NOT consume the socket
    /// — it falls through to the normal routing (relay in apps_script,
    /// raw-TCP in direct). `do_camouflage_tunnel` likewise establishes
    /// the upstream *before* MITM-accepting the browser and hands the
    /// socket back on a total upstream failure, so an IP-blocked /
    /// wrong-cert destination also falls through rather than dropping the
    /// CONNECT. Built once, shared.
    pub doh_resolver: Option<Arc<crate::doh::DohResolver>>,
}

type ModeState = (Option<Arc<DomainFronter>>, Arc<RewriteCtx>, Mode);
type HeaderList = Vec<(String, String)>;
type ParsedRequestHead = (String, String, String, HeaderList);

/// One-shot resolution of the YouTube routing knobs (`youtube_via_relay`,
/// `relay_url_patterns`, `exit_node.mode == "full"`) for a given
/// `Config` + `Mode`. Pulled out of `ProxyServer::new` so it can be
/// unit-tested directly without spinning up the full proxy.
///
/// Two gates govern the resolved patterns:
///
/// 1. **Mode gate** — only `apps_script` mode has a relay path to route
///    patterns through. In `direct` mode there's no Apps Script, so
///    pulling hosts out of SNI-rewrite would just send them to raw-TCP
///    fallback (a routing regression). In `full` mode the dispatcher
///    short-circuits to the tunnel mux before MITM ever runs, so
///    patterns would never be consulted. Outside `apps_script` the
///    resolved sets are always empty.
///
/// 2. **youtube_via_relay-effective gate** — the explicit
///    `youtube_via_relay` toggle OR exit-node-full mode (commit 88b2767).
///    When *either* is on, YouTube is fully relayed already, so the
///    per-path filter is redundant. Worse, in exit-node-full mode the
///    filter is *harmful*: non-matching paths on `youtube.com` would
///    route via `forward_via_sni_rewrite_http`, bypassing
///    `DomainFronter::relay` and with it the exit node — defeating
///    the whole point of full mode.
///
/// User-supplied `relay_url_patterns` entries always run inside
/// `apps_script` mode regardless of the YT flag; they may target hosts
/// other than `youtube.com` that the user wants path-pinned
/// independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedRouting {
    /// Effective `youtube_via_relay` after OR-ing with exit-node-full
    /// mode. Mirrors what `RewriteCtx::youtube_via_relay` ends up with.
    pub youtube_via_relay_effective: bool,
    /// Resolved patterns, lowercased, scheme-stripped, deduplicated.
    /// Empty outside `apps_script` mode and when both gates above
    /// allow the defaults to be skipped.
    pub relay_url_patterns: Vec<String>,
    /// Host parts of `relay_url_patterns` that ARE
    /// SNI-rewrite-capable. Pulled out of SNI-rewrite at dispatch time
    /// so MITM can run for them.
    pub force_mitm_hosts: Vec<String>,
    /// Host parts of `relay_url_patterns` that are NOT
    /// SNI-rewrite-capable, retained only so `ProxyServer::new` can log
    /// a startup warning. Patterns referencing them stay in
    /// `relay_url_patterns` (so a matching path still routes through
    /// the relay if the host is MITM'd via the regular TLS-detect
    /// path), but the path-vs-forwarder filter is inert for them — the
    /// forwarder would return a wrong-origin response from the Google
    /// edge.
    pub skipped_force_mitm_hosts: Vec<String>,
    /// User patterns dropped because `youtube_via_relay_effective` is
    /// true AND the pattern's host is already covered by
    /// `YOUTUBE_RELAY_HOSTS`. Keeping them would partially defeat the
    /// "full YT through relay" contract: the path filter would flag
    /// non-matching paths as forwarder-eligible, and dispatch would
    /// route them via `forward_via_sni_rewrite_http` instead of the
    /// relay. Surfaced for the startup warning so the user knows their
    /// extra entry was redundant + harmful.
    pub suppressed_yt_patterns: Vec<String>,
    /// True iff `exit_node.enabled && mode == "full"` AND we're in
    /// apps_script mode. Used only for the startup log line that
    /// announces the YT-via-relay implication of exit-node-full.
    pub exit_node_full_mode_active: bool,
}

impl ResolvedRouting {
    pub(crate) fn from_config(config: &Config, mode: Mode) -> Self {
        let exit_node_full_mode = config.exit_node.enabled
            && config.exit_node.mode.eq_ignore_ascii_case("full")
            && !config.exit_node.relay_url.is_empty()
            && !config.exit_node.psk.is_empty();
        let exit_node_full_mode_active = exit_node_full_mode && mode == Mode::AppsScript;
        let youtube_via_relay_effective = config.youtube_via_relay || exit_node_full_mode_active;

        let mut relay_url_patterns: Vec<String> = Vec::new();
        let mut suppressed_yt_patterns: Vec<String> = Vec::new();
        if mode == Mode::AppsScript {
            if !youtube_via_relay_effective {
                for p in DEFAULT_RELAY_URL_PATTERNS {
                    relay_url_patterns.push((*p).to_string());
                }
            }
            for p in &config.relay_url_patterns {
                let trimmed = p.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let normalized = normalize_pattern(trimmed);
                // YT-overlap suppression: when `youtube_via_relay_effective`
                // is true, every YT-family host is already pulled out of
                // SNI-rewrite by the `YOUTUBE_RELAY_HOSTS` carve-out, so
                // every YT request flows through the relay regardless. A
                // user pattern targeting a YT host adds it to
                // `force_mitm_hosts`, which switches on the path filter;
                // non-matching YT paths then route through
                // `forward_via_sni_rewrite_http`, partially defeating the
                // user's `youtube_via_relay = true` opt-in. Drop the
                // pattern entirely (matching paths already go to relay
                // without it) and surface it for the startup warning.
                let pattern_host = normalized
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('.');
                if youtube_via_relay_effective && host_matches_youtube_relay(pattern_host) {
                    suppressed_yt_patterns.push(normalized);
                    continue;
                }
                relay_url_patterns.push(normalized);
            }
            let mut seen_patterns: std::collections::HashSet<String> = Default::default();
            relay_url_patterns.retain(|p| seen_patterns.insert(p.clone()));
        }

        // Only hosts that would naturally take the SNI-rewrite tunnel
        // (i.e. match `SNI_REWRITE_SUFFIXES`) are valid targets for the
        // path-level filter. The non-matching path goes through
        // `forward_via_sni_rewrite_http`, which dials `google_ip:443`
        // with `SNI=front_domain` — the Google edge dispatches by the
        // inner `Host` header, but only if that Host is actually served
        // by the same edge. A user-supplied pattern like
        // `evilsite.com/api/` would otherwise pull `evilsite.com` from
        // the (already-not-matching) SNI list as a no-op AND make
        // `host_in_force_mitm_list` true, sending non-matching paths
        // through the forwarder which would return a wrong-origin
        // response from the Google edge — silently treated as success.
        // Filter at startup, log the skip, leave the pattern itself
        // alone so a matching path still routes via relay if the host
        // is reached via a different path (TLS-detect → MITM → relay).
        // Fronting-group hosts are NOT eligible either: the forwarder
        // only knows `(google_ip, front_domain)`, not the group's
        // `(ip, sni)` pair. Path-routing on fronting groups is a
        // separate feature.
        let mut force_mitm_hosts: Vec<String> = Vec::new();
        let mut skipped_hosts: Vec<String> = Vec::new();
        let mut seen_hosts: std::collections::HashSet<String> = Default::default();
        for p in &relay_url_patterns {
            let host_part = p
                .split('/')
                .next()
                .unwrap_or("")
                .trim_start_matches('.')
                .to_string();
            if host_part.is_empty() || !seen_hosts.insert(host_part.clone()) {
                continue;
            }
            if host_is_sni_rewrite_capable(&host_part) {
                force_mitm_hosts.push(host_part);
            } else {
                skipped_hosts.push(host_part);
            }
        }

        Self {
            youtube_via_relay_effective,
            relay_url_patterns,
            force_mitm_hosts,
            skipped_force_mitm_hosts: skipped_hosts,
            suppressed_yt_patterns,
            exit_node_full_mode_active,
        }
    }
}

/// Canonicalise a `relay_url_patterns` entry to the form the runtime
/// matchers expect: lowercase, no scheme, no trailing dot on the host.
/// Lowercasing happens BEFORE scheme strip so `HTTPS://Foo.com/Bar/`
/// normalises cleanly (`trim_start_matches("https://")` is
/// case-sensitive). Trailing dots on the host (e.g. `foo.com./api/`,
/// FQDN-form) are stripped so they match against the `extract_host` →
/// trim-trailing-dot canonical form.
pub(crate) fn normalize_pattern(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    let no_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    // Split into host + path-prefix, trim a trailing dot from the host,
    // re-join. Patterns without a `/` are treated as host-only.
    match no_scheme.find('/') {
        Some(i) => {
            let host = no_scheme[..i].trim_end_matches('.');
            let rest = &no_scheme[i..];
            format!("{}{}", host, rest)
        }
        None => no_scheme.trim_end_matches('.').to_string(),
    }
}

/// True when `host` matches a `YOUTUBE_RELAY_HOSTS` entry under the
/// same one-directional suffix shape as `host_in_force_mitm_list`.
/// Used at startup to suppress user-supplied `relay_url_patterns`
/// whose host is already covered by the `youtube_via_relay` carve-out
/// — keeping such an entry would re-introduce the
/// `forward_via_sni_rewrite_http` bypass (the path filter would mark
/// non-matching paths as forwarder-eligible) and partially defeat the
/// "full YT through relay" contract the user opted into.
fn host_matches_youtube_relay(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    YOUTUBE_RELAY_HOSTS
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

/// True when `host` is served by the Google edge — i.e. matches one of
/// `SNI_REWRITE_SUFFIXES`. Used at startup to validate that
/// `relay_url_patterns` host parts are actually safe targets for the
/// SNI-rewrite HTTP forwarder. One-directional suffix match because we
/// only need to know "would this host be SNI-rewrite-capable in the
/// absence of force_mitm_hosts?" — bidirectional matching would falsely
/// validate sub-suffixes that the SNI list doesn't really cover.
fn host_is_sni_rewrite_capable(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    SNI_REWRITE_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

/// True if `host` matches a known DoH endpoint — either the built-in
/// `DEFAULT_DOH_HOSTS` list or a user-supplied entry in `extra`. Match
/// is case-insensitive, and entries match either exactly OR as a
/// dot-anchored suffix unconditionally (no leading-dot requirement,
/// unlike `passthrough_hosts`). The DoH list is *always* about a
/// service — every legitimate tenant subdomain of `cloudflare-dns.com`
/// or a user's private `doh.acme.test` is a DoH endpoint, so requiring
/// users to remember to write `.doh.acme.test` would be a footgun
/// without an obvious benefit.
fn host_matches_doh_entry(h: &str, entry: &str) -> bool {
    let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
    let e = e.strip_prefix('.').unwrap_or(&e);
    if e.is_empty() {
        return false;
    }
    h == e || h.ends_with(&format!(".{}", e))
}

/// IANA-registered STUN/TURN UDP ports plus the Google STUN allocation
/// (`stun.l.google.com:19302`). When `Config::block_stun` is on, the
/// UDP-relay datagram filter (`handle_socks5_udp_associate`) drops
/// matching datagrams so WebRTC apps skip UDP ICE candidates and fall
/// back to TCP TURN — typically on :443, which stays open. We do NOT
/// reject the same ports on the TCP CONNECT path, since that would also
/// break the very TURN-TCP fallback we're steering clients toward.
/// Centralized in a helper so a focused test pins the port list.
fn is_stun_turn_port(port: u16) -> bool {
    matches!(port, 3478 | 5349 | 19302)
}

pub fn matches_doh_host(host: &str, extra: &[String]) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if h.is_empty() {
        return false;
    }
    if DEFAULT_DOH_HOSTS
        .iter()
        .any(|s| host_matches_doh_entry(h, s))
    {
        return true;
    }
    extra.iter().any(|s| host_matches_doh_entry(h, s))
}

/// Early routing decision for `dispatch_tunnel`. Each variant maps to
/// one terminal action that doesn't need to read from the socket — so
/// classification is a pure function of the host, port, and config
/// knobs, and is easy to unit-test exhaustively. The post-classification
/// steps in `dispatch_tunnel` (fronting_groups, direct mode, SNI rewrite,
/// Apps Script peek) all need to inspect socket bytes and stay in the
/// async dispatcher itself.
///
/// Ordering is deliberate and load-bearing:
///   - `PassthroughHostsMatch` wins over everything else so a user
///     can opt out of *any* routing decision for a specific host.
///   - `BlockDoh` wins above any mode-specific routing because it's
///     a global policy in `config.rs` (`"immediately reject any
///     CONNECT to a known DoH endpoint"`). Honouring it in every
///     mode — including `local_bypass` — preserves that contract;
///     the alternative (mode-specific exceptions) means strict-DoH
///     deployments can be silently broken by a mode switch. Browser
///     DoH falls back to tun2proxy's virtual DNS regardless of
///     active mode.
///   - `LocalBypass` then owns every remaining TLS host. It sits
///     above `BypassDoh` because `BypassDoh` would route DoH hosts
///     to raw TCP (no DPI bypass), and `LocalBypass`'s fragmented
///     dial is strictly more capable on a no-relay mode where
///     "bypass to raw" makes no sense.
///   - `BlockDoh` wins over `BypassDoh` (a configured "block" is
///     stronger than a "bypass"; matches the existing precedence).
///   - `Full` wins over everything below because it tunnels via the
///     mux instead of any host-specific path.
///   - `Continue` means "keep going down the dispatcher's per-CONNECT
///     decision tree" (fronting_groups → direct mode → SNI rewrite →
///     Apps Script peek).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EarlyRoute {
    PassthroughHostsMatch,
    LocalBypass,
    BlockDoh,
    BypassDoh,
    Full,
    /// Drive-mailbox transport (mode=`drive`). Sits between `BypassDoh`
    /// and `Full` in the precedence order: the global DoH policy knobs
    /// still win above us (Drive polling is even slower than Apps
    /// Script's relay, so routing DoH through it would compound the
    /// browser-DNS latency hit `bypass_doh` exists to mitigate), but
    /// for non-DoH traffic Drive mode tunnels everything via the
    /// Drive mux just like Full mode tunnels via the Apps Script mux.
    Drive,
    Continue,
}

/// Decide the early route for a CONNECT. Pure function — separated
/// from `dispatch_tunnel` so the precedence rules (especially the
/// LocalBypass-before-DoH and PassthroughHosts-first ones) are
/// exhaustively unit-testable without spinning up a TcpStream / fake
/// upstream / `ProxyServer`. The dispatcher's job is then just to
/// match on the result and execute.
pub(crate) fn classify_early_route(
    host: &str,
    port: u16,
    mode: Mode,
    passthrough_hosts: &[String],
    bypass_doh_hosts: &[String],
    block_doh: bool,
    bypass_doh: bool,
) -> EarlyRoute {
    if matches_passthrough(host, passthrough_hosts) {
        return EarlyRoute::PassthroughHostsMatch;
    }
    // `block_doh` is documented as a global policy ("immediately
    // reject any CONNECT to a known DoH endpoint") and is checked
    // before any mode-specific routing — including LocalBypass —
    // so users who set `block_doh: true` keep their browser DNS
    // pinned to the tun2proxy virtual DNS path across mode
    // switches.
    if block_doh && port == 443 && matches_doh_host(host, bypass_doh_hosts) {
        return EarlyRoute::BlockDoh;
    }
    if mode == Mode::LocalBypass {
        return EarlyRoute::LocalBypass;
    }
    if bypass_doh && port == 443 && matches_doh_host(host, bypass_doh_hosts) {
        return EarlyRoute::BypassDoh;
    }
    if mode == Mode::Drive {
        return EarlyRoute::Drive;
    }
    if mode == Mode::Full {
        return EarlyRoute::Full;
    }
    EarlyRoute::Continue
}

/// A `FrontingGroup` after one-time validation: the group's `sni` is
/// parsed into a `ServerName` so we don't repay that on every dialed
/// connection, and domain entries are pre-lower-cased + dot-trimmed
/// so the per-request match path is just byte comparisons.
#[derive(Clone)]
pub struct FrontingGroupResolved {
    pub name: String,
    pub ip: String,
    pub sni: String,
    pub server_name: ServerName<'static>,
    domains_normalized: Vec<String>,
    /// Camouflage mode (patterniha `ForceIP`): dial the destination's own
    /// resolved IP, send `sni` only to blind DPI, verify the cert against
    /// the real destination host (or `verify_names` when set). See
    /// [`FrontingGroup::force_ip`].
    pub force_ip: bool,
    /// Normalized extra cert names for camouflage mode, accepted *in
    /// addition to* the real per-request destination host (always
    /// accepted). Used to pin the decoy SNI's own name for edges that
    /// return a cert matching the SNI rather than the Host. See
    /// [`FrontingGroup::verify_names`].
    pub verify_names: Vec<String>,
}

// `TlsConnector` isn't `Debug`; hand-roll one that elides it so the
// surrounding `tracing` / test `assert_eq!` ergonomics that relied on the
// old derive keep working.
impl std::fmt::Debug for FrontingGroupResolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrontingGroupResolved")
            .field("name", &self.name)
            .field("ip", &self.ip)
            .field("sni", &self.sni)
            .field("domains", &self.domains_normalized)
            .field("force_ip", &self.force_ip)
            .field("verify_names", &self.verify_names)
            .finish()
    }
}

impl FrontingGroupResolved {
    pub(crate) fn from_config(g: &FrontingGroup) -> Result<Self, String> {
        let server_name = ServerName::try_from(g.sni.clone())
            .map_err(|e| format!("invalid sni '{}': {}", g.sni, e))?;
        let domains_normalized: Vec<String> = g
            .domains
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        if !g.force_ip && g.ip.trim().is_empty() {
            return Err("ip is required unless force_ip = true".into());
        }

        let verify_names: Vec<String> = g
            .verify_names
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        // Fail fast at startup if an explicit verify list is unusable —
        // better than discovering it per-connection at dial time. (Empty
        // list = verify against the real host, validated per-connection.)
        if g.force_ip && !verify_names.is_empty() {
            crate::camouflage::build_camouflage_connector(&verify_names)
                .map_err(|e| format!("force_ip verify_names: {}", e))?;
        }

        Ok(Self {
            name: g.name.clone(),
            ip: g.ip.clone(),
            sni: g.sni.clone(),
            server_name,
            domains_normalized,
            force_ip: g.force_ip,
            verify_names,
        })
    }
}

/// First fronting group whose domain list contains `host`, if any.
/// Match is case-insensitive and unconditionally suffix-anchored: an
/// entry `vercel.com` matches both `vercel.com` and `*.vercel.com`.
/// This is the right shape for fronting because every legitimate
/// subdomain of a fronted domain is itself fronted by the same edge
/// — requiring users to spell out every subdomain would be a footgun.
/// Same matching shape as the DoH host list. First match wins, so
/// users can put more-specific groups earlier when entries would
/// otherwise overlap.
pub fn match_fronting_group<'a>(
    host: &str,
    groups: &'a [Arc<FrontingGroupResolved>],
) -> Option<&'a Arc<FrontingGroupResolved>> {
    if groups.is_empty() {
        return None;
    }
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if h.is_empty() {
        return None;
    }
    for g in groups {
        for d in &g.domains_normalized {
            if is_dot_anchored_match(h, d) {
                return Some(g);
            }
        }
    }
    None
}

/// True if `host` equals `entry` exactly OR is a strict dot-anchored
/// suffix of it (i.e. `entry == "vercel.com"` matches `host ==
/// "app.vercel.com"` but not `host == "xvercel.com"`). Both inputs
/// must already be lowercase + trailing-dot trimmed; the function
/// does no allocation, unlike the obvious `format!(".{}", entry)`
/// implementation that allocates per call.
#[inline]
fn is_dot_anchored_match(host: &str, entry: &str) -> bool {
    if host == entry {
        return true;
    }
    let hb = host.as_bytes();
    let eb = entry.as_bytes();
    hb.len() > eb.len() && hb.ends_with(eb) && hb[hb.len() - eb.len() - 1] == b'.'
}

/// True if `host` matches any entry in the user's passthrough list.
/// Match is case-insensitive. Entries match either exactly, or as a
/// suffix if they start with "." (e.g. ".internal.example" matches
/// "a.b.internal.example" and the bare "internal.example"). Bare
/// entries like "example.com" only match the exact hostname — users
/// who want subdomains included should use ".example.com".
pub fn matches_passthrough(host: &str, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    list.iter().any(|entry| {
        let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if e.is_empty() {
            return false;
        }
        if let Some(suffix) = e.strip_prefix('.') {
            h == suffix || h.ends_with(&format!(".{}", suffix))
        } else {
            h == e
        }
    })
}

/// Build the mode-dependent half of the proxy state from a `Config`: the
/// `DomainFronter` (when mode needs one) and the `RewriteCtx` carrying all
/// the resolved routing knobs. Used by both `ProxyServer::new` at startup
/// and `RuntimeState::switch_mode` for live mode toggling — the two paths
/// must produce identical state so the second-pass switch behaves the same
/// as a fresh Start.
fn build_mode_state(config: &Config) -> Result<ModeState, ProxyError> {
    let mode = config
        .mode_kind()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;

    // Modes that don't use the Apps Script relay skip the DomainFronter
    // entirely — its constructor errors on a missing `script_id`, which
    // is exactly the state direct / local_bypass users are in.
    // `Mode::uses_apps_script_relay` is the single source of truth so
    // a future mode automatically picks the right side without another
    // pattern-match drift bug.
    let fronter = if mode.uses_apps_script_relay() {
        let f = DomainFronter::new(config).map_err(|e| std::io::Error::other(format!("{e}")))?;
        Some(Arc::new(f))
    } else {
        None
    };

    let tls_config = if config.verify_ssl {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
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
    let tls_connector = TlsConnector::from(Arc::new(tls_config));

    // Surface a config combo that is otherwise silently inert: extras
    // listed under `bypass_doh_hosts` only take effect when the bypass
    // itself is on. A user who set `tunnel_doh: true` *and* populated
    // the extras list almost certainly didn't mean to disable the
    // feature their custom hosts feed into.
    if config.tunnel_doh && !config.bypass_doh_hosts.is_empty() {
        tracing::warn!(
            "config: bypass_doh_hosts has {} entries but tunnel_doh=true — \
                 the bypass is off, so the extras have no effect. Set \
                 tunnel_doh=false (or omit it) to use them.",
            config.bypass_doh_hosts.len()
        );
    }

    // Same-shape warning for fronting_groups in full mode. The dispatch
    // short-circuits to the tunnel mux before the fronting_groups check
    // (full mode preserves end-to-end TLS, fronting_groups requires
    // MITM), so groups configured here will never fire. Surface this
    // at startup rather than letting users wonder why their Vercel
    // domains never hit the configured edge.
    if mode == Mode::Full && !config.fronting_groups.is_empty() {
        tracing::warn!(
            "config: fronting_groups has {} entries but mode=full — \
                 full mode tunnels everything end-to-end through Apps Script \
                 (no MITM), so groups never fire. Switch to mode=apps_script \
                 or mode=direct to use them, or remove the groups to silence \
                 this warning.",
            config.fronting_groups.len()
        );
    }
    // Same shape for local_bypass. The dispatch's [`EarlyRoute::LocalBypass`]
    // arm runs above the fronting-groups check on purpose: local_bypass
    // is the "no MITM, fragment everything" mode by design, and an
    // SNI-rewrite-via-CDN-edge route here would need the MITM CA the user
    // explicitly opted out of. Surface this at startup so users don't
    // wonder why their Vercel/Fastly groups silently stopped working
    // after a mode switch.
    if mode == Mode::LocalBypass && !config.fronting_groups.is_empty() {
        tracing::warn!(
            "config: fronting_groups has {} entries but mode=local_bypass — \
                 local_bypass fragments every TLS host end-to-end (no MITM), \
                 so groups never fire. Switch to mode=apps_script or \
                 mode=direct to use them, or remove the groups to silence \
                 this warning.",
            config.fronting_groups.len()
        );
    }
    // The fragmentation path in local_bypass cannot honour
    // `upstream_socks5`: the engine writes the ClientHello as N small
    // TCP segments, but a TCP-relay intermediary reassembles them and
    // re-emits one segment to the real destination — so the SNI is
    // back in a single packet and the DPI bypass is defeated. Other
    // local_bypass code paths (a `passthrough_hosts` match, the
    // non-TLS `Skip` fallthrough that lands on `plain_tcp_passthrough`)
    // DO still honour the upstream proxy, because they're just raw
    // TCP routing with no fragmentation invariant to preserve.
    //
    // The warning fires when both are set so users don't silently
    // think their egress policy applies to fragmented flows. It
    // intentionally does not reject the combination — a user with
    // both passthrough_hosts+upstream_socks5 has a meaningful
    // configuration: "route these specific hosts through SOCKS5,
    // fragment everything else direct."
    if mode == Mode::LocalBypass
        && config
            .upstream_socks5
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    {
        tracing::warn!(
            "config: upstream_socks5={} but mode=local_bypass — the fragmentation \
             path requires direct TCP to the real destination (any SOCKS5 \
             intermediary reassembles segments and defeats the bypass), so it \
             ignores `upstream_socks5`. Other paths in this mode \
             (passthrough_hosts matches, non-TLS fallthrough) DO still honour \
             it. Remove `upstream_socks5`, or accept the split-honouring, to \
             silence this warning.",
            config.upstream_socks5.as_deref().unwrap_or("")
        );
    }

    let mut fronting_groups: Vec<Arc<FrontingGroupResolved>> =
        Vec::with_capacity(config.fronting_groups.len());
    let mut seen_names: std::collections::HashSet<String> = Default::default();
    for g in &config.fronting_groups {
        let resolved = FrontingGroupResolved::from_config(g).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("fronting_groups['{}']: {}", g.name, e),
            )
        })?;
        // Surface duplicate group names at startup. Not a hard
        // error — copy-pasted configs can land here legitimately
        // — but log lines key on `name` and dedup ambiguity makes
        // them unreadable.
        if !seen_names.insert(resolved.name.clone()) {
            tracing::warn!(
                "fronting group name '{}' is used by more than one group; \
                     log lines that reference the name will be ambiguous",
                resolved.name
            );
        }
        tracing::info!(
            "fronting group '{}': sni={} ip={} domains={}",
            resolved.name,
            resolved.sni,
            resolved.ip,
            resolved.domains_normalized.len()
        );
        fronting_groups.push(Arc::new(resolved));
    }

    let resolved_routing = ResolvedRouting::from_config(config, mode);
    // Unconditional routing-state dump. The existing logs below only
    // fire when patterns/skipped/suppressed lists are non-empty, which
    // leaves users without visibility into the no-op cases that
    // bug-report logs need to disambiguate (e.g. is force_mitm_hosts
    // empty because youtube_via_relay_effective is true, or because
    // patterns themselves are empty?). Diagnostic-only — no behavior
    // change.
    tracing::info!(
        "routing: mode={:?} youtube_via_relay_effective={} exit_node_full_mode_active={} \
         force_mitm_hosts=[{}] relay_url_patterns=[{}]",
        mode,
        resolved_routing.youtube_via_relay_effective,
        resolved_routing.exit_node_full_mode_active,
        resolved_routing.force_mitm_hosts.join(", "),
        resolved_routing.relay_url_patterns.join(", "),
    );
    if resolved_routing.exit_node_full_mode_active && !config.youtube_via_relay {
        tracing::info!(
            "exit_node.mode=full → routing YouTube through relay (upstream commit 88b2767)"
        );
    }
    if !resolved_routing.relay_url_patterns.is_empty() {
        tracing::info!(
            "relay_url_patterns: MITM forced on {}; relay only for: {}",
            resolved_routing.force_mitm_hosts.join(", "),
            resolved_routing.relay_url_patterns.join(", "),
        );
    }
    if !resolved_routing.skipped_force_mitm_hosts.is_empty() {
        tracing::warn!(
            "relay_url_patterns: ignoring path-routing for {} — host is not in \
                 SNI_REWRITE_SUFFIXES, so the SNI-rewrite forwarder would return a \
                 wrong-origin response from the Google edge. Patterns matching this \
                 host still route through the relay if the host is reached, but \
                 non-matching paths fall back to the regular dispatch.",
            resolved_routing.skipped_force_mitm_hosts.join(", "),
        );
    }
    if !resolved_routing.suppressed_yt_patterns.is_empty() {
        tracing::warn!(
            "relay_url_patterns: dropped {} — youtube_via_relay (or \
                 exit_node.mode=full) routes all YouTube through the relay \
                 already, so a YT-host path filter would route non-matching \
                 paths through the SNI-rewrite forwarder and partially defeat \
                 the full-relay contract. Remove these entries from \
                 config.json to silence this warning.",
            resolved_routing.suppressed_yt_patterns.join(", "),
        );
    }

    // Fronting groups are dispatched BEFORE the force-MITM check
    // (`dispatch_tunnel` step 2a vs 2). That precedence is intentional
    // — a user adding `youtube.com` to a fronting group is making a
    // deliberate "send all of YT through this alternate edge" choice
    // and the path filter, which assumes the Google edge handles the
    // request, would land at the wrong upstream. But the silent
    // override is a footgun if the user didn't realise the two
    // features overlap, so surface it at startup with both names
    // and the resolved precedence.
    for forced in &resolved_routing.force_mitm_hosts {
        for g in &fronting_groups {
            let overlaps = g.domains_normalized.iter().any(|d| {
                forced == d
                    || forced.ends_with(&format!(".{}", d))
                    || d.ends_with(&format!(".{}", forced))
            });
            if overlaps {
                tracing::warn!(
                    "config: fronting group '{}' covers host '{}', which is also \
                         in relay_url_patterns. Fronting-group dispatch wins — the \
                         path filter will NOT run for this host. Remove the host \
                         from the fronting group if you want path-pinned relay routing.",
                    g.name,
                    forced,
                );
            }
        }
    }
    let ResolvedRouting {
        youtube_via_relay_effective,
        relay_url_patterns: resolved_patterns,
        force_mitm_hosts,
        skipped_force_mitm_hosts: _,
        suppressed_yt_patterns: _,
        exit_node_full_mode_active,
    } = resolved_routing;

    let direct_mode = build_direct_mode_ctx(&config.direct_mode);

    // Only stand up the DoH resolver when a force_ip (camouflage) group
    // actually needs it. Build failure is non-fatal — the affected
    // groups no-op and the dispatcher falls through to its other paths.
    //
    // `fallback_system_dns = false` is deliberate and load-bearing for
    // the fall-through contract: the dispatcher resolves *before*
    // MITM-terminating the browser, and only commits to the force_ip
    // tunnel if resolution succeeds. If we let a poisoned system-DNS
    // answer count as "success", dispatch would consume the socket, then
    // fail cert verification, then close — exactly the blackhole the
    // fall-through is meant to avoid. DoH-only means a DoH miss returns
    // an error, the dispatcher falls through to relay/raw, and the host
    // stays reachable. (In Iran the system resolver is poisoned for
    // precisely these hosts, so the fallback would be actively harmful
    // here anyway.)
    let doh_resolver = if fronting_groups.iter().any(|g| g.force_ip) {
        match crate::doh::DohResolver::with_default_resolvers(false) {
            Ok(r) => {
                tracing::info!(
                    "force_ip fronting active — DoH resolver up (Cloudflare {}/1.0.0.1 camouflaged + Google dns.google)",
                    crate::doh::DEFAULT_RESOLVER_IP,
                );
                Some(Arc::new(r))
            }
            Err(e) => {
                tracing::error!(
                    "force_ip groups configured but DoH resolver failed to build: {} \
                     — those groups will be inactive",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    let rewrite_ctx = Arc::new(RewriteCtx {
        google_ip: config.google_ip.clone(),
        front_domain: config.front_domain.clone(),
        hosts: config.hosts.clone(),
        tls_connector,
        upstream_socks5: config.upstream_socks5.clone(),
        mode,
        youtube_via_relay: youtube_via_relay_effective,
        relay_url_patterns: resolved_patterns,
        force_mitm_hosts,
        exit_node_full_mode_active,
        passthrough_hosts: config.passthrough_hosts.clone(),
        block_quic: config.block_quic,
        block_stun: config.block_stun,
        bypass_doh: !config.tunnel_doh,
        block_doh: config.block_doh,
        bypass_doh_hosts: config.bypass_doh_hosts.clone(),
        fronting_groups,
        direct_mode,
        doh_resolver,
    });

    Ok((fronter, rewrite_ctx, mode))
}

/// Decision predicate for the Direct Mode dispatch branch. Pulled out
/// of `dispatch_tunnel` so the precedence rules — port-gating,
/// force-MITM carve-out, `youtube_via_relay` exclusion, explicit hosts
/// override — can be tested directly without standing up sockets,
/// certs, or a full RewriteCtx.
///
/// Returns `true` only when EVERY condition for taking the direct
/// branch is satisfied. False otherwise; caller falls through to
/// `should_use_sni_rewrite` and the rest of the pipeline. Keep this
/// predicate in lockstep with the `dispatch_tunnel` step 2b block.
pub(crate) fn should_take_direct_mode_branch(
    port: u16,
    direct: Option<&Arc<crate::direct_mode::DirectModeCtx>>,
    host: &str,
    force_mitm_hosts: &[String],
    youtube_via_relay: bool,
    hosts: &std::collections::HashMap<String, String>,
) -> bool {
    if port != 443 {
        return false;
    }
    let Some(direct) = direct else {
        return false;
    };
    if host_in_force_mitm_list(host, force_mitm_hosts) {
        return false;
    }
    if youtube_via_relay && host_matches_youtube_relay(host) {
        return false;
    }
    // Explicit hosts override is a deliberate user choice: they typed
    // `mail.google.com: 1.2.3.4` because they know that IP works on
    // their network. Direct Mode dialing to a different front would
    // silently bypass that signal. Always defer to the user — the
    // SNI-rewrite path honours the override and that's what they
    // asked for.
    if hosts_override(hosts, host).is_some() {
        return false;
    }
    if !direct.is_direct(host) {
        return false;
    }
    // Defense-in-depth: Direct Mode's `SkipPrefaced` fallback can only
    // route to `do_sni_rewrite_tunnel_from_tcp`, which is only safe
    // for hosts in `SNI_REWRITE_SUFFIXES`. Hosts outside that list
    // (e.g. a user-customised `direct_mode.google_domains` that adds
    // back `googlevideo.com`) would on dial failure 502 or trigger a
    // wrong-edge / wrong-cert error rather than fall to the relay.
    // Skip Direct Mode entirely for those — the existing dispatch
    // routes them through their normal path (relay in AppsScript mode).
    // The bundled `DEFAULT_GOOGLE_DOMAINS` is already constrained to
    // this intersection; this check defends against custom lists.
    if !matches_sni_rewrite(host, youtube_via_relay, force_mitm_hosts) {
        return false;
    }
    true
}

/// Build the `DirectModeCtx` from a `DirectModeConfig`. Returns `None`
/// when disabled in config so the dispatch branch is fully skipped
/// (no atomic load, no Arc traffic on the hot path) — same shape as
/// `fronting_groups` being an empty `Vec`. Substitutes built-in
/// defaults when the user left the list fields empty.
fn build_direct_mode_ctx(
    cfg: &crate::config::DirectModeConfig,
) -> Option<Arc<crate::direct_mode::DirectModeCtx>> {
    if !cfg.enabled {
        return None;
    }
    let fronts: Vec<String> = if cfg.fronts.is_empty() {
        crate::direct_mode::DEFAULT_FRONTS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        cfg.fronts.clone()
    };
    let google_domains: Vec<String> = if cfg.google_domains.is_empty() {
        crate::direct_mode::DEFAULT_GOOGLE_DOMAINS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        cfg.google_domains.clone()
    };
    let sanctioned_domains: Vec<String> = if cfg.sanctioned_domains.is_empty() {
        crate::direct_mode::DEFAULT_SANCTIONED_DOMAINS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        cfg.sanctioned_domains.clone()
    };
    if fronts.is_empty() {
        tracing::warn!("direct_mode: enabled but no fronts configured — disabling");
        return None;
    }
    tracing::info!(
        "direct_mode: enabled (fronts={}, google_domains={}, sanctioned={})",
        fronts.len(),
        google_domains.len(),
        sanctioned_domains.len(),
    );
    Some(Arc::new(crate::direct_mode::DirectModeCtx::from_parts(
        true,
        fronts,
        google_domains,
        sanctioned_domains,
        Some(crate::data_dir::data_dir()),
    )))
}

/// Pick out `TunnelMux` coalesce knobs from a `Config`, applying the
/// "0 → default" semantics (step=10ms, max=1000ms). Lives outside
/// `RuntimeState::new` / `switch_mode` so both paths produce identical
/// values for the same config — a live switch updates the runtime's
/// atomics from this, so editing `coalesce_*_ms` and toggling into
/// Full mode picks up the new values rather than the ones captured at
/// startup. Returns `(step_ms, max_ms)`.
fn resolve_coalesce(config: &Config) -> (u64, u64) {
    let step = if config.coalesce_step_ms > 0 {
        config.coalesce_step_ms as u64
    } else {
        10
    };
    let max = if config.coalesce_max_ms > 0 {
        config.coalesce_max_ms as u64
    } else {
        1000
    };
    (step, max)
}

/// Spawn the mode-dependent background tasks for `fronter` (keepalive,
/// pool refill, periodic stats log) and a one-shot pool warm. Used by
/// both `RuntimeState::run` at startup and `switch_mode` after a swap
/// into a mode that needs a fronter. Caller holds the `mode_tasks`
/// mutex; tasks are stored under that guard so a subsequent abort sees
/// every handle.
///
/// Idempotent — aborts any prior tasks on `tasks` before spawning fresh
/// ones. That matters because the UI can call `switch_mode` between
/// `Cmd::Start` flipping `running = true` and `run()` reaching its
/// startup spawn point; without the abort-first contract, the switch's
/// tasks would be silently dropped by `run()`'s subsequent overwrite.
fn spawn_mode_tasks(tasks: &mut ModeTasks, fronter: Arc<DomainFronter>, config: &Config) {
    tasks.abort_all();
    // Pre-warm — runs to completion and exits, but tracked so a switch
    // landing inside its window can abort the old warmup along with the
    // rest of the bag.
    tasks.warm = Some(tokio::spawn({
        let f = fronter.clone();
        async move {
            let n = f.num_scripts().clamp(6, 16);
            f.warm(n).await;
        }
    }));
    tasks.keepalive = Some(tokio::spawn({
        let f = fronter.clone();
        async move { f.run_keepalive().await }
    }));
    tasks.refill = Some(tokio::spawn({
        let f = fronter.clone();
        async move { f.run_pool_refill().await }
    }));
    tasks.probe = Some(tokio::spawn({
        let f = fronter.clone();
        async move { f.run_probe_loop().await }
    }));
    tasks.health = Some(tokio::spawn({
        let f = fronter.clone();
        let enabled = config.heartbeat_enabled;
        let interval_secs = config.heartbeat_interval_secs;
        let threshold = config.heartbeat_failure_threshold;
        let cfg = config.clone();
        async move {
            f.run_ip_health(enabled, interval_secs, threshold, cfg)
                .await
        }
    }));
    tasks.stats = Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let s = fronter.snapshot_stats();
            if s.relay_calls > 0 || s.cache_hits > 0 {
                tracing::info!("{}", s.fmt_line());
            }
        }
    }));
}

impl ProxyServer {
    pub fn new(config: &Config, mitm: Arc<Mutex<MitmCertManager>>) -> Result<Self, ProxyError> {
        let state = RuntimeState::new(config, mitm)?;
        Ok(Self { state })
    }

    pub fn fronter(&self) -> Option<Arc<DomainFronter>> {
        self.state.fronter()
    }

    /// Hand out the shared runtime handle. The caller (UI background thread)
    /// holds it alongside the spawned run-future's `JoinHandle` so a
    /// `Cmd::SwitchMode` can invoke `state.switch_mode(...)` without
    /// stopping the proxy.
    pub fn state(&self) -> Arc<RuntimeState> {
        self.state.clone()
    }

    pub async fn run(
        self,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        self.state.run(shutdown_rx).await
    }
}

impl RuntimeState {
    pub fn new(
        config: &Config,
        mitm: Arc<Mutex<MitmCertManager>>,
    ) -> Result<Arc<Self>, ProxyError> {
        let (fronter, rewrite_ctx, _mode) = build_mode_state(config)?;
        let socks5_port = config.socks5_port.unwrap_or(config.listen_port + 1);
        let bundle = Arc::new(ModeBundle {
            rewrite_ctx,
            fronter,
            // TunnelMux is spawned in `run()` because `TunnelMux::start`
            // calls `tokio::spawn` internally and needs a runtime. Same
            // story for `DriveMux::start` — spawning the shared Drive
            // poller from `new()` would touch the runtime before the
            // caller (CLI / Tauri runtime / JNI) has even decided to
            // start the proxy, so we defer to `run_inner` too.
            tunnel_mux: None,
            drive_mux: None,
        });
        let (coalesce_step, coalesce_max) = resolve_coalesce(config);
        Ok(Arc::new(Self {
            host: config.listen_host.clone(),
            port: config.listen_port,
            socks5_port,
            bundle: ArcSwap::from(bundle),
            mitm,
            mode_tasks: Mutex::new(ModeTasks::default()),
            coalesce_step_ms: AtomicU64::new(coalesce_step),
            coalesce_max_ms: AtomicU64::new(coalesce_max),
            switch_lock: Mutex::new(()),
            switch_serial_lock: Mutex::new(()),
            stopped: AtomicBool::new(false),
            config: ArcSwap::from_pointee(config.clone()),
        }))
    }

    /// Cheap accessor exposed to UI / JNI / CLI callers so they don't have
    /// to know that `ModeBundle` is wrapped in `ArcSwap`.
    pub fn fronter(&self) -> Option<Arc<DomainFronter>> {
        self.bundle.load().fronter.clone()
    }

    /// Mode the proxy is currently serving traffic in. UI uses this for
    /// "what mode is *actually* live right now" displays (status badge,
    /// rollback target on a failed switch). Keeps the `ArcSwap` /
    /// `ModeBundle` details out of callers.
    pub fn current_mode(&self) -> Mode {
        self.bundle.load().rewrite_ctx.mode
    }

    pub async fn run(
        self: Arc<Self>,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        // Trampoline so every exit path (bind failure, accept-loop
        // crash, normal shutdown) funnels through the same cleanup
        // epilog. The previous shape only cleaned up inside the
        // shutdown arm of `select!`, which meant a bind failure after a
        // racing `switch_mode` had already spawned mode_tasks would
        // leak those tasks: run() returned via `?` and the UI's spawn
        // dropped the JoinHandle but the keepalive / refill / stats
        // tasks held their own `Arc<DomainFronter>` and kept pinging.
        let result = self.clone().run_inner(shutdown_rx).await;

        // Unconditional cleanup: set `stopped` (so any switch_mode
        // currently waiting on `switch_lock` bails on resumption),
        // abort whatever mode_tasks are populated, and drop any live
        // `TunnelMux` out of the bundle.
        //
        // Why drop the mux: `TunnelMux::start` spawns a `mux_loop`
        // task that captures its own `Arc<DomainFronter>` and lives
        // for as long as any `Arc<TunnelMux>` exists. `abort_all`
        // only reaches the keepalive/refill/stats/warm tasks — the
        // mux_loop is NOT in `mode_tasks`. Leaving `tunnel_mux` in
        // the bundle means the mux_loop (and its captured fronter)
        // outlive `run()`'s return until the UI eventually releases
        // its `Arc<RuntimeState>`, which is observable as the fronter
        // still pinging Apps Script for a window after Stop. Clearing
        // it here drops the only stable `Arc<TunnelMux>`, so the
        // mux_loop's mpsc Sender drops and the loop exits naturally.
        //
        // Idempotent: the shutdown arm of run_inner already aborts
        // accept tasks; running cleanup a second time on a bundle
        // that already has `tunnel_mux: None` is a no-op (guarded
        // below).
        {
            let _g = self.switch_lock.lock().await;
            self.stopped.store(true, Ordering::SeqCst);
            self.mode_tasks.lock().await.abort_all();
            let cur = self.bundle.load_full();
            if cur.tunnel_mux.is_some() || cur.drive_mux.is_some() {
                // Same rationale as the `tunnel_mux` clear above
                // applies to `drive_mux`: the Drive shared poller
                // holds its own `Arc<DriveMux>` for as long as the
                // bundle does, so dropping it here is what lets the
                // poller task exit naturally on Stop. Both fields
                // are cleared together in a single store so the
                // bundle never carries half-stopped state.
                self.bundle.store(Arc::new(ModeBundle {
                    rewrite_ctx: cur.rewrite_ctx.clone(),
                    fronter: cur.fronter.clone(),
                    tunnel_mux: None,
                    drive_mux: None,
                }));
            }
        }

        result
    }

    async fn run_inner(
        self: Arc<Self>,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        // Bind listeners FIRST. Both binds are the only fallible step in
        // the startup path; doing them before any task spawn means a
        // bind failure (port already in use, permission denied) returns
        // `Err` with nothing locally spawned to clean up. Tasks spawned
        // by a racing switch_mode are reaped in the outer `run()`'s
        // cleanup epilog.
        let http_addr = format!("{}:{}", self.host, self.port);
        let socks_addr = format!("{}:{}", self.host, self.socks5_port);
        let http_listener = TcpListener::bind(&http_addr).await?;
        let socks_listener = TcpListener::bind(&socks_addr).await?;
        tracing::warn!(
            "Listening HTTP   on {} — set your browser HTTP proxy to this address.",
            http_addr
        );
        tracing::warn!(
            "Listening SOCKS5 on {} — xray / Telegram / app-level SOCKS5 clients use this.",
            socks_addr
        );

        // DriveMux startup can refresh OAuth over the network. Build a
        // candidate outside `switch_lock` so Stop / switch cleanup isn't
        // pinned behind that I/O. The short locked block below installs it
        // only if Drive is still the active mode and no racing switch has
        // already provided a mux.
        let mut startup_drive_mux = {
            let cur = self.bundle.load_full();
            if cur.rewrite_ctx.mode == Mode::Drive && cur.drive_mux.is_none() {
                let cfg = self.config.load_full();
                Some(crate::drive_client::DriveMux::start(&cfg).await)
            } else {
                None
            }
        };

        // Spawn TunnelMux inside the runtime (`TunnelMux::start` calls
        // `tokio::spawn`). If the starting mode is Full and the bundle
        // doesn't already have a mux (a `switch_mode` racing Start may
        // have installed one), install it now so the first connections
        // see it. Holding `switch_lock` for the install/swap block
        // serialises this against switch_mode so we don't overwrite each
        // other's bundle.
        {
            let _g = self.switch_lock.lock().await;
            let cur = self.bundle.load_full();
            if cur.rewrite_ctx.mode == Mode::Full
                && cur.tunnel_mux.is_none()
                && cur.fronter.is_some()
            {
                let f = cur.fronter.clone().unwrap();
                let step = self.coalesce_step_ms.load(Ordering::Relaxed);
                let max = self.coalesce_max_ms.load(Ordering::Relaxed);
                let mux = TunnelMux::start(f, step, max);
                self.bundle.store(Arc::new(ModeBundle {
                    rewrite_ctx: cur.rewrite_ctx.clone(),
                    fronter: cur.fronter.clone(),
                    tunnel_mux: Some(mux),
                    drive_mux: cur.drive_mux.clone(),
                }));
            }

            // Drive-mode parallel of the Full-mux spawn above. Same
            // rationale (mux startup needs a tokio runtime; can't
            // happen in `ProxyServer::new`). A racing `switch_mode`
            // may have installed the mux already — `is_none()` keeps
            // this idempotent so a switch-into-Drive immediately
            // followed by Start doesn't double-spawn the poller.
            let cur = self.bundle.load_full();
            if cur.rewrite_ctx.mode == Mode::Drive && cur.drive_mux.is_none() {
                let dm = match startup_drive_mux.take() {
                    Some(Ok(dm)) => dm,
                    Some(Err(e)) => {
                        return Err(std::io::Error::other(format!("drive mux: {e}")).into());
                    }
                    None => {
                        return Err(
                            std::io::Error::other("drive mux missing after startup race").into(),
                        );
                    }
                };
                self.bundle.store(Arc::new(ModeBundle {
                    rewrite_ctx: cur.rewrite_ctx.clone(),
                    fronter: cur.fronter.clone(),
                    tunnel_mux: cur.tunnel_mux.clone(),
                    drive_mux: Some(dm),
                }));
            }

            // Drop any unused candidate. If the recheck above didn't
            // install it (mode flipped away from Drive via a racing
            // switch_mode, or a racing switch already populated
            // drive_mux), the `Some(Ok(dm))` would otherwise stay
            // pinned in `run_inner`'s frame for the entire proxy
            // lifetime — the poller (which holds `Weak<DriveMuxInner>`)
            // would keep upgrading and polling Drive uselessly.
            let _ = startup_drive_mux.take();

            // Mode-dependent background tasks (warm + keepalive + refill +
            // stats) are owned by `mode_tasks` so `switch_mode` can abort
            // them and respawn the new mode's set atomically. Skip if a
            // racing switch_mode already populated them — its set is on
            // the *current* fronter (we re-read the bundle above under
            // the switch_lock).
            if let Some(f) = self.bundle.load().fronter.clone() {
                let mut tasks = self.mode_tasks.lock().await;
                if tasks.is_empty() {
                    let cfg = self.config.load_full();
                    spawn_mode_tasks(&mut tasks, f, &cfg);
                }
            }
        }

        let accept_state = self.clone();
        let mut http_task = tokio::spawn(async move {
            let mut fd_exhaust_count: u64 = 0;
            // Track every per-client child task in a JoinSet so that when
            // this accept task is aborted on shutdown, dropping the JoinSet
            // aborts the children too. Previously children were bare
            // `tokio::spawn(...)` handles with no ownership — aborting the
            // parent accept loop stopped taking new connections but left
            // in-flight ones running with the OLD config. That manifested
            // as "hitting Stop in the UI doesn't actually stop anything
            // already running" (issue #99) and as "changing auth_key and
            // Start doesn't take effect for domains with a live
            // keep-alive" because the old DomainFronter stayed alive
            // inside those child tasks.
            let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            loop {
                // Opportunistic reap so completed children don't pile up
                // memory on long-running proxies.
                while children.try_join_next().is_some() {}

                let (sock, peer) = match http_listener.accept().await {
                    Ok(x) => {
                        fd_exhaust_count = 0;
                        x
                    }
                    Err(e) => {
                        accept_backoff("http", &e, &mut fd_exhaust_count).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                // Load the current bundle ONCE per accepted connection so
                // (ctx, fronter, mux) stay self-consistent for the lifetime
                // of this handler even if `switch_mode` races. A `switch_mode`
                // happening between this load and the spawn just means the
                // *next* accept sees the new state.
                let bundle = accept_state.bundle.load_full();
                let mitm = accept_state.mitm.clone();
                let fronter = bundle.fronter.clone();
                let rewrite_ctx = bundle.rewrite_ctx.clone();
                let mux = bundle.tunnel_mux.clone();
                let drive_mux = bundle.drive_mux.clone();
                children.spawn(async move {
                    if let Err(e) =
                        handle_http_client(sock, fronter, mitm, rewrite_ctx, mux, drive_mux).await
                    {
                        tracing::debug!("http client {} closed: {}", peer, e);
                    }
                });
            }
        });

        let accept_state2 = self.clone();
        let mut socks_task = tokio::spawn(async move {
            let mut fd_exhaust_count: u64 = 0;
            // Same pattern as http_task above — JoinSet so shutdown
            // drops in-flight SOCKS5 clients instead of leaving them to
            // keep running on the stale config.
            let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            loop {
                while children.try_join_next().is_some() {}

                let (sock, peer) = match socks_listener.accept().await {
                    Ok(x) => {
                        fd_exhaust_count = 0;
                        x
                    }
                    Err(e) => {
                        accept_backoff("socks", &e, &mut fd_exhaust_count).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let bundle = accept_state2.bundle.load_full();
                let mitm = accept_state2.mitm.clone();
                let fronter = bundle.fronter.clone();
                let rewrite_ctx = bundle.rewrite_ctx.clone();
                let mux = bundle.tunnel_mux.clone();
                let drive_mux = bundle.drive_mux.clone();
                children.spawn(async move {
                    if let Err(e) =
                        handle_socks5_client(sock, fronter, mitm, rewrite_ctx, mux, drive_mux).await
                    {
                        tracing::debug!("socks client {} closed: {}", peer, e);
                    }
                });
            }
        });

        // The outer `run()` cleanup epilog handles `stopped` +
        // `mode_tasks.abort_all()`. Inside `select!` we still need to
        // abort the OTHER accept task on every exit path — dropping a
        // `JoinHandle` only detaches it, so without an explicit
        // `.abort()` the sibling listener would stay bound and serving
        // even after `run()` returned.
        //
        // The two non-shutdown arms propagate the anomaly as an `Err`
        // rather than logging and returning `Ok(())`. Reaching those
        // arms means the accept loop exited on its own, which — given
        // the loop has no `break` — can only happen via panic (caught
        // by tokio into `JoinError::is_panic()`). Surfacing that as
        // `ProxyError::Io` lets the UI background thread distinguish
        // "user clicked Stop" from "proxy crashed" and show an error
        // line instead of a silent "proxy stopped". `is_cancelled()`
        // is still treated as a clean exit because it only happens if
        // somebody aborted the task from outside this `select!`, which
        // is currently unreachable but worth not flagging if it ever
        // becomes a thing.
        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                tracing::info!("Shutdown signal received, stopping listeners");
                http_task.abort();
                socks_task.abort();
            }
            res = &mut http_task => {
                socks_task.abort();
                match res {
                    Ok(()) => {
                        return Err(std::io::Error::other(
                            "http accept loop exited unexpectedly",
                        )
                        .into());
                    }
                    Err(e) if !e.is_cancelled() => {
                        return Err(std::io::Error::other(format!(
                            "http accept loop ended unexpectedly: {e}"
                        ))
                        .into());
                    }
                    Err(_) => {}
                }
            }
            res = &mut socks_task => {
                http_task.abort();
                match res {
                    Ok(()) => {
                        return Err(std::io::Error::other(
                            "socks5 accept loop exited unexpectedly",
                        )
                        .into());
                    }
                    Err(e) if !e.is_cancelled() => {
                        return Err(std::io::Error::other(format!(
                            "socks5 accept loop ended unexpectedly: {e}"
                        ))
                        .into());
                    }
                    Err(_) => {}
                }
            }
        }

        Ok(())
    }

    /// Hot-swap the proxy into a new mode (or rebuild the fronter/mux with
    /// fresh config) without touching the bound listeners. The accept loops
    /// pick up the new `ModeBundle` on their next `accept().await`; in-flight
    /// requests keep their already-cloned arcs to completion.
    ///
    /// `apply` semantics: this always rebuilds the bundle from `new_config`,
    /// even when the mode kind is unchanged — so a user editing
    /// `script_id` / `passthrough_hosts` / `fronting_groups` while running
    /// gets the new settings on the next connection. The listen host/port
    /// in `new_config` are ignored; changing those requires Stop + Start
    /// since rebinding a socket is fundamentally observable to clients.
    /// `coalesce_step_ms` / `coalesce_max_ms` ARE picked up — they're
    /// stored as atomics on `RuntimeState` and a Full-mode switch reads
    /// the current values for `TunnelMux::start`.
    ///
    /// Returns `Err(ProxyError::ShuttingDown)` if the proxy has already
    /// been stopped (or is in the middle of stopping). Callers should
    /// treat that as a no-op, not a UI-surfaced error — it just means
    /// the user clicked Stop while a SwitchMode was queued.
    pub async fn switch_mode(self: &Arc<Self>, new_config: &Config) -> Result<(), ProxyError> {
        let _serial = self.switch_serial_lock.lock().await;
        {
            let _g = self.switch_lock.lock().await;
            if self.stopped.load(Ordering::SeqCst) {
                return Err(ProxyError::ShuttingDown);
            }
        }

        // Build the new state BEFORE touching live state — if config parse
        // or DomainFronter::new fails, the running proxy stays on its
        // current bundle untouched. Errors propagate to the UI. DriveMux
        // startup may refresh OAuth over the network, so all pre-build work
        // happens before the shutdown/swap lock is taken.
        let (new_fronter, new_ctx, new_mode) = build_mode_state(new_config)?;
        // Pick up coalesce edits from `new_config` so a Full-mode switch
        // honours the latest tuning. Stored as the runtime's "current
        // snapshot" so subsequent switches (and any future `run()`
        // restarts, although that path doesn't exist today) see them too.
        let (new_step, new_max) = resolve_coalesce(new_config);

        // Build a fresh `DriveMux` if the post-switch mode is Drive,
        // else `None`. A switch *away* from Drive lets the previous mux
        // drop, which causes the shared poller to exit naturally — same
        // shape as `TunnelMux`'s lifecycle. Errors propagate as
        // `ProxyError` so the UI surfaces malformed Drive config the same
        // way it surfaces a missing `script_id` on a switch to AppsScript.
        let new_drive_mux = if new_mode == Mode::Drive {
            Some(
                crate::drive_client::DriveMux::start(new_config)
                    .await
                    .map_err(|e| std::io::Error::other(format!("drive mux: {e}")))?,
            )
        } else {
            None
        };

        let _g = self.switch_lock.lock().await;
        // Re-check `stopped` under the lock: the shutdown arm of `run()`
        // sets this also under `switch_lock`, so once we hold the lock
        // either (a) shutdown has not yet run and stopped == false, or
        // (b) shutdown has run, stopped == true, and we must NOT spawn
        // tasks because nothing will abort them.
        if self.stopped.load(Ordering::SeqCst) {
            return Err(ProxyError::ShuttingDown);
        }

        self.coalesce_step_ms.store(new_step, Ordering::Relaxed);
        self.coalesce_max_ms.store(new_max, Ordering::Relaxed);
        let new_mux = if new_mode == Mode::Full {
            new_fronter
                .as_ref()
                .map(|f| TunnelMux::start(f.clone(), new_step, new_max))
        } else {
            None
        };

        // Abort old mode tasks BEFORE the swap so the old fronter's refcount
        // can drop. The accept loops still see the old bundle until the
        // store() below; that's fine — they don't read `mode_tasks`.
        {
            let mut tasks = self.mode_tasks.lock().await;
            tasks.abort_all();
        }

        let prev_mode = self.bundle.load().rewrite_ctx.mode;
        self.bundle.store(Arc::new(ModeBundle {
            rewrite_ctx: new_ctx,
            fronter: new_fronter.clone(),
            tunnel_mux: new_mux,
            drive_mux: new_drive_mux,
        }));

        // Refresh stored config snapshot before spawning so the new
        // mode_tasks (notably `run_ip_health`) read the post-switch
        // values rather than the construction-time ones.
        self.config.store(Arc::new(new_config.clone()));

        if let Some(f) = new_fronter {
            let mut tasks = self.mode_tasks.lock().await;
            // Tasks could only land here on a stopped runtime if a Stop
            // raced past the early `stopped` check above (the shutdown
            // arm takes `switch_lock` and sets `stopped` before
            // releasing). The early check inside `switch_lock` makes
            // that impossible by construction; spawn unconditionally.
            spawn_mode_tasks(&mut tasks, f, new_config);
        }

        tracing::warn!(
            "Mode switched live: {} → {} (listeners unchanged)",
            prev_mode.as_str(),
            new_mode.as_str(),
        );

        Ok(())
    }
}

/// Back-off helper for the accept() loop.
///
/// Motivated by issue #18: when the process hits its file-descriptor limit
/// (EMFILE — `No file descriptors available`), `accept()` returns that
/// error synchronously and is immediately ready to fire again. The old
/// loop just `continue`'d, producing a wall of identical ERROR lines
/// thousands per second and starving the tokio runtime of CPU that
/// existing connections would have used to drain and close.
///
/// Two things this does right:
///   1. Sleeps when `EMFILE` / `ENFILE` are seen, proportional to how long
///      the problem has been going on (exponential-ish, capped at 2s).
///      Gives existing connections a chance to finish and free fds.
///   2. Rate-limits the log line: first occurrence logs a full warning
///      with fix instructions, subsequent ones log once per 100 errors
///      so the log doesn't fill up.
async fn accept_backoff(kind: &str, err: &std::io::Error, count: &mut u64) {
    let is_fd_limit = matches!(
        err.raw_os_error(),
        Some(libc_emfile) if libc_emfile == 24 || libc_emfile == 23
    );

    *count = count.saturating_add(1);

    if is_fd_limit {
        if *count == 1 {
            tracing::warn!(
                "accept ({}) hit RLIMIT_NOFILE: {}. Backing off. Raise the fd limit: \
                 `ulimit -n 65536` before starting, or (OpenWRT) use the shipped procd \
                 init which sets nofile=16384. The listener will keep retrying.",
                kind,
                err
            );
        } else if (*count).is_multiple_of(100) {
            tracing::warn!(
                "accept ({}) still fd-limited after {} retries. Current connections \
                 need to finish before we can accept new ones.",
                kind,
                *count
            );
        }
        // Back off exponentially-ish up to 2s. First hit: 50ms, 10th hit:
        // ~500ms, 50th+: 2s cap.
        let backoff_ms = (50u64 * (*count).min(40)).min(2000);
        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
    } else {
        // Transient non-EMFILE error (e.g. ECONNABORTED from a client that
        // went away during the handshake). One-line log, short sleep to
        // avoid a tight loop in case it repeats.
        tracing::error!("accept ({}): {}", kind, err);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

async fn handle_http_client(
    mut sock: TcpStream,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
    drive_mux: Option<Arc<crate::drive_client::DriveMux>>,
) -> std::io::Result<()> {
    let (head, leftover) = match read_http_head(&mut sock).await? {
        HeadReadResult::Got { head, leftover } => (head, leftover),
        HeadReadResult::Closed => return Ok(()),
        HeadReadResult::Oversized => {
            // Reply with 431 instead of just dropping the socket so the
            // browser shows a real error rather than retrying the same
            // oversized request in a loop.
            tracing::warn!(
                "request head exceeds {} bytes — refusing with 431",
                MAX_HEADER_BYTES
            );
            let _ = sock
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
                      Connection: close\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
            let _ = sock.flush().await;
            return Ok(());
        }
    };

    let (method, target, _version, _headers) = parse_request_head(&head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target);
        // Mirror the SOCKS5 short-circuit: if the tunnel-node just failed
        // this (host, port) with unreachable, return 502 immediately rather
        // than acknowledging the CONNECT and blowing tunnel quota on a
        // guaranteed retry. See `TunnelMux::is_unreachable` for context.
        if let Some(ref mux) = tunnel_mux {
            if mux.is_unreachable(&host, port) {
                tracing::info!("CONNECT {}:{} (negative-cached, refusing)", host, port);
                let _ = sock
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = sock.flush().await;
                return Ok(());
            }
        }
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        sock.flush().await?;
        dispatch_tunnel(
            sock,
            host,
            port,
            fronter,
            mitm,
            rewrite_ctx,
            tunnel_mux,
            drive_mux,
        )
        .await
    } else {
        // Plain HTTP proxy request (e.g. `GET http://…`).
        //
        // apps_script mode: relay through the Apps Script fronter (which
        // is the whole point of the relay).
        //
        // direct mode: no fronter exists, so passthrough as raw TCP.
        // Same contract as `dispatch_tunnel` honors for CONNECT in
        // direct mode — anything not on the Google edge / not in a
        // configured fronting_group is forwarded direct (or via
        // `upstream_socks5`) so the user's browser still works while
        // they finish setting up Apps Script. Issue: typing a bare
        // `http://example.com` URL used to return a 502 here even
        // though `https://example.com` (CONNECT) worked fine.
        if rewrite_ctx.mode == Mode::Drive {
            match drive_mux {
                Some(mux) => do_plain_http_drive(sock, &head, &leftover, &rewrite_ctx, mux).await,
                None => {
                    tracing::error!(
                        "plain HTTP request in drive mode but no drive mux (should not happen)"
                    );
                    Ok(())
                }
            }
        } else {
            match fronter {
                Some(f) => do_plain_http(sock, &head, &leftover, f).await,
                None => do_plain_http_passthrough(sock, &head, &leftover, &rewrite_ctx).await,
            }
        }
    }
}

// ---------- SOCKS5 ----------

async fn handle_socks5_client(
    mut sock: TcpStream,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
    drive_mux: Option<Arc<crate::drive_client::DriveMux>>,
) -> std::io::Result<()> {
    // RFC 1928 handshake: VER=5, NMETHODS, METHODS...
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    // Only "no auth" (0x00) is supported.
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    sock.write_all(&[0x05, 0x00]).await?;

    // Request: VER=5, CMD, RSV=0, ATYP, DST.ADDR, DST.PORT
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    let cmd = req[1];
    if cmd != 0x01 && cmd != 0x03 {
        // CONNECT and UDP ASSOCIATE only.
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let atyp = req[3];
    let host: String = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            sock.read_exact(&mut ip).await?;
            let addr = std::net::Ipv6Addr::from(ip);
            addr.to_string()
        }
        _ => {
            sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    if cmd == 0x03 {
        tracing::info!("SOCKS5 UDP ASSOCIATE requested for {}:{}", host, port);
        return handle_socks5_udp_associate(sock, rewrite_ctx, tunnel_mux).await;
    }

    // Negative-cache short-circuit: if the tunnel-node just failed to reach
    // this exact (host, port) with `Network is unreachable` / `No route to
    // host`, reply 0x04 (Host unreachable) immediately. Saves a 1.5–2s tunnel
    // round-trip on guaranteed-failing targets — the IPv6 probe retry loop
    // is the main offender on devices without IPv6.
    if let Some(ref mux) = tunnel_mux {
        if mux.is_unreachable(&host, port) {
            tracing::info!(
                "SOCKS5 CONNECT -> {}:{} (negative-cached, refusing)",
                host,
                port
            );
            sock.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            sock.flush().await?;
            return Ok(());
        }
    }

    // `block_stun` is UDP-only by design: the goal is to make WebRTC
    // skip UDP ICE candidates so it falls back to TCP TURN. Blocking
    // TCP/3478 too would break the very fallback path we're steering
    // clients toward (TURN-TCP deployments that don't advertise :443),
    // so we leave the CONNECT path alone here. The matching UDP
    // datagram filter lives in `handle_socks5_udp_associate`.

    tracing::info!("SOCKS5 CONNECT -> {}:{}", host, port);

    // Success reply with zeroed BND.
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    sock.flush().await?;

    dispatch_tunnel(
        sock,
        host,
        port,
        fronter,
        mitm,
        rewrite_ctx,
        tunnel_mux,
        drive_mux,
    )
    .await
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SocksUdpTarget {
    host: String,
    port: u16,
    atyp: u8,
    addr: Vec<u8>,
}

/// Per-target relay session state shared between the dispatch loop and
/// the per-session task. The dispatch loop pushes uplink datagrams via
/// `uplink`; the task drains the upstream and serializes both directions
/// onto a single tunnel-mux call at a time. `sid` is held here so the
/// dispatch teardown path can issue close_session for any task it has
/// to abort mid-await.
struct UdpRelaySession {
    sid: String,
    uplink: mpsc::Sender<Bytes>,
}

/// All per-ASSOCIATE UDP relay state behind a single mutex so insertion
/// order, the live-session map, and per-task self-removal can all stay
/// consistent. Wrapping each separately invited a slow leak: the
/// previous design's `insertion_order` deque was only pruned on
/// overflow eviction, so a long-lived ASSOCIATE that opened many
/// short-lived sessions accumulated dead `SocksUdpTarget` entries.
struct UdpRelayState {
    sessions: HashMap<SocksUdpTarget, UdpRelaySession>,
    /// Insertion-order log for FIFO eviction. NOT a real LRU — repeated
    /// uplinks to a hot session do not move it to the back. We keep it
    /// in lockstep with `sessions` (insert appends; remove scans and
    /// erases the matching entry — O(N) but N ≤ 256).
    order: VecDeque<SocksUdpTarget>,
}

impl UdpRelayState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get_uplink(&self, target: &SocksUdpTarget) -> Option<mpsc::Sender<Bytes>> {
        self.sessions.get(target).map(|s| s.uplink.clone())
    }

    fn insert(&mut self, target: SocksUdpTarget, session: UdpRelaySession) {
        self.order.push_back(target.clone());
        self.sessions.insert(target, session);
    }

    fn remove(&mut self, target: &SocksUdpTarget) {
        if let Some(pos) = self.order.iter().position(|t| t == target) {
            self.order.remove(pos);
        }
        self.sessions.remove(target);
    }

    /// Pop the oldest session entries until `sessions.len() < cap`.
    /// Stale `order` entries (already removed by self-cleanup on a
    /// task's natural exit) are quietly skipped.
    fn evict_until_under(&mut self, cap: usize) -> Vec<SocksUdpTarget> {
        let mut evicted = Vec::new();
        while self.sessions.len() >= cap {
            let Some(victim) = self.order.pop_front() else {
                break;
            };
            if self.sessions.remove(&victim).is_some() {
                evicted.push(victim);
            }
        }
        evicted
    }

    /// Snapshot live sids for the teardown close_session sweep. We
    /// take a copy (not a drain) so the caller can decide whether to
    /// also clear the map.
    fn live_sids(&self) -> Vec<String> {
        self.sessions.values().map(|s| s.sid.clone()).collect()
    }

    fn clear(&mut self) {
        self.sessions.clear();
        self.order.clear();
    }
}

/// SOCKS5 UDP request frame: 4-byte header + atyp-specific address + 2-byte
/// port + payload. DOMAIN atyp uses a 1-byte length prefix + up to 255
/// bytes, so the largest header is `4 + 1 + 255 + 2 = 262`. Round to 300
/// for safety; payload itself can be a full 64 KB datagram.
const SOCKS5_UDP_RECV_BUF_BYTES: usize = 65535 + 300;

/// Bound on per-session uplink queue depth. UDP is lossy by design — if
/// the per-session task can't keep up, drop the newest datagram (caller
/// uses `try_send`) instead of stalling the whole UDP relay loop.
const UDP_UPLINK_QUEUE: usize = 64;

/// Initial poll spacing when a session is idle. Tunnel-node already
/// long-polls each empty `udp_data` for up to 5 s, so this is a
/// client-side floor — bursts of upstream packets reset back to this.
const UDP_INITIAL_POLL_DELAY: Duration = Duration::from_millis(500);

/// Cap on the exponential backoff for an idle session. After this many
/// seconds of zero traffic in either direction, polls happen at most
/// once per `UDP_MAX_POLL_DELAY` plus the tunnel-node long-poll window —
/// so an idle UDP destination costs roughly one batch slot every 35 s.
const UDP_MAX_POLL_DELAY: Duration = Duration::from_secs(30);

/// Cap on simultaneous UDP relay sessions per SOCKS5 ASSOCIATE. STUN
/// candidate gathering and DNS fanout produce dozens of distinct
/// targets; an abusive or runaway client could produce thousands.
/// 256 is generous for legitimate use and bounds tunnel-node UDP
/// sessions a single ASSOCIATE can hold open.
///
/// Eviction policy is FIFO by insertion time, not true LRU — repeated
/// uplinks to a hot session do not move it to the back. Real LRU
/// would need a touch on every uplink (extra lock acquisition per
/// datagram); the long-tail of dead targets gets cleaned up here just
/// fine without that cost, and live targets are typically also recently
/// inserted.
const MAX_UDP_SESSIONS_PER_ASSOCIATE: usize = 256;

/// Drop UDP datagrams larger than this (pre-base64). Standard MTU is
/// 1500B, jumbo frames are ~9000B; anything above that is either a
/// pathologically fragmented IP datagram or abusive traffic. Each
/// datagram carries ~33% base64 + JSON envelope overhead and consumes
/// Apps Script per-account quota, so a permissive ceiling here matters.
const MAX_UDP_PAYLOAD_BYTES: usize = 9 * 1024;

async fn handle_socks5_udp_associate(
    mut control: TcpStream,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    if rewrite_ctx.mode != Mode::Full {
        tracing::debug!("UDP ASSOCIATE rejected: only full mode supports UDP tunneling");
        write_socks5_reply(&mut control, 0x07, None).await?;
        return Ok(());
    }
    let Some(mux) = tunnel_mux else {
        tracing::debug!("UDP ASSOCIATE rejected: full mode has no tunnel mux");
        write_socks5_reply(&mut control, 0x01, None).await?;
        return Ok(());
    };

    // Per RFC 1928 §6 the UDP relay only accepts datagrams from the
    // SOCKS5 client. We pin the source IP to the control TCP peer up
    // front so a third party on the bind interface can't hijack the
    // session by sending the first datagram. THIS — not the bind IP
    // below — is what actually keeps unauthenticated traffic out.
    let client_peer_ip = control.peer_addr()?.ip();

    // Bind the UDP relay to the same local IP the SOCKS5 client used
    // to reach the control TCP socket. `TcpStream::local_addr()` on an
    // accepted socket returns the concrete terminating address (e.g.
    // 127.0.0.1 for a loopback client, 192.168.1.5 for a LAN client),
    // not the listener's bind specifier — so this naturally tracks the
    // path the client took. Source-IP filtering above is the security
    // boundary; the bind choice is just about reachability.
    let bind_ip = control.local_addr()?.ip();
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    write_socks5_reply(&mut control, 0x00, Some(udp.local_addr()?)).await?;
    tracing::info!(
        "SOCKS5 UDP relay bound on {} for client {}",
        udp.local_addr()?,
        client_peer_ip
    );

    // Fixed reusable recv buffer. We deliberately don't go the
    // `BytesMut::split().freeze()` route here even though `tunnel_loop`
    // does: in TCP the read region IS the payload, but UDP always
    // slices the SOCKS5 header off, so we'd be copying out anyway —
    // and a frozen `Bytes` from the recv buf would refcount-pin the
    // full ~65 KB allocation behind a tiny DNS reply, ballooning
    // memory under bursts. Right-sized `Bytes::copy_from_slice` on
    // accepted payloads keeps retention proportional to actual data.
    let mut recv_buf = vec![0u8; SOCKS5_UDP_RECV_BUF_BYTES];
    let mut control_buf = [0u8; 1];
    let mut client_addr: Option<SocketAddr> = None;
    let state: Arc<Mutex<UdpRelayState>> = Arc::new(Mutex::new(UdpRelayState::new()));
    // Tracking per-target tasks here — instead of bare `tokio::spawn`
    // — lets the teardown path call `abort_all()`, cancelling any
    // in-flight `mux.udp_data` await. Without it, a task mid-poll
    // could keep paying tunnel-node round trips for up to 5 s after
    // the SOCKS5 client went away.
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut oversized_dropped: u64 = 0;
    let mut sessions_evicted: u64 = 0;
    let mut foreign_ip_drops: u64 = 0;

    loop {
        tokio::select! {
            recv = udp.recv_from(&mut recv_buf) => {
                let (n, peer) = match recv {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("udp associate recv failed: {}", e);
                        break;
                    }
                };

                // Source-IP check: anything not from the SOCKS5 client's
                // host is dropped silently.
                if peer.ip() != client_peer_ip {
                    foreign_ip_drops += 1;
                    if foreign_ip_drops == 1 || foreign_ip_drops.is_multiple_of(100) {
                        tracing::debug!(
                            "udp dropped from unauthorized source {}: count={}",
                            peer.ip(),
                            foreign_ip_drops,
                        );
                    }
                    continue;
                }

                // Parse BEFORE port-locking. A malformed datagram from
                // the right IP must not pin client_addr to its source
                // port — otherwise a co-tenant on the bind interface
                // can race one bad packet to DoS the legitimate client
                // (whose real datagram, sent from a different ephemeral
                // port, would then be silently rejected).
                let Some((target, payload_off)) = parse_socks5_udp_packet_offsets(&recv_buf[..n]) else {
                    continue;
                };
                let payload_slice = &recv_buf[payload_off..n];

                // Issue #213: client-side QUIC block. UDP/443 is
                // HTTP/3 — drop the datagram silently so the client
                // stack retries a couple of times and then falls back
                // to TCP/HTTPS, which goes through the regular CONNECT
                // path. Skipping this at the SOCKS5 layer (rather than
                // letting it hit the tunnel-node) avoids paying the
                // 200–500 ms tunnel-node round-trip per dropped QUIC
                // datagram, which would otherwise compound during the
                // 1–3 retries before the browser falls back.
                //
                // Silent drop instead of an explicit error reply: the
                // SOCKS5 UDP wire has no "destination unreachable"
                // datagram — `0x04` only exists in TCP CONNECT replies
                // (RFC 1928 §6). The browser's QUIC stack already has
                // a "no response → fall back" timeout, so silent drop
                // is the contractually correct shape.
                if rewrite_ctx.block_quic && target.port == 443 {
                    tracing::debug!(
                        "udp dropped: block_quic=true, target {}:443",
                        target.host
                    );
                    continue;
                }

                // Same shape as the QUIC drop above, but for WebRTC
                // STUN/TURN. The intent is to make Meet/Discord/WhatsApp
                // skip UDP ICE candidates and fall back to TCP TURN on
                // :443 immediately, instead of waiting out the 10–30 s
                // ICE timeout per attempt. The upstream PR added the
                // matching CONNECT-path check; doing it here too is what
                // actually denies the UDP candidates that the PR's
                // comment claims to deny.
                if rewrite_ctx.block_stun && is_stun_turn_port(target.port) {
                    tracing::debug!(
                        "udp dropped: block_stun=true, target {}:{}",
                        target.host,
                        target.port,
                    );
                    continue;
                }

                // RFC 1928 §6: lock to the first VALID datagram's source
                // port. Subsequent datagrams must come from the same
                // (ip, port) pair.
                if let Some(existing) = client_addr {
                    if existing != peer {
                        continue;
                    }
                } else {
                    tracing::info!("UDP relay locked to client {}", peer);
                    client_addr = Some(peer);
                }

                // Size guard: drop oversize datagrams before they reach
                // the mux. Each datagram costs ~payload * 1.33 in the
                // batched JSON envelope plus tunnel-node CPU; uncapped,
                // a runaway client can exhaust Apps Script quota.
                if payload_slice.len() > MAX_UDP_PAYLOAD_BYTES {
                    oversized_dropped += 1;
                    if oversized_dropped == 1 || oversized_dropped.is_multiple_of(100) {
                        tracing::debug!(
                            "udp datagram dropped: {} B > {} B (count={})",
                            payload_slice.len(),
                            MAX_UDP_PAYLOAD_BYTES,
                            oversized_dropped,
                        );
                    }
                    continue;
                }

                // Right-sized copy: the queued/in-flight payload owns its
                // own allocation, so the recv buffer can be reused on the
                // next iteration without keeping every queued datagram
                // alive. Sized to the actual payload (≤ MAX_UDP_PAYLOAD_BYTES
                // = 9 KB after the guard above), not the full ~65 KB recv
                // buffer.
                let payload = Bytes::copy_from_slice(payload_slice);

                // Fast path: existing session — push payload onto its
                // bounded uplink queue, drop on overflow (UDP semantics).
                {
                    let st = state.lock().await;
                    if let Some(uplink) = st.get_uplink(&target) {
                        let _ = uplink.try_send(payload);
                        continue;
                    }
                }

                // Cap reached → evict oldest sessions before opening a
                // new one. Each evicted entry drops its uplink Sender,
                // which causes the per-session task to exit its select
                // and tell tunnel-node to close. Any uplink already in
                // that channel is delivered before the task exits.
                {
                    let mut st = state.lock().await;
                    let evicted = st.evict_until_under(MAX_UDP_SESSIONS_PER_ASSOCIATE);
                    for victim in evicted {
                        sessions_evicted += 1;
                        if sessions_evicted == 1 || sessions_evicted.is_multiple_of(50) {
                            tracing::debug!(
                                "udp session cap {} reached; evicted {}:{} (total evicted={})",
                                MAX_UDP_SESSIONS_PER_ASSOCIATE,
                                victim.host,
                                victim.port,
                                sessions_evicted,
                            );
                        }
                    }
                }

                // New target: open via tunnel-node and spawn the per-session
                // task. The first datagram rides the udp_open op so we
                // save one round trip on session establishment.
                let resp = match mux.udp_open(&target.host, target.port, payload).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(
                            "udp open {}:{} failed: {}",
                            target.host, target.port, e
                        );
                        continue;
                    }
                };
                if let Some(ref e) = resp.e {
                    tracing::debug!("udp open {}:{} failed: {}", target.host, target.port, e);
                    continue;
                }
                let Some(sid) = resp.sid.clone() else {
                    tracing::debug!(
                        "udp open {}:{} returned no sid",
                        target.host, target.port
                    );
                    continue;
                };
                send_udp_response_packets(&udp, peer, &target, &resp).await;

                // Tunnel-node may report eof on the open response if the
                // upstream socket died between bind and the first drain
                // (e.g., immediate ICMP unreachable). The session has
                // already been reaped on that side — skip insert/spawn
                // and let the next datagram from the client retry.
                if resp.eof.unwrap_or(false) {
                    tracing::debug!(
                        "udp open {}:{} returned eof; not tracking session",
                        target.host,
                        target.port,
                    );
                    continue;
                }

                let (uplink_tx, uplink_rx) = mpsc::channel::<Bytes>(UDP_UPLINK_QUEUE);
                let task_mux = mux.clone();
                let task_udp = udp.clone();
                let task_target = target.clone();
                let task_state = state.clone();
                let task_sid = sid.clone();
                tasks.spawn(async move {
                    udp_session_task(
                        task_mux,
                        task_udp,
                        task_sid,
                        task_target.clone(),
                        peer,
                        uplink_rx,
                    )
                    .await;
                    // Natural-exit cleanup (eof / mux error / channel
                    // close): remove from shared state so a future
                    // packet to the same target opens a fresh session,
                    // and so insertion_order doesn't leak. Skipped on
                    // teardown since abort_all cancels this await point.
                    task_state.lock().await.remove(&task_target);
                });

                state.lock().await.insert(
                    target,
                    UdpRelaySession {
                        sid,
                        uplink: uplink_tx,
                    },
                );
            }
            read = control.read(&mut control_buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }

    // Teardown. Snapshot live sids first; they're authoritative for
    // which tunnel-node sessions still exist. Then clear state — that
    // drops every uplink Sender, so any task waiting on `recv()` wakes
    // and exits naturally. Finally `abort_all` cancels tasks that were
    // mid-`mux.udp_data` await; for those the natural-exit close won't
    // run, so we send close_session here on their behalf.
    let live_sids: Vec<String>;
    {
        let mut st = state.lock().await;
        live_sids = st.live_sids();
        st.clear();
    }
    tasks.abort_all();
    for sid in live_sids {
        mux.close_session(&sid).await;
    }
    Ok(())
}

/// Per-target relay task. Owns one tunnel-node UDP session and shuttles
/// datagrams in both directions through a single in-flight tunnel call
/// at a time. Two cancellation points:
///   * `uplink_rx.recv()` returns `None` when the dispatch loop drops
///     the matching `Sender` (SOCKS5 client gone, or session evicted).
///   * `mux.udp_data` returns eof / error when the tunnel-node session
///     is reaped or the target is unreachable.
async fn udp_session_task(
    mux: Arc<TunnelMux>,
    udp: Arc<UdpSocket>,
    sid: String,
    target: SocksUdpTarget,
    client_addr: SocketAddr,
    mut uplink_rx: mpsc::Receiver<Bytes>,
) {
    let mut backoff = UDP_INITIAL_POLL_DELAY;
    loop {
        // `biased;` prefers uplink so an active client doesn't get
        // shadowed by a long sleep. Both branches are cancel-safe.
        let resp = tokio::select! {
            biased;
            uplink = uplink_rx.recv() => {
                let Some(payload) = uplink else { break; };
                // Active uplink — reset the empty-poll backoff so the
                // next inbound poll happens promptly.
                backoff = UDP_INITIAL_POLL_DELAY;
                match mux.udp_data(&sid, payload).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("udp data {} failed: {}", sid, e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(backoff) => {
                match mux.udp_data(&sid, Vec::new()).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("udp poll {} failed: {}", sid, e);
                        break;
                    }
                }
            }
        };
        if resp.e.is_some() || resp.eof.unwrap_or(false) {
            break;
        }
        let got_pkts = resp.pkts.as_ref().map(|p| !p.is_empty()).unwrap_or(false);
        if got_pkts {
            send_udp_response_packets(&udp, client_addr, &target, &resp).await;
            backoff = UDP_INITIAL_POLL_DELAY;
        } else {
            // Empty poll — back off so an idle destination doesn't
            // monopolize batch slots.
            backoff = (backoff * 2).min(UDP_MAX_POLL_DELAY);
        }
    }
    // Be polite even if the session is already gone server-side; the
    // tunnel-node tolerates close on an unknown sid.
    mux.close_session(&sid).await;
}

async fn send_udp_response_packets(
    udp: &UdpSocket,
    client_addr: SocketAddr,
    target: &SocksUdpTarget,
    resp: &crate::domain_fronter::TunnelResponse,
) {
    let packets = match decode_udp_packets(resp) {
        Ok(packets) => packets,
        Err(e) => {
            tracing::debug!("{}", e);
            return;
        }
    };
    for packet in packets {
        let framed = build_socks5_udp_packet(target, &packet);
        if let Err(e) = udp.send_to(&framed, client_addr).await {
            // Errors here mean the local socket can't reach the SOCKS5
            // client (ENETUNREACH, EHOSTDOWN, etc.). Surface at debug
            // so a "my UDP traffic isn't coming back" report has
            // something to grep for; volume is bounded by what we'd
            // have delivered anyway.
            tracing::debug!(
                "udp send to client {} failed for {}:{}: {}",
                client_addr,
                target.host,
                target.port,
                e,
            );
        }
    }
}

async fn write_socks5_reply(
    sock: &mut TcpStream,
    rep: u8,
    addr: Option<SocketAddr>,
) -> std::io::Result<()> {
    let mut out = vec![0x05, rep, 0x00];
    match addr {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            out.push(0x01);
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    sock.write_all(&out).await?;
    sock.flush().await
}

/// Parse the SOCKS5 UDP frame header and return the target plus the byte
/// offset at which the payload starts. Splitting "structure parsing"
/// from "give me a payload slice" lets the recv hot path stay on a
/// fixed reusable `Vec<u8>` buffer and only allocate a right-sized
/// `Bytes::copy_from_slice(&recv_buf[off..n])` for accepted payloads
/// (after the size guard). DO NOT change this back to a zero-copy
/// `Bytes::slice` path: that was tried and reverted because slicing
/// the recv buffer with `bytes` 1.x refcounts the whole ~65 KB
/// allocation, so a queued tiny DNS reply pinned the full datagram-
/// sized buffer until it drained — burst retention regressed by
/// orders of magnitude on UDP-heavy workloads. The thin
/// `parse_socks5_udp_packet` wrapper below keeps existing `&[u8]`
/// callers (tests) working.
fn parse_socks5_udp_packet_offsets(buf: &[u8]) -> Option<(SocksUdpTarget, usize)> {
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return None;
    }
    let atyp = buf[3];
    let mut pos = 4usize;
    let (host, addr) = match atyp {
        0x01 => {
            if buf.len() < pos + 4 + 2 {
                return None;
            }
            let addr = buf[pos..pos + 4].to_vec();
            pos += 4;
            let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            (ip.to_string(), addr)
        }
        0x03 => {
            if buf.len() < pos + 1 {
                return None;
            }
            let len = buf[pos] as usize;
            pos += 1;
            if len == 0 || buf.len() < pos + len + 2 {
                return None;
            }
            let addr = buf[pos..pos + len].to_vec();
            pos += len;
            // Reject non-UTF-8 hostnames at the parser. Lossy decoding
            // would forward U+FFFD into DNS and trigger an opaque
            // NXDOMAIN — failing fast here gives us a clean parse-level
            // drop that the test suite can assert on.
            let host = std::str::from_utf8(&addr).ok()?.to_owned();
            (host, addr)
        }
        0x04 => {
            if buf.len() < pos + 16 + 2 {
                return None;
            }
            let addr = buf[pos..pos + 16].to_vec();
            pos += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr);
            (std::net::Ipv6Addr::from(octets).to_string(), addr)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Some((
        SocksUdpTarget {
            host,
            port,
            atyp,
            addr,
        },
        pos,
    ))
}

fn parse_socks5_udp_packet(buf: &[u8]) -> Option<(SocksUdpTarget, &[u8])> {
    let (target, off) = parse_socks5_udp_packet_offsets(buf)?;
    Some((target, &buf[off..]))
}

fn build_socks5_udp_packet(target: &SocksUdpTarget, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + target.addr.len() + 2 + payload.len() + 1);
    out.extend_from_slice(&[0, 0, 0, target.atyp]);
    match target.atyp {
        0x03 => {
            out.push(target.addr.len() as u8);
            out.extend_from_slice(&target.addr);
        }
        _ => out.extend_from_slice(&target.addr),
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ---------- Smart dispatch (used by both HTTP CONNECT and SOCKS5) ----------

fn should_use_sni_rewrite(
    hosts: &std::collections::HashMap<String, String>,
    host: &str,
    port: u16,
    youtube_via_relay: bool,
    force_mitm_hosts: &[String],
) -> bool {
    // The SNI-rewrite path expects TLS from the client: it accepts inbound
    // TLS, then opens a second TLS connection to the Google edge with a front
    // SNI. Auto-forcing that path for non-TLS ports (for example a SOCKS5
    // CONNECT to google.com:80) makes the proxy wait for a ClientHello that
    // will never arrive.
    //
    // youtube_via_relay=true removes YouTube suffixes from the match so
    // YouTube traffic falls through to the Apps Script relay path instead
    // of the SNI-rewrite tunnel. An explicit hosts override still wins
    // over the config toggle, except for hosts pulled out by
    // `relay_url_patterns` — those need MITM for the per-path matcher
    // even if the user has a hosts override (the override is still used
    // as the upstream IP for the SNI-rewrite forwarder, just not as a
    // CONNECT-tunnel target).
    if port != 443 {
        return false;
    }
    if host_in_force_mitm_list(host, force_mitm_hosts) {
        return false;
    }
    matches_sni_rewrite(host, youtube_via_relay, force_mitm_hosts)
        || hosts_override(hosts, host).is_some()
}

async fn dispatch_tunnel(
    sock: TcpStream,
    host: String,
    port: u16,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
    drive_mux: Option<Arc<crate::drive_client::DriveMux>>,
) -> std::io::Result<()> {
    // Early routing decisions that don't need socket reads live in the
    // pure `classify_early_route` helper so the precedence (especially
    // LocalBypass-above-DoH and passthrough_hosts-above-everything) is
    // exhaustively unit-testable. See the [`EarlyRoute`] doc for the
    // ordering rationale, and the dispatcher tests further down in
    // this file for the regression-pinning cases.
    let early = classify_early_route(
        &host,
        port,
        rewrite_ctx.mode,
        &rewrite_ctx.passthrough_hosts,
        &rewrite_ctx.bypass_doh_hosts,
        rewrite_ctx.block_doh,
        rewrite_ctx.bypass_doh,
    );
    match early {
        EarlyRoute::PassthroughHostsMatch => {
            // User-configured passthrough list wins over every other path.
            // The host matches `passthrough_hosts`, so we raw-TCP it
            // (through upstream_socks5 if set) and never touch Apps
            // Script, SNI-rewrite, or MITM. Point: saves Apps Script
            // quota on hosts the user already has reachability to, and
            // avoids MITM-breaking cert pinning on hosts the user
            // knows are cert-pinned. Issues #39, #127.
            let via = rewrite_ctx.upstream_socks5.as_deref();
            tracing::info!(
                "dispatch {}:{} -> raw-tcp ({}) (passthrough_hosts match)",
                host,
                port,
                via.unwrap_or("direct")
            );
            plain_tcp_passthrough(sock, &host, port, via).await;
            return Ok(());
        }
        EarlyRoute::LocalBypass => {
            // Fragmented direct-to-destination for every TLS CONNECT
            // (any port) except DoH-block matches and explicit
            // passthrough_hosts (those branches won above). Raw
            // passthrough for everything else. No Apps Script, no
            // SNI-rewrite, no MITM CA install. Defeats DPI only;
            // IP-blocked destinations stay unreachable.
            //
            // No `port == 443` gate by design: TLS in production
            // runs on 443, 8443 (alt-HTTPS), 993 (IMAPS), 853 (DoT),
            // 465 (SMTPS), etc. The TLS-handshake peek inside
            // `try_local_bypass_tunnel` is the right discriminator
            // — it returns `Skip(sock)` on any peek that isn't 0x16
            // (TLS handshake content type), so non-TLS connections
            // (HTTP on 80, SMTP on 25, server-first protocols
            // generally) fall through to raw passthrough below with
            // no false-positive fragmentation attempts.
            // User-pinned `hosts: { foo.com: 1.2.3.4 }` is honoured
            // in every other dispatch path in this file as a
            // deliberate user choice ("this IP works on my network").
            // LocalBypass had a hole where it ignored the override
            // and connected to whatever `host` resolved to; thread
            // the resolved IP through so fragmentation dials the
            // pinned address while the ClientHello still carries
            // the original SNI (the destination serves the right
            // cert, browser pinning checks succeed).
            let dial_override = hosts_override(&rewrite_ctx.hosts, &host).map(|s| s.to_string());
            tracing::debug!(
                "dispatch {}:{} -> local-bypass (TLS-peek fragmentation{})",
                host,
                port,
                match dial_override.as_deref() {
                    Some(ip) => format!(", dial={}", ip),
                    None => String::new(),
                },
            );
            match crate::direct_mode::try_local_bypass_tunnel(
                sock,
                &host,
                port,
                dial_override.as_deref(),
            )
            .await
            {
                Ok(crate::direct_mode::TunnelOutcome::Done) => return Ok(()),
                Ok(crate::direct_mode::TunnelOutcome::Skip(s)) => {
                    // Peeked non-TLS (HTTP on 80, server-first
                    // protocol on whatever port). No ClientHello to
                    // fragment, so the fragmentation-vs-SOCKS5
                    // incompatibility doesn't apply here — honour
                    // `upstream_socks5` like the passthrough_hosts
                    // arm above does. The startup warning in
                    // `build_mode_state` already tells users that
                    // local_bypass split-honours upstream; this
                    // branch is one of the "honour" sides.
                    let via = rewrite_ctx.upstream_socks5.as_deref();
                    tracing::info!(
                        "dispatch {}:{} -> raw-tcp ({}) (local-bypass: peeked non-TLS)",
                        host,
                        port,
                        via.unwrap_or("direct")
                    );
                    plain_tcp_passthrough(s, &host, port, via).await;
                    return Ok(());
                }
                Ok(crate::direct_mode::TunnelOutcome::SkipPrefaced(_)) => {
                    // `try_local_bypass_tunnel` does its raw-replay
                    // fallback internally, so this variant never
                    // reaches us. Guarded loudly so a future refactor
                    // that adds it gets a log line, not a silent drop.
                    tracing::error!(
                        "local-bypass returned SkipPrefaced (unexpected); dropping {}:{}",
                        host,
                        port
                    );
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!("local-bypass error for {}:{}: {}", host, port, e);
                    return Ok(());
                }
            }
        }
        EarlyRoute::BlockDoh => {
            // Reject connections to known DoH endpoints so browsers
            // fall back to system DNS (tun2proxy virtual DNS —
            // instant). Fires in every mode, including
            // `local_bypass` — `block_doh` is documented as a
            // global "immediately reject any CONNECT to a known DoH
            // endpoint" policy, and a strict-DoH deployment relies
            // on it surviving mode switches. See the precedence
            // doc on [`EarlyRoute`]; the LocalBypass arm sits
            // below this one on purpose.
            tracing::info!("dispatch {}:{} -> blocked (block_doh)", host, port);
            drop(sock);
            return Ok(());
        }
        EarlyRoute::BypassDoh => {
            // DNS-over-HTTPS is the dominant per-flow DNS cost in
            // Full mode (every browser name lookup costs a ~2 s Apps
            // Script round-trip), and the tunnel adds no privacy
            // beyond what DoH already provides. Route known DoH
            // hosts directly. Port-gated to 443 (inside the
            // classifier) so a non-TLS CONNECT to e.g.
            // `dns.google:80` doesn't get diverted off-tunnel by
            // accident. See `DEFAULT_DOH_HOSTS` and config.rs
            // `tunnel_doh`.
            let via = rewrite_ctx.upstream_socks5.as_deref();
            tracing::info!(
                "dispatch {}:{} -> raw-tcp ({}) (doh bypass)",
                host,
                port,
                via.unwrap_or("direct")
            );
            plain_tcp_passthrough(sock, &host, port, via).await;
            return Ok(());
        }
        EarlyRoute::Full => {
            // Full tunnel mode: ALL traffic goes through the batch
            // multiplexer (Apps Script → tunnel node → real TCP).
            // No MITM, no cert.
            let mux = match tunnel_mux {
                Some(m) => m,
                None => {
                    tracing::error!(
                        "dispatch {}:{} -> full mode but no tunnel mux (should not happen)",
                        host,
                        port
                    );
                    return Ok(());
                }
            };
            tracing::info!("dispatch {}:{} -> full tunnel (via batch mux)", host, port);
            crate::tunnel_client::tunnel_connection(sock, &host, port, &mux).await?;
            return Ok(());
        }
        EarlyRoute::Drive => {
            // Drive-mailbox transport: every TLS CONNECT becomes a
            // sequence of encrypted frames uploaded to a shared
            // Google Drive folder, which a separate
            // `rahgozar-drive-relay` process polls. No MITM (full
            // end-to-end tunnel), so the dispatcher hands the raw
            // socket straight to the Drive client. Same shape as
            // the `EarlyRoute::Full` arm above.
            let mux = match drive_mux {
                Some(m) => m,
                None => {
                    tracing::error!(
                        "dispatch {}:{} -> drive mode but no drive mux (should not happen)",
                        host,
                        port
                    );
                    return Ok(());
                }
            };
            tracing::info!("dispatch {}:{} -> drive tunnel (via drive mux)", host, port);
            crate::drive_client::tunnel_connection(sock, &host, port, &mux).await?;
            return Ok(());
        }
        EarlyRoute::Continue => {
            // Fall through to the steps below that need the socket
            // (fronting_groups peek, direct-mode TLS read, etc.).
        }
    }

    // 2a. User-configured fronting groups (Vercel, Fastly, etc.). Wins
    //     over the built-in Google SNI-rewrite suffix list AND over
    //     Direct Mode below — if a user adds e.g. `youtube.com` to a
    //     fronting group, that's an explicit override and the fronting
    //     edge takes precedence over the automatic Google routing.
    //     Port-gated to 443: SNI-rewrite needs a real ClientHello and
    //     a non-TLS CONNECT to the same hostname would just hang. Only
    //     HTTPS sites are fronted by these CDNs in practice, so the
    //     gate has no false negatives we care about.
    let mut sock = sock;
    if port == 443 {
        // `Arc::clone` here is refcount-only; we hold it across the
        // await below without keeping `rewrite_ctx` borrowed.
        let group_match = match_fronting_group(&host, &rewrite_ctx.fronting_groups).map(Arc::clone);
        if let Some(group) = group_match {
            if group.force_ip {
                // Camouflage mode: resolve the destination's real IP via
                // poison-safe DoH *before* consuming the socket. A DoH
                // miss MUST fall through to the rest of the dispatch
                // (relay in apps_script, raw-TCP in direct) rather than
                // MITM-terminate the browser and then drop the CONNECT —
                // dropping would regress a curated host like
                // googlevideo.com from "slow relay" to "connection
                // closes". The resolved IPs are threaded into the tunnel
                // so we don't pay a second lookup.
                //
                // Breaker check first (keyed by group name): if this
                // group's edge is already known-unreachable, fall through
                // *without even resolving DNS* — a tripped group's
                // fall-through is then truly free.
                let resolved = if camouflage_breaker_tripped(&group.name) {
                    None
                } else {
                    match &rewrite_ctx.doh_resolver {
                        Some(r) => r.resolve(&host).await.ok().filter(|v| !v.is_empty()),
                        None => None,
                    }
                };
                match resolved {
                    Some(ips) => {
                        tracing::info!(
                            "dispatch {}:{} -> camouflage tunnel (fronting group '{}', force_ip/DoH sni={})",
                            host,
                            port,
                            group.name,
                            group.sni
                        );
                        // Camouflage establishes the upstream BEFORE
                        // MITM-accepting the browser; on total upstream
                        // failure it returns the untouched socket so we
                        // fall through to the normal route instead of
                        // dropping the CONNECT.
                        match do_camouflage_tunnel(sock, &host, port, mitm.clone(), &group, ips)
                            .await
                        {
                            Ok(()) => return Ok(()),
                            Err(returned) => {
                                sock = returned;
                                tracing::debug!(
                                    "force_ip group '{}': upstream unreachable for {} — falling through to normal dispatch",
                                    group.name,
                                    host
                                );
                                // Fall through: sock/mitm/rewrite_ctx intact.
                            }
                        }
                    }
                    None => {
                        tracing::debug!(
                            "force_ip group '{}': DoH could not resolve {} — falling through to normal dispatch",
                            group.name,
                            host
                        );
                        // Fall through: sock/mitm/rewrite_ctx untouched.
                    }
                }
            } else {
                tracing::info!(
                    "dispatch {}:{} -> sni-rewrite tunnel (fronting group '{}', edge {} sni={})",
                    host,
                    port,
                    group.name,
                    group.ip,
                    group.sni
                );
                return do_sni_rewrite_tunnel_from_tcp(
                    sock,
                    &host,
                    port,
                    mitm,
                    rewrite_ctx,
                    Some(group),
                )
                .await;
            }
        }
    }

    // 2b. TLS-fragmentation Direct Mode for Google-owned domains.
    //     Sits between fronting_groups (2a) and the built-in
    //     SNI-rewrite suffix list (2) — explicit user fronting wins,
    //     but Direct Mode takes over from the MITM SNI-rewrite path
    //     for plain Google traffic. Big win: the browser does real
    //     TLS to Google with a real cert, so no MITM CA install is
    //     needed for any Google domain.
    //
    //     Skipped (handed to step 2 below) when:
    //       - port != 443 (need a real ClientHello to fragment);
    //       - host is in `force_mitm_hosts` — `relay_url_patterns`
    //         pulled this host out of SNI-rewrite specifically so
    //         the MITM path-matcher can run; bypassing MITM here
    //         would defeat that;
    //       - `youtube_via_relay` is on AND the host is one of the
    //         four `YOUTUBE_RELAY_HOSTS` — user explicitly wants
    //         YouTube traffic through the relay (e.g. for SafeSearch
    //         enforcement via SNI), so fragmented-direct is wrong.
    //         The carve-out is narrow: `ytimg.com` / `googlevideo.com`
    //         still go direct, matching how `matches_sni_rewrite`
    //         already treats them.
    //
    //     On total dial failure the socket comes back un-consumed
    //     (peek-only path) and falls through to step 2 — preserves
    //     the existing SNI-rewrite tunnel as a fallback on networks
    //     where fragmentation can't beat DPI alone.
    if should_take_direct_mode_branch(
        port,
        rewrite_ctx.direct_mode.as_ref(),
        &host,
        &rewrite_ctx.force_mitm_hosts,
        rewrite_ctx.youtube_via_relay,
        &rewrite_ctx.hosts,
    ) {
        // Predicate guaranteed direct is Some.
        let direct = rewrite_ctx.direct_mode.as_ref().expect("predicate guard");
        tracing::debug!(
            "dispatch {}:{} -> direct-mode (TLS fragmentation)",
            host,
            port
        );
        match crate::direct_mode::try_tunnel(sock, &host, port, direct).await {
            Ok(crate::direct_mode::TunnelOutcome::Done) => return Ok(()),
            Ok(crate::direct_mode::TunnelOutcome::Skip(s)) => {
                tracing::debug!(
                    "dispatch {}:{} -> direct-mode skipped, falling through to SNI-rewrite",
                    host,
                    port,
                );
                sock = s;
            }
            Ok(crate::direct_mode::TunnelOutcome::SkipPrefaced(prefaced)) => {
                // Every (front, profile) failed the handshake check.
                // The ClientHello is buffered as a preface in front of
                // the original client socket; the SNI-rewrite tunnel
                // can re-accept the same bytes via its generic stream
                // signature. This is the *only* sensible fallback for
                // a host that reached this branch (already proven
                // SNI-rewrite-eligible by the predicate guards).
                tracing::info!(
                    "dispatch {}:{} -> sni-rewrite tunnel (direct-mode handshake failed, prefaced fallback)",
                    host,
                    port,
                );
                return do_sni_rewrite_tunnel_from_tcp(
                    prefaced,
                    &host,
                    port,
                    mitm,
                    rewrite_ctx,
                    None,
                )
                .await;
            }
            Err(e) => {
                tracing::debug!("direct-mode error for {}:{}: {}", host, port, e);
                return Ok(());
            }
        }
    }

    // 2c. Sanctioned-domain routing override (AppsScript mode only).
    //     Google geo-blocks Iranian IPs for Gemini / AI Studio / Bard
    //     / Labs; both the direct fragmented path AND the SNI-rewrite
    //     path originate from the user's source IP, so neither reaches
    //     those endpoints. Only the Apps Script relay does (it runs in
    //     Google US datacenters and outbound traffic carries a US IP).
    //
    //     We can ONLY apply this override when an Apps Script relay
    //     actually exists — in `Mode::Direct` there's no relay at all,
    //     so pulling the host out of SNI-rewrite would just drop it
    //     onto raw TCP (which the user's network blocks anyway, that's
    //     why they're using rahgozar). For Mode::Direct users the
    //     SNI-rewrite path is the LEAST-BAD option and we keep it.
    //
    //     `direct_mode.is_some()` is the second guard: a user who
    //     disabled Direct Mode entirely opts out of this routing
    //     override too — they're responsible for routing via
    //     `relay_url_patterns` or similar machinery instead.
    let sanctioned = rewrite_ctx.mode == Mode::AppsScript
        && rewrite_ctx
            .direct_mode
            .as_ref()
            .map(|d| d.is_sanctioned(&host))
            .unwrap_or(false);

    // 2. Explicit hosts override or SNI-rewrite suffix: for HTTPS targets,
    //    use the TLS SNI-rewrite tunnel (skipped in full mode above).
    if !sanctioned
        && should_use_sni_rewrite(
            &rewrite_ctx.hosts,
            &host,
            port,
            rewrite_ctx.youtube_via_relay,
            &rewrite_ctx.force_mitm_hosts,
        )
    {
        tracing::info!(
            "dispatch {}:{} -> sni-rewrite tunnel (Google edge direct)",
            host,
            port
        );
        return do_sni_rewrite_tunnel_from_tcp(sock, &host, port, mitm, rewrite_ctx, None).await;
    }
    if sanctioned {
        tracing::info!(
            "dispatch {}:{} -> Apps Script relay (sanctioned host: geo-blocked direct)",
            host,
            port
        );
    }

    // 3. direct mode: no Apps Script relay exists. Anything that isn't
    //    SNI-rewrite-matched (Google edge or a configured fronting_group)
    //    gets raw TCP passthrough so the user's browser still works while
    //    they're deploying Code.gs. They'd switch to apps_script mode for
    //    full DPI bypass.
    if rewrite_ctx.mode == Mode::Direct {
        let via = rewrite_ctx.upstream_socks5.as_deref();
        tracing::info!(
            "dispatch {}:{} -> raw-tcp ({}) (direct mode: no relay)",
            host,
            port,
            via.unwrap_or("direct")
        );
        plain_tcp_passthrough(sock, &host, port, via).await;
        return Ok(());
    }

    // From here on we know mode == AppsScript, so `fronter` is Some.
    let fronter = match fronter {
        Some(f) => f,
        None => {
            // Defensive: mode says apps_script but the fronter is missing.
            // Fall back to raw TCP rather than panicking.
            tracing::error!(
                "dispatch {}:{} -> raw-tcp (unexpected: apps_script mode with no fronter)",
                host,
                port
            );
            plain_tcp_passthrough(sock, &host, port, rewrite_ctx.upstream_socks5.as_deref()).await;
            return Ok(());
        }
    };

    // 3. Peek at the first byte to detect TLS vs plain. Time-bounded — if the
    //    client doesn't send anything within 300ms, assume server-first
    //    protocol (SMTP, POP3, FTP banner) and jump straight to plain TCP.
    let mut peek_buf = [0u8; 8];
    let peek_n = match tokio::time::timeout(
        std::time::Duration::from_millis(300),
        sock.peek(&mut peek_buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return Ok(()),
        Err(_) => {
            // Client silent: likely a server-first protocol.
            let via = rewrite_ctx.upstream_socks5.as_deref();
            tracing::info!(
                "dispatch {}:{} -> raw-tcp ({}) (client silent, likely server-first)",
                host,
                port,
                via.unwrap_or("direct")
            );
            plain_tcp_passthrough(sock, &host, port, via).await;
            return Ok(());
        }
    };

    if peek_n >= 1 && peek_buf[0] == 0x16 {
        // Looks like TLS: MITM + relay via Apps Script. Note: upstream_socks5
        // is NOT consulted here by design — HTTPS goes through the Apps Script
        // relay, which is the whole reason rahgozar exists. If you want HTTPS
        // to flow through xray, disable rahgozar and point your browser at
        // xray directly.
        tracing::info!(
            "dispatch {}:{} -> MITM + Apps Script relay (TLS detected)",
            host,
            port
        );
        run_mitm_then_relay(sock, &host, port, mitm, &fronter, rewrite_ctx.clone()).await;
        return Ok(());
    }

    // 4. Not TLS. If bytes look like HTTP, relay on scheme=http. Otherwise
    //    fall back to plain TCP passthrough.
    if peek_n > 0 && looks_like_http(&peek_buf[..peek_n]) {
        let scheme = if port == 443 { "https" } else { "http" };
        tracing::info!(
            "dispatch {}:{} -> Apps Script relay (plain HTTP, scheme={})",
            host,
            port,
            scheme
        );
        relay_http_stream_raw(sock, &host, port, scheme, &fronter, rewrite_ctx.clone()).await;
        return Ok(());
    }

    let via = rewrite_ctx.upstream_socks5.as_deref();
    tracing::info!(
        "dispatch {}:{} -> raw-tcp ({}) (non-HTTP, non-TLS client payload)",
        host,
        port,
        via.unwrap_or("direct")
    );
    plain_tcp_passthrough(sock, &host, port, via).await;
    Ok(())
}

// ---------- Plain TCP passthrough ----------

async fn plain_tcp_passthrough(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    upstream_socks5: Option<&str>,
) {
    let target_host = host.trim_start_matches('[').trim_end_matches(']');
    // Shorter connect timeout for IP literals (4s vs 10s for hostnames).
    // Ported from upstream Python 7b1812c: when the target is an IP (i.e.
    // a raw Telegram DC, or an IP someone hardcoded), and that route is
    // DPI-dropped, the client speeds up its own DC-rotation / fallback if
    // we fail fast. Ten seconds of "waiting for a dead IP" translates
    // directly into Telegram's 10s-per-DC rotation delay — users see the
    // app sit on "connecting..." for nearly a minute as it walks through
    // DC1, DC2, DC3. At 4s we cut that in roughly half.
    // Hostnames still get 10s because DNS + first-hop TCP genuinely can
    // take that long on flaky links, and the resolver fallbacks already
    // trim the worst case.
    let connect_timeout = if looks_like_ip(target_host) {
        std::time::Duration::from_secs(4)
    } else {
        std::time::Duration::from_secs(10)
    };
    let upstream = if let Some(proxy) = upstream_socks5 {
        match socks5_connect_via(proxy, target_host, port).await {
            Ok(s) => {
                tracing::info!("tcp via upstream-socks5 {} -> {}:{}", proxy, host, port);
                s
            }
            Err(e) => {
                tracing::warn!(
                    "upstream-socks5 {} -> {}:{} failed: {} (falling back to direct)",
                    proxy,
                    host,
                    port,
                    e
                );
                match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port)))
                    .await
                {
                    Ok(Ok(s)) => s,
                    _ => return,
                }
            }
        }
    } else {
        match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port))).await {
            Ok(Ok(s)) => {
                tracing::info!("plain-tcp passthrough -> {}:{}", host, port);
                s
            }
            Ok(Err(e)) => {
                tracing::debug!("plain-tcp connect {}:{} failed: {}", host, port, e);
                return;
            }
            Err(_) => {
                tracing::debug!(
                    "plain-tcp connect {}:{} timeout (likely blocked; client should rotate)",
                    host,
                    port
                );
                return;
            }
        }
    };
    let _ = upstream.set_nodelay(true);
    let (mut ar, mut aw) = sock.split();
    let (mut br, mut bw) = {
        let (r, w) = upstream.into_split();
        (r, w)
    };
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
}

/// Open a TCP stream to `(host, port)` through an upstream SOCKS5 proxy
/// (no-auth only). Returns the connected stream after SOCKS5 negotiation.
async fn socks5_connect_via(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(proxy))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = s.set_nodelay(true);

    // Greeting: VER=5, NMETHODS=1, METHOD=no-auth
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks5 greet rejected: {:?}",
            reply
        )));
    }

    // CONNECT request: VER=5, CMD=1, RSV=0, ATYP=3 (domain) | 1 (IPv4) | 4 (IPv6)
    let mut req: Vec<u8> = Vec::with_capacity(8 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hostname > 255",
            ));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply header: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks5 connect rejected rep=0x{:02x}",
            head[1]
        )));
    }
    // Skip BND.ADDR + BND.PORT.
    match head[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut name).await?;
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("socks5 bad ATYP in reply: {}", other),
            ));
        }
    }
    Ok(s)
}

fn looks_like_http(first_bytes: &[u8]) -> bool {
    // Cheap sniff: must start with an ASCII HTTP method token followed by a space.
    for m in [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT ", "TRACE ",
    ] {
        if first_bytes.starts_with(m.as_bytes()) {
            return true;
        }
    }
    false
}

/// Read an HTTP head (request line + headers) up to the first \r\n\r\n.
/// Returns (head_bytes, leftover_after_head). The leftover may contain part
/// of the request body already received.
/// Maximum size of an HTTP request head (request line + all headers).
///
/// Set to match upstream Python's `MAX_HEADER_BYTES` (64 KB,
/// masterking32/MasterHttpRelayVPN constants.py). Real browsers
/// virtually never exceed ~16 KB; anything past 64 KB is either a
/// buggy client or a deliberate slowloris-style header bomb.
/// Previously 1 MB, which let a misbehaving client allocate a lot
/// of memory before failing.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Maximum request body we buffer in the HTTP/MITM relay paths.
///
/// These paths have to materialize the full body before passing it to
/// Apps Script, and Apps Script's request payload limit is well below
/// "unbounded" once base64/JSON overhead is included. Refusing above
/// 32 MiB keeps a malicious local/LAN client from forcing a huge
/// allocation while still leaving room for ordinary form/API uploads.
const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Result of `read_http_head` / `read_http_head_io`.
/// `Oversized` is distinct from other I/O errors so the caller can
/// reply with `431 Request Header Fields Too Large` instead of just
/// dropping the connection (which a browser would silently retry,
/// reproducing the same problem).
enum HeadReadResult {
    Got { head: Vec<u8>, leftover: Vec<u8> },
    Closed,
    Oversized,
}

async fn read_http_head(sock: &mut TcpStream) -> std::io::Result<HeadReadResult> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(HeadReadResult::Closed)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(HeadReadResult::Got { head, leftover });
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(HeadReadResult::Oversized);
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_request_head(head: &[u8]) -> Option<ParsedRequestHead> {
    let s = std::str::from_utf8(head).ok()?;
    let mut lines = s.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if !is_valid_http_method(&method) {
        return None;
    }

    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((method, target, version, headers))
}

fn is_valid_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

// ---------- CONNECT handling ----------

async fn run_mitm_then_relay(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    fronter: &DomainFronter,
    rewrite_ctx: Arc<RewriteCtx>,
) {
    // Peek the TLS ClientHello BEFORE minting the MITM cert. When the client
    // resolves the hostname itself (DoH in Chrome/Firefox) and hands us a raw
    // IP via SOCKS5, the only place the real hostname lives is the SNI. If we
    // mint a cert for the IP, Chrome rejects with ERR_CERT_COMMON_NAME_INVALID
    // — the IP isn't in the cert's SAN. Reading SNI up front and using it as
    // both the cert subject and the upstream Host for the Apps Script relay
    // is what unblocks Cloudflare-fronted sites and any browser on Android
    // where DoH is the default.
    let start = match LazyConfigAcceptor::new(Acceptor::default(), sock).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("TLS ClientHello peek failed for {}: {}", host, e);
            return;
        }
    };

    let sni_hostname = start.client_hello().server_name().map(String::from);

    // Effective host: SNI when present and looks like a hostname (anything
    // other than a bare IPv4 literal — IP SNIs exist for weird setups but
    // minting a cert for them still triggers ERR_CERT_COMMON_NAME_INVALID,
    // so we fall through to the raw host in that case).
    let effective_host: String = match sni_hostname.as_deref() {
        Some(s) if !looks_like_ip(s) && !s.is_empty() => s.to_string(),
        _ => host.to_string(),
    };

    tracing::info!(
        "MITM TLS -> {}:{} (socks_host={}, sni={})",
        effective_host,
        port,
        host,
        sni_hostname.as_deref().unwrap_or("<none>"),
    );

    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(&effective_host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", effective_host, e);
                return;
            }
        }
    };

    let mut tls = match start.into_stream(server_config).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("TLS accept failed for {}: {}", effective_host, e);
            return;
        }
    };

    // Keep-alive loop: read HTTP requests from the decrypted stream. Pass the
    // SNI-derived hostname so the Apps Script relay fetches
    // `https://<real hostname>/path` instead of `https://<raw IP>/path` — the
    // latter would produce an IP-in-Host request that Cloudflare/etc. reject
    // outright.
    loop {
        match handle_mitm_request(
            &mut tls,
            &effective_host,
            port,
            fronter,
            "https",
            &rewrite_ctx,
        )
        .await
        {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("MITM handler error for {}: {}", effective_host, e);
                break;
            }
        }
    }
}

/// True if `s` parses as an IPv4 or IPv6 literal. Used to decide whether
/// a string is a hostname we should mint a MITM leaf cert for — IP SANs
/// need their own cert extension and we don't bother emitting those,
/// so fall back to the SOCKS5-provided target in that case.
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

// ---------- Plain HTTP relay on a raw TCP stream (port 80 targets) ----------

async fn relay_http_stream_raw(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    scheme: &str,
    fronter: &DomainFronter,
    rewrite_ctx: Arc<RewriteCtx>,
) {
    loop {
        match handle_mitm_request(&mut sock, host, port, fronter, scheme, &rewrite_ctx).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("http relay error for {}: {}", host, e);
                break;
            }
        }
    }
}

/// Cap on how many DoH-resolved IPs a `force_ip` group will try before
/// giving up. The first reachable one almost always wins; the extras are
/// just resilience against a single dead edge IP. Bounded so a host that
/// resolves to a large anycast set doesn't blow the per-CONNECT latency
/// budget on serial connect attempts.
const FORCE_IP_MAX_TARGETS: usize = 3;

async fn do_sni_rewrite_tunnel_from_tcp<S>(
    sock: S,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    // When Some, a *pinned* fronting group: dial its edge `ip` with
    // SNI=`sni`, cert verified against `sni` (the shared connector).
    // None = built-in Google edge (dial `google_ip`, SNI=`front_domain`).
    // Camouflage (`force_ip`) groups do NOT use this path — they go
    // through `do_camouflage_tunnel`, which dials upstream before
    // MITM-accepting the browser so it can fall through on failure.
    group: Option<Arc<FrontingGroupResolved>>,
) -> std::io::Result<()>
where
    // Generic over the inbound socket so the dispatcher can hand us
    // either a plain `TcpStream` or a `PrefacedTcpStream` (the
    // direct-mode fallback path wraps the already-consumed ClientHello
    // bytes back in front of the original socket). `TlsAcceptor` is
    // already generic over IO; this just propagates that to our
    // signature.
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (target_ip, outbound_sni, server_name) = match &group {
        Some(g) => (g.ip.clone(), g.sni.clone(), g.server_name.clone()),
        None => {
            let ip = hosts_override(&rewrite_ctx.hosts, host)
                .map(|s| s.to_string())
                .unwrap_or_else(|| rewrite_ctx.google_ip.clone());
            let sni = rewrite_ctx.front_domain.clone();
            let sn = match ServerName::try_from(sni.clone()) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!("invalid front_domain '{}': {}", sni, e);
                    return Ok(());
                }
            };
            (ip, sni, sn)
        }
    };

    tracing::info!(
        "SNI-rewrite tunnel -> {}:{} via {} (outbound SNI={})",
        host,
        port,
        target_ip,
        outbound_sni
    );

    // Accept browser TLS with a cert we sign for `host`.
    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", host, e);
                return Ok(());
            }
        }
    };
    let inbound = match TlsAcceptor::from(server_config).accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("inbound TLS accept failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Open outbound TLS to the edge with SNI=outbound_sni.
    let upstream_tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target_ip.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            s
        }
        Ok(Err(e)) => {
            tracing::debug!("upstream connect failed for {}: {}", host, e);
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("upstream connect timeout for {}", host);
            return Ok(());
        }
    };

    let outbound = match rewrite_ctx
        .tls_connector
        .connect(server_name, upstream_tcp)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("outbound TLS connect failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Bridge decrypted bytes between the two TLS streams.
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let (mut or, mut ow) = tokio::io::split(outbound);
    let client_to_server = async { tokio::io::copy(&mut ir, &mut ow).await };
    let server_to_client = async { tokio::io::copy(&mut or, &mut iw).await };
    tokio::select! {
        _ = client_to_server => {}
        _ = server_to_client => {}
    }
    Ok(())
}

/// Per-attempt budget (TCP connect + camouflaged TLS handshake) for one
/// candidate IP. Deliberately tight: the whole point of camouflage mode
/// is *fast* fall-through, and a reachable Google/Meta edge completes
/// well under a second. A loose 10 s here, multiplied by
/// `FORCE_IP_MAX_TARGETS`, would turn an IP-blocked host into a 30 s
/// per-CONNECT stall before falling through — see the breaker below.
const CAMOUFLAGE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a fronting *group* stays marked "upstream unreachable" after
/// a CONNECT where every candidate IP failed. While tripped, subsequent
/// CONNECTs routed to that group fall through to the normal route
/// *immediately* instead of re-paying the connect attempts.
///
/// **Keyed by group name, not host.** This is the load-bearing choice:
/// YouTube fans out to ephemeral per-session subdomains
/// (`r1---sn-….googlevideo.com`), each seen once, so a per-host breaker
/// would essentially never get a repeat hit on the exact case it exists
/// for. But if a group's edge IPs are blackholed, they're blackholed for
/// the whole group — so one trip short-circuits every host the group
/// fronts for the cooldown. Mirrors the DoH negative cache, but for the
/// IP-blocked-yet-resolvable case DNS can't catch (the resolver returns
/// valid IPs; the IPs themselves are dropped).
const CAMOUFLAGE_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);
/// Hard cap on the breaker map so a config with many force_ip groups
/// can't grow it without bound. Expired entries are swept first. (With
/// group-name keying this is tiny in practice — one entry per group.)
const CAMOUFLAGE_BREAKER_MAX_ENTRIES: usize = 512;

fn camouflage_breaker_map() -> &'static std::sync::Mutex<std::collections::HashMap<String, Instant>>
{
    static MAP: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Instant>>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// True if `key` (a fronting group name) is currently breaker-tripped.
fn camouflage_breaker_tripped(key: &str) -> bool {
    let map = match camouflage_breaker_map().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    map.get(key).is_some_and(|until| Instant::now() < *until)
}

/// Mark `key` (a group name) unreachable for `CAMOUFLAGE_BREAKER_COOLDOWN`.
/// Sweeps expired entries (and, if still at cap, the soonest-expiring one)
/// before inserting so the map stays bounded.
fn camouflage_note_unreachable(key: &str) {
    let mut map = match camouflage_breaker_map().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if map.len() >= CAMOUFLAGE_BREAKER_MAX_ENTRIES && !map.contains_key(key) {
        let now = Instant::now();
        map.retain(|_, until| now < *until);
        if map.len() >= CAMOUFLAGE_BREAKER_MAX_ENTRIES {
            if let Some(k) = map.iter().min_by_key(|(_, u)| **u).map(|(k, _)| k.clone()) {
                map.remove(&k);
            }
        }
    }
    map.insert(
        key.to_string(),
        Instant::now() + CAMOUFLAGE_BREAKER_COOLDOWN,
    );
}

/// Clear any breaker entry for `key` (a group name) after a successful dial.
fn camouflage_note_reachable(key: &str) {
    let mut map = match camouflage_breaker_map().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    map.remove(key);
}

/// Camouflage (`force_ip`) tunnel: dial the destination's own
/// DoH-resolved IP with a decoy SNI and a verifier bound to the real
/// host, then MITM the browser and splice.
///
/// **Outbound-first ordering is load-bearing.** We establish the upstream
/// TCP+TLS connection BEFORE accepting (MITM-terminating) the browser's
/// TLS. If every candidate IP is unreachable / IP-blocked / wrong-cert,
/// the browser socket is still untouched, so we hand it back
/// (`Err(sock)`) and the dispatcher falls through to the normal route
/// (Apps Script relay in apps_script, raw TCP in direct) instead of
/// black-holing the CONNECT. Accepting the browser first (as the
/// pinned/built-in path does) would make an upstream failure
/// unrecoverable — that was the v1 regression for IP-blocked googlevideo.
///
/// Returns `Ok(())` when handled (success, or a browser-side failure
/// after we committed); `Err(sock)` when the upstream couldn't be
/// established and the caller should fall through with the untouched
/// socket.
async fn do_camouflage_tunnel(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    group: &FrontingGroupResolved,
    ips: Vec<std::net::IpAddr>,
) -> Result<(), TcpStream> {
    // Fast fall-through when this group's edge is known-unreachable: a
    // recent CONNECT routed here already found every candidate IP
    // blackholed. Keyed by group name (not host) because YouTube fans out
    // to ephemeral per-session subdomains — a per-host breaker would never
    // hit twice, but the group's edge IPs are blocked for the whole group.
    // Skip the dial and hand the socket back so the dispatcher uses
    // relay/raw. (The dispatcher also pre-checks this before resolving DNS;
    // this is the self-contained guard.)
    if camouflage_breaker_tripped(&group.name) {
        tracing::debug!(
            "force_ip '{}': breaker tripped — falling through without dialing ({})",
            group.name,
            host
        );
        return Err(sock);
    }

    // Peek (non-consuming) the browser's ClientHello to learn which ALPN
    // protocols it offered. We then offer the upstream only those, and
    // later hand the browser exactly the one the upstream picked — so the
    // raw splice's two TLS legs always agree on protocol. This is what
    // lets YouTube's web app run over HTTP/2 (it stalls/spins over forced
    // http/1.1). Peeking keeps the socket intact for fall-through; a
    // failed/partial peek degrades to http/1.1 on both legs (never a
    // mismatch). 8 KiB covers a normal ClientHello in one segment.
    let browser_alpn = {
        let mut peek = [0u8; 8192];
        match tokio::time::timeout(std::time::Duration::from_millis(500), sock.peek(&mut peek))
            .await
        {
            Ok(Ok(n)) if n > 0 => crate::camouflage::client_hello_alpn(&peek[..n]),
            _ => None,
        }
    };
    let upstream_offer = crate::camouflage::choose_upstream_alpn(browser_alpn.as_deref());

    // Always accept a cert for the real requested host, AND any names the
    // group pins via `verify_names`. The pinned names matter because some
    // edges return a cert matching the decoy SNI we sent (e.g. Google's
    // GFE returns a `www.google.com` cert) rather than one for the inner
    // Host — so we accept either. Every name here is owned by the
    // legitimate destination (or the decoy provider, e.g. Google /
    // Microsoft), so a censor MITM — which can't present any valid public
    // cert — still fails closed regardless.
    let mut verify: Vec<String> = vec![host.to_ascii_lowercase()];
    verify.extend(group.verify_names.iter().cloned());
    let connector =
        match crate::camouflage::build_camouflage_connector_with_alpn(&verify, &upstream_offer) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "force_ip group '{}': camouflage connector build failed: {}",
                    group.name,
                    e
                );
                return Err(sock);
            }
        };

    // Dial the candidate IPs CONCURRENTLY and take the first that completes
    // the camouflaged handshake. Done BEFORE touching the browser socket so
    // a total failure can fall through. Racing (rather than a serial loop)
    // bounds the all-fail latency to one `CAMOUFLAGE_ATTEMPT_TIMEOUT`
    // instead of `FORCE_IP_MAX_TARGETS ×` it — important because on a
    // blocked group every IP just times out.
    let dials: Vec<_> = ips
        .into_iter()
        .take(FORCE_IP_MAX_TARGETS)
        .map(|ip| {
            let connector = &connector;
            let server_name = group.server_name.clone();
            Box::pin(async move {
                let target = ip.to_string();
                match tokio::time::timeout(CAMOUFLAGE_ATTEMPT_TIMEOUT, async {
                    let tcp = TcpStream::connect((target.as_str(), port)).await?;
                    let _ = tcp.set_nodelay(true);
                    connector
                        .connect(server_name, tcp)
                        .await
                        .map_err(std::io::Error::other)
                })
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "dial timeout",
                    )),
                }
            })
        })
        .collect();
    if dials.is_empty() {
        camouflage_note_unreachable(&group.name);
        return Err(sock);
    }
    let outbound = match futures_util::future::select_ok(dials).await {
        Ok((stream, _rest)) => stream,
        Err(e) => {
            // Every candidate failed — trip the group breaker so the next
            // CONNECT routed here falls through immediately, and hand the
            // (untouched) socket back to the dispatcher.
            tracing::debug!(
                "force_ip '{}': all upstreams failed for {}: {}",
                group.name,
                host,
                e
            );
            camouflage_note_unreachable(&group.name);
            return Err(sock);
        }
    };
    // Reached a working edge — clear any stale breaker mark.
    camouflage_note_reachable(&group.name);

    // Which protocol did the real edge negotiate? Offer the browser
    // exactly that so the spliced legs stay coherent. Default to
    // http/1.1 when the edge negotiated no ALPN.
    let negotiated_alpn: Vec<Vec<u8>> = match outbound.get_ref().1.alpn_protocol() {
        Some(p) => vec![p.to_vec()],
        None => vec![b"http/1.1".to_vec()],
    };

    // Upstream is up. Mint the MITM leaf and accept the browser TLS. A
    // cert-gen failure can still fall through (sock not yet consumed);
    // once `accept` consumes the socket a browser-side failure cannot.
    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config_alpn(host, &negotiated_alpn) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "force_ip '{}': cert gen failed for {}: {}",
                    group.name,
                    host,
                    e
                );
                return Err(sock);
            }
        }
    };
    let inbound = match TlsAcceptor::from(server_config).accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(
                "force_ip '{}': inbound TLS accept failed for {}: {}",
                group.name,
                host,
                e
            );
            return Ok(());
        }
    };

    let (mut ir, mut iw) = tokio::io::split(inbound);
    let (mut or, mut ow) = tokio::io::split(outbound);
    tokio::select! {
        _ = tokio::io::copy(&mut ir, &mut ow) => {}
        _ = tokio::io::copy(&mut or, &mut iw) => {}
    }
    Ok(())
}

/// Build the HTTP/1.1 request bytes the SNI-rewrite forwarder writes
/// upstream. Pure function — pulled out of `forward_via_sni_rewrite_http`
/// so the request-rebuilding logic can be unit-tested directly without
/// standing up a TLS connector.
///
/// Forces `Host` to the real origin (the Google edge dispatches by the
/// inner Host even though the outer SNI is sanitised) and
/// `Connection: close` so the upstream signals end-of-response by
/// closing the TCP socket. That lets us read until EOF without parsing
/// HTTP framing on the response side.
///
/// **Framing-header rewrite**: by the time we run, `read_body` has
/// already decoded any chunked request body into a flat byte buffer.
/// Forwarding the inbound `Transfer-Encoding: chunked` verbatim would
/// leave the upstream waiting forever for chunk markers that aren't in
/// the bytes we send. Strip every framing header (`Transfer-Encoding`,
/// any pre-existing `Content-Length`, the hop-by-hop hints `TE`,
/// `Trailer`, `Upgrade`, plus the connection-management headers
/// `Connection`, `Proxy-Connection`, `Keep-Alive`) and emit a single
/// fresh `Content-Length: <decoded body length>` for any method that
/// can carry a body. The result is a request the upstream can frame
/// unambiguously regardless of how the browser originally framed it.
pub(crate) fn build_sni_forward_request_bytes(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let host_with_port = if port == 443 || port == 80 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };
    let mut req: Vec<u8> = Vec::with_capacity(512 + body.len());
    req.extend_from_slice(method.as_bytes());
    req.extend_from_slice(b" ");
    req.extend_from_slice(path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\n");
    req.extend_from_slice(b"Host: ");
    req.extend_from_slice(host_with_port.as_bytes());
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(b"Connection: close\r\n");
    // Emit Content-Length whenever we have a body or whenever the method
    // is one that semantically carries a body (POST/PUT/PATCH). For body-
    // less safe methods like GET/HEAD we omit it — adding `Content-Length: 0`
    // is technically valid but some origins read it as "request expects
    // a body" which has caused 400s in the past.
    let needs_content_length = !body.is_empty()
        || method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("PATCH");
    if needs_content_length {
        req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("proxy-connection")
            || k.eq_ignore_ascii_case("keep-alive")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("te")
            || k.eq_ignore_ascii_case("trailer")
            || k.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);
    req
}

/// Forward an HTTP request via the SNI-rewrite trick at the HTTP layer.
///
/// Used by `handle_mitm_request` for hosts that were pulled out of
/// SNI-rewrite by `relay_url_patterns` but whose URL path did NOT match
/// any pattern. Saves the Apps Script quota the per-path filter is
/// designed to recover, while still letting matching paths fall through
/// to the relay.
///
/// Wire mechanics: dial `google_ip:443` (or a `hosts`-overridden IP) with
/// SNI=`front_domain`, then send a literal HTTP/1.1 request whose `Host`
/// header is the *real* origin name. The Google edge dispatches on the
/// inner `Host`, so the response comes from the right backend even though
/// the outer SNI is a sanitised one. `Connection: close` is forced so we
/// can read until EOF and never need to parse `Content-Length` /
/// `Transfer-Encoding` ourselves — and the browser side then sees
/// `Connection: close` and won't pipeline another request on the dead
/// MITM stream.
///
/// Ported from upstream `_forward_via_sni_rewrite` (commit b3b9220).
async fn forward_via_sni_rewrite_http(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    rewrite_ctx: &RewriteCtx,
) -> std::io::Result<Vec<u8>> {
    let target_ip = hosts_override(&rewrite_ctx.hosts, host)
        .map(|s| s.to_string())
        .unwrap_or_else(|| rewrite_ctx.google_ip.clone());
    let sni = rewrite_ctx.front_domain.clone();
    let server_name = ServerName::try_from(sni.clone()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid front_domain '{}': {}", sni, e),
        )
    })?;

    let upstream_tcp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target_ip.as_str(), port)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream connect timeout"))??;
    let _ = upstream_tcp.set_nodelay(true);

    let mut tls = rewrite_ctx
        .tls_connector
        .connect(server_name, upstream_tcp)
        .await
        .map_err(|e| std::io::Error::other(format!("tls: {}", e)))?;

    let req = build_sni_forward_request_bytes(method, host, port, path, headers, body);
    tls.write_all(&req).await?;
    tls.flush().await?;

    // Read response until EOF / ungraceful TLS close. The upstream is
    // `Connection: close`, so EOF is a complete response. UnexpectedEof
    // (rustls's signal for a TCP close without a close_notify alert) is
    // treated the same as a clean EOF — same compromise that
    // `read_http_response` makes.
    //
    // A read timeout means the upstream is hung mid-response and we
    // can't prove what we have is complete. Return an error so the
    // caller falls back to the relay path; serving a truncated
    // response to the browser would silently corrupt it.
    //
    // **Cap is much tighter than the global 200 MB response ceiling**:
    // this code path only runs for hosts in `force_mitm_hosts` AND paths
    // that did NOT match a `relay_url_patterns` entry. With the default
    // pattern set that's "non-`/youtubei/` GETs on `youtube.com`" —
    // realistic responses are HTML pages, JS bundles, and small inline
    // assets, capped at a few MB in practice. Cutting the per-call cap
    // to 32 MB shrinks the memory blast radius under concurrent load on
    // memory-constrained devices (OpenWRT routers, Android) by ~6× vs
    // the original 200 MB, while still leaving comfortable headroom
    // above the realistic max. Streaming the body straight back to the
    // browser would avoid the buffer entirely — see followup TODO; the
    // tighter cap is the cheap memory-pressure defense in the meantime.
    const MAX_RESP_BYTES: usize = 32 * 1024 * 1024;
    let mut response = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let read_res =
            tokio::time::timeout(std::time::Duration::from_secs(30), tls.read(&mut buf)).await;
        match read_res {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > MAX_RESP_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "sni-rewrite forward response exceeded cap",
                    ));
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "sni-rewrite forward read timeout (response may be truncated)",
                ));
            }
        }
    }
    if response.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "sni-rewrite forward got empty response",
        ));
    }
    Ok(response)
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
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

fn parse_host_port(target: &str) -> (String, u16) {
    if let Some((h, p)) = target.rsplit_once(':') {
        let port: u16 = p.parse().unwrap_or(443);
        (h.to_string(), port)
    } else {
        (target.to_string(), 443)
    }
}

async fn handle_mitm_request<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    fronter: &DomainFronter,
    scheme: &str,
    rewrite_ctx: &Arc<RewriteCtx>,
) -> std::io::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (head, leftover) = match read_http_head_io(stream).await? {
        HeadReadResult::Got { head, leftover } => (head, leftover),
        HeadReadResult::Closed => return Ok(false),
        HeadReadResult::Oversized => {
            // Inside MITM: same reasoning as the plaintext path. Return
            // 431 over the decrypted stream so the browser surfaces a
            // real error to the user instead of looping a connection
            // reset, which was the symptom upstream caught (Apps Script
            // ate malformed JSON when truncated header blocks were
            // forwarded blindly).
            tracing::warn!(
                "MITM header block exceeds {} bytes — closing ({}:{})",
                MAX_HEADER_BYTES,
                host,
                port
            );
            let _ = stream
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
                      Connection: close\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
            let _ = stream.flush().await;
            return Ok(false);
        }
    };

    let (method, path, _version, headers) = match parse_request_head(&head) {
        Some(v) => v,
        None => return Ok(false),
    };

    let body = match read_body(stream, &leftover, &headers).await {
        Ok(body) => body,
        Err(e) if is_body_too_large(&e) => {
            tracing::warn!(
                "MITM request body exceeds {} bytes — returning 413 ({}:{})",
                MAX_REQUEST_BODY_BYTES,
                host,
                port
            );
            let _ = write_payload_too_large(stream).await;
            return Ok(false);
        }
        Err(e) => return Err(e),
    };

    // ── Per-host URL fix-ups ──────────────────────────────────────────
    // x.com's GraphQL endpoints concatenate three huge JSON blobs into
    // the query string: `?variables=<json>&features=<json>&fieldToggles=<json>`.
    // The combined URL regularly exceeds Apps Script's URL length limit
    // (Apps Script returns "بیش از حد مجاز: طول نشانی وب URLFetch" /
    // "URLFetch URL length exceeded"). The `variables=` portion alone
    // is enough for x.com to serve the timeline — `features` /
    // `fieldToggles` are client-capability hints it tolerates being
    // absent. Truncating at the first `&` after `?variables=` ships a
    // working request that fits under the limit. Ported from upstream
    // Python 2d959d4 (p0u1ya's fix). Issue #64.
    //
    // Host matcher: browsers actually hit `www.x.com` (and sometimes
    // `api.x.com`), not bare `x.com`. The original check only matched
    // `x.com` exactly, so real traffic flew past the rewrite until
    // pourya-p's log in #64 showed the real Host header. Match every
    // subdomain of x.com here.
    let host_lower = host.to_ascii_lowercase();
    let is_x_com = host_lower == "x.com"
        || host_lower.ends_with(".x.com")
        || host_lower == "twitter.com"
        || host_lower.ends_with(".twitter.com");
    let path = if is_x_com && path.starts_with("/i/api/graphql/") && path.contains("?variables=") {
        match path.split_once('&') {
            Some((short, _)) => {
                tracing::debug!(
                    "x.com graphql URL truncated: {} chars -> {}",
                    path.len(),
                    short.len()
                );
                short.to_string()
            }
            None => path,
        }
    } else {
        path
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let url = if port == default_port {
        format!("{}://{}{}", scheme, host, path)
    } else {
        format!("{}://{}:{}{}", scheme, host, port, path)
    };

    // Short-circuit CORS preflight at the MITM boundary.
    //
    // Apps Script's UrlFetchApp.fetch() only accepts methods {get, delete,
    // patch, post, put} — OPTIONS triggers the Swedish-localized
    // "Ett attribut med ogiltigt värde har angetts: method" error, which
    // kills every XHR/fetch preflight and is the root cause of "JS doesn't
    // load" on sites like Discord, Yahoo finance widgets, etc.
    //
    // Answering the preflight ourselves is safe: we already terminate the
    // TLS for the browser (we minted the cert), so it's legitimate for us
    // to own the wire-level conversation. CORS is a browser-side
    // protection, not a network security one — responding 204 with
    // permissive ACL headers just tells the browser the *subsequent* real
    // request is allowed, and that real request still goes through the
    // Apps Script relay where the origin server gets final say on content.
    // The origin header is echoed (not "*") so Credentials-true responses
    // stay spec-valid.
    if method.eq_ignore_ascii_case("OPTIONS") {
        tracing::info!("preflight 204 {} (short-circuit, no relay)", url);
        let origin = header_value(&headers, "origin").unwrap_or("*");
        let acrm = header_value(&headers, "access-control-request-method")
            .unwrap_or("GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
        let acrh = header_value(&headers, "access-control-request-headers").unwrap_or("*");
        let resp = format!(
            "HTTP/1.1 204 No Content\r\n\
             Access-Control-Allow-Origin: {origin}\r\n\
             Access-Control-Allow-Methods: {acrm}\r\n\
             Access-Control-Allow-Headers: {acrh}\r\n\
             Access-Control-Allow-Credentials: true\r\n\
             Access-Control-Max-Age: 86400\r\n\
             Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        let connection_close = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
        return Ok(!connection_close);
    }

    // Path-level relay routing (b3b9220). Hosts that were pulled out of
    // SNI-rewrite by `relay_url_patterns` are MITM'd so we can inspect the
    // URL: paths that match a pattern go through the Apps Script relay
    // (this is what fixes YouTube SafeSearch / live-stream gating on
    // `/youtubei/`); every other path on the same host is forwarded over
    // a fresh SNI-rewrite TLS connection, saving the relay quota that the
    // pre-port `youtube_via_relay = true` knob would have spent on every
    // static asset. A failed forward falls through to the relay path so a
    // network blip on the Google edge doesn't take the host offline.
    //
    // **Safe-method gate**: the forwarder is only used for GET/HEAD/OPTIONS.
    // The fallback-on-error semantics combined with non-idempotent methods
    // (POST/PUT/PATCH/DELETE) would be a replay hazard: write_all may
    // succeed against the upstream and then a read timeout / cap-exceeded
    // / late TLS error fires fallback, which sends the same side-effecting
    // request through Apps Script. POSTs to non-`/youtubei/` paths on
    // youtube.com are uncommon, and the quota cost of routing them via
    // relay is acceptable next to the correctness risk of duplicating
    // them. Mirrors the same gate on idempotency that
    // `relay_parallel_range` and `parallel_relay` apply elsewhere.
    //
    // **Exit-node-full gate**: when `exit_node.mode = "full"` is active
    // (commit 88b2767), every relay request is required to route through
    // the second-hop exit node. The forwarder dials the Google edge
    // directly with no awareness of the exit node, so taking it for any
    // path — even ones that look "skippable" by the path filter —
    // silently bypasses the exit node and breaks the documented "every
    // URL routes through the exit node" contract on
    // `DomainFronter::exit_node_matches`. With the gate active,
    // user-supplied `relay_url_patterns` still pull their hosts out of
    // SNI-rewrite (so MITM runs); the path-vs-forwarder split just
    // collapses, and every path on those hosts goes to relay → exit
    // node. The default `youtube.com/youtubei/` is suppressed earlier
    // in `ResolvedRouting` (because `youtube_via_relay_effective` is
    // true here), so this only affects user-supplied entries — which
    // is the case the reviewer flagged.
    let method_is_safe_for_forwarder = method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("OPTIONS");
    let host_is_force_mitm = host_in_force_mitm_list(host, &rewrite_ctx.force_mitm_hosts);
    let url_matches_pattern = url_matches_relay_pattern(&url, &rewrite_ctx.relay_url_patterns);
    let forwarder_eligible = scheme == "https"
        && port == 443
        && method_is_safe_for_forwarder
        && !rewrite_ctx.exit_node_full_mode_active
        && !rewrite_ctx.relay_url_patterns.is_empty()
        && host_is_force_mitm
        && !url_matches_pattern;

    // Diagnostic: when a request to a force-MITM host bypasses the
    // forwarder fast-path, log which condition tripped. Restricted to
    // force-MITM hosts so non-YT MITM (e.g. inspected sanctioned hosts)
    // doesn't get spammed. Same `yt_forwarder` target as the rest of
    // the fast-path lines so users can filter with `RUST_LOG=yt_forwarder=info`.
    if host_is_force_mitm && !forwarder_eligible {
        let reason = if scheme != "https" {
            format!("scheme={}", scheme)
        } else if port != 443 {
            format!("port={}", port)
        } else if !method_is_safe_for_forwarder {
            format!("method={}", method)
        } else if rewrite_ctx.exit_node_full_mode_active {
            "exit_node_full_mode_active".to_string()
        } else if rewrite_ctx.relay_url_patterns.is_empty() {
            "relay_url_patterns_empty".to_string()
        } else if url_matches_pattern {
            "url_matches_relay_pattern".to_string()
        } else {
            "unknown".to_string()
        };
        tracing::info!(
            target: "yt_forwarder",
            "gate skipped {} {}: {}",
            method, url, reason,
        );
    }

    if forwarder_eligible {
        // All forwarder log lines use `target = "yt_forwarder"` so users
        // diagnosing #977-style reports can `RUST_LOG=yt_forwarder=info`
        // (or =debug) and see exactly which requests took the fast path,
        // their sizes, and their latencies — without grepping the
        // general-relay info-spam.
        tracing::info!(target: "yt_forwarder", "dispatch {} {}", method, url);
        let t0 = std::time::Instant::now();
        match forward_via_sni_rewrite_http(&method, host, port, &path, &headers, &body, rewrite_ctx)
            .await
        {
            Ok(response_bytes) => {
                let response_len = response_bytes.len();
                let elapsed_ms = t0.elapsed().as_millis();
                tracing::info!(
                    target: "yt_forwarder",
                    "ok {} {} bytes={} latency_ms={}",
                    method, url, response_len, elapsed_ms,
                );
                // Record BEFORE the downstream write: we want
                // `forwarder_calls` to reflect "the path filter
                // produced an upstream response," not "the browser
                // received it." A client disconnect during write would
                // otherwise leave the metric understating fast-path
                // utilisation — we'd see only relay-path traffic in
                // stats while the forwarder was actually doing work.
                fronter.record_forwarder_call(response_len as u64);
                stream.write_all(&response_bytes).await?;
                stream.flush().await?;
                // The forwarder always sets `Connection: close` on the
                // upstream request, so the upstream side has closed by
                // the time we get here — propagate that to the inbound
                // browser side too. The browser will reopen for the next
                // request (and we'll mint a new MITM session).
                return Ok(false);
            }
            Err(e) => {
                tracing::warn!(
                    target: "yt_forwarder",
                    "error {} {}: {} (latency_ms={}) — falling back to relay",
                    method, url, e, t0.elapsed().as_millis(),
                );
                // `record_forwarder_error` only describes what just
                // happened to the fast path. Whether the relay-path
                // fallback below recovers the request is reflected in
                // `relay_calls` / `relay_failures`; combining those
                // with `forwarder_errors` lets diagnostics tell apart
                // "fast path missed but request served" from "request
                // failed end-to-end."
                fronter.record_forwarder_error();
                // fall through
            }
        }
    }

    tracing::info!("relay {} {}", method, url);

    // CORS response-header injection. The preflight short-circuit
    // above handles `OPTIONS`, but the *actual* fetch that follows
    // also needs CORS-compliant headers on the way back, or the
    // browser drops the response and the JS layer sees a CORS
    // failure. Apps Script's `UrlFetchApp.fetch()` preserves the
    // origin server's response headers inconsistently — sometimes the
    // destination returns `Access-Control-Allow-Origin: *` (which is
    // incompatible with `Allow-Credentials: true`), sometimes omits
    // ACL headers entirely. The visible symptom on YouTube is comments
    // not loading and the "restricted" gate firing on cross-origin
    // XHR responses that the browser rejected before the JS handler
    // could even read them. Idea credit: ThisIsDara/mhr-cfw-go.
    //
    // Only injects when the request had an `Origin` header — non-CORS
    // requests (top-level navigation, plain image fetches) don't need
    // the headers and adding them would be noise. The relay response
    // is otherwise byte-identical, so this never affects non-browser
    // clients (curl, wget, app-level HTTP clients).
    let cors_origin = header_value(&headers, "origin").map(|s| s.to_string());
    let transform_head = |head: &[u8]| -> Vec<u8> {
        match cors_origin.as_deref() {
            Some(origin) => inject_cors_into_head(head, origin).unwrap_or_else(|| head.to_vec()),
            None => head.to_vec(),
        }
    };

    // For GETs without a body, take the range-parallel path — probes
    // with `Range: bytes=0-<chunk>`, and if the origin supports ranges,
    // fetches the rest in parallel 256 KB chunks. This is what lets
    // YouTube video streaming / gvt1.com Chrome-updates / big static
    // files not stall waiting on one ~2s Apps Script call per MB.
    // Anything with a body (POST/PUT/PATCH) goes through the normal
    // relay path — range semantics on mutating requests are undefined
    // and would break form submissions.
    //
    // The range-parallel call writes directly to the stream so files
    // above Apps Script's single-GET ceiling (~40 MiB) can stream
    // through chunk-by-chunk instead of being buffered into one giant
    // `Vec<u8>` (which previously failed for 100 MiB+ downloads — #1042).
    if method.eq_ignore_ascii_case("GET") && body.is_empty() {
        fronter
            .relay_parallel_range_to(stream, &method, &url, &headers, &body, transform_head)
            .await?;
    } else {
        let response = fronter.relay(&method, &url, &headers, &body).await;
        let response = match cors_origin.as_deref() {
            Some(origin) => inject_cors_response_headers(&response, origin),
            None => response,
        };
        stream.write_all(&response).await?;
    }
    stream.flush().await?;

    // Keep-alive unless the client asked to close.
    let connection_close = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
    Ok(!connection_close)
}

async fn read_http_head_io<S>(stream: &mut S) -> std::io::Result<HeadReadResult>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(HeadReadResult::Closed)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(HeadReadResult::Got { head, leftover });
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(HeadReadResult::Oversized);
        }
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Strip any `Access-Control-*` response headers the origin server
/// emitted (or that Apps Script's `UrlFetchApp.fetch()` may have
/// mangled / dropped) and inject a permissive set keyed on the
/// browser's request `Origin`. Returns a new response buffer; never
/// mutates in place.
///
/// The body is preserved byte-for-byte; only the header block before
/// the first `\r\n\r\n` is rewritten. If the response can't be parsed
/// as HTTP/1.x (no header/body separator), it's returned unchanged so
/// edge-case responses (e.g. raw error blobs from upstream) aren't
/// corrupted.
///
/// Why permissive (`Allow-Methods: *`, `Allow-Headers: *`,
/// `Expose-Headers: *`): the browser already pre-cleared the request
/// via the preflight short-circuit (line ~2435), and the relay path
/// doesn't expose anything that wasn't already going to the
/// destination through the user's own MITM trust anchor. The wide
/// permissions only relax browser-side CORS gating; they don't widen
/// the underlying network reach. `Allow-Credentials: true` is
/// echo-only-with-explicit-origin (spec requires it; `*` is invalid
/// alongside credentials) — that's why we echo the request's origin
/// and never use `*`.
fn inject_cors_response_headers(response: &[u8], origin: &str) -> Vec<u8> {
    // Find the header / body separator. If we can't parse the
    // response as HTTP/1.x, hand it back unchanged.
    let sep = b"\r\n\r\n";
    let Some(idx) = response.windows(sep.len()).position(|w| w == sep) else {
        return response.to_vec();
    };
    let head_with_terminator = &response[..idx + sep.len()];
    let body = &response[idx + sep.len()..];

    let Some(mut buf) = inject_cors_into_head(head_with_terminator, origin) else {
        return response.to_vec();
    };
    buf.extend_from_slice(body);
    buf
}

/// Head-only variant of `inject_cors_response_headers`. Takes the head
/// block of an HTTP/1.x response *including* the trailing `\r\n\r\n`
/// separator and returns a rewritten head block, again including the
/// `\r\n\r\n` terminator. Returns `None` if the head block isn't valid
/// UTF-8 — the caller should pass the original bytes through unchanged
/// in that case.
///
/// Split out so the range-parallel streaming path can apply CORS
/// rewrites to the response head before the body has been assembled
/// (where the buffered path could just rewrite the finished
/// head+body blob).
pub(crate) fn inject_cors_into_head(head_with_terminator: &[u8], origin: &str) -> Option<Vec<u8>> {
    let sep = b"\r\n\r\n";
    let head = head_with_terminator
        .strip_suffix(sep)
        .unwrap_or(head_with_terminator);
    let head_str = std::str::from_utf8(head).ok()?;

    let mut out = String::with_capacity(head.len() + 256);
    let mut lines = head_str.split("\r\n");
    if let Some(status) = lines.next() {
        out.push_str(status);
        out.push_str("\r\n");
    }
    // Rebuild the header block, dropping any pre-existing
    // `Access-Control-*` lines so the destination's value can't
    // conflict with ours.
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("access-control-") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    // Inject our own. `Vary: Origin` tells downstream caches that the
    // response varies per request origin (so CDN-shared caches don't
    // serve one user's CORS-tagged response to a different origin).
    out.push_str("Access-Control-Allow-Origin: ");
    out.push_str(origin);
    out.push_str("\r\n");
    out.push_str("Access-Control-Allow-Credentials: true\r\n");
    out.push_str("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD\r\n");
    out.push_str("Access-Control-Allow-Headers: *\r\n");
    out.push_str("Access-Control-Expose-Headers: *\r\n");
    out.push_str("Vary: Origin\r\n");
    out.push_str("\r\n");

    Some(out.into_bytes())
}

fn expects_100_continue(headers: &[(String, String)]) -> bool {
    header_value(headers, "expect")
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("100-continue"))
        })
        .unwrap_or(false)
}

fn invalid_body(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

fn body_too_large() -> std::io::Error {
    // FileTooLarge (stable since 1.83) is the canonical kind for this
    // condition. Using a distinct ErrorKind — rather than InvalidData
    // with a magic message substring — keeps the 413 path tied to a
    // compiler-checked tag, so renaming the message can't silently
    // demote responses to 500.
    std::io::Error::new(
        std::io::ErrorKind::FileTooLarge,
        format!("request body exceeds {} byte cap", MAX_REQUEST_BODY_BYTES),
    )
}

fn is_body_too_large(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::FileTooLarge
}

async fn write_payload_too_large<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(
            b"HTTP/1.1 413 Payload Too Large\r\n\
              Connection: close\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    stream.flush().await
}

async fn read_body<S>(
    stream: &mut S,
    leftover: &[u8],
    headers: &[(String, String)],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let transfer_encoding = header_value(headers, "transfer-encoding");
    let is_chunked = transfer_encoding
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false);

    let content_length = match header_value(headers, "content-length") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| invalid_body(format!("invalid Content-Length: {}", v)))?,
        ),
        None => None,
    };

    if transfer_encoding.is_some() && !is_chunked {
        return Err(invalid_body(format!(
            "unsupported Transfer-Encoding: {}",
            transfer_encoding.unwrap_or_default()
        )));
    }

    if is_chunked && content_length.is_some() {
        return Err(invalid_body(
            "both Transfer-Encoding: chunked and Content-Length are present",
        ));
    }

    if expects_100_continue(headers) && (is_chunked || content_length.is_some()) {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        stream.flush().await?;
    }

    if is_chunked {
        return read_chunked_request_body(stream, leftover.to_vec()).await;
    }

    let Some(content_length) = content_length else {
        return Ok(Vec::new());
    };

    if content_length > MAX_REQUEST_BODY_BYTES {
        return Err(body_too_large());
    }

    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&leftover[..leftover.len().min(content_length)]);
    let mut tmp = [0u8; 8192];
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF mid-body",
            ));
        }
        let need = content_length - body.len();
        body.extend_from_slice(&tmp[..n.min(need)]);
    }
    Ok(body)
}

async fn read_chunked_request_body<S>(stream: &mut S, mut buf: Vec<u8>) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];

    loop {
        let line = read_crlf_line(stream, &mut buf, &mut tmp).await?;
        if line.is_empty() {
            continue;
        }

        let line_str = std::str::from_utf8(&line)
            .map_err(|_| invalid_body("non-utf8 chunk size line"))?
            .trim();
        let size_hex = line_str.split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| invalid_body(format!("bad chunk size '{}'", line_str)))?;

        if size == 0 {
            loop {
                let trailer = read_crlf_line(stream, &mut buf, &mut tmp).await?;
                if trailer.is_empty() {
                    return Ok(out);
                }
            }
        }

        let Some(total_len) = out.len().checked_add(size) else {
            return Err(body_too_large());
        };
        if total_len > MAX_REQUEST_BODY_BYTES {
            return Err(body_too_large());
        }
        let want = size
            .checked_add(2)
            .ok_or_else(|| invalid_body(format!("chunk too large '{}'", line_str)))?;
        fill_buffer(stream, &mut buf, &mut tmp, want).await?;
        if &buf[size..size + 2] != b"\r\n" {
            return Err(invalid_body("chunk missing trailing CRLF"));
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(idx) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..idx].to_vec();
            buf.drain(..idx + 2);
            return Ok(line);
        }
        let n = stream.read(tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn fill_buffer<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
    want: usize,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    while buf.len() < want {
        let n = stream.read(tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

// ---------- Plain HTTP proxy ----------

async fn do_plain_http(
    mut sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    fronter: Arc<DomainFronter>,
) -> std::io::Result<()> {
    let (method, target, _version, headers) = parse_request_head(head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    let body = match read_body(&mut sock, leftover, &headers).await {
        Ok(body) => body,
        Err(e) if is_body_too_large(&e) => {
            tracing::warn!(
                "plain HTTP request body exceeds {} bytes — returning 413",
                MAX_REQUEST_BODY_BYTES
            );
            let _ = write_payload_too_large(&mut sock).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    // Browser sends `GET http://example.com/path HTTP/1.1` on plain proxy.
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.clone()
    } else {
        // Fallback: stitch Host header with path.
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        format!("http://{}{}", host, target)
    };

    tracing::info!("HTTP {} {}", method, url);
    // Plain HTTP proxy path — same range-parallel strategy as the
    // MITM-HTTPS path above. Large downloads on port 80 (package
    // mirrors, video poster streams, etc.) need the same acceleration
    // or the relay stalls per-chunk. No CORS injection on this path —
    // plain-http proxy traffic isn't a browser-MITM flow, so the
    // origin's response headers go through unchanged.
    if method.eq_ignore_ascii_case("GET") && body.is_empty() {
        fronter
            .relay_parallel_range_to(
                &mut sock,
                &method,
                &url,
                &headers,
                &body,
                |head: &[u8]| head.to_vec(),
            )
            .await?;
    } else {
        let response = fronter.relay(&method, &url, &headers, &body).await;
        sock.write_all(&response).await?;
    }
    sock.flush().await?;
    Ok(())
}

/// Drive-mode plain-HTTP proxy request. Drive mode is a TCP tunnel, so
/// parse the proxy target, rewrite the request line to origin-form, and
/// send the already-read bytes as the first Data frame after Connect.
async fn do_plain_http_drive(
    sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    rewrite_ctx: &RewriteCtx,
    mux: Arc<crate::drive_client::DriveMux>,
) -> std::io::Result<()> {
    let (method, target, version, headers) = match parse_request_head(head) {
        Some(v) => v,
        None => return Ok(()),
    };

    let (host, port, path) = match resolve_plain_http_target(&target, &headers) {
        Some(v) => v,
        None => {
            tracing::debug!("plain-http drive: cannot parse target {}", target);
            return Ok(());
        }
    };

    match classify_early_route(
        &host,
        port,
        rewrite_ctx.mode,
        &rewrite_ctx.passthrough_hosts,
        &rewrite_ctx.bypass_doh_hosts,
        rewrite_ctx.block_doh,
        rewrite_ctx.bypass_doh,
    ) {
        EarlyRoute::PassthroughHostsMatch => {
            tracing::info!(
                "dispatch http {}:{} -> raw-tcp ({}) (passthrough_hosts match)",
                host,
                port,
                rewrite_ctx.upstream_socks5.as_deref().unwrap_or("direct"),
            );
            plain_http_passthrough_resolved(
                sock,
                &method,
                &version,
                &headers,
                &host,
                port,
                &path,
                leftover,
                rewrite_ctx,
            )
            .await
        }
        EarlyRoute::BlockDoh => {
            tracing::info!("dispatch http {}:{} -> blocked (block_doh)", host, port);
            Ok(())
        }
        EarlyRoute::BypassDoh => {
            tracing::info!(
                "dispatch http {}:{} -> raw-tcp ({}) (doh bypass)",
                host,
                port,
                rewrite_ctx.upstream_socks5.as_deref().unwrap_or("direct"),
            );
            plain_http_passthrough_resolved(
                sock,
                &method,
                &version,
                &headers,
                &host,
                port,
                &path,
                leftover,
                rewrite_ctx,
            )
            .await
        }
        EarlyRoute::Drive => {
            tracing::info!(
                "dispatch http {}:{} -> drive tunnel (via drive mux)",
                host,
                port
            );
            let mut initial = rewrite_plain_http_request_head(&method, &version, &headers, &path);
            initial.extend_from_slice(leftover);
            crate::drive_client::tunnel_connection_with_preface(
                sock,
                host.trim_start_matches('[').trim_end_matches(']'),
                port,
                &mux,
                Bytes::from(initial),
            )
            .await
        }
        EarlyRoute::LocalBypass | EarlyRoute::Full | EarlyRoute::Continue => {
            plain_http_passthrough_resolved(
                sock,
                &method,
                &version,
                &headers,
                &host,
                port,
                &path,
                leftover,
                rewrite_ctx,
            )
            .await
        }
    }
}

/// `direct` mode plain-HTTP passthrough. The CONNECT path already
/// falls through to raw TCP for hosts outside the SNI-rewrite set in
/// `direct`; this is the same idea for the `GET http://…` proxy form
/// so a bare `http://example.com` typed in the address bar doesn't 502.
///
/// We rewrite the absolute-form request URI (`GET http://host/path`) to
/// origin form (`GET /path`), strip hop-by-hop headers, force
/// `Connection: close` so a keep-alive client can't pipeline a request
/// to a different host onto our spliced socket, then dial the origin
/// (honoring `upstream_socks5` if set) and splice both directions.
async fn do_plain_http_passthrough(
    sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    rewrite_ctx: &RewriteCtx,
) -> std::io::Result<()> {
    let (method, target, version, headers) = match parse_request_head(head) {
        Some(v) => v,
        None => return Ok(()),
    };

    let (host, port, path) = match resolve_plain_http_target(&target, &headers) {
        Some(v) => v,
        None => {
            tracing::debug!("plain-http passthrough: cannot parse target {}", target);
            return Ok(());
        }
    };

    tracing::info!(
        "dispatch http {}:{} -> raw-tcp ({}) (direct mode: no relay)",
        host,
        port,
        rewrite_ctx.upstream_socks5.as_deref().unwrap_or("direct"),
    );

    plain_http_passthrough_resolved(
        sock,
        &method,
        &version,
        &headers,
        &host,
        port,
        &path,
        leftover,
        rewrite_ctx,
    )
    .await
}

async fn plain_http_passthrough_resolved(
    mut sock: TcpStream,
    method: &str,
    version: &str,
    headers: &[(String, String)],
    host: &str,
    port: u16,
    path: &str,
    leftover: &[u8],
    rewrite_ctx: &RewriteCtx,
) -> std::io::Result<()> {
    let rewritten = rewrite_plain_http_request_head(method, version, headers, path);

    let target_host = host.trim_start_matches('[').trim_end_matches(']');
    let connect_timeout = if looks_like_ip(target_host) {
        std::time::Duration::from_secs(4)
    } else {
        std::time::Duration::from_secs(10)
    };
    let upstream = if let Some(proxy) = rewrite_ctx.upstream_socks5.as_deref() {
        match socks5_connect_via(proxy, target_host, port).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "upstream-socks5 {} -> {}:{} failed: {} (falling back to direct)",
                    proxy,
                    host,
                    port,
                    e
                );
                match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port)))
                    .await
                {
                    Ok(Ok(s)) => s,
                    _ => return Ok(()),
                }
            }
        }
    } else {
        match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port))).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!("plain-http connect {}:{} failed: {}", host, port, e);
                return Ok(());
            }
            Err(_) => {
                tracing::debug!("plain-http connect {}:{} timeout", host, port);
                return Ok(());
            }
        }
    };
    let _ = upstream.set_nodelay(true);

    let (mut ar, mut aw) = sock.split();
    let (mut br, mut bw) = upstream.into_split();
    bw.write_all(&rewritten).await?;
    if !leftover.is_empty() {
        bw.write_all(leftover).await?;
    }
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
    Ok(())
}

fn rewrite_plain_http_request_head(
    method: &str,
    version: &str,
    headers: &[(String, String)],
    path: &str,
) -> Vec<u8> {
    // Rewrite request line to origin form and drop hop-by-hop headers.
    let mut rewritten = Vec::new();
    rewritten.extend_from_slice(method.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(version.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        // Strip hop-by-hop proxy metadata before forwarding to origin.
        // `proxy-authorization` in particular would otherwise leak the
        // user's proxy credentials/tokens to destination servers in
        // direct-passthrough + Drive modes.
        if kl == "proxy-authorization"
            || kl == "proxy-connection"
            || kl == "connection"
            || kl == "keep-alive"
        {
            continue;
        }
        rewritten.extend_from_slice(k.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(v.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");
    rewritten
}

/// Parse the target of a plain-HTTP proxy request line into
/// `(host, port, origin-form-path)`. Browsers send absolute form
/// (`http://host[:port]/path`); we also accept the origin-form
/// fallback (`/path` with a `Host:` header) for transparent-proxy
/// clients. `https://` is accepted defensively, though browsers route
/// HTTPS through CONNECT and shouldn't hit this path.
fn resolve_plain_http_target(
    target: &str,
    headers: &[(String, String)],
) -> Option<(String, u16, String)> {
    let (rest, default_port) = if let Some(r) = target.strip_prefix("http://") {
        (r, 80u16)
    } else if let Some(r) = target.strip_prefix("https://") {
        (r, 443u16)
    } else if target.starts_with('/') {
        let host_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())?;
        let (host, port) = split_authority(host_header, 80);
        return Some((host, port, target.to_string()));
    } else {
        return None;
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = split_authority(authority, default_port);
    Some((host, port, path.to_string()))
}

/// Split an `authority` (`host[:port]`, with optional IPv6 brackets)
/// into a `(host, port)` pair, defaulting the port when absent.
fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    // Bare IPv6 (multiple colons, no brackets) — `rsplit_once(':')`
    // would otherwise mangle `::1` into `(":", 1)`. Take the whole
    // string as the host and use the default port.
    let colons = authority.bytes().filter(|&b| b == b':').count();
    if colons > 1 && !authority.starts_with('[') {
        return (authority.to_string(), default_port);
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (authority.to_string(), default_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// `block_stun` rejects three specific UDP ports — IANA STUN (3478),
    /// STUNS/TURNS over TLS (5349), and Google's STUN allocation (19302).
    /// The drop fires only on the UDP-relay path; TCP CONNECT to the
    /// same ports is intentionally left open so TURN-TCP fallback works.
    /// Pin the port set so a careless `matches!` typo or a new-port
    /// refactor doesn't silently un-block WebRTC candidates the rest of
    /// the pipeline assumed were already gone.
    #[test]
    fn is_stun_turn_port_matches_only_documented_ports() {
        assert!(is_stun_turn_port(3478), "IANA STUN UDP");
        assert!(is_stun_turn_port(5349), "STUNS/TURNS over TLS");
        assert!(is_stun_turn_port(19302), "Google STUN allocation");

        // Neighboring ports must not be caught: 3479 is unassigned but
        // adjacent; 443 is HTTPS / TURNS-fallback target (must stay open);
        // 0 / u16::MAX are sentinel boundaries.
        assert!(!is_stun_turn_port(0));
        assert!(!is_stun_turn_port(443));
        assert!(!is_stun_turn_port(3477));
        assert!(!is_stun_turn_port(3479));
        assert!(!is_stun_turn_port(5348));
        assert!(!is_stun_turn_port(5350));
        assert!(!is_stun_turn_port(19301));
        assert!(!is_stun_turn_port(19303));
        assert!(!is_stun_turn_port(u16::MAX));
    }

    /// The UDP-relay path filters STUN/TURN by inspecting the parsed
    /// SOCKS5 UDP packet's `target.port`. This guards the assumption that
    /// `parse_socks5_udp_packet_offsets` extracts the destination port
    /// from the header in the right byte order — feed it a packet
    /// addressed at `stun.l.google.com:19302` (literal IPv4 form) and
    /// confirm the parsed port lights up `is_stun_turn_port`. Also
    /// exercises both polarities of the `block_stun` config gate so a
    /// future refactor that inverts the condition fails loudly.
    #[test]
    fn block_stun_udp_path_recognizes_stun_target_port() {
        // SOCKS5 UDP request header (RFC 1928 §7):
        //   RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
        // Use ATYP=0x01 (IPv4) so we don't drag DNS into the test.
        fn build_pkt(port: u16, payload: &[u8]) -> Vec<u8> {
            let mut pkt = vec![0x00, 0x00, 0x00, 0x01];
            pkt.extend_from_slice(&[74, 125, 250, 129]); // any IPv4
            pkt.extend_from_slice(&port.to_be_bytes());
            pkt.extend_from_slice(payload);
            pkt
        }

        // Mirror the runtime decision verbatim — both lines are the
        // exact gate in `handle_socks5_udp_associate`'s recv loop.
        fn should_drop(block_stun: bool, target_port: u16) -> bool {
            block_stun && is_stun_turn_port(target_port)
        }

        // STUN target packet parses cleanly and the payload offset
        // skips the 4 + 4 + 2 = 10-byte SOCKS5 UDP header.
        let stun_pkt = build_pkt(19302, b"stun-binding-request-payload");
        let (stun_target, stun_payload_off) =
            parse_socks5_udp_packet_offsets(&stun_pkt).expect("STUN packet must parse");
        assert_eq!(stun_target.port, 19302);
        assert_eq!(
            &stun_pkt[stun_payload_off..],
            b"stun-binding-request-payload",
            "payload offset must skip past the SOCKS5 header",
        );

        // block_stun=true: STUN target gets dropped.
        assert!(
            should_drop(true, stun_target.port),
            "block_stun=true must drop datagrams to STUN/TURN ports",
        );
        // block_stun=false: STUN target passes through.
        assert!(
            !should_drop(false, stun_target.port),
            "block_stun=false must NOT drop STUN/TURN — \
             config has to remain a real toggle",
        );

        // Negative: a parallel packet to :443 must NOT match under
        // either polarity — that's the TURN-over-TLS fallback path
        // we explicitly want to keep open even when block_stun is on.
        let https_pkt = build_pkt(443, b"");
        let (https_target, _) =
            parse_socks5_udp_packet_offsets(&https_pkt).expect("HTTPS packet must parse");
        assert_eq!(https_target.port, 443);
        assert!(
            !should_drop(true, https_target.port),
            "block_stun=true must NOT touch :443 — TURNS fallback lives there",
        );
        assert!(!should_drop(false, https_target.port));
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn resolve_plain_http_target_parses_absolute_form() {
        let h = headers(&[]);
        let (host, port, path) = resolve_plain_http_target("http://example.com/", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");

        let (host, port, path) =
            resolve_plain_http_target("http://example.com:8080/foo?x=1", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo?x=1");

        let (host, port, path) = resolve_plain_http_target("http://example.com", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn resolve_plain_http_target_falls_back_to_host_header() {
        let h = headers(&[("Host", "example.com:8080")]);
        let (host, port, path) = resolve_plain_http_target("/foo", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo");
    }

    #[test]
    fn resolve_plain_http_target_rejects_bare_authority() {
        // No scheme, doesn't start with `/` — not something we can route.
        assert!(resolve_plain_http_target("example.com", &headers(&[])).is_none());
        assert!(resolve_plain_http_target("http://", &headers(&[])).is_none());
    }

    #[test]
    fn split_authority_handles_ports_and_ipv6() {
        assert_eq!(
            split_authority("example.com", 80),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            split_authority("example.com:8080", 80),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            split_authority("[::1]:8080", 80),
            ("[::1]".to_string(), 8080)
        );
        // Bare IPv6 without brackets — keep the whole string as the host
        // and use the default port instead of mis-splitting on a colon.
        assert_eq!(split_authority("::1", 80), ("::1".to_string(), 80));
    }

    #[test]
    fn socks5_udp_domain_packet_round_trips() {
        let mut raw = vec![0, 0, 0, 0x03, 11];
        raw.extend_from_slice(b"example.com");
        raw.extend_from_slice(&3478u16.to_be_bytes());
        raw.extend_from_slice(b"hello");

        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 3478);
        assert_eq!(payload, b"hello");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[test]
    fn socks5_udp_rejects_fragmented_packets() {
        let raw = [0, 0, 1, 0x01, 127, 0, 0, 1, 0x13, 0x8a, b'x'];
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_rejects_non_utf8_domain() {
        // Lone continuation byte (0x80) — not valid UTF-8. Lossy decode
        // would forward U+FFFD into DNS; strict parse should reject so
        // we fail fast instead of issuing a doomed lookup.
        let raw = [0, 0, 0, 0x03, 1, 0x80, 0, 80];
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_rejects_truncated_inputs() {
        // Header alone is not enough.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01]).is_none());
        // IPv4 with truncated address bytes (need 4 octets).
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01, 127, 0, 0]).is_none());
        // IPv4 with no port.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01, 127, 0, 0, 1]).is_none());
        // DOMAIN with zero-length.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x03, 0, 0, 80]).is_none());
        // DOMAIN with length exceeding remaining buffer.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x03, 5, b'a', b'b']).is_none());
        // Unknown atyp.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x09, 1, 2, 3, 4]).is_none());
        // IPv6 with truncated address.
        let raw = [0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 11 bytes < 16
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_ipv4_round_trips() {
        let mut raw = vec![0, 0, 0, 0x01, 1, 2, 3, 4];
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.extend_from_slice(b"\x00\x01");

        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "1.2.3.4");
        assert_eq!(target.port, 53);
        assert_eq!(payload, b"\x00\x01");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[test]
    fn socks5_udp_ipv6_round_trips() {
        let mut raw = vec![0, 0, 0, 0x04];
        raw.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        raw.extend_from_slice(&443u16.to_be_bytes());
        raw.extend_from_slice(b"q");
        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, 443);
        assert_eq!(payload, b"q");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_decodes_chunked_request() {
        let (mut client, mut server) = duplex(1024);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"llo\r\n6\r\n world\r\n0\r\nFoo: bar\r\n\r\n")
                .await
                .unwrap();
        });

        let body = read_body(
            &mut server,
            b"5\r\nhe",
            &headers(&[("Transfer-Encoding", "chunked")]),
        )
        .await
        .unwrap();

        writer.await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_sends_100_continue_before_waiting_for_body() {
        let (mut client, mut server) = duplex(1024);
        let client_task = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut tmp = [0u8; 64];
            loop {
                let n = client.read(&mut tmp).await.unwrap();
                assert!(n > 0, "proxy closed before sending 100 Continue");
                got.extend_from_slice(&tmp[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert_eq!(got, b"HTTP/1.1 100 Continue\r\n\r\n");
            client.write_all(b"hello").await.unwrap();
        });

        let body = read_body(
            &mut server,
            &[],
            &headers(&[("Content-Length", "5"), ("Expect", "100-continue")]),
        )
        .await
        .unwrap();

        client_task.await.unwrap();
        assert_eq!(body, b"hello");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_rejects_oversized_content_length_before_allocating() {
        let (_client, mut server) = duplex(64);
        let err = read_body(
            &mut server,
            &[],
            &headers(&[("Content-Length", &(MAX_REQUEST_BODY_BYTES + 1).to_string())]),
        )
        .await
        .expect_err("oversized body must be rejected before allocation");

        assert!(is_body_too_large(&err));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_rejects_oversized_chunked_body_before_fill() {
        let (_client, mut server) = duplex(64);
        let first_chunk = format!("{:x}\r\n", MAX_REQUEST_BODY_BYTES + 1);
        let err = read_body(
            &mut server,
            first_chunk.as_bytes(),
            &headers(&[("Transfer-Encoding", "chunked")]),
        )
        .await
        .expect_err("oversized chunked body must be rejected before buffering");

        assert!(is_body_too_large(&err));
    }

    #[test]
    fn body_too_large_detector_round_trips_through_constructor() {
        // Guard against future drift between `body_too_large` and
        // `is_body_too_large` — if anyone retypes the error
        // construction, this test must keep failing until both ends
        // agree on the same signal.
        assert!(is_body_too_large(&body_too_large()));
        assert!(!is_body_too_large(&invalid_body("something else")));
        assert!(!is_body_too_large(&std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        )));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_payload_too_large_emits_413_status_line() {
        let (mut client, mut server) = duplex(256);
        write_payload_too_large(&mut server)
            .await
            .expect("413 must write cleanly to an open stream");
        drop(server);

        let mut buf = Vec::new();
        client
            .read_to_end(&mut buf)
            .await
            .expect("client side must drain the 413");
        let text = std::str::from_utf8(&buf).expect("413 response is ASCII");
        assert!(
            text.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
            "413 status line missing or malformed: {:?}",
            text
        );
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn sni_rewrite_is_only_for_port_443() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("example.com".to_string(), "1.2.3.4".to_string());
        let no_force: Vec<String> = vec![];

        assert!(should_use_sni_rewrite(
            &hosts,
            "google.com",
            443,
            false,
            &no_force
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "google.com",
            80,
            false,
            &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.example.com",
            443,
            false,
            &no_force,
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.example.com",
            80,
            false,
            &no_force,
        ));
    }

    #[test]
    fn youtube_via_relay_routes_youtube_through_relay_path() {
        // Issue #102 + #275. When youtube_via_relay=true:
        //   - YouTube API + HTML hosts (where Restricted Mode lives)
        //     opt out of SNI rewrite so they go through the relay.
        //   - YouTube image / video / channel-asset CDNs STAY on SNI
        //     rewrite — Restricted Mode isn't enforced on those, and
        //     routing video chunks through Apps Script burns quota
        //     and risks the 6-min execution cap. Pre-#275 ytimg.com
        //     was incorrectly carved out alongside the API surfaces.
        //   - Non-YouTube Google suffixes are unaffected by the flag.
        let hosts = std::collections::HashMap::new();
        let no_force: Vec<String> = vec![];

        // Default behaviour (flag off): everything in the SNI pool
        // rewrites including all YouTube assets.
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            false,
            &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "i.ytimg.com",
            443,
            false,
            &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts, "youtu.be", 443, false, &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.google.com",
            443,
            false,
            &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            false,
            &no_force,
        ));

        // googlevideo.com is INTENTIONALLY NOT in SNI_REWRITE_SUFFIXES
        // — see the long note at the top of the SNI list. v1.7.4 tried
        // adding it; reverted in v1.7.6 after user reports of total
        // YouTube breakage. If the project ever ships an EVA-edge-IP
        // config knob, this assertion can flip. Until then, video
        // chunks correctly fall through to the Apps Script relay path
        // and this assertion guards against a regression.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "rr1---sn-abc.googlevideo.com",
            443,
            false,
            &no_force,
        ));

        // Flag on: only the API + HTML hosts opt out.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            true,
            &no_force
        ));
        assert!(!should_use_sni_rewrite(
            &hosts, "youtu.be", 443, true, &no_force
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube-nocookie.com",
            443,
            true,
            &no_force,
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            true,
            &no_force,
        ));

        // Flag on: image / channel-asset CDNs STAY on SNI rewrite. Pre-#275
        // ytimg.com was incorrectly carved out alongside the API surfaces.
        // googlevideo.com still goes through the relay path (not in the
        // SNI list at all — see note above the SNI_REWRITE_SUFFIXES
        // entries) so the same flag-on assertion isn't applicable to it.
        assert!(should_use_sni_rewrite(
            &hosts,
            "i.ytimg.com",
            443,
            true,
            &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "yt3.ggpht.com",
            443,
            true,
            &no_force
        ));

        // Flag on: non-YouTube Google suffixes are unaffected. Note
        // youtubei.googleapis.com (above) is the *carve-out* — the
        // broader googleapis.com suffix is NOT carved out, so e.g.
        // Drive / Calendar / etc. continue to SNI-rewrite.
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.google.com",
            443,
            true,
            &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "fonts.gstatic.com",
            443,
            true,
            &no_force
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "drive.googleapis.com",
            443,
            true,
            &no_force,
        ));
    }

    #[test]
    fn hosts_override_beats_youtube_via_relay() {
        // If the user added an explicit hosts override for a YouTube
        // subdomain, it should win — the override is a deliberate
        // user choice, the toggle is a default policy.
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("rr4.googlevideo.com".to_string(), "1.2.3.4".to_string());
        let no_force: Vec<String> = vec![];

        assert!(should_use_sni_rewrite(
            &hosts,
            "rr4.googlevideo.com",
            443,
            true,
            &no_force,
        ));
    }

    #[test]
    fn passthrough_hosts_exact_match() {
        let list = vec!["example.com".to_string(), "banking.local".to_string()];
        assert!(matches_passthrough("example.com", &list));
        assert!(matches_passthrough("banking.local", &list));
        assert!(matches_passthrough("EXAMPLE.COM", &list)); // case-insensitive
        assert!(!matches_passthrough("notexample.com", &list));
        assert!(!matches_passthrough("sub.example.com", &list)); // exact only, not suffix
    }

    #[test]
    fn passthrough_hosts_dot_prefix_is_suffix_match() {
        let list = vec![".internal.example".to_string()];
        assert!(matches_passthrough("internal.example", &list)); // bare parent matches
        assert!(matches_passthrough("a.internal.example", &list));
        assert!(matches_passthrough("a.b.c.internal.example", &list));
        assert!(!matches_passthrough("internal.exampleX", &list));
        assert!(!matches_passthrough("fakeinternal.example", &list));
    }

    #[test]
    fn passthrough_hosts_empty_list_never_matches() {
        let list: Vec<String> = vec![];
        assert!(!matches_passthrough("anything.com", &list));
        assert!(!matches_passthrough("", &list));
    }

    #[test]
    fn inject_cors_response_headers_replaces_existing_acl_with_origin_echo() {
        // Origin server returned `Access-Control-Allow-Origin: *` which
        // browsers reject when paired with `Allow-Credentials: true` (the
        // YouTube comments failure mode). Our injection must strip the
        // wildcard and substitute the request's actual origin so that
        // credentialed requests succeed.
        let response = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: application/json\r\n\
                        Access-Control-Allow-Origin: *\r\n\
                        Access-Control-Allow-Methods: GET\r\n\
                        Content-Length: 12\r\n\
                        \r\n\
                        {\"a\":\"b\"}xx";
        let injected = inject_cors_response_headers(response, "https://www.youtube.com");
        let s = std::str::from_utf8(&injected).unwrap();
        // Original wildcard must be gone.
        assert!(
            !s.contains("Access-Control-Allow-Origin: *"),
            "wildcard origin must be stripped, got: {}",
            s
        );
        // Echoed origin + credentials must be present.
        assert!(s.contains("Access-Control-Allow-Origin: https://www.youtube.com\r\n"));
        assert!(s.contains("Access-Control-Allow-Credentials: true\r\n"));
        // Body preserved byte-for-byte.
        assert!(injected.ends_with(b"{\"a\":\"b\"}xx"));
        // Status line preserved.
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn inject_cors_response_headers_preserves_non_acl_headers() {
        // Non-ACL headers (Content-Type, Set-Cookie, Cache-Control, …)
        // must pass through unchanged. Only `Access-Control-*` lines
        // are stripped.
        let response = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: text/html\r\n\
                        Set-Cookie: a=1\r\n\
                        Cache-Control: max-age=300\r\n\
                        Access-Control-Allow-Origin: https://other.example\r\n\
                        \r\n\
                        body";
        let injected = inject_cors_response_headers(response, "https://www.youtube.com");
        let s = std::str::from_utf8(&injected).unwrap();
        assert!(s.contains("Content-Type: text/html\r\n"));
        assert!(s.contains("Set-Cookie: a=1\r\n"));
        assert!(s.contains("Cache-Control: max-age=300\r\n"));
        // Wrong origin replaced.
        assert!(!s.contains("Access-Control-Allow-Origin: https://other.example\r\n"));
        assert!(s.contains("Access-Control-Allow-Origin: https://www.youtube.com\r\n"));
    }

    #[test]
    fn inject_cors_response_headers_returns_unchanged_when_no_header_terminator() {
        // A response missing the `\r\n\r\n` separator (e.g. raw error
        // blob, truncated upstream) must round-trip unchanged so we
        // don't corrupt non-HTTP/1.x bytes.
        let response = b"not an http response";
        let injected = inject_cors_response_headers(response, "https://x.com");
        assert_eq!(injected.as_slice(), response);
    }

    #[test]
    fn passthrough_hosts_ignores_empty_and_whitespace_entries() {
        let list = vec!["".to_string(), "   ".to_string(), "real.com".to_string()];
        assert!(!matches_passthrough("", &list));
        assert!(matches_passthrough("real.com", &list));
    }

    #[test]
    fn passthrough_hosts_trailing_dot_normalized() {
        // FQDNs sometimes have a trailing dot; both entry-side and host-side
        // trailing dots should be treated as equivalent to the un-dotted form.
        let list = vec!["example.com.".to_string()];
        assert!(matches_passthrough("example.com", &list));
        assert!(matches_passthrough("example.com.", &list));
    }

    #[test]
    fn doh_default_list_exact_matches() {
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("chrome.cloudflare-dns.com", &extra));
        assert!(matches_doh_host("dns.google", &extra));
        assert!(matches_doh_host("dns.quad9.net", &extra));
        assert!(matches_doh_host("doh.opendns.com", &extra));
    }

    #[test]
    fn doh_default_list_case_insensitive_and_trailing_dot() {
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("DNS.GOOGLE", &extra));
        assert!(matches_doh_host("dns.google.", &extra));
    }

    #[test]
    fn doh_default_list_suffix_match_for_tenant_subdomains() {
        // `cloudflare-dns.com` is in the default list — Workers-hosted
        // tenant DoH endpoints sit under it and should match too.
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("tenant.cloudflare-dns.com", &extra));
        // But a substring match must NOT pass: `xcloudflare-dns.com` is
        // a different domain.
        assert!(!matches_doh_host("xcloudflare-dns.com", &extra));
    }

    #[test]
    fn doh_default_list_unrelated_hosts_do_not_match() {
        let extra: Vec<String> = vec![];
        assert!(!matches_doh_host("example.com", &extra));
        assert!(!matches_doh_host("googlevideo.com", &extra));
        assert!(!matches_doh_host("", &extra));
    }

    #[test]
    fn doh_extra_list_extends_default() {
        let extra = vec![
            ".internal-doh.example".to_string(),
            "doh.acme.test".to_string(),
        ];
        // Defaults still match.
        assert!(matches_doh_host("dns.google", &extra));
        // User additions match.
        assert!(matches_doh_host("doh.acme.test", &extra));
        assert!(matches_doh_host("a.b.internal-doh.example", &extra));
        // Unrelated still doesn't match.
        assert!(!matches_doh_host("example.com", &extra));
    }

    #[test]
    fn doh_extra_entries_match_subdomains_without_leading_dot() {
        // Asymmetry footgun guard: user adds `doh.acme.test` and expects
        // `tenant.doh.acme.test` to match too — same as `dns.google`
        // matching `tenant.dns.google` from the default list. Unlike
        // `passthrough_hosts`, DoH extras don't require a leading dot.
        let extra = vec!["doh.acme.test".to_string()];
        assert!(matches_doh_host("doh.acme.test", &extra));
        assert!(matches_doh_host("tenant.doh.acme.test", &extra));
        // But substring overlap must still be rejected.
        assert!(!matches_doh_host("xdoh.acme.test", &extra));
    }

    fn fg(name: &str, sni: &str, domains: &[&str]) -> Arc<FrontingGroupResolved> {
        Arc::new(
            FrontingGroupResolved::from_config(&FrontingGroup {
                name: name.into(),
                ip: "127.0.0.1".into(),
                sni: sni.into(),
                domains: domains.iter().map(|s| s.to_string()).collect(),
                force_ip: false,
                verify_names: vec![],
            })
            .expect("test fronting group should resolve"),
        )
    }

    #[test]
    fn fronting_group_match_exact_and_suffix() {
        let groups = vec![fg("vercel", "react.dev", &["vercel.com", "nextjs.org"])];
        // Exact.
        assert_eq!(
            match_fronting_group("vercel.com", &groups).map(|g| g.name.as_str()),
            Some("vercel")
        );
        // Suffix.
        assert_eq!(
            match_fronting_group("app.vercel.com", &groups).map(|g| g.name.as_str()),
            Some("vercel")
        );
        // Different member.
        assert_eq!(
            match_fronting_group("docs.nextjs.org", &groups).map(|g| g.name.as_str()),
            Some("vercel")
        );
        // Non-member.
        assert!(match_fronting_group("example.com", &groups).is_none());
        // Substring overlap is NOT a match (xvercel.com isn't *.vercel.com).
        assert!(match_fronting_group("xvercel.com", &groups).is_none());
    }

    #[test]
    fn fronting_group_match_case_and_trailing_dot() {
        let groups = vec![fg("fastly", "www.python.org", &["reddit.com"])];
        assert_eq!(
            match_fronting_group("Reddit.COM", &groups).map(|g| g.name.as_str()),
            Some("fastly")
        );
        assert_eq!(
            match_fronting_group("reddit.com.", &groups).map(|g| g.name.as_str()),
            Some("fastly")
        );
        assert_eq!(
            match_fronting_group("WWW.Reddit.com.", &groups).map(|g| g.name.as_str()),
            Some("fastly")
        );
    }

    #[test]
    fn fronting_group_match_first_wins() {
        // When a host is in two groups, the earlier group is chosen.
        // Lets users put more-specific groups first.
        let groups = vec![
            fg("specific", "a.example", &["api.example.com"]),
            fg("broad", "b.example", &["example.com"]),
        ];
        assert_eq!(
            match_fronting_group("api.example.com", &groups).map(|g| g.name.as_str()),
            Some("specific")
        );
        assert_eq!(
            match_fronting_group("example.com", &groups).map(|g| g.name.as_str()),
            Some("broad")
        );
    }

    #[test]
    fn fronting_group_match_empty_list() {
        let groups: Vec<Arc<FrontingGroupResolved>> = Vec::new();
        assert!(match_fronting_group("vercel.com", &groups).is_none());
    }

    // ── SNI-rewrite forwarder request builder (b3b9220) ──────────────────

    fn parse_request(req: &[u8]) -> (String, Vec<(String, String)>, Vec<u8>) {
        let s = std::str::from_utf8(req).expect("request bytes must be utf-8");
        let mut parts = s.split("\r\n\r\n");
        let head = parts.next().unwrap();
        let body_start = head.len() + 4;
        let body = req[body_start..].to_vec();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap().to_string();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (k, v) = line.split_once(": ").expect("malformed header line");
            headers.push((k.to_string(), v.to_string()));
        }
        (request_line, headers, body)
    }

    fn header_present(headers: &[(String, String)], name: &str) -> bool {
        headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    fn header_get_raw<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn forwarder_request_get_emits_correct_request_line_and_host() {
        let req = build_sni_forward_request_bytes(
            "GET",
            "www.youtube.com",
            443,
            "/watch?v=abc",
            &[("User-Agent".into(), "Mozilla/5.0".into())],
            b"",
        );
        let (line, headers, body) = parse_request(&req);
        assert_eq!(line, "GET /watch?v=abc HTTP/1.1");
        assert_eq!(header_get_raw(&headers, "Host"), Some("www.youtube.com"));
        assert_eq!(header_get_raw(&headers, "Connection"), Some("close"));
        assert_eq!(header_get_raw(&headers, "User-Agent"), Some("Mozilla/5.0"));
        // GET without body must not emit Content-Length.
        assert!(
            !header_present(&headers, "Content-Length"),
            "GET with no body must not emit Content-Length"
        );
        assert!(body.is_empty());
    }

    #[test]
    fn forwarder_request_strips_inbound_chunked_and_sets_fresh_content_length() {
        // `read_body` decodes chunked request bodies before they reach the
        // forwarder, so the Transfer-Encoding header is a lie about the
        // bytes we have. The builder MUST drop it AND any inbound
        // Content-Length, then emit a single fresh Content-Length matching
        // the decoded body length. Otherwise the upstream waits forever
        // for chunk markers that aren't there (or reads the wrong number
        // of bytes).
        let body = b"hello-decoded-body";
        let req = build_sni_forward_request_bytes(
            "POST",
            "example.com",
            443,
            "/api",
            &[
                ("Transfer-Encoding".into(), "chunked".into()),
                ("Content-Length".into(), "999".into()), // stale lie
                ("Content-Type".into(), "application/json".into()),
            ],
            body,
        );
        let (_line, headers, parsed_body) = parse_request(&req);
        assert!(
            !header_present(&headers, "Transfer-Encoding"),
            "Transfer-Encoding must be stripped: {:?}",
            headers
        );
        assert_eq!(
            header_get_raw(&headers, "Content-Length"),
            Some(body.len().to_string().as_str()),
            "Content-Length must reflect actual body length"
        );
        // Make sure there is exactly ONE Content-Length header.
        let cl_count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .count();
        assert_eq!(cl_count, 1, "must emit exactly one Content-Length header");
        // Non-framing headers like Content-Type pass through.
        assert_eq!(
            header_get_raw(&headers, "Content-Type"),
            Some("application/json")
        );
        assert_eq!(parsed_body, body);
    }

    #[test]
    fn forwarder_request_drops_hop_by_hop_and_connection_headers() {
        let req = build_sni_forward_request_bytes(
            "GET",
            "www.youtube.com",
            443,
            "/",
            &[
                ("Connection".into(), "keep-alive".into()),
                ("Proxy-Connection".into(), "keep-alive".into()),
                ("Keep-Alive".into(), "timeout=5".into()),
                ("TE".into(), "trailers".into()),
                ("Trailer".into(), "X-Foo".into()),
                ("Upgrade".into(), "websocket".into()),
                ("Host".into(), "spoofed.example.com".into()), // must be overwritten
                ("Accept".into(), "text/html".into()),
            ],
            b"",
        );
        let (_line, headers, _body) = parse_request(&req);
        // Forced headers we own.
        assert_eq!(header_get_raw(&headers, "Host"), Some("www.youtube.com"));
        assert_eq!(header_get_raw(&headers, "Connection"), Some("close"));
        // None of the inbound copies of the headers we own may pass through.
        let host_count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Host"))
            .count();
        assert_eq!(host_count, 1, "must emit exactly one Host header");
        // Hop-by-hop must be dropped.
        assert!(!header_present(&headers, "Proxy-Connection"));
        assert!(!header_present(&headers, "Keep-Alive"));
        assert!(!header_present(&headers, "TE"));
        assert!(!header_present(&headers, "Trailer"));
        assert!(!header_present(&headers, "Upgrade"));
        // Non-framing pass through.
        assert_eq!(header_get_raw(&headers, "Accept"), Some("text/html"));
    }

    #[test]
    fn forwarder_request_includes_port_in_host_for_nondefault_ports() {
        let req = build_sni_forward_request_bytes("GET", "youtube.com", 8443, "/", &[], b"");
        let (_line, headers, _body) = parse_request(&req);
        assert_eq!(header_get_raw(&headers, "Host"), Some("youtube.com:8443"));
    }

    #[test]
    fn forwarder_request_post_with_empty_body_still_emits_content_length() {
        // POSTs may legitimately have no body, but origins generally
        // expect Content-Length: 0 on a body-bearing method. The
        // get/head/options branch is the one that omits CL.
        let req = build_sni_forward_request_bytes(
            "POST",
            "youtube.com",
            443,
            "/youtubei/v1/no-body",
            &[],
            b"",
        );
        let (_line, headers, _body) = parse_request(&req);
        assert_eq!(header_get_raw(&headers, "Content-Length"), Some("0"));
    }

    // ── normalize_pattern ─────────────────────────────────────────────────

    #[test]
    fn normalize_pattern_strips_scheme_case_insensitively() {
        // The original implementation lowercased AFTER trim_start_matches,
        // so `HTTPS://Foo.com/` slipped through with the scheme intact.
        // Now we lowercase first.
        assert_eq!(
            normalize_pattern("HTTPS://YouTube.com/YouTubei/"),
            "youtube.com/youtubei/"
        );
        assert_eq!(
            normalize_pattern("HTTP://Example.com/api/"),
            "example.com/api/"
        );
        // Bare patterns (no scheme) lower-cased.
        assert_eq!(
            normalize_pattern("YouTube.com/YouTubei/"),
            "youtube.com/youtubei/"
        );
    }

    #[test]
    fn normalize_pattern_trims_trailing_dot_on_host() {
        // FQDN-form host with trailing dot must canonicalise to the same
        // form `extract_host` returns (it trims the dot).
        assert_eq!(
            normalize_pattern("youtube.com./youtubei/"),
            "youtube.com/youtubei/"
        );
        assert_eq!(
            normalize_pattern("https://YouTube.com./api/"),
            "youtube.com/api/"
        );
        // Trailing dot on host-only patterns (no path) too.
        assert_eq!(normalize_pattern("foo.com."), "foo.com");
    }

    #[test]
    fn normalize_pattern_preserves_path_dots() {
        // Only the host component gets its trailing dot stripped — path
        // components keep theirs (a path like `/v1.0/` is legitimate).
        assert_eq!(normalize_pattern("youtube.com/v1.0/"), "youtube.com/v1.0/");
        assert_eq!(normalize_pattern("youtube.com./v1.0/"), "youtube.com/v1.0/");
    }

    #[test]
    fn normalize_pattern_handles_whitespace() {
        assert_eq!(
            normalize_pattern("  youtube.com/youtubei/  "),
            "youtube.com/youtubei/"
        );
    }

    // ── host_is_sni_rewrite_capable ──────────────────────────────────────

    #[test]
    fn sni_capable_recognises_google_edge_hosts() {
        // SNI_REWRITE_SUFFIXES coverage check.
        assert!(host_is_sni_rewrite_capable("youtube.com"));
        assert!(host_is_sni_rewrite_capable("www.youtube.com"));
        assert!(host_is_sni_rewrite_capable("studio.youtube.com"));
        assert!(host_is_sni_rewrite_capable("googleapis.com"));
        assert!(host_is_sni_rewrite_capable("youtubei.googleapis.com"));
        assert!(host_is_sni_rewrite_capable("YouTube.COM")); // case insensitive
        assert!(host_is_sni_rewrite_capable("youtube.com.")); // trailing dot
    }

    #[test]
    fn sni_capable_rejects_non_google_hosts() {
        // The whole point of the check: don't let users pull non-Google
        // hosts through the SNI-rewrite forwarder, which would return
        // wrong-origin responses from the Google edge.
        assert!(!host_is_sni_rewrite_capable("evilsite.com"));
        assert!(!host_is_sni_rewrite_capable("googlevideo.com")); // not in list
        assert!(!host_is_sni_rewrite_capable("api.example.com"));
        // Suffix-attack: "x" + matching suffix must not pass.
        assert!(!host_is_sni_rewrite_capable("notyoutube.com"));
        // Empty / pathological input.
        assert!(!host_is_sni_rewrite_capable(""));
    }

    #[test]
    fn resolved_routing_skips_non_sni_capable_user_pattern_hosts() {
        // Direct test of the wrong-origin defense: a user-supplied
        // pattern targeting a non-Google host must NOT add to
        // `force_mitm_hosts`, because the forwarder would dial Google's
        // edge and return a wrong-origin response. The pattern itself
        // is preserved in `relay_url_patterns` so a matching path still
        // routes via relay if the host is reached through the regular
        // TLS-detect → MITM → relay path.
        //
        // Uses `googleapis.com/api/` as the SNI-capable example —
        // intentionally NOT a YT-family host, so the
        // `youtube_via_relay`-driven YT-suppression doesn't drop it.
        // youtube_via_relay is left off here so the SNI-capable filter
        // is the only thing being exercised.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": [
                "evilsite.com/api/",
                "googleapis.com/inner/"
            ]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // Pattern preserved.
        assert!(r
            .relay_url_patterns
            .contains(&"evilsite.com/api/".to_string()));
        assert!(r
            .relay_url_patterns
            .contains(&"googleapis.com/inner/".to_string()));
        // Non-Google host filtered out of force_mitm_hosts.
        assert!(
            !r.force_mitm_hosts.contains(&"evilsite.com".to_string()),
            "evilsite.com must not be force-MITM'd: {:?}",
            r.force_mitm_hosts,
        );
        // Google-edge host kept.
        assert!(r.force_mitm_hosts.contains(&"googleapis.com".to_string()));
        // And the skip is surfaced for the startup warning.
        assert!(r
            .skipped_force_mitm_hosts
            .contains(&"evilsite.com".to_string()));
    }

    // ── Regression: exit_node.mode=full + user pattern ──────────────────

    #[test]
    fn youtube_via_relay_drops_user_supplied_yt_patterns() {
        // Critical: when youtube_via_relay is on, every YT request goes
        // through the relay via the YOUTUBE_RELAY_HOSTS carve-out, so a
        // user-supplied `youtube.com/youtubei/` pattern is redundant
        // AND harmful — it would re-add youtube.com to force_mitm_hosts
        // and the path filter would then route non-matching paths
        // through `forward_via_sni_rewrite_http`, partially defeating
        // the user's "full YT through relay" opt-in. Dropped at startup
        // with a warning.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "youtube_via_relay": true,
            "relay_url_patterns": [
                "youtube.com/youtubei/",
                "www.youtube.com/watch",
                "googleapis.com/specific-api/"
            ]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // Both YT-host entries dropped; non-YT entry survives.
        assert!(
            !r.relay_url_patterns
                .iter()
                .any(|p| p.starts_with("youtube.com/")),
            "youtube.com/* must be dropped: {:?}",
            r.relay_url_patterns,
        );
        assert!(
            !r.relay_url_patterns
                .iter()
                .any(|p| p.starts_with("www.youtube.com/")),
            "www.youtube.com/* must be dropped: {:?}",
            r.relay_url_patterns,
        );
        assert!(r
            .relay_url_patterns
            .contains(&"googleapis.com/specific-api/".to_string()));
        // youtube.com NOT in force_mitm_hosts (would reactivate the path
        // filter); googleapis.com IS.
        assert!(!r.force_mitm_hosts.contains(&"youtube.com".to_string()));
        assert!(!r.force_mitm_hosts.contains(&"www.youtube.com".to_string()));
        assert!(r.force_mitm_hosts.contains(&"googleapis.com".to_string()));
        // Suppressed list surfaces both for the startup warning.
        assert!(r
            .suppressed_yt_patterns
            .contains(&"youtube.com/youtubei/".to_string()));
        assert!(r
            .suppressed_yt_patterns
            .contains(&"www.youtube.com/watch".to_string()));
    }

    #[test]
    fn youtube_via_relay_off_keeps_user_supplied_yt_patterns() {
        // Sanity check the inverse: when youtube_via_relay is off, user
        // YT patterns should remain (the path filter is the whole point
        // of relay_url_patterns when YT isn't fully relayed).
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": ["youtube.com/youtubei/v2/"]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r.suppressed_yt_patterns.is_empty());
        // User pattern is in the resolved list (alongside the default).
        assert!(r
            .relay_url_patterns
            .contains(&"youtube.com/youtubei/v2/".to_string()));
        assert!(r.force_mitm_hosts.contains(&"youtube.com".to_string()));
    }

    #[test]
    fn exit_node_full_also_drops_user_supplied_yt_patterns() {
        // Belt-and-suspenders: in exit-node-full mode, the runtime
        // forwarder gate already blocks bypass, but
        // youtube_via_relay_effective is true and the same suppression
        // logic applies. A user-supplied YT pattern would be dropped
        // here too, which is fine — the exit-node-full contract makes
        // it a no-op anyway.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": ["youtube.com/youtubei/"],
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r.youtube_via_relay_effective);
        assert!(r.exit_node_full_mode_active);
        assert!(r
            .suppressed_yt_patterns
            .contains(&"youtube.com/youtubei/".to_string()));
        assert!(!r.force_mitm_hosts.contains(&"youtube.com".to_string()));
    }

    #[test]
    fn host_matches_youtube_relay_one_directional() {
        // Same shape as host_in_force_mitm_list — exact match or
        // dot-anchored subdomain.
        assert!(host_matches_youtube_relay("youtube.com"));
        assert!(host_matches_youtube_relay("www.youtube.com"));
        assert!(host_matches_youtube_relay("studio.youtube.com"));
        assert!(host_matches_youtube_relay("youtu.be"));
        assert!(host_matches_youtube_relay("youtube-nocookie.com"));
        assert!(host_matches_youtube_relay("youtubei.googleapis.com"));
        assert!(host_matches_youtube_relay("v1.youtubei.googleapis.com"));
        // Case-insensitive + trailing dot.
        assert!(host_matches_youtube_relay("YouTube.com"));
        assert!(host_matches_youtube_relay("youtube.com."));
        // Sibling subdomains of the parent SNI suffix don't match.
        assert!(!host_matches_youtube_relay("drive.googleapis.com"));
        // Substring attack must not match.
        assert!(!host_matches_youtube_relay("notyoutube.com"));
        assert!(!host_matches_youtube_relay("youtube.com.evil.test"));
    }

    #[test]
    fn exit_node_full_mode_active_propagates_through_resolved_routing() {
        // The flag must round-trip from config to ResolvedRouting so
        // RewriteCtx can carry it to handle_mitm_request and gate the
        // SNI-HTTP forwarder. Selective-mode exit-nodes don't set it.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r.exit_node_full_mode_active);

        // Same config but in selective mode → flag NOT set.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "selective",
                "hosts": ["chatgpt.com"]
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(!r.exit_node_full_mode_active);
    }

    #[test]
    fn exit_node_full_keeps_user_patterns_for_relay_routing() {
        // Critical correctness invariant: in exit_node.mode=full, a
        // user's `relay_url_patterns` entry must NOT cause non-matching
        // paths on its host to bypass the exit node. Two halves to the
        // contract:
        //   1. The user's pattern host is still pulled into
        //      `force_mitm_hosts` so MITM runs and the in-relay
        //      `exit_node_matches` can route through the second hop.
        //   2. `exit_node_full_mode_active` is true so dispatch knows
        //      to skip the SNI-HTTP forwarder for non-matching paths,
        //      sending them to relay → exit node instead of bypassing
        //      both via the Google edge.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": ["googleapis.com/specific-api/"],
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);

        // The user pattern survives — they want googleapis.com to be
        // MITM'd and routed via relay (which then routes through exit
        // node by the full-mode contract).
        assert_eq!(
            r.relay_url_patterns,
            vec!["googleapis.com/specific-api/".to_string()]
        );
        assert_eq!(r.force_mitm_hosts, vec!["googleapis.com".to_string()]);
        // The default `youtube.com/youtubei/` is correctly suppressed
        // because youtube_via_relay_effective is true via exit-node-full.
        assert!(!r
            .relay_url_patterns
            .iter()
            .any(|p| p.starts_with("youtube.com/youtubei/")));
        // And the runtime gate fires.
        assert!(r.exit_node_full_mode_active);
        assert!(r.youtube_via_relay_effective);
    }

    #[test]
    fn forwarder_dispatch_gate_off_when_exit_node_full() {
        // RewriteCtx-level invariant: with exit_node_full_mode_active,
        // the gate that decides whether to use the forwarder must be
        // observably off — even when every other condition would
        // dispatch through it.
        // Reconstruct the gate logic that lives in handle_mitm_request,
        // since pulling a real RewriteCtx through the test requires an
        // I/O-bound DomainFronter.
        let force_mitm_hosts = vec!["googleapis.com".to_string()];
        let patterns = vec!["googleapis.com/specific-api/".to_string()];
        let url = "https://api.googleapis.com/other-path";
        let host = "api.googleapis.com";
        let port = 443u16;
        let scheme = "https";
        let method = "GET";

        let method_safe = method.eq_ignore_ascii_case("GET")
            || method.eq_ignore_ascii_case("HEAD")
            || method.eq_ignore_ascii_case("OPTIONS");

        // Without the exit-node-full gate, every other condition would
        // dispatch through the forwarder.
        let pre_gate = scheme == "https"
            && port == 443
            && method_safe
            && !patterns.is_empty()
            && host_in_force_mitm_list(host, &force_mitm_hosts)
            && !url_matches_relay_pattern(url, &patterns);
        assert!(pre_gate, "test fixture must reach the forwarder gate");

        // With exit_node_full_mode_active = true, the actual gate is off.
        let exit_node_full_mode_active = true;
        let actual_gate = scheme == "https"
            && port == 443
            && method_safe
            && !exit_node_full_mode_active
            && !patterns.is_empty()
            && host_in_force_mitm_list(host, &force_mitm_hosts)
            && !url_matches_relay_pattern(url, &patterns);
        assert!(
            !actual_gate,
            "exit_node.mode=full must disable the forwarder dispatch even \
             when host/path/method would otherwise route through it",
        );
    }

    // ── Regression: trailing-dot URL hosts ────────────────────────────────

    #[test]
    fn url_matches_relay_pattern_trims_trailing_dot_on_url_host() {
        // `host_in_force_mitm_list` trims trailing dots, so dispatch
        // would force-MITM a `www.youtube.com.` request. Without the
        // matching trim here, the URL-host-vs-pattern-host suffix
        // check failed and `/youtubei/v1/...` would route through the
        // SNI-HTTP forwarder instead of the relay — observable as
        // SafeSearch staying sticky after a system that emits FQDN
        // hostnames (some Linux DNS resolvers, browser DoH paths) hits
        // YouTube.
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com./youtubei/v1/browse",
            &patterns,
        ));
        assert!(url_matches_relay_pattern(
            "https://youtube.com./youtubei/",
            &patterns,
        ));
    }

    #[test]
    fn url_matches_relay_pattern_strips_authority_port() {
        // Same canonicalisation: an authority with `:443` must match
        // pattern hosts that don't include the default port. Otherwise
        // the host-vs-pattern compare fails and the dispatcher treats
        // the URL as non-matching → forwarder dispatch.
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com:443/youtubei/v1/browse",
            &patterns,
        ));
        // Non-default port still match — the URL went through some
        // explicit-port flow; the host part is what matters.
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com:8443/youtubei/v1/browse",
            &patterns,
        ));
    }

    #[test]
    fn dispatch_matchers_agree_under_trailing_dot() {
        // End-to-end check: same input must lead to the same
        // membership decision in both matchers, otherwise the dispatch
        // and pattern-check layers disagree (the symptom the reviewer
        // flagged: host force-MITM'd but URL-pattern check fails).
        let force = vec!["youtube.com".to_string()];
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        for variant in [
            "www.youtube.com",
            "www.youtube.com.",
            "WWW.YouTube.COM",
            "WWW.YouTube.COM.",
        ] {
            assert!(host_in_force_mitm_list(variant, &force), "{}", variant);
            let url = format!("https://{}/youtubei/v1/browse", variant);
            assert!(url_matches_relay_pattern(&url, &patterns), "{}", url);
        }
    }

    // ── fronting_groups precedence ───────────────────────────────────────

    #[test]
    fn fronting_group_overlap_with_relay_pattern_resolves_dispatch_via_group() {
        // Documented precedence: dispatch_tunnel checks fronting_groups
        // BEFORE force_mitm_hosts (steps 2a vs 2 in dispatch_tunnel).
        // A user adding `youtube.com` to a fronting group is making a
        // deliberate "alternate edge for YT" choice; the path filter
        // assumes the Google edge handles the request and would land
        // at the wrong upstream if it ran. The override is intentional;
        // this test pins it so a future refactor doesn't accidentally
        // flip the precedence.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "fronting_groups": [{
                "name": "alt-yt-edge",
                "ip": "203.0.113.10",
                "sni": "react.dev",
                "domains": ["youtube.com"]
            }]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        // ResolvedRouting still includes the default pattern — patterns
        // are mode-gated, not fronting-group-gated. The actual override
        // happens at dispatch time.
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r
            .relay_url_patterns
            .contains(&"youtube.com/youtubei/".to_string()));

        // Build the resolved fronting group and confirm
        // `match_fronting_group` returns it for the YT host. This is
        // the call dispatch_tunnel uses at step 2a, BEFORE the force-MITM
        // check at step 2 — the YT request never reaches the path filter.
        let group = FrontingGroupResolved::from_config(&cfg.fronting_groups[0]).unwrap();
        let groups = vec![Arc::new(group)];
        assert!(match_fronting_group("www.youtube.com", &groups).is_some());
        assert!(match_fronting_group("youtube.com", &groups).is_some());
    }

    #[test]
    fn fronting_group_with_disjoint_domain_does_not_interfere() {
        // Sanity check: a fronting group covering an unrelated host
        // (vercel.com) does not affect the YT path filter. Guards
        // against accidentally widening the precedence rule.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "fronting_groups": [{
                "name": "vercel",
                "ip": "76.76.21.21",
                "sni": "react.dev",
                "domains": ["vercel.com"]
            }]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // YT pattern survives untouched.
        assert!(r
            .relay_url_patterns
            .contains(&"youtube.com/youtubei/".to_string()));

        let group = FrontingGroupResolved::from_config(&cfg.fronting_groups[0]).unwrap();
        let groups = vec![Arc::new(group)];
        // YT host doesn't match the unrelated group.
        assert!(match_fronting_group("www.youtube.com", &groups).is_none());
    }

    #[test]
    fn fronting_group_resolve_rejects_invalid_sni() {
        let bad = FrontingGroup {
            name: "bad".into(),
            ip: "127.0.0.1".into(),
            sni: "not a valid hostname".into(),
            domains: vec!["x.com".into()],
            force_ip: false,
            verify_names: vec![],
        };
        assert!(FrontingGroupResolved::from_config(&bad).is_err());
    }

    #[test]
    fn camouflage_breaker_trips_and_clears() {
        // Unique host so the process-global breaker map can't collide
        // with another test.
        let h = "breaker-unit-test.invalid";
        assert!(!camouflage_breaker_tripped(h));
        camouflage_note_unreachable(h);
        assert!(camouflage_breaker_tripped(h));
        camouflage_note_reachable(h);
        assert!(!camouflage_breaker_tripped(h));
    }

    /// The load-bearing invariant: when every candidate upstream IP fails
    /// to connect, `do_camouflage_tunnel` must return the browser socket
    /// *untouched* (never MITM-accepted) so the dispatcher can fall
    /// through to relay/raw. Also pins that the breaker trips after.
    #[tokio::test]
    async fn camouflage_tunnel_returns_untouched_socket_on_upstream_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        // A definitely-closed port (bind then drop) → connect refused fast.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = probe.local_addr().unwrap().port();
        drop(probe);

        // Browser <-> proxy socket pair.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (sock, _peer) = listener.accept().await.unwrap();

        // MITM manager is required by the signature but never used on the
        // all-fail path (we return before the cert mint), so a throwaway
        // CA dir is fine.
        let tmp = std::env::temp_dir().join(format!(
            "rahgozar-cam-test-{}-{}",
            std::process::id(),
            closed_port
        ));
        let mitm = Arc::new(Mutex::new(
            crate::mitm::MitmCertManager::new_in(&tmp).unwrap(),
        ));

        let host = "camo-unreachable-test.invalid";
        // Unique group name so the process-global breaker map can't
        // collide with another test.
        let group = FrontingGroupResolved::from_config(&FrontingGroup {
            name: "camo-test-group".into(),
            ip: "".into(),
            sni: "www.microsoft.com".into(),
            domains: vec![host.into()],
            force_ip: true,
            verify_names: vec![],
        })
        .unwrap();
        // Loopback + closed port → every dial attempt fails fast.
        let ips = vec!["127.0.0.1".parse().unwrap()];

        let res = do_camouflage_tunnel(sock, host, closed_port, mitm, &group, ips).await;
        let mut returned = res.expect_err("must hand the socket back on all-upstream-fail");

        // Prove the socket was never MITM-accepted: a raw byte still
        // round-trips on it. A TLS accept would have consumed/garbled it.
        client.write_all(b"Z").await.unwrap();
        let mut b = [0u8; 1];
        let n = returned.read(&mut b).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&b, b"Z");

        // And the breaker is now tripped for this group (keyed by name).
        assert!(camouflage_breaker_tripped(&group.name));
        camouflage_note_reachable(&group.name); // cleanup shared state
    }

    #[test]
    fn url_matches_relay_pattern_basic() {
        // Default upstream pattern. Path-anchored — matches the
        // youtubei prefix, NOT a similarly-named query string.
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com/youtubei/v1/browse",
            &patterns,
        ));
        assert!(url_matches_relay_pattern(
            "https://m.youtube.com/youtubei/v1/player",
            &patterns,
        ));
        // Bare scheme variant
        assert!(url_matches_relay_pattern(
            "http://youtube.com/youtubei/",
            &patterns,
        ));
        // Wrong path on the right host
        assert!(!url_matches_relay_pattern(
            "https://www.youtube.com/watch?v=abc",
            &patterns,
        ));
        // Right path-shape on the wrong host
        assert!(!url_matches_relay_pattern(
            "https://example.com/youtubei/v1",
            &patterns,
        ));
        // Suffix attack — trailing dot on host should not bypass match.
        // (URL parsing strips the trailing dot before reaching here in
        // practice; the matcher is strict on the host segment.)
        assert!(!url_matches_relay_pattern(
            "https://evil-youtube.com/youtubei/",
            &patterns,
        ));
    }

    #[test]
    fn url_matches_relay_pattern_empty_patterns_never_matches() {
        let empty: Vec<String> = vec![];
        assert!(!url_matches_relay_pattern(
            "https://www.youtube.com/",
            &empty
        ));
    }

    #[test]
    fn host_in_force_mitm_list_is_suffix_anchored() {
        let list = vec!["youtube.com".to_string()];
        assert!(host_in_force_mitm_list("youtube.com", &list));
        assert!(host_in_force_mitm_list("www.youtube.com", &list));
        assert!(host_in_force_mitm_list("m.youtube.com", &list));
        // Strict suffix — trailing-dot trim should still match.
        assert!(host_in_force_mitm_list("youtube.com.", &list));
        // Substring attack must NOT match.
        assert!(!host_in_force_mitm_list("notyoutube.com", &list));
        assert!(!host_in_force_mitm_list("youtube.com.evil.test", &list));
        // Empty list never matches.
        let empty: Vec<String> = vec![];
        assert!(!host_in_force_mitm_list("anything", &empty));
    }

    fn make_direct_ctx() -> Arc<crate::direct_mode::DirectModeCtx> {
        Arc::new(crate::direct_mode::DirectModeCtx::from_parts(
            true,
            vec!["www.google.com".into()],
            crate::direct_mode::DEFAULT_GOOGLE_DOMAINS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            crate::direct_mode::DEFAULT_SANCTIONED_DOMAINS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            None,
        ))
    }

    fn empty_hosts() -> std::collections::HashMap<String, String> {
        std::collections::HashMap::new()
    }

    #[test]
    fn direct_mode_branch_fires_for_google_host() {
        let direct = make_direct_ctx();
        let h = empty_hosts();
        assert!(should_take_direct_mode_branch(
            443,
            Some(&direct),
            "mail.google.com",
            &[],
            false,
            &h
        ));
        assert!(should_take_direct_mode_branch(
            443,
            Some(&direct),
            "i.ytimg.com",
            &[],
            false,
            &h
        ));
    }

    #[test]
    fn direct_mode_branch_skips_non_google() {
        let direct = make_direct_ctx();
        let h = empty_hosts();
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "example.com",
            &[],
            false,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "twitter.com",
            &[],
            false,
            &h
        ));
    }

    #[test]
    fn direct_mode_branch_skips_non_443() {
        let direct = make_direct_ctx();
        let h = empty_hosts();
        // Port-gated: a non-443 CONNECT (e.g. google.com:80) must NOT
        // be diverted to a path that requires a TLS ClientHello.
        assert!(!should_take_direct_mode_branch(
            80,
            Some(&direct),
            "google.com",
            &[],
            false,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            8080,
            Some(&direct),
            "google.com",
            &[],
            false,
            &h
        ));
    }

    #[test]
    fn direct_mode_branch_skips_when_ctx_none() {
        let h = empty_hosts();
        // Feature disabled in config → predicate returns false even
        // for canonical Google hosts.
        assert!(!should_take_direct_mode_branch(
            443,
            None,
            "mail.google.com",
            &[],
            false,
            &h
        ));
    }

    #[test]
    fn direct_mode_branch_yields_to_force_mitm_hosts() {
        let direct = make_direct_ctx();
        let h = empty_hosts();
        let force = vec!["youtube.com".to_string()];
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "www.youtube.com",
            &force,
            false,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "youtube.com",
            &force,
            false,
            &h
        ));
        // Sibling hosts not in force_mitm_hosts still take direct.
        assert!(should_take_direct_mode_branch(
            443,
            Some(&direct),
            "i.ytimg.com",
            &force,
            false,
            &h
        ));
    }

    #[test]
    fn direct_mode_branch_yields_to_youtube_via_relay() {
        let direct = make_direct_ctx();
        let h = empty_hosts();
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "www.youtube.com",
            &[],
            true,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "youtu.be",
            &[],
            true,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "youtubei.googleapis.com",
            &[],
            true,
            &h
        ));
        // Static CDN (ytimg) still takes direct under youtube_via_relay
        // — it's SNI-rewrite-capable, so the carve-out doesn't apply.
        // googlevideo.com is NOT in `DEFAULT_GOOGLE_DOMAINS` (no safe
        // fallback path), so it never enters Direct Mode in the first
        // place; see `default_google_domains_are_subset_of_sni_rewrite_suffixes`.
        assert!(should_take_direct_mode_branch(
            443,
            Some(&direct),
            "i.ytimg.com",
            &[],
            true,
            &h
        ));
    }

    #[test]
    fn direct_mode_branch_yields_to_sanctioned_domains() {
        let direct = make_direct_ctx();
        let h = empty_hosts();
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "gemini.google.com",
            &[],
            false,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "aistudio.google.com",
            &[],
            false,
            &h
        ));
        assert!(should_take_direct_mode_branch(
            443,
            Some(&direct),
            "mail.google.com",
            &[],
            false,
            &h
        ));
    }

    #[test]
    fn direct_mode_branch_yields_to_hosts_override() {
        // A user-typed `hosts: { "mail.google.com": "1.2.3.4" }` is a
        // deliberate signal that this exact IP works on the user's
        // network. Direct Mode would silently bypass the override by
        // dialing to a different front; instead defer to SNI-rewrite,
        // which honours the override.
        let direct = make_direct_ctx();
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("mail.google.com".to_string(), "1.2.3.4".to_string());
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "mail.google.com",
            &[],
            false,
            &hosts
        ));
        // Non-overridden hosts still take direct.
        assert!(should_take_direct_mode_branch(
            443,
            Some(&direct),
            "drive.google.com",
            &[],
            false,
            &hosts
        ));
    }

    #[test]
    fn direct_mode_branch_skips_non_sni_rewrite_capable_hosts() {
        // Defense-in-depth: even if a user customises
        // `direct_mode.google_domains` to include hosts that aren't
        // in `SNI_REWRITE_SUFFIXES` (e.g. they re-add `googlevideo.com`
        // because they read zyrln's defaults), the predicate must
        // skip Direct Mode for them — fallback to SNI-rewrite would
        // hit wrong-cert errors, regressing the pre-Direct-Mode
        // relay-only routing for those hosts.
        let custom = Arc::new(crate::direct_mode::DirectModeCtx::from_parts(
            true,
            vec!["www.google.com".into()],
            vec![
                // Bundled defaults — these ARE in SNI_REWRITE_SUFFIXES.
                ".google.com".into(),
                ".youtube.com".into(),
                // User-added entries that ARE NOT — must be skipped.
                ".googlevideo.com".into(),
                ".gmail.com".into(),
                ".android.com".into(),
            ],
            vec![],
            None,
        ));
        let h = empty_hosts();
        // SNI-rewrite-capable → fires.
        assert!(should_take_direct_mode_branch(
            443,
            Some(&custom),
            "mail.google.com",
            &[],
            false,
            &h
        ));
        assert!(should_take_direct_mode_branch(
            443,
            Some(&custom),
            "www.youtube.com",
            &[],
            false,
            &h
        ));
        // Non-SNI-rewrite-capable → skipped (defense-in-depth check).
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&custom),
            "r1.googlevideo.com",
            &[],
            false,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&custom),
            "mail.gmail.com",
            &[],
            false,
            &h
        ));
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&custom),
            "developer.android.com",
            &[],
            false,
            &h
        ));
    }

    #[test]
    fn default_google_domains_are_subset_of_sni_rewrite_suffixes() {
        // Contract guard: `DEFAULT_GOOGLE_DOMAINS` must be a strict
        // subset of `SNI_REWRITE_SUFFIXES` so the bundled defaults
        // never trigger the wrong-fallback regression. If someone
        // re-adds googlevideo.com / gmail.com / etc. to the defaults
        // in `direct_mode.rs`, this fails loudly.
        for entry in crate::direct_mode::DEFAULT_GOOGLE_DOMAINS {
            let bare = entry.trim_start_matches('.');
            assert!(
                SNI_REWRITE_SUFFIXES.contains(&bare),
                "{} is in DEFAULT_GOOGLE_DOMAINS but not in SNI_REWRITE_SUFFIXES — \
                 the SkipPrefaced fallback to SNI-rewrite would be unsafe for this host",
                bare
            );
        }
    }

    #[test]
    fn direct_mode_branch_yields_when_breaker_tripped() {
        // After enough consecutive failures the breaker engages and
        // the dispatcher skips direct mode entirely until cooldown
        // elapses — protects users on networks where direct never
        // works from eating fast-path + race latency on every CONNECT.
        let direct = make_direct_ctx();
        let h = empty_hosts();
        for _ in 0..crate::direct_mode::CIRCUIT_BREAKER_THRESHOLD {
            direct.note_failure();
        }
        assert!(direct.breaker_tripped());
        assert!(!should_take_direct_mode_branch(
            443,
            Some(&direct),
            "mail.google.com",
            &[],
            false,
            &h
        ));
        // Recording a success clears the breaker.
        direct.note_success();
        assert!(!direct.breaker_tripped());
        assert!(should_take_direct_mode_branch(
            443,
            Some(&direct),
            "mail.google.com",
            &[],
            false,
            &h
        ));
    }

    #[test]
    fn force_mitm_pulls_host_out_of_sni_rewrite() {
        // With `relay_url_patterns: ["youtube.com/youtubei/"]`, the host
        // youtube.com gets pulled out of SNI-rewrite so MITM can run
        // and inspect paths. Other YT-family hosts (ytimg, ggpht) stay
        // on SNI-rewrite — they aren't in the patterns and the user
        // hasn't asked for path-level routing on them.
        let hosts = std::collections::HashMap::new();
        let force = vec!["youtube.com".to_string()];

        // youtube.com itself is force-MITM'd → not SNI-rewrite.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            false,
            &force,
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "m.youtube.com",
            443,
            false,
            &force,
        ));
        // Sibling YT hosts NOT in the force list still SNI-rewrite.
        assert!(should_use_sni_rewrite(
            &hosts,
            "i.ytimg.com",
            443,
            false,
            &force,
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "yt3.ggpht.com",
            443,
            false,
            &force,
        ));
    }

    #[test]
    fn force_mitm_overrides_hosts_override() {
        // If the user has both an explicit hosts override AND a relay_url_patterns
        // entry that pulls the same host out of SNI-rewrite, the pattern wins —
        // we need MITM for the per-path matcher to run. The hosts override is
        // still used as the upstream IP by `forward_via_sni_rewrite_http` /
        // `do_sni_rewrite_tunnel_from_tcp`, just not as a CONNECT-tunnel target.
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("www.youtube.com".to_string(), "1.2.3.4".to_string());
        let force = vec!["youtube.com".to_string()];

        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            false,
            &force,
        ));
    }

    fn make_test_config(mode: &str) -> crate::config::Config {
        let s = format!(
            r#"{{
                "mode": "{mode}",
                "auth_key": "secret-test-secret-test",
                "script_id": "X"
            }}"#,
        );
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn resolved_routing_apps_script_default_prepends_youtubei_pattern() {
        // The default-shipped pattern is `youtube.com/youtubei/`. With no
        // user config and no exit node, apps_script mode should resolve
        // exactly that one pattern and pull `youtube.com` from
        // SNI-rewrite (so MITM can run for path inspection).
        let cfg = make_test_config("apps_script");
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert_eq!(
            r.relay_url_patterns,
            vec!["youtube.com/youtubei/".to_string()]
        );
        assert_eq!(r.force_mitm_hosts, vec!["youtube.com".to_string()]);
        assert!(!r.youtube_via_relay_effective);
        assert!(!r.exit_node_full_mode_active);
    }

    #[test]
    fn resolved_routing_direct_mode_skips_default_pattern() {
        // CRITICAL regression guard. In direct mode there is no
        // Apps Script relay path. The `youtube.com/youtubei/` default
        // would pull `youtube.com` from SNI-rewrite, and the dispatcher
        // would then send YT requests to RAW TCP fallback because nothing
        // would match SNI-rewrite OR Apps Script. Test asserts that
        // direct mode resolves to empty pattern + force-MITM lists.
        let cfg = make_test_config("direct");
        let r = ResolvedRouting::from_config(&cfg, Mode::Direct);
        assert!(
            r.relay_url_patterns.is_empty(),
            "direct mode must not populate relay_url_patterns: {:?}",
            r.relay_url_patterns,
        );
        assert!(
            r.force_mitm_hosts.is_empty(),
            "direct mode must not populate force_mitm_hosts: {:?}",
            r.force_mitm_hosts,
        );
    }

    #[test]
    fn resolved_routing_full_mode_skips_default_pattern() {
        // Mode::Full's dispatcher short-circuits to the tunnel mux
        // before MITM runs, so patterns would never be consulted —
        // resolving them is dead weight. Same gate as direct mode.
        let cfg = make_test_config("full");
        let r = ResolvedRouting::from_config(&cfg, Mode::Full);
        assert!(r.relay_url_patterns.is_empty());
        assert!(r.force_mitm_hosts.is_empty());
    }

    #[test]
    fn resolved_routing_direct_mode_youtube_still_sni_rewrites() {
        // End-to-end check of the direct-mode regression: with the
        // resolved sets empty, `should_use_sni_rewrite` should send
        // www.youtube.com:443 to the SNI-rewrite tunnel, not raw-TCP
        // fallback.
        let cfg = make_test_config("direct");
        let r = ResolvedRouting::from_config(&cfg, Mode::Direct);
        let hosts = std::collections::HashMap::new();
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            r.youtube_via_relay_effective,
            &r.force_mitm_hosts,
        ));
    }

    #[test]
    fn resolved_routing_youtube_via_relay_skips_default_pattern() {
        // When the user explicitly opts in to `youtube_via_relay = true`,
        // YouTube is fully relayed already — the per-path filter is
        // redundant. User extras still resolve, just not the default.
        // The user pattern host MUST be SNI-rewrite-capable to land in
        // `force_mitm_hosts`; here we use `googleapis.com` since it's
        // in `SNI_REWRITE_SUFFIXES`.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "youtube_via_relay": true,
            "relay_url_patterns": ["googleapis.com/api/"]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // Default `youtube.com/youtubei/` NOT prepended; user entry kept.
        assert_eq!(
            r.relay_url_patterns,
            vec!["googleapis.com/api/".to_string()]
        );
        assert_eq!(r.force_mitm_hosts, vec!["googleapis.com".to_string()]);
        assert!(r.skipped_force_mitm_hosts.is_empty());
        assert!(r.youtube_via_relay_effective);
    }

    #[test]
    fn resolved_routing_exit_node_full_mode_skips_default_pattern() {
        // CRITICAL regression guard. With `exit_node.mode = "full"`
        // and `youtube_via_relay = false`, the prior code prepended
        // `youtube.com/youtubei/` even though the YT-via-relay flag
        // was effectively true. That made non-`/youtubei/` YouTube
        // requests route through `forward_via_sni_rewrite_http`,
        // bypassing `DomainFronter::relay` and with it the exit node
        // — defeating the whole point of full mode. Now the effective
        // flag gates the prepend, and YT goes fully through relay
        // (and thus through the exit node).
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "youtube_via_relay": false,
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(
            r.youtube_via_relay_effective,
            "exit_node.mode=full must imply youtube_via_relay (88b2767)",
        );
        assert!(r.exit_node_full_mode_active);
        assert!(
            r.relay_url_patterns.is_empty(),
            "exit_node.mode=full must NOT prepend default pattern \
             (would bypass exit node for non-/youtubei/ paths): {:?}",
            r.relay_url_patterns,
        );
        assert!(r.force_mitm_hosts.is_empty());
    }

    #[test]
    fn resolved_routing_exit_node_full_in_direct_mode_does_not_imply_yt_relay() {
        // exit_node config is shared across modes but only applies to
        // apps_script. In direct mode there's no relay → no exit node
        // → the OR with exit-node-full must NOT promote
        // youtube_via_relay_effective to true (would be misleading).
        let s = r#"{
            "mode": "direct",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::Direct);
        assert!(!r.youtube_via_relay_effective);
        assert!(!r.exit_node_full_mode_active);
        assert!(r.relay_url_patterns.is_empty());
    }

    #[test]
    fn resolved_routing_exit_node_selective_does_not_imply_yt_relay() {
        // Exit-node `selective` (the default) only sends listed hosts
        // through the second hop. YouTube isn't in the typical CF-anti-bot
        // list, and the per-path filter is fine to keep — non-`/youtubei/`
        // YT paths going via SNI-rewrite forward is the win the filter
        // was designed for.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "selective",
                "hosts": ["chatgpt.com"]
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(!r.youtube_via_relay_effective);
        assert!(!r.exit_node_full_mode_active);
        // Default pattern still prepended.
        assert_eq!(
            r.relay_url_patterns,
            vec!["youtube.com/youtubei/".to_string()]
        );
    }

    #[test]
    fn resolved_routing_user_patterns_dedup_against_default() {
        // If a user pastes the default pattern verbatim (or with stray
        // whitespace / scheme), dedup keeps a single entry.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": [
                "https://YouTube.com/YouTubei/",
                "  example.com/api/  "
            ]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert_eq!(
            r.relay_url_patterns,
            vec![
                "youtube.com/youtubei/".to_string(),
                "example.com/api/".to_string(),
            ],
        );
    }

    #[test]
    fn force_mitm_pulls_only_configured_host_and_subdomains() {
        // One-directional suffix match: an entry like
        // `youtubei.googleapis.com` pulls itself and its subdomains, but
        // does NOT pull the parent `googleapis.com` or sibling
        // subdomains. Sibling traffic stays on SNI-rewrite. This is a
        // regression guard against the original bidirectional-match
        // implementation, which pulled parents and made
        // `host_in_force_mitm_list` disagree with `matches_sni_rewrite`.
        let hosts = std::collections::HashMap::new();
        let force = vec!["youtubei.googleapis.com".to_string()];

        // Exact force host: pulled.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            false,
            &force,
        ));
        // Subdomain of the force host: pulled.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "v1.youtubei.googleapis.com",
            443,
            false,
            &force,
        ));
        // Sibling subdomain of the parent: NOT pulled (stays on SNI-rewrite).
        assert!(should_use_sni_rewrite(
            &hosts,
            "drive.googleapis.com",
            443,
            false,
            &force,
        ));
    }

    #[test]
    fn force_mitm_subdomain_does_not_pull_parent_sni_suffix() {
        // Direct test of the asymmetry that motivated dropping the
        // bidirectional clause. force=`studio.youtube.com` must NOT
        // make `www.youtube.com` or bare `youtube.com` pull out of
        // SNI-rewrite — those should still take the SNI-rewrite tunnel
        // (matched via the `youtube.com` entry in SNI_REWRITE_SUFFIXES).
        // Otherwise the dispatch-side `host_in_force_mitm_list` would
        // disagree (no recognition of the parent), and parent-host
        // traffic would be force-MITM'd-then-blindly-relayed instead of
        // taking the fast SNI tunnel.
        let hosts = std::collections::HashMap::new();
        let force = vec!["studio.youtube.com".to_string()];

        // Configured host pulled.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "studio.youtube.com",
            443,
            false,
            &force,
        ));
        // Parent NOT pulled — still SNI-rewrites.
        assert!(should_use_sni_rewrite(
            &hosts,
            "youtube.com",
            443,
            false,
            &force,
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            false,
            &force,
        ));
        // Matchers must agree on membership of the parent.
        assert!(!host_in_force_mitm_list("youtube.com", &force));
        assert!(!host_in_force_mitm_list("www.youtube.com", &force));
    }

    // ── Live-switch lifecycle tests ─────────────────────────────────────
    // Cover three contracts: switch-vs-shutdown safety (no spawning
    // after Stop), error paths leaving the bundle untouched, and
    // mode-task lifecycle (abort-on-switch, no leaks).

    fn switch_test_direct_config() -> crate::config::Config {
        serde_json::from_str(r#"{"mode": "direct"}"#).unwrap()
    }

    fn switch_test_apps_script_config() -> crate::config::Config {
        serde_json::from_str(
            r#"{
                "mode": "apps_script",
                "auth_key": "secret-test-secret-test",
                "script_id": "X"
            }"#,
        )
        .unwrap()
    }

    fn switch_test_full_config() -> crate::config::Config {
        // Full-tunnel mode shares its DomainFronter::new validation
        // contract with apps_script (script_id is the only required
        // field for `DomainFronter::new` itself; runtime tunnel-node
        // settings are validated elsewhere and not exercised here).
        // What's *unique* about Full mode for switch_mode is that the
        // ModeBundle ends up with `Some(tunnel_mux)` — the path that
        // calls `TunnelMux::start`.
        serde_json::from_str(
            r#"{
                "mode": "full",
                "auth_key": "secret-test-secret-test",
                "script_id": "X"
            }"#,
        )
        .unwrap()
    }

    fn switch_test_invalid_apps_script_config() -> crate::config::Config {
        // apps_script without script_id — DomainFronter::new will reject
        // with "no script_id configured". Used to verify the error path
        // through switch_mode leaves the live bundle untouched.
        serde_json::from_str(r#"{"mode": "apps_script"}"#).unwrap()
    }

    /// Build a `RuntimeState` for tests. Returns the `TempDir` alongside
    /// so the caller can keep it alive for the test's scope — the
    /// underlying `MitmCertManager` reads CA key+cert into memory at
    /// construction and doesn't touch them again, so the TempDir can
    /// safely drop at end of scope (cleaning up the generated `ca/ca.key`
    /// material). A previous shape leaked the TempDir via
    /// `std::mem::forget`, which left CA private keys littering the
    /// host's temp directory after every test run.
    async fn make_runtime_state(
        cfg: &crate::config::Config,
    ) -> (Arc<RuntimeState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mitm = MitmCertManager::new_in(tmp.path()).expect("mitm init");
        let mitm = Arc::new(Mutex::new(mitm));
        let state = RuntimeState::new(cfg, mitm).expect("runtime state");
        (state, tmp)
    }

    #[tokio::test]
    async fn switch_direct_to_apps_script_swaps_mode_and_populates_fronter() {
        let (state, _tmp) = make_runtime_state(&switch_test_direct_config()).await;
        assert_eq!(state.bundle.load().rewrite_ctx.mode, Mode::Direct);
        assert!(state.bundle.load().fronter.is_none());
        // No tasks at rest — `run()` hasn't been called, switch_mode
        // hasn't either.
        assert!(state.mode_tasks.lock().await.is_empty());

        state
            .switch_mode(&switch_test_apps_script_config())
            .await
            .expect("switch ok");

        let cur = state.bundle.load();
        assert_eq!(cur.rewrite_ctx.mode, Mode::AppsScript);
        assert!(cur.fronter.is_some());
        // switch_mode must have spawned the fronter's background tasks.
        assert!(!state.mode_tasks.lock().await.is_empty());

        // Clean up so the tokio runtime can tear down without warning
        // about still-running background tasks.
        state.mode_tasks.lock().await.abort_all();
    }

    #[tokio::test]
    async fn switch_direct_to_full_starts_tunnel_mux() {
        // Exercises the Full-mode branch of switch_mode: bundle gets a
        // `Some(tunnel_mux)` from `TunnelMux::start`, fronter is built
        // the same way as apps_script, and the mode-task set is
        // spawned. Without this test the `TunnelMux::start` call inside
        // `switch_mode` is reachable only at process startup via
        // `RuntimeState::run`'s post-bind init — not by any live-switch
        // test.
        let (state, _tmp) = make_runtime_state(&switch_test_direct_config()).await;
        assert_eq!(state.current_mode(), Mode::Direct);
        assert!(state.bundle.load().tunnel_mux.is_none());

        state
            .switch_mode(&switch_test_full_config())
            .await
            .expect("switch to full");

        let cur = state.bundle.load();
        assert_eq!(cur.rewrite_ctx.mode, Mode::Full);
        assert!(cur.fronter.is_some(), "Full mode must have a fronter");
        assert!(
            cur.tunnel_mux.is_some(),
            "Full mode must install a TunnelMux",
        );
        drop(cur);
        assert!(!state.mode_tasks.lock().await.is_empty());

        // Switching away from Full must clear the mux (next mode has no
        // tunnel) so its mpsc::Sender drops and the spawned mux_loop
        // exits naturally.
        state
            .switch_mode(&switch_test_direct_config())
            .await
            .expect("switch back to direct");
        let cur = state.bundle.load();
        assert!(cur.tunnel_mux.is_none(), "direct mode must clear the mux");
        assert!(cur.fronter.is_none());

        state.mode_tasks.lock().await.abort_all();
    }

    #[tokio::test]
    async fn switch_apps_script_to_direct_clears_fronter_and_tasks() {
        let (state, _tmp) = make_runtime_state(&switch_test_apps_script_config()).await;
        // Prime apps_script tasks via a no-op switch into the same mode.
        state
            .switch_mode(&switch_test_apps_script_config())
            .await
            .expect("prime");
        assert!(!state.mode_tasks.lock().await.is_empty());
        assert!(state.bundle.load().fronter.is_some());

        state
            .switch_mode(&switch_test_direct_config())
            .await
            .expect("switch to direct");

        let cur = state.bundle.load();
        assert_eq!(cur.rewrite_ctx.mode, Mode::Direct);
        assert!(cur.fronter.is_none());
        // No fronter → spawn_mode_tasks was never called → bag stays
        // empty. The previous mode's handles were aborted by switch_mode.
        assert!(state.mode_tasks.lock().await.is_empty());
    }

    #[tokio::test]
    async fn switch_with_invalid_config_keeps_live_bundle_intact() {
        let (state, _tmp) = make_runtime_state(&switch_test_direct_config()).await;

        let err = state
            .switch_mode(&switch_test_invalid_apps_script_config())
            .await
            .expect_err("invalid apps_script config must reject");
        // The DomainFronter::new "no script_id configured" error comes
        // through as a generic io::Other.
        let msg = format!("{}", err);
        assert!(
            msg.contains("script_id") || msg.contains("no script_id"),
            "unexpected error message: {}",
            msg
        );

        // Live bundle untouched.
        let cur = state.bundle.load();
        assert_eq!(cur.rewrite_ctx.mode, Mode::Direct);
        assert!(cur.fronter.is_none());
        assert!(state.mode_tasks.lock().await.is_empty());
    }

    #[tokio::test]
    async fn switch_after_stop_bails_and_does_not_spawn_tasks() {
        // Guards the switch-vs-shutdown contract: if Stop has set
        // `stopped = true` under `switch_lock`, a later `switch_mode`
        // must NOT spawn fresh keepalive/refill/stats tasks that
        // would outlive shutdown.
        let (state, _tmp) = make_runtime_state(&switch_test_direct_config()).await;
        {
            let _g = state.switch_lock.lock().await;
            state.stopped.store(true, Ordering::SeqCst);
        }
        let err = state
            .switch_mode(&switch_test_apps_script_config())
            .await
            .expect_err("must refuse after stop");
        // The "shutting down" race is its own error variant so the UI
        // can suppress it. A string-only assertion would be brittle
        // against future error-message edits.
        assert!(matches!(err, ProxyError::ShuttingDown), "got {:?}", err);

        // Bundle unchanged.
        assert_eq!(state.bundle.load().rewrite_ctx.mode, Mode::Direct);
        // Critical: nothing was spawned — otherwise the test runtime
        // would be holding orphan tasks pinning DomainFronter alive.
        assert!(state.mode_tasks.lock().await.is_empty());
    }

    #[tokio::test]
    async fn spawn_mode_tasks_aborts_prior_handles() {
        // Belt-and-braces check on the startup-vs-switch race: if the UI
        // fires SwitchMode between `running = true` and run()'s post-bind
        // task spawn, run() must not silently leak the switch's task
        // handles. spawn_mode_tasks aborts prior entries first.
        let cfg = switch_test_apps_script_config();
        let (state, _tmp) = make_runtime_state(&cfg).await;
        let fronter = state.bundle.load().fronter.clone().expect("apps_script");

        // First pass — populate the bag and grab `AbortHandle`s for
        // every long-lived task in the set. `AbortHandle::is_finished()`
        // reads the same completion bit as `JoinHandle::is_finished`,
        // so it's the right signal to observe whether the next
        // `spawn_mode_tasks` actually aborted each prior handle.
        //
        // Why every task, not just keepalive: `abort_all` / `is_empty`
        // both touch every field on `ModeTasks`, and a refactor that
        // forgets one (e.g. adds a new task field and forgets to wire
        // it into `abort_all`) would silently leak handles on every
        // switch. Earlier this test only captured `keepalive`, and the
        // `health` field was added without test coverage — exactly the
        // shape of bug this regression guard exists to catch.
        let (prior_keepalive, prior_refill, prior_health, prior_probe) = {
            let mut tasks = state.mode_tasks.lock().await;
            spawn_mode_tasks(&mut tasks, fronter.clone(), &cfg);
            let keepalive = tasks
                .keepalive
                .as_ref()
                .expect("keepalive spawned")
                .abort_handle();
            let refill = tasks
                .refill
                .as_ref()
                .expect("refill spawned")
                .abort_handle();
            let health = tasks
                .health
                .as_ref()
                .expect("health spawned")
                .abort_handle();
            let probe = tasks.probe.as_ref().expect("probe spawned").abort_handle();
            (keepalive, refill, health, probe)
        };
        for (name, h) in [
            ("keepalive", &prior_keepalive),
            ("refill", &prior_refill),
            ("health", &prior_health),
            ("probe", &prior_probe),
        ] {
            assert!(
                !h.is_finished(),
                "prior {} should still be running before respawn",
                name,
            );
        }

        // Second pass — must abort the first set.
        {
            let mut tasks = state.mode_tasks.lock().await;
            spawn_mode_tasks(&mut tasks, fronter, &cfg);
        }

        // Tokio's abort is cooperative — yield a few times so the
        // runtime can mark each prior task as finished before we
        // inspect them. Loop bound is generous; in practice one or
        // two yields is enough.
        for (name, h) in [
            ("keepalive", &prior_keepalive),
            ("refill", &prior_refill),
            ("health", &prior_health),
            ("probe", &prior_probe),
        ] {
            for _ in 0..32 {
                if h.is_finished() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(
                h.is_finished(),
                "spawn_mode_tasks must abort the previous {} handle",
                name,
            );
        }

        state.mode_tasks.lock().await.abort_all();
    }

    #[tokio::test]
    async fn run_bind_failure_leaves_no_mode_tasks_running() {
        // Regression guard for the startup ordering: bind must happen
        // BEFORE any spawn_mode_tasks call, so a bind failure returns
        // cleanly with no orphaned keepalive/refill/stats/warm tasks
        // pinging the upstream forever.
        //
        // Force the failure by binding 127.0.0.1:0 ourselves first, then
        // pointing RuntimeState at the same address.
        let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("blocker bind");
        let blocked_addr = blocker.local_addr().expect("local_addr");
        let cfg_json = format!(
            r#"{{
                "mode": "apps_script",
                "auth_key": "secret-test-secret-test",
                "script_id": "X",
                "listen_host": "127.0.0.1",
                "listen_port": {}
            }}"#,
            blocked_addr.port(),
        );
        let cfg: crate::config::Config = serde_json::from_str(&cfg_json).expect("config parse");
        let (state, _tmp) = make_runtime_state(&cfg).await;

        // Pre-condition: no tasks at rest.
        assert!(state.mode_tasks.lock().await.is_empty());

        let (_tx, rx) = tokio::sync::oneshot::channel();
        let result = state.clone().run(rx).await;
        assert!(
            matches!(result, Err(ProxyError::Io(_))),
            "expected Io bind failure, got {:?}",
            result
        );

        // Post-condition: nothing was spawned. Without the bind-first
        // ordering this would observe live keepalive/refill/stats handles
        // (and the test process would still be pinging Apps Script after
        // the test ended).
        assert!(
            state.mode_tasks.lock().await.is_empty(),
            "bind failure must not leak mode tasks",
        );
        // Bundle also should still have no tunnel_mux installed — the
        // startup mux init runs after bind, so a bind failure must not
        // have populated it either.
        assert!(state.bundle.load().tunnel_mux.is_none());
        // Cleanup epilog also flips `stopped` so any post-failure
        // switch_mode bails instead of spawning fresh tasks against a
        // dead listener.
        assert!(state.stopped.load(Ordering::SeqCst));

        drop(blocker);
    }

    #[tokio::test]
    async fn run_bind_failure_after_switch_aborts_switched_in_tasks() {
        // The harder lifecycle race: a `switch_mode` lands BEFORE
        // `run()` reaches `bind`, then bind fails. Without the
        // cleanup epilog on `run()`, the `?` early-return would skip
        // the shutdown arm and leak the switch's spawned mode_tasks
        // forever.
        let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("blocker bind");
        let blocked_port = blocker.local_addr().expect("local_addr").port();

        let cfg_json = format!(
            r#"{{
                "mode": "direct",
                "listen_host": "127.0.0.1",
                "listen_port": {}
            }}"#,
            blocked_port,
        );
        let cfg: crate::config::Config = serde_json::from_str(&cfg_json).expect("config parse");
        let (state, _tmp) = make_runtime_state(&cfg).await;

        // Simulate the UI firing SwitchMode between `running = true`
        // and the spawned `server.run()` reaching its bind call.
        state
            .switch_mode(&switch_test_apps_script_config())
            .await
            .expect("pre-bind switch");
        assert!(
            !state.mode_tasks.lock().await.is_empty(),
            "pre-bind switch should have spawned tasks",
        );

        // Now run() — bind will fail because `blocker` still holds
        // the port. The cleanup epilog must reap the switch's tasks.
        let (_tx, rx) = tokio::sync::oneshot::channel();
        let result = state.clone().run(rx).await;
        assert!(
            matches!(result, Err(ProxyError::Io(_))),
            "expected bind failure, got {:?}",
            result,
        );

        assert!(
            state.mode_tasks.lock().await.is_empty(),
            "run() cleanup epilog must abort the switch's mode tasks",
        );
        assert!(
            state.stopped.load(Ordering::SeqCst),
            "run() cleanup epilog must mark the runtime as stopped",
        );

        // And a subsequent switch_mode is correctly refused.
        let err = state
            .switch_mode(&switch_test_apps_script_config())
            .await
            .expect_err("switch after stopped must bail");
        assert!(matches!(err, ProxyError::ShuttingDown));

        drop(blocker);
    }

    #[tokio::test]
    async fn run_bind_failure_after_full_switch_clears_tunnel_mux() {
        // Full-mode flavour of the bind-failure cleanup contract: a
        // `switch_mode` to Full lands before `run()` reaches `bind`,
        // installing a `TunnelMux`. Bind then fails. The cleanup
        // epilog must clear `tunnel_mux` from the bundle so the
        // `mux_loop` task's mpsc Sender drops and the loop exits —
        // otherwise the loop (and the `Arc<DomainFronter>` it
        // captured) outlive `run()` until the UI releases the
        // `Arc<RuntimeState>` minutes later.
        let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("blocker bind");
        let blocked_port = blocker.local_addr().expect("local_addr").port();

        let cfg_json = format!(
            r#"{{
                "mode": "direct",
                "listen_host": "127.0.0.1",
                "listen_port": {}
            }}"#,
            blocked_port,
        );
        let cfg: crate::config::Config = serde_json::from_str(&cfg_json).expect("config parse");
        let (state, _tmp) = make_runtime_state(&cfg).await;

        // Pre-bind switch into Full → installs TunnelMux + mode tasks.
        state
            .switch_mode(&switch_test_full_config())
            .await
            .expect("pre-bind full switch");
        assert!(
            state.bundle.load().tunnel_mux.is_some(),
            "Full switch must install a TunnelMux before bind",
        );
        assert!(!state.mode_tasks.lock().await.is_empty());

        let (_tx, rx) = tokio::sync::oneshot::channel();
        let result = state.clone().run(rx).await;
        assert!(
            matches!(result, Err(ProxyError::Io(_))),
            "expected bind failure, got {:?}",
            result,
        );

        // Cleanup epilog must drop the mux from the bundle.
        assert!(
            state.bundle.load().tunnel_mux.is_none(),
            "cleanup epilog must clear bundle.tunnel_mux so mux_loop exits",
        );
        assert!(state.mode_tasks.lock().await.is_empty());
        assert!(state.stopped.load(Ordering::SeqCst));

        drop(blocker);
    }

    #[tokio::test]
    async fn concurrent_switch_mode_calls_do_not_leak_or_panic() {
        // The UI now serialises Cmd::SwitchMode via `rt.block_on`, but
        // the lock-based serialisation in `switch_mode` itself is the
        // defence-in-depth for any future caller (or test) that spawns
        // multiple switches concurrently. Spin up several races and
        // assert that (a) every call returns Ok, (b) the final bundle
        // matches one of the requested modes, and (c) mode_tasks
        // contains exactly one fresh set — not several leaked.
        let (state, _tmp) = make_runtime_state(&switch_test_direct_config()).await;

        // 8 switches: 4 → apps_script, 4 → direct. Random-ish ordering
        // via tokio's join_all scheduling.
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let s = state.clone();
            let cfg = if i % 2 == 0 {
                switch_test_apps_script_config()
            } else {
                switch_test_direct_config()
            };
            handles.push(tokio::spawn(async move { s.switch_mode(&cfg).await }));
        }
        for h in handles {
            h.await.expect("join").expect("switch ok");
        }

        // Final mode is whichever one was last to commit under
        // `switch_lock`. Both are valid outcomes — we just want to
        // confirm no torn state or panic.
        let final_mode = state.current_mode();
        assert!(matches!(final_mode, Mode::AppsScript | Mode::Direct));

        // No leaked tasks: either we're in direct (no fronter, empty
        // bag) or we're in apps_script (single fresh fronter, four
        // task handles). Without spawn_mode_tasks's abort_all contract,
        // back-to-back apps_script switches would have stacked four
        // sets of handles in the bag.
        let tasks = state.mode_tasks.lock().await;
        match final_mode {
            Mode::Direct => {
                assert!(tasks.is_empty(), "direct mode should have no tasks");
            }
            Mode::AppsScript => {
                assert!(tasks.keepalive.is_some());
                assert!(tasks.refill.is_some());
                assert!(tasks.stats.is_some());
                assert!(tasks.warm.is_some());
            }
            _ => unreachable!(),
        }
        drop(tasks);
        state.mode_tasks.lock().await.abort_all();
    }

    #[tokio::test]
    async fn run_startup_races_with_switch_mode_apply_under_lock() {
        // Models the UI's startup window: a `switch_mode` lands while
        // `run()` is mid-init. Both serialise under `switch_lock`; the
        // post-bind init block in `run()` then sees `mode_tasks` already
        // populated and skips, leaving the switch's set in place.
        //
        // Without the bind happening first or the `is_empty()` guard,
        // either (a) bind failure leaks the switch's tasks or (b) run()
        // double-spawns and orphans the switch's handles.
        //
        // Reserve TWO ports via 0-port probes, drop, then ask run() to
        // bind both. `socks5_port` defaults to `listen_port + 1`, and
        // an adjacent port is exactly the kind of thing a sibling
        // parallel test in the suite tends to be holding — leaving it
        // implicit would make this test flaky under `cargo test` (the
        // failure mode being `ProxyError::ShuttingDown` from the
        // cleanup epilog firing on a bind-failed `run`). Probe both
        // explicitly so flakes can only come from a genuinely racy
        // co-tenant on the host, not the test suite itself.
        let probe_http = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe http");
        let probe_socks = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe socks");
        let http_port = probe_http.local_addr().expect("http addr").port();
        let socks_port = probe_socks.local_addr().expect("socks addr").port();
        drop(probe_http);
        drop(probe_socks);

        let cfg_json = format!(
            r#"{{
                "mode": "direct",
                "listen_host": "127.0.0.1",
                "listen_port": {},
                "socks5_port": {}
            }}"#,
            http_port, socks_port,
        );
        let cfg: crate::config::Config = serde_json::from_str(&cfg_json).expect("config parse");
        let (state, _tmp) = make_runtime_state(&cfg).await;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let state_run = state.clone();
        let run_handle = tokio::spawn(async move { state_run.run(shutdown_rx).await });

        // Tiny yield so run() at least reaches its first await point;
        // not required for correctness (the lock serialises) but it
        // makes the race more interesting under loom-like exploration.
        tokio::task::yield_now().await;

        // Apply a switch concurrently with run()'s startup-init.
        state
            .switch_mode(&switch_test_apps_script_config())
            .await
            .expect("switch_mode during startup");

        assert_eq!(state.current_mode(), Mode::AppsScript);
        {
            let tasks = state.mode_tasks.lock().await;
            assert!(
                !tasks.is_empty(),
                "switch into apps_script must have spawned tasks",
            );
        }

        // Tear down cleanly.
        let _ = shutdown_tx.send(());
        let run_result = run_handle.await.expect("join run");
        assert!(
            run_result.is_ok(),
            "run() should exit clean: {:?}",
            run_result
        );

        // Cleanup epilog must reap the switch's tasks.
        assert!(
            state.mode_tasks.lock().await.is_empty(),
            "shutdown cleanup must abort the switch's mode_tasks",
        );
        assert!(state.stopped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn switch_fail_then_success_leaves_consistent_state() {
        // Covers the proxy-side half of the UI's "fail-A, succeed-B"
        // sequence: switch_mode must leave the runtime untouched on
        // failure, and a subsequent success must commit cleanly. The
        // UI-side `mode_switch_revert` clearing is plumbed separately
        // (see `Cmd::SwitchMode` Ok-arm); this test pins the underlying
        // state-machine invariant the UI's bookkeeping depends on.
        let (state, _tmp) = make_runtime_state(&switch_test_direct_config()).await;

        // Fail-A: apps_script without script_id → DomainFronter rejects.
        let err = state
            .switch_mode(&switch_test_invalid_apps_script_config())
            .await
            .expect_err("invalid config must fail");
        assert!(matches!(err, ProxyError::Io(_)));
        // Live state unchanged.
        assert_eq!(state.current_mode(), Mode::Direct);
        assert!(state.bundle.load().fronter.is_none());
        assert!(state.mode_tasks.lock().await.is_empty());

        // Succeed-B: valid apps_script.
        state
            .switch_mode(&switch_test_apps_script_config())
            .await
            .expect("valid switch ok");
        assert_eq!(state.current_mode(), Mode::AppsScript);
        assert!(state.bundle.load().fronter.is_some());
        let tasks = state.mode_tasks.lock().await;
        assert!(tasks.keepalive.is_some());
        assert!(tasks.refill.is_some());
        assert!(tasks.stats.is_some());
        assert!(tasks.warm.is_some());
        drop(tasks);

        state.mode_tasks.lock().await.abort_all();
    }

    #[tokio::test]
    async fn switch_mode_picks_up_edited_coalesce_knobs() {
        // Live switches must read coalesce_*_ms from the new config,
        // not from the values captured at startup. Most observable in
        // a switch into Full mode where the new TunnelMux is built
        // with the runtime's current snapshot — without this, a user
        // edits `coalesce_max_ms`, switches to Full, and the mux uses
        // the old value while the form claims the new one is live.
        let mut start_cfg = switch_test_direct_config();
        start_cfg.coalesce_step_ms = 5;
        start_cfg.coalesce_max_ms = 500;
        let (state, _tmp) = make_runtime_state(&start_cfg).await;
        assert_eq!(state.coalesce_step_ms.load(Ordering::Relaxed), 5);
        assert_eq!(state.coalesce_max_ms.load(Ordering::Relaxed), 500);

        // Edited apps_script config with different coalesce values.
        let mut new_cfg = switch_test_apps_script_config();
        new_cfg.coalesce_step_ms = 25;
        new_cfg.coalesce_max_ms = 2500;
        state.switch_mode(&new_cfg).await.expect("switch ok");

        assert_eq!(state.coalesce_step_ms.load(Ordering::Relaxed), 25);
        assert_eq!(state.coalesce_max_ms.load(Ordering::Relaxed), 2500);

        // And `0` falls back to defaults (10 / 1000) — same shape as
        // the original ProxyServer::new used.
        let mut zero_cfg = switch_test_direct_config();
        zero_cfg.coalesce_step_ms = 0;
        zero_cfg.coalesce_max_ms = 0;
        state.switch_mode(&zero_cfg).await.expect("switch back");
        assert_eq!(state.coalesce_step_ms.load(Ordering::Relaxed), 10);
        assert_eq!(state.coalesce_max_ms.load(Ordering::Relaxed), 1000);

        state.mode_tasks.lock().await.abort_all();
    }

    // -------- classify_early_route routing-decision tests --------
    //
    // These pin the dispatcher's pre-socket decisions against the
    // ordering rationale documented on `EarlyRoute`. Pure-function
    // tests, no TcpStream / no real upstream / no ProxyServer —
    // making it easy to add cases as the matrix grows.

    /// `block_doh` is documented as a global policy that fires
    /// regardless of mode. Strict-DoH deployments rely on
    /// `block_doh: true` to keep browser DNS pinned to the
    /// tun2proxy virtual DNS path across mode switches; honouring
    /// it in LocalBypass preserves that contract. Pins the
    /// precedence so a future "let LocalBypass own all routing"
    /// reorder doesn't silently break it.
    #[test]
    fn block_doh_wins_over_local_bypass() {
        let decision = classify_early_route(
            "dns.google",
            443,
            Mode::LocalBypass,
            &[],
            &[],
            /* block_doh = */ true,
            /* bypass_doh = */ false,
        );
        assert_eq!(decision, EarlyRoute::BlockDoh);
    }

    /// `bypass_doh`, on the other hand, is a routing optimisation
    /// (skip-the-relay) that makes no sense in LocalBypass — there
    /// is no relay to skip. LocalBypass's fragmented dial is
    /// strictly more capable than the bypass-to-raw-TCP path it
    /// would otherwise take, so LocalBypass wins this one.
    #[test]
    fn local_bypass_wins_over_bypass_doh() {
        let decision = classify_early_route(
            "cloudflare-dns.com",
            443,
            Mode::LocalBypass,
            &[],
            &[],
            /* block_doh = */ false,
            /* bypass_doh = */ true,
        );
        assert_eq!(decision, EarlyRoute::LocalBypass);
    }

    /// And when both DoH gates are off, LocalBypass owns DoH hosts
    /// the same way it owns any other TLS host — the fragmented
    /// dial handles them. Pins the "every TLS host" guarantee
    /// against the regression of someone accidentally introducing
    /// a `Mode::LocalBypass` exclusion in the DoH matchers.
    #[test]
    fn local_bypass_owns_doh_host_when_no_doh_policy_set() {
        let decision = classify_early_route(
            "dns.google",
            443,
            Mode::LocalBypass,
            &[],
            &[],
            /* block_doh = */ false,
            /* bypass_doh = */ false,
        );
        assert_eq!(decision, EarlyRoute::LocalBypass);
    }

    /// LocalBypass routes any port — not just 443. Pins the
    /// reviewer's "every TLS CONNECT" guarantee against a future
    /// regression where someone re-adds a `port == 443` gate.
    /// (The TLS-vs-non-TLS discrimination happens later, inside
    /// `try_local_bypass_tunnel`'s peek.)
    #[test]
    fn local_bypass_fires_on_non_443_ports() {
        for port in [8443u16, 993, 853, 465, 22222] {
            let decision = classify_early_route(
                "example.com",
                port,
                Mode::LocalBypass,
                &[],
                &[],
                false,
                false,
            );
            assert_eq!(
                decision,
                EarlyRoute::LocalBypass,
                "port {} should route to LocalBypass",
                port
            );
        }
    }

    /// User-configured `passthrough_hosts` beats every other route —
    /// including LocalBypass. This is the escape hatch users tap
    /// when fragmentation latency isn't worth it for a specific
    /// host (e.g. a corporate intranet on the LAN). If LocalBypass
    /// ever ate the passthrough entry, that escape hatch silently
    /// stops working.
    ///
    /// Downstream invariant the dispatcher relies on: the
    /// `PassthroughHostsMatch` arm in `dispatch_tunnel` reads
    /// `rewrite_ctx.upstream_socks5` and passes it to
    /// `plain_tcp_passthrough`, so a `passthrough_hosts` match in
    /// `local_bypass` mode still honours the upstream SOCKS5 proxy.
    /// That split-honouring (fragmentation can't honour upstream,
    /// passthrough still does) is announced via the startup warning
    /// in `build_mode_state`. Test stays at the classifier level
    /// because asserting on `plain_tcp_passthrough`'s arguments
    /// needs end-to-end scaffolding the rest of these tests don't
    /// pull in.
    #[test]
    fn passthrough_hosts_wins_over_local_bypass() {
        let decision = classify_early_route(
            "intranet.corp",
            443,
            Mode::LocalBypass,
            &["intranet.corp".to_string()],
            &[],
            false,
            false,
        );
        assert_eq!(decision, EarlyRoute::PassthroughHostsMatch);
    }

    /// In relay-using modes the existing DoH precedence is unchanged:
    /// block_doh > bypass_doh > Full > Continue. This test pins the
    /// previously-existing behaviour so the refactor (moving the
    /// branches into `classify_early_route`) didn't drift the
    /// relay-mode side of the matrix.
    #[test]
    fn relay_modes_keep_doh_precedence() {
        // block_doh fires for AppsScript+DoH+443.
        let d = classify_early_route("dns.google", 443, Mode::AppsScript, &[], &[], true, false);
        assert_eq!(d, EarlyRoute::BlockDoh);

        // block_doh does NOT fire on non-443 (DoH is HTTPS-only and
        // a non-443 CONNECT to dns.google is something else entirely).
        let d = classify_early_route("dns.google", 853, Mode::AppsScript, &[], &[], true, false);
        assert_eq!(d, EarlyRoute::Continue);

        // bypass_doh fires only when block_doh is off (block wins).
        let d = classify_early_route("dns.google", 443, Mode::AppsScript, &[], &[], false, true);
        assert_eq!(d, EarlyRoute::BypassDoh);

        // Full mode beats Continue for non-DoH hosts; DoH gates still
        // win above Full in this matrix.
        let d = classify_early_route("example.com", 443, Mode::Full, &[], &[], false, false);
        assert_eq!(d, EarlyRoute::Full);
        let d = classify_early_route("dns.google", 443, Mode::Full, &[], &[], true, false);
        assert_eq!(d, EarlyRoute::BlockDoh);
    }

    /// Direct mode keeps falling through — its dispatch logic lives
    /// in the socket-needing tail of `dispatch_tunnel`
    /// (fronting_groups, Google direct fragmentation, SNI rewrite,
    /// raw passthrough). Confirms the classifier doesn't accidentally
    /// short-circuit it.
    #[test]
    fn direct_mode_returns_continue() {
        let d = classify_early_route("example.com", 443, Mode::Direct, &[], &[], false, false);
        assert_eq!(d, EarlyRoute::Continue);
    }

    /// Drive mode short-circuits every TLS CONNECT to the Drive mux
    /// (mirror of Full mode's behaviour, just with a different
    /// transport on the other side of `dispatch_tunnel`).
    #[test]
    fn drive_mode_routes_to_drive() {
        let d = classify_early_route("example.com", 443, Mode::Drive, &[], &[], false, false);
        assert_eq!(d, EarlyRoute::Drive);
        // Non-DoH host on a non-443 port still routes to Drive — the
        // mux is the transport for everything in Drive mode, same as
        // Full. The classifier's port-gates only apply to the global
        // DoH knobs.
        let d = classify_early_route("example.com", 8443, Mode::Drive, &[], &[], false, false);
        assert_eq!(d, EarlyRoute::Drive);
    }

    /// `passthrough_hosts` is documented as the top-priority global
    /// policy — wins over every mode-specific route including Drive.
    /// Pins the precedence so a future reorder of the classifier
    /// doesn't silently break the "I added this host to passthrough,
    /// why does it still go through Drive?" story.
    #[test]
    fn passthrough_hosts_wins_over_drive() {
        let decision = classify_early_route(
            "intranet.corp",
            443,
            Mode::Drive,
            &["intranet.corp".to_string()],
            &[],
            false,
            false,
        );
        assert_eq!(decision, EarlyRoute::PassthroughHostsMatch);
    }

    /// `block_doh` is documented as a global policy ("immediately
    /// reject any CONNECT to a known DoH endpoint"). Survives a
    /// switch to Drive mode for the same reason it survives a switch
    /// to LocalBypass — a strict-DoH deployment relies on it.
    #[test]
    fn block_doh_wins_over_drive() {
        let d = classify_early_route("dns.google", 443, Mode::Drive, &[], &[], true, false);
        assert_eq!(d, EarlyRoute::BlockDoh);
    }

    /// `bypass_doh` sits ABOVE Drive in the precedence: Drive's
    /// shared poller has its own ~hundreds-of-ms RTT floor, so
    /// routing browser-DNS lookups through it would compound the
    /// latency hit `bypass_doh` exists to mitigate. Same precedence
    /// shape as `bypass_doh > Full` for Apps Script Full mode.
    #[test]
    fn bypass_doh_wins_over_drive() {
        let d = classify_early_route("dns.google", 443, Mode::Drive, &[], &[], false, true);
        assert_eq!(d, EarlyRoute::BypassDoh);
        // Non-443 still routes to Drive — bypass_doh is HTTPS-only by
        // construction (matches the port-gate in `classify_early_route`).
        let d = classify_early_route("dns.google", 853, Mode::Drive, &[], &[], false, true);
        assert_eq!(d, EarlyRoute::Drive);
    }

    /// Pins the `Mode::uses_drive_relay` truth table. Same shape as
    /// the `mode_uses_apps_script_relay` / `mode_uses_mitm_ca`
    /// predicate tests elsewhere — adding a new mode should be a
    /// deliberate edit to BOTH the enum and this matrix, not a
    /// silent default. (`uses_drive_relay` is the single source of
    /// truth the config validator and `build_mode_state` defer to.)
    #[test]
    fn mode_uses_drive_relay_predicate() {
        assert!(!Mode::AppsScript.uses_drive_relay());
        assert!(!Mode::Direct.uses_drive_relay());
        assert!(!Mode::Full.uses_drive_relay());
        assert!(!Mode::LocalBypass.uses_drive_relay());
        assert!(Mode::Drive.uses_drive_relay());
    }
}
