use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Read(String, #[source] std::io::Error),
    #[error("failed to parse config json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Operating mode. `AppsScript` is the full client — MITMs TLS locally and
/// relays HTTP/HTTPS through a user-deployed Apps Script endpoint.
/// `Direct` runs without any Apps Script relay: only the SNI-rewrite tunnel
/// is active, targeting the Google edge by default plus any user-configured
/// `fronting_groups`. Originally introduced as a `script.google.com`
/// bootstrap (when this mode could only reach Google's edge it was named
/// `google_only`), now generalized to any user-configured CDN edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    AppsScript,
    /// Was named `GoogleOnly` before v1.9 and the introduction of
    /// `fronting_groups`. The string `"google_only"` is still accepted
    /// in `mode_kind()` as a deprecated alias so existing configs do
    /// not break.
    Direct,
    Full,
    /// Local-only DPI bypass: every TLS CONNECT is dialed straight to
    /// its real destination IP with the browser's real ClientHello
    /// split across TCP segments (the same fragmentation engine
    /// `direct_mode.rs` uses for Google traffic). No Apps Script, no
    /// VPS, no MITM CA install. Defeats DPI-only blocks; cannot help
    /// against IP-level blocks (the destination must still be
    /// reachable from the user's network).
    LocalBypass,
    /// Drive-mailbox transport: every TLS CONNECT
    /// is multiplexed into encrypted frames uploaded as files to a
    /// shared Google Drive folder. A separate `rahgozar-drive-relay`
    /// binary on a VPS the user controls polls the folder, dials the
    /// real destination, and writes response frames back. The Iranian
    /// ISP only sees TLS to `*.google.com` (the same cover Apps Script
    /// mode relies on). Requires `drive.oauth_refresh_token`,
    /// `drive.folder_id`, and `drive.relay_pubkey`. No MITM CA install.
    Drive,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::AppsScript => "apps_script",
            Mode::Direct => "direct",
            Mode::Full => "full",
            Mode::LocalBypass => "local_bypass",
            Mode::Drive => "drive",
        }
    }

    /// True iff this mode talks to the user's Apps Script deployment
    /// (and therefore requires a non-empty `script_id` + `auth_key`).
    /// Single source of truth — UI / config validator / profile-store
    /// allowlists should all defer here rather than open-coding the
    /// `apps_script || full` match, which is the kind of duplicated
    /// allowlist that silently drifts when a new mode lands. The
    /// negation "no relay needed" covers both `direct` (no relay
    /// configured) and `local_bypass` (no relay used) symmetrically.
    pub fn uses_apps_script_relay(self) -> bool {
        matches!(self, Mode::AppsScript | Mode::Full)
    }

    /// True iff this mode terminates inbound TLS with a MITM cert at
    /// any point — i.e. uses the MITM CA on disk for at least one
    /// dispatch path. Separate predicate from
    /// [`uses_apps_script_relay`] because the truth tables differ:
    /// `Direct` uses the MITM CA (SNI-rewrite tunnel, fronting
    /// groups, direct-mode SkipPrefaced fallback) but does NOT use
    /// the relay; `Full` uses the relay but never MITMs (the
    /// dispatcher short-circuits to the tunnel mux before any
    /// MITM logic runs). A naive "negation of one is the other"
    /// would silently install the CA in Full mode and skip it in
    /// Direct — a real regression.
    ///
    /// Used by the CLI startup path (`src/main.rs`) to gate
    /// `install_ca` / `is_ca_trusted` checks, and by the desktop
    /// `StatusTab` / `CaCard` to decide whether to render CA-status
    /// UI. Adding a new mode is a deliberate edit here; the test
    /// `mode_uses_mitm_ca_predicate` pins the truth table.
    pub fn uses_mitm_ca(self) -> bool {
        matches!(self, Mode::AppsScript | Mode::Direct)
    }

    /// True iff this mode tunnels through the Google Drive mailbox
    /// and therefore requires a non-empty
    /// `drive.oauth_refresh_token`, `drive.folder_id`, and
    /// `drive.relay_pubkey`. Single source of truth — same pattern as
    /// [`uses_apps_script_relay`] above; adding a future "Drive +
    /// MITM" hybrid would be a deliberate edit here, and the test
    /// `mode_uses_drive_relay_predicate` pins the truth table.
    ///
    /// Used by the config validator (rejecting Drive mode without
    /// OAuth credentials at load time, not first connect) and by
    /// `proxy_server::build_mode_state` (deciding whether to spawn
    /// the [`crate::drive_client::DriveMux`] background poller).
    pub fn uses_drive_relay(self) -> bool {
        matches!(self, Mode::Drive)
    }
}

impl std::str::FromStr for Mode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "apps_script" => Ok(Mode::AppsScript),
            "direct" => Ok(Mode::Direct),
            // Deprecated alias; see `Mode` docstring and `mode_kind()`.
            "google_only" => Ok(Mode::Direct),
            "full" => Ok(Mode::Full),
            "local_bypass" => Ok(Mode::LocalBypass),
            "drive" => Ok(Mode::Drive),
            other => Err(ConfigError::Invalid(format!(
                "unknown mode '{}' (expected 'apps_script', 'direct', 'full', 'local_bypass', or 'drive')",
                other
            ))),
        }
    }
}

/// One row in the deployment-ID list as serialised. Either a bare
/// string (legacy form — `["A","B"]`) or an object with an enabled
/// flag (new form — `[{"id":"A","enabled":true}]`). Bare strings
/// default to enabled. Hand-edited mixed arrays also load.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ScriptIdEntryWire {
    Bare(String),
    Object {
        id: String,
        #[serde(default = "default_true")]
        enabled: bool,
    },
}

fn default_true() -> bool {
    true
}

impl ScriptIdEntryWire {
    pub fn into_entry(self) -> ScriptIdEntry {
        match self {
            ScriptIdEntryWire::Bare(id) => ScriptIdEntry { id, enabled: true },
            ScriptIdEntryWire::Object { id, enabled } => ScriptIdEntry { id, enabled },
        }
    }
}

/// Canonical in-memory shape: id + enabled flag. The desktop / Android
/// UIs round-trip this directly; the runtime relay consumes only the
/// `enabled == true` subset via `Config::script_ids_resolved()`.
#[derive(Debug, Clone)]
pub struct ScriptIdEntry {
    pub id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ScriptId {
    One(String),
    Many(Vec<ScriptIdEntryWire>),
}

impl ScriptId {
    /// Flatten to canonical entries, preserving on-disk order. Legacy
    /// bare-string rows surface as `enabled: true`.
    pub fn into_entries(self) -> Vec<ScriptIdEntry> {
        match self {
            ScriptId::One(s) => vec![ScriptIdEntry {
                id: s,
                enabled: true,
            }],
            ScriptId::Many(v) => v.into_iter().map(ScriptIdEntryWire::into_entry).collect(),
        }
    }

    /// Enabled-only IDs — what the relay actually rotates through.
    /// Disabled rows are silently dropped here; they only re-appear in
    /// the UI round-trip via `Config::script_id_entries()`.
    pub fn into_vec(self) -> Vec<String> {
        self.into_entries()
            .into_iter()
            .filter(|e| e.enabled)
            .map(|e| e.id)
            .collect()
    }
}

/// Top-level config schema. Every field is `pub` so the Tauri desktop
/// crate (`desktop/src-tauri`) — a separate package that path-deps on
/// this lib via the workspace — can read each one for its `get_config`
/// command and reconcile updates from the Tunnel form. The earlier
/// egui binary lived in this same package so accessibility wasn't a
/// question; now we're across a crate boundary, and a `#[non_exhaustive]`
/// marker (tried once for "future-proofing for downstream consumers")
/// would re-introduce the same E0639 build error there. No external
/// crates depend on us as a library — `rahgozar` isn't published to
/// crates.io — so the `non_exhaustive` annotation buys us nothing
/// real anyway.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: String,
    #[serde(default = "default_google_ip")]
    pub google_ip: String,
    #[serde(default = "default_front_domain")]
    pub front_domain: String,
    #[serde(default)]
    pub script_id: Option<ScriptId>,
    #[serde(default)]
    pub script_ids: Option<ScriptId>,
    #[serde(default)]
    pub auth_key: String,
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub socks5_port: Option<u16>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Hex color (`#RRGGBB`) for INFO lines in the desktop UI's Recent log
    /// panel. Empty string = compiled default green. Per-level colors are
    /// independent so users with red/green colour-blindness can re-pair
    /// any subset.
    #[serde(default = "default_log_color_info")]
    pub log_color_info: String,
    /// Hex color (`#RRGGBB`) for WARN lines in the desktop UI's Recent log
    /// panel. Empty string = compiled default amber.
    #[serde(default = "default_log_color_warn")]
    pub log_color_warn: String,
    /// Hex color (`#RRGGBB`) for ERROR lines in the desktop UI's Recent log
    /// panel. Empty string = compiled default red.
    #[serde(default = "default_log_color_error")]
    pub log_color_error: String,
    #[serde(default = "default_verify_ssl")]
    pub verify_ssl: bool,
    #[serde(default)]
    pub hosts: HashMap<String, String>,
    #[serde(default)]
    pub enable_batching: bool,
    /// Optional upstream SOCKS5 proxy for non-HTTP / raw-TCP traffic
    /// (e.g. `"127.0.0.1:50529"` pointing at a local xray / v2ray instance).
    /// When set, the SOCKS5 listener forwards raw-TCP flows through it
    /// instead of connecting directly. HTTP/HTTPS traffic (which goes
    /// through the Apps Script relay) and SNI-rewrite tunnels are
    /// unaffected.
    #[serde(default)]
    pub upstream_socks5: Option<String>,
    /// Fan-out factor for non-cached relay requests when multiple
    /// `script_id`s are configured. `0` or `1` = off (round-robin, the
    /// default). `2` or more = fire that many Apps Script instances in
    /// parallel per request and return the first successful response —
    /// kills long-tail latency caused by a single slow Apps Script
    /// instance, at the cost of using that much more daily quota.
    /// Value is clamped to the number of available (non-blacklisted)
    /// script IDs.
    #[serde(default)]
    pub parallel_relay: u8,
    /// Adaptive batch coalesce: after each op arrives, wait this many ms
    /// for more ops before firing the batch. Resets on every arrival.
    /// 0 = use compiled default (10ms).
    #[serde(default)]
    pub coalesce_step_ms: u16,
    /// Hard cap on total coalesce wait (ms). 0 = use compiled default (1000ms).
    #[serde(default)]
    pub coalesce_max_ms: u16,
    /// Optional explicit SNI rotation pool for outbound TLS to `google_ip`.
    /// Empty / missing = auto-expand from `front_domain` (current default of
    /// {www, mail, drive, docs, calendar}.google.com). Set to an explicit list
    /// to pick exactly which SNI names get rotated through — useful when one
    /// of the defaults is locally blocked (e.g. mail.google.com in Iran at
    /// various times). Can be tested per-name via the UI or `rahgozar test-sni`.
    #[serde(default)]
    pub sni_hosts: Option<Vec<String>>,
    #[serde(default = "default_fetch_ips_from_api")]
    pub fetch_ips_from_api: bool,

    #[serde(default = "default_max_ips_to_scan")]
    pub max_ips_to_scan: usize,

    #[serde(default = "default_scan_batch_size")]
    pub scan_batch_size: usize,

    #[serde(default = "default_google_ip_validation")]
    pub google_ip_validation: bool,

    /// Background heartbeat for the active `google_ip`. When the current
    /// front IP becomes unreachable mid-session (ISP filter newly applied
    /// to that datacenter range, blackhole, etc.), the relay keeps trying
    /// to open new connections to the dead address until the user
    /// restarts. With heartbeat on, a background task probes
    /// `google_ip:443` every `heartbeat_interval_secs` and, after
    /// `heartbeat_failure_threshold` consecutive failures, runs a fresh
    /// `scan_ips` pass and swaps in the first working candidate. Existing
    /// pool entries are cleared on swap so subsequent opens use the new
    /// IP. Default `true` — the swap is a no-op when the active IP is
    /// healthy, so cost is one cheap TLS handshake per interval.
    #[serde(default = "default_heartbeat_enabled")]
    pub heartbeat_enabled: bool,

    /// Seconds between heartbeat probes of the active `google_ip`.
    /// Default 30 — same cadence NovaProxy uses, balances detection
    /// latency against background-noise traffic.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Consecutive probe failures before the heartbeat triggers a
    /// rescan + IP swap. Default 3 — at the default 30s interval, that's
    /// ~90s of unreachability before action, which filters transient
    /// network blips without leaving the user stuck for long. Set to 1
    /// for fast-fail; higher values for noisy networks.
    ///
    /// `0` is treated as `1` at runtime (with a warning logged on
    /// startup): the literal reading would be "rescan on every probe
    /// failure," which is the same behaviour as `1` once you account
    /// for the comparison being `consecutive_failures >= threshold`.
    /// Not rejected at config validation — a typo here is recoverable
    /// at runtime and shouldn't block startup. See
    /// `DomainFronter::run_ip_health` for the clamp.
    #[serde(default = "default_heartbeat_failure_threshold")]
    pub heartbeat_failure_threshold: u32,

    /// Opt-in: allow `br` and `zstd` in the outbound `Accept-Encoding`
    /// header sent to destinations through Apps Script, and decode
    /// brotli/zstd response bodies on the way back. When `false`
    /// (default) the historical strip-policy applies: br/zstd are
    /// removed from client Accept-Encoding before forwarding, so
    /// destinations only ever respond with gzip/identity (which
    /// `UrlFetchApp` auto-decodes). When `true`, destinations may send
    /// brotli/zstd, rahgozar decodes the body before stripping the
    /// `Content-Encoding` header for browser delivery. Saves bandwidth
    /// on the destination → Apps Script leg for sites whose CDNs prefer
    /// brotli over gzip. Opt-in because `UrlFetchApp`'s exact handling
    /// of non-gzip encodings is empirically derived rather than
    /// documented — flip on, test your sites, report regressions.
    #[serde(default)]
    pub allow_brotli_zstd: bool,
    /// When true, GET requests to `x.com/i/api/graphql/<hash>/<op>?variables=…`
    /// have their query trimmed to just the `variables=` param before being
    /// relayed. The `features` / `fieldToggles` params that X ships with
    /// these requests change frequently and bust the response cache —
    /// stripping them dramatically improves hit rate on Twitter/X browsing.
    ///
    /// Credit: idea from seramo_ir, originally adapted to the Python
    /// MasterHttpRelayVPN by the Persian community
    /// (https://gist.github.com/seramo/0ae9e5d30ac23a73d5eb3bd2710fcd67).
    ///
    /// Off by default — some X endpoints may reject calls that omit
    /// features. Turn on and observe.
    #[serde(default)]
    pub normalize_x_graphql: bool,

    /// Route YouTube traffic through the Apps Script relay instead of
    /// the direct SNI-rewrite tunnel. Ported from upstream Python
    /// `youtube_via_relay` (issue #102).
    ///
    /// Why this exists: when YouTube is SNI-rewritten to `google_ip`
    /// with `SNI=www.google.com`, Google's frontend can enforce
    /// SafeSearch / Restricted Mode based on the SNI → some videos show
    /// as "restricted." Routing through Apps Script bypasses that check
    /// (it hits YouTube from Google's own backend, not via www.google.com
    /// SNI) but introduces the UrlFetchApp User-Agent and quota costs.
    ///
    /// Trade-off: enabling removes SafeSearch-on-SNI, adds `User-Agent:
    /// Google-Apps-Script` header and counts YouTube traffic against
    /// your Apps Script quota. Off by default.
    #[serde(default)]
    pub youtube_via_relay: bool,

    /// URL path prefixes that are forced through the Apps Script relay
    /// (instead of the SNI-rewrite tunnel) — pinned by host AND path,
    /// so only the matching paths burn relay quota while other paths
    /// on the same host stay on the fast SNI-rewrite forward path.
    ///
    /// Format: `host/path/prefix` (no scheme). Hosts here are pulled
    /// out of the built-in SNI-rewrite suffix list so the proxy MITMs
    /// them and can inspect URLs. A request whose URL starts with the
    /// pattern goes through the relay; any other path on the same host
    /// is forwarded over a fresh TLS connection to `google_ip` with
    /// SNI=`front_domain` (i.e. the SNI-rewrite trick at the HTTP
    /// layer instead of the TLS-tunnel layer).
    ///
    /// Default: `youtube.com/youtubei/` is prepended unless
    /// `youtube_via_relay = true` OR `exit_node.mode == "full"` is
    /// active (in which cases YouTube is fully relayed already, so the
    /// per-path filter is redundant — and in exit-node-full the filter
    /// would actively bypass the second hop, so it has to stay off).
    /// User entries are appended to the default in apps_script mode.
    ///
    /// **Cannot disable the default by setting an empty list**:
    /// `#[serde(default)]` collapses an omitted key and an explicit
    /// `[]` to the same `Vec::new()`, so the default is always
    /// prepended whenever the gate above doesn't suppress it. To turn
    /// off the YouTube path filter entirely, flip `youtube_via_relay
    /// = true` (full YT relay, redundant filter) or run in `direct` /
    /// `full` mode (no apps_script path → no filter).
    ///
    /// Why this exists: YouTube's in-page RPC at `/youtubei/v1/...`
    /// is where SafeSearch / live-video gating decisions are made.
    /// Pre-port, the only fix was `youtube_via_relay = true`, which
    /// burnt Apps Script quota on every static asset. Path-pinning
    /// the relay to `/youtubei/` recovers the SafeSearch fix at ~1%
    /// of the quota cost. Ported from upstream `RELAY_URL_PATTERNS` /
    /// `relay_url_patterns` (commit b3b9220).
    #[serde(default)]
    pub relay_url_patterns: Vec<String>,

    /// Strip surplus SABR quality-track entries (top-level field-3 of
    /// the segment-fetch protobuf) from `/videoplayback` POST bodies on
    /// `*.googlevideo.com` / `*.youtube.com`. **Default `false` —
    /// opt-in.** The original use case was fixing "Response too large"
    /// 502s on multi-track segment fetches that exceed Apps Script
    /// `UrlFetchApp`'s ~10 MB cap (commits 9b6d03e + 33db28a from
    /// upstream Python).
    ///
    /// **Why off by default** (#977 testing, unacoder, May 2026):
    /// stripping field-3 entries broke video playback in the field
    /// across two iterations of the heuristic. The strip-all variant
    /// produced empty googlevideo responses on single-track requests
    /// (player retried indefinitely with `rn=` incrementing); the
    /// keep-first refinement still broke playback even on single-track
    /// 1080p60 default-config tests. The most plausible explanation is
    /// that field-3 entries aren't homogeneous quality-track selectors
    /// — they likely encode multiple request facets (audio/video
    /// tracks, init-segment refs) and stripping any of them produces
    /// responses the player can't splice into its buffer. Without a
    /// captured `/videoplayback` request body and proto reflection we
    /// can't design a correct heuristic, so default-off ships safe
    /// behaviour for the unbroken-playback common case.
    ///
    /// **When to flip on**: if you specifically hit "Response too
    /// large" 502s on long-form videos at high quality (1080p+ on
    /// long playlists is the usual case). The opt-in behaviour uses
    /// the keep-first heuristic — strictly less aggressive than
    /// upstream's strip-all, so it's the safer of the two flavours.
    /// Accept that some videos may still not play correctly with the
    /// strip on; you're trading "occasional 502s" for "occasional
    /// broken segments." Most users should leave this off.
    #[serde(default = "default_sabr_strip")]
    pub sabr_strip: bool,

    /// User-configurable passthrough list. Any host whose name matches
    /// one of these entries bypasses the Apps Script relay entirely and
    /// is plain-TCP-passthroughed (optionally through `upstream_socks5`).
    ///
    /// Accepts exact hostnames ("example.com") and leading-dot suffixes
    /// (".internal.example" matches "a.b.internal.example"). Matches are
    /// case-insensitive.
    ///
    /// Dispatched BEFORE SNI-rewrite and Apps Script, so a passthrough
    /// entry wins over the default Google-edge routing. Useful for
    /// sites where you already have reachability without the relay
    /// (saving Apps Script quota) or for hosts that break under MITM.
    ///
    /// Issues #39, #127.
    #[serde(default)]
    pub passthrough_hosts: Vec<String>,

    /// Block outbound QUIC (UDP/443) at the SOCKS5 listener.
    ///
    /// QUIC is HTTP/3-over-UDP. In `apps_script` mode it's hopeless —
    /// Apps Script is HTTP-only, so QUIC datagrams either get refused
    /// outright (UDP ASSOCIATE rejected) or silently fall through to
    /// `raw-tcp direct` and fail in interesting ways. In `full` mode
    /// the tunnel-node CAN carry UDP, but QUIC's congestion control
    /// stacked on top of TCP-encapsulated transport produces TCP
    /// meltdown for any non-trivial bandwidth — browsers see <1 Mbps
    /// where the same site over plain HTTPS would do >50.
    ///
    /// With `block_quic = true`, the SOCKS5 UDP relay drops any
    /// datagram destined for port 443 (silent UDP — caller's stack
    /// retries a few times then falls back). Browsers then re-issue
    /// the same request as TCP/HTTPS through the regular CONNECT
    /// path, which goes through the relay normally.
    ///
    /// Why this is opt-in rather than always-on: for users on Full
    /// mode + udpgw (a recent path; v1.7.0+) the QUIC TCP-meltdown
    /// is partially mitigated by udpgw's persistent-socket reuse,
    /// and a tiny minority of sites only support HTTP/3 (rare). The
    /// flag lets users who care about consistency over peak speed
    /// opt out of QUIC at the source rather than discovering its
    /// failure modes later. Issue #213.
    #[serde(default = "default_block_quic")]
    pub block_quic: bool,

    /// Block STUN/TURN UDP ports (3478, 5349, 19302) at the SOCKS5 listener.
    /// Forces WebRTC apps (Google Meet, Discord, WhatsApp) to fall back to
    /// TCP TURN on port 443, skipping the 10-30s UDP ICE timeout. Default
    /// true — TCP fallback works for all tested apps and connects instantly.
    #[serde(default = "default_block_stun")]
    pub block_stun: bool,
    /// When true, suppress the random `_pad` field that v1.8.0+ adds
    /// to outbound Apps Script requests for DPI evasion. Default off
    /// (padding active). Some users on heavily-throttled ISPs find
    /// the +25% bandwidth cost from padding compounds with the
    /// throttle to push borderline-working batches into timeouts;
    /// turning padding off recovers a bit of headroom at the cost of
    /// length-distribution defense against DPI fingerprinting. Issue
    /// #391 (EBRAHIM-AM).
    ///
    /// Don't flip this on speculatively — for users where Apps Script
    /// outbound is uncongested, padding is free DPI defense. Only
    /// turn off if you've measured throughput improvement after the
    /// flip on your specific ISP path.
    #[serde(default)]
    pub disable_padding: bool,

    /// Disable HTTP/2 multiplexing on the Apps Script relay leg.
    /// Default `false` (= h2 enabled): the TLS handshake to the Google
    /// edge advertises ALPN `["h2", "http/1.1"]`; if the server picks
    /// h2 we route all relay traffic over a single multiplexed
    /// connection (~100 concurrent streams) instead of the legacy
    /// per-request TLS pool of 8-80 sockets. Kills head-of-line
    /// blocking on slow Apps Script responses (one stalled call no
    /// longer pins a whole socket). Set to `true` to force the
    /// pre-v1.9.x HTTP/1.1 path — useful as a kill switch if a specific
    /// deployment, fronting domain, or middlebox refuses h2.
    #[serde(default)]
    pub force_http1: bool,

    /// Opt-out for the DoH bypass. Default `false` (= bypass active):
    /// CONNECTs to well-known DoH hostnames (Cloudflare, Google, Quad9,
    /// AdGuard, NextDNS, OpenDNS, browser-pinned variants like
    /// `chrome.cloudflare-dns.com` and `mozilla.cloudflare-dns.com`)
    /// skip the Apps Script tunnel and exit via plain TCP (or
    /// `upstream_socks5` if set). DoH already encrypts the queries
    /// themselves, so the only privacy property the tunnel was adding
    /// is hiding *the fact that you're doing DoH* from the local
    /// network — a marginal gain not worth the ~2 s Apps Script
    /// round-trip cost paid on every name lookup. In Full mode this
    /// was the dominant DNS slowdown source.
    ///
    /// Set `tunnel_doh: false` to enable the bypass and let DoH go
    /// direct (saves the ~2 s Apps Script round-trip per name on
    /// networks where the DoH endpoints are reachable). With the
    /// bypass off, browsers that find their pinned DoH host
    /// unreachable already fall back to OS DNS on their own, so
    /// failure modes are graceful in either direction.
    ///
    /// **Default flipped to `true` in v1.9.0** (issue #468). The
    /// previous default (`false` = bypass active) silently broke for
    /// Iranian users because Iran ISPs filter direct connections to
    /// `dns.google`, `chrome.cloudflare-dns.com`, etc. — exactly the
    /// "pinned DoH" hosts that the bypass was sending through. The
    /// safe default keeps DoH inside the tunnel; users on networks
    /// where direct DoH works can opt back into the bypass.
    ///
    /// Port-gated to TCP/443 only. A private DoH on a non-standard port
    /// (e.g. `doh.internal.example:8443`) won't take the bypass path —
    /// list it in `passthrough_hosts` instead, which has no port gate.
    #[serde(default = "default_tunnel_doh")]
    pub tunnel_doh: bool,

    /// Extra hostnames to treat as DoH endpoints in addition to the
    /// built-in default list. Case-insensitive; entries match exactly
    /// OR as a dot-anchored suffix unconditionally — `doh.acme.test`
    /// covers both `doh.acme.test` and `tenant.doh.acme.test`. (Unlike
    /// `passthrough_hosts`, no leading dot is required for suffix
    /// matching: every legitimate subdomain of a DoH host is itself
    /// a DoH endpoint, so the leading-dot convention would be a
    /// footgun.) Use this to cover private/enterprise DoH resolvers
    /// without waiting for a release.
    ///
    /// Inert when `tunnel_doh = true` — the bypass itself is off, so
    /// the extras have nothing to feed. The proxy logs a warning at
    /// startup if both are set together.
    #[serde(default)]
    pub bypass_doh_hosts: Vec<String>,

    /// When true, immediately reject (close) any CONNECT to a known DoH
    /// endpoint. Takes priority over `tunnel_doh` — the connection is
    /// never established in either direction. Browsers fall back to system
    /// DNS, which tun2proxy handles via virtual DNS (instant, no tunnel
    /// round-trip). This eliminates the ~1.5s per-domain DoH overhead
    /// that #468's `tunnel_doh: true` default introduced.
    ///
    /// Background: #468 changed `tunnel_doh` from false (bypass) to true
    /// (tunnel) because Iranian ISPs block direct DoH endpoints. But
    /// tunneling DoH costs an extra ~1.5s Apps Script round-trip per DNS
    /// lookup, which made every page load noticeably slower. Blocking
    /// DoH entirely avoids both problems: no ISP-visible DoH connection,
    /// no tunnel round-trip — browsers use the system DNS path instead.
    ///
    /// Default `true` (NOT `bool::default() = false`). Critical for
    /// upgrading users — see #773: with the v1.9.13 default-derive bug,
    /// existing configs got `block_doh = false` paired with `tunnel_doh
    /// = true` (the new tunnel-DoH default from #468), routing every
    /// browser DNS lookup through Apps Script and adding ~1.5s per page
    /// load. The named-default function fixes the upgrade path so the
    /// fast block-then-system-DNS behaviour is what users actually get.
    #[serde(default = "default_block_doh")]
    pub block_doh: bool,

    /// Multi-edge domain-fronting groups. Each group is a triple of
    /// (edge IP, front SNI, member domains): when a CONNECT to one of
    /// the member domains arrives, the proxy MITMs at the local CA
    /// then re-encrypts upstream against `ip` with `sni` as the TLS
    /// SNI — same trick we already do for `google_ip` + `front_domain`,
    /// but generalised so users can target Vercel's edge (sni=react.dev,
    /// fronting vercel.com / vercel.app / nextjs.org / ...) or Fastly's
    /// (sni=www.python.org, fronting reddit.com / githubassets.com / ...)
    /// directly without burning Apps Script quota or relying on the
    /// Google edge for non-Google traffic.
    ///
    /// The cert returned by the upstream is validated against `sni` by
    /// rustls as normal — no custom SAN-allowlist needed, the front SNI
    /// must itself be a real domain hosted by the same edge as the
    /// targets. Picking the right (ip, sni) pair is on the user; see
    /// `docs/fronting-groups.md` for the recipe.
    ///
    /// Group match wins over the built-in Google SNI-rewrite suffix list
    /// but loses to `passthrough_hosts` (explicit user opt-out wins) and
    /// to the DoH bypass. Empty / missing = feature off.
    #[serde(default)]
    pub fronting_groups: Vec<FrontingGroup>,

    /// TLS-fragmentation Direct Mode for Google-owned domains. When
    /// enabled, Google-edge-served traffic skips both the Apps Script
    /// relay AND the MITM SNI-rewrite path: the browser's real TLS
    /// ClientHello is forwarded to Google directly, split into N TCP
    /// segments so DPI can't reassemble the SNI. No MITM cert needed
    /// for Google traffic, no Apps Script quota burn for Gmail / Drive
    /// / Maps / YouTube / etc.
    ///
    /// On total dial failure, traffic falls back to the existing
    /// SNI-rewrite tunnel — so existing setups keep working even on
    /// networks where fragmentation alone doesn't beat DPI.
    ///
    /// Ported from zyrln (https://github.com/ajavadinezhad/zyrln).
    #[serde(default)]
    pub direct_mode: DirectModeConfig,

    /// Auto-blacklist tuning — how many timeouts within the window
    /// trip a per-deployment cooldown.
    ///
    /// Default `3` matches the historical behavior. Single-deployment
    /// users who hit transient network blips have reported (#391, #444)
    /// that 3 strikes are too few — one cold-start stall plus two
    /// network glitches lock out their only relay path. Bumping to
    /// `5` or `6` is a reasonable workaround for that case.
    ///
    /// Multi-deployment users with 10+ healthy alternatives can lower
    /// this (e.g. `2`) to fail-fast off a flaky deployment without
    /// burning latency on retries.
    #[serde(default = "default_auto_blacklist_strikes")]
    pub auto_blacklist_strikes: u32,

    /// Window (seconds) for the auto-blacklist strike counter. Strikes
    /// older than this are dropped. Default `30`. Larger windows make
    /// the heuristic less twitchy at the cost of holding state longer
    /// for deployments that have already recovered.
    #[serde(default = "default_auto_blacklist_window_secs")]
    pub auto_blacklist_window_secs: u64,

    /// Cooldown (seconds) when the strike threshold trips. Default
    /// `120`. Single-deployment users who can't afford a 2-min lockout
    /// when their only relay misbehaves can drop to `30` or `60`. Multi-
    /// deployment users with healthy alternatives can extend to `600`
    /// to keep a known-bad deployment out of rotation longer.
    #[serde(default = "default_auto_blacklist_cooldown_secs")]
    pub auto_blacklist_cooldown_secs: u64,

    /// Per-batch HTTP round-trip timeout (seconds). Default `30` —
    /// matches Apps Script's typical response cliff and historical
    /// `BATCH_TIMEOUT` constant. Slow Iran ISP networks may want `45`
    /// or `60` to give Apps Script time to respond past throttle
    /// windows. Networks with fail-fast preference may want `15` to
    /// retry sooner when a deployment hangs. Floor `5`, ceiling `300`
    /// (anything beyond exceeds Apps Script's hard 6-min cap with
    /// no benefit).
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,

    /// Language code appended to Apps Script `/macros/s/<sid>/exec` calls
    /// as `?hl=<lang>` and paired with `Accept-Language` on the relay
    /// POST. Default `"en"` forces Google's frontend error pages and
    /// quota/auth/deploy envelope strings into English so the
    /// [`envelope error classifier`](`looks_like_quota_error` and
    /// friends) can pattern-match them reliably regardless of the user's
    /// browser locale. Change only if you specifically want non-English
    /// Apps Script error pages for debugging — the classifier patterns
    /// are English-only, so any other value disables auth/deploy/admin
    /// auto-blacklisting (quota still works because the German strings
    /// are explicitly listed). Ported from upstream Python `apps_script_lang`
    /// (commit 00edfe9).
    #[serde(default = "default_apps_script_lang")]
    pub apps_script_lang: String,

    /// Verbatim JSON for any config.json key this build doesn't model
    /// (e.g. fields shipped by a newer build of the desktop UI, or
    /// keys hand-edited by the user that haven't graduated to a real
    /// field yet). Captured here via `#[serde(flatten)]` so unknown
    /// fields round-trip cleanly through load → UI form → save
    /// instead of being silently dropped.
    ///
    /// The profile-storage layer in `src/profiles.rs` promises raw
    /// snapshot preservation; the on-disk snapshot is the same
    /// `config.json` contents, so any field that makes it through
    /// this map will also survive a Save-as-profile / Switch round
    /// trip.
    ///
    /// Order matters: `#[serde(flatten)]` must come BEFORE
    /// `exit_node` so unknown keys collect into the map rather than
    /// being claimed by it. (`flatten` on a HashMap absorbs every
    /// not-already-named field.)
    #[serde(flatten, default)]
    pub extras: std::collections::BTreeMap<String, serde_json::Value>,

    /// Optional second-hop exit node, for sites that block traffic
    /// from Google datacenter IPs (Apps Script's outbound IP space).
    /// Most visibly: Cloudflare-fronted services that flag the GCP IP
    /// block as bots — ChatGPT (chatgpt.com), Claude (claude.ai),
    /// Grok (grok.com / x.com), and a long tail of CF-protected SaaS.
    ///
    /// Architecture: chain becomes
    ///   `client → SNI rewrite → Apps Script (Google IP) → exit node
    ///    (Deno Deploy / fly.io / etc., non-Google IP) → destination`
    ///
    /// The destination sees the exit node's outbound IP, not Google's.
    /// CF anti-bot's "this is a Google datacenter" heuristic doesn't
    /// fire. rahgozar's DPI cover (Iran ISP only sees the SNI-rewritten
    /// TLS to a Google IP) is unchanged — the second hop happens
    /// inside Apps Script, invisible from the user's network.
    ///
    /// Setup walkthrough at `assets/exit_node/README.md`. Default off.
    #[serde(default)]
    pub exit_node: ExitNodeConfig,

    /// Configuration for Drive-mailbox transport (mode=`drive`). Only
    /// the three credential fields (`oauth_refresh_token`, `folder_id`,
    /// `relay_pubkey`) are required; the poll/concurrency knobs have
    /// sensible defaults. See [`DriveConfig`] for the per-field rules.
    /// Setup walkthrough lands at `docs/drive_mode.md` once the
    /// transport ships.
    #[serde(default)]
    pub drive: DriveConfig,
}

/// Configuration for the optional second-hop exit node.
///
/// Same `#[non_exhaustive]` rationale as `Config` — the exit-node
/// feature is still maturing (host lists, mode strings, retry knobs are
/// all places future fields are likely to land), so cross-crate
/// consumers should round-trip through serde rather than struct literal.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ExitNodeConfig {
    /// Master switch. Default false. Even with `relay_url` and `psk`
    /// set, nothing routes through the exit node unless this is true.
    #[serde(default)]
    pub enabled: bool,

    /// HTTPS URL of the exit-node endpoint. Typically a Deno Deploy /
    /// fly.io serverless deployment (or your own VPS) running the
    /// `assets/exit_node/exit_node.ts` script (or an equivalent). The
    /// exit node is what makes the outbound `fetch()` call to the
    /// destination, so its IP is what the destination sees.
    #[serde(default)]
    pub relay_url: String,

    /// Pre-shared key — must match the `PSK` constant in the exit-node
    /// script. Without a matching PSK the exit node refuses the request
    /// (401). The PSK is what keeps the exit node from being usable as
    /// an open proxy by anyone who learns its URL. Treat like a
    /// password: do not commit, rotate if leaked. Generate with
    /// `openssl rand -hex 32`.
    #[serde(default)]
    pub psk: String,

    /// `"selective"` (default): only hosts in `hosts` go through the
    /// exit node; everything else takes the regular Apps Script path.
    /// Recommended — the exit-node hop adds ~200-500 ms per request,
    /// so reserve it for sites that need a non-Google IP.
    ///
    /// `"full"`: every request goes through the exit node. Useful only
    /// when the entire workload is CF-anti-bot affected, or when the
    /// exit node happens to be faster than Apps Script alone for the
    /// user's network path (rare but possible on very slow ISPs).
    #[serde(default = "default_exit_node_mode")]
    pub mode: String,

    /// In `"selective"` mode, the list of destination hostnames that
    /// route through the exit node. Matches exactly OR as a
    /// dot-anchored suffix, mirroring `passthrough_hosts` semantics:
    /// `"chatgpt.com"` covers `chatgpt.com` and `api.chatgpt.com` and
    /// `auth.chatgpt.com` etc. Leading dots are stripped at load.
    ///
    /// The recurring CF-anti-bot list from community reports:
    /// `chatgpt.com`, `claude.ai`, `x.com`, `grok.com`. Extend for
    /// any other CF-blocked sites you need.
    #[serde(default)]
    pub hosts: Vec<String>,
}

fn default_exit_node_mode() -> String {
    "selective".into()
}

/// Configuration for the Drive-mailbox transport (`mode = "drive"`).
///
/// Architecture: every TLS CONNECT is multiplexed into encrypted
/// frames uploaded as files to the shared `folder_id`; a separate
/// `rahgozar-drive-relay` binary on a VPS abroad polls the folder,
/// dials the real destination, and writes response frames back.
/// Both ends authenticate to the same Google account via OAuth
/// (`drive.file` scope only — the app sees only files it creates,
/// not the user's whole Drive). The relay's long-lived X25519 public
/// key (`relay_pubkey`) is published out-of-band by
/// `rahgozar-drive-relay keygen`.
///
/// `#[non_exhaustive]` rationale matches `ExitNodeConfig` — the
/// transport is still maturing and cross-crate consumers should
/// round-trip via serde rather than struct literals.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct DriveConfig {
    /// OAuth 2.0 client_id from the user's own Google Cloud project.
    /// rahgozar is **BYO ("bring your own") OAuth**: every user
    /// registers their own installed-app OAuth client in Google Cloud
    /// Console (see `docs/drive_oauth_setup.md` for the walkthrough)
    /// and pastes the credentials here. Rationale: an unverified
    /// OAuth client has a 100-user cap on the `drive.file` scope —
    /// BYO sidesteps it entirely because every user gets their own
    /// 100 they never hit. Required for `mode=drive`; `validate()`
    /// rejects an empty value with a pointer to the setup guide.
    #[serde(default)]
    pub oauth_client_id: String,

    /// OAuth 2.0 client_secret paired with [`Self::oauth_client_id`].
    /// Per RFC 8252 §8.6 this is not actually secret for installed
    /// apps (anyone with the binary can extract it), but Google's
    /// token endpoint still requires it. Treated as a credential at
    /// rest — stored plaintext alongside `oauth_refresh_token` and
    /// `exit_node.psk`. Required for `mode=drive`.
    #[serde(default)]
    pub oauth_client_secret: String,

    /// OAuth 2.0 refresh token for the Drive API. Obtained via the
    /// PKCE installed-app flow (desktop / Android Tauri command) or
    /// the RFC 8628 device-code flow (OpenWRT / headless), running
    /// against the user-supplied [`Self::oauth_client_id`] +
    /// [`Self::oauth_client_secret`]. Stored plaintext alongside
    /// `auth_key` and `exit_node.psk` — the `drive.file` scope
    /// limits exposure to files this OAuth client itself created.
    /// Documented trade-off in `docs/drive_mode.md`.
    #[serde(default)]
    pub oauth_refresh_token: String,

    /// Drive folder ID (the bare ID, not a URL — what
    /// `files.create(mimeType=application/vnd.google-apps.folder)`
    /// returns). Both client and relay must use the same folder ID;
    /// session-isolation happens via the per-frame `sid` prefix in
    /// the filename grammar, not via per-session folders.
    #[serde(default)]
    pub folder_id: String,

    /// Relay's long-lived X25519 public key, bech32m-encoded (HRP
    /// `rgdr1...`, ~63 chars). Printed by `rahgozar-drive-relay
    /// keygen` on the VPS; user pastes into the client UI. Bech32m
    /// has a checksum so a one-character typo fails the parser
    /// cleanly instead of silently producing a Diffie-Hellman with
    /// the wrong peer.
    #[serde(default)]
    pub relay_pubkey: String,

    /// Baseline poll interval (milliseconds) for the shared Drive
    /// `files.list` poller. The poller adapts: drops to a faster
    /// floor after a non-empty batch (pipelining), ramps up after
    /// consecutive empty polls (idle), so this is the *floor*
    /// during active traffic plus the starting tick for an idle
    /// session. Default 300 — keeps the poller well under Drive's
    /// 10 QPS sustained budget while leaving headroom for upload /
    /// download / delete calls on the same account.
    #[serde(default = "default_drive_poll_interval_ms")]
    pub poll_interval_ms: u32,

    /// Maximum concurrent file uploads / downloads kept in flight by
    /// the shared poller's worker pool. Bounded so a burst of inbound
    /// files can't blow past Drive's per-user QPS quota — at the
    /// default 8 plus the poll cost, the steady-state ceiling is
    /// ~9 QPS, comfortably below 10. Bump only if you understand
    /// how it interacts with `poll_interval_ms`.
    #[serde(default = "default_drive_max_concurrent_uploads")]
    pub max_concurrent_uploads: u8,
}

fn default_drive_poll_interval_ms() -> u32 {
    300
}

fn default_drive_max_concurrent_uploads() -> u8 {
    8
}

impl Default for DriveConfig {
    /// Match the deserialize-from-`{}` shape. A `#[derive(Default)]`
    /// would emit `u32::default() = 0` for the tuning knobs, which is
    /// then rejected by `Config::validate` ("poll_interval_ms must be
    /// > 0") with a confusing error message the moment the user tries
    /// to switch into Drive mode — the parent's `#[serde(default)]`
    /// on the `drive` field calls THIS impl, not the per-field
    /// `#[serde(default = "...")]` annotations (those only fire on
    /// missing-field deserialization). Same defaults as the per-field
    /// annotations so a missing-section JSON and an empty-section
    /// `{"drive":{}}` JSON produce identical configs.
    fn default() -> Self {
        Self {
            oauth_client_id: String::new(),
            oauth_client_secret: String::new(),
            oauth_refresh_token: String::new(),
            folder_id: String::new(),
            relay_pubkey: String::new(),
            poll_interval_ms: default_drive_poll_interval_ms(),
            max_concurrent_uploads: default_drive_max_concurrent_uploads(),
        }
    }
}

/// Configuration for the TLS-fragmentation Direct Mode (port of zyrln's
/// `relay/core/direct.go`). Defaults to enabled with the upstream
/// suffix list — set `enabled: false` to disable.
///
/// `fronts` / `google_domains` / `sanctioned_domains` are exposed only
/// so users on unusual networks can override (e.g. add a corporate
/// Google domain, or replace the front list with `clients4.google.com`
/// if `www.google.com` is somehow blocked). Empty → use built-in
/// defaults from `direct_mode.rs`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectModeConfig {
    /// Master switch. Default `true`. Even with the feature on, only
    /// hosts matching `google_domains` (and not on `sanctioned_domains`)
    /// take this path; everything else routes as before.
    #[serde(default = "default_direct_mode_enabled")]
    pub enabled: bool,

    /// Front hostnames for the TCP dial — the browser's ClientHello
    /// still carries the real SNI, this is just where we open the
    /// socket. Both must resolve to a Google edge that serves Google
    /// certs. Empty → built-in `["www.google.com", "script.google.com"]`.
    #[serde(default)]
    pub fronts: Vec<String>,

    /// Suffix list of Google-edge-served domains that should use Direct
    /// Mode. Each entry matches the bare apex (`google.com`) and any
    /// subdomain (`mail.google.com`). Empty → bundled default in
    /// `src/direct_mode.rs::DEFAULT_GOOGLE_DOMAINS` (14 suffixes
    /// covering google.com / googleapis.com / gstatic.com / youtube
    /// family / etc., constrained to the intersection with
    /// `SNI_REWRITE_SUFFIXES` so the dial-failure fallback path is
    /// always safe).
    #[serde(default)]
    pub google_domains: Vec<String>,

    /// Domains that route via the Apps Script relay even when Direct
    /// Mode is enabled — needed for services that Google geo-blocks
    /// from Iranian IPs (Gemini, AI Studio, Bard, Labs). Subdomains
    /// inherit the exclusion. Empty → built-in 5-entry list.
    #[serde(default)]
    pub sanctioned_domains: Vec<String>,
}

impl Default for DirectModeConfig {
    fn default() -> Self {
        Self {
            enabled: default_direct_mode_enabled(),
            fronts: Vec::new(),
            google_domains: Vec::new(),
            sanctioned_domains: Vec::new(),
        }
    }
}

fn default_direct_mode_enabled() -> bool {
    true
}

/// One multi-edge fronting group. Edge CDNs like Vercel and Fastly
/// host hundreds of tenants behind a single set of edge IPs and use
/// the inner HTTP `Host` header (after TLS handshake) to dispatch to
/// the right backend. Pick one neutral domain hosted on the same edge
/// as `sni`; the cert it serves will be valid for that name (rustls
/// validates against `sni`, not against the inner `Host`), and the
/// edge will route based on the `Host` header.
/// `skip_serializing_if` predicate for `bool` fields that default false —
/// keeps the serialized config clean (omit when false) and reads clearer
/// than an inline `std::ops::Not::not` path.
fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrontingGroup {
    /// Human-readable name used in log lines. Free-form; uniqueness not
    /// enforced but recommended.
    pub name: String,
    /// Edge IP to dial in the pinned-front model (`force_ip = false`). A
    /// single IP for now — most edges have many but one is enough to
    /// validate the technique. **Ignored when `force_ip = true`**: in
    /// that mode the destination's own IP is resolved per-connection
    /// (via DoH), so `ip` may be left empty.
    #[serde(default)]
    pub ip: String,
    /// SNI to send on the outbound TLS handshake.
    ///
    /// - Pinned-front model (`force_ip = false`): must be a real domain
    ///   served by the same edge as `domains`, otherwise the edge will
    ///   either refuse the handshake or serve a default page that 404s
    ///   the inner Host. Examples: `react.dev` for Vercel, `www.python.org`
    ///   for Fastly. The cert is verified against this name.
    /// - Camouflage model (`force_ip = true`): a *fake* benign host used
    ///   only to blind on-path SNI DPI (e.g. `www.microsoft.com` for
    ///   Meta, `www.google.com` for googlevideo). The cert is NOT verified
    ///   against this name — see `verify_names`.
    pub sni: String,
    /// Member domain list. Matching is case-insensitive: an entry
    /// matches the host exactly OR as an unconditional dot-anchored
    /// suffix (`vercel.com` matches `app.vercel.com` too). Same shape
    /// as the DoH host list.
    ///
    /// Canonical form for matching is lowercase and trailing-dot
    /// trimmed; entries are normalized to that form once at proxy
    /// startup. The on-disk representation is preserved as written
    /// (we don't mutate the user's config), so `Vercel.com.` and
    /// `vercel.com` both work — the matcher is the source of truth
    /// for equality.
    pub domains: Vec<String>,
    /// **Camouflage mode.** When true, the proxy dials the destination's
    /// *own* IP (resolved out-of-band via poison-safe DoH) instead of the
    /// pinned `ip`, sends the fake `sni` purely to blind DPI, and verifies
    /// the peer cert against `verify_names` (the destination's real
    /// names) rather than `sni`. This is patterniha's `ForceIP` +
    /// `verifyPeerCertByName` technique — required for destinations with
    /// no frontable shared edge (Google video / EVA edge, Meta). Default
    /// `false` (the original pinned-front behaviour).
    #[serde(default, skip_serializing_if = "is_false")]
    pub force_ip: bool,
    /// Extra cert names accepted in camouflage mode (`force_ip = true`),
    /// *in addition to* the real per-request destination host (which is
    /// always accepted — correct for arbitrary subdomains like
    /// `scontent-x.cdninstagram.com`). Pin the decoy SNI's own name here
    /// when an edge returns a cert matching the SNI you sent rather than
    /// the inner Host — e.g. Google's GFE answers a `www.google.com`-SNI
    /// handshake with a `www.google.com` cert, so the curated
    /// `youtube-web` / `google-video` groups pin `www.google.com` and
    /// `meta` pins `www.microsoft.com` (mirrors patterniha's
    /// `verifyPeerCertByName`). Every entry must be a name owned by the
    /// legitimate destination or decoy provider — a censor can't forge any
    /// valid public cert, so this stays fail-closed. Empty = accept only
    /// the real host. Ignored when `force_ip = false`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verify_names: Vec<String>,
}

fn default_fetch_ips_from_api() -> bool {
    false
}
fn default_max_ips_to_scan() -> usize {
    100
}
fn default_scan_batch_size() -> usize {
    500
}
fn default_google_ip_validation() -> bool {
    true
}

/// Source of truth for `heartbeat_enabled`'s default. Public so any
/// UI surface that needs to emit a "current default" hint can pull
/// the value from here instead of re-encoding the literal — a
/// config-only tweak here would otherwise silently drift caller
/// behaviour away from the runtime default.
pub fn default_heartbeat_enabled() -> bool {
    true
}

/// Source of truth for `heartbeat_interval_secs`'s default. See
/// `default_heartbeat_enabled` for the why-it's-pub rationale.
pub fn default_heartbeat_interval_secs() -> u64 {
    30
}

/// Source of truth for `heartbeat_failure_threshold`'s default. See
/// `default_heartbeat_enabled` for the why-it's-pub rationale.
pub fn default_heartbeat_failure_threshold() -> u32 {
    3
}

/// Default for `tunnel_doh`: `true` (DoH stays inside the tunnel).
/// Flipped from `false` in v1.9.0 per #468 — Iran ISPs filter direct
/// connections to pinned DoH hosts (`dns.google`, `chrome.cloudflare-dns.com`,
/// …) and the prior bypass-on default silently broke DNS for the
/// dominant userbase. Users on networks where direct DoH works can
/// opt back in with `tunnel_doh: false`.
fn default_tunnel_doh() -> bool {
    true
}

/// Default for `block_quic`: `true`. QUIC over the TCP-based tunnel
/// causes TCP-over-TCP meltdown (<1 Mbps). Browsers fall back to
/// HTTPS/TCP within seconds of the silent UDP drop. Issue #793.
fn default_block_quic() -> bool {
    true
}

/// Default for `block_stun`: `false`. Upstream PR #1115 shipped this
/// as `true` so WebRTC apps would skip the ~10–30 s UDP ICE timeout
/// and fall back to TCP TURN immediately. For rahgozar we default it
/// off to preserve existing upgrade behavior: an existing config that
/// omits the key keeps the pre-PR semantics (UDP STUN/TURN datagrams
/// pass through the relay unchanged) so a user on Meet/WhatsApp who
/// upgrades doesn't suddenly see calls behave differently without
/// being aware of the new toggle. Users who do want the fast-fail
/// behavior can opt in by setting `block_stun: true` in `config.json`
/// or via the UI checkbox.
fn default_block_stun() -> bool {
    false
}

/// Default for `block_doh`: `true` (browser DoH is rejected so the
/// browser falls back to system DNS, which `tun2proxy` resolves
/// instantly via virtual DNS — saves the ~1.5s tunnel round-trip per
/// name lookup that #468's `tunnel_doh: true` default would otherwise
/// pay). #773 — without this named-default function, `#[serde(default)]`
/// on `bool` resolves to `false`, and existing configs upgrading to
/// v1.9.13 silently lost the block-and-fall-back behaviour, paying
/// the full DoH-via-Apps-Script penalty on every page load. Power
/// users who specifically want browser DoH (with the latency cost)
/// can opt back in by setting `block_doh: false`.
fn default_block_doh() -> bool {
    true
}

/// Defaults for the auto-blacklist tuning knobs (#391, #444). These
/// preserve historical behavior — `3 strikes / 30s window / 120s cooldown`.
fn default_auto_blacklist_strikes() -> u32 {
    3
}
fn default_auto_blacklist_window_secs() -> u64 {
    30
}
fn default_auto_blacklist_cooldown_secs() -> u64 {
    120
}

/// Default for `request_timeout_secs`: 30s, matching the historical
/// hard-coded `BATCH_TIMEOUT` and Apps Script's typical response cliff.
fn default_request_timeout_secs() -> u64 {
    30
}

/// Default for `apps_script_lang`: `"en"`. English forces Apps Script /
/// Google frontend to emit error strings the envelope classifier knows
/// how to bucket (quota / auth / deploy / admin). Sanitised at use-site
/// by [`Config::apps_script_lang_resolved`] so an empty / whitespace
/// override doesn't disable the `?hl=` query parameter.
fn default_apps_script_lang() -> String {
    "en".into()
}

/// Default for `sabr_strip`: `false`. Flipped from `true` after #977
/// testing — both strip-all and keep-first variants of the heuristic
/// broke video playback in the field, including on single-track
/// default-config tests at 1080p60. Without proto reflection on a
/// captured `/videoplayback` body we can't design a correct heuristic,
/// so default-off ships the unbroken-playback common case. Users who
/// specifically hit "Response too large" 502s on long-form 1080p+
/// videos can opt in with `sabr_strip: true` (uses the keep-first
/// flavour, less aggressive than upstream's strip-all).
fn default_sabr_strip() -> bool {
    false
}

fn default_google_ip() -> String {
    "216.239.38.120".into()
}
fn default_front_domain() -> String {
    "www.google.com".into()
}
fn default_listen_host() -> String {
    "0.0.0.0".into()
}
fn default_listen_port() -> u16 {
    8085
}
fn default_log_level() -> String {
    "warn".into()
}
pub const DEFAULT_LOG_COLOR_INFO: &str = "#5ab464";
pub const DEFAULT_LOG_COLOR_WARN: &str = "#e0a83a";
pub const DEFAULT_LOG_COLOR_ERROR: &str = "#dc6e6e";
fn default_log_color_info() -> String {
    DEFAULT_LOG_COLOR_INFO.into()
}
fn default_log_color_warn() -> String {
    DEFAULT_LOG_COLOR_WARN.into()
}
fn default_log_color_error() -> String {
    DEFAULT_LOG_COLOR_ERROR.into()
}
fn default_verify_ssl() -> bool {
    true
}

/// Validate a `direct_mode` hostname / suffix list entry.
///
/// Accepts: ASCII LDH-shaped (RFC 952 §2 + RFC 1123 §2.1) DNS labels
/// separated by dots. IDN domains must be pre-encoded as punycode
/// (`xn--…`) — the runtime matcher is byte-based and can't compare
/// raw Unicode to a wire-encoded hostname.
///
/// Rejects (fail-fast at config load, not after a 3-second dial):
///   - empty / whitespace-only (degrades to a slow runtime failure);
///   - URL schemes (`https://...`) — direct_mode entries aren't URLs;
///   - paths (any `/`) — same reason;
///   - whitespace inside the entry (space / tab / newline) — almost
///     always copy-paste fat-finger error;
///   - ports / IPv6 colons (`example.com:443` or `2607:...`) — fronts
///     are dialed with the destination port, IPv6 literals as fronts
///     aren't supported by the matcher anyway;
///   - labels with non-LDH characters (`_underscore`, raw Unicode);
///   - labels with leading or trailing hyphen (`-bad`, `bad-`);
///   - labels longer than 63 octets, names longer than 253 octets
///     (RFC 1035 §2.3.4 limits — anything beyond these can't resolve).
fn validate_direct_mode_hostname(field: &str, i: usize, raw: &str) -> Result<(), ConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{}[{}]: empty / whitespace-only entry",
            field, i
        )));
    }
    if raw.chars().any(|c| matches!(c, ' ' | '\t' | '\r' | '\n')) {
        return Err(ConfigError::Invalid(format!(
            "{}[{}] ('{}'): hostname must not contain whitespace",
            field, i, raw
        )));
    }
    if trimmed.contains("://") || trimmed.starts_with("//") {
        return Err(ConfigError::Invalid(format!(
            "{}[{}] ('{}'): expected a bare hostname, not a URL",
            field, i, raw
        )));
    }
    if trimmed.contains('/') {
        return Err(ConfigError::Invalid(format!(
            "{}[{}] ('{}'): path component is not allowed — entries match by hostname only",
            field, i, raw
        )));
    }
    if trimmed.contains(':') {
        return Err(ConfigError::Invalid(format!(
            "{}[{}] ('{}'): port / IPv6 colon is not allowed — \
             fronts are dialed with the destination's port",
            field, i, raw
        )));
    }
    let stripped = trimmed.trim_start_matches('.').trim_end_matches('.');
    if stripped.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{}[{}] ('{}'): hostname has no labels (just dots)",
            field, i, raw
        )));
    }
    if stripped.len() > 253 {
        return Err(ConfigError::Invalid(format!(
            "{}[{}] ('{}'): hostname exceeds RFC 1035 max length of 253 octets",
            field, i, raw
        )));
    }
    for label in stripped.split('.') {
        if label.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "{}[{}] ('{}'): empty label (consecutive dots)",
                field, i, raw
            )));
        }
        if label.len() > 63 {
            return Err(ConfigError::Invalid(format!(
                "{}[{}] ('{}'): label '{}' exceeds RFC 1035 max of 63 octets",
                field, i, raw, label
            )));
        }
        // LDH (Letters, Digits, Hyphen) + the leading/trailing-hyphen
        // ban from RFC 952 §2 / RFC 1123 §2.1. IDN labels arrive
        // already punycode-encoded (`xn--…`) which is itself LDH, so
        // this check is compatible with international names; the
        // matcher (`direct_mode::is_google_domain`) is byte-based and
        // a raw Unicode label here couldn't match wire-encoded
        // hostnames anyway.
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ConfigError::Invalid(format!(
                "{}[{}] ('{}'): label '{}' contains non-LDH character \
                 (only letters, digits, and hyphens allowed; IDN names \
                 must be punycode-encoded as 'xn--...')",
                field, i, raw, label
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ConfigError::Invalid(format!(
                "{}[{}] ('{}'): label '{}' must not start or end with a hyphen",
                field, i, raw, label
            )));
        }
    }
    Ok(())
}

/// Validate a single `relay_url_patterns` entry. The expected shape is
/// `host/path-prefix` (or bare `host`, equivalent to `host/`), with an
/// optional `http://` / `https://` scheme that gets stripped at runtime.
///
/// Checks:
/// * non-empty after trim
/// * scheme strip leaves a non-empty host
/// * host part is a syntactically valid DNS hostname per RFC 1123:
///   labels of [a-zA-Z0-9-], ≤ 63 chars each, no leading/trailing
///   hyphen, no empty labels (which would mean consecutive dots),
///   total host ≤ 253 chars
///
/// What's intentionally NOT checked here:
/// * whether the host is in `SNI_REWRITE_SUFFIXES` — that's a runtime
///   `tracing::warn!` (see `ResolvedRouting::skipped_force_mitm_hosts`)
///   because users may want a pattern to be no-op-pulled-out-of-MITM
///   path filter while the matching half still routes via relay.
/// * path syntax — any byte sequence after the first `/` is treated
///   as a literal prefix to `starts_with` against URL paths, by design.
fn validate_relay_url_pattern(p: &str) -> Result<(), String> {
    let trimmed = p.trim();
    if trimmed.is_empty() {
        return Err("entry is empty / whitespace-only".to_string());
    }
    // Strip a scheme (case-insensitive) the same way ResolvedRouting
    // does at startup, so user input like "https://Foo.com/path/" is
    // validated as its post-normalization form.
    let lower = trimmed.to_ascii_lowercase();
    let no_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    if no_scheme.is_empty() {
        return Err("scheme present but no host follows".to_string());
    }
    // Bare hosts (no slash) are valid — they mean "any path on this host"
    // and round-trip through the same matchers as `host/`.
    let host = match no_scheme.find('/') {
        Some(i) => &no_scheme[..i],
        None => no_scheme,
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err("host part is empty".to_string());
    }
    if host.len() > 253 {
        return Err(format!(
            "host exceeds 253 characters ({} chars)",
            host.len()
        ));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(format!(
                "host '{}' contains an empty label (consecutive or leading dots)",
                host
            ));
        }
        if label.len() > 63 {
            return Err(format!("host label '{}' exceeds 63 characters", label));
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(format!(
                "host label '{}' starts or ends with a hyphen",
                label
            ));
        }
        for c in label.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-') {
                return Err(format!(
                    "host label '{}' contains invalid character '{}' \
                     (only ASCII letters, digits, and hyphens allowed)",
                    label, c
                ));
            }
        }
    }
    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.display().to_string(), e))?;
        let cfg: Config = serde_json::from_str(&data)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mode = self.mode_kind()?;
        if mode.uses_apps_script_relay() {
            if self.auth_key.trim().is_empty() || self.auth_key == "CHANGE_ME_TO_A_STRONG_SECRET" {
                return Err(ConfigError::Invalid(
                    "auth_key must be set to a strong secret".into(),
                ));
            }
            let ids = self.script_ids_resolved();
            if ids.is_empty() {
                return Err(ConfigError::Invalid(
                    "script_id (or script_ids) is required".into(),
                ));
            }
            for id in &ids {
                if id.is_empty() || id == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID" {
                    return Err(ConfigError::Invalid(
                        "script_id is not set — deploy Code.gs and paste its Deployment ID".into(),
                    ));
                }
            }
        }
        if mode.uses_drive_relay() {
            if self.drive.oauth_client_id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "drive.oauth_client_id is required for mode=drive — rahgozar is BYO OAuth: \
                     register your own installed-app client in Google Cloud Console and paste \
                     the client_id here. See docs/drive_oauth_setup.md for the walkthrough."
                        .into(),
                ));
            }
            if self.drive.oauth_client_secret.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "drive.oauth_client_secret is required for mode=drive — paste it next to \
                     drive.oauth_client_id. See docs/drive_oauth_setup.md for the walkthrough."
                        .into(),
                ));
            }
            if self.drive.oauth_refresh_token.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "drive.oauth_refresh_token is required for mode=drive — run the OAuth flow first \
                     (Sign in with Google in the desktop UI, or `rahgozar-drive-relay oauth device-code` \
                     on a headless host)"
                        .into(),
                ));
            }
            if self.drive.folder_id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "drive.folder_id is required for mode=drive — create the shared mailbox folder \
                     in the same Google account, paste the bare folder ID (not the URL)"
                        .into(),
                ));
            }
            if self.drive.relay_pubkey.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "drive.relay_pubkey is required for mode=drive — run `rahgozar-drive-relay keygen` \
                     on your VPS and paste the bech32m-encoded public key it prints (HRP `rgdr1`)"
                        .into(),
                ));
            }
            // Parse the bech32m pubkey eagerly so a typo / wrong-HRP
            // / wrong-length fails the SAME load path the UI + CLI
            // both use, rather than landing as a runtime error on
            // first connect. Single source of truth: `drive_crypto`.
            // Same fail-fast contract as the `fronting_groups[*].sni`
            // ServerName parse at line ~1272 below.
            crate::drive_crypto::RelayPubkey::from_bech32m(&self.drive.relay_pubkey)
                .map_err(|e| ConfigError::Invalid(format!("drive.relay_pubkey: {}", e)))?;
            // Tuning knobs must be > 0 to be usable. 0 would either
            // busy-loop the poller (poll_interval_ms) or stall every
            // upload (max_concurrent_uploads). Mirrors the relay-side
            // guard in `RelayConfig::validate`.
            if self.drive.poll_interval_ms == 0 {
                return Err(ConfigError::Invalid(
                    "drive.poll_interval_ms must be > 0 (would otherwise busy-loop the poller)"
                        .into(),
                ));
            }
            if self.drive.max_concurrent_uploads == 0 {
                return Err(ConfigError::Invalid(
                    "drive.max_concurrent_uploads must be > 0 (would otherwise stall every upload)"
                        .into(),
                ));
            }
            // Drive endpoints (googleapis.com / oauth2.googleapis.com /
            // accounts.google.com) MUST resolve via the `google_ip`
            // override on the Iran client side — system DNS is the
            // poisoned/blocked ISP DNS we exist to bypass. Without a
            // valid IP here, `build_drive_http_client` falls back to
            // system DNS with only a tracing warning; the user's
            // entire Drive transport leaks to the ISP. Reject up
            // front. Note: Apps Script mode tolerates an empty
            // google_ip (operator may rely on system DNS for
            // bootstrapping); Drive mode does not.
            let gip = self.google_ip.trim();
            if gip.is_empty() {
                return Err(ConfigError::Invalid(
                    "google_ip is required for mode=drive — Drive endpoints must resolve via this \
                     pinned IP, not system DNS (the ISP DNS Drive Mode exists to bypass). Set a \
                     known-working Google edge IP (e.g. one discovered via `cdn_discover`)."
                        .into(),
                ));
            }
            if gip.parse::<std::net::IpAddr>().is_err() {
                return Err(ConfigError::Invalid(format!(
                    "google_ip {gip:?} is not a valid IP address — would silently fall back to \
                     system DNS for Drive endpoints, leaking the transport to the ISP"
                )));
            }
        }
        if self.scan_batch_size == 0 {
            return Err(ConfigError::Invalid(
                "scan_batch_size must be greater than 0".into(),
            ));
        }
        if self.socks5_port == Some(self.listen_port) {
            return Err(ConfigError::Invalid(format!(
                "listen_port and socks5_port must differ on the same host \
                 (both set to {} on {}). Change one of them in config.json.",
                self.listen_port, self.listen_host
            )));
        }
        for (i, g) in self.fronting_groups.iter().enumerate() {
            if g.name.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}]: name is empty",
                    i
                )));
            }
            // `ip` is the pinned edge to dial in the classic (non-force_ip)
            // model. In camouflage mode (`force_ip = true`) the
            // destination's own IP is resolved per-connection via DoH, so
            // an empty `ip` is expected and fine there.
            if !g.force_ip && g.ip.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): ip is empty (required unless force_ip = true)",
                    i, g.name
                )));
            }
            if g.sni.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): sni is empty",
                    i, g.name
                )));
            }
            // Parse the SNI here so an invalid hostname fails the same
            // load path the UI / `rahgozar` CLI both use, rather than
            // surfacing later only when ProxyServer::new tries to build
            // the TLS server name. Same fail-fast contract as the rest
            // of validate(). The parse is cheap; runtime path repeats
            // it once at proxy startup, idempotently.
            if let Err(e) = ServerName::try_from(g.sni.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): invalid sni '{}': {}",
                    i, g.name, g.sni, e
                )));
            }
            if g.domains.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): domains list is empty",
                    i, g.name
                )));
            }
            for d in &g.domains {
                if d.trim().is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "fronting_groups[{}] ('{}'): empty domain entry",
                        i, g.name
                    )));
                }
            }
            // Explicit camouflage `verify_names` are a documented config
            // field, so validate them on the same load path as `sni`
            // rather than letting an invalid entry surface only later in
            // `FrontingGroupResolved::from_config`. Empty list = verify
            // against the real host (nothing to validate here).
            for v in &g.verify_names {
                let v = v.trim().trim_end_matches('.');
                if v.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "fronting_groups[{}] ('{}'): empty verify_names entry",
                        i, g.name
                    )));
                }
                if let Err(e) = ServerName::try_from(v.to_string()) {
                    return Err(ConfigError::Invalid(format!(
                        "fronting_groups[{}] ('{}'): invalid verify_names entry '{}': {}",
                        i, g.name, v, e
                    )));
                }
            }
        }
        // `relay_url_patterns` is documented as `host/path-prefix` (no
        // scheme) but `Vec<String>` deserializes anything. Validate the
        // shape at load time so a typo like `///` or `host..com/` becomes
        // a fail-fast error instead of a late routing surprise. Mirrors
        // the fail-fast contract the rest of validate() applies to
        // fronting_groups, scan_batch_size, etc.
        for (i, p) in self.relay_url_patterns.iter().enumerate() {
            if let Err(e) = validate_relay_url_pattern(p) {
                return Err(ConfigError::Invalid(format!(
                    "relay_url_patterns[{}] ('{}'): {}",
                    i, p, e
                )));
            }
        }
        // `direct_mode` overrides — same fail-fast contract as the rest
        // of validate(). The runtime substitutes built-in defaults when
        // these lists are empty, but a *non-empty* list containing
        // whitespace-only or syntactically nonsense entries should hard
        // error rather than degrade to a slow connection failure on
        // first dial.
        for (i, f) in self.direct_mode.fronts.iter().enumerate() {
            validate_direct_mode_hostname("direct_mode.fronts", i, f)?;
        }
        for (i, d) in self.direct_mode.google_domains.iter().enumerate() {
            validate_direct_mode_hostname("direct_mode.google_domains", i, d)?;
        }
        for (i, d) in self.direct_mode.sanctioned_domains.iter().enumerate() {
            validate_direct_mode_hostname("direct_mode.sanctioned_domains", i, d)?;
        }
        Ok(())
    }

    pub fn mode_kind(&self) -> Result<Mode, ConfigError> {
        // Delegates to `impl FromStr for Mode` so the string-to-enum
        // mapping (including the `google_only` back-compat alias) is
        // a single source of truth. See the impl for the rationale.
        self.mode.parse::<Mode>()
    }

    pub fn script_ids_resolved(&self) -> Vec<String> {
        self.script_id_entries()
            .into_iter()
            .filter(|e| e.enabled)
            .map(|e| e.id)
            .collect()
    }

    /// Full entry list with `enabled` flags preserved, in on-disk order.
    /// UI code (desktop `get_config`, Android config load) calls this to
    /// round-trip disabled rows; the relay must use
    /// `script_ids_resolved()` to avoid routing through disabled IDs.
    ///
    /// Hand-edited configs (or migrations between platforms) can carry
    /// BOTH `script_id` (canonical, what Rust + recent Android write)
    /// and `script_ids` (legacy plural alias). Merge with `script_id`
    /// winning on ID collision — otherwise a UI round-trip can silently
    /// discard the canonical entries by reading only the legacy ones
    /// and then writing them back. Matches the merge+dedupe order
    /// Android's `loadFromJson` uses.
    pub fn script_id_entries(&self) -> Vec<ScriptIdEntry> {
        let mut out: Vec<ScriptIdEntry> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut absorb = |s: &ScriptId| {
            for entry in s.clone().into_entries() {
                if seen.insert(entry.id.clone()) {
                    out.push(entry);
                }
            }
        };
        if let Some(s) = &self.script_id {
            absorb(s);
        }
        if let Some(s) = &self.script_ids {
            absorb(s);
        }
        out
    }

    /// Sanitised `apps_script_lang` — trimmed, lowercased, and validated
    /// as a BCP47-ish language tag (ASCII letters, optional single
    /// hyphen-separated region, ≤ 10 chars). Falls back to `"en"` for
    /// empty / whitespace / malformed input so a hand-edited config
    /// can't smuggle `&` / `\r\n` / `%` into the `?hl=` query string
    /// or the `Accept-Language` header. Centralised so the URL builder
    /// and the relay header path agree on what value to use.
    pub fn apps_script_lang_resolved(&self) -> String {
        sanitize_apps_script_lang(&self.apps_script_lang).unwrap_or_else(|| "en".into())
    }
}

/// Whitelist-validate a user-supplied `apps_script_lang`. Returns the
/// normalised value when it parses as a BCP47-ish tag, `None` otherwise
/// so callers can fall back to `"en"`. The allowed grammar is:
///
/// * 1–8 ASCII letters (e.g. `en`, `eng`)
/// * optionally followed by `-` and 1–8 more ASCII letters / digits
///   (e.g. `en-US`, `zh-CN`, `pt-BR`)
///
/// Anything else — special characters, embedded whitespace, empty
/// segments around hyphens, length over 10, non-ASCII — is rejected.
/// This keeps the value safe to interpolate into URL query strings and
/// HTTP header values without further encoding.
fn sanitize_apps_script_lang(raw: &str) -> Option<String> {
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || v.len() > 10 {
        return None;
    }
    let mut parts = v.split('-');
    let head = parts.next()?;
    if head.is_empty() || head.len() > 8 || !head.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    if let Some(region) = parts.next() {
        if region.is_empty()
            || region.len() > 8
            || !region.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return None;
        }
    }
    if parts.next().is_some() {
        // Reject `xx-yy-zz` — Apps Script only honours the primary tag
        // and the extra subtags add attack surface for no benefit.
        return None;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": "ABCDEF"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert_eq!(cfg.script_ids_resolved(), vec!["ABCDEF".to_string()]);
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_multi_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": ["A", "B", "C"]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert_eq!(cfg.script_ids_resolved(), vec!["A", "B", "C"]);
    }

    #[test]
    fn parses_script_id_entries_with_enabled_flag() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": [
                {"id": "A", "enabled": true},
                {"id": "B", "enabled": false},
                {"id": "C", "enabled": true}
            ]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        // Runtime sees only the enabled subset…
        assert_eq!(cfg.script_ids_resolved(), vec!["A", "C"]);
        // …but the UI round-trip preserves order + flags.
        let entries = cfg.script_id_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id, "A");
        assert!(entries[0].enabled);
        assert_eq!(entries[1].id, "B");
        assert!(!entries[1].enabled);
        assert_eq!(entries[2].id, "C");
        assert!(entries[2].enabled);
    }

    #[test]
    fn parses_mixed_legacy_and_object_entries() {
        // Hand-edited configs may interleave bare strings with objects;
        // bare strings default to enabled.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": ["A", {"id": "B", "enabled": false}, "C"]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert_eq!(cfg.script_ids_resolved(), vec!["A", "C"]);
        assert_eq!(cfg.script_id_entries().len(), 3);
    }

    #[test]
    fn merges_script_id_and_script_ids_with_canonical_first() {
        // A config that carries BOTH keys (e.g. hand-edited, or a
        // round-trip between platforms with different writers): the
        // canonical `script_id` must win on ID collision, so a desktop
        // get_config → save sequence can't silently discard a
        // canonical entry by reading only the legacy plural.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id":  [{"id": "A", "enabled": false}, {"id": "B", "enabled": true}],
            "script_ids": [{"id": "A", "enabled": true},  {"id": "C", "enabled": true}]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        let entries = cfg.script_id_entries();
        // Order: A (canonical), B (canonical), C (plural — new ID).
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id, "A");
        assert!(!entries[0].enabled, "canonical script_id wins on A");
        assert_eq!(entries[1].id, "B");
        assert!(entries[1].enabled);
        assert_eq!(entries[2].id, "C");
        assert!(entries[2].enabled);
        // Resolved (runtime) view skips A (disabled).
        assert_eq!(cfg.script_ids_resolved(), vec!["B", "C"]);
    }

    #[test]
    fn all_disabled_entries_fail_validation_for_apps_script() {
        // `script_ids_resolved()` filters to enabled-only, so a config
        // with every row disabled looks the same to validation as one
        // with no rows at all — the relay can't run either way.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": [
                {"id": "A", "enabled": false},
                {"id": "B", "enabled": false}
            ]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_placeholder_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "SECRET",
            "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_wrong_mode() {
        let s = r#"{
            "mode": "domain_fronting",
            "auth_key": "SECRET",
            "script_id": "X"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_direct_without_script_id() {
        // Direct mode: no script_id, no auth_key — both are only meaningful
        // once the Apps Script relay exists.
        let s = r#"{
            "mode": "direct"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate()
            .expect("direct must validate without script_id / auth_key");
        assert_eq!(cfg.mode_kind().unwrap(), Mode::Direct);
    }

    #[test]
    fn parses_local_bypass_without_script_id() {
        // local_bypass: no relay, no MITM CA. Like Direct, neither
        // script_id nor auth_key is required because nothing reaches
        // Apps Script in this mode.
        let s = r#"{
            "mode": "local_bypass"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate()
            .expect("local_bypass must validate without script_id / auth_key");
        assert_eq!(cfg.mode_kind().unwrap(), Mode::LocalBypass);
        assert_eq!(Mode::LocalBypass.as_str(), "local_bypass");
    }

    #[test]
    fn mode_uses_apps_script_relay_predicate() {
        // Single source of truth for "this mode needs script_id +
        // auth_key". Every UI / backend / profile-store gate defers
        // here rather than open-coding `mode == AppsScript || mode
        // == Full`, which is the kind of allowlist that drifts when
        // a new mode lands.
        assert!(
            Mode::AppsScript.uses_apps_script_relay(),
            "apps_script obviously needs the relay"
        );
        assert!(
            Mode::Full.uses_apps_script_relay(),
            "full tunnel goes through Apps Script too"
        );
        assert!(
            !Mode::Direct.uses_apps_script_relay(),
            "direct mode has no relay path"
        );
        assert!(
            !Mode::LocalBypass.uses_apps_script_relay(),
            "local_bypass intentionally has no relay path"
        );
    }

    #[test]
    fn mode_uses_mitm_ca_predicate() {
        // Separate truth table from `uses_apps_script_relay`. Direct
        // and AppsScript both rely on the MITM CA for SNI-rewrite
        // tunnelling (fronting groups, Google edge direct, the
        // direct-mode SkipPrefaced fallback); Full and LocalBypass
        // never MITM. A naive "uses_apps_script_relay implies
        // uses_mitm_ca" assumption would silently install the CA in
        // Full mode and skip it in Direct.
        assert!(
            Mode::AppsScript.uses_mitm_ca(),
            "apps_script terminates TLS inbound for relay dispatch"
        );
        assert!(
            Mode::Direct.uses_mitm_ca(),
            "direct uses the MITM CA for SNI-rewrite tunnelling \
             (Google edge, fronting groups, SkipPrefaced fallback)"
        );
        assert!(
            !Mode::Full.uses_mitm_ca(),
            "full tunnel short-circuits to the tunnel mux before any MITM"
        );
        assert!(
            !Mode::LocalBypass.uses_mitm_ca(),
            "local_bypass passes the real ClientHello through (no MITM)"
        );
        assert!(
            !Mode::Drive.uses_mitm_ca(),
            "drive transports encrypted frames through Google Drive, no MITM CA"
        );
    }

    #[test]
    fn mode_from_str_round_trips_via_as_str() {
        // Every variant produced by `as_str()` must parse back via
        // `FromStr` to the same variant. The desktop `save_config`
        // command relies on this round-trip — if it ever skews (e.g.
        // a new variant added to `as_str` but missing from
        // `FromStr`), the desktop save path silently fails.
        for m in [
            Mode::AppsScript,
            Mode::Direct,
            Mode::Full,
            Mode::LocalBypass,
            Mode::Drive,
        ] {
            let parsed: Mode = m
                .as_str()
                .parse()
                .unwrap_or_else(|e| panic!("{} must FromStr-parse: {}", m.as_str(), e));
            assert_eq!(parsed, m);
        }
        // google_only is a deprecated alias for direct — must keep
        // parsing forever or existing user configs break on upgrade.
        let alias: Mode = "google_only".parse().unwrap();
        assert_eq!(alias, Mode::Direct);
        // Bogus mode produces a useful error rather than silently
        // accepting it.
        assert!("not_a_real_mode".parse::<Mode>().is_err());
    }

    #[test]
    fn google_only_alias_parses_as_direct() {
        // Backwards compat: `direct` was named `google_only` before
        // fronting_groups. Existing configs must continue to load.
        let s = r#"{
            "mode": "google_only"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate()
            .expect("google_only alias must still validate");
        assert_eq!(cfg.mode_kind().unwrap(), Mode::Direct);
    }

    #[test]
    fn direct_ignores_placeholder_script_id() {
        // UI round-trip: user saved config in apps_script with the placeholder,
        // then switched mode to direct. The placeholder should not block
        // validation in the no-relay mode.
        let s = r#"{
            "mode": "direct",
            "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_full_mode() {
        let s = r#"{
            "mode": "full",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": "ABCDEF"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.mode_kind().unwrap(), Mode::Full);
    }

    #[test]
    fn full_mode_requires_script_id() {
        let s = r#"{
            "mode": "full",
            "auth_key": "SECRET"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_mode_value() {
        let s = r#"{
            "mode": "hybrid",
            "auth_key": "X",
            "script_id": "X"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_scan_batch_size() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "SECRET",
            "script_id": "X",
            "scan_batch_size": 0
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn fronting_groups_parse_and_validate() {
        let s = r#"{
            "mode": "direct",
            "fronting_groups": [
                {
                    "name": "vercel",
                    "ip": "76.76.21.21",
                    "sni": "react.dev",
                    "domains": ["vercel.com", "nextjs.org"]
                }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.fronting_groups.len(), 1);
        assert_eq!(cfg.fronting_groups[0].name, "vercel");
        assert_eq!(cfg.fronting_groups[0].domains.len(), 2);
    }

    #[test]
    fn fronting_group_rejects_invalid_sni_at_validate() {
        // SNI must parse as a DNS hostname at the same fail-fast point
        // as the rest of validate(), not later at proxy-startup time.
        // The CLI and UI both run validate() on Save / before serve.
        let s = r#"{
            "mode": "direct",
            "fronting_groups": [{
                "name": "bad",
                "ip": "1.2.3.4",
                "sni": "not a valid hostname",
                "domains": ["x.com"]
            }]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        let err = cfg
            .validate()
            .expect_err("invalid sni must fail validate()");
        let msg = format!("{}", err);
        assert!(
            msg.contains("invalid sni"),
            "error should mention invalid sni: {}",
            msg
        );
    }

    #[test]
    fn fronting_group_rejects_empty_fields() {
        for bad in [
            r#"{ "name": "", "ip": "1.2.3.4", "sni": "a.b", "domains": ["x.com"] }"#,
            r#"{ "name": "n", "ip": "",       "sni": "a.b", "domains": ["x.com"] }"#,
            r#"{ "name": "n", "ip": "1.2.3.4","sni": "",    "domains": ["x.com"] }"#,
            r#"{ "name": "n", "ip": "1.2.3.4","sni": "a.b", "domains": []        }"#,
            r#"{ "name": "n", "ip": "1.2.3.4","sni": "a.b", "domains": ["  "]    }"#,
        ] {
            let s = format!(r#"{{ "mode": "direct", "fronting_groups": [{}] }}"#, bad);
            let cfg: Config = serde_json::from_str(&s).unwrap();
            assert!(
                cfg.validate().is_err(),
                "expected validation error for: {}",
                bad
            );
        }
    }

    #[test]
    fn rejects_same_http_and_socks5_port() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "SECRET",
            "script_id": "X",
            "listen_port": 8085,
            "socks5_port": 8085
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    // ── relay_url_patterns validation ────────────────────────────────────

    #[test]
    fn fronting_group_serde_round_trip_matches_android_encoder() {
        // The Android `ConfigStore.encode()` ships fronting_groups across
        // devices as serde-compatible JSON. If the field shapes drift
        // (e.g. someone renames `sni` → `front_sni` on the Rust side),
        // an exported QR/URL silently stops importing on the desktop.
        // This test pins the exact JSON shape both sides agree on.
        let json = r#"{
            "name": "fastly",
            "ip": "151.101.0.223",
            "sni": "python.org",
            "domains": ["reddit.com", "github.com"]
        }"#;
        let g: FrontingGroup = serde_json::from_str(json).unwrap();
        assert_eq!(g.name, "fastly");
        assert_eq!(g.ip, "151.101.0.223");
        assert_eq!(g.sni, "python.org");
        assert_eq!(g.domains, vec!["reddit.com", "github.com"]);
        let reserialized = serde_json::to_value(&g).unwrap();
        let original: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(reserialized, original, "serde round-trip changed shape");
    }

    #[test]
    fn validate_relay_url_pattern_accepts_canonical_forms() {
        // The default pattern.
        assert!(validate_relay_url_pattern("youtube.com/youtubei/").is_ok());
        // Bare host (any path) — equivalent to `host/`.
        assert!(validate_relay_url_pattern("youtube.com").is_ok());
        // Trailing dot on host (FQDN form).
        assert!(validate_relay_url_pattern("youtube.com./youtubei/").is_ok());
        assert!(validate_relay_url_pattern("youtube.com.").is_ok());
        // Mixed case is fine — runtime lowercases before matching.
        assert!(validate_relay_url_pattern("YouTube.com/YouTubei/").is_ok());
        // Scheme is stripped at runtime; validator accepts both forms.
        assert!(validate_relay_url_pattern("https://youtube.com/youtubei/").is_ok());
        assert!(validate_relay_url_pattern("http://youtube.com/api/").is_ok());
        assert!(validate_relay_url_pattern("HTTPS://YouTube.com/api/").is_ok());
        // Multi-label hosts, hyphens inside labels.
        assert!(validate_relay_url_pattern("api-v2.example.com/path/").is_ok());
        assert!(validate_relay_url_pattern("foo-bar.googleapis.com/v1/").is_ok());
        // IPv4 literal — labels are all-digits, still passes the
        // alphanumeric+hyphen rule. Realistic for `hosts`-overridden
        // edges or local testing.
        assert!(validate_relay_url_pattern("1.2.3.4/path/").is_ok());
        // Path can be anything past the first `/` — it's just a
        // `starts_with` prefix.
        assert!(validate_relay_url_pattern("youtube.com/v1.0/").is_ok());
        assert!(validate_relay_url_pattern("youtube.com/api?weird=ok").is_ok());
        // Whitespace surrounding the entry is trimmed.
        assert!(validate_relay_url_pattern("  youtube.com/youtubei/  ").is_ok());
    }

    #[test]
    fn validate_relay_url_pattern_rejects_empty() {
        assert!(validate_relay_url_pattern("").is_err());
        assert!(validate_relay_url_pattern("   ").is_err());
        assert!(validate_relay_url_pattern("\t\n").is_err());
    }

    #[test]
    fn validate_direct_mode_hostname_accepts_canonical_forms() {
        for s in [
            "google.com",
            "www.google.com",
            ".google.com",
            "google.com.",
            ".google.com.",
            "youtube-nocookie.com",
            "r1---sn-aigl6n7e.googlevideo.com",
        ] {
            assert!(
                validate_direct_mode_hostname("f", 0, s).is_ok(),
                "{:?} should validate",
                s
            );
        }
    }

    #[test]
    fn validate_direct_mode_hostname_rejects_garbage() {
        for s in [
            "",
            "   ",
            "\t",
            "\n",
            "ho st.com",
            "host\tcom",
            "host\ncom",
            "https://google.com",
            "//google.com",
            "google.com/path",
            "google.com:443",
            "[2607:f8b0::1]",
            "2607:f8b0::1",
            ".",
            "..",
            "...",
            "host..com",
            // LDH rules below: non-ASCII / underscore / leading-hyphen
            // / trailing-hyphen are wire-illegal even though they'd
            // pass the structural checks above.
            "_bad.example.com",      // underscore in label
            "bad_label.example.com", // underscore mid-label
            "-leading.example.com",  // leading hyphen
            "trailing-.example.com", // trailing hyphen
            "münchen.example.com",   // raw Unicode (must be punycode)
            "host!.example.com",     // arbitrary symbol
        ] {
            assert!(
                validate_direct_mode_hostname("f", 0, s).is_err(),
                "{:?} should be rejected",
                s
            );
        }
    }

    #[test]
    fn validate_direct_mode_hostname_accepts_punycode_idn() {
        // Punycode-encoded IDN passes LDH (xn-- + LDH).
        assert!(validate_direct_mode_hostname("f", 0, "xn--mnchen-3ya.example.com").is_ok());
    }

    #[test]
    fn validate_direct_mode_hostname_rejects_oversized() {
        let too_long_label = "a".repeat(64);
        assert!(validate_direct_mode_hostname("f", 0, &too_long_label).is_err());
        let long_name = (0..40)
            .map(|_| "abcdef".to_string())
            .collect::<Vec<_>>()
            .join(".");
        assert!(long_name.len() > 253);
        assert!(validate_direct_mode_hostname("f", 0, &long_name).is_err());
    }

    #[test]
    fn validate_config_rejects_bad_direct_mode_entries() {
        let mut cfg: Config = serde_json::from_str(
            r#"{"mode":"direct","script_id":"x","auth_key":"strong","direct_mode":{"fronts":["www.google.com:443"]}}"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err(), "port-bearing front should reject");

        cfg.direct_mode.fronts = vec!["www.google.com".into()];
        cfg.direct_mode.google_domains = vec!["https://google.com".into()];
        assert!(
            cfg.validate().is_err(),
            "scheme in google_domains should reject"
        );

        cfg.direct_mode.google_domains = vec![".google.com".into()];
        cfg.direct_mode.sanctioned_domains = vec!["gemini.google.com/api".into()];
        assert!(
            cfg.validate().is_err(),
            "path in sanctioned_domains should reject"
        );

        cfg.direct_mode.sanctioned_domains = vec!["gemini.google.com".into()];
        assert!(cfg.validate().is_ok(), "valid config should pass");
    }

    #[test]
    fn validate_relay_url_pattern_rejects_missing_host() {
        // Just a path.
        assert!(validate_relay_url_pattern("/").is_err());
        assert!(validate_relay_url_pattern("/api/").is_err());
        // Scheme but no host.
        assert!(validate_relay_url_pattern("https://").is_err());
        assert!(validate_relay_url_pattern("https:///path/").is_err());
        // Just dots.
        assert!(validate_relay_url_pattern(".").is_err());
        assert!(validate_relay_url_pattern("./api/").is_err());
        // Garbage.
        assert!(validate_relay_url_pattern("///").is_err());
    }

    #[test]
    fn validate_relay_url_pattern_rejects_malformed_host() {
        // Consecutive dots → empty label in the middle.
        assert!(validate_relay_url_pattern("host..com/path/").is_err());
        // Leading hyphen on a label.
        assert!(validate_relay_url_pattern("-host.com/path/").is_err());
        // Trailing hyphen on a label.
        assert!(validate_relay_url_pattern("host-.com/path/").is_err());
        assert!(validate_relay_url_pattern("foo.host-.com/").is_err());
        // Whitespace inside the host.
        assert!(validate_relay_url_pattern("host with space/path/").is_err());
        // Underscore — disallowed in DNS hostnames per RFC 1123.
        assert!(validate_relay_url_pattern("ho_st.com/path/").is_err());
        // Special characters that signal user pasted a URL with auth /
        // query / fragment into the host slot.
        assert!(validate_relay_url_pattern("user@host.com/path/").is_err());
        assert!(validate_relay_url_pattern("ho?st.com/path/").is_err());
        assert!(validate_relay_url_pattern("ho#st.com/path/").is_err());
    }

    #[test]
    fn validate_relay_url_pattern_rejects_oversized_labels() {
        // Per RFC 1123: each label ≤ 63 chars.
        let long_label = "a".repeat(64);
        let pat = format!("{}.com/path/", long_label);
        assert!(validate_relay_url_pattern(&pat).is_err());

        // Total host ≤ 253 chars.
        let many_labels: Vec<String> = (0..40).map(|i| format!("label{:02}", i)).collect();
        let very_long_host = many_labels.join(".");
        // many_labels has 40 entries of 7 chars + 39 dots = 319 > 253.
        let pat = format!("{}/path/", very_long_host);
        assert!(validate_relay_url_pattern(&pat).is_err());
    }

    #[test]
    fn config_validate_surfaces_relay_pattern_errors_with_index_and_pattern() {
        // End-to-end: a malformed entry must fail Config::validate() with
        // an error that names both the index and the offending pattern,
        // so a user staring at a multi-line config can locate it. Mirrors
        // the fronting_groups error shape.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": [
                "youtube.com/youtubei/",
                "host..com/oops/"
            ]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        let err = cfg.validate().expect_err("malformed entry must fail");
        let msg = format!("{}", err);
        assert!(
            msg.contains("relay_url_patterns[1]"),
            "error must name the entry index: {}",
            msg
        );
        assert!(
            msg.contains("host..com/oops/"),
            "error must echo the offending pattern: {}",
            msg
        );
    }

    #[test]
    fn sabr_strip_defaults_to_false_when_omitted() {
        // After the #977 flip: `serde(default = "default_sabr_strip")`
        // must resolve to false so configs without the field get the
        // safe (unbroken-playback) common case. Existing configs that
        // never had the field continue to work — they just don't get
        // the strip applied.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(
            !cfg.sabr_strip,
            "default must be false (strip opt-in, default off)"
        );
    }

    #[test]
    fn sabr_strip_round_trips_explicit_true_for_opt_in() {
        // Users specifically hitting "Response too large" 502s on
        // long-form high-quality videos can opt in with sabr_strip:
        // true. The keep-first heuristic kicks in only on multi-track
        // bodies — single-track requests pass through untouched.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "sabr_strip": true
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(
            cfg.sabr_strip,
            "explicit true must round-trip for opt-in users"
        );
    }

    #[test]
    fn sabr_strip_round_trips_explicit_false_explicitly() {
        // Round-trip the explicit-false case too — `false` is the
        // default but a user might write it out for clarity, and we
        // shouldn't lose information either way.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "sabr_strip": false
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(!cfg.sabr_strip);
    }

    #[test]
    fn config_validate_accepts_well_formed_relay_patterns() {
        // Mixed canonical / scheme-prefixed / bare-host entries all pass.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": [
                "youtube.com/youtubei/",
                "https://googleapis.com/api/",
                "studio.youtube.com",
                "1.2.3.4/health/"
            ]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().expect("well-formed patterns must validate");
    }

    // ── Drive-mode validation ───────────────────────────────────────
    //
    // Each test starts from a complete Drive config and mutates ONE
    // field to the invalid value, so a failure trivially points at
    // which guard fired. Mirrors the existing
    // `validate_config_rejects_bad_direct_mode_entries` shape.

    /// Build a known-good Drive-mode config, using a freshly minted
    /// relay keypair so the bech32m pubkey is real.
    fn well_formed_drive_config() -> Config {
        let pk = crate::drive_crypto::RelaySecret::generate(rand::rngs::OsRng).public_key();
        let s = format!(
            r#"{{
                "mode": "drive",
                "drive": {{
                    "oauth_client_id": "1234567890-test.apps.googleusercontent.com",
                    "oauth_client_secret": "GOCSPX-test-client-secret",
                    "oauth_refresh_token": "1//xxxxxxxxxxxxxxxxxxxx",
                    "folder_id": "0AABBccDDeeFFggHHiiJJkkLL",
                    "relay_pubkey": "{}"
                }}
            }}"#,
            pk.to_bech32m()
        );
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn validate_accepts_well_formed_drive_config() {
        let cfg = well_formed_drive_config();
        cfg.validate()
            .expect("well-formed Drive config must validate");
    }

    #[test]
    fn validate_rejects_drive_without_oauth_client_id() {
        let mut cfg = well_formed_drive_config();
        cfg.drive.oauth_client_id.clear();
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("oauth_client_id"),
            "error must name the missing field; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_without_oauth_client_secret() {
        let mut cfg = well_formed_drive_config();
        cfg.drive.oauth_client_secret.clear();
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("oauth_client_secret"),
            "error must name the missing field; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_without_oauth_refresh_token() {
        let mut cfg = well_formed_drive_config();
        cfg.drive.oauth_refresh_token.clear();
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("oauth_refresh_token"),
            "error must name the missing field; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_without_folder_id() {
        let mut cfg = well_formed_drive_config();
        cfg.drive.folder_id.clear();
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("folder_id"),
            "error must name the missing field; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_without_relay_pubkey() {
        let mut cfg = well_formed_drive_config();
        cfg.drive.relay_pubkey.clear();
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("relay_pubkey"),
            "error must name the missing field; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_with_garbage_relay_pubkey() {
        let mut cfg = well_formed_drive_config();
        cfg.drive.relay_pubkey = "not bech32m at all".to_string();
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("relay_pubkey") && msg.to_lowercase().contains("bech32m"),
            "error must surface the bech32m parse failure; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_with_wrong_hrp_relay_pubkey() {
        let mut cfg = well_formed_drive_config();
        // Mint a 32-byte payload with the wrong HRP. The shape is
        // valid bech32m but the HRP doesn't match `rgdr`, so the
        // validator must refuse — that's what catches "user pasted
        // a bitcoin address / lightning invoice / etc.".
        let hrp = bech32::Hrp::parse_unchecked("ln");
        let bytes = [0u8; 32];
        cfg.drive.relay_pubkey = bech32::encode::<bech32::Bech32m>(hrp, &bytes).unwrap();
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("relay_pubkey") && msg.contains("HRP"),
            "error must call out the wrong HRP; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_with_empty_google_ip() {
        let mut cfg = well_formed_drive_config();
        cfg.google_ip.clear();
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("google_ip"),
            "error must name the missing google_ip; got {err}"
        );
    }

    #[test]
    fn validate_rejects_drive_with_malformed_google_ip() {
        let mut cfg = well_formed_drive_config();
        cfg.google_ip = "not-an-ip".into();
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("google_ip") && msg.contains("not a valid IP"),
            "error must call out the malformed IP; got {err}"
        );
    }

    #[test]
    fn validate_skips_drive_checks_in_other_modes() {
        // Same incomplete drive config, but mode=direct. The drive
        // checks must NOT fire — `mode.uses_drive_relay()` gates them.
        let s = r#"{
            "mode": "direct",
            "drive": {
                "oauth_refresh_token": "",
                "folder_id": "",
                "relay_pubkey": ""
            }
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate()
            .expect("drive checks must be skipped when mode != drive");
    }
}

#[cfg(test)]
mod rt_tests {
    use super::*;

    #[test]
    fn round_trip_all_current_fields() {
        // Regression guard: make sure a config written by the UI (all current
        // optional fields present and populated) loads back cleanly.
        // Includes the v2.1+ heartbeat + brotli/zstd knobs so this test
        // actually pins what its name advertises.
        let json = r#"{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "AKfyc_TEST",
  "auth_key": "testtesttest",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086,
  "log_level": "info",
  "verify_ssl": true,
  "upstream_socks5": "127.0.0.1:50529",
  "parallel_relay": 2,
  "sni_hosts": ["www.google.com", "drive.google.com"],
  "fetch_ips_from_api": true,
  "max_ips_to_scan": 50,
  "scan_batch_size": 100,
  "google_ip_validation": true,
  "heartbeat_enabled": false,
  "heartbeat_interval_secs": 17,
  "heartbeat_failure_threshold": 5,
  "allow_brotli_zstd": true
}"#;
        let tmp = std::env::temp_dir().join("rahgozar-rt-test.json");
        std::fs::write(&tmp, json).unwrap();
        let cfg = Config::load(&tmp).expect("config should load");
        assert_eq!(cfg.mode, "apps_script");
        assert_eq!(cfg.auth_key, "testtesttest");
        assert_eq!(cfg.listen_port, 8085);
        assert_eq!(cfg.upstream_socks5.as_deref(), Some("127.0.0.1:50529"));
        assert_eq!(cfg.parallel_relay, 2);
        assert_eq!(
            cfg.sni_hosts.as_ref().unwrap(),
            &vec!["www.google.com".to_string(), "drive.google.com".to_string()]
        );
        assert!(cfg.fetch_ips_from_api);
        // Heartbeat / brotli-zstd round-trip: a hand-edited config
        // must preserve user-set values, not silently snap back to
        // defaults.
        assert!(!cfg.heartbeat_enabled);
        assert_eq!(cfg.heartbeat_interval_secs, 17);
        assert_eq!(cfg.heartbeat_failure_threshold, 5);
        assert!(cfg.allow_brotli_zstd);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn force_http1_round_trips_through_config() {
        let json = r#"{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "X",
  "auth_key": "secretkey123",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "log_level": "info",
  "verify_ssl": true,
  "force_http1": true
}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.force_http1, "force_http1=true must round-trip");
    }

    /// Unknown / future config.json keys captured into `extras` round-trip
    /// through serde load. The write-side equivalents (preserving extras
    /// across a save, omitting default values from the wire form) used
    /// to live next to `ConfigWire` in the egui binary; since the
    /// desktop UI moved to Tauri (which round-trips via raw
    /// `serde_json::Value` overlay, see
    /// `desktop/src-tauri/src/commands.rs::save_config`) those write
    /// invariants are instead exercised by integration tests in the
    /// Tauri crate.
    #[test]
    fn unknown_fields_captured_into_extras() {
        let json = r#"{
            "mode": "apps_script",
            "auth_key": "secretkey123",
            "script_id": "X",
            "future_field_xyz": [1, 2, 3],
            "another_future_field": {"nested": true}
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(
            cfg.extras.contains_key("future_field_xyz"),
            "extras must capture unknown scalar/array fields"
        );
        assert!(
            cfg.extras.contains_key("another_future_field"),
            "extras must capture unknown object fields"
        );
        assert_eq!(
            cfg.extras.get("future_field_xyz").unwrap(),
            &serde_json::json!([1, 2, 3])
        );
        // Modelled fields must NOT end up in extras (otherwise we'd
        // double-emit them on save).
        assert!(!cfg.extras.contains_key("mode"));
        assert!(!cfg.extras.contains_key("auth_key"));
        assert!(!cfg.extras.contains_key("script_id"));
    }

    #[test]
    fn force_http1_defaults_false_when_omitted() {
        // Existing configs from before v1.9.13 don't have the field.
        // serde(default) must give false (h2 active) so older configs
        // continue to work and unchanged users get the optimization.
        let json = r#"{
  "mode": "apps_script",
  "auth_key": "secretkey123",
  "script_id": "X"
}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(!cfg.force_http1, "default must be false (h2 enabled)");
    }

    #[test]
    fn round_trip_minimal_fields_only() {
        // User saves with defaults for everything optional. This is what the
        // UI's save button actually writes for a first-run user.
        let json = r#"{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "A",
  "auth_key": "secretkey123",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "log_level": "info",
  "verify_ssl": true
}"#;
        let tmp = std::env::temp_dir().join("rahgozar-rt-min.json");
        std::fs::write(&tmp, json).unwrap();
        let cfg = Config::load(&tmp).expect("minimal config should load");
        assert_eq!(cfg.mode, "apps_script");
        let _ = std::fs::remove_file(&tmp);
    }
}
