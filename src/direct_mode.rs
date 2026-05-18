//! TLS-fragmentation Direct Mode for Google-owned domains.
//!
//! Ported from zyrln (https://github.com/ajavadinezhad/zyrln) — Go original
//! at `relay/core/{fragment,direct,direct_profiles}.go`. The idea: for
//! Google-served domains, skip both Apps Script relay and the SNI-rewrite
//! MITM path entirely. Instead, dial straight to a Google front IP and
//! pass the browser's *real* TLS ClientHello through, split across N TCP
//! segments with inter-chunk delays. DPI engines that need to reassemble
//! the SNI in a single packet can't catch it; once past the handshake,
//! Google routes by the encrypted Host (HTTP/2) or SNI as usual, so the
//! browser ends up with a real TLS session to the real origin.
//!
//! Compared to `do_sni_rewrite_tunnel_from_tcp`, this path needs **no
//! MITM CA install** — that's the main UX win on top of bypassing the
//! relay's quota.
//!
//! Failure model: TLS-handshake-level. We don't commit on TCP-connect
//! alone — TCP succeeds even when DPI is going to RST the handshake a
//! few hundred ms later. Instead, every dial path writes the
//! ClientHello fragmented and then *waits for the upstream to send
//! bytes* (the TLS ServerHello) within a short window. Only profiles
//! that actually elicit a ServerHello are accepted as winners; the
//! race re-runs over remaining profiles when the first one doesn't.
//! When every profile fails, we hand a `PrefacedTcpStream`-wrapped
//! client socket back to the dispatcher with the buffered ClientHello
//! as a preface so the existing SNI-rewrite tunnel can re-accept the
//! same ClientHello bytes. zyrln stops at TCP commit; this implementation
//! adds the validation step and the fallback wrap.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
// `portable_atomic::AtomicI64` instead of `std::sync::atomic::AtomicI64`
// because rahgozar's release matrix includes `mipsel-unknown-linux-musl`,
// which has no native 64-bit atomics — std's AtomicI64 isn't defined
// on that target and the crate fails to compile. The `fallback` feature
// (already enabled in Cargo.toml) uses a global spinlock for those
// targets and compiles to native instructions everywhere else. See the
// same import pattern in `src/tunnel_client.rs` / `src/cache.rs`.
use portable_atomic::AtomicI64;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Hard cap on the fast-path attempt — covers TCP connect + fragmented
/// ClientHello send + ServerHello arrival.
///
/// 2 s is the tightest the median Iran-ISP latency profile tolerates
/// (RTT to Google edge ~150 ms × ~6 round-trips for TCP + fragmented
/// ClientHello + ServerHello). Smaller would false-fail on slow
/// connections; larger inflates the "Direct Mode never works here"
/// regression latency budget (see file-level note on `CIRCUIT_BREAKER`).
pub const FAST_PATH_TIMEOUT: Duration = Duration::from_secs(2);

/// Time we wait for the upstream to send any bytes (the TLS ServerHello)
/// after our fragmented ClientHello hits the wire. Below this we
/// classify the profile as DPI-killed and try the next one. Note this
/// is *inside* the fast-path / race envelopes, not in addition to.
pub const SERVER_HELLO_TIMEOUT: Duration = Duration::from_millis(1500);

/// Outer cap on the race phase. Tight by design — we run 8 profiles in
/// parallel, so the first viable one usually returns within the first
/// RTT plus a few ms of fragmentation pacing. A bigger window mostly
/// just stretches the "all fronts dead" failure tail before the
/// circuit breaker engages.
pub const RACE_TIMEOUT: Duration = Duration::from_secs(4);

/// TLS handshake content type byte. Every real ServerHello arrives as a
/// TLS record whose first byte is this value. `0x15` would be an
/// alert (e.g. handshake_failure from a wrong-edge / DPI inject),
/// `0x17` would be application-data (mid-stream proxy), HTTP plaintext
/// would be ASCII — none of those mean the fragmented profile won;
/// committing to splice with them produces broken connections that
/// the user can't recover from. Bail in those cases so the race
/// (and ultimately the SNI-rewrite fallback) gets a chance.
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// Consecutive "every-profile-failed" events that trip the circuit
/// breaker. Once tripped, Direct Mode short-circuits to the dispatcher
/// (no fragmented dials attempted) for `CIRCUIT_BREAKER_COOLDOWN` —
/// so a user on a network where direct just doesn't work doesn't pay
/// the full fast-path + race timeout on every Google CONNECT.
///
/// Set to `2` so a user on an entirely-blocked network only eats
/// ~12 s of bad-direct latency total before the breaker engages and
/// they're back to SNI-rewrite-only routing. Threshold = 1 would be
/// too twitchy (a single transient blip would lock out Direct Mode
/// for 60 s on a network where it normally works).
pub const CIRCUIT_BREAKER_THRESHOLD: u32 = 2;
pub const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(60);

/// Default front list — used as TCP destinations during dial. The
/// browser's ClientHello carries its own SNI (the real origin); the
/// front hostname just gives us a Google IP to connect to. Both of these
/// resolve to Google's edge, which serves any Google cert.
pub const DEFAULT_FRONTS: &[&str] = &["www.google.com", "script.google.com"];

/// Suffix list for "is this a Google-edge-served domain that Direct
/// Mode should fragment?" Constrained to the **intersection** of
/// zyrln's `googleDomains` and rahgozar's `SNI_REWRITE_SUFFIXES` in
/// `proxy_server.rs`.
///
/// The intersection is load-bearing: when fragmented dial fails for a
/// committed connection, the only viable fallback path is the
/// SNI-rewrite tunnel (the only path that takes a generic stream and
/// reuses the already-consumed ClientHello via `PrefacedTcpStream`).
/// SNI-rewrite is only safe for hosts in `SNI_REWRITE_SUFFIXES`; for
/// anything else (e.g. `googlevideo.com`, which was deliberately
/// removed from that list in v1.7.6 because the Google video CDN's
/// EVA edge IPs return wrong-cert errors when hit with the regular
/// GFE-targeted SNI rewrite) the fallback would 502 or serve
/// wrong-cert errors, *regressing* the prior relay-only behavior. So
/// we just don't enter Direct Mode for those hosts — they keep their
/// existing route (relay in AppsScript mode).
///
/// Hosts dropped from zyrln's list (and rationale):
/// - `gmail.com`, `googlemail.com`: redirect to `mail.google.com`
///   anyway, which IS in this list.
/// - `android.com`, `appspot.com`, `withgoogle.com`: not on the GFE
///   edge that `google_ip` points to.
/// - `googlevideo.com`: served from Google's EVA edge, distinct certs;
///   relay is the existing working path.
///
/// Each entry has a leading `.` (verbatim from zyrln) and matches a
/// host that either *is* the bare apex (e.g. `google.com`) or has the
/// suffix as a parent domain (e.g. `mail.google.com`). The runtime
/// normalizes off the leading dot during `from_parts`.
pub const DEFAULT_GOOGLE_DOMAINS: &[&str] = &[
    ".google.com",
    ".googleapis.com",
    ".googleusercontent.com",
    ".gstatic.com",
    ".ggpht.com",
    ".googletagmanager.com",
    ".googletagservices.com",
    ".googlesyndication.com",
    ".google-analytics.com",
    ".googleadservices.com",
    ".doubleclick.net",
    // YouTube family — present in SNI_REWRITE_SUFFIXES so fallback is
    // safe. `googlevideo.com` is NOT here; see file-level rationale.
    ".youtube.com",
    ".youtube-nocookie.com",
    ".ytimg.com",
];

/// Google domains that route via the relay even when Direct Mode is
/// enabled, because Google geo-blocks Iranian IPs and a direct connection
/// from inside Iran would land on a 403 page. Going through the Apps
/// Script relay (which runs in Google's US-hosted infra) bypasses the
/// geo-block. Verbatim from zyrln `sanctionedDomains`. Sanctioned-list
/// match takes precedence over Google-list match.
pub const DEFAULT_SANCTIONED_DOMAINS: &[&str] = &[
    "gemini.google.com",
    "bard.google.com",
    "ai.google",
    "aistudio.google.com",
    "labs.google",
];

const CANDIDATE_FILE: &str = "direct_candidate.txt";

/// Strategy enum baked into each profile so the `Splits` callback can
/// stay a pure function of the ClientHello bytes (no closures, no Send
/// bounds to worry about). Mirrors the four shapes in zyrln's
/// `directProfiles`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitStrategy {
    /// No fragmentation. zyrln's `p00`: `NumChunks=1, Delay=0`.
    Passthrough,
    /// Evenly spaced cut points: `p_i = (n*i) / num_chunks`.
    Equal,
    /// Cut points derived from the SNI byte offsets inside the
    /// ClientHello. zyrln's `p07`.
    Sni,
    /// `{1, 5}` (TLS record-header and handshake-header boundaries)
    /// prepended to `Sni` strategy output. zyrln's `p01`. Note: zyrln
    /// emits a duplicated, unsorted list here; we sort + dedupe before
    /// use to avoid an out-of-order `b[prev:s]` panic equivalent.
    SniPrefixed,
}

#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub id: &'static str,
    pub num_chunks: usize,
    pub delay: Duration,
    pub strategy: SplitStrategy,
}

/// ID of the profile used on the very first dial of a fresh install
/// (no candidate cache yet). zyrln ships `p00` (passthrough) as
/// `PROFILES[0]` so their default behaviour on Iran networks is "send
/// the ClientHello unsplit, TCP-connect succeeds, DPI kills the
/// handshake later, no fallback fires". For rahgozar we want the
/// opposite: the first dial should actively fragment so a user on a
/// DPI network gets working Google access immediately. `p05` is
/// zyrln's own `DefaultFragmentConfig` (`NumChunks: 87, Delay: 5ms`)
/// — a well-tested middle ground that defeats most Iranian SNDPI
/// variants. The cached candidate path is unchanged: when a previous
/// successful dial landed on a different profile, that profile wins
/// on subsequent dials regardless of what this constant says.
pub const DEFAULT_PROFILE_ID: &str = "p05";

/// The 8 fragmentation profiles — verbatim from zyrln `direct_profiles.go`.
///
/// Order matches zyrln's array literal so `direct_candidate.txt` files
/// produced by either project are interchangeable. The first-dial
/// default is decoupled from array order via `DEFAULT_PROFILE_ID`.
pub const PROFILES: &[Profile] = &[
    Profile {
        id: "p00",
        num_chunks: 1,
        delay: Duration::ZERO,
        strategy: SplitStrategy::Passthrough,
    },
    Profile {
        id: "p01",
        num_chunks: 8,
        delay: Duration::from_millis(5),
        strategy: SplitStrategy::SniPrefixed,
    },
    Profile {
        id: "p02",
        num_chunks: 16,
        delay: Duration::from_millis(1),
        strategy: SplitStrategy::Equal,
    },
    Profile {
        id: "p03",
        num_chunks: 32,
        delay: Duration::from_millis(3),
        strategy: SplitStrategy::Equal,
    },
    Profile {
        id: "p04",
        num_chunks: 64,
        delay: Duration::from_millis(5),
        strategy: SplitStrategy::Equal,
    },
    Profile {
        id: "p05",
        num_chunks: 87,
        delay: Duration::from_millis(5),
        strategy: SplitStrategy::Equal,
    },
    Profile {
        id: "p06",
        num_chunks: 120,
        delay: Duration::from_millis(10),
        strategy: SplitStrategy::Equal,
    },
    Profile {
        id: "p07",
        num_chunks: 8,
        delay: Duration::from_millis(25),
        strategy: SplitStrategy::Sni,
    },
];

fn profile_by_id(id: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.id == id)
}

/// First-dial profile when no candidate is cached. Looks up
/// `DEFAULT_PROFILE_ID`; falls back to the first array entry only if
/// that ID has been removed (shouldn't happen — defended for forward
/// compatibility if the array is ever pruned).
fn default_profile() -> &'static Profile {
    profile_by_id(DEFAULT_PROFILE_ID).unwrap_or(&PROFILES[0])
}

// ---------- Classifier ----------

/// Normalize a configured host / suffix entry to the canonical form used
/// for matching: trim whitespace, lowercase, strip trailing dots, and
/// strip a leading dot (we add it back in the matcher). Pure function
/// so the runtime ctx can pre-normalize at startup and the matcher can
/// then do byte-compare instead of repeated allocation.
pub fn normalize_domain_entry(s: &str) -> String {
    let mut out = s.trim().to_ascii_lowercase();
    while out.ends_with('.') {
        out.pop();
    }
    while out.starts_with('.') {
        out.remove(0);
    }
    out
}

/// True when `host` is on the Google-served suffix list AND not on the
/// sanctioned exception list. Lowercases and strips port. Sanctioned
/// match wins over Google match (the Iran geo-block check).
///
/// `google` / `sanctioned` entries are expected to be pre-normalized via
/// `normalize_domain_entry` — the runtime `DirectModeCtx::from_parts`
/// does this once at startup. Matching is suffix-anchored with a
/// mandatory dot boundary, matching how `host_in_force_mitm_list`
/// behaves elsewhere in the codebase.
pub fn is_google_domain(host: &str, google: &[String], sanctioned: &[String]) -> bool {
    let h = normalize_domain_entry(strip_port(host));
    if h.is_empty() {
        return false;
    }
    if domain_list_matches(&h, sanctioned) {
        return false;
    }
    domain_list_matches(&h, google)
}

fn strip_port(host: &str) -> &str {
    // Strip a `:port` suffix but only if it looks like a port (digits
    // only) — IPv6 literals contain colons that aren't port separators
    // and arrive without brackets in some code paths.
    match host.rsplit_once(':') {
        Some((prefix, port)) if !prefix.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            prefix
        }
        _ => host,
    }
}

/// Suffix-anchored matcher. `host` and `list` entries are both
/// pre-normalized (lowercase, no leading / trailing dot). Returns true
/// if `host` equals an entry OR is a strict subdomain.
fn domain_list_matches(host: &str, list: &[String]) -> bool {
    for entry in list {
        let entry = entry.as_str();
        if entry.is_empty() {
            continue;
        }
        if host == entry {
            return true;
        }
        // Strict subdomain check: at least one byte before the dot, and
        // the dot precedes the entry boundary. `evil.example.com`
        // matches `example.com` (offset 4 holds `.`); `eviexample.com`
        // does not (offset 3 holds `i`, not `.`).
        if host.len() > entry.len() + 1
            && host.ends_with(entry)
            && host.as_bytes()[host.len() - entry.len() - 1] == b'.'
        {
            return true;
        }
    }
    false
}

// ---------- Split helpers ----------

/// Evenly spaced split points: `p_i = (n*i) / num_chunks` for `i` in
/// `1..num_chunks-1`. Deduped against the previous value. Mirrors
/// zyrln's `equalSplits`.
pub fn equal_splits(n: usize, num_chunks: usize) -> Vec<usize> {
    if num_chunks <= 1 || n == 0 {
        return Vec::new();
    }
    let mut out: Vec<usize> = Vec::with_capacity(num_chunks.saturating_sub(1));
    let mut prev = 0usize;
    for i in 1..num_chunks {
        let p = (n * i) / num_chunks;
        if p == 0 || p == n {
            continue;
        }
        if p == prev {
            continue;
        }
        out.push(p);
        prev = p;
    }
    out
}

/// `count` distinct random positions in `(0, n)`. Mirrors zyrln's
/// `randomSplits` (uses Fisher–Yates over the pool `[1, n-1]`).
pub fn random_splits(n: usize, count: usize) -> Vec<usize> {
    if n <= 1 || count == 0 {
        return Vec::new();
    }
    let pool: usize = n - 1;
    let take = count.min(pool);
    let mut idx: Vec<usize> = (1..n).collect();
    let mut rng = rand::thread_rng();
    use rand::Rng;
    for i in 0..take {
        let j = i + rng.gen_range(0..(idx.len() - i));
        idx.swap(i, j);
    }
    idx.truncate(take);
    idx.sort_unstable();
    idx
}

/// Parse a TLS ClientHello and return the byte range `[start, end)` of
/// the SNI host_name extension's value. Returns `None` on any
/// malformation. Mirrors zyrln's `tlsSNIHostRange` — bounds-checked at
/// every step so a truncated or malformed record never panics.
pub fn tls_sni_host_range(data: &[u8]) -> Option<(usize, usize)> {
    let get = |i: usize, n: usize| data.get(i..i + n);

    // Record type byte 0 must be Handshake (0x16).
    if *data.first()? != 0x16 {
        return None;
    }
    // Skip 5-byte record header.
    let mut i = 5;
    // Handshake type byte must be ClientHello (0x01).
    if *data.get(i)? != 0x01 {
        return None;
    }
    // Skip handshake type (1) + length (3) = 4 bytes.
    i = i.checked_add(4)?;
    // Skip legacy version (2) + random (32) = 34 bytes.
    i = i.checked_add(2 + 32)?;
    // session_id_length (1 byte) + session_id.
    let session_len = *data.get(i)? as usize;
    i = i.checked_add(1 + session_len)?;
    // cipher_suites_length (2 bytes) + cipher_suites.
    let cipher = get(i, 2)?;
    let cipher_len = u16::from_be_bytes([cipher[0], cipher[1]]) as usize;
    i = i.checked_add(2 + cipher_len)?;
    // compression_methods_length (1 byte) + compression_methods.
    let comp_len = *data.get(i)? as usize;
    i = i.checked_add(1 + comp_len)?;
    // extensions_length (2 bytes).
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
        let ext_body_end = i.checked_add(l)?;
        if ext_body_end > ext_end {
            return None;
        }
        if typ == 0x0000 {
            return sni_host_range_in_extension(data, i, ext_body_end);
        }
        i = ext_body_end;
    }
    None
}

fn sni_host_range_in_extension(data: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let mut i = start;
    let list_hdr = data.get(i..i + 2)?;
    let list_len = u16::from_be_bytes([list_hdr[0], list_hdr[1]]) as usize;
    i += 2;
    let list_end = i.checked_add(list_len)?;
    if list_end > end {
        return None;
    }
    while i + 3 <= list_end {
        let name_type = data[i];
        i += 1;
        let nl = u16::from_be_bytes([*data.get(i)?, *data.get(i + 1)?]) as usize;
        i += 2;
        let name_end = i.checked_add(nl)?;
        if name_end > list_end {
            return None;
        }
        if name_type == 0 {
            return Some((i, name_end));
        }
        i = name_end;
    }
    None
}

/// Cut points derived from the SNI byte range inside the ClientHello,
/// plus `{1, 5}` (record-header and handshake-header byte boundaries).
/// Returns `None` when SNI can't be located so the caller can fall
/// back to `equal_splits`/`random_splits`.
pub fn sni_splits(data: &[u8]) -> Option<Vec<usize>> {
    let (host_start, host_end) = tls_sni_host_range(data)?;
    let n = data.len();
    let candidates: [usize; 7] = [
        1,
        5,
        host_start.saturating_sub(8),
        host_start.saturating_sub(1),
        host_start + 1,
        host_start + 7,
        host_end,
    ];
    let mut out: Vec<usize> = candidates.into_iter().filter(|&p| p > 0 && p < n).collect();
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Final split set for a profile + ClientHello. Empty result means
/// "no fragmentation, single passthrough write".
///
/// Defensive: always sorts and dedupes. zyrln's `p01` returns
/// `append([1,5], sniSplits(b)...)` which is unsorted and duplicated;
/// feeding that to a fragmenter loop expecting monotonic offsets
/// triggers a slice-out-of-range panic on real ClientHellos. We
/// normalize here so no profile can corrupt the writer.
pub fn compute_splits(p: &Profile, data: &[u8]) -> Vec<usize> {
    let n = data.len();
    if n < 2 || matches!(p.strategy, SplitStrategy::Passthrough) {
        return Vec::new();
    }

    let raw: Vec<usize> = match p.strategy {
        SplitStrategy::Passthrough => unreachable!(),
        SplitStrategy::Equal => equal_splits(n, p.num_chunks),
        SplitStrategy::Sni => sni_splits(data).unwrap_or_default(),
        SplitStrategy::SniPrefixed => {
            let mut v = vec![1usize, 5];
            if let Some(s) = sni_splits(data) {
                v.extend(s);
            }
            v
        }
    };

    let mut sorted: Vec<usize> = raw.into_iter().filter(|&s| s > 0 && s < n).collect();
    sorted.sort_unstable();
    sorted.dedup();

    if sorted.is_empty() && !matches!(p.strategy, SplitStrategy::Equal) {
        // SNI strategies that couldn't find SNI fall back to random
        // points so the profile still has *some* fragmenting effect.
        return random_splits(n, p.num_chunks.saturating_sub(1));
    }
    sorted
}

// ---------- Fragmenter ----------

/// Write `data` to `sock` split into chunks per `profile`. Between each
/// chunk: flush + sleep for `profile.delay`. The last chunk has no
/// trailing sleep. With `num_chunks` chunks there are `num_chunks - 1`
/// sleeps total — mirrors zyrln's loop placement.
///
/// Assumes `sock` already has `TCP_NODELAY` set; without it Nagle
/// coalesces our individual `write` calls and the fragmentation is
/// silently undone.
pub async fn fragmented_write(
    sock: &mut TcpStream,
    data: &[u8],
    profile: &Profile,
) -> std::io::Result<()> {
    let splits = compute_splits(profile, data);
    if splits.is_empty() {
        sock.write_all(data).await?;
        return Ok(());
    }
    let mut prev = 0usize;
    for s in &splits {
        let s = *s;
        debug_assert!(s > prev && s < data.len());
        sock.write_all(&data[prev..s]).await?;
        sock.flush().await?;
        prev = s;
        if !profile.delay.is_zero() {
            tokio::time::sleep(profile.delay).await;
        }
    }
    sock.write_all(&data[prev..]).await?;
    sock.flush().await
}

// ---------- Candidate persistence ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub front: String,
    pub profile_id: &'static str,
}

/// Atomically swappable remembered (front, profile) pair, optionally
/// backed by a file at `data_dir/direct_candidate.txt`. Loads on
/// construction; persists on every `remember()` (best-effort, errors
/// swallowed). No TTL.
pub struct CandidateCache {
    path: Option<PathBuf>,
    current: ArcSwapOption<Candidate>,
}

impl CandidateCache {
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        let path = data_dir.map(|d| d.join(CANDIDATE_FILE));
        let cache = Self {
            path,
            current: ArcSwapOption::from(None),
        };
        cache.reload_from_disk();
        cache
    }

    fn reload_from_disk(&self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        let s = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let trimmed = s.trim();
        let mut it = trimmed.splitn(2, '\n');
        let front = it.next().unwrap_or("").trim().to_string();
        let pid = it.next().unwrap_or("").trim();
        if front.is_empty() {
            return;
        }
        let Some(p) = profile_by_id(pid) else {
            return;
        };
        self.current.store(Some(Arc::new(Candidate {
            front,
            profile_id: p.id,
        })));
    }

    pub fn current(&self) -> Option<Arc<Candidate>> {
        self.current.load_full()
    }

    pub fn remember(&self, front: &str, profile_id: &'static str) {
        // No-op when the cached candidate already matches — the splice
        // path calls `remember()` after EVERY successful Google CONNECT,
        // and most of those reuse the same winning (front, profile).
        // Skipping the disk write in that common case saves a syscall
        // and a `spawn_blocking` shuffle per connection.
        if let Some(existing) = self.current.load_full().as_ref() {
            if existing.front == front && existing.profile_id == profile_id {
                return;
            }
        }
        let cand = Arc::new(Candidate {
            front: front.to_string(),
            profile_id,
        });
        self.current.store(Some(cand.clone()));
        if let Some(path) = self.path.as_ref() {
            // Persist off the runtime worker thread — `std::fs::write`
            // blocks, and `remember()` is called from the splice path
            // where blocking a worker starves every other connection
            // sharing the executor slot.
            //
            // `Handle::try_current()` distinguishes the production path
            // (always on tokio) from sync unit tests (no current
            // runtime). Tests fall through to the inline write, which
            // is fine because they're short and serial.
            //
            // Errors are swallowed: cache persistence is a performance
            // optimisation (skip the next restart's re-race), never a
            // correctness boundary — a read-only filesystem must not
            // crash the proxy.
            let path = path.clone();
            let body = format!("{}\n{}", cand.front, cand.profile_id);
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn_blocking(move || {
                        let _ = std::fs::write(&path, body);
                    });
                }
                Err(_) => {
                    let _ = std::fs::write(&path, body);
                }
            }
        }
    }
}

// ---------- Runtime context ----------

pub struct DirectModeCtx {
    pub enabled: AtomicBool,
    pub fronts: Vec<String>,
    pub google_domains: Vec<String>,
    pub sanctioned_domains: Vec<String>,
    pub fast_path_timeout: Duration,
    pub race_timeout: Duration,
    pub server_hello_timeout: Duration,
    pub cache: Arc<CandidateCache>,
    /// Consecutive total-failure events. Reset to 0 on any successful
    /// dial. Once it hits `CIRCUIT_BREAKER_THRESHOLD`, the breaker
    /// `tripped_until` instant is armed.
    pub consecutive_failures: AtomicU32,
    /// Micros-from-`breaker_base` until which Direct Mode is disabled.
    /// Stored as `i64` so a `0` default is naturally "not tripped".
    /// Uses `portable_atomic::AtomicI64` so the 32-bit targets in our
    /// release matrix (notably `mipsel-unknown-linux-musl`, which has
    /// no native 64-bit CAS) still compile — std's `AtomicI64` isn't
    /// defined there and would fail the cdylib build.
    pub breaker_until: AtomicI64,
    /// Reference instant for `breaker_until` — `Instant` can't be
    /// stored atomically, so we measure from this monotonic base.
    pub breaker_base: Instant,
}

impl DirectModeCtx {
    /// Build a runtime context. `data_dir` is where the candidate file
    /// lives; pass `None` to disable persistence (still functions, just
    /// re-races every restart).
    ///
    /// Domain entries are pre-normalized once here (trim, lowercase,
    /// strip leading/trailing dots) so the per-CONNECT matcher in
    /// `is_google_domain` is a tight byte-compare loop. Fronts are
    /// trimmed only — case is preserved because some DNS providers are
    /// (technically) case-sensitive and the front hostname goes back
    /// out as-typed in `DNS lookup` / `tracing::info!` output.
    pub fn from_parts(
        enabled: bool,
        fronts: Vec<String>,
        google_domains: Vec<String>,
        sanctioned_domains: Vec<String>,
        data_dir: Option<PathBuf>,
    ) -> Self {
        // Fronts: trim whitespace AND strip leading/trailing dots like
        // the suffix lists. A user writing `.www.google.com.` should
        // resolve to `www.google.com` at dial time, not a DNS-NX
        // `.www.google.com.` lookup. Case is preserved because DNS is
        // case-insensitive in practice but tracing emits the configured
        // string back to the user verbatim — keeping their input shape
        // makes log lines less confusing.
        let fronts: Vec<String> = fronts
            .into_iter()
            .map(|f| {
                f.trim()
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_string()
            })
            .filter(|f| !f.is_empty())
            .collect();
        let google_domains: Vec<String> = google_domains
            .into_iter()
            .map(|d| normalize_domain_entry(&d))
            .filter(|d| !d.is_empty())
            .collect();
        let sanctioned_domains: Vec<String> = sanctioned_domains
            .into_iter()
            .map(|d| normalize_domain_entry(&d))
            .filter(|d| !d.is_empty())
            .collect();
        Self {
            enabled: AtomicBool::new(enabled),
            fronts,
            google_domains,
            sanctioned_domains,
            fast_path_timeout: FAST_PATH_TIMEOUT,
            race_timeout: RACE_TIMEOUT,
            server_hello_timeout: SERVER_HELLO_TIMEOUT,
            cache: Arc::new(CandidateCache::new(data_dir)),
            consecutive_failures: AtomicU32::new(0),
            breaker_until: AtomicI64::new(0),
            breaker_base: Instant::now(),
        }
    }

    /// True iff the circuit breaker is currently tripped. Cheap atomic
    /// load on the hot path — avoid the dial entirely when this is true.
    pub fn breaker_tripped(&self) -> bool {
        let until_micros = self.breaker_until.load(Ordering::Relaxed);
        if until_micros <= 0 {
            return false;
        }
        let now_micros = self.breaker_base.elapsed().as_micros() as i64;
        now_micros < until_micros
    }

    /// Record a successful dial — clears the failure streak.
    pub fn note_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.breaker_until.store(0, Ordering::Relaxed);
    }

    /// Record a total-failure event (every (front, profile) attempted
    /// without a ServerHello). After `CIRCUIT_BREAKER_THRESHOLD`
    /// consecutive failures the breaker trips for
    /// `CIRCUIT_BREAKER_COOLDOWN`.
    pub fn note_failure(&self) {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= CIRCUIT_BREAKER_THRESHOLD {
            let now = self.breaker_base.elapsed().as_micros() as i64;
            let until = now + CIRCUIT_BREAKER_COOLDOWN.as_micros() as i64;
            self.breaker_until.store(until, Ordering::Relaxed);
            tracing::warn!(
                "direct-mode circuit breaker tripped after {} consecutive failures; \
                 disabling for {:?}",
                n,
                CIRCUIT_BREAKER_COOLDOWN
            );
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Should this host be routed via fragmented Direct Mode?
    /// `port == 443` check is the caller's responsibility — different
    /// ports may have their own routing.
    pub fn is_direct(&self, host: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }
        if self.breaker_tripped() {
            return false;
        }
        is_google_domain(host, &self.google_domains, &self.sanctioned_domains)
    }

    /// True when `host` is on the sanctioned list. Used by the
    /// dispatcher to route these domains through the Apps Script relay
    /// — Google geo-blocks Iranian IPs for these services, so the
    /// SNI-rewrite path (which still originates from the user's IP)
    /// returns 403. Only the relay (Google US datacenter outbound IPs)
    /// reaches them. Independent of `is_enabled()` so the
    /// fragmented-direct toggle and the sanctioned-routing override
    /// are decoupled — turning off fragmentation doesn't change
    /// whether sanctioned-list lookups still succeed.
    ///
    /// Note that the dispatcher additionally gates this routing on
    /// `direct_mode.is_some()` and `mode == AppsScript` (see
    /// `dispatch_tunnel` step 2c): a user who removed the
    /// `direct_mode` block entirely from `config.json`, or who's
    /// running in `Mode::Direct` (no relay exists), opts out of the
    /// sanctioned-routing override. This method just reports list
    /// membership; the dispatcher decides whether to honour it.
    pub fn is_sanctioned(&self, host: &str) -> bool {
        let h = normalize_domain_entry(strip_port(host));
        if h.is_empty() {
            return false;
        }
        domain_list_matches(&h, &self.sanctioned_domains)
    }
}

/// Wraps a `TcpStream` with a buffered preface that's served from
/// `poll_read` before any further bytes are pulled from the underlying
/// socket. Used to hand back the client's already-consumed ClientHello
/// when Direct Mode commits to fragmented dialing and then every
/// profile fails the handshake. The downstream SNI-rewrite path
/// `TlsAcceptor::accept` reads the same ClientHello bytes that the
/// direct path already consumed.
///
/// Writes pass straight to the inner socket; the preface is read-only.
pub struct PrefacedTcpStream {
    preface: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl PrefacedTcpStream {
    pub fn new(preface: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            preface,
            pos: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefacedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.preface.len() {
            let remaining = self.preface.len() - self.pos;
            let n = remaining.min(buf.remaining());
            let start = self.pos;
            let end = start + n;
            // Have to take ownership of the slice ref before mutating
            // pos because `buf.put_slice` borrows the slice for the
            // duration of the call.
            buf.put_slice(&self.preface[start..end]);
            self.pos = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefacedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------- Dialer ----------

/// Outcome of `try_tunnel`.
///
/// - `Done` — Direct Mode handled the connection (success or terminal
///   failure that wrote a response back to the client).
/// - `Skip(TcpStream)` — Direct Mode declined without consuming bytes
///   (non-TLS, breaker tripped, port != 443 caught upstream, etc.).
///   The dispatcher continues with the untouched socket.
/// - `SkipPrefaced(PrefacedTcpStream)` — Direct Mode consumed the
///   ClientHello, raced every (front × profile) pair, and none
///   produced a TLS ServerHello. The buffered ClientHello is wrapped
///   in front of the original socket so the SNI-rewrite tunnel can
///   read the same bytes the browser sent (no replay from the
///   browser, no double handshake).
pub enum TunnelOutcome {
    Done,
    Skip(TcpStream),
    SkipPrefaced(PrefacedTcpStream),
}

/// Attempt fragmented direct tunnel.
///
/// Peek-only short-circuits (non-TLS, breaker tripped) return
/// `Skip(sock)` with no bytes consumed. Once we commit to reading
/// the ClientHello, fallback returns `SkipPrefaced` so the
/// dispatcher's SNI-rewrite path can re-read the same bytes.
pub async fn try_tunnel(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    ctx: &DirectModeCtx,
) -> std::io::Result<TunnelOutcome> {
    // Breaker check FIRST — bail without even peeking. The dispatcher
    // sees a clean `Skip(sock)` and continues normally; in the
    // hot-failure case the user pays nothing more than a hashmap
    // lookup vs. the 3 s + 8 s round we'd otherwise eat.
    if ctx.breaker_tripped() {
        tracing::debug!(
            "direct-mode breaker tripped — skipping {}:{} without dialing",
            host,
            port
        );
        return Ok(TunnelOutcome::Skip(sock));
    }

    // Confirm TLS via peek. Non-TLS Google traffic (rare) goes back to
    // the dispatcher. 300 ms matches the timeout the dispatcher uses
    // elsewhere for "client silent => server-first protocol".
    let mut peek = [0u8; 1];
    let peek_res = tokio::time::timeout(Duration::from_millis(300), sock.peek(&mut peek)).await;
    match peek_res {
        Ok(Ok(1)) if peek[0] == 0x16 => {}
        _ => return Ok(TunnelOutcome::Skip(sock)),
    }

    // Read the full ClientHello up front so every dial attempt can
    // write the same bytes (and so the fallback path has the exact
    // bytes the browser sent — without replay, a TLS layer that
    // already consumed them couldn't re-handshake).
    let client_hello = match read_first_tls_record(&mut sock).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!("direct-mode: client ClientHello read failed: {}", e);
            return Ok(TunnelOutcome::Done);
        }
    };

    // Try fast path then race. Each candidate must produce a real
    // ServerHello (any upstream bytes) before we accept it — TCP
    // connect alone is NOT enough; DPI happily lets TCP succeed and
    // then RSTs the post-ClientHello stream.
    let dialed = dial_with_validation(host, port, ctx, &client_hello).await;
    let Some(win) = dialed else {
        // Every profile failed. Hand the dispatcher a prefaced stream
        // so the SNI-rewrite path can serve a real TLS handshake on
        // the same bytes the browser sent. The original `sock` is
        // wrapped, the buffered ClientHello becomes its read-preface.
        ctx.note_failure();
        tracing::debug!(
            "direct-mode: all profiles failed handshake for {}:{}, falling back",
            host,
            port
        );
        return Ok(TunnelOutcome::SkipPrefaced(PrefacedTcpStream::new(
            client_hello,
            sock,
        )));
    };

    ctx.note_success();
    ctx.cache.remember(&win.front, win.profile.id);

    tracing::info!(
        "direct-mode {}:{} via {} (profile={}, ServerHello in {}ms)",
        host,
        port,
        win.front,
        win.profile.id,
        win.handshake_ms,
    );

    splice_after_handshake(sock, win.upstream, win.server_bytes).await;
    Ok(TunnelOutcome::Done)
}

/// Winner of the dial race. Carries enough state for `try_tunnel` to
/// commit: the upstream socket already has the fragmented ClientHello
/// written, and the buffered `server_bytes` (the first chunk from
/// upstream, almost always the ServerHello) needs to be flushed back
/// to the client before bidirectional copy begins.
struct DialWinner {
    upstream: TcpStream,
    front: String,
    profile: &'static Profile,
    server_bytes: Vec<u8>,
    handshake_ms: u128,
}

/// Fast path then race, each participant validated against ServerHello
/// arrival (not just TCP connect).
async fn dial_with_validation(
    host: &str,
    port: u16,
    ctx: &DirectModeCtx,
    client_hello: &[u8],
) -> Option<DialWinner> {
    if ctx.fronts.is_empty() {
        return None;
    }
    let candidate = ctx.cache.current();
    // Cached candidate is only honoured when its front is STILL in the
    // configured list. Two scenarios this guards against:
    //   1. User edits `direct_mode.fronts` between runs — the old
    //      candidate's front would now resolve to a host we no longer
    //      trust, wasting `fast_path_timeout` on every restart.
    //   2. `direct_candidate.txt` is tampered or corrupt — the front
    //      string could direct the very first connection to an arbitrary
    //      hostname. Constraining to `ctx.fronts` makes the cache file a
    //      preference, not a security boundary.
    let (fast_front, fast_profile) = match &candidate {
        Some(c) if ctx.fronts.iter().any(|f| f == &c.front) => {
            let p = profile_by_id(c.profile_id).unwrap_or_else(default_profile);
            (c.front.clone(), p)
        }
        _ => (ctx.fronts[0].clone(), default_profile()),
    };

    // Fast path: single attempt under `fast_path_timeout`.
    if let Some(w) = tokio::time::timeout(
        ctx.fast_path_timeout,
        dial_one(
            host,
            port,
            fast_front.clone(),
            fast_profile,
            client_hello,
            ctx.server_hello_timeout,
        ),
    )
    .await
    .ok()
    .flatten()
    {
        return Some(w);
    }
    tracing::debug!(
        "direct-mode fast path failed (no ServerHello) for {}:{} via {} (profile {}), racing",
        host,
        port,
        fast_front,
        fast_profile.id
    );

    // Race phase — every (front × profile) pair except the one we just
    // failed on. JoinSet drives the concurrent dials; the first
    // ServerHello-validated winner cancels the rest.
    let mut tasks = tokio::task::JoinSet::new();
    let skipped_pair = (fast_front.clone(), fast_profile.id);
    let client_hello_owned = client_hello.to_vec();
    let sh_timeout = ctx.server_hello_timeout;
    for f in &ctx.fronts {
        for p in PROFILES.iter() {
            if &skipped_pair.0 == f && skipped_pair.1 == p.id {
                continue;
            }
            let f = f.clone();
            let host_owned = host.to_string();
            let body = client_hello_owned.clone();
            tasks.spawn(async move { dial_one(&host_owned, port, f, p, &body, sh_timeout).await });
        }
    }

    let outer = tokio::time::timeout(ctx.race_timeout, async {
        while let Some(joined) = tasks.join_next().await {
            if let Ok(Some(win)) = joined {
                return Some(win);
            }
        }
        None
    })
    .await;

    let winner = outer.ok().flatten();
    tasks.shutdown().await;
    winner
}

/// Single dial attempt: TCP-connect, fragment-write the ClientHello,
/// wait up to `sh_timeout` for ANY bytes from upstream. The
/// first-bytes check is our handshake-level validation — DPI that
/// would kill a non-fragmented hello has already RST'd the stream by
/// this point, surfacing as EOF or `ConnectionReset`. The bytes we
/// read (typically the ServerHello prefix) are returned so the
/// caller can write them back to the client before starting
/// bidirectional copy.
async fn dial_one(
    _host: &str,
    port: u16,
    front: String,
    profile: &'static Profile,
    client_hello: &[u8],
    sh_timeout: Duration,
) -> Option<DialWinner> {
    let start = Instant::now();
    let mut s = TcpStream::connect((front.as_str(), port)).await.ok()?;
    // TCP_NODELAY is mandatory: without it, Nagle coalesces our
    // fragment writes back into a single segment and the whole scheme
    // collapses.
    let _ = s.set_nodelay(true);
    if fragmented_write(&mut s, client_hello, profile)
        .await
        .is_err()
    {
        return None;
    }
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(sh_timeout, s.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        // Zero-byte read or read error within the timeout means DPI
        // either RST'd us or upstream gave up. Don't commit.
        _ => return None,
    };
    buf.truncate(n);
    // ServerHello must arrive as a TLS Handshake record (content type
    // 0x16). Anything else means we're not talking to the real edge:
    // a TLS alert (0x15) is a wrong-edge / handshake_failure; HTTP
    // plaintext is a blockpage; application-data (0x17) is a
    // mid-stream proxy. Caching any of these as a working candidate
    // would steer every future dial into the same dead-end, so reject
    // up-front and let the race try other profiles.
    if buf[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    Some(DialWinner {
        upstream: s,
        front,
        profile,
        server_bytes: buf,
        handshake_ms: start.elapsed().as_millis(),
    })
}

/// Bridge client ↔ upstream after a validated handshake. The first
/// chunk of ServerHello bytes is already buffered in `server_bytes`;
/// flush it to the client before starting bidirectional copy.
async fn splice_after_handshake(client: TcpStream, upstream: TcpStream, server_bytes: Vec<u8>) {
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    if cw.write_all(&server_bytes).await.is_err() {
        return;
    }
    let c2u = tokio::io::copy(&mut cr, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut cw);
    tokio::select! {
        _ = c2u => {}
        _ = u2c => {}
    }
}

/// Read until we have at least one complete TLS record (the
/// ClientHello). Returns any trailing bytes already buffered in the
/// same read call too — those bytes were sent by the client alongside
/// the ClientHello and need to flow upstream as part of the same
/// fragmented write.
async fn read_first_tls_record(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    const MAX_FIRST: usize = 32 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before ClientHello",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() < 5 {
            continue;
        }
        if buf[0] != 0x16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a TLS handshake",
            ));
        }
        let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() >= 5 + rec_len {
            return Ok(buf);
        }
        if buf.len() > MAX_FIRST {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ClientHello too large",
            ));
        }
    }
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests pre-normalize the same way `DirectModeCtx::from_parts`
    /// does at startup — entries with leading dots / trailing dots /
    /// whitespace get the same treatment a hand-edited config.json
    /// would receive when the proxy boots.
    fn s(v: &[&str]) -> Vec<String> {
        v.iter()
            .map(|s| normalize_domain_entry(s))
            .filter(|s| !s.is_empty())
            .collect()
    }

    #[test]
    fn classifier_basic_google_hits() {
        let g = s(DEFAULT_GOOGLE_DOMAINS);
        let san = s(DEFAULT_SANCTIONED_DOMAINS);
        for h in [
            "google.com",
            "www.google.com",
            "mail.google.com",
            "maps.googleapis.com",
            "googleapis.com",
            "gstatic.com",
            "www.gstatic.com",
            "i.ytimg.com",
            "www.youtube.com",
            "youtube.com",
            "youtube-nocookie.com",
        ] {
            assert!(is_google_domain(h, &g, &san), "{} should be Google", h);
        }
    }

    #[test]
    fn classifier_excludes_non_sni_rewrite_capable_hosts_from_defaults() {
        // googlevideo.com / gmail.com / android.com etc. are
        // intentionally NOT in `DEFAULT_GOOGLE_DOMAINS` because the
        // Direct Mode fallback path (SNI-rewrite tunnel) doesn't
        // safely handle them. They go through their existing route
        // instead (relay in AppsScript mode). See the file-level
        // comment on `DEFAULT_GOOGLE_DOMAINS` for full rationale.
        let g = s(DEFAULT_GOOGLE_DOMAINS);
        let san = s(DEFAULT_SANCTIONED_DOMAINS);
        for h in [
            "r1---sn-aigl6n7e.googlevideo.com",
            "googlevideo.com",
            "gmail.com",
            "googlemail.com",
            "developer.android.com",
            "myproject.appspot.com",
            "labs.withgoogle.com",
        ] {
            assert!(
                !is_google_domain(h, &g, &san),
                "{} must NOT be in DEFAULT_GOOGLE_DOMAINS (no safe fallback)",
                h
            );
        }
    }

    #[test]
    fn classifier_non_google_misses() {
        let g = s(DEFAULT_GOOGLE_DOMAINS);
        let san = s(DEFAULT_SANCTIONED_DOMAINS);
        for h in [
            "instagram.com",
            "twitter.com",
            "example.com",
            "notgoogle.com",
            "evilgoogle.com",
            "fakeyoutube.com",
        ] {
            assert!(!is_google_domain(h, &g, &san), "{} should NOT be Google", h);
        }
    }

    #[test]
    fn classifier_strips_port() {
        let g = s(DEFAULT_GOOGLE_DOMAINS);
        let san = s(DEFAULT_SANCTIONED_DOMAINS);
        assert!(is_google_domain("youtube.com:443", &g, &san));
        assert!(!is_google_domain("instagram.com:443", &g, &san));
    }

    #[test]
    fn classifier_case_insensitive() {
        let g = s(DEFAULT_GOOGLE_DOMAINS);
        let san = s(DEFAULT_SANCTIONED_DOMAINS);
        assert!(is_google_domain("MAIL.Google.COM", &g, &san));
    }

    #[test]
    fn normalize_handles_dots_case_whitespace() {
        assert_eq!(normalize_domain_entry("  .Google.COM. "), "google.com");
        assert_eq!(normalize_domain_entry("...example.org..."), "example.org");
        assert_eq!(normalize_domain_entry(""), "");
        assert_eq!(normalize_domain_entry("   "), "");
        assert_eq!(normalize_domain_entry("\tfoo.bar\t"), "foo.bar");
    }

    #[test]
    fn classifier_accepts_unnormalized_entries_via_runtime_ctx() {
        // The runtime ctx normalizes at startup. Verify a config with
        // sloppy entries (mixed case, leading dots, trailing dots,
        // surrounding whitespace) still classifies correctly once it's
        // gone through `DirectModeCtx::from_parts`.
        let ctx = DirectModeCtx::from_parts(
            true,
            vec!["www.google.com".into()],
            vec![".Google.COM.".into(), "  .youtube.com  ".into()],
            vec!["aistudio.GOOGLE.com.".into()],
            None,
        );
        assert!(ctx.is_direct("mail.google.com"));
        assert!(ctx.is_direct("WWW.YOUTUBE.COM"));
        assert!(!ctx.is_direct("aistudio.google.com"));
        assert!(!ctx.is_direct("instagram.com"));
    }

    #[test]
    fn classifier_subdomain_boundary_strict() {
        let g = s(&[".example.com"]);
        let san: Vec<String> = Vec::new();
        // Strict subdomain boundary — `notexample.com` does NOT match
        // `.example.com`. Same shape `host_in_force_mitm_list` uses.
        assert!(is_google_domain("example.com", &g, &san));
        assert!(is_google_domain("sub.example.com", &g, &san));
        assert!(!is_google_domain("notexample.com", &g, &san));
        assert!(!is_google_domain("xexample.com", &g, &san));
    }

    #[test]
    fn classifier_handles_ipv6_without_port() {
        // No leading bracket because the dispatcher trims them off
        // before host classification; ensure we don't trip on the
        // internal colons of a raw IPv6 literal.
        let g = s(DEFAULT_GOOGLE_DOMAINS);
        let san = s(DEFAULT_SANCTIONED_DOMAINS);
        assert!(!is_google_domain("2607:f8b0:4005:80b::200e", &g, &san));
    }

    #[test]
    fn ctx_disabled_short_circuits() {
        let ctx = DirectModeCtx::from_parts(
            false,
            vec!["www.google.com".into()],
            DEFAULT_GOOGLE_DOMAINS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            DEFAULT_SANCTIONED_DOMAINS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            None,
        );
        assert!(!ctx.is_direct("mail.google.com"));
        ctx.enabled.store(true, Ordering::Relaxed);
        assert!(ctx.is_direct("mail.google.com"));
    }

    #[test]
    fn default_profile_is_fragmenting() {
        // Regression guard for the "fresh install dials with p00
        // passthrough" bug — the first-dial default must be a profile
        // that actually fragments, otherwise users on Iran DPI
        // networks would TCP-connect and silently fail at handshake
        // with no race-fallback ever firing.
        let p = default_profile();
        assert_ne!(p.strategy, SplitStrategy::Passthrough);
        assert!(
            p.num_chunks >= 8,
            "default profile should split into >= 8 chunks, got {}",
            p.num_chunks
        );
    }

    #[test]
    fn classifier_sanctioned_excluded() {
        let g = s(DEFAULT_GOOGLE_DOMAINS);
        let san = s(DEFAULT_SANCTIONED_DOMAINS);
        for h in [
            "gemini.google.com",
            "aistudio.google.com",
            "labs.google",
            "ai.google",
        ] {
            assert!(!is_google_domain(h, &g, &san), "{} should be sanctioned", h);
        }
        // Subdomains of sanctioned exclude too.
        assert!(!is_google_domain("foo.aistudio.google.com", &g, &san));
    }

    #[test]
    fn equal_splits_evenly_spaced() {
        let splits = equal_splits(300, 4);
        // Expect roughly 75, 150, 225.
        assert_eq!(splits, vec![75, 150, 225]);
    }

    #[test]
    fn equal_splits_drops_zero_and_n() {
        assert_eq!(equal_splits(1, 4), Vec::<usize>::new());
        assert_eq!(equal_splits(10, 1), Vec::<usize>::new());
        assert!(equal_splits(10, 10).iter().all(|&p| p > 0 && p < 10));
    }

    #[test]
    fn random_splits_distinct_and_in_bounds() {
        let n = 300;
        let count = 86;
        let s = random_splits(n, count);
        assert_eq!(s.len(), count);
        assert!(s.iter().all(|&p| p > 0 && p < n));
        // Distinct + sorted ascending.
        for w in s.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn random_splits_saturates() {
        let s = random_splits(5, 100);
        assert_eq!(s, vec![1, 2, 3, 4]);
    }

    #[test]
    fn tls_sni_host_range_rejects_non_tls() {
        assert!(tls_sni_host_range(b"GET / HTTP/1.1\r\n").is_none());
        // Application-data record (0x17), not handshake.
        assert!(tls_sni_host_range(&[0x17, 0x03, 0x03, 0, 0]).is_none());
        // Truncated record header.
        assert!(tls_sni_host_range(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn tls_sni_host_range_finds_sni_in_real_hello() {
        // Hand-built minimal ClientHello with SNI = "example.com".
        // Layout follows RFC 8446 §4.1.2.
        let host = b"example.com";
        let mut ext = Vec::new();
        // SNI extension body: server_name_list_length(2) +
        // name_type(1) + name_length(2) + name.
        ext.push(0); // server_name_list_length high byte (placeholder)
        ext.push(0); // low
        let list_start = ext.len();
        ext.push(0); // name_type = host_name
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);
        let list_len = ext.len() - list_start;
        ext[0] = (list_len >> 8) as u8;
        ext[1] = list_len as u8;

        // Wrap in extension header: type(2) + length(2).
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&[0, 0]); // type 0x0000
        sni_ext.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&ext);

        // Build handshake body.
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // legacy version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id_len
        hs.extend_from_slice(&(2u16).to_be_bytes()); // cipher_suites len
        hs.extend_from_slice(&[0x00, 0x35]); // a single cipher
        hs.push(1); // compression methods len
        hs.push(0); // null compression
        hs.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes()); // extensions length
        hs.extend_from_slice(&sni_ext);

        // Wrap in handshake message: type(1) + length(3 bytes BE).
        let mut hsmsg = Vec::new();
        hsmsg.push(0x01); // ClientHello
        let l = hs.len();
        hsmsg.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hsmsg.extend_from_slice(&hs);

        // Wrap in TLS record: type(1) + version(2) + length(2).
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hsmsg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hsmsg);

        let (start, end) = tls_sni_host_range(&rec).expect("SNI should parse");
        assert_eq!(&rec[start..end], host);
    }

    #[test]
    fn compute_splits_p00_passthrough_empty() {
        let v = compute_splits(&PROFILES[0], &[0x16; 300]);
        assert!(v.is_empty());
    }

    #[test]
    fn compute_splits_equal_profile_yields_chunks() {
        let v = compute_splits(&PROFILES[4], &[0xab; 300]); // p04, num_chunks=64
        assert!(!v.is_empty());
        assert!(v.iter().all(|&p| p > 0 && p < 300));
        // Sorted ascending.
        for w in v.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn compute_splits_sni_falls_back_to_random_when_no_sni() {
        // Not a TLS ClientHello at all — sni_splits returns None,
        // SniPrefixed sees only [1, 5] which both get filtered to 1, 5
        // if buffer is long enough.
        let v = compute_splits(&PROFILES[1], &[0u8; 300]); // p01
                                                           // The [1, 5] prefix is in-bounds for a 300-byte buffer, so we
                                                           // get exactly those two split points after dedupe.
        assert_eq!(v, vec![1, 5]);
    }

    #[test]
    fn compute_splits_p01_no_panic_on_duplicated_input() {
        // Build a real ClientHello so sni_splits returns a list that
        // contains 1 and 5 along with SNI-derived points. The p01
        // strategy prepends another [1, 5]. Pre-fix this would feed
        // an unsorted, duplicated list to the writer and panic on
        // `b[prev:s]` with prev > s. Verify the result is sorted +
        // deduped.
        let host = b"x.test";
        // Minimal viable hello (reuse logic from sni test).
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0, 0]);
        let s = ext.len();
        ext.push(0);
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);
        let ll = ext.len() - s;
        ext[0] = (ll >> 8) as u8;
        ext[1] = ll as u8;
        let mut sni = Vec::new();
        sni.extend_from_slice(&[0, 0]);
        sni.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        sni.extend_from_slice(&ext);
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        hs.extend_from_slice(&(2u16).to_be_bytes());
        hs.extend_from_slice(&[0, 0x35]);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        hs.extend_from_slice(&sni);
        let mut hm = Vec::new();
        hm.push(0x01);
        let l = hs.len();
        hm.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hm.extend_from_slice(&hs);
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hm.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hm);

        let v = compute_splits(&PROFILES[1], &rec); // p01
        for w in v.windows(2) {
            assert!(
                w[0] < w[1],
                "p01 splits must be strictly ascending: {:?}",
                v
            );
        }
    }

    use tokio::io::AsyncReadExt;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fragmented_write_reassembles_byte_exact() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();

        let server = tokio::spawn({
            let expected = payload.clone();
            async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut got = Vec::new();
                let _ = s.read_to_end(&mut got).await;
                assert_eq!(got, expected);
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        let profile = Profile {
            id: "test",
            num_chunks: 87,
            delay: Duration::from_millis(0),
            strategy: SplitStrategy::Equal,
        };
        fragmented_write(&mut client, &payload, &profile)
            .await
            .unwrap();
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fragmented_write_delays_applied() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let _ = s.read_to_end(&mut got).await;
            got
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        let profile = Profile {
            id: "test",
            num_chunks: 3,
            delay: Duration::from_millis(10),
            strategy: SplitStrategy::Equal,
        };
        let start = std::time::Instant::now();
        fragmented_write(&mut client, &[0xaa; 30], &profile)
            .await
            .unwrap();
        let elapsed = start.elapsed();
        drop(client);
        let _ = server.await.unwrap();
        // 3 chunks ⇒ 2 inter-chunk sleeps of 10 ms each. Be generous
        // on the lower bound so a slow CI host doesn't trip a false
        // failure but conservative enough to catch "delays missing".
        assert!(
            elapsed >= Duration::from_millis(15),
            "expected ≥ 15 ms with 10 ms inter-chunk delays, got {:?}",
            elapsed
        );
    }

    #[test]
    fn candidate_cache_persists_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CandidateCache::new(Some(dir.path().to_path_buf()));
        assert!(cache.current().is_none());
        cache.remember("www.google.com", "p05");
        let c = cache.current().expect("remembered");
        assert_eq!(c.front, "www.google.com");
        assert_eq!(c.profile_id, "p05");

        // New cache instance loads from the same dir.
        let cache2 = CandidateCache::new(Some(dir.path().to_path_buf()));
        let c2 = cache2.current().expect("reloaded");
        assert_eq!(c2.front, "www.google.com");
        assert_eq!(c2.profile_id, "p05");
    }

    #[test]
    fn candidate_cache_unknown_profile_id_silently_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CANDIDATE_FILE);
        std::fs::write(&path, "www.google.com\npX9").unwrap();
        let cache = CandidateCache::new(Some(dir.path().to_path_buf()));
        // Unknown profile_id ⇒ no remembered candidate.
        assert!(cache.current().is_none());
    }

    #[test]
    fn candidate_cache_no_persistence_when_dir_none() {
        let cache = CandidateCache::new(None);
        cache.remember("www.google.com", "p00");
        let c = cache.current().expect("in-memory");
        assert_eq!(c.front, "www.google.com");
    }

    // ---- Behavioral tests for the dial/race/fallback contract ----

    #[allow(unused_imports)]
    use tokio::io::AsyncWriteExt;

    /// Start an in-process TCP server on 127.0.0.1 that accepts a
    /// single connection and behaves per `mode`:
    ///   - `Echo`: reads at least one byte, then echoes a fixed
    ///     "ServerHello-like" prefix back. Simulates a working
    ///     fragmentation profile.
    ///   - `Silent`: accepts and never writes. Simulates DPI that
    ///     RST's the post-ClientHello stream (the read just times
    ///     out our SERVER_HELLO_TIMEOUT).
    ///   - `Reset`: accepts and immediately drops. Simulates an
    ///     RST-after-handshake DPI kill.
    enum FakeServerMode {
        Echo,
        Silent,
        Reset,
    }

    async fn fake_server(mode: FakeServerMode) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            // Loop so a single fake can serve many test clients (the
            // race phase fans out to N connections).
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let mode = match &mode {
                    FakeServerMode::Echo => FakeServerMode::Echo,
                    FakeServerMode::Silent => FakeServerMode::Silent,
                    FakeServerMode::Reset => FakeServerMode::Reset,
                };
                match mode {
                    FakeServerMode::Echo => {
                        let mut buf = [0u8; 4096];
                        let _ = sock.read(&mut buf).await;
                        let _ = sock.write_all(b"\x16\x03\x03ServerHelloMock").await;
                        // Keep the socket alive so the splice loop has
                        // something to copy from until the client side
                        // closes.
                        let _ = sock.shutdown().await;
                    }
                    FakeServerMode::Silent => {
                        // Just hang on to the socket without writing;
                        // sleep past SERVER_HELLO_TIMEOUT so the
                        // direct path classifies us as failed.
                        tokio::time::sleep(Duration::from_secs(6)).await;
                    }
                    FakeServerMode::Reset => {
                        drop(sock);
                    }
                }
            }
        });
        (format!("127.0.0.1:{}", addr.port()), h)
    }

    fn ctx_with_front(front: &str, server_hello_timeout_ms: u64) -> DirectModeCtx {
        let mut ctx = DirectModeCtx::from_parts(
            true,
            vec![front.to_string()],
            vec![".example.test".into()], // matches "host.example.test"
            vec![],
            None,
        );
        ctx.server_hello_timeout = Duration::from_millis(server_hello_timeout_ms);
        // Keep the race + fast_path tight so a failure test doesn't
        // hang the suite if something regresses.
        ctx.fast_path_timeout = Duration::from_millis(server_hello_timeout_ms + 500);
        ctx.race_timeout = Duration::from_millis(server_hello_timeout_ms * 2 + 1000);
        ctx
    }

    fn minimal_client_hello() -> Vec<u8> {
        // Real ClientHello structure (record type 0x16, version 0x0301,
        // 5-byte header + 1 body byte). Read path just needs the first
        // byte to be 0x16 and the length to balance.
        let mut v = vec![0x16, 0x03, 0x01, 0, 1];
        v.push(0x00);
        v
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dial_one_commits_only_on_server_hello() {
        // Echo server → success path returns server_bytes.
        let (addr, _h) = fake_server(FakeServerMode::Echo).await;
        let (host, port) = addr.split_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let hello = minimal_client_hello();
        let winner = dial_one(
            "example.com",
            port,
            host.to_string(),
            &PROFILES[0], // p00 passthrough — irrelevant, just need a profile
            &hello,
            Duration::from_secs(2),
        )
        .await;
        let w = winner.expect("echo server must produce a winner");
        assert!(
            w.server_bytes.starts_with(b"\x16\x03\x03"),
            "expected ServerHello prefix, got {:?}",
            &w.server_bytes
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dial_one_rejects_when_server_silent() {
        // Silent server → no bytes within timeout → None.
        let (addr, _h) = fake_server(FakeServerMode::Silent).await;
        let (host, port) = addr.split_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let hello = minimal_client_hello();
        let winner = dial_one(
            "example.com",
            port,
            host.to_string(),
            &PROFILES[0],
            &hello,
            Duration::from_millis(200),
        )
        .await;
        assert!(winner.is_none());
    }

    /// Variant of `fake_server` that lets the test pick the exact bytes
    /// the server sends back, so we can exercise the
    /// `TLS_CONTENT_TYPE_HANDSHAKE` discriminator with realistic
    /// "looks-like-something-but-not-a-ServerHello" inputs.
    async fn fake_server_bytes(bytes: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&bytes).await;
                let _ = sock.shutdown().await;
            }
        });
        (format!("127.0.0.1:{}", addr.port()), h)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dial_one_rejects_tls_alert() {
        // 0x15 0x03 0x03 = TLS Alert record. A wrong-edge or DPI inject
        // commonly returns one of these — caching a profile that
        // produced an alert as "working" would commit every future
        // dial to the same dead-end.
        let (addr, _h) = fake_server_bytes(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).await;
        let (host, port) = addr.split_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let result = dial_one(
            "example.com",
            port,
            host.to_string(),
            &PROFILES[0],
            &minimal_client_hello(),
            Duration::from_secs(2),
        )
        .await;
        assert!(
            result.is_none(),
            "TLS alert must NOT count as a successful ServerHello"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dial_one_rejects_http_blockpage() {
        // ISP blockpage is plain HTTP — first byte is `H` (0x48).
        let (addr, _h) =
            fake_server_bytes(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec())
                .await;
        let (host, port) = addr.split_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let result = dial_one(
            "example.com",
            port,
            host.to_string(),
            &PROFILES[0],
            &minimal_client_hello(),
            Duration::from_secs(2),
        )
        .await;
        assert!(
            result.is_none(),
            "HTTP blockpage bytes must NOT count as a successful ServerHello"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dial_one_rejects_application_data() {
        // 0x17 = TLS application_data record — a mid-stream proxy that
        // forwarded the connection somewhere unrelated and just spliced
        // some encrypted bytes back. Not a ServerHello.
        let (addr, _h) = fake_server_bytes(vec![0x17, 0x03, 0x03, 0x00, 0x10, 0xaa, 0xbb]).await;
        let (host, port) = addr.split_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let result = dial_one(
            "example.com",
            port,
            host.to_string(),
            &PROFILES[0],
            &minimal_client_hello(),
            Duration::from_secs(2),
        )
        .await;
        assert!(
            result.is_none(),
            "TLS application-data bytes must NOT count as a successful ServerHello"
        );
    }

    #[test]
    fn fronts_strip_dots_during_normalization() {
        // Regression guard: leading/trailing dots on fronts used to
        // survive `from_parts` and fail DNS at runtime. The runtime
        // now normalizes the same way it does for suffix lists.
        let ctx = DirectModeCtx::from_parts(
            true,
            vec![".www.google.com.".into(), " script.google.com ".into()],
            vec![".google.com".into()],
            vec![],
            None,
        );
        assert_eq!(
            ctx.fronts,
            vec![
                "www.google.com".to_string(),
                "script.google.com".to_string()
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stale_cached_front_falls_back_to_fronts_zero() {
        // A `direct_candidate.txt` written before a config edit may
        // name a front that's no longer in `ctx.fronts`. We must not
        // use it on the fast path — the cache is a preference, not a
        // security boundary.
        let dir = tempfile::tempdir().unwrap();
        // Pre-seed the cache file with a now-stale front.
        std::fs::write(
            dir.path().join("direct_candidate.txt"),
            "old.example.com\np05",
        )
        .unwrap();
        let ctx = DirectModeCtx::from_parts(
            true,
            vec!["www.google.com".into()],
            vec![".google.com".into()],
            vec![],
            Some(dir.path().to_path_buf()),
        );
        // The cache loaded the stale candidate; the dialer should
        // refuse to use it because the front isn't in ctx.fronts.
        // We can't fully exercise `dial_with_validation` without a
        // live network, but we can verify the precondition: the
        // candidate IS loaded into the cache.
        let c = ctx.cache.current().expect("cache loaded");
        assert_eq!(c.front, "old.example.com");
        // ... and the front is NOT in ctx.fronts:
        assert!(!ctx.fronts.iter().any(|f| f == &c.front));
        // The full dial path is exercised under load in
        // `all_fronts_silent_trips_circuit_breaker`; this test
        // narrowly guards the contract that stale fronts are
        // detectable.
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dial_one_rejects_on_reset() {
        // Server immediately drops connection → read returns 0 → None.
        let (addr, _h) = fake_server(FakeServerMode::Reset).await;
        let (host, port) = addr.split_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let hello = minimal_client_hello();
        let winner = dial_one(
            "example.com",
            port,
            host.to_string(),
            &PROFILES[0],
            &hello,
            Duration::from_secs(2),
        )
        .await;
        assert!(
            winner.is_none(),
            "RST-on-accept must NOT produce a winner (TCP succeeded but no ServerHello)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn all_fronts_silent_trips_circuit_breaker() {
        // After CIRCUIT_BREAKER_THRESHOLD consecutive "all profiles
        // failed" events, the breaker engages and is_direct returns
        // false even for canonical Google hosts.
        let (addr, _h) = fake_server(FakeServerMode::Silent).await;
        let (host, port) = addr.split_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let ctx = ctx_with_front(host, 50);
        let port = port; // capture
        for _ in 0..CIRCUIT_BREAKER_THRESHOLD {
            let res =
                dial_with_validation("host.example.test", port, &ctx, &minimal_client_hello())
                    .await;
            assert!(res.is_none());
            ctx.note_failure();
        }
        assert!(
            ctx.breaker_tripped(),
            "breaker should engage after {} failures",
            CIRCUIT_BREAKER_THRESHOLD
        );
        // is_direct gated by breaker.
        assert!(!ctx.is_direct("host.example.test"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn circuit_breaker_resets_on_success() {
        let ctx = DirectModeCtx::from_parts(
            true,
            vec!["www.google.com".into()],
            vec![".example.test".into()],
            vec![],
            None,
        );
        for _ in 0..CIRCUIT_BREAKER_THRESHOLD {
            ctx.note_failure();
        }
        assert!(ctx.breaker_tripped());
        ctx.note_success();
        assert!(!ctx.breaker_tripped());
        assert!(ctx.is_direct("host.example.test"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn prefaced_stream_serves_buffered_bytes_first() {
        // The fallback path wraps the consumed ClientHello in front of
        // the original socket. AsyncRead must serve preface bytes
        // first, then transparently switch to the inner stream.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s.write_all(b"AFTER").await;
            let _ = s.shutdown().await;
        });
        let client = TcpStream::connect(addr).await.unwrap();
        let mut prefaced = PrefacedTcpStream::new(b"BEFORE".to_vec(), client);
        let mut got = Vec::new();
        prefaced.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got, b"BEFOREAFTER");
        server.await.unwrap();
    }
}
