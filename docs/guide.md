# rahgozar — Full guide

This is the long version — every config option, every advanced mode, every troubleshooting tip. For the 5-minute quick start, see the [main README](../README.md).

[Persian version (راهنمای فارسی)](guide.fa.md)

## Contents

- [How it works in detail](#how-it-works-in-detail)
- [Platforms and binaries](#platforms-and-binaries)
- [Where files live on disk](#where-files-live-on-disk)
- [Apps Script deployment](#apps-script-deployment)
  - [Cloudflare Worker variant (faster)](#cloudflare-worker-variant)
  - [Direct mode (when ISP blocks `script.google.com`)](#direct-mode)
  - [Local Bypass mode (all-host DPI bypass, no relay, no cert)](#local-bypass-mode)
- [CLI reference](#cli-reference)
  - [scan-ips API mode](#scan-ips-api-mode)
- [Telegram via xray](#telegram-via-xray)
- [Full Tunnel mode](#full-tunnel-mode)
  - [How deployment IDs affect performance](#how-deployment-ids-affect-performance)
  - [Setup walkthrough](#setup)
- [Exit node — for ChatGPT / Claude / Grok](#exit-node)
- [Sharing via hotspot](#sharing-via-hotspot)
- [Running on OpenWRT or any musl distro](#running-on-openwrt)
- [Diagnostics](#diagnostics)
  - [SNI pool editor](#sni-pool-editor)
- [What's implemented and what isn't](#whats-implemented-and-what-isnt)
- [Known limitations](#known-limitations)
- [Security posture](#security-posture)
- [FAQ](#faq)

## How it works in detail

```text
Browser / Telegram / xray
        |
        | HTTP proxy (8085)  or  SOCKS5 (8086)
        v
rahgozar (local)
        |
        | TLS to Google IP, SNI = www.google.com
        v                       ^
   DPI sees www.google.com      |
        |                       | Host: script.google.com (inside TLS)
        v                       |
  Google edge frontend ---------+
        |
        v
  Apps Script relay (your free Google account)
        |
        v
  Real destination
```

The censor's DPI inspects the TLS SNI and lets `www.google.com` through. Google's edge serves both `www.google.com` and `script.google.com` from the same IP and routes by the HTTP `Host` header inside the encrypted stream.

For Google-owned domains (`google.com`, `youtube.com`, `fonts.googleapis.com`, …) the same tunnel is used directly — no Apps Script relay. This bypasses the per-fetch quota and avoids the locked-in `Google-Apps-Script` User-Agent for those sites. Add more domains via the `hosts` map in `config.json`.

## Platforms and binaries

Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64), **Android 7.0+** (universal APK covering arm64, armv7, x86_64, x86). Prebuilt binaries on the [releases page](https://github.com/dazzling-no-more/rahgozar/releases).

**Android:** download `rahgozar-android-universal-v*.apk`. Full walk-through in [docs/android.md](android.md) (English) or [docs/android.fa.md](android.fa.md) (Persian). The Android build runs the same `rahgozar` Rust crate as desktop (via JNI) plus a TUN bridge via `tun2proxy` so every app on the device routes its IP traffic through the proxy without per-app config.

> **Important Android caveat (issues [#74](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/74) / [#81](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/81)):** TUN captures all IP traffic, but HTTPS from third-party apps only works for apps that trust user-installed CAs. From Android 7+ apps must opt in via `networkSecurityConfig`. **Chrome and Firefox do**; **Telegram, WhatsApp, Instagram, YouTube, banking apps, games** do not. For those: use `PROXY_ONLY` mode and point in-app proxy at `127.0.0.1:1081` (SOCKS5), or use `google_only` mode (no CA, Google services only), or set `upstream_socks5` to an external VPS. This is an Android security design, not a bug.

### What's in a release

Each archive contains:

| file | purpose |
|---|---|
| `rahgozar` / `rahgozar.exe` | CLI. Headless use, servers, automation. No system deps on macOS / Windows. |
| `rahgozar-desktop-*.msi` / `.dmg` / `.AppImage` / `.deb` | Platform-native installer for the **desktop UI** (Tauri-bundled). Replaces the previous egui `rahgozar-ui` binary as of v2.4. |

macOS users: install via the `.dmg` and drag rahgozar to Applications. First launch needs `rahgozar --install-cert` (CLI binary) once to install the MITM CA. Windows / Linux users run the installer normally; the desktop UI installs the CA from inside the app.

Linux UI also needs `libxkbcommon`, `libwayland-client`, `libxcb`, `libgl`, `libx11`, `libgtk-3`. On most desktop distros these are already there; on a headless box install them via your package manager, or just use the CLI.

## Where files live on disk

Config and the MITM CA live in the OS user-data dir:

- macOS: `~/Library/Application Support/rahgozar/`
- Linux: `~/.config/rahgozar/`
- Windows: `%APPDATA%\rahgozar\`

Inside that dir:

- `config.json` — your settings (written by the UI's **Save** button or hand-edited)
- `ca/ca.crt`, `ca/ca.key` — the MITM root certificate. Only you have the private key.

The CLI also falls back to `./config.json` in the current working directory for backward compatibility.

## Apps Script deployment

The 5-minute version is in the [main README](../README.md#step-1--make-the-google-apps-script-one-time). This section covers the variants.

### Cloudflare Worker variant

A variant in [`assets/apps_script/Code.cfw.gs`](../assets/apps_script/Code.cfw.gs) + [`assets/cloudflare/worker.js`](../assets/cloudflare/worker.js) turns Apps Script into a thin forwarder and offloads the actual `fetch` to a Cloudflare Worker you deploy. **Day-one win:** latency (~10–50 ms at the CF edge vs ~250–500 ms in Apps Script — visibly snappier for browsing and Telegram).

It does **not** reduce your daily 20k Apps Script `UrlFetchApp` count, because today's rahgozar always sends single-URL relay requests; the batch path on the GAS+Worker side is wired and ready (`ceil(N/40)` quota per N-URL batch) but no shipping client emits it.

**Trade-offs:**

- Worse for YouTube long-form (30 s wall clock vs 6 min Apps Script)
- Doesn't fix Cloudflare anti-bot
- **Not compatible with `mode: "full"`** (no tunnel-ops support → won't help WhatsApp / messengers on Android Full mode)

Full setup and trade-off table in [`assets/cloudflare/README.md`](../assets/cloudflare/README.md). rahgozar needs no config changes — same `mode: "apps_script"`, same `script_id`, same `auth_key`.

### Direct mode

If your ISP is already blocking Google Apps Script (or all of Google), you need Step 1 to succeed *before* you have a relay. rahgozar ships a `direct` mode for exactly this — no Apps Script relay required. Google traffic uses TLS-fragmentation direct dial (browser does real TLS to Google, no MITM cert needed) and falls back to the SNI-rewrite tunnel if fragmentation can't beat the local DPI. (Was named `google_only` before v1.9 — old name still accepted.)

1. Download the binary (see [main README → Step 2](../README.md#step-2--download-rahgozar))
2. Copy [`config.direct.example.json`](../config.direct.example.json) to `config.json` — no `script_id`, no `auth_key` required
3. Run `rahgozar serve` and set browser HTTP proxy to `127.0.0.1:8085`
4. In `direct` mode, the proxy only routes `*.google.com`, `*.youtube.com`, and other Google-edge hosts (plus any [`fronting_groups`](fronting-groups.md) you've configured) via the SNI-rewrite tunnel. Other traffic goes raw — no Apps Script relay exists yet.
5. Now do Step 1 in your browser (the connection to `script.google.com` will be SNI-fronted). Deploy `Code.gs`, copy the Deployment ID.
6. In the UI / Android app / by editing `config.json`, switch mode to `apps_script`, paste the Deployment ID and your auth key, and restart.

Verify reachability before even starting the proxy: `rahgozar test-sni` probes `*.google.com` directly and works without any config beyond `google_ip` + `front_domain`.

### Local Bypass mode

`local_bypass` is the "fragment everything" sibling of `direct`. Every TLS CONNECT (regardless of destination) gets its real ClientHello split across TCP segments and sent direct to the real destination IP — no Apps Script relay, no SNI-rewrite, no MITM CA install. Non-TLS traffic goes through as raw TCP.

**Pick this when:**

- You want DPI bypass for *every* TLS host, not just Google.
- You don't want to install the MITM CA cert.
- The destinations you care about are DPI-blocked but *not* IP-blocked. (Iran-blocked-by-IP destinations like `claude.ai` / `x.ai` / `chatgpt.com` stay unreachable — local fragmentation cannot help against an IP block. Use `apps_script` or `full` with an exit node for those.)

**Pick `direct` instead when:**

- You only need Google (gmail, drive, search, YouTube). `direct` is faster because non-Google traffic stays as raw TCP (zero overhead), while `local_bypass` adds ~300 ms per TLS handshake to every host for the fragmentation pacing.
- You've configured `fronting_groups` for specific CDN-fronted hosts — `local_bypass` ignores `fronting_groups` entirely.
- You're using rahgozar as Psiphon's / xray's upstream proxy (see [Use as upstream](use-as-upstream.md)).

**Latency cost.** TLS handshakes pay the fragmentation pacing on every connect — profile p05 (the default) is 87 chunks × 5 ms = ~430 ms of inter-chunk delay on top of the normal TLS RTT. The first connect on a fresh network can be up to 6 s if profile p05 doesn't beat your local DPI and the race phase has to try other profiles; subsequent connects skip straight to whichever profile won. On most Iranian ISPs profile p05 works on the first try, so the typical hit is ~150–500 ms per handshake.

**Cannot bypass IP blocks.** This bears repeating because it's the most common point of confusion. `local_bypass` evades **DPI** (the deep-packet-inspection layer that reads the SNI). It does not change which IPs are reachable. If your ISP firewalls outbound connections to a specific IP range (Iran blocks Anthropic, OpenAI, xAI, and a long list of others at the IP level), local fragmentation cannot route around that. You need a relay (Apps Script in `apps_script` mode) or a tunneled exit (`full` mode + tunnel node).

**Android use.** This is where `local_bypass` shines. With `connection_mode: vpn_tun` (the default), Android's VpnService captures every app's traffic — not just Chrome's — and `local_bypass` then fragments every TLS handshake from every app. Many apps with **certificate pinning** (Google Meet, banking apps, some messengers) that break under the SNI-rewrite MITM in `apps_script` / `direct` modes work fine here because they see the destination's real certificate.

**Config example.** Copy [`config.local_bypass.example.json`](../config.local_bypass.example.json) to `config.json`. No `script_id` or `auth_key` needed.

## CLI reference

Everything the UI does is also in the CLI. Copy `config.example.json` to `config.json` (next to the binary, or in the user-data dir):

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "PASTE_YOUR_DEPLOYMENT_ID_HERE",
  "auth_key": "same-secret-as-in-code-gs",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086,
  "log_level": "info",
  "verify_ssl": true
}
```

Then:

```bash
./rahgozar                   # serve (default)
./rahgozar test              # one-shot end-to-end probe
./rahgozar scan-ips          # rank Google frontend IPs by latency
./rahgozar test-sni          # probe SNI names against your google_ip
./rahgozar --install-cert    # reinstall the MITM CA
./rahgozar --remove-cert     # uninstall + delete the whole ca/ dir
./rahgozar --help
```

`--remove-cert` deletes the CA from the OS trust store, deletes the on-disk `ca/` directory, and verifies the revocation by name. NSS cleanup (Firefox, Chrome on Linux) is best-effort: if `certutil` isn't on PATH or a browser holds the NSS DB open, the tool logs a manual-cleanup hint. Your `config.json` and the Apps Script deployment are untouched, so a fresh CA does not require redeploying `Code.gs`.

> **Upgrading from pre-v1.2.11?** Earlier versions wrote a bare `user_pref("security.enterprise_roots.enabled", true);` into each Firefox profile's `user.js` without a marker. `--remove-cert` does not strip that line — it's indistinguishable from one a user or corp policy wrote. Firefox falls back to its built-in Mozilla root store the moment the MITM CA leaves the OS trust store, so this has no functional effect. Delete by hand if it bothers you.

`script_id` can also be a JSON array: `["id1", "id2", "id3"]`.

### scan-ips API mode

By default, `scan-ips` uses a static list. Enable dynamic IP discovery in `config.json`:

```json
{
  "fetch_ips_from_api": true,
  "max_ips_to_scan": 100,
  "scan_batch_size": 100,
  "google_ip_validation": true
}
```

When enabled:

- Fetches `goog.json` from Google's public IP ranges API
- Extracts CIDRs and expands them to individual IPs
- Prioritizes IPs from famous Google domains (google.com, youtube.com, etc.)
- Randomly selects up to `max_ips_to_scan` candidates (prioritized first)
- Tests only those candidates for connectivity and frontend validation

You may find IPs faster than the static array, but no guarantee they all work.

## Telegram via xray

The Apps Script relay only speaks HTTP request / response, so non-HTTP protocols (Telegram MTProto, IMAP, SSH, raw TCP) can't travel through it. Without anything else, those flows hit the direct-TCP fallback — which means they're not actually tunneled, and an ISP that blocks Telegram still blocks them.

**Fix:** run a local [xray](https://github.com/XTLS/Xray-core) (or v2ray / sing-box) with a VLESS / Trojan / Shadowsocks outbound to your own VPS, and point rahgozar at xray's SOCKS5 inbound via the **Upstream SOCKS5** field (or the `upstream_socks5` config key). When set, raw-TCP flows through rahgozar's SOCKS5 listener get chained into xray → the real tunnel.

```text
Telegram  ┐                                                    ┌─ Apps Script ── HTTP/HTTPS
          ├─ SOCKS5 :8086 ─┤ rahgozar ├─ SNI rewrite ──────── google.com, youtube.com, …
Browser   ┘                                                    └─ upstream SOCKS5 ─ xray ── VLESS ── your VPS   (Telegram, IMAP, SSH, raw TCP)
```

Config fragment:

```json
{
  "upstream_socks5": "127.0.0.1:50529"
}
```

HTTP / HTTPS keeps going through Apps Script (no change), and the SNI-rewrite tunnel for `google.com` / `youtube.com` keeps bypassing both — YouTube stays as fast as before while Telegram gets a real tunnel.

## Full Tunnel mode

`"mode": "full"` routes **all** traffic end-to-end through Apps Script and a remote [tunnel-node](../tunnel-node/) — no MITM certificate needed. TCP carried as persistent tunnel sessions, UDP from Android / TUN clients via SOCKS5 `UDP ASSOCIATE` to the tunnel-node which emits real UDP server-side. Trade-off: higher per-request latency (every byte goes Apps Script → tunnel-node → destination), but works for any protocol and any app, no CA install required.

### How deployment IDs affect performance

Each Apps Script batch round-trip takes ~2 s. In Full mode, rahgozar runs a **pipelined batch multiplexer** that fires multiple batches concurrently without waiting on the previous one. Each Deployment ID (= one Google account) gets its own concurrency pool of **30 in-flight requests** — matching the per-account Apps Script execution limit.

```text
max_concurrent = 30 × number_of_deployment_ids
```

| Deployments | Concurrent | Notes |
|---|---|---|
| 1 | 30 | Single account — fine for light browsing |
| 3 | 90 | Good for daily use |
| 6 | 180 | Recommended for heavy use |
| 12 | 360 | Multi-account power setup |

More deployments = more total concurrency = lower per-session latency. Each batch round-robins across your IDs, spreading load and reducing the chance of hitting any single deployment's quota ceiling.

**Resource guards:**

- **50 ops max** per batch — if more sessions are active, the mux splits into multiple batches
- **4 MB payload cap** per batch — well under Apps Script's 50 MB limit
- **30 s timeout** per batch — slow / dead targets can't block other sessions forever

### Setup

**→ [Full Tunnel — complete setup walkthrough](full-tunnel-setup.md)**

Copy-paste from zero: rent a VPS, install Docker, run tunnel-node, paste CodeFull.gs into Apps Script with click-by-click UI steps, wire all three constants, write `config.json`, test end-to-end. ~15 minutes (~25 with VPS provisioning).

## Exit node

Cloudflare-fronted services (chatgpt.com, claude.ai, grok.com, x.com, openai.com) flag traffic from Google datacenter IPs as bots and serve a Turnstile / CAPTCHA challenge. The exit node fix is a small TypeScript HTTP handler you deploy on a serverless host (Deno Deploy, fly.io, or your own VPS) that sits between Apps Script and the destination:

```text
client → Apps Script (Google IP) → your exit node (non-Google IP) → CF-protected site
```

The destination sees the exit node's IP, not Google's, so the anti-bot heuristic doesn't fire.

**Setup:** [`assets/exit_node/README.md`](../assets/exit_node/README.md). 5 min, free tier.

## Sharing via hotspot

rahgozar listens on `0.0.0.0` by default, so any device on the same network can use it. Common scenario: share the tunnel from an Android phone to an iPhone, iPad, or laptop over hotspot:

1. **Android:** enable mobile hotspot + start the app
2. **Other device:** connect to the Android hotspot Wi-Fi
3. **Configure proxy** on the other device:
   - Server: `192.168.43.1` (Android's default hotspot IP)
   - Port: `8080` (HTTP) or `1081` (SOCKS5)

### iOS

Settings → Wi-Fi → tap (i) on the hotspot network → Configure Proxy → Manual → Server `192.168.43.1`, Port `8080`.

For full device-wide coverage on iOS, use [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) or [Potatso](https://apps.apple.com/app/potatso/id1239860606) — point at SOCKS5 (`192.168.43.1:1081`) and it routes all traffic through the tunnel.

### macOS / Windows

Set system HTTP proxy to `192.168.43.1:8080`, or per-app SOCKS5 to `192.168.43.1:1081`.

> If `listen_host` is `127.0.0.1` in your config, change to `0.0.0.0` to allow other devices.

## Running on OpenWRT

The `*-linux-musl-*` archives ship a fully static CLI that runs on OpenWRT, Alpine, and any libc-less Linux. Put the binary on the router and start as a service:

```sh
# From a machine that can reach your router:
scp rahgozar root@192.168.1.1:/usr/bin/rahgozar
scp rahgozar.init root@192.168.1.1:/etc/init.d/rahgozar
scp config.json root@192.168.1.1:/etc/rahgozar/config.json

# On the router:
chmod +x /usr/bin/rahgozar /etc/init.d/rahgozar
/etc/init.d/rahgozar enable
/etc/init.d/rahgozar start
logread -e rahgozar -f       # tail logs
```

LAN devices then point HTTP proxy at the router's LAN IP (default port `8085`) or SOCKS5 at `<router-ip>:8086`. Set `listen_host` to `0.0.0.0` in `/etc/rahgozar/config.json` so the router accepts LAN connections.

Memory footprint ~15–20 MB resident — fine on anything ≥128 MB RAM. No UI on musl (routers are headless).

## Diagnostics

- **`rahgozar test`** — sends one request through the relay, reports success / latency. First thing to try when something breaks — separates "relay is up" from "client config is wrong".
- **`rahgozar scan-ips`** — parallel TLS probe of 28 known Google frontend IPs, sorted by latency. Take the winner, put it in `google_ip`. UI has same thing behind **scan** button.
- **`rahgozar test-sni`** — parallel TLS probe of every SNI name in your rotation pool against `google_ip`. Tells you which front-domain names pass through your ISP's DPI. UI has same thing in **SNI pool…** window with checkboxes, per-row **Test** buttons, and **Keep ✓ only** to auto-trim.
- **Periodic stats** logged every 60 s at `info` level (relay calls, cache hit rate, bytes relayed, active vs blacklisted scripts). UI shows live.

### SNI pool editor

By default, rahgozar rotates through `{www, mail, drive, docs, calendar}.google.com` on outbound TLS to your `google_ip`, to avoid fingerprinting one name too heavily. Some may be locally blocked (e.g. `mail.google.com` has been targeted in Iran at various times).

Either:

- UI → **SNI pool…** → **Test all** → **Keep ✓ only** to auto-trim. Add custom names via the text field at the bottom. Save.
- Or edit `config.json`:

```json
{
  "sni_hosts": ["www.google.com", "drive.google.com", "docs.google.com"]
}
```

Leaving `sni_hosts` unset gives you the default auto-pool. Run `rahgozar test-sni` to verify what works from your network.

## Background IP-health monitor (heartbeat)

The relay opens TLS to whatever `google_ip` is set in your config. When an ISP newly filters that specific datacenter range mid-session, all opens fail until you restart and re-run `scan-ips`. The background heartbeat closes that gap automatically.

**What it does.** Every `heartbeat_interval_secs` (default 30 s) the relay sends one TCP+TLS+HEAD probe to `google_ip:443` with an SNI from your rotation pool. On `heartbeat_failure_threshold` (default 3) consecutive failures, it runs the same `scan_ips` pass the `scan-ips` subcommand uses, picks the first reachable candidate that validates against any SNI in your `sni_hosts` pool, swaps `google_ip` in-memory, and clears the connection pool + h2 cache so subsequent opens target the new IP. In-flight requests on the old IP drain naturally. The swap is in-memory only — `config.json` on disk is unchanged.

**Cost.** One TLS handshake every 30 s (≈ 2 KB up + 5 KB down on the wire) when the IP is healthy. No-op when probes succeed.

**Config knobs:**

```json
{
  "heartbeat_enabled": true,
  "heartbeat_interval_secs": 30,
  "heartbeat_failure_threshold": 3
}
```

Defaults match what's shipped. Set `heartbeat_enabled: false` to opt out. Lower `heartbeat_interval_secs` for faster detection on flaky networks; raise it (or raise the threshold) on networks where TLS handshakes are themselves expensive. A threshold of 0 is clamped to 1 with a log warning.

When the swap fires, you'll see `WARN ip-health: swapping <old> -> <new>` in the log. Persistent rescans without a successful swap (`ip-health: rescan found zero reachable IPs`) mean Google is unreachable from your network entirely — restarting won't help, you need a different exit (Full Tunnel + VPS, exit_node, etc.).

## Opt-in brotli / zstd response decoding

By default rahgozar strips `br` and `zstd` from outbound `Accept-Encoding` headers before forwarding to Apps Script. The reason: `UrlFetchApp` auto-decompresses gzip server-side but doesn't recognise br or zstd; if a destination served brotli, Apps Script would deliver raw brotli bytes to the relay, which historically had no decoder and would pass the corrupted bytes to your browser as plaintext.

v2.1+ ships brotli + zstd decoders, gated behind a config flag:

```json
{ "allow_brotli_zstd": true }
```

With the flag on, the relay allows `br` and `zstd` in forwarded `Accept-Encoding`, decodes the response body server-side before the browser sees it, and strips `Content-Encoding` only when decode succeeds (failure or unrecognised chain → header preserved so the browser can try).

**When this helps:** sites whose CDN prefers brotli over gzip. Up to ~20% smaller payloads on the destination → Apps Script leg.

**When this doesn't help much:** most CDNs serving `User-Agent: Mozilla/5.0... Apps-Script` already fall back to gzip. The Apps Script → rahgozar leg is gzipped JSON regardless of what the inner body uses, so wire-level wins end up smaller than the destination-leg numbers suggest.

**Why opt-in:** `UrlFetchApp`'s exact handling of non-gzip encodings is empirically derived rather than documented. Flip on, test your sites, report regressions. Decoded output is capped at 64 MiB to defend against compression-bomb destinations.

## What's implemented and what isn't

This port focuses on the **`apps_script` mode** — the only one that reliably works against a modern censor in 2026. Implemented:

- [x] Local HTTP proxy (CONNECT for HTTPS, plain forwarding for HTTP)
- [x] Local SOCKS5 with smart TLS / HTTP / raw-TCP dispatch (Telegram, xray, etc.)
- [x] MITM with on-the-fly per-domain certs via `rcgen`
- [x] CA generation + auto-install on macOS / Linux / Windows
- [x] Firefox NSS cert install (best-effort via `certutil`)
- [x] Apps Script JSON relay protocol-compatible with `Code.gs`
- [x] Connection pooling (45 s TTL, max 20 idle)
- [x] Gzip response decoding
- [x] Multi-script round-robin
- [x] Auto-blacklist failing scripts on 429 / quota errors (10 min cooldown)
- [x] Response cache (50 MB, FIFO + TTL, `Cache-Control: max-age` aware, heuristics for static assets)
- [x] Request coalescing: concurrent identical GETs share one upstream fetch
- [x] SNI-rewrite tunnels for `google.com`, `youtube.com`, `youtu.be`, `youtube-nocookie.com`, `fonts.googleapis.com`, configurable via `hosts` map
- [x] Automatic redirect handling on the relay (`/exec` → `googleusercontent.com`)
- [x] Header filtering (strip connection-specific, brotli)
- [x] `test` and `scan-ips` subcommands
- [x] Script IDs masked in logs (`prefix…suffix`) so logs don't leak deployment IDs
- [x] Desktop UI (Tauri) — cross-platform native installers (.msi / .dmg / .AppImage / .deb)
- [x] Optional upstream SOCKS5 chaining for non-HTTP traffic (Telegram MTProto, IMAP, SSH…)
- [x] Connection pool pre-warm on startup
- [x] Per-connection SNI rotation across `{www, mail, drive, docs, calendar}.google.com`
- [x] Optional parallel script-ID dispatch (`parallel_relay`): fan-out to N script instances, return first success
- [x] Per-site stats drill-down in the UI (requests, cache hit %, bytes, avg latency per host)
- [x] Editable SNI rotation pool (UI window + `sni_hosts` config field) with reachability probes
- [x] OpenWRT / Alpine / musl builds — static binaries, procd init script included
- [x] **Exit node** support for Cloudflare-fronted sites (v1.9.4+)
- [x] **Goog.script.init iframe unwrap** — defense-in-depth against deployments that return HtmlService-wrapped responses (v1.9.6+)

Intentionally **not** implemented:

- **HTTP/2 multiplexing** — `h2` crate state machine has too many subtle hang cases; coalescing + 20-conn pool gets most of the benefit
- **Request batching (`q:[...]` mode in apps_script mode)** — connection pool + tokio async already parallelizes well; batching adds ~200 lines of state for unclear gain
- **Range-based parallel download** — edge cases real (non-Range servers, chunked mid-stream); YouTube already bypasses Apps Script via SNI-rewrite tunnel
- **Other modes** (`domain_fronting`, `google_fronting`, `custom_domain`) — Cloudflare killed generic domain fronting in 2024; Cloud Run needs a paid plan

## Known limitations

These are inherent to the Apps Script + domain-fronting approach, not bugs in this client. The original Python version has the same issues.

- **User-Agent fixed to `Google-Apps-Script`** for traffic through the relay. `UrlFetchApp.fetch()` doesn't allow override. Sites that detect bots (Google search, some CAPTCHAs) serve degraded / no-JS pages. Workaround: add the affected domain to the `hosts` map so it's routed through the SNI-rewrite tunnel with your real browser's UA. `google.com`, `youtube.com`, `fonts.googleapis.com` are already there.
- **Video playback slow and quota-limited** for anything through the relay. YouTube HTML loads fast (SNI-rewrite tunnel), but `googlevideo.com` chunks go through Apps Script. Free tier: ~20k `UrlFetchApp` calls / day, 50 MB body cap per fetch. Fine for text browsing, painful for 1080p. Rotate multiple `script_id`s for headroom, or use a real VPN for video.
- **Brotli stripped** from forwarded `Accept-Encoding` by default. Apps Script auto-decompresses gzip but not `br`/`zstd`; forwarding either would garble responses. Set `allow_brotli_zstd: true` to opt in to client-side decoding — see [the dedicated section above](#opt-in-brotli--zstd-response-decoding) for trade-offs.
- **WebSockets don't work** through the relay — it's request / response JSON. Sites that upgrade to WS fail (ChatGPT streaming, Discord voice, etc.).
- **HSTS-preloaded / hard-pinned sites** reject the MITM cert. Most sites are fine; a handful aren't.
- **Google / YouTube 2FA and sensitive logins** may trigger "unrecognized device" warnings because requests originate from Google's Apps Script IPs, not yours. Log in once via the tunnel (`google.com` is in the rewrite list) to avoid this.

## Security posture

- The MITM root **stays on your machine only**. `ca/ca.key` private key is generated locally and never leaves the user-data dir.
- `auth_key` is a shared secret you pick. Server-side `Code.gs` rejects requests without a matching key.
- Traffic between your machine and Google's edge is standard TLS 1.3.
- What Google can see: the destination URL and headers of each request (Apps Script fetches on your behalf). Same trust model as any hosted proxy — if not acceptable, use a self-hosted VPN instead.
- **IP exposure caveat (`apps_script` mode):** v1.2.9 strips every `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `Via` / `CF-Connecting-IP` / `True-Client-IP` / `Fastly-Client-IP` and ~10 related identity-revealing headers from outbound before reaching Apps Script ([#104](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/104)). What it does **not** cover: whatever Google's own infrastructure may add when its Apps Script runtime makes the subsequent `UrlFetchApp.fetch()` to the target. That second leg is server-side, outside this client's control. Destination sees a Google datacenter IP, but no public guarantee Google never propagates the original caller's IP in some internal header chain. If your threat model requires the destination cannot under any circumstances learn your IP, **use Full Tunnel mode** (traffic exits from your own VPS, only the VPS IP is exposed end-to-end). `apps_script` mode is fine for bypassing DPI / reaching blocked sites where "seen by Google" is acceptable. Raised in [#148](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/148).
- v1.9.6+ Code.gs / CodeFull.gs also strip `X-Forwarded-*` / `Forwarded` / `Via` server-side as a second line of defense.

## FAQ

**How many Deployment IDs do I need?** One is fine for normal use. The free `UrlFetchApp` quota is 20,000 fetches / day per account (100,000 for paid Workspace), with a 50 MB body cap per fetch. Use **one deployment per Google account** — the 30-concurrent limit is per account, so multiple deployments on the same account don't add concurrency. To scale, deploy in different Google accounts. Reference: <https://developers.google.com/apps-script/guides/services/quotas>

**Why does Google search show without JavaScript sometimes?** Apps Script is forced to set `User-Agent: Google-Apps-Script`. Some sites detect that and serve no-JS fallback. Domains in the SNI-rewrite list (`google.com`, `youtube.com`, etc.) are immune because they go directly to Google's edge, not through Apps Script.

**Is logging into a Google account through this safe?** Recommended: log in once **without** the proxy, or with a real VPN, the first time. Google may flag the Apps Script IP as an "unknown device" and warn. After the initial login, use is fine.

**How do I remove the certificate later?**

- **Easiest (any OS):** click **Remove CA** in the UI, or:
  - macOS / Linux: `sudo ./rahgozar --remove-cert`
  - Windows (run as administrator): `rahgozar.exe --remove-cert`
  - Removes from system trust store, NSS (Firefox / Chrome on Linux), and deletes `ca/ca.crt` + `ca/ca.key` on disk. Your `config.json` and Apps Script deployment are not touched.
- **Manually:** the cert's Common Name is `MasterHttpRelayVPN` (not `rahgozar` — that's the app name).
  - **macOS:** Keychain Access → System → search `MasterHttpRelayVPN` → delete. Then `rm -rf ~/Library/Application\ Support/rahgozar/ca/`
  - **Windows:** `certmgr.msc` → Trusted Root Certification Authorities → search `MasterHttpRelayVPN` → delete
  - **Linux:** delete `/usr/local/share/ca-certificates/MasterHttpRelayVPN.crt` then `sudo update-ca-certificates`

**`GLIBC_2.39 not found` error on Linux?** Use `rahgozar-linux-musl-amd64.tar.gz` — fully static, runs on any Linux without `glibc`.

## License

MIT. See [LICENSE](../LICENSE).
