# Use rahgozar as upstream proxy (Psiphon, xray, browsers)

🇮🇷 نسخهٔ فارسی: [docs/use-as-upstream.fa.md](use-as-upstream.fa.md)

rahgozar runs a local HTTP proxy on `127.0.0.1:8085` and a SOCKS5 proxy on
`127.0.0.1:8086` (Android defaults: HTTP `8080`, SOCKS5 `1081`). Any tool
with an upstream-proxy setting can route through it.

The common case: Psiphon's bootstrap servers are blocked, so you point
Psiphon's upstream proxy at rahgozar, and Psiphon's first hop reaches its
network through rahgozar's fronted-SNI tunnel.

## Use `direct` mode

`apps_script` and `full` modes try to send every host through the Apps
Script relay, which doesn't speak Psiphon's binary protocol. `direct`
mode skips the relay: SNI-rewrite for hosts rahgozar knows, raw TCP for
everything else. That's what Psiphon needs — its own crypto stays
end-to-end and cert pinning isn't broken.

Pick **Direct (no relay)** in the desktop UI / Android app, or set:

```jsonc
{
  "mode": "direct",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086
}
```

## Psiphon — Windows / macOS / Linux

1. Start rahgozar in `direct` mode. The host:port appears under the Start
   button — click **copy**.
2. Psiphon → **Options** → **Proxy settings** → **Upstream proxy**.
3. Check **Connect through an upstream proxy**.
4. **Hostname:** `127.0.0.1`. **Port:** `8085`. **Type:** `HTTP`. (Or
   SOCKS5 on port `8086`.)
5. **Save**, then **Connect** in Psiphon.

## Psiphon — Android

Android allows only one active VPN at a time, and Psiphon needs that slot.
Before starting: open rahgozar and switch **Connection mode** to
**PROXY_ONLY** (under Network). In PROXY_ONLY mode, rahgozar runs only the
local proxy listeners, leaving the VPN slot free for Psiphon.

1. Open rahgozar, set Connection mode to `PROXY_ONLY`, pick `Direct` mode,
   tap **Connect**. The host:port is shown under the Connect button — tap
   **copy**.
2. Psiphon app → **Options** → **Proxy** → **Upstream proxy**.
3. **Host:** `127.0.0.1`. **Port:** `8080` (HTTP) or `1081` (SOCKS5).
4. Connect in Psiphon.

## xray / v2ray

Add an `http` (or `socks`) outbound pointing at rahgozar:

```jsonc
{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "http",
      "settings": {
        "servers": [
          { "address": "127.0.0.1", "port": 8085 }
        ]
      }
    }
  ]
}
```

## Browsers / SwitchyOmega

Point the proxy at `127.0.0.1:8085`. Nothing else to configure.

## Troubleshooting

- **Psiphon stuck at "Connecting…"** — confirm rahgozar is in `direct`
  mode and the port matches what you typed into Psiphon. The recent log
  in the rahgozar UI shows each CONNECT; you should see Psiphon's hosts
  there as `raw-tcp (direct mode: no relay)`.
- **A specific host gets MITM'd when you don't want it to** — add it to
  `passthrough_hosts` in `config.json`. That list overrides every other
  dispatch decision.
- **Chain the other way (rahgozar's outbound through Psiphon or xray)** —
  set `upstream_socks5` in `config.json` to that tool's local SOCKS5
  port. Raw-TCP / passthrough flows then exit through it. Apps Script
  relay traffic still goes through the Google edge by design.

## See also

- [docs/fronting-groups.md](fronting-groups.md) — add non-Google CDNs
  (Vercel, Fastly, Netlify) to the SNI-rewrite path.
- [docs/guide.md#direct-mode](guide.md#direct-mode) — full `direct` mode
  reference.
