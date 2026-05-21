# Full Tunnel — complete setup walkthrough

> *Persian / فارسی: [full-tunnel-setup.fa.md](./full-tunnel-setup.fa.md)*

This is the only document you need to set up Full Tunnel mode from zero. ~15 minutes if you have a VPS already, ~25 minutes including renting one. By the end **all** your traffic — Telegram, YouTube, any app — routes through the tunnel.

You'll set up three pieces:

```text
your device                    Google                       your VPS
┌──────────┐  TLS to Google   ┌──────────┐   HTTPS         ┌────────────┐
│ rahgozar │ ────────────────▶│ Apps     │ ───────────────▶│ tunnel-node│ ─▶ Internet
│ (client) │   (fronted)      │ Script   │  (CodeFull.gs)  │ (Docker)   │
└──────────┘                  └──────────┘                 └────────────┘
   Step 4                       Step 3                        Step 2
```

For background (architecture, performance, deployment-ID scaling) see [guide.md → Full Tunnel mode](guide.md#full-tunnel-mode). This document only covers setup.

## What you need

- A **Google account** (a Gmail address). One account = 30 concurrent tunnel requests. You can scale by adding more later (step 6).
- A **VPS** with a public IPv4 address. Any provider works. Cheapest tier is fine — ~30 MB RAM, no CPU baseline. Recommendations:
  - **Hetzner CX22** (€4–5/mo, Falkenstein/Helsinki, 20 TB egress) — best value for EU/MENA users.
  - **DigitalOcean basic droplet** ($6/mo, NYC/SFO) — best for US users.
  - **Iranian users**: if your ISP filters the VPS IP (you can't `ping` it from home), use [Google Cloud Run](../tunnel-node/README.md#cloud-run) instead — the destination IP becomes Google's, invisible to your ISP. See [#313](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/313). The rest of this guide is still useful for the Apps Script + client config parts.
- **rahgozar** installed on the device you want to tunnel from. See the [README](../README.md) if you haven't already.

Pick **Ubuntu 22.04 LTS** or **Debian 12** when the VPS provider asks for an OS image — the commands below assume one of those.

## Step 1 — SSH into your VPS

From your laptop terminal:

```bash
ssh root@<VPS_IP>
```

Replace `<VPS_IP>` with the IPv4 address your VPS provider gave you. If the provider gave you a separate non-root user, use that instead and prefix the rest of the commands with `sudo`.

## Step 2 — Install Docker and run tunnel-node

Still in the VPS shell. Three commands:

```bash
# A. Install Docker (Ubuntu/Debian one-liner)
curl -fsSL https://get.docker.com | sh

# B. Generate two random secrets. Save the output somewhere safe —
#    you'll paste both into Apps Script in step 3.
echo "CLIENT_SECRET = $(openssl rand -hex 24)"
echo "TUNNEL_SECRET = $(openssl rand -hex 24)"

# C. Run tunnel-node. Paste the TUNNEL_SECRET value from step B
#    in place of <TUNNEL_SECRET> below.
docker run -d \
  --name rahgozar-tunnel \
  --restart unless-stopped \
  -p 8080:8080 \
  -e TUNNEL_AUTH_KEY="<TUNNEL_SECRET>" \
  ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
```

Tag scheme: `:latest` tracks the most recent release, `:1.8` follows the latest 1.8.x, `:1.8.0` pins an exact version. Pin a specific tag in production if you want predictable upgrades. Versions: <https://github.com/dazzling-no-more/rahgozar/releases>.

> What the two secrets are for:
> - **`CLIENT_SECRET`** authenticates *your rahgozar client* to *Apps Script*.
> - **`TUNNEL_SECRET`** authenticates *Apps Script* to *your VPS tunnel-node*.
> Different secrets, different legs of the chain. Don't mix them up.

### Open the firewall

If `ufw` is enabled on your VPS (DigitalOcean enables it; Hetzner doesn't by default):

```bash
ufw allow 22/tcp     # keep SSH open!
ufw allow 8080/tcp   # tunnel-node
ufw reload
```

Many cloud providers also have a **separate firewall in their web console** (DO Cloud Firewall, AWS Security Group, GCP VPC firewall). Open TCP/8080 there too if applicable.

### Verify it's reachable

From your laptop (**not** the VPS — open a second terminal):

```bash
curl http://<VPS_IP>:8080/health
# expected output: ok
```

If you don't see `ok`, the firewall is still blocking — fix that before continuing.

## Step 3 — Deploy CodeFull.gs as an Apps Script Web App

Now go to your laptop browser. Keep the `CLIENT_SECRET` and `TUNNEL_SECRET` values from step 2 handy.

1. Open <https://script.google.com> and sign in with the Google account you want to use.
2. Click **+ New project** (top-left).
3. The editor opens with a placeholder `Code.gs` file. Select everything in it (Ctrl+A) and delete.
4. Get the contents of [`CodeFull.gs`](../assets/apps_script/CodeFull.gs):
   - **In another tab**, open <https://github.com/dazzling-no-more/rahgozar/blob/main/assets/apps_script/CodeFull.gs>
   - Click the **"Copy raw file"** button (clipboard icon at the top-right of the file view). This puts the full file content in your clipboard.
   - *(Shortcut: if your network reaches `raw.githubusercontent.com`, you can open <https://raw.githubusercontent.com/dazzling-no-more/rahgozar/main/assets/apps_script/CodeFull.gs> directly, select all, copy.)*
5. Paste into the empty Apps Script editor (Ctrl+V).
6. Near the top of the file, find these three lines:

   ```js
   const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
   const TUNNEL_SERVER_URL = "https://YOUR_TUNNEL_NODE_URL";
   const TUNNEL_AUTH_KEY = "YOUR_TUNNEL_AUTH_KEY";
   ```

   Edit them to:

   ```js
   const AUTH_KEY = "<CLIENT_SECRET from step 2>";
   const TUNNEL_SERVER_URL = "http://<VPS_IP>:8080";
   const TUNNEL_AUTH_KEY = "<TUNNEL_SECRET from step 2>";
   ```

7. Rename the project: click **"Untitled project"** at the top, type `rahgozar` (or anything you like), press Enter.
8. Save: **Ctrl+S** (or click the floppy-disk icon).
9. Click **Deploy** (top-right blue button) → **New deployment**.
10. Click the **gear icon** next to "Select type" → choose **Web app**.
11. Fill in:
    - **Description**: `rahgozar` (anything)
    - **Execute as**: **Me** (your email)
    - **Who has access**: **Anyone** ← important, must be "Anyone", not "Anyone with a Google account"
12. Click **Deploy**.
13. Google will ask you to **authorize**. Because this is an unverified app, you'll see scary warnings:
    - Click **Authorize access** → pick your account
    - "Google hasn't verified this app" → click **Advanced** → **Go to rahgozar (unsafe)** → **Allow**

    *(This warning is normal for any personal Apps Script project. Your code only runs in your own account.)*

14. You'll see a **Deployment ID** that looks like `AKfycbz...` (about 50 characters). **Copy it.** You'll paste it into the client config in step 4.

Done with this account. *If you only need one account, skip to step 4.* To scale later, see [step 6](#step-6--add-more-accounts-optional).

## Step 4 — Configure the rahgozar client

On the device you want to tunnel from, edit your rahgozar `config.json`. Minimum config (desktop):

```json
{
  "mode": "full",
  "script_id": "<Deployment ID from step 3>",
  "auth_key": "<CLIENT_SECRET from step 2>",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086
}
```

The `listen_host`/`listen_port`/`socks5_port` lines aren't strictly required — the defaults are `0.0.0.0:8085` (HTTP) and `8086` (SOCKS5). Pinning to `127.0.0.1` makes the proxy localhost-only so other devices on your LAN can't accidentally use it. If you *want* LAN sharing (e.g. to share the tunnel from a desktop to your phone), keep `0.0.0.0` and skip those three lines — see [Sharing via hotspot](guide.md#sharing-via-hotspot).

Key mapping:

| Place | Variable name | Value |
|---|---|---|
| VPS (`docker run -e ...`) | `TUNNEL_AUTH_KEY` | TUNNEL_SECRET |
| CodeFull.gs line 17 | `TUNNEL_AUTH_KEY` | TUNNEL_SECRET (same) |
| CodeFull.gs line 15 | `AUTH_KEY` | CLIENT_SECRET |
| rahgozar config.json | `auth_key` | CLIENT_SECRET (same) |
| CodeFull.gs line 16 | `TUNNEL_SERVER_URL` | `http://<VPS_IP>:8080` |
| rahgozar config.json | `script_id` | Apps Script Deployment ID |

**Config file location** depends on platform:

- **Linux/macOS/Windows desktop**: pass `--config /path/to/config.json` on the command line, or place it next to the binary.
- **Android**: open the app and use the GUI fields (Mode = Full, Script ID, Auth Key). The listen-host/port fields above don't apply on Android — the VpnService routes traffic without a local proxy port.

Full schema and all fields are in [`config.full.example.json`](../config.full.example.json).

## Step 5 — Test it

Start rahgozar. The log should show something like:

```
INFO mode=full script_ids=1
INFO Apps Script reachable, deployment_id=AKfycbz...
INFO HTTP proxy : 127.0.0.1:8085
INFO SOCKS5 proxy: 127.0.0.1:8086
```

Then point a browser at the rahgozar proxy (HTTP `127.0.0.1:8085` or SOCKS5 `127.0.0.1:8086`) and visit any site. First request takes ~2 seconds (Apps Script cold path); subsequent ones are faster.

Test quickly without a browser:

```bash
# From your laptop:
curl -x http://127.0.0.1:8085 https://api.ipify.org
# Expected: an IP that belongs to your VPS provider (not your real IP)
```

If you see your VPS provider's IP, **the tunnel works**. End-to-end.

## Step 6 — Add more accounts (optional)

One Google account = 30 concurrent requests. For heavy use, add more:

1. Sign out of Google, sign in with a second account (or use a separate browser profile).
2. Repeat **step 3** entirely (paste the same CodeFull.gs, same `CLIENT_SECRET`, same `TUNNEL_SERVER_URL`, same `TUNNEL_SECRET`). The three constants stay identical across accounts; only the Deployment ID changes.
3. Copy the new Deployment ID.
4. Update `config.json` — `script_id` becomes an array:

   ```json
   {
     "mode": "full",
     "script_id": ["AKfyc...1", "AKfyc...2", "AKfyc...3"],
     "auth_key": "<CLIENT_SECRET>"
   }
   ```

Rough sizing: 1–2 accounts solo / browsing, 3–6 accounts for shared or heavy use, up to 12 for power users. See [guide.md → How deployment IDs affect performance](guide.md#how-deployment-ids-affect-performance).

## Updating tunnel-node later

On the VPS:

```bash
docker pull ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
docker rm -f rahgozar-tunnel
docker run -d --name rahgozar-tunnel --restart unless-stopped \
  -p 8080:8080 -e TUNNEL_AUTH_KEY="<TUNNEL_SECRET>" \
  ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
```

Pin a specific tag (e.g. `:1.8.0`) instead of `:latest` if you want stable upgrades. Versions: <https://github.com/dazzling-no-more/rahgozar/releases>.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `curl http://<VPS_IP>:8080/health` hangs | Cloud-provider firewall blocks 8080 — open it in the provider's web console (not just `ufw`) |
| `curl /health` → `Connection refused` | Container isn't running. On VPS: `docker ps` (should list `rahgozar-tunnel`); `docker logs rahgozar-tunnel` for errors |
| Client connects but every request fails with `unauthorized` / `502` | One of the two secrets doesn't match. Check: `CLIENT_SECRET` is identical in `config.json` `auth_key` and `CodeFull.gs` `AUTH_KEY`; `TUNNEL_SECRET` is identical in `docker run -e TUNNEL_AUTH_KEY=` and `CodeFull.gs` `TUNNEL_AUTH_KEY` |
| Client reports `script_id ... not deployed` | You forgot to publish after editing CodeFull.gs. **Deploy → Manage deployments → ✏️ edit → New version → Deploy** |
| Tunnel works but ChatGPT / Claude / Grok / x.com show CAPTCHA | Expected — those sites block Google datacenter IPs. Deploy an [exit node](../assets/exit_node/README.md) (5 min, free tier) |
| `curl /health` works from your laptop, but rahgozar still can't reach the Apps Script | Your ISP is filtering Google Apps Script entirely. Use [direct mode](guide.md#direct-mode) for Google traffic, or move tunnel-node to [Cloud Run](../tunnel-node/README.md#cloud-run) |
| Want to see explicit errors instead of decoy 404s | Set `MHRV_DIAGNOSTIC=1` on the container env (`-e MHRV_DIAGNOSTIC=1`) **temporarily**. Turn off before sharing publicly |

## HTTP vs HTTPS for tunnel-node

The `http://<VPS_IP>:8080` setup above is the simple path and what most users start with — but it has a real tradeoff worth understanding before you decide.

**What HTTP exposes:** the Apps Script → tunnel-node leg crosses the public Internet in plaintext. Anyone with visibility on that path (Google's outbound infrastructure, transit ISPs, your VPS provider's network, anyone with a packet capture on the VPS) can see:

- The `TUNNEL_AUTH_KEY` (shipped in every request body)
- The hostnames and request payloads that the tunnel is fetching on your behalf

The user-side leg (your device → Apps Script) is still TLS-to-Google and stays domain-fronted. The censorship-bypass property is unaffected. What's at risk is **secrecy of the tunnel auth key and request contents** against network-path observers.

For most users (personal use, low-stakes browsing) plaintext is acceptable. For shared deployments, sensitive traffic, or anyone who wants stronger end-to-end secrecy, run HTTPS in front of tunnel-node.

### Adding HTTPS with Caddy

If you own a domain pointing at the VPS, [Caddy](https://caddyserver.com/) is the simplest option — it gets a Let's Encrypt certificate automatically:

```caddy
tunnel.your-domain.com {
    reverse_proxy localhost:8080
}
```

Then:

1. Change `TUNNEL_SERVER_URL` in CodeFull.gs to `https://tunnel.your-domain.com` (and re-deploy the script).
2. Bind tunnel-node to localhost only so it's not reachable directly: change the `-p 8080:8080` flag to `-p 127.0.0.1:8080:8080` and recreate the container.
3. Close port 8080 on the public firewall — only 80/443 stay open for Caddy.

## Reference

- [tunnel-node/README.md](../tunnel-node/README.md) — protocol details, Cloud Run deployment, docker-compose, building from source
- [guide.md → Full Tunnel mode](guide.md#full-tunnel-mode) — architecture, performance characteristics, deployment-ID scaling math
- [assets/apps_script/README.md](../assets/apps_script/README.md) — about the three .gs variants (Code.gs vs CodeFull.gs vs Code.cfw.gs)
