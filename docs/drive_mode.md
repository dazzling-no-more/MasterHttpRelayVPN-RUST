# Drive Mode — complete setup walkthrough

> *Persian / فارسی: [drive_mode.fa.md](./drive_mode.fa.md)*

This is the only document you need to set up Drive Mode from zero. ~20 minutes if you have a VPS already, ~30 minutes including renting one. By the end, your TCP traffic flows through a Google Drive folder you own — your ISP only sees TLS to `*.google.com`.

> **Setup model:** Drive Mode is **BYO OAuth** — rahgozar ships no embedded OAuth client. Before Step 5 below, you'll register your own OAuth client in Google Cloud Console (about 10 minutes, free, one-time): see [drive_oauth_setup.md](./drive_oauth_setup.md) for the step-by-step walkthrough. Rationale: an unverified OAuth client has a 100-user cap on `drive.file` scope; BYO sidesteps it entirely because every user gets their own 100 they never hit.

You'll set up three pieces:

```text
your device (Iran)              Google                   your VPS (abroad)
┌──────────┐  TLS to            ┌──────────┐  HTTPS     ┌──────────────────┐
│ rahgozar │ ─*.google.com────▶ │ Drive    │ ◀── poll ──│ rahgozar-drive-  │─▶ Internet
│ (client) │   (SNI rewrite)    │ API      │            │ relay (systemd)  │
└──────────┘                    └──────────┘            └──────────────────┘
   Step 7                       Shared mailbox             Steps 2–6
                                folder you own
```

For background — why Drive Mode exists alongside Apps Script, how it interacts with the existing SNI-rewrite + domain-fronting machinery — see [guide.md](./guide.md). This document only covers setup.

## When to use Drive Mode vs Apps Script

Apps Script remains the default for most users — it needs no VPS and the relay logic runs free on Google's infrastructure. Drive Mode is the right choice when:

- Apps Script quotas bite (sustained heavy use; multi-account rotation isn't enough).
- Google has flagged your Apps Script deployment (account-level enforcement on Iranian users — happens occasionally).
- You want a separate code path under separate Google enforcement.

What you give up vs Apps Script:
- **A VPS abroad** ($4–6/mo) that runs the relay binary. You don't need a public-IP VPS — the relay only makes outbound connections to Drive + the destinations it forwards to.
- **Higher latency.** Drive doesn't support long-polling, so the client + relay each poll every 100–300 ms. Median web latency is ~500 ms vs ~300 ms on Apps Script.
- **15 GB Drive quota.** Files get deleted after every successful round-trip + an orphan reaper sweeps stragglers, but a runaway flow can fill it. Daily heavy use stays well under 1 GB peak in practice.

## What you need

- A **Google account** (a Gmail address). The same account signs in on both the client AND the relay — they share the Drive folder through that account. (Two different accounts can be made to work but you'd have to share the folder explicitly; not covered here.)
- A **VPS** with normal outbound internet. **No public IPv4 required** — the relay only opens outbound connections. Cheapest tier is fine — ~50 MB RAM, no CPU baseline. Recommendations:
  - **Hetzner CX22** (€4–5/mo, Falkenstein/Helsinki, 20 TB egress) — best value for EU/MENA users.
  - **DigitalOcean basic droplet** ($6/mo, NYC/SFO) — best for US users.
  - **Iranian users**: your VPS's IP is irrelevant in Drive Mode — traffic to Drive goes through Google's edge, not your VPS. Pick wherever is cheapest.
- **rahgozar** installed on the device you want to tunnel from. See the [README](../README.md) if you haven't already.

Pick **Ubuntu 22.04 LTS** or **Debian 12** when the VPS provider asks for an OS image — the commands below assume one of those.

## Step 1 — SSH into your VPS

From your laptop terminal:

```bash
ssh root@<VPS_IP>
```

Replace `<VPS_IP>` with the IPv4 address your VPS provider gave you. If the provider gave you a non-root user, use that and prefix the rest of the commands with `sudo`.

## Step 2 — Install the relay binary

Pick the Linux x86_64 build from the [latest release](https://github.com/dazzling-no-more/rahgozar/releases/latest):

```bash
# Fetch the relay binary + install script + systemd unit.
# Replace VERSION with the release tag (e.g. v2.8.0).
VERSION=<latest tag>
ARCH=$(uname -m)   # likely x86_64; arm64 builds exist too

curl -fsSLo /tmp/rahgozar-drive-relay \
  https://github.com/dazzling-no-more/rahgozar/releases/download/${VERSION}/rahgozar-drive-relay-linux-${ARCH}
chmod +x /tmp/rahgozar-drive-relay

# Install script: creates the `rahgozar-relay` system user, drops the
# binary at /usr/local/bin, installs the systemd unit, and creates a
# 0700-mode config dir at /etc/rahgozar-drive-relay.
curl -fsSLo /tmp/install-drive-relay.sh \
  https://raw.githubusercontent.com/dazzling-no-more/rahgozar/${VERSION}/drive-relay/scripts/install-drive-relay.sh
curl -fsSLo /tmp/rahgozar-drive-relay.service \
  https://raw.githubusercontent.com/dazzling-no-more/rahgozar/${VERSION}/drive-relay/systemd/rahgozar-drive-relay.service

sudo BINARY=/tmp/rahgozar-drive-relay \
  SERVICE_FILE=/tmp/rahgozar-drive-relay.service \
  sh /tmp/install-drive-relay.sh
```

The installer prints the next three commands. They all run as the dedicated `rahgozar-relay` user (NOT root) — running them as root would store the keypair + OAuth token under the wrong owner and the daemon would fail to read them on start.

## Step 3 — Mint the relay's X25519 keypair

```bash
sudo -u rahgozar-relay rahgozar-drive-relay keygen \
  --out /etc/rahgozar-drive-relay/relay.key
```

This writes a 32-byte secret to `relay.key` (mode 0600) and prints the public key on stdout — a 63-character string starting with `rgdr1...`. **Copy it.** You'll paste it into the client app in step 7.

If you ever lose `relay.key`, you must `keygen` again, paste the new pubkey into every client's config, and restart. There's no recovery — the secret only exists on disk.

## Step 4 — Sign in to Google (device-code flow)

If you haven't already, follow [drive_oauth_setup.md](./drive_oauth_setup.md) first to register your own OAuth clients in Google Cloud Console. For the command below, use the **TVs and Limited Input devices** client.

```bash
sudo -u rahgozar-relay rahgozar-drive-relay oauth device-code \
  --client-id     "<your client_id>" \
  --client-secret "<your client_secret>" \
  --out /etc/rahgozar-drive-relay/config.json
```

The relay prints a URL + a short user-code, then polls Google waiting for you to complete the flow:

```
==============================================================
  Open this URL in any browser and enter the code below:

    https://www.google.com/device
    code: ABCD-EFGH

  This flow expires in 1800 seconds.
==============================================================
```

On your laptop or phone, open the URL, paste the code, sign in with the **same Google account** the client app will use, and approve. The relay's SSH session catches the success and writes the refresh token into `/etc/rahgozar-drive-relay/config.json`.

> **What scope does it ask for?** Only `https://www.googleapis.com/auth/drive.file` — Drive Mode can only see files created/opened by this rahgozar OAuth app in the mailbox folder. It can't read your existing Drive contents.

## Step 5 — Fill in the config

You now have `/etc/rahgozar-drive-relay/config.json` with the refresh token set. The other fields need finishing — open it with your favourite editor:

```bash
sudo -u rahgozar-relay nano /etc/rahgozar-drive-relay/config.json
```

The file looks like this after step 4:

```json
{
  "oauth_client_id": "1234567890-xxxxxxxx.apps.googleusercontent.com",
  "oauth_client_secret": "GOCSPX-xxxxxxxxxxxxxxxx",
  "oauth_refresh_token": "1//04xxxxxxxxxx...",
  "folder_id": "",
  "x25519_secret_key_path": "/etc/rahgozar-drive-relay/relay.key",
  "poll_interval_ms": 300,
  "max_concurrent_dials": 8,
  "idle_timeout_secs": 120,
  "allow_destinations": [],
  "metrics_bind": null
}
```

Leave `folder_id` blank for now — you'll fill it in from the client app in step 7.

The other defaults are sensible:
- `poll_interval_ms: 300` — baseline interval the relay polls Drive. Adapts: faster during active traffic, slower when idle. Bumping this saves Drive quota at the cost of latency.
- `max_concurrent_dials: 8` — outbound dial cap. Adequate for solo browsing.
- `idle_timeout_secs: 120` — sessions with no traffic for this long get evicted. Idle browser tabs are reaped here.
- `allow_destinations: []` — empty = allow any destination. Set to e.g. `["chatgpt.com", "x.com"]` if you want the relay to refuse Connect frames to anything else.

## Step 6 — Create the shared Drive folder (from the client app)

You'll get the folder ID in step 7's desktop or Android UI. Save the ID, then come back and edit step 5's config:

```bash
# After step 7 hands you the folder ID:
sudo -u rahgozar-relay nano /etc/rahgozar-drive-relay/config.json
# Set "folder_id": "0AABBccDDeeFFgg..." with the value from the client UI.
```

Then start the daemon:

```bash
sudo systemctl enable --now rahgozar-drive-relay
sudo systemctl status rahgozar-drive-relay     # should be `active (running)`
sudo journalctl -u rahgozar-drive-relay -f      # tail the logs
```

If the daemon refuses to start, the log line tells you why — usually a missing config field or a wrong key file path.

## Step 7 — Configure the client app

Open the rahgozar desktop app or Android app. The Tunnel tab on desktop and the main setup screen on Android are where you configure modes.

1. **Mode picker**: pick **"Drive (mailbox via Google Drive)"**. A new "Drive mailbox setup" section appears.
2. **OAuth client (BYO)**: at the top, paste the OAuth Client ID and Client secret from [drive_oauth_setup.md](./drive_oauth_setup.md). Use the **Desktop app** client on desktop. Use the **TVs and Limited Input devices** client on Android. Click **Save** — without saving these first, the Sign-in button stays disabled.
3. **Sign in with Google**: click the button. On desktop, a browser tab opens, you approve the consent screen, and the tab closes itself when done. On Android, a device-code dialog appears; tap **Open**, enter the displayed code, sign in, and return to rahgozar. Use the **same Google account** you used on the relay in step 4.
4. **Create folder**: click **Create new**, enter a name (default: `rahgozar mailbox`), click **Create**. The new folder's ID gets pasted into the Folder ID field. **Copy this ID** — you need to paste it into the relay's config in step 6.
5. **Relay public key**: paste the `rgdr1...` string from step 3. The field validates live — green check if the bech32m checksum passes.
6. **Advanced** (optional): tweak `poll_interval_ms` / `max_concurrent_uploads` if you know what you're doing. Defaults are fine.
7. Click **Save**.

The desktop/Android OAuth client and the VPS relay OAuth client may be
different client types, but they must belong to the **same Google Cloud
project and consent screen**. Drive Mode uses `drive.file`, and Google
scopes that access to the app/project that created or opened the
mailbox files; clients from different projects can end up invisible to
each other even when the Google account and folder ID match.

Now go back to step 6 on the VPS and paste the folder ID into the relay's `config.json`. Restart the daemon if it was already running:

```bash
sudo systemctl restart rahgozar-drive-relay
```

## Step 8 — Test it

Back in the client UI, with mode set to Drive and the form saved:

1. Click **Test connection** under the Folder ID field. It should report something like *✓ OK — folder 0AABB...gg has 0 file(s).*
2. Click **Start**. On desktop, the proxy comes up on `127.0.0.1:8085` (HTTP) and `:8086` (SOCKS5). On Android, approve the VPN prompt if Android shows one; the app routes device traffic through the Drive transport.
3. On desktop, point a browser at the proxy and visit any site. On Android, open a browser or app and check your public IP.

Test quickly without a browser:

```bash
# From the laptop where rahgozar is running:
curl -x http://127.0.0.1:8085 https://api.ipify.org
# Expected: an IP that belongs to your VPS provider (not your real IP).
```

If you see your VPS provider's IP, **Drive Mode works**. End-to-end.

## Updating the relay later

Releases bump regularly. To update:

```bash
ssh root@<VPS_IP>
# Stop the daemon, download the new binary, restart.
sudo systemctl stop rahgozar-drive-relay
VERSION=<new tag>
curl -fsSLo /usr/local/bin/rahgozar-drive-relay \
  https://github.com/dazzling-no-more/rahgozar/releases/download/${VERSION}/rahgozar-drive-relay-linux-x86_64
sudo chmod +x /usr/local/bin/rahgozar-drive-relay
sudo systemctl start rahgozar-drive-relay
sudo journalctl -u rahgozar-drive-relay -f
```

The keypair and OAuth token survive — you don't need to re-pair or re-sign-in.

## Troubleshooting

**`rahgozar-drive-relay run` fails with `oauth_refresh_token is empty`.**
You skipped step 4. Run `oauth device-code` again.

**Daemon starts, logs "OAuth refresh failed at startup".**
Your refresh token got revoked (signed out of Google? changed account password? Google sanctions-flagged the account?). Re-run step 4.

**"Sign in with Google" returns `invalid_client`.**
The `oauth_client_id` / `oauth_client_secret` in the Drive setup section don't match the OAuth client type this app path needs. Desktop must use a **Desktop app** OAuth client. Android and the VPS relay must use a **TVs and Limited Input devices** OAuth client. Common causes: typo on paste, copied only part of the secret, copied the other client type, or the OAuth client was deleted/rotated. Re-paste both values from [drive_oauth_setup.md](./drive_oauth_setup.md), Save, try Sign in again.

**Test connection reports "Folder not found".**
Either the `folder_id` in the desktop config doesn't match what's on the VPS, or you signed in to a different Google account in step 7 than in step 4. Both ends must use the same account + same folder.

**`curl --proxy http://127.0.0.1:8085 ...` hangs.**
Check the relay logs (`journalctl -u rahgozar-drive-relay -f`) — if there are no log lines after "OAuth refresh token verified", the relay isn't seeing the Hello frames from the client. Common causes:
- Folder ID mismatch (client app + relay are using different folders).
- Wrong relay public key in the desktop config (client encrypts with the wrong key; relay can't decrypt; silently drops frames).

**Drive storage filling up.**
Check the folder in Drive's web UI. If it has thousands of files, the orphan reaper isn't catching up — increase `poll_interval_ms` on both sides to reduce upload rate, or shorten `idle_timeout_secs` on the relay so the reaper sweeps stale files sooner.

**Multiple devices sharing one Drive folder.**
Supported. Each client filters the `r2c_*` listing by its own local session-id set before downloading, so it ignores frames addressed to other clients' sessions (they all hit the same folder but only your own `r2c_<sid>_*` files match an active session in your local table). Run desktop + Android + a second phone against one relay + one folder simultaneously without conflict; each device's sessions stay isolated by their 128-bit `sid`. The relay doesn't need to know how many clients are talking to it — it just writes back to whichever sid sent the c2r.

## FAQ

**Can I use Drive Mode on Android?**
Yes. Android uses the device-code OAuth flow, so you need a **TVs and Limited Input devices** OAuth client in Google Cloud Console. The desktop app still uses the loopback browser flow with a **Desktop app** OAuth client.

**Can the relay run on the same machine as the client?**
Yes, in theory — the relay's only requirement is "free internet access". But the whole point of Drive Mode is the relay being outside the censored network, so co-locating defeats the purpose.

**What if Google sanctions-blocks the Drive API for Iranian IPs?**
The Drive transport inherits rahgozar's existing `google_ip` SNI-rewrite: the desktop config's `google_ip` field is used to pin Drive endpoints to a known-working Google edge IP. Same setup as Apps Script mode — the existing IP-discovery / SNI-pool machinery applies unchanged.

**Is this faster or slower than Apps Script?**
Slower, in the median. Apps Script fetches in ~300–500 ms per round-trip; Drive Mode polling adds 100–300 ms per leg, so a typical HTTP request is ~600–800 ms vs ~400–600 ms on Apps Script. The throughput ceiling is higher because Drive's QPS budget is fatter than Apps Script's 30-concurrent cap.
