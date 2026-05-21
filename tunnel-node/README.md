# Tunnel Node

> *Persian / فارسی: [README.fa.md](./README.fa.md)*

HTTP tunnel bridge server for MasterHttpRelayVPN "full" mode. Bridges HTTP tunnel requests (from Apps Script) to real TCP connections.

> **Just want Full Tunnel set up?** Use [`docs/full-tunnel-setup.md`](../docs/full-tunnel-setup.md) — copy-paste walkthrough covering VPS, Apps Script, and client config. This README is the reference for all deployment options and protocol details.

## Architecture

```text
Phone → rahgozar → [domain-fronted TLS] → Apps Script → [HTTP] → Tunnel Node → [real TCP] → Internet
```

The tunnel node manages persistent TCP and UDP sessions. TCP sessions are real TCP connections to a destination server; UDP sessions are connected UDP sockets to one destination host:port. Data flows through a JSON protocol:

- **connect** — open TCP to host:port, return session ID
- **data** — write client data, return server response
- **udp_open** — open UDP to host:port, optionally send the first datagram
- **udp_data** — send one UDP datagram, or poll for returned datagrams when `d` is omitted
- **close** — tear down session
- **batch** — process multiple ops in one HTTP request (reduces round trips)

## Deployment

### Cloud Run

```bash
cd tunnel-node
gcloud run deploy tunnel-node \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars TUNNEL_AUTH_KEY=$(openssl rand -hex 24) \
  --memory 256Mi \
  --cpu 1 \
  --max-instances 1
```

### Docker — prebuilt image (any VPS)

The fastest path. Pull a prebuilt image and run it; no Rust toolchain needed on the VPS.

```bash
# Generate a strong secret. Save it — you'll paste the same value into CodeFull.gs.
SECRET=$(openssl rand -hex 24)
echo "Your TUNNEL_AUTH_KEY: $SECRET"

# Pull + run.
docker run -d \
  --name rahgozar-tunnel \
  --restart unless-stopped \
  -p 8080:8080 \
  -e TUNNEL_AUTH_KEY="$SECRET" \
  ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
```

The `:latest` tag tracks the most recent release. To pin a specific version (recommended for production), use `ghcr.io/dazzling-no-more/rahgozar-tunnel-node:1.5.0` (or whatever release you're on). Image is available for `linux/amd64` and `linux/arm64`. Tags follow rahgozar releases without the `v` prefix — see <https://github.com/dazzling-no-more/rahgozar/releases>.

**docker-compose.yml** if you prefer:

```yaml
services:
  tunnel:
    image: ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      TUNNEL_AUTH_KEY: ${TUNNEL_AUTH_KEY}
```

Then `TUNNEL_AUTH_KEY=your-secret docker compose up -d`.

### Docker — build from source

If you'd rather build the image yourself (or add custom changes):

```bash
cd tunnel-node
docker build -t tunnel-node .
docker run -p 8080:8080 -e TUNNEL_AUTH_KEY=your-secret tunnel-node
```

### Prebuilt static binary (no Docker, no Rust toolchain)

For users who want a single static binary instead of a container. Each release publishes a fully-static musl build for the two common VPS architectures — works on any Linux distro (Alpine, Debian, Ubuntu, RHEL, …) without libc compatibility concerns.

```bash
# Pick the asset that matches your VPS:
#   x86_64  → rahgozar-tunnel-node-linux-musl-amd64.tar.gz
#   aarch64 → rahgozar-tunnel-node-linux-musl-arm64.tar.gz
curl -LO https://github.com/dazzling-no-more/rahgozar/releases/latest/download/rahgozar-tunnel-node-linux-musl-amd64.tar.gz
tar xzf rahgozar-tunnel-node-linux-musl-amd64.tar.gz

# Generate a secret (save it for CodeFull.gs).
SECRET=$(openssl rand -hex 24)

# Run.
TUNNEL_AUTH_KEY="$SECRET" PORT=8080 ./tunnel-node
```

Drop it under systemd / OpenRC / supervisord / `tmux` — whatever your VPS prefers. A minimal systemd unit:

```ini
# /etc/systemd/system/rahgozar-tunnel.service
[Unit]
Description=Rahgozar tunnel-node bridge
After=network.target

[Service]
Environment=TUNNEL_AUTH_KEY=your-secret
Environment=PORT=8080
ExecStart=/usr/local/bin/tunnel-node
Restart=on-failure
DynamicUser=yes

[Install]
WantedBy=multi-user.target
```

Each release archive is signed with the rahgozar minisign key — verify with `minisign -Vm <archive> -p rahgozar-update.pub` if you want provenance before running.

### Build from source

```bash
cd tunnel-node
cargo build --release
TUNNEL_AUTH_KEY=your-secret PORT=8080 ./target/release/tunnel-node
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TUNNEL_AUTH_KEY` | Yes | `changeme` | Shared secret — must match `TUNNEL_AUTH_KEY` in CodeFull.gs |
| `PORT` | No | `8080` | Listen port (Cloud Run sets this automatically) |

## Protocol

### Single op: `POST /tunnel`

```json
{"k":"auth","op":"connect","host":"example.com","port":443}
{"k":"auth","op":"data","sid":"uuid","data":"base64"}
{"k":"auth","op":"close","sid":"uuid"}
```

### Batch: `POST /tunnel/batch`

```json
{
  "k": "auth",
  "ops": [
    {"op":"data","sid":"uuid1","d":"base64"},
    {"op":"udp_data","sid":"uuid2","d":"base64"},
    {"op":"close","sid":"uuid3"}
  ]
}
→ {"r": [{...}, {...}, {...}]}
```

### Health check: `GET /health` → `ok`

## Performance: deployment count and pipeline depth

The rahgozar client runs a pipelined batch multiplexer in full mode. Each Apps Script round-trip takes ~2s, so the client keeps multiple batch requests in flight concurrently. Per-session pipeline depth adapts between idle, optimistic startup, and active-transfer levels; each configured script deployment ID adds another Apps Script concurrency pool.

More deployments = more concurrent batches hitting the tunnel-node and less chance that one Apps Script account becomes the bottleneck. They increase total throughput and reduce queueing under load, but a fresh HTTPS request still normally needs two Apps Script cycles to first response data.

The tunnel-node itself is stateless per-request (sessions are keyed by UUID), so it handles concurrent batches naturally. For best results, deploy 3–12 Apps Script instances across separate Google accounts and list all their deployment IDs in the client config.
