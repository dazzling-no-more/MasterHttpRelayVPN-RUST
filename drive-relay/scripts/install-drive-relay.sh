#!/bin/sh
# Install rahgozar-drive-relay as a systemd service.
#
# Reads BINARY + SERVICE_FILE from the working directory by default;
# override via env vars if you're running from somewhere else.
#
# Idempotent — safe to re-run to update the binary after a release.

set -eu

BINARY="${BINARY:-./rahgozar-drive-relay}"
SERVICE_FILE="${SERVICE_FILE:-./systemd/rahgozar-drive-relay.service}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
CONFIG_DIR="/etc/rahgozar-drive-relay"
USER_NAME="rahgozar-relay"
GROUP_NAME="rahgozar-relay"

if [ "$(id -u)" -ne 0 ]; then
    echo "this script must be run as root" >&2
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "binary not found at $BINARY (override with BINARY=...)" >&2
    exit 1
fi

if [ ! -f "$SERVICE_FILE" ]; then
    echo "service file not found at $SERVICE_FILE (override with SERVICE_FILE=...)" >&2
    exit 1
fi

# 1. Create the service group + user (no-op if either already exists).
#    `useradd` creates a same-named primary group on most distros, but
#    `--system` users on Debian/Ubuntu DON'T get one by default — so the
#    `chown "$USER_NAME:$GROUP_NAME"` below would fail with "invalid
#    group" without this explicit groupadd. Idempotent: groupadd's
#    --force-style behaviour isn't portable across distros, so we test
#    first.
if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
    groupadd --system "$GROUP_NAME"
fi
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid "$GROUP_NAME" "$USER_NAME"
fi

# 2. Install the binary.
install -m 0755 "$BINARY" "$INSTALL_PREFIX/rahgozar-drive-relay"

# 3. Create the config directory with restrictive permissions.
mkdir -p "$CONFIG_DIR"
chown "$USER_NAME:$GROUP_NAME" "$CONFIG_DIR"
chmod 0700 "$CONFIG_DIR"

# 4. Install the systemd unit and reload.
install -m 0644 "$SERVICE_FILE" /etc/systemd/system/rahgozar-drive-relay.service
systemctl daemon-reload

cat <<EOF

Installed rahgozar-drive-relay to $INSTALL_PREFIX/rahgozar-drive-relay.

Next steps (run all three as the relay user, NOT as root):

  1. Mint a fresh X25519 keypair. The printed bech32m public key
     goes into the desktop client's drive.relay_pubkey field.

     sudo -u $USER_NAME rahgozar-drive-relay keygen \\
       --out $CONFIG_DIR/relay.key

  2. Run the OAuth device-code flow. rahgozar is BYO OAuth —
     register your own OAuth client first (see docs/drive_oauth_setup.md)
     and pass its client_id + client_secret here. Follow the printed
     URL + code on a phone or laptop.

     sudo -u $USER_NAME rahgozar-drive-relay oauth device-code \\
       --client-id     'YOUR_CLIENT_ID.apps.googleusercontent.com' \\
       --client-secret 'YOUR_CLIENT_SECRET' \\
       --out $CONFIG_DIR/config.json

  3. Open $CONFIG_DIR/config.json and set:
       "folder_id":              (created in the desktop client UI)
       "x25519_secret_key_path": "$CONFIG_DIR/relay.key"

  4. Start the daemon and enable on boot:

     sudo systemctl enable --now rahgozar-drive-relay
     sudo systemctl status rahgozar-drive-relay

EOF
