#!/bin/bash
set -euo pipefail

AUTH_DEV_HOST="${AUTH_DEV_HOST:-192.168.1.167}"
AUTH_DEV_PORT="${AUTH_DEV_PORT:-22}"
AUTH_DEV_USER="${AUTH_DEV_USER:-}"
AUTH_DEV_SSH_KEY="${AUTH_DEV_SSH_KEY:-}"

if [ -z "$AUTH_DEV_USER" ]; then
    echo "ERROR: AUTH_DEV_USER is required" >&2
    exit 1
fi

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -p "$AUTH_DEV_PORT")
if [ -n "$AUTH_DEV_SSH_KEY" ]; then
    SSH_OPTS+=(-i "$AUTH_DEV_SSH_KEY")
fi
TARGET="$AUTH_DEV_USER@$AUTH_DEV_HOST"

echo "==> Verifying SSH connectivity to $TARGET"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" "echo ok" >/dev/null 2>&1; then
    echo "ERROR: SSH to $TARGET failed" >&2
    echo "Check that your key is configured and BatchMode works." >&2
    exit 1
fi

echo "==> Checking for Podman on the VM"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" "command -v podman" >/dev/null 2>&1; then
    echo "ERROR: Podman is not installed on $TARGET" >&2
    echo "Install it with: sudo dnf install -y podman" >&2
    exit 1
fi

echo "==> Creating remote config directory"
ssh "${SSH_OPTS[@]}" "$TARGET" 'mkdir -p -m 700 ~/.config/auth-broker'

echo "==> Checking remote BROKER_TOKEN file"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'test -f ~/.config/auth-broker/auth-broker.env'; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env does not exist on $TARGET" >&2
    echo "Create it on the VM with mode 600, for example:" >&2
    echo "  mkdir -p -m 700 ~/.config/auth-broker" >&2
    echo "  cat > ~/.config/auth-broker/auth-broker.env <<'EOF'" >&2
    echo "  BROKER_TOKEN=dev-only-change-this" >&2
    echo "  EOF" >&2
    echo "  chmod 600 ~/.config/auth-broker/auth-broker.env" >&2
    exit 1
fi

echo "==> Verifying remote env file permissions"
PERMS=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'stat -c %a ~/.config/auth-broker/auth-broker.env')
if [ "$PERMS" != "600" ]; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env must be mode 600 (got $PERMS)" >&2
    exit 1
fi

echo "==> Verifying Podman works"
REMOTE_PODMAN=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'podman --version')
echo "  $REMOTE_PODMAN"

echo
echo "==> Development VM ready"
echo "  host: $AUTH_DEV_HOST"
echo "  port: $AUTH_DEV_PORT"
echo "  user: $AUTH_DEV_USER"
