#!/bin/bash
set -euo pipefail

AUTH_DEV_HOST="${AUTH_DEV_HOST:-192.168.1.167}"
AUTH_DEV_PORT="${AUTH_DEV_PORT:-22}"
AUTH_DEV_USER="${AUTH_DEV_USER:-}"
AUTH_DEV_SSH_KEY="${AUTH_DEV_SSH_KEY:-}"

if [ -z "$AUTH_DEV_USER" ]; then
    echo "ERROR: AUTH_DEV_USER is required" >&2
    echo "Example: export AUTH_DEV_USER=andrew" >&2
    exit 1
fi

for cmd in go podman ssh curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is required on this workstation" >&2
        exit 1
    fi
done

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BROKER_DIR="$REPO_ROOT/auth-broker"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -p "$AUTH_DEV_PORT")
if [ -n "$AUTH_DEV_SSH_KEY" ]; then
    SSH_OPTS+=(-i "$AUTH_DEV_SSH_KEY")
fi
TARGET="$AUTH_DEV_USER@$AUTH_DEV_HOST"

echo "==> Testing auth-broker"
cd "$BROKER_DIR"
go test ./...
go vet ./...

echo "==> Building auth-broker container"
podman build -t auth-broker:dev "$BROKER_DIR"

echo "==> Verifying remote env file"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'test -f ~/.config/auth-broker/auth-broker.env'; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env not found on $TARGET" >&2
    echo "Run: ./scripts/bootstrap-dev-vm.sh" >&2
    exit 1
fi

echo "==> Verifying remote env file permissions"
PERMS=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'stat -c %a ~/.config/auth-broker/auth-broker.env')
if [ "$PERMS" != "600" ]; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env must be mode 600 (got $PERMS)" >&2
    exit 1
fi

echo "==> Verifying remote BROKER_TOKEN value"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'grep -qE "^BROKER_TOKEN=.+$" ~/.config/auth-broker/auth-broker.env'; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env must contain a non-empty BROKER_TOKEN value" >&2
    exit 1
fi

echo "==> Transferring image to $TARGET"
podman save auth-broker:dev | ssh "${SSH_OPTS[@]}" "$TARGET" podman load

echo "==> Replacing remote container"
ssh "${SSH_OPTS[@]}" "$TARGET" '
    podman rm -f auth-broker 2>/dev/null || true
    podman run -d \
        --name auth-broker \
        -p 8080:8080 \
        --env-file ~/.config/auth-broker/auth-broker.env \
        --restart on-failure:5 \
        auth-broker:dev
'

echo "==> Waiting for /healthz"
HEALTH_URL="http://$AUTH_DEV_HOST:8080/healthz"
for i in {1..15}; do
    if RESPONSE=$(curl -s --max-time 3 "$HEALTH_URL" 2>/dev/null); then
        if [ "$RESPONSE" = '{"status":"ok"}' ]; then
            echo
            echo "auth-broker deployed successfully"
            echo "$HEALTH_URL"
            exit 0
        fi
    fi
    sleep 1
done

echo "ERROR: health check failed at $HEALTH_URL" >&2
echo
echo "==> Recent container logs" >&2
ssh "${SSH_OPTS[@]}" "$TARGET" 'podman logs --tail 100 auth-broker' >&2 || true
exit 1
