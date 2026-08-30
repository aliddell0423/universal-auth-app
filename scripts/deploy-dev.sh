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
VAULT_DIR="$REPO_ROOT/vault-service"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -p "$AUTH_DEV_PORT")
if [ -n "$AUTH_DEV_SSH_KEY" ]; then
    SSH_OPTS+=(-i "$AUTH_DEV_SSH_KEY")
fi
TARGET="$AUTH_DEV_USER@$AUTH_DEV_HOST"

echo "==> Testing auth-broker"
cd "$BROKER_DIR"
go test ./...
go vet ./...

echo "==> Testing vault-service"
cd "$VAULT_DIR"
go test ./...
go vet ./...

echo "==> Building auth-broker container"
cd "$BROKER_DIR"
podman build -t auth-broker:dev "$BROKER_DIR"

echo "==> Building vault-service container"
cd "$VAULT_DIR"
podman build -t vault-service:dev "$VAULT_DIR"

echo "==> Verifying remote broker env file"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'test -f ~/.config/auth-broker/auth-broker.env'; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env not found on $TARGET" >&2
    echo "Run: ./scripts/bootstrap-dev-vm.sh" >&2
    exit 1
fi

PERMS=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'stat -c %a ~/.config/auth-broker/auth-broker.env')
if [ "$PERMS" != "600" ]; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env must be mode 600 (got $PERMS)" >&2
    exit 1
fi

if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'grep -qE "^BROKER_TOKEN=.+$" ~/.config/auth-broker/auth-broker.env'; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env must contain a non-empty BROKER_TOKEN value" >&2
    exit 1
fi

echo "==> Verifying remote vault env file"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'test -f ~/.config/universal-auth-vault/vault.env'; then
    echo "ERROR: ~/.config/universal-auth-vault/vault.env not found on $TARGET" >&2
    echo "Run: ./scripts/bootstrap-dev-vm.sh" >&2
    exit 1
fi

VAULT_PERMS=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'stat -c %a ~/.config/universal-auth-vault/vault.env')
if [ "$VAULT_PERMS" != "600" ]; then
    echo "ERROR: ~/.config/universal-auth-vault/vault.env must be mode 600 (got $VAULT_PERMS)" >&2
    exit 1
fi

if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'grep -qE "^VAULT_TOKEN=.+$" ~/.config/universal-auth-vault/vault.env'; then
    echo "ERROR: VAULT_TOKEN must be non-empty in ~/.config/universal-auth-vault/vault.env" >&2
    exit 1
fi

echo "==> Transferring images to $TARGET"
podman save auth-broker:dev | ssh "${SSH_OPTS[@]}" "$TARGET" podman load
podman save vault-service:dev | ssh "${SSH_OPTS[@]}" "$TARGET" podman load

echo "==> Replacing remote containers"
ssh "${SSH_OPTS[@]}" "$TARGET" '
    podman rm -f auth-broker 2>/dev/null || true
    podman run -d \
        --name auth-broker \
        -p 8080:8080 \
        --env-file ~/.config/auth-broker/auth-broker.env \
        --restart on-failure:5 \
        auth-broker:dev

    podman rm -f vault-service 2>/dev/null || true
    podman run -d \
        --name vault-service \
        -p 8081:8081 \
        --env-file ~/.config/universal-auth-vault/vault.env \
        -v "$HOME/.local/share/universal-auth/vault:/data" \
        --restart on-failure:5 \
        vault-service:dev
'

echo "==> Waiting for health checks"
BROKER_HEALTH="http://$AUTH_DEV_HOST:8080/healthz"
VAULT_HEALTH="http://$AUTH_DEV_HOST:8081/healthz"

for i in {1..15}; do
    BROKER_OK=false
    VAULT_OK=false

    if RESPONSE=$(curl -s --max-time 3 "$BROKER_HEALTH" 2>/dev/null); then
        if [ "$RESPONSE" = '{"status":"ok"}' ]; then
            BROKER_OK=true
        fi
    fi

    if RESPONSE=$(curl -s --max-time 3 "$VAULT_HEALTH" 2>/dev/null); then
        if [ "$RESPONSE" = '{"status":"ok"}' ]; then
            VAULT_OK=true
        fi
    fi

    if [ "$BROKER_OK" = true ] && [ "$VAULT_OK" = true ]; then
        echo
        echo "auth-broker deployed successfully"
        echo "  $BROKER_HEALTH"
        echo "vault-service deployed successfully"
        echo "  $VAULT_HEALTH"
        exit 0
    fi
    sleep 1
done

echo "ERROR: health check failed" >&2
echo "  broker: $BROKER_HEALTH" >&2
echo "  vault:  $VAULT_HEALTH" >&2
echo
echo "==> Recent broker logs" >&2
ssh "${SSH_OPTS[@]}" "$TARGET" 'podman logs --tail 100 auth-broker' >&2 || true
echo
echo "==> Recent vault logs" >&2
ssh "${SSH_OPTS[@]}" "$TARGET" 'podman logs --tail 100 vault-service' >&2 || true
exit 1
