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
    if ssh "${SSH_OPTS[@]}" "$TARGET" 'grep -qE "^(ID|ID_LIKE)=.*(ubuntu|debian)" /etc/os-release'; then
        echo "ERROR: Podman is not installed on $TARGET" >&2
        echo "Install it with the following commands on the VM:" >&2
        echo "  sudo apt-get update" >&2
        echo "  sudo apt-get install -y podman" >&2
    else
        echo "ERROR: Podman is not installed on $TARGET" >&2
        echo "Install it using the VM's package manager." >&2
    fi
    exit 1
fi

echo "==> Creating remote config directory"
ssh "${SSH_OPTS[@]}" "$TARGET" 'mkdir -p -m 700 ~/.config/auth-broker'

echo "==> Checking remote BROKER_TOKEN file"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'test -f ~/.config/auth-broker/auth-broker.env'; then
    echo "ERROR: ~/.config/auth-broker/auth-broker.env does not exist on $TARGET" >&2
    echo "Create it on the VM with a non-empty BROKER_TOKEN value and mode 600." >&2
    echo "Use the README instructions to generate a secure random token." >&2
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

echo "==> Creating remote vault config and data directories"
ssh "${SSH_OPTS[@]}" "$TARGET" 'mkdir -p -m 700 ~/.config/universal-auth-vault'
ssh "${SSH_OPTS[@]}" "$TARGET" 'mkdir -p -m 700 ~/.local/share/universal-auth/vault'

echo "==> Checking remote vault environment file"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'test -f ~/.config/universal-auth-vault/vault.env'; then
    echo "ERROR: ~/.config/universal-auth-vault/vault.env does not exist on $TARGET" >&2
    echo "Create it on the VM with mode 600 and a non-empty VAULT_TOKEN value." >&2
    echo "Use: openssl rand -hex 32 > /tmp/token" >&2
    echo "Then: printf 'VAULT_TOKEN=%s\\n' $(cat /tmp/token) > ~/.config/universal-auth-vault/vault.env" >&2
    exit 1
fi

echo "==> Verifying remote vault environment file permissions"
VAULT_PERMS=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'stat -c %a ~/.config/universal-auth-vault/vault.env')
if [ "$VAULT_PERMS" != "600" ]; then
    echo "ERROR: ~/.config/universal-auth-vault/vault.env must be mode 600 (got $VAULT_PERMS)" >&2
    exit 1
fi

echo "==> Verifying remote vault secrets"
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'grep -qE "^VAULT_TOKEN=.+$" ~/.config/universal-auth-vault/vault.env'; then
    echo "ERROR: VAULT_TOKEN must be non-empty" >&2
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
