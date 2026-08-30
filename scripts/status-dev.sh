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

echo "==> auth-broker container"
ssh "${SSH_OPTS[@]}" "$TARGET" 'podman ps -a --filter name=auth-broker --format "{{.Names}}\t{{.Status}}\t{{.Ports}}"'

echo
echo "==> /healthz"
HEALTH_URL="http://$AUTH_DEV_HOST:8080/healthz"
if RESPONSE=$(curl -s --max-time 3 "$HEALTH_URL" 2>/dev/null); then
    echo "$HEALTH_URL"
    echo "$RESPONSE"
else
    echo "unhealthy"
fi
