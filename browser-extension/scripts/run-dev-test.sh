#!/usr/bin/env bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

"$PROJECT_ROOT/browser-extension/scripts/install-firefox-dev.sh"

mkdir -p "$HOME/.config/universal-auth"
chmod 700 "$HOME/.config/universal-auth" 2>/dev/null || true

if [ -n "$BROKER_TOKEN" ] && [ ! -f "$HOME/.config/universal-auth/broker.token" ]; then
  printf '%s\n' "$BROKER_TOKEN" > "$HOME/.config/universal-auth/broker.token"
  chmod 600 "$HOME/.config/universal-auth/broker.token"
  echo "Created $HOME/.config/universal-auth/broker.token"
fi

if [ -n "$VAULT_TOKEN" ] && [ ! -f "$HOME/.config/universal-auth/vault.token" ]; then
  printf '%s\n' "$VAULT_TOKEN" > "$HOME/.config/universal-auth/vault.token"
  chmod 600 "$HOME/.config/universal-auth/vault.token"
  echo "Created $HOME/.config/universal-auth/vault.token"
fi

echo ""
echo "Make sure the Pixel is paired:"
echo "  cd $PROJECT_ROOT/desktop-agent"
echo "  go run ./cmd/authctl pair --broker http://192.168.1.167:8080 --expected-device-id <PIXEL_DEVICE_ID>"
echo ""
echo "Make sure ~/.config/universal-auth/config.json contains vault_url:"
echo '  {"broker_url":"...","vault_url":"http://192.168.1.167:8081","trusted_device":{...}}'
echo ""
echo "Add a fake credential to the vault:"
echo "  curl -X POST http://192.168.1.167:8081/v1/credentials \\"
echo "    -H 'Authorization: Bearer \$VAULT_TOKEN' \\"
echo "    -H 'Content-Type: application/json' \\"
echo '    -d '\''{"origin":"http://127.0.0.1:8765","username":"demo@universalauth.test","password":"development-password-only"}'\'''
echo ""
echo "Starting test site on http://127.0.0.1:8765"
echo "1. Load the temporary add-on from about:debugging -> This Firefox -> Load Temporary Add-on -> $PROJECT_ROOT/browser-extension/manifest.json"
echo "2. Open http://127.0.0.1:8765 in Firefox"
echo "3. Focus the password field and approve on the Pixel"
echo ""

python3 -m http.server 8765 -d "$PROJECT_ROOT/browser-extension/test"
