#!/usr/bin/env bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BROWSER_DIR="${CHROMIUM_CONFIG:-$HOME/.config/BraveSoftware/Brave-Browser}"

cd "$PROJECT_ROOT/desktop-agent"
mkdir -p "$HOME/.local/bin"
go build -o "$HOME/.local/bin/ua-browser-host" ./cmd/ua-browser-host

mkdir -p "$BROWSER_DIR/NativeMessagingHosts"
cat > "$BROWSER_DIR/NativeMessagingHosts/com.aliddell.universalauth.json" <<EOF2
{
  "name": "com.aliddell.universalauth",
  "description": "Universal Auth browser bridge",
  "path": "$HOME/.local/bin/ua-browser-host",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://oinchecmbfaepcifihpfakaoniabnmma/"
  ]
}
EOF2

echo "Installed native host to $HOME/.local/bin/ua-browser-host"
echo "Installed native messaging manifest to $BROWSER_DIR/NativeMessagingHosts/com.aliddell.universalauth.json"
echo "Load the unpacked extension from brave://extensions (Developer mode) using $PROJECT_ROOT/browser-extension/chromium"
