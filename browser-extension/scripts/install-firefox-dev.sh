#!/usr/bin/env bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

cd "$PROJECT_ROOT/desktop-agent"

mkdir -p "$HOME/.local/bin"
go build -o "$HOME/.local/bin/ua-browser-host" ./cmd/ua-browser-host

mkdir -p "$HOME/.mozilla/native-messaging-hosts"

cat > "$HOME/.mozilla/native-messaging-hosts/com.aliddell.universalauth.json" <<EOF
{
  "name": "com.aliddell.universalauth",
  "description": "Universal Auth browser bridge",
  "path": "$HOME/.local/bin/ua-browser-host",
  "type": "stdio",
  "allowed_extensions": [
    "universal-auth@aliddell.dev"
  ]
}
EOF

echo "Installed native host to $HOME/.local/bin/ua-browser-host"
echo "Installed native messaging manifest to $HOME/.mozilla/native-messaging-hosts/com.aliddell.universalauth.json"
