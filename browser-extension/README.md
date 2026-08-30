# Universal Auth — Firefox Browser Prototype

This prototype proves the browser-to-Pixel-to-browser credential flow. It uses a development credential file and does not include an encrypted vault, background daemon, or mobile transport.

## Development credential file

Create `~/.config/universal-auth/dev-credentials.json` (mode `0600`) with fake credentials only:

```json
{
  "http://127.0.0.1:8765": {
    "username": "demo@universalauth.test",
    "password": "development-password-only"
  }
}
```

```bash
mkdir -p ~/.config/universal-auth
chmod 700 ~/.config/universal-auth
chmod 600 ~/.config/universal-auth/dev-credentials.json
```

## Broker token

The native host cannot inherit `BROKER_TOKEN` from an arbitrary terminal. For the prototype, store the token in `~/.config/universal-auth/broker.token` (mode `0600`):

```bash
printf '%s\n' "$BROKER_TOKEN" > ~/.config/universal-auth/broker.token
chmod 600 ~/.config/universal-auth/broker.token
```

The `BROKER_TOKEN` environment variable still takes priority.

## Install the native host

From the repository root:

```bash
./browser-extension/scripts/install-firefox-dev.sh
```

This builds `ua-browser-host` into `~/.local/bin/` and registers the Firefox Native Messaging manifest in `~/.mozilla/native-messaging-hosts/`.

## Pair the desktop

```bash
cd desktop-agent
go run ./cmd/authctl pair \
  --broker http://192.168.1.167:8080 \
  --expected-device-id <PIXEL_DEVICE_ID>
```

## Load the extension in Firefox

1. Open `about:debugging`.
2. Click **This Firefox**.
3. Click **Load Temporary Add-on...**.
4. Select `browser-extension/manifest.json`.

## Run the test login page

```bash
python3 -m http.server 8765 -d browser-extension/test
```

Open `http://127.0.0.1:8765` in Firefox, click/focus the password field, and approve on the Pixel.

## Security notes

- Do not store real passwords in `dev-credentials.json`.
- Do not commit `broker.token` or `dev-credentials.json`.
- The extension never receives the broker token or Pixel private key.
- The native host refuses to release credentials without a locally verified Pixel signature.
