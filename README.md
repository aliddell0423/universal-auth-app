# universal-auth-app

A personal authentication broker project. The first component is `auth-broker/`, a minimal in-memory HTTP broker that stores and approves or denies authentication requests.

## Development VM deployment

The scripts in `scripts/` deploy the `auth-broker` container from the Fedora workstation to a development VM at `192.168.1.167` without using a container registry.

### Configuration

Set on the workstation before running the scripts:

```bash
export AUTH_DEV_USER=<username>
# optional:
export AUTH_DEV_HOST=192.168.1.167  # default
export AUTH_DEV_PORT=22             # default
export AUTH_DEV_SSH_KEY=~/.ssh/id_ed25519
```

### Initial VM setup

```bash
./scripts/bootstrap-dev-vm.sh
```

This verifies SSH, Podman, and the `~/.config/auth-broker/` directory. If the environment file is missing, create it on the VM before deploying.

This requires `openssl` (installed by default on Ubuntu Server; otherwise install with `sudo apt-get install -y openssl`).

```bash
mkdir -p -m 700 ~/.config/auth-broker

printf 'BROKER_TOKEN=%s\n' "$(openssl rand -hex 32)" \
  > ~/.config/auth-broker/auth-broker.env

chmod 600 ~/.config/auth-broker/auth-broker.env
```

This creates a random 256-bit development bearer token. The file must always be mode `600`, must never be committed, and is DEVELOPMENT ONLY. It will later be replaced by cryptographic device identities.

### Normal deployment

```bash
./scripts/deploy-dev.sh
```

This runs tests, builds the container, transfers it over SSH, replaces the running VM container, and verifies `/healthz`.

### View logs

```bash
./scripts/logs-dev.sh
```

### Check status

```bash
./scripts/status-dev.sh
```

## Android client

The Android client is in `auth_client/`. It is a minimal Jetpack Compose app written in Kotlin that displays pending authentication requests and lets you approve or deny them.

### Android Studio requirement

Open the `auth_client/` directory in Android Studio (the project uses AGP 9.3.2 with built-in Kotlin).

### Configure the development broker token

Add the broker token to `auth_client/local.properties`:

```properties
broker.token=<token-from-vm>
```

The token is compiled into the debug APK as `BuildConfig.BROKER_TOKEN`. It is extracted from the remote VM's `~/.config/auth-broker/auth-broker.env` file. **This is development-only and is not a secure long-term secret** — it can be extracted from the APK.

`local.properties` is ignored by Git, so the token will not be committed.

### Broker address

The app is currently hardcoded to `http://192.168.1.167:8080`.

### Run on a physical Google Pixel

1. On the Pixel: open **Settings → About phone** and tap **Build number** seven times to enable Developer Options.
2. Go to **Settings → System → Developer options** and enable either **Wireless debugging** or **USB debugging**.
3. If using Wireless debugging: tap **Pair with pairing code**, then in Android Studio choose **Device Manager → Pair using Wi-Fi** and enter the code.
4. If using USB: connect the Pixel to the Fedora workstation and authorize the debugging prompt.
5. Select the Pixel as the deployment target in Android Studio.
6. Click **Run**.

### Current Android functionality

The current app:

- fetches pending requests from the broker,
- displays source, kind, resource, message, creation time, and a per-request challenge,
- lets you approve or deny a request,
- refreshes the list after a decision,
- **requires strong biometric authentication before Approve**,
- **signs each approval with a hardware-backed Android Keystore EC P-256 private key**.

Deny does not require biometric authentication and does not produce a signature.

### Security model

The approval flow is now:

```text
BIOMETRIC_STRONG
       ↓
auth-per-use Android Keystore private key
       ↓
ECDSA P-256 signature over a canonical request payload
       ↓
broker verifies signature against the registered Pixel public key
       ↓
request becomes approved with an approval_proof
```

The private key:

- never leaves Android Keystore,
- is non-exportable,
- is bound to `BIOMETRIC_STRONG` and auth-per-use,
- is invalidated when enrolled biometrics change,
- must be backed by StrongBox or the TEE; software-backed keys are rejected.

The public key is derived as a SHA-256 fingerprint (`device_id`) and registered with the broker. Each request contains a fresh 256-bit challenge. The signed canonical payload includes the request ID, challenge, decision, source, kind, resource, and message. The broker reconstructs the payload from its own copy of the request and verifies the signature.

### Development limitations

- The broker uses HTTP rather than TLS.
- The bearer token is still used for API access and initial device enrollment.
- The device registry and request store are currently in memory.
- Device enrollment is not yet cryptographically secured against a compromised broker or network.
- Android remote key attestation is not implemented.
- The desktop does not yet independently verify `approval_proof`; it currently trusts the broker.

This milestone does **not** make the system safe against a compromised broker.

### Manual test on Pixel 10

#### Registration

1. Redeploy the updated broker.
2. Launch Universal Auth on the Pixel.
3. Verify the Pixel generates or retrieves its hardware-backed signing key.
4. Verify the app successfully registers the public key with the broker.
5. Confirm the key reports StrongBox or TEE hardware backing.

#### Happy path

1. Create a broker request from Fedora.
2. Open/refresh Universal Auth on the Pixel.
3. Verify the request appears with a `challenge`.
4. Tap **Approve**.
5. Verify the Android system biometric dialog appears.
6. Authenticate with the enrolled strong biometric.
7. Verify the broker request becomes `approved` and contains `approval_proof`.

#### Cancellation test

1. Create another request.
2. Tap **Approve**.
3. Cancel the biometric prompt.
4. Verify the request remains `pending`.

#### Failed biometric attempt

1. Trigger an unsuccessful biometric scan, then successfully authenticate without closing the prompt.
2. Verify the correct request is still approved.

#### Unsigned bypass test

From Fedora attempt the old unsigned approval:

```bash
curl -X POST \
  -H "Authorization: Bearer $BROKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approved"}' \
  http://192.168.1.167:8080/v1/requests/<id>/decision
```

This must fail and the request must remain `pending`.

#### Denial

1. Create another request.
2. Tap **Deny**.
3. Verify it becomes `denied` without a biometric prompt.

## Desktop client

`desktop-agent/` is the Fedora command-line client `authctl`. It treats the broker as an untrusted relay: it never accepts `"approved"` at face value and instead verifies the Pixel's ECDSA P-256 signature itself.

### Usage

```bash
export BROKER_TOKEN='...'

cd desktop-agent

go run ./cmd/authctl pair \
  --broker http://192.168.1.167:8080 \
  --expected-device-id <PIXEL_DEVICE_ID>
```

```bash
go run ./cmd/authctl request \
  --source andrew-fedora \
  --kind test \
  --resource desktop-test \
  --message "Approve this from Fedora"
```

### Trust model

Before desktop verification:

```text
Pixel signs
   ↓
broker verifies
   ↓
desktop trusts broker status
```

After this milestone:

```text
Pixel signs
   ↓
broker relays/stores proof
   ↓
desktop verifies Pixel signature itself
```

The desktop:

- pins the Pixel public key using an out-of-band `--expected-device-id`
- creates requests with its own `client_nonce`
- reconstructs the canonical `universal-auth:v2` payload from local intent values
- verifies `SHA256withECDSA` against the pinned Pixel public key
- only then prints `APPROVED` and exits `0`

### Exit codes

- `0` — approved and signature verified
- `2` — denied
- `3` — timeout
- `4` — security verification failure
- `5` — network/protocol/config error

### Remaining limitations

- HTTP instead of TLS
- bearer token transport authentication
- in-memory broker state
- one trusted Pixel
- manual fingerprint pairing via `--expected-device-id`
- no persistent desktop daemon
- no Android remote attestation

## Browser extension prototype

`browser-extension/` is a Firefox MV3 prototype that fills a login form after Pixel biometric approval. It does not implement an encrypted credential vault, background daemon, or mobile transport.

### Native host

The native host `ua-browser-host` is launched by Firefox Native Messaging. It reads a framed JSON request, looks up a fake development credential by exact browser-derived origin, runs the existing Universal Auth `credential_access` approval flow, and only returns the credential after Fedora independently verifies the Pixel signature.

### Install

```bash
./browser-extension/scripts/install-firefox-dev.sh
```

Create `~/.config/universal-auth/dev-credentials.json` (mode `0600`) with fake credentials and `~/.config/universal-auth/broker.token` (mode `0600`) if `BROKER_TOKEN` is not exported. See `browser-extension/README.md` for the manual test procedure.

### Security notes for the browser prototype

- The extension never receives the broker token or Pixel private key.
- The background script derives the origin from `sender.url`; the page cannot request an arbitrary origin.
- Credential lookup is exact string matching; `https://github.com` does not match `https://github.com.attacker.example`.
- Credentials are returned only after a locally verified Pixel signature.
- The form is not submitted automatically.

## Security notes

- Never commit `BROKER_TOKEN`, SSH private keys, passwords, `broker.token`, or `dev-credentials.json` to this repository.
- The bearer token is development-only and will be replaced by cryptographic device identities later.
