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

### Setup

`authctl setup` is the idempotent entry point. It creates the config, creates the
desktop identity, registers the desktop with the broker, installs the Firefox
native host, and pins the Pixel once it is paired. It is safe to run repeatedly.

```bash
export BROKER_TOKEN='...'
export VAULT_TOKEN='...'

cd desktop-agent

go run ./cmd/authctl setup \
  --broker http://192.168.1.167:8080 \
  --vault http://192.168.1.167:8081 \
  --desktop-name "Fedora Desktop"
```

Subsequent runs need no flags; the stored endpoints are reused:

```bash
go run ./cmd/authctl setup
```

`--check` reports the current state without writing anything:

```bash
go run ./cmd/authctl setup --check
```

Setup never replaces a trusted desktop or Pixel. A mismatch is a hard failure
that must be resolved deliberately with `authctl pair`.

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

## Vault service

`vault-service/` is a new Go service that stores credentials in a SQLite database. Each credential is encrypted with a fresh random AES-256-GCM DEK, and that DEK is wrapped by a temporary `VAULT_KEK` held on the Ubuntu server. See `vault-service/README.md` for details.

This is the first real encrypted credential store. It is still development-only because the server holds the KEK; a full server compromise could expose credentials. Pixel-controlled key release is future work.

### Deploy

On the VM create `~/.config/universal-auth-vault/vault.env` with `VAULT_TOKEN` and `VAULT_KEK` (mode `0600`). Then:

```bash
./scripts/deploy-dev.sh
```

This builds and deploys both `auth-broker` and `vault-service`, bind-mounting `~/.local/share/universal-auth/vault` to `/data` for persistence.

Push notifications: when `FCM_SERVICE_ACCOUNT_FILE` is set in `~/.config/auth-broker/auth-broker.env` (a Firebase Admin SDK service-account JSON, stored inside the broker's `/data` mount), the broker sends an FCM "credential request" notification for each release request. The app shows it and tapping opens the approval screen; the notification carries only the request ID.

## Browser extension

Works in Firefox and in Chromium-based browsers such as Brave.

- **Brave/Chromium:** run `browser-extension/scripts/install-chromium-dev.sh` (builds `ua-browser-host` and writes the native-messaging manifest), then in `brave://extensions` turn on Developer mode, **Load unpacked**, and pick `browser-extension/chromium/`. The `key` in its manifest pins the extension ID the host allowlist expects. After pulling changes, click the reload icon on the extension card.
- **Firefox:** `browser-extension/scripts/install-firefox-dev.sh`, then load `browser-extension/manifest.json` from `about:debugging`.

`browser-extension/chromium/` differs from the Firefox build only by its manifest; after editing the shared sources run `browser-extension/scripts/sync-chromium.sh` (`verify-all.sh` fails if you forget).

### Using it

- **Filling.** Click into a password field: a small Universal Auth panel lists the saved logins for the site. Pick one and approve on your phone. Nothing is released until you pick.
- **Signing up / changing a password.** On new-password fields the panel leads with a generated password. It follows the site's rules when the page declares them (`passwordrules`, `minlength`, `maxlength`, `pattern`); otherwise 20 characters with symbols. **Options** adjusts length and symbols, and **Remember** keeps those choices for the site. **Use password** fills the new and confirm fields.
- **Saving.** After you submit a form, a banner offers to save the login (or, if that account is already saved, to update its password). The banner can follow a redirect within the same origin. For cross-origin sign-ins, use the toolbar to save the login on the sign-in page before submitting. Saving is instant; updating needs your fingerprint. Choose **Use on** to save for a parent domain (for example `utexas.edu`) so the login is also offered on its subdomains.
- **Toolbar button.** Lists the logins for the current site with Fill, Copy password, Edit and Delete; adds a login; links this site to a login saved for another site; and sets generator options for the site.

### Matching

A login is offered on a page when it was saved for that exact origin, for the same host with or without `www.`, for a parent domain (`utexas.edu` is offered on `enterprise.login.utexas.edu`, never the reverse), or when you linked the page to it. Scheme and port must match, IP addresses match exactly, and lookalikes such as `utexas.edu.evil.com` never match. Links live in `~/.config/universal-auth/site-aliases.json` on this computer, not in the vault, so neither the server nor a web page can change where a login is offered.

### Several accounts per site

Each login has an account label (default: the username), and a site can hold one login per label. With several, the panel and `vaultctl get --account` choose between them. Labels are stored unencrypted in the vault so the picker works without a fingerprint, the same way site origins already are. Passwords and usernames inside the encrypted payload stay encrypted.

### Approvals

| Action | Fingerprint |
| --- | --- |
| Fill, copy or reveal a password | yes |
| Save a new login | no (encryption only needs the Pixel's public key) |
| Change or delete a saved login | yes |

Changes and deletes are enforced by the vault, not just the tools. The desktop opens a `vault_write` request whose nonce is a hash of the exact change. The vault applies the change only with the Pixel's signature over that request, checked against the Pixel approval key in `VAULT_APPROVER_PUBLIC_KEY` (standard-Base64 SPKI, the `public_key` from the desktop config), and it accepts each approval once.

### Security notes

- The extension never receives the broker token, vault token, or any Pixel key.
- Origins always come from the browser (`sender.url`), never from page data. The host releases a login only if it is offered on the requesting origin, and saves only under that origin or one of its parent domains.
- Forms are never submitted automatically.

## Secure Release v1

The server no longer holds a decryption key. `VAULT_KEK` has been removed for v2 credentials. The flow is:

- Fedora generates a long-term ECDSA identity key and registers it with the broker.
- Pixel creates a second P-256 ECDH key in Android Keystore, protected by `BIOMETRIC_STRONG`.
- New credentials are encrypted on Fedora with a random 32-byte DEK.
- The DEK is wrapped to Pixel's vault public key using P-256 ECDH + HKDF-SHA256 + AES-256-GCM.
- The server stores only the ciphertext package and wrapped DEK; it cannot decrypt.
- To release, Fedora creates a fresh one-time ECDH key, signs the release request with its identity key, and polls the broker.
- Pixel verifies the desktop signature and request binding, prompts once for a strong biometric, uses its hardware key to unwrap the DEK, and re-encrypts the DEK to Fedora's one-time transfer public key.
- Fedora derives the transfer key locally, decrypts the DEK, and decrypts the username/password locally.

Firefox autofill still works: `ua-browser-host` fetches the ciphertext package from the server, performs the release protocol, and returns the plaintext.

Existing generic `authctl request` approvals and the Pixel approval signing key continue to work unchanged.

## Secrets and SSH keys (package v3, Secure Release v2)

Besides website logins, the vault stores generic secrets and SSH keys. A v3 package has a `kind` and a `resource`, and its plaintext is a map of named fields:

| Kind | Resource | Typical fields |
| --- | --- | --- |
| `login` | web origin, e.g. `https://github.com` | `username`, `password` |
| `secret` | name, e.g. `api-keys/openai` | any `KEY=VALUE` pairs |
| `ssh_key` | name, e.g. `ssh/github` | `private_key`, optional `passphrase`, `comment` |

Names are lowercase letters, digits and `. _ - /`, up to 128 characters. Kind and resource are bound into the package hash, the wrap key and the AEAD associated data, and the Pixel shows the resource it is releasing. Existing v2 login packages keep working, and the vault database is migrated in place on first start.

```bash
cd desktop-agent

# store (no approval)
vaultctl add --origin https://github.com --username andrew                 # prompts for the password
vaultctl add --origin https://github.com --username work@corp.com --generate --rules "maxlength: 16; required: upper; required: digit; allowed: lower"
vaultctl add --kind secret --name api-keys/openai --field API_KEY=sk-... --field ORG=me
vaultctl add --kind ssh_key --name ssh/github --field-file private_key=$HOME/.ssh/id_ed25519

# inspect (metadata only, no approval)
vaultctl list
vaultctl list --origin https://github.com

# release: one approval each
vaultctl get --origin https://github.com --account work@corp.com --field password
vaultctl get --name api-keys/openai --json
export OPENAI_API_KEY="$(vaultctl get --name api-keys/openai --field API_KEY)"

# change: one approval, plus one to read current values you don't supply
vaultctl edit --origin https://github.com --account andrew --generate        # new password, keeps username
vaultctl edit --id <id> --set-origin https://login.github.com
vaultctl edit --id <id> --set-account personal                              # label only: one approval
vaultctl delete --id <id>

# helpers
vaultctl generate --length 24
vaultctl generate --rules "minlength: 8; maxlength: 12; required: upper; required: digit; allowed: lower"
vaultctl link --site https://m.facebook.com --to https://www.facebook.com
```

`--field KEY=VALUE` puts the value in your shell history and process list; prefer `--field-file KEY=PATH` for anything sensitive.

### SSH agent

`ua-ssh-agent` serves the SSH agent protocol on a `0600` unix socket and never keeps a private key. Every signature request releases the key from the vault (one Pixel approval and fingerprint), signs once, and drops it. Ed25519, ECDSA (P-256/384/521) and RSA keys are supported.

```bash
go build -o ~/.local/bin/ua-ssh-agent ./cmd/ua-ssh-agent

ua-ssh-agent                       # offer every ssh_key in the vault
ua-ssh-agent --name ssh/github     # or only the named ones

export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/ua-ssh-agent.sock"
ssh-add -l
```

Listing keys needs no approval: `vaultctl add --kind ssh_key` saves the public half in `~/.config/universal-auth/ssh-public-keys.json`. On a machine without that entry the agent asks for one approval at startup to learn the public key. Before signing, the agent checks that the released key matches the public key it advertised.

The Pixel refuses a release when the resource shown in the approval prompt differs from the one inside the signed package.

### Upgrade order

Desktop tools now speak Secure Release v2, which older builds reject. Deploy the broker and vault service (`./scripts/deploy-dev.sh`), install the updated Android app, then rebuild the desktop binaries (`vaultctl`, `ua-browser-host`, `ua-ssh-agent`).

## Security notes

- Never commit `BROKER_TOKEN`, `VAULT_TOKEN`, SSH private keys, passwords, `broker.token`, `vault.token`, `identity.key`, or `vault.db` to this repository.
- The bearer token is transport authorization only; it cannot authorize a credential release.
- Legacy v1 credentials cannot be released through the new flow and will fail closed.
- Credential plaintext is never available to the server.
