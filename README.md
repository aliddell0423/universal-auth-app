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

The current app only:

- fetches pending requests from the broker,
- displays source, kind, resource, message, and creation time,
- lets you approve or deny a request,
- refreshes the list after a decision.

Biometrics, cryptographic signing, and other integrations are not yet implemented.

## Security notes

- Never commit `BROKER_TOKEN`, SSH private keys, or passwords to this repository.
- The bearer token is development-only and will be replaced by cryptographic device identities later.
