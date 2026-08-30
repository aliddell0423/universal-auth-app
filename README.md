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

## Security notes

- Never commit `BROKER_TOKEN`, SSH private keys, or passwords to this repository.
- The bearer token is development-only and will be replaced by cryptographic device identities later.
