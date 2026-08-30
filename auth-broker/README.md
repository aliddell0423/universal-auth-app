# auth-broker

A minimal in-memory authentication broker for self-hosted home-server use.

This is the first MVP. It accepts authentication requests, stores them in memory, and allows a second client to approve or deny them.

## What this project does

- Exposes a small HTTP API on port `:8080`.
- Creates and tracks authentication requests with `pending`, `approved`, and `denied` statuses.
- Stores requests only in memory in a thread-safe map.
- Uses a static bearer token for development-only API authentication.
- Provides a multi-stage container image running as a non-root user.

## What this project explicitly does not do yet

The following are deliberately out of scope for this MVP and will come later:

- Android app or biometric authentication
- Cryptographic signing, passkeys, or hardware-backed keys
- WebSockets, SSE, gRPC, browser or SSH integration
- Persistent storage (SQLite, PostgreSQL, Redis)
- TLS, reverse proxy, OAuth, JWT, PAM, file encryption
- Kubernetes, Docker Compose, Podman Quadlet, CI/CD, or cloud deployment

## Prerequisites

- Go 1.26 (matching the module's `go` directive)
- Podman or Docker for container builds

## Run directly with Go

```bash
cd auth-broker
export BROKER_TOKEN=dev-only-change-this
go run ./cmd/broker
```

The service fails to start if `BROKER_TOKEN` is unset or empty.

## Run tests

```bash
cd auth-broker
go test ./...
go vet ./...
```

## Build with Podman

```bash
cd auth-broker
podman build -t auth-broker:dev .
```

## Run the container

```bash
podman run \
  --rm \
  --name auth-broker \
  -p 127.0.0.1:8080:8080 \
  -e BROKER_TOKEN=dev-only-change-this \
  auth-broker:dev
```

## Example curl workflow

This workflow simulates a PC creating a request and a second client (e.g. a fake phone) approving it.

```bash
# 1. Health check
curl http://127.0.0.1:8080/healthz

# 2. Create an authentication request
ID=$(curl -s -X POST \
  -H "Authorization: Bearer dev-only-change-this" \
  -H "Content-Type: application/json" \
  -d '{"source":"andrew-fedora","kind":"test","resource":"development","message":"Please authenticate"}' \
  http://127.0.0.1:8080/v1/requests | jq -r '.id')

# 3. List pending requests
curl -s -H "Authorization: Bearer dev-only-change-this" \
  http://127.0.0.1:8080/v1/requests/pending | jq

# 4. Approve the request (fake phone)
curl -s -X POST \
  -H "Authorization: Bearer dev-only-change-this" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approved"}' \
  http://127.0.0.1:8080/v1/requests/${ID}/decision | jq

# 5. Retrieve the approved request
curl -s -H "Authorization: Bearer dev-only-change-this" \
  http://127.0.0.1:8080/v1/requests/${ID} | jq
```

Expected flow:

```text
PC creates request
       ↓
broker stores pending request
       ↓
second curl command acts as fake phone
       ↓
request approved
       ↓
PC retrieves approved status
```

## API endpoint summary

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/healthz` | none | Health check |
| POST | `/v1/requests` | Bearer | Create a request |
| GET | `/v1/requests/pending` | Bearer | List pending requests |
| GET | `/v1/requests/{id}` | Bearer | Get a request |
| POST | `/v1/requests/{id}/decision` | Bearer | Approve or deny a request |

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `BROKER_TOKEN` | yes | Static bearer token for `/v1/*` endpoints. **DEVELOPMENT/MVP SECURITY ONLY.** |

## Security notice

The static bearer token in this MVP is a temporary convenience. It will be replaced with cryptographic device identities in a future milestone. Do not use this for real authentication without that replacement.
