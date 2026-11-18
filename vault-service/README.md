# vault-service

A small Go service that stores credentials in a SQLite database, encrypted at rest using per-credential AES-256-GCM DEKs, wrapped by a temporary 32-byte `VAULT_KEK`.

## Important: development-only, server-held key

This service is **not** the final vault architecture. Right now the Ubuntu server holds `VAULT_KEK`. A full compromise of that server can theoretically expose credentials. The purpose of this milestone is real persistence, real encryption at rest, and real API integration. The next architecture will use Pixel-controlled key release.

## Configuration

The service reads the following environment variables:

- `VAULT_TOKEN` — Bearer token for `/v1/*` endpoints. Must be non-empty.
- `VAULT_KEK` — Base64-encoded 32-byte key encryption key. Must decode to exactly 32 bytes. Must be non-empty.
- `VAULT_ADDR` — listen address. Default `:8081`.
- `VAULT_DB_PATH` — SQLite database path. Default `/data/vault.db`.

Generate development secrets:

```bash
openssl rand -hex 32 > /tmp/token
openssl rand -base64 32 > /tmp/kek
printf 'VAULT_TOKEN=%s\nVAULT_KEK=%s\n' "$(cat /tmp/token)" "$(tr -d '\n' < /tmp/kek)" > ~/.config/universal-auth-vault/vault.env
chmod 600 ~/.config/universal-auth-vault/vault.env
```

## Build and run

```bash
cd vault-service
go test ./...
go vet ./...
go build -o vault-service ./cmd/vault-service
./vault-service
```

## API

All `/v1/*` endpoints require `Authorization: Bearer <VAULT_TOKEN>`.

- `GET /healthz`, `GET /readyz`
- `GET /v1/credentials[?resource=...&kind=...]`: list metadata (`credential_id`, `kind`, `resource`, `account`, timestamps). Never secrets.
- `POST /v1/credentials`: store a new encrypted package. `(kind, resource, account)` must be unique.
- `GET /v1/credentials/exists?resource=...[&kind=...]`
- `GET /v1/credentials/package?resource=...[&kind=...][&account=...]`: fetch the encrypted package. Returns 409 if several entries match.
- `GET /v1/credentials/{id}`: fetch the encrypted package by ID.
- `PUT /v1/credentials/{id}` with `{"package": ..., "approval": <approved vault_write broker request>}`: replace the package (same credential ID and kind; resource and account may change).
- `DELETE /v1/credentials/{id}` with `{"approval": ...}`: delete.

`resource` is a web origin for `login` packages or a secret name for `secret` and `ssh_key` packages; `origin=` is accepted as an alias.

### Write approvals

`PUT` and `DELETE` need a Pixel-approved broker request of kind `vault_write`. Its `client_nonce` must equal `base64url(sha256(canonical write))` (format pinned by `testdata/contracts/vault_write_canonical.txt`), its `resource` must be the credential's current resource, and its signature must verify against `VAULT_APPROVER_PUBLIC_KEY`. Each approval is accepted once. Without `VAULT_APPROVER_PUBLIC_KEY`, `PUT` and `DELETE` return 503.

## Encryption

Each credential is stored as:

- `ciphertext` — AES-256-GCM over the JSON payload, with a fresh random DEK and nonce.
- `wrapped_dek` — AES-256-GCM over the DEK, using `VAULT_KEK`, with a separate fresh nonce.
- AAD binds `crypto_version`, `id`, and `origin`.
- Origins are normalized to `scheme://host[:port]`, accepting only `http` and `https`, with exact matching.
