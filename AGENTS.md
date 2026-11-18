# Agent notes

- Verify everything: `./scripts/verify-all.sh` (fixture sync, Go test + vet for `auth-broker`, `vault-service`, `desktop-agent`, Android unit tests and debug build).
- Each Go component is its own module; run `go` commands from inside its directory, not the repo root.
- Contract fixtures live in `testdata/contracts/` and are mirrored for Android: after changing them run `rsync -a testdata/contracts/ auth_client/app/src/test/resources/contracts/`.
- `testdata/contracts/release_vector_v3.json` is generated: `cd desktop-agent && UPDATE_VECTORS=1 go test ./internal/release/ -run TestContractReleaseVectorV3`, then re-sync. The Android `SecureReleaseVectorTest` consumes it.
- Wire formats (package canonical form, AAD, salts, release request) are implemented twice, in `desktop-agent/internal/{vaultcrypto,release}` and `auth_client/.../crypto/SecureRelease.kt`; change both together.
- Browser extension sources live in `browser-extension/`; `browser-extension/chromium/` is a copy with its own manifest. After editing, run `browser-extension/scripts/sync-chromium.sh`. Generator tests: `node --test browser-extension/test/`.
- The vault-write canonical form (`testdata/contracts/vault_write_canonical.txt`) is implemented in `vault-service/internal/approval` and `desktop-agent/internal/vaultwrite`; regenerate with `cd vault-service && UPDATE_VECTORS=1 go test ./internal/api/ -run TestWriteCanonicalFixture`, then re-sync the Android fixtures.
- The deployed vault needs `VAULT_APPROVER_PUBLIC_KEY` (the Pixel approval key, `trusted_device.public_key` in the desktop config) in `~/.config/universal-auth-vault/vault.env`; without it edits and deletes are refused.
