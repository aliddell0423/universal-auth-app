# Agent notes

- Verify everything: `./scripts/verify-all.sh` (fixture sync, Go test + vet for `auth-broker`, `vault-service`, `desktop-agent`, Android unit tests and debug build).
- Each Go component is its own module; run `go` commands from inside its directory, not the repo root.
- Contract fixtures live in `testdata/contracts/` and are mirrored for Android: after changing them run `rsync -a testdata/contracts/ auth_client/app/src/test/resources/contracts/`.
- `testdata/contracts/release_vector_v3.json` is generated: `cd desktop-agent && UPDATE_VECTORS=1 go test ./internal/release/ -run TestContractReleaseVectorV3`, then re-sync. The Android `SecureReleaseVectorTest` consumes it.
- Wire formats (package canonical form, AAD, salts, release request) are implemented twice, in `desktop-agent/internal/{vaultcrypto,release}` and `auth_client/.../crypto/SecureRelease.kt`; change both together.
