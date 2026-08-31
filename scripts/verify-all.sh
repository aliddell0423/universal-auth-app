#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Verifying contract fixture sync ==="
"$ROOT/scripts/verify-contract-fixtures.sh"

for mod in auth-broker vault-service desktop-agent; do
    echo "=== $mod: go test + go vet ==="
    (cd "$ROOT/$mod" && go test ./... && go vet ./...)
done

echo "=== Android: unit tests ==="
(cd "$ROOT/auth_client" && ./gradlew :app:testDebugUnitTest)

echo "=== Android: assemble debug ==="
(cd "$ROOT/auth_client" && ./gradlew :app:assembleDebug)

echo "=== All verification passed ==="
