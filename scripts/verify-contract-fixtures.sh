#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_FIXTURES="$ROOT/testdata/contracts"
ANDROID_FIXTURES="$ROOT/auth_client/app/src/test/resources/contracts"

if [ ! -d "$REPO_FIXTURES" ]; then
    echo "Repository fixtures not found: $REPO_FIXTURES" >&2
    exit 1
fi

if [ ! -d "$ANDROID_FIXTURES" ]; then
    echo "Android fixtures not found: $ANDROID_FIXTURES" >&2
    exit 1
fi

diff -r "$REPO_FIXTURES" "$ANDROID_FIXTURES" >/dev/null 2>&1 || {
    echo "Contract fixture drift detected between:" >&2
    echo "  $REPO_FIXTURES" >&2
    echo "  $ANDROID_FIXTURES" >&2
    echo "Run 'rsync -av "$REPO_FIXTURES/" "$ANDROID_FIXTURES/"' to sync Android to the repository fixtures." >&2
    exit 1
}

echo "Contract fixtures are in sync."
