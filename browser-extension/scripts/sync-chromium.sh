#!/usr/bin/env bash
# Copies the shared extension sources into browser-extension/chromium/, which
# differs from the Firefox build only by its manifest. With --check, fails if
# the copies are stale instead of updating them.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
FILES=(background.js content.js passgen.js popup.html popup.js icon-16.png icon-32.png icon-48.png icon-128.png)
status=0
for f in "${FILES[@]}"; do
  if [ "${1:-}" = "--check" ]; then
    if ! cmp -s "$DIR/$f" "$DIR/chromium/$f"; then
      echo "stale: browser-extension/chromium/$f (run browser-extension/scripts/sync-chromium.sh)" >&2
      status=1
    fi
  else
    cp "$DIR/$f" "$DIR/chromium/$f"
  fi
done
exit $status
