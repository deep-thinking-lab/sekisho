#!/usr/bin/env bash
# In a public snapshot (marked by .public-tree), fails if any private-only path from
# .public-exclude is present. In the private development repository it does nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .public-tree ] || { echo "check-public-tree: private repository, skipped"; exit 0; }
found=0
while IFS= read -r path; do
    case "$path" in ''|'#'*) continue ;; esac
    if [ -e "$path" ]; then echo "check-public-tree: private path present: $path" >&2; found=1; fi
done < .public-exclude
[ "$found" -eq 0 ] || exit 1
echo "check-public-tree: ok"
