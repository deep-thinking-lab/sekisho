#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
root="$(cd "$root" && pwd -P)"
allowed_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/allowed-deps.txt"

metadata="$(cargo metadata --format-version 1 --no-deps --manifest-path "$root/Cargo.toml")"

if command -v jq >/dev/null 2>&1; then
  deps="$(printf '%s\n' "$metadata" | jq -r --arg prefix "$root/crates/" '
    .packages[]
    | select(.manifest_path | startswith($prefix))
    | .manifest_path as $manifest
    | .dependencies[]
    | [.name, $manifest] | @tsv
  ')"
else
  deps="$(printf '%s\n' "$metadata" | python3 -c '
import json
import sys

prefix = sys.argv[1] + "/crates/"
for package in json.load(sys.stdin)["packages"]:
    manifest = package["manifest_path"]
    if manifest.startswith(prefix):
        for name in package["dependencies"]:
            print(name["name"] + "\t" + manifest)
' "$root")"
fi

status=0
while IFS=$'\t' read -r name manifest; do
  [ -n "$name" ] || continue
  if ! grep -Fxq -- "$name" "$allowed_file"; then
    echo "disallowed dependency: $name (${manifest#"$root"/})"
    status=1
  fi
done <<< "$deps"

exit "$status"
