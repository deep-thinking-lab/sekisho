#!/usr/bin/env bash
# Fails if any GitHub workflow could sign a release. The release signing key
# lives offline with the maintainer, who signs SHA256SUMS and install.sh by
# hand. CI builds unsigned draft releases only, so no workflow may reference a
# MINISIGN_* secret, the old signing variables, or run `minisign -S`.
# Usage: check-release-signing.sh [dir]   (default: the repository's .github)
set -euo pipefail

dir="${1:-$(cd "$(dirname "$0")/.." && pwd)/.github}"
[ -d "$dir" ] || {
  printf 'check-release-signing: no such directory: %s\n' "$dir" >&2
  exit 1
}

files=()
while IFS= read -r -d '' file; do
  files+=("$file")
done < <(find "$dir" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)
[ "${#files[@]}" -gt 0 ] || {
  printf 'check-release-signing: no workflow files under %s\n' "$dir" >&2
  exit 1
}

status=0
forbid() {
  local why="$1"
  shift
  local hits
  if hits="$(grep -n -H -E "$@" -- "${files[@]}")"; then
    printf 'check-release-signing: %s:\n%s\n' "$why" "$hits" >&2
    status=1
  fi
}

# GitHub secret names are case-insensitive, so match secrets.minisign_* too.
forbid 'a workflow references a MINISIGN_* secret' \
  -i -e "secrets[[:space:]]*(\.|\[)[[:space:]]*[\"']?minisign_"
forbid 'a workflow hands every secret to a step' \
  -i -e 'tojson\([[:space:]]*secrets[[:space:]]*\)'
forbid 'a workflow mentions MINISIGN_SECRET_KEY' -i -e 'MINISIGN_SECRET_KEY'
forbid 'a workflow mentions MINISIGN_PASSWORD' -i -e 'MINISIGN_PASSWORD'
forbid 'a workflow signs with minisign -S' \
  -e 'minisign([[:space:]]+[^[:space:]]+)*[[:space:]]+-[A-Za-z]*S'

if [ "$status" -ne 0 ]; then
  printf 'check-release-signing: the release key is offline only; CI must not sign (see docs/decisions/0001-offline-release-signing.md)\n' >&2
  exit 1
fi
echo "check-release-signing: ok"
