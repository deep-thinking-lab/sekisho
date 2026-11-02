#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <git-url> <ref>" >&2
  exit 2
fi

git_url="$1"
ref="$2"

for tool in git just cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ci-runner: missing required command: $tool" >&2
    exit 1
  fi
done

work="$(mktemp -d "${TMPDIR:-/tmp}/sekisho-ci.XXXXXX")"
trap 'rm -rf "$work"' EXIT

repo="$work/repo"
target="$work/target"

if ! git clone --quiet "$git_url" "$repo"; then
  echo "CI FAIL unknown clone"
  exit 1
fi

if ! git -C "$repo" checkout --quiet "$ref"; then
  echo "CI FAIL unknown checkout"
  exit 1
fi

if ! sha="$(git -C "$repo" rev-parse --verify HEAD)"; then
  echo "CI FAIL unknown checkout"
  exit 1
fi

log="$work/ci.log"
set +e
(cd "$repo" && CARGO_TARGET_DIR="$target" just ci) 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
set -e

if [ "$status" -eq 0 ]; then
  echo "CI PASS $sha"
  exit 0
fi

step="$(sed -n "s/^error: [Rr]ecipe \`\([^\`]*\)\` failed.*\$/\1/p" "$log" | tail -n 1)"
[ -n "$step" ] || step="unknown"
echo "CI FAIL $sha $step"
exit 1
