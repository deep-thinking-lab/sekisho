#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
budget=25000

[ -d "$root/crates" ] || {
  echo "no crates directory under $root" >&2
  exit 2
}

loc=0
while IFS= read -r file; do
  case "$file" in
    */tests/*) continue ;;
  esac
  case "$(basename "$file")" in
    *_tests.rs) continue ;;
  esac
  count="$(awk '!/^[[:space:]]*$/ && !/^[[:space:]]*\/\// { n++ } END { print n + 0 }' "$file")"
  loc=$((loc + count))
done < <(find "$root/crates" -type f -name '*.rs' -path '*/src/*')

echo "rust_loc=$loc budget=$budget"
[ "$loc" -le "$budget" ]
