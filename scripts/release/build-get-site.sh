#!/usr/bin/env bash
# Build the deploy directory for get.sekisho.sh, the Cloudflare Pages project
# `sekisho-get` (separate from the site project `sekisho-dev`). Builds only; it
# never deploys.
#
# Usage: build-get-site.sh <out-dir> <install.sh.minisig>
#
# The signature is the `install.sh.minisig` asset of the release whose
# install.sh this checkout holds. Before anything is written it must verify
# against the pinned release key in site/public/release-key.txt, with the
# trusted comment `sekisho-install v<crate version>`. SEKISHO_RELEASE_KEY_FILE
# may name another copy of the key, but the build refuses it unless it is
# identical to the pinned key, so a test key can never reach the deploy output.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
  printf 'build-get-site: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 2 ] || fail "usage: build-get-site.sh <out-dir> <install.sh.minisig>"
out="$1"
signature="$2"
pinned_key_file="$root/site/public/release-key.txt"
key_file="${SEKISHO_RELEASE_KEY_FILE:-$pinned_key_file}"

command -v minisign >/dev/null 2>&1 || fail "minisign is required"
[ -f "$signature" ] || fail "signature file not found: $signature"
[ -f "$key_file" ] || fail "release key file not found: $key_file"
cmp -s "$key_file" "$pinned_key_file" ||
  fail "$key_file is not the pinned release key in site/public/release-key.txt"
pinned_key="$(sed -n '2p' "$pinned_key_file")"
grep -qx "MINISIGN_PUBLIC_KEY=\"$pinned_key\"" "$root/install.sh" ||
  fail "install.sh does not embed the pinned release key"

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/crates/sekisho/Cargo.toml" | head -n 1)"
[ -n "$version" ] || fail "cannot read the sekisho crate version"
comment="$(minisign -V -Q -m "$root/install.sh" -x "$signature" -p "$pinned_key_file")" ||
  fail "install.sh.minisig does not verify install.sh with the pinned release key"
[ "$comment" = "sekisho-install v$version" ] ||
  fail "install.sh.minisig is signed for '$comment', not 'sekisho-install v$version'"
if [ -e "$out" ] && [ -n "$(ls -A "$out")" ]; then
  fail "output directory is not empty: $out"
fi

mkdir -p "$out"
cp "$root/install.sh" "$out/install.sh"
cp "$root/install.sh" "$out/index.html"
cp "$signature" "$out/install.sh.minisig"
cp "$pinned_key_file" "$out/release-key.txt"
# With a 404.html, Pages answers unknown paths with 404 instead of serving
# index.html (the installer) as a single-page-app fallback.
cat >"$out/404.html" <<'NOTFOUND'
Not found. The Sekisho installer is https://get.sekisho.sh/install.sh
NOTFOUND
cat >"$out/_headers" <<'HEADERS'
/*
  X-Content-Type-Options: nosniff
/
  Content-Type: text/plain; charset=utf-8
  Cache-Control: no-cache
/index.html
  Content-Type: text/plain; charset=utf-8
  Cache-Control: no-cache
/install.sh
  Content-Type: text/plain; charset=utf-8
  Cache-Control: no-cache
/install.sh.minisig
  Content-Type: text/plain; charset=utf-8
  Cache-Control: no-cache
/release-key.txt
  Content-Type: text/plain; charset=utf-8
HEADERS
printf '%s\n' "$out"
