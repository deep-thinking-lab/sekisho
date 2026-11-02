#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/sekisho-release-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

for tool in actionlint minisign shellcheck; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

actionlint "$root/.github/workflows/ci.yml" "$root/.github/workflows/release.yml"
shellcheck "$root/install.sh"
shellcheck "$root/scripts/demo.sh"
shellcheck "$root/scripts/docker-entrypoint.sh"
shellcheck "$root/scripts/release/local-build.sh"
shellcheck "$root/scripts/release/test-release.sh"
shellcheck "$root/scripts/release/build-get-site.sh"
shellcheck "$root/scripts/check-release-signing.sh"

# CI never signs: the check passes on the real workflows and refuses each way a
# workflow could reach the offline release key.
"$root/scripts/check-release-signing.sh" >/dev/null ||
  fail "a workflow references the release signing key"
workflows="$tmp/workflows"
mkdir "$workflows"
# shellcheck disable=SC2016 # literal workflow text, not shell expansions
printf 'on: push\njobs:\n  ok:\n    runs-on: ubuntu-latest\n    steps:\n      - run: minisign -Vm SHA256SUMS -P "$KEY"\n' >"$workflows/ok.yml"
"$root/scripts/check-release-signing.sh" "$workflows" >/dev/null ||
  fail "release signing check refused a verify-only workflow"
# shellcheck disable=SC2016 # literal workflow text, not shell expansions
for forbidden in \
  'KEY: ${{ secrets.MINISIGN_KEY }}' \
  "KEY: \${{ secrets['minisign_anything'] }}" \
  'ALL: ${{ toJSON(secrets) }}' \
  'run: echo "$MINISIGN_SECRET_KEY"' \
  'run: echo "$MINISIGN_PASSWORD"' \
  'run: minisign -S -s key -m SHA256SUMS' \
  'run: minisign -W -Sm SHA256SUMS'; do
  printf 'on: push\n# %s\n' "$forbidden" >"$workflows/bad.yaml"
  if "$root/scripts/check-release-signing.sh" "$workflows" >/dev/null 2>&1; then
    fail "release signing check accepted: $forbidden"
  fi
done
rm "$workflows/bad.yaml"

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/crates/sekisho/Cargo.toml" | head -n 1)"
[ -n "$version" ] || fail "cannot read the sekisho crate version"

dist="$tmp/dist"
target="$tmp/target"
archive="$(
  SEKISHO_DIST_DIR="$dist" \
    CARGO_TARGET_DIR="$target" \
    "$root/scripts/release/local-build.sh" "v$version"
)"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) platform=linux-x86_64 ;;
  Linux/aarch64|Linux/arm64) platform=linux-arm64 ;;
  Darwin/arm64) platform=darwin-arm64 ;;
  *) fail "unsupported test host: $(uname -s)/$(uname -m)" ;;
esac

# The archive version must be the crate version the binary reports.
if output="$(
  SEKISHO_DIST_DIR="$tmp/wrong-dist" CARGO_TARGET_DIR="$target" \
    "$root/scripts/release/local-build.sh" "v9.9.9" 2>&1
)"; then
  fail "local build packaged version 9.9.9 from crate version $version"
fi
case "$output" in
  *"does not match crates/sekisho/Cargo.toml version $version"*) ;;
  *) fail "mismatched version refusal printed: $output" ;;
esac
[ ! -e "$tmp/wrong-dist" ] || fail "local build wrote output for a mismatched version"

expected_archive="$dist/sekisho-$version-$platform.tar.gz"
[ "$archive" = "$expected_archive" ] ||
  fail "local build wrote $archive, want $expected_archive"
[ -s "$archive" ] || fail "local build did not create a tarball"

mkdir "$tmp/extract"
tar -xzf "$archive" -C "$tmp/extract"
version_output="$("$tmp/extract/sekisho" --version)"
[ "$version_output" = "sekisho $version" ] ||
  fail "packaged binary printed: $version_output"

release_key="$(sed -n '2p' "$root/site/public/release-key.txt")"
grep -qx "MINISIGN_PUBLIC_KEY=\"$release_key\"" "$root/install.sh" ||
  fail "install.sh does not ship the key published in site/public/release-key.txt"
# An installer without a key must still refuse to run.
sed 's|^MINISIGN_PUBLIC_KEY=.*|MINISIGN_PUBLIC_KEY="RWQ_PLACEHOLDER"|' "$root/install.sh" >"$tmp/install-placeholder.sh"
chmod +x "$tmp/install-placeholder.sh"
missing_release="$tmp/missing"
mkdir "$missing_release"
if output="$(
  SEKISHO_RELEASE_BASE_URL="file://$missing_release" \
    SEKISHO_VERSION="$version" \
    "$tmp/install-placeholder.sh" 2>&1
)"; then
  fail "installer accepted the placeholder public key"
fi
case "$output" in
  *"has no release public key"*) ;;
  *) fail "placeholder refusal printed: $output" ;;
esac

minisign -G -W -p "$tmp/minisign.pub" -s "$tmp/minisign.key" >/dev/null
public_key="$(sed -n '2p' "$tmp/minisign.pub")"
[ -n "$public_key" ] || fail "minisign did not create a public key"
awk -v key="$public_key" '
  /^MINISIGN_PUBLIC_KEY=/ {
    print "MINISIGN_PUBLIC_KEY=\"" key "\""
    next
  }
  { print }
' "$root/install.sh" >"$tmp/install.sh"
chmod 0755 "$tmp/install.sh"

release="$tmp/release"
mkdir "$release"
cp "$archive" "$release/"
archive_name="$(basename "$archive")"
archive_hash="$(sha256_file "$release/$archive_name")"

# sign_sums <trusted comment>: sign $release/SHA256SUMS the way the release
# runbook does, with the version in the trusted comment.
sign_sums() {
  rm -f "$release/SHA256SUMS.minisig"
  minisign -S -s "$tmp/minisign.key" -m "$release/SHA256SUMS" \
    -x "$release/SHA256SUMS.minisig" -t "$1" -q
}

# run_installer <bin-dir> [VAR=value...]: run the test installer against the
# local release directory, pinned to $version unless the caller overrides it.
run_installer() {
  bin="$1"
  shift
  env SEKISHO_INSTALL_BIN_DIR="$bin" \
    SEKISHO_RELEASE_BASE_URL="file://$release" \
    SEKISHO_VERSION="$version" \
    "$@" "$tmp/install.sh" 2>&1
}

printf '%s  %s\n' "$archive_hash" "$archive_name" >"$release/SHA256SUMS"
sign_sums "sekisho v$version"

install_bin="$tmp/install-bin"
mkdir "$install_bin"
run_installer "$install_bin" >/dev/null || fail "installer refused a correctly signed release"
[ -x "$install_bin/sekisho" ] || fail "installer did not install sekisho"
installed_version="$("$install_bin/sekisho" --version)"
[ "$installed_version" = "sekisho $version" ] ||
  fail "installed binary printed: $installed_version"

# expect_refusal <name> <message> <VAR=value...>: the installer must fail with
# <message> and write no binary.
expect_refusal() {
  name="$1"
  message="$2"
  shift 2
  refused_bin="$tmp/refused-$name"
  mkdir "$refused_bin"
  if output="$(run_installer "$refused_bin" "$@")"; then
    fail "installer accepted $name"
  fi
  case "$output" in
    *"$message"*) ;;
    *) fail "$name refusal printed: $output" ;;
  esac
  [ ! -e "$refused_bin/sekisho" ] || fail "installer wrote a binary after refusing $name"
}

# The trusted comment binds the version: an old signed SHA256SUMS, or one
# signed without the version, cannot pass for this release.
sign_sums "SHA256SUMS"
expect_refusal unversioned-comment "is signed for 'SHA256SUMS', not 'sekisho v$version'"
sign_sums "sekisho v0.0.1"
expect_refusal other-version-comment "not 'sekisho v$version'"
sign_sums "sekisho v$version extra"
expect_refusal padded-comment "not 'sekisho v$version'"

# "Latest" is the highest stable semver in the list, never a prerelease, and
# release text cannot inject a tag. The signed comment must still match it.
cat >"$tmp/releases.json" <<'JSON'
[
  {"tag_name": "v0.9.9", "body": "see \"tag_name\": \"v9.9.9\""},
  {
    "tag_name": "v0.10.0",
    "prerelease": false
  },
  {"tag_name": "v1.0.0-rc.1", "prerelease": true},
  {"tag_name": "v0.2.0"}
]
JSON
sign_sums "sekisho v$version"
expect_refusal latest-by-semver "not 'sekisho v0.10.0'" \
  SEKISHO_VERSION= SEKISHO_RELEASES_API_URL="file://$tmp/releases.json"

# Downloads are HTTPS only and size capped.
expect_refusal plain-http "refusing to download over anything but HTTPS" \
  SEKISHO_RELEASE_BASE_URL="http://127.0.0.1:9/release"
cp "$release/SHA256SUMS" "$tmp/SHA256SUMS.good"
head -c 2097152 /dev/zero >>"$release/SHA256SUMS"
expect_refusal oversized-sums "could not download file://$release/SHA256SUMS"
cp "$tmp/SHA256SUMS.good" "$release/SHA256SUMS"

printf '%064d  %s\n' 0 "$archive_name" >"$release/SHA256SUMS"
sign_sums "sekisho v$version"
expect_refusal tampered-checksum "checksum mismatch"

fake_bin="$tmp/fake-bin"
mkdir "$fake_bin"
cat >"$fake_bin/sekisho" <<'EOF'
#!/bin/sh
printf "%s\n" "$*" >"$SEKISHO_TEST_ARGS"
EOF
chmod 0755 "$fake_bin/sekisho"

SEKISHO_TEST_ARGS="$tmp/loopback-args" \
  PATH="$fake_bin:$PATH" \
  "$root/scripts/docker-entrypoint.sh"
[ "$(cat "$tmp/loopback-args")" = "up" ] ||
  fail "Docker entrypoint did not default to loopback"

SEKISHO_INSECURE_BIND=1 \
  SEKISHO_TEST_ARGS="$tmp/public-args" \
  PATH="$fake_bin:$PATH" \
  "$root/scripts/docker-entrypoint.sh"
[ "$(cat "$tmp/public-args")" = "up --bind 0.0.0.0:7470 --insecure-bind" ] ||
  fail "Docker entrypoint did not enable the public bind"

if output="$(
  SEKISHO_INSECURE_BIND=true \
    SEKISHO_TEST_ARGS="$tmp/invalid-args" \
    PATH="$fake_bin:$PATH" \
    "$root/scripts/docker-entrypoint.sh" 2>&1
)"; then
  fail "Docker entrypoint accepted a non-explicit public bind"
fi
case "$output" in
  *"SEKISHO_INSECURE_BIND must be 1"*) ;;
  *) fail "Docker entrypoint rejection printed: $output" ;;
esac

# get.sekisho.sh deploy directory: built only from a signature that verifies
# with the pinned key and names this release. The real key is offline, so the
# success path runs in a copy of the tree that pins the test key.
get_root="$tmp/get-root"
mkdir -p "$get_root/scripts/release" "$get_root/site/public" "$get_root/crates/sekisho"
cp "$root/scripts/release/build-get-site.sh" "$get_root/scripts/release/"
cp "$root/crates/sekisho/Cargo.toml" "$get_root/crates/sekisho/"
cp "$tmp/install.sh" "$get_root/install.sh"
cp "$tmp/minisign.pub" "$get_root/site/public/release-key.txt"
get_site="$get_root/scripts/release/build-get-site.sh"
minisign -S -s "$tmp/minisign.key" -m "$get_root/install.sh" -x "$tmp/install.sh.minisig" \
  -t "sekisho-install v$version" -q
"$get_site" "$tmp/get" "$tmp/install.sh.minisig" >/dev/null ||
  fail "get site build refused a correctly signed installer"
for file in index.html install.sh install.sh.minisig release-key.txt _headers 404.html; do
  [ -s "$tmp/get/$file" ] || fail "get site is missing $file"
done
cmp -s "$get_root/install.sh" "$tmp/get/index.html" || fail "get site / is not install.sh"
cmp -s "$get_root/site/public/release-key.txt" "$tmp/get/release-key.txt" ||
  fail "get site release-key.txt is not the pinned key"
minisign -Vm "$tmp/get/index.html" -x "$tmp/get/install.sh.minisig" \
  -p "$tmp/get/release-key.txt" -q || fail "get site signature does not verify"
if grep -q '^#!' "$tmp/get/404.html" || cmp -s "$tmp/get/404.html" "$get_root/install.sh"; then
  fail "get site 404.html is the installer"
fi
awk '
  /^\// { path = $0; next }
  { headers[path] = headers[path] "|" $0 }
  END {
    ok = headers["/*"] ~ /X-Content-Type-Options: nosniff/
    split("/ /index.html /install.sh /install.sh.minisig", paths, " ")
    for (i in paths) {
      h = headers[paths[i]]
      if (h !~ /Content-Type: text\/plain; charset=utf-8/ || h !~ /Cache-Control: no-cache/) ok = 0
    }
    exit ok ? 0 : 1
  }
' "$tmp/get/_headers" || fail "get site _headers lacks nosniff, text/plain or no-cache"

# expect_get_site_refusal <name> <message> <command...>
expect_get_site_refusal() {
  name="$1"
  message="$2"
  shift 2
  if output="$("$@" 2>&1)"; then
    fail "get site build accepted $name"
  fi
  case "$output" in
    *"$message"*) ;;
    *) fail "get site $name refusal printed: $output" ;;
  esac
  [ ! -e "$tmp/get-bad" ] || fail "get site build wrote output after refusing $name"
}

# A key other than the pinned one never reaches the deploy output.
expect_get_site_refusal test-key "is not the pinned release key" \
  env SEKISHO_RELEASE_KEY_FILE="$tmp/minisign.pub" \
  "$root/scripts/release/build-get-site.sh" "$tmp/get-bad" "$tmp/install.sh.minisig"
minisign -S -s "$tmp/minisign.key" -m "$get_root/install.sh" -x "$tmp/old.minisig" \
  -t "install.sh" -q
expect_get_site_refusal unversioned-comment "not 'sekisho-install v$version'" \
  "$get_site" "$tmp/get-bad" "$tmp/old.minisig"
printf 'tampered\n' >"$tmp/bad.minisig"
expect_get_site_refusal bad-signature "does not verify install.sh" \
  "$get_site" "$tmp/get-bad" "$tmp/bad.minisig"

printf 'release tests ok\n'
