#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version>" >&2
  exit 64
fi

version="${1#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || {
  echo "invalid version: $1" >&2
  exit 64
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
dist_dir="${SEKISHO_DIST_DIR:-$repo_root/dist}"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
case "$target_dir" in
  /*) ;;
  *) target_dir="$repo_root/$target_dir" ;;
esac

if [ -n "${RELEASE_TARGET:-}" ]; then
  target="$RELEASE_TARGET"
else
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux/aarch64|Linux/arm64) target=aarch64-unknown-linux-gnu ;;
    Darwin/arm64) target=aarch64-apple-darwin ;;
    *)
      echo "unsupported host: $(uname -s)/$(uname -m)" >&2
      exit 64
      ;;
  esac
fi

case "$target" in
  x86_64-unknown-linux-gnu) release_platform=linux-x86_64 ;;
  aarch64-unknown-linux-gnu) release_platform=linux-arm64 ;;
  aarch64-apple-darwin) release_platform=darwin-arm64 ;;
  *)
    echo "unsupported release target: $target" >&2
    exit 64
    ;;
esac

crate_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo_root/crates/sekisho/Cargo.toml" | head -n 1)"
[ "$crate_version" = "$version" ] || {
  echo "release version $version does not match crates/sekisho/Cargo.toml version $crate_version" >&2
  exit 65
}

stage="$(mktemp -d "${TMPDIR:-/tmp}/sekisho-release.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$dist_dir"

(
  cd "$repo_root"
  cargo build --release --locked --target "$target" -p sekisho --bin sekisho
)

install -m 0755 "$target_dir/$target/release/sekisho" "$stage/sekisho"
cp "$repo_root/LICENSE" "$stage/LICENSE"
built_version="$("$stage/sekisho" --version)"
[ "$built_version" = "sekisho $version" ] || {
  echo "built binary prints '$built_version', not 'sekisho $version'" >&2
  exit 65
}

archive="$dist_dir/sekisho-${version}-${release_platform}.tar.gz"
COPYFILE_DISABLE=1 tar -czf "$archive" -C "$stage" sekisho LICENSE
printf '%s\n' "$archive"
