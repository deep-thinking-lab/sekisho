#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

last_out=""

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

run_expect() {
  local want="$1" label="$2"
  shift 2
  local status
  if last_out="$("$@" 2>&1)"; then status=0; else status=$?; fi
  [ "$status" -eq "$want" ] ||
    fail "$label exited $status, want $want"$'\n'"$last_out"
}

loc_root="$tmp/loc"
mkdir -p "$loc_root/crates/fake/src/tests" "$loc_root/crates/fake/tests"
awk 'BEGIN { for (i = 1; i <= 25001; i++) print "fn f" i "() {}" }' \
  > "$loc_root/crates/fake/src/lib.rs"
cat >> "$loc_root/crates/fake/src/lib.rs" <<'EOF'

// a comment line
   // an indented comment line

EOF
for excluded in "$loc_root/crates/fake/src/tests/huge.rs" \
  "$loc_root/crates/fake/src/huge_tests.rs" \
  "$loc_root/crates/fake/tests/huge.rs"; do
  awk 'BEGIN { for (i = 1; i <= 30000; i++) print "fn t" i "() {}" }' > "$excluded"
done

run_expect 1 "loc.sh over-budget fixture" "$root/scripts/loc.sh" "$loc_root"
[ "$last_out" = "rust_loc=25001 budget=25000" ] ||
  fail "loc.sh fixture counted the wrong lines: $last_out"

budget_root="$tmp/budget"
mkdir -p "$budget_root/crates/fake/src"
awk 'BEGIN { for (i = 1; i <= 25000; i++) print "fn b" i "() {}" }' \
  > "$budget_root/crates/fake/src/lib.rs"
run_expect 0 "loc.sh at-budget fixture" "$root/scripts/loc.sh" "$budget_root"
[ "$last_out" = "rust_loc=25000 budget=25000" ] ||
  fail "loc.sh at-budget fixture counted the wrong lines: $last_out"

deps_root="$tmp/deps"
mkdir -p "$deps_root/crates/fake/src"
: > "$deps_root/crates/fake/src/lib.rs"
cat > "$deps_root/Cargo.toml" <<'EOF'
[workspace]
resolver = "2"
members = ["crates/fake"]
EOF
cat > "$deps_root/crates/fake/Cargo.toml" <<'EOF'
[package]
name = "fake"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"
regex = "1"

[dev-dependencies]
once_cell = "1"

[build-dependencies]
cc = "1"
EOF

target_deps_root="$tmp/target-deps"
mkdir -p "$target_deps_root/crates/fake/src"
: > "$target_deps_root/crates/fake/src/lib.rs"
cat > "$target_deps_root/Cargo.toml" <<'EOF'
[workspace]
resolver = "2"
members = ["crates/fake"]
EOF
cat > "$target_deps_root/crates/fake/Cargo.toml" <<'EOF'
[package]
name = "fake"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[target.'cfg(windows)'.dev-dependencies]
winapi = "0.3"

[target.'cfg(target_os = "linux")'.build-dependencies]
bindgen = "0.69"
EOF

run_expect 1 "deny-deps.sh disallowed fixture" "$root/scripts/deny-deps.sh" "$deps_root"
for name in regex once_cell cc; do
  case "$last_out" in
    *"disallowed dependency: $name ("*) ;;
    *) fail "deny-deps.sh did not name $name: $last_out" ;;
  esac
done
case "$last_out" in
  *"disallowed dependency: serde"*) fail "deny-deps.sh flagged allowed dep serde" ;;
esac

expect_target_deps() {
  local label="$1"
  shift
  run_expect 1 "deny-deps.sh $label" "$@"
  for name in libc winapi bindgen; do
    case "$last_out" in
      *"disallowed dependency: $name ("*) ;;
      *) fail "deny-deps.sh $label did not name $name: $last_out" ;;
    esac
  done
  case "$last_out" in
    *"disallowed dependency: serde"*)
      fail "deny-deps.sh $label flagged allowed dep serde"
      ;;
  esac
}

if command -v jq >/dev/null 2>&1; then
  expect_target_deps "target-specific fixture with jq" \
    "$root/scripts/deny-deps.sh" "$target_deps_root"
else
  echo "skip: jq not installed, target-specific jq path not exercised" >&2
fi

no_jq_bin="$tmp/no-jq-bin"
mkdir -p "$no_jq_bin"
for tool in bash env python3 grep dirname cargo; do
  path="$(command -v "$tool")" || fail "test-gates.sh needs $tool"
  ln -s "$path" "$no_jq_bin/$tool"
done
if env PATH="$no_jq_bin" bash -c 'command -v jq >/dev/null 2>&1'; then
  fail "test-gates.sh no-jq PATH still resolves jq"
fi
expect_target_deps "target-specific fixture without jq" \
  env PATH="$no_jq_bin" "$root/scripts/deny-deps.sh" "$target_deps_root"

run_expect 0 "loc.sh real repo" "$root/scripts/loc.sh"
[[ "$last_out" =~ ^rust_loc=[0-9]+\ budget=25000$ ]] ||
  fail "loc.sh real repo printed: $last_out"

run_expect 0 "deny-deps.sh real repo" "$root/scripts/deny-deps.sh"
[ -z "$last_out" ] || fail "deny-deps.sh real repo printed: $last_out"

echo "gates ok"
