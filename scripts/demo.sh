#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/sekisho-demo.XXXXXX")"
umask 077

sekisho_pid=""
http_pid=""

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$sekisho_pid" ]; then
    kill "$sekisho_pid" 2>/dev/null || true
    wait "$sekisho_pid" 2>/dev/null || true
  fi
  if [ -n "$http_pid" ]; then
    kill "$http_pid" 2>/dev/null || true
    wait "$http_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

say() {
  printf '%s\n' "$*"
}

now_ms() {
  python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
}

for tool in base64 cargo curl git grep python3 sed; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

if [ -n "${SEKISHO_BIN:-}" ]; then
  bin="$SEKISHO_BIN"
else
  cargo build --quiet --manifest-path "$root/Cargo.toml" --bin sekisho
  bin="$root/target/debug/sekisho"
fi
[ -x "$bin" ] || fail "Sekisho binary is not executable: $bin"

total_start="$(now_ms)"
step_start=$total_start
step_label=""
step_labels=()
step_millis=()

begin_step() {
  step_label="$1"
  step_start="$(now_ms)"
}

finish_step() {
  step_labels+=("$step_label")
  step_millis+=("$(( $(now_ms) - step_start ))")
}

begin_step "prepare local repository"
remotes="$tmp/remotes"
http_root="$tmp/http"
work="$tmp/work"
bare="$remotes/owner/repo.git"
mkdir -p "$remotes/owner" "$http_root"
git init --quiet --bare "$bare"
git --git-dir="$bare" config http.receivepack true
git init --quiet "$work"
git -C "$work" config user.name "Sekisho Demo"
git -C "$work" config user.email "demo@sekisho.invalid"
printf 'Sekisho quickstart demo\n' >"$work/README"
git -C "$work" add README
git -C "$work" commit --quiet --message "initial demo commit"
finish_step

begin_step "start git http backend"
cat >"$http_root/server.py" <<'EOF'
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def read_body(request):
    if request.headers.get("Transfer-Encoding", "").lower() != "chunked":
        return request.rfile.read(int(request.headers.get("Content-Length", "0")))
    chunks = []
    while True:
        size = int(request.rfile.readline().split(b";", 1)[0].strip(), 16)
        if size == 0:
            while request.rfile.readline() not in (b"\r\n", b"\n", b""):
                pass
            return b"".join(chunks)
        chunks.append(request.rfile.read(size))
        request.rfile.read(2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def run_backend(self):
        body = read_body(self) if self.command == "POST" else b""
        parsed = urlsplit(self.path)
        env = os.environ.copy()
        env.update({
            "REQUEST_METHOD": self.command,
            "PATH_INFO": parsed.path,
            "QUERY_STRING": parsed.query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "GIT_HTTP_EXPORT_ALL": "1",
            "REMOTE_USER": "sekisho",
        })
        result = subprocess.run(
            ["git", "http-backend"],
            input=body,
            env=env,
            capture_output=True,
        )
        response = result.stdout.replace(b"\r\n", b"\n")
        if b"\n\n" not in response:
            self.send_error(502)
            return
        headers, payload = response.split(b"\n\n", 1)
        status = 200
        fields = []
        for line in headers.splitlines():
            name, separator, value = line.decode("latin-1").partition(":")
            if not separator:
                continue
            if name.lower() == "status":
                status = int(value.strip().split(" ", 1)[0])
            else:
                fields.append((name, value.strip()))
        self.send_response(status)
        for name, value in fields:
            self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = run_backend
    do_POST = run_backend


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
EOF
http_log="$tmp/http.log"
env GIT_PROJECT_ROOT="$remotes" \
  python3 "$http_root/server.py" \
  >"$http_log" 2>&1 &
http_pid=$!
http_port=""
for ((attempt = 0; attempt < 200; attempt++)); do
  http_port="$(sed -nE 's/^([0-9]+)$/\1/p' "$http_log" | head -n 1)"
  if [ -n "$http_port" ]; then
    break
  fi
  kill -0 "$http_pid" 2>/dev/null || break
  sleep 0.05
done
[ -n "$http_port" ] || fail "local git http backend did not become ready"
finish_step

begin_step "sekisho up"
home="$tmp/home"
mkdir -p "$home"
chmod 700 "$home"
printf 'demo-upstream-token\n' >"$home/upstream.secret"
cat >"$home/config.toml" <<EOF
[[remote]]
name = "local"
base_url = "http://127.0.0.1:$http_port"
token_file = "upstream.secret"
case_insensitive = true
EOF
cat >"$home/policy.toml" <<'EOF'
version = 1

[[rule]]
name = "fetch the demo repository"
tool = "git.fetch"
target = "127.0.0.1/owner/repo"
decision = "allow"

[[rule]]
name = "allow agent branches"
tool = "git.push"
target = "127.0.0.1/owner/repo:refs/heads/agent/**"
params = { force = false }
decision = "allow"
budget = { max = 50, per = "1h" }

[[rule]]
name = "hold main for approval"
tool = "git.push"
target = "127.0.0.1/owner/repo:refs/heads/main"
decision = "ask"
approvers = 1
EOF
chmod 600 "$home/config.toml" "$home/policy.toml"
admin_id="demo-admin"
admin_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
sekisho_output="$tmp/sekisho.out"
mkfifo "$sekisho_output"
"$bin" up --home "$home" --bind 127.0.0.1:0 --admin-password-stdin \
  >"$sekisho_output" <<EOF &
$admin_id
$admin_password
$admin_password
EOF
sekisho_pid=$!
exec 3<"$sekisho_output"
base_url=""
totp_secret=""
while IFS= read -r line <&3; do
  case "$line" in
    "TOTP secret: "*)
      totp_secret="${line#TOTP secret: }"
      ;;
    "Listening on "*)
      base_url="${line#Listening on }"
      break
      ;;
  esac
done
[ -n "$base_url" ] || fail "Sekisho did not become ready"
[ -n "$totp_secret" ] || fail "Sekisho did not return the enrolled TOTP secret"
finish_step

begin_step "agent add"
agent_token="$(SEKISHO_HOME="$home" "$bin" agent add demo-agent)"
[ -n "$agent_token" ] || fail "agent add did not return a token"
basic_token="$(printf 'any:%s' "$agent_token" | base64 | tr -d '\r\n')"
finish_step

proxy_url="$base_url/git/local/owner/repo.git"
push_ref() {
  local ref="$1"
  env GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=http.extraHeader \
    GIT_CONFIG_VALUE_0="Authorization: Basic $basic_token" \
    GIT_TERMINAL_PROMPT=0 \
    git -C "$work" push --porcelain "$proxy_url" "HEAD:$ref"
}

expected_commit="$(git -C "$work" rev-parse HEAD)"

begin_step "allowed branch push"
if ! allowed_output="$(push_ref refs/heads/agent/demo 2>&1)"; then
  fail "allowed branch push failed: $allowed_output"
fi
allowed_commit="$(git --git-dir="$bare" rev-parse refs/heads/agent/demo)"
[ "$allowed_commit" = "$expected_commit" ] ||
  fail "allowed branch push did not update the upstream branch"
finish_step

begin_step "main push held"
held_status=0
held_output="$(push_ref refs/heads/main 2>&1)" || held_status=$?
[ "$held_status" -ne 0 ] || fail "main push unexpectedly succeeded"
case "$held_output" in
  *"approval required"*) ;;
  *) fail "main push did not report an approval requirement: $held_output" ;;
esac
approval_id="$(
  printf '%s\n' "$held_output" |
    sed -nE 's/.*(apr_[0-9a-z]+).*/\1/p' |
    head -n 1
)"
[ -n "$approval_id" ] || fail "main push did not name the approval"
if git --git-dir="$bare" show-ref --verify --quiet refs/heads/main; then
  fail "main branch reached the upstream before approval"
fi
finish_step

begin_step "admin approval"
totp_code="$(
  printf '%s' "$totp_secret" |
    python3 -c '
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = base64.b32decode(sys.stdin.read().strip().upper(), casefold=True)
counter = int(time.time()) // 30
digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
print(f"{value % 1_000_000:06d}")
'
)"
cookie_jar="$tmp/cookies.txt"
curl -fsS --cookie-jar "$cookie_jar" "$base_url/login" >/dev/null
prelogin="$(
  awk '$6 == "sekisho_prelogin" { print $7 }' "$cookie_jar" | tail -n 1
)"
[ -n "$prelogin" ] || fail "login did not issue a CSRF cookie"
login_json="$(
  printf '%s' "$admin_password" |
    curl -fsS \
      --cookie "$cookie_jar" \
      --cookie-jar "$cookie_jar" \
      --data-urlencode "user_id=$admin_id" \
      --data-urlencode "password@-" \
      --data-urlencode "totp=$totp_code" \
      --data-urlencode "csrf_token=$prelogin" \
      "$base_url/login"
)"
csrf_token="$(
  printf '%s' "$login_json" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["csrf_token"])'
)"
approval_status="$(
  curl -fsS --output /dev/null --write-out '%{http_code}' \
    --cookie "$cookie_jar" \
    --header "X-CSRF-Token: $csrf_token" \
    --request POST \
    "$base_url/approvals/$approval_id/approve"
)"
[ "$approval_status" = "200" ] ||
  fail "admin approval returned HTTP $approval_status"
finish_step

begin_step "approved main push"
if ! approved_output="$(push_ref refs/heads/main 2>&1)"; then
  fail "approved main push failed: $approved_output"
fi
main_commit="$(git --git-dir="$bare" rev-parse refs/heads/main)"
[ "$main_commit" = "$expected_commit" ] ||
  fail "approved main push did not update the upstream branch"
finish_step

begin_step "audit export"
audit_file="$tmp/audit.jsonl"
export_key_log="$tmp/audit-export.log"
SEKISHO_HOME="$home" "$bin" audit export --out "$audit_file" 2>"$export_key_log"
public_key="$(
  sed -n 's/^--pubkey //p' "$export_key_log" | tail -n 1
)"
[ -n "$public_key" ] || fail "audit export did not print the external public key"
for event in ActionRequested ApprovalRequested Approved Consumed; do
  grep -q "\"kind\":\"$event\"" "$audit_file" ||
    fail "audit export is missing $event"
done
finish_step

begin_step "audit verify"
verify_output="$(
  SEKISHO_HOME="$home" "$bin" audit verify "$audit_file" --pubkey "$public_key"
)"
case "$verify_output" in
  valid:*) ;;
  *) fail "audit verify returned: $verify_output" ;;
esac
unauthenticated_status=0
SEKISHO_HOME="$home" "$bin" audit verify "$audit_file" >/dev/null 2>&1 ||
  unauthenticated_status=$?
[ "$unauthenticated_status" -eq 3 ] ||
  fail "audit verify without an external key exited $unauthenticated_status, want 3"
finish_step

say "Demo passed."
say "Allowed branch push, main approval, forwarding, and signed audit verification all worked."
printf '\nTimed summary\n'
for index in "${!step_labels[@]}"; do
  printf '  %s: %sms\n' "${step_labels[$index]}" "${step_millis[$index]}"
done
printf '  total: %sms\n' "$(( $(now_ms) - total_start ))"
