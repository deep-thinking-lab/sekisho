#!/usr/bin/env bash
# Fails if a retired GitHub owner name or domain appears outside docs/tasks/ (task history).
# The organisation is deep-thinking-lab (deep-thinking-llc and dthink are not ours to rely on),
# and the domain is sekisho.sh (sekisho.dev belongs to someone else).
set -euo pipefail
cd "$(dirname "$0")/.."
if hits=$(git grep -n -E 'deep-thinking-llc|(github\.com|ghcr\.io)/dthink/|"dthink/|sekisho\.dev' -- . ':!docs/tasks' ':!scripts/check-org-names.sh'); then
    printf 'check-org-names: retired owner names or domains found (use deep-thinking-lab and sekisho.sh):\n%s\n' "$hits" >&2
    exit 1
fi
echo "check-org-names: ok"
