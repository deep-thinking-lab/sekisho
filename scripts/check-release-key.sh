#!/usr/bin/env bash
# Tripwire for the rotated release key: the old key ID and public key must not appear in any
# tracked file (the two rotation notes may name the old ID only), and install.sh and
# site/public/release-key.txt must both carry the current key.
set -euo pipefail
cd "$(dirname "$0")/.."
old_id='7360B7CB''6ECFDAB5'
old_key='RWS12s9uy7dg'
new_key='RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh'
new_id='4BCB4340933E1FC4'
fail=0
if hits=$(git grep -n -i -e "$old_key" -- . ':!scripts/check-release-key.sh'); then
    printf 'check-release-key: old release public key found:\n%s\n' "$hits" >&2
    fail=1
fi
if hits=$(git grep -n -i -e "$old_id" -- . ':!scripts/check-release-key.sh' ':!RELEASE_NOTES-0.1.1.md' ':!docs/decisions/0001-offline-release-signing.md'); then
    printf 'check-release-key: old release key ID found:\n%s\n' "$hits" >&2
    fail=1
fi
for f in install.sh site/public/release-key.txt; do
    for want in "$new_key" "$new_id"; do
        if ! grep -qF "$want" "$f"; then
            printf 'check-release-key: %s does not contain %s\n' "$f" "$want" >&2
            fail=1
        fi
    done
done
[ "$fail" -eq 0 ] || exit 1
echo "check-release-key: ok"
