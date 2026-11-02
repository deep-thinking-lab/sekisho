ci: fmt clippy test loc deps gates-test release-signing release-test org-names public-tree release-key

fmt:
    cargo fmt --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

loc:
    ./scripts/loc.sh

deps:
    ./scripts/deny-deps.sh

gates-test:
    ./scripts/test-gates.sh

# CI never signs releases: no MINISIGN_* secret or minisign -S in any workflow.
release-signing:
    ./scripts/check-release-signing.sh

release-test:
    ./scripts/release/test-release.sh

org-names:
    ./scripts/check-org-names.sh

public-tree:
    ./scripts/check-public-tree.sh

# Build (never deploy) the get.sekisho.sh directory for Cloudflare Pages project sekisho-get.
get-site out signature:
    ./scripts/release/build-get-site.sh {{out}} {{signature}}

# The rotated-out release key must not return; install.sh and release-key.txt carry the current key.
release-key:
    ./scripts/check-release-key.sh
