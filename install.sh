#!/bin/sh
# Install a signed Sekisho release. POSIX sh. Verify this script before you
# run it; each step runs only if the one before it succeeded:
#   curl -fsSLO https://get.sekisho.sh/install.sh &&
#     curl -fsSLO https://get.sekisho.sh/install.sh.minisig &&
#     minisign -Vm install.sh -P RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh &&
#     sh ./install.sh
set -eu
umask 077

# The Sekisho release key, also published at https://get.sekisho.sh/release-key.txt
MINISIGN_PUBLIC_KEY="RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh"
MINISIGN_KEY_ID="4BCB4340933E1FC4"

DEFAULT_REPO="deep-thinking-lab/sekisho"

# Download limits: connect and total time in seconds, and size caps in bytes.
CONNECT_TIMEOUT=20
MAX_TIME=600
MAX_ARCHIVE_BYTES=268435456
MAX_SMALL_BYTES=1048576
MAX_METADATA_BYTES=8388608

say() {
    printf '%s\n' "$*"
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# download <url> <out> <max-bytes>. HTTPS only (curl also requires TLS 1.2 or
# newer and HTTPS redirects), with timeouts and a size cap. A file:// URL is
# accepted only when the caller set it explicitly, for a local mirror.
download() {
    url=$1
    out=$2
    max=$3
    case "$url" in
        https://*) proto='=https' ;;
        file://*) proto='=file' ;;
        *) die "refusing to download over anything but HTTPS: $url" ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto "$proto" --proto-redir '=https' --tlsv1.2 \
            --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
            --max-filesize "$max" -o "$out" "$url" || die "could not download $url"
    elif command -v wget >/dev/null 2>&1; then
        [ "$proto" = '=https' ] || die "a file:// URL needs curl"
        wget -q --https-only --timeout="$CONNECT_TIMEOUT" --tries=1 \
            -O "$out" "$url" || die "could not download $url"
    else
        die "curl or wget is required to download release artifacts"
    fi
    size=$(wc -c <"$out" | tr -d ' ')
    [ "$size" -le "$max" ] || die "download is larger than $max bytes: $url"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        die "sha256sum, shasum or openssl is required to verify the download"
    fi
}

detect_platform() {
    case "$(uname -s)" in
        Linux) OS=linux ;;
        Darwin) OS=darwin ;;
        *) die "unsupported operating system: $(uname -s)" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) ARCH=x86_64 ;;
        arm64|aarch64) ARCH=arm64 ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
    if [ "$OS" = darwin ] && [ "$ARCH" != arm64 ]; then
        die "macOS releases are published for arm64 only"
    fi
}

# The newest stable version (X.Y.Z, no suffix) among the tag_name fields of a
# GitHub releases list, by semver. The list is not signed, so it only proposes a
# version: the signed SHA256SUMS must then name that same version.
latest_version() {
    # shellcheck disable=SC2020 # each of , { and } becomes a newline
    tr ',{}' '\n\n\n' <"$1" |
        sed -n 's/^[[:space:]]*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"[[:space:]]*$/\1/p' |
        sort -t . -k 1,1n -k 2,2n -k 3,3n |
        tail -n 1
}

resolve_version() {
    if [ -n "${SEKISHO_VERSION:-}" ]; then
        VERSION=${SEKISHO_VERSION#v}
        return 0
    fi
    repo=${SEKISHO_REPO:-$DEFAULT_REPO}
    releases_url=${SEKISHO_RELEASES_API_URL:-https://api.github.com/repos/$repo/releases?per_page=100}
    say "Finding the latest release (set SEKISHO_VERSION to pin one)..."
    download "$releases_url" "$WORK/releases.json" "$MAX_METADATA_BYTES"
    VERSION=$(latest_version "$WORK/releases.json")
    [ -n "$VERSION" ] || die "could not find a release version in the GitHub release list"
}

# The trusted comment is signed with SHA256SUMS and names the release, so an
# old signed SHA256SUMS cannot pass for another version.
verify_signature() {
    command -v minisign >/dev/null 2>&1 ||
        die "minisign is required to verify the release signature"
    comment=$(minisign -V -Q -P "$MINISIGN_PUBLIC_KEY" -m "$WORK/SHA256SUMS" \
        -x "$WORK/SHA256SUMS.minisig") ||
        die "release signature verification failed; nothing was installed"
    [ "$comment" = "sekisho v$VERSION" ] ||
        die "SHA256SUMS is signed for '$comment', not 'sekisho v$VERSION'; nothing was installed"
}

verify_checksum() {
    expected=$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*" f { print $1 }' "$WORK/SHA256SUMS")
    [ -n "$expected" ] || die "SHA256SUMS has no entry for $ARCHIVE; nothing was installed"
    actual=$(sha256_file "$WORK/$ARCHIVE")
    [ "$actual" = "$expected" ] ||
        die "checksum mismatch for $ARCHIVE; nothing was installed"
}

install_binary() {
    bin_dir=${SEKISHO_INSTALL_BIN_DIR:-/usr/local/bin}
    if [ ! -d "$bin_dir" ]; then
        if [ -w "$(dirname "$bin_dir")" ]; then
            install -d -m 0755 "$bin_dir"
        else
            as_root install -d -m 0755 "$bin_dir"
        fi
    fi
    [ -f "$WORK/extract/sekisho" ] || die "release archive does not contain sekisho"
    if [ -w "$bin_dir" ]; then
        install -m 0755 "$WORK/extract/sekisho" "$bin_dir/sekisho"
    else
        as_root install -m 0755 "$WORK/extract/sekisho" "$bin_dir/sekisho"
    fi
}

main() {
    if [ "$MINISIGN_PUBLIC_KEY" = "RWQ_PLACEHOLDER" ]; then
        die "this installer has no release public key yet, so the release cannot be authenticated"
    fi
    say "Release signing key: $MINISIGN_PUBLIC_KEY (minisign key ID $MINISIGN_KEY_ID)"

    detect_platform

    WORK=$(mktemp -d "${TMPDIR:-/tmp}/sekisho-install.XXXXXX") ||
        die "could not create a temporary directory"
    trap 'rm -rf "$WORK"' EXIT
    trap 'exit 130' HUP INT TERM

    resolve_version
    case "$VERSION" in
        ''|*[!0-9A-Za-z.-]*) die "invalid release version: $VERSION" ;;
    esac

    ARCHIVE="sekisho-$VERSION-$OS-$ARCH.tar.gz"
    release_base=${SEKISHO_RELEASE_BASE_URL:-https://github.com/${SEKISHO_REPO:-$DEFAULT_REPO}/releases/download/v$VERSION}

    say "Downloading Sekisho $VERSION for $OS/$ARCH..."
    download "$release_base/SHA256SUMS" "$WORK/SHA256SUMS" "$MAX_SMALL_BYTES"
    download "$release_base/SHA256SUMS.minisig" "$WORK/SHA256SUMS.minisig" "$MAX_SMALL_BYTES"
    verify_signature

    download "$release_base/$ARCHIVE" "$WORK/$ARCHIVE" "$MAX_ARCHIVE_BYTES"
    verify_checksum

    mkdir "$WORK/extract"
    tar -xzf "$WORK/$ARCHIVE" -C "$WORK/extract" ||
        die "could not extract $ARCHIVE"
    install_binary

    say "Installed sekisho to ${SEKISHO_INSTALL_BIN_DIR:-/usr/local/bin}."
    say "Run: sekisho up"
}

main "$@"
