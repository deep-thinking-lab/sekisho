# 0001: Release signing happens offline, never in CI

Status: accepted, 1 November 2026.

## Decision

The minisign release key (key ID `4BCB4340933E1FC4`) lives only offline with the maintainer. GitHub Actions never holds it, never signs, never publishes a release and never replaces a release asset.

`.github/workflows/release.yml` runs on a `v*` tag. It builds the three archives, writes an unsigned `SHA256SUMS`, and attaches the archives, `SHA256SUMS` and `install.sh` to a draft release. If the release is already published, or the draft already has assets, the job fails instead of changing it. `scripts/check-release-signing.sh` fails if any workflow references a `MINISIGN_*` secret, `MINISIGN_SECRET_KEY`, `MINISIGN_PASSWORD` or `minisign -S`. The release workflow runs it before it builds, and `just ci` runs it on every change.

## Why

A signing key in a repository secret signs whatever any workflow on any branch or tag asks it to sign. Anyone who can push a tag or change a workflow could ship a release that every installer would trust. Signing by hand puts a human check between a CI build and a trusted release.

## Runbook

1. Push the tag `vX.Y.Z`. The Release workflow creates the draft `vX.Y.Z` with unsigned assets.
2. Download the draft's assets into an empty directory and check them:

   ```sh
   mkdir ci && cd ci
   gh release download vX.Y.Z --repo deep-thinking-lab/sekisho
   sha256sum -c SHA256SUMS
   git -C .. show vX.Y.Z:install.sh | cmp - install.sh
   ```

3. Build locally from the same tag on a trusted machine with `scripts/release/local-build.sh vX.Y.Z`, and compare the `sekisho` binary inside your archive with the one inside the CI archive for the same platform. If they differ and you cannot explain why, do not sign the CI archives: build every platform on trusted machines, delete the CI assets from the draft by hand, and use your local archives and a `SHA256SUMS` you wrote yourself.
4. Sign offline, on the machine that holds the key. The trusted comment names the release: `install.sh` refuses a `SHA256SUMS` whose comment is not exactly `sekisho vX.Y.Z`, and `just get-site` refuses an `install.sh.minisig` whose comment is not exactly `sekisho-install vX.Y.Z`.

   ```sh
   minisign -S -s /path/to/offline/minisign.key -m SHA256SUMS -t "sekisho vX.Y.Z"
   minisign -S -s /path/to/offline/minisign.key -m install.sh -t "sekisho-install vX.Y.Z"
   minisign -V -Q -m SHA256SUMS -p site/public/release-key.txt
   minisign -V -Q -m install.sh -p site/public/release-key.txt
   ```

   The two verify commands print the trusted comments; check they read `sekisho vX.Y.Z` and `sekisho-install vX.Y.Z`.

5. Test the installer against the signed files before anyone else can: put the archives, `SHA256SUMS` and `SHA256SUMS.minisig` in one directory and run `SEKISHO_RELEASE_BASE_URL=file:///that/dir SEKISHO_VERSION=X.Y.Z sh install.sh`.
6. Upload the signatures by hand with `gh release upload vX.Y.Z SHA256SUMS.minisig install.sh.minisig`. Never pass `--clobber`.
7. Publish the draft by hand, then build the `get.sekisho.sh` directory with `just get-site <out-dir> install.sh.minisig`.

The repository must not hold `MINISIGN_SECRET_KEY` or `MINISIGN_PASSWORD` secrets. Delete them in the GitHub repository settings if they exist.

## Key rotation

The release key was rotated on 1 Nov 2026 to `4BCB4340933E1FC4`, because the previous secret had been stored in CI. Anything signed by the previous key, ID `7360B7CB6ECFDAB5`, must not be trusted.
