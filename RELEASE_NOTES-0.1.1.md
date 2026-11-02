# Sekisho 0.1.1

Sekisho 0.1.1 is a security release of the developer preview. It tightens how hook actions are matched, requires a TOTP code for every state change made through the local admin token, and hardens the git proxy, login and notifications. Some of these changes can make an existing setup refuse to start or change how a policy matches, so read the upgrade notes before you upgrade.

## Install

```sh
curl -fsSLO https://get.sekisho.sh/install.sh &&
  curl -fsSLO https://get.sekisho.sh/install.sh.minisig &&
  minisign -Vm install.sh -P RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh &&
  cat install.sh &&
  sh ./install.sh
```

Each command runs only if the one before it succeeded, so the installer runs only after `minisign` prints `Signature and comment signature verified`. The installer verifies the minisign signature on `SHA256SUMS` and the archive checksum before it installs. The release is signed with minisign key ID `4BCB4340933E1FC4`.

The Linux binaries need glibc 2.39 or newer, so they run on Ubuntu 24.04 or newer. They do not run on Ubuntu 22.04 or Debian 12; on those, build from source instead.

Assets:

- `sekisho-0.1.1-linux-x86_64.tar.gz`
- `sekisho-0.1.1-linux-arm64.tar.gz`
- `sekisho-0.1.1-darwin-arm64.tar.gz`
- `SHA256SUMS` and `SHA256SUMS.minisig`
- `install.sh` and `install.sh.minisig`, new in this release, so you can verify the installer before you run it

## Upgrade notes

### TOTP is required for CLI approvals and policy reload

`sekisho approvals approve <id>`, `sekisho approvals deny <id>` and `sekisho policy reload` now need a TOTP code from the admin's authenticator app. The local admin token alone can no longer approve, deny or reload the policy.

There is no `--totp` flag. On a terminal the command prompts `TOTP code:`. Otherwise it reads the code as one line on stdin. Each code can be used once. Scripts that called these commands without a code must now supply one on stdin.

### Slack one-click approval needs `include_params = true`

An Approve button decides immediately only when the Slack entry sets both `slack_requires_totp = false` and `include_params = true`, so the approver sees the parameters they approve. With `slack_requires_totp = false` alone, Deny still decides from Slack, but Approve replies with a link to the web approval page. If any parameter was redacted, the button cannot approve and points to the web inbox. See [Approval notifications](docs/notifications.md).

### Hook targets changed: re-check your policies

Hook targets now name the real path each Claude Code tool touches. Bash targets `cwd:<real working directory>/`, and directory targets end in `/`.

- Deny rules keep their meaning. They also match the bare path behind `cwd:` and the directory without its trailing `/`.
- Allow and ask rules match only the new targets, so a file path allow rule no longer allows Bash. To allow Bash in a project, add a rule with `tool = "hook:claude-code/bash"` and `target = "cwd:/path/to/project/**"`.
- The hook denies, rather than guesses, when a tool input is ambiguous, such as a path starting with `~` or an unknown tool with more than one path argument.

Check each policy file after upgrading:

```sh
sekisho policy check "$HOME/.sekisho/policy.toml"
```

See [Migrating policies to the new hook targets](docs/policy.md#migrating-policies-to-the-new-hook-targets).

### `tool_prefix` must end at a segment boundary

A `tool_prefix` must end in `/`, `_`, `.` or `:`. A prefix such as `mcp:github` is rejected, because it would also match a server named `github-admin`. Use `mcp:github/`.

### Integral floats are rejected in params

Action parameters containing a float with no fractional part, such as `1.0`, or `-0.0`, are rejected. The canonical form would give them the same digest as the integer, so an approval for one could authorize the other. Send integers as integers.

### Plain HTTP upstreams are allowed for loopback only

A git remote's `base_url` and `api_url` must use HTTPS unless the host is loopback (`localhost`, `127.0.0.1` or `::1`), because Sekisho sends the upstream token to them. Sekisho refuses to start otherwise.

### New `trusted_proxies` setting

If Sekisho runs behind a reverse proxy, list the proxy addresses in `trusted_proxies` in `config.toml`. Sekisho uses the rightmost `X-Forwarded-For` address that is not a trusted proxy for per-address login limits. If requests carry `X-Forwarded-For` while `trusted_proxies` is empty, Sekisho logs a warning and skips per-address limits. See [Security](docs/security.md).

### Pending approvals are capped

An agent can hold at most 20 pending approvals. Past that, a request an `ask` rule would hold is denied with the reason `too many pending approvals`. At most 16 requests per agent wait for a decision at once. Further requests get the `ask` answer and the approval id straight away instead of waiting.

### Run Sekisho as a separate OS user

We recommend running `sekisho up` as a dedicated OS user and the agent as your own user. Sekisho denies hook actions whose target is inside the Sekisho home, but an agent running as the same OS user can still reach the home through any tool you allow without approval, such as Bash. See [Run Sekisho as a separate OS user](docs/security.md#run-sekisho-as-a-separate-os-user).

## Other changes

- The Sekisho home is denied to hook actions by its configured path, its real path and its device and inode, including searches rooted at a directory that contains it. On macOS this covers the `/System/Volumes/Data` firmlink and the `/.nofollow`, `/.resolve` and `/.vol` prefixes. A hard link into the home made by the same OS user is not caught, which is one more reason to run Sekisho as a separate OS user.
- The git proxy proves fast-forwards from the pushed pack, treats any update it cannot prove as forced, and bounds the work a single push can cause.
- Logins: wrong passwords are throttled per client address, every failed login gets the same response, and failed attempts by others no longer lock an approver out.
- An approved action is decided again before its approval is consumed, so a deny rule loaded while the request waited wins.
- Slack messages carry action parameters only with `include_params = true`, with obvious secrets redacted.
- The policy file is checked for owner and permissions on the open file descriptor, and a replayed TOTP code counts as a failed attempt.

## Release key rotation

The release signing key was rotated on 1 Nov 2026. The current key ID is `4BCB4340933E1FC4`. Anything signed by the previous key, ID `7360B7CB6ECFDAB5`, must not be trusted.
