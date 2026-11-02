# Sekisho

Let agents act. Keep the keys.

**Status:** Developer preview (v0.1). Expect rough edges; the audit format and policy schema may change before v1.

Sekisho is a self-hosted permission layer for AI agents. Agents use a Sekisho token while Sekisho keeps the upstream credentials. Every consequential action is allowed, denied or held for a human to approve. Every state change lands in a signed audit trail that you own and can verify offline.

One binary. One SQLite file. No Kubernetes, no cloud account, no KVM.

## What Sekisho enforces today

- The Claude Code `PreToolUse` hook sends each tool request to `sekisho hook claude-code`.
- The git proxy checks every ref update before it forwards a push to the upstream remote.
- The MCP gateway (experimental) checks every tool call to the MCP servers you declare in config. See [MCP gateway](docs/mcp.md).

## Notifications and Slack approvals

- Webhook and Slack notifications tell approvers when an action is waiting. See [Approval notifications](docs/notifications.md).
- Approve or deny from Slack with signed interactive buttons. By default a button links to the web page for TOTP sign-in. Both features are in the free Community edition.

## Quickstart

These steps take you from an installed binary to a git push held for approval:

1. Install a signed release. You need `curl`, `minisign`, `tar`, and one of `sha256sum`, `shasum` or `openssl`.

   The Linux binaries need glibc 2.39 or newer, so they run on Ubuntu 24.04 or newer. They do not run on Ubuntu 22.04 or Debian 12; on those, build from source instead.

   Download the installer and its signature, verify the installer with the release key, read it, then run it:

   ```sh
   curl -fsSLO https://get.sekisho.sh/install.sh &&
     curl -fsSLO https://get.sekisho.sh/install.sh.minisig &&
     minisign -Vm install.sh -P RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh &&
     cat install.sh &&
     sh ./install.sh
   ```

   Each command runs only if the one before it succeeded, so the installer runs only after `minisign` prints `Signature and comment signature verified`. From release 0.1.1, the same two files are also attached to each GitHub release.

   The installer verifies the release signature and checksum, then installs to `/usr/local/bin`. Run it as your normal user. It invokes `sudo` if the destination needs elevated permissions.

   [Release 0.1.1](https://github.com/deep-thinking-lab/sekisho/releases/tag/v0.1.1) is signed with minisign key ID `4BCB4340933E1FC4`. The public key is:

   ```text
   RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh
   ```

   Alternatively, build from source with `git` and a Rust toolchain:

   ```sh
   git clone https://github.com/deep-thinking-lab/sekisho
   cd sekisho
   cargo build --release
   export PATH="$PWD/target/release:$PATH"
   ```

2. Start Sekisho.

   ```sh
   sekisho up
   ```

   Sekisho keeps its state in `~/.sekisho`. To use another directory, run `sekisho up --home /path/to/home` or set `SEKISHO_HOME`. On first run it asks for an admin id, a password and a password confirmation, then prints a TOTP enrollment URI and secret. The secret is shown once. Save it now and add it to an authenticator app. For scripted setup, run `sekisho up --admin-password-stdin` and send the id, password and confirmation as three lines on stdin.

3. Add an agent and print the Claude Code hook configuration.

   ```sh
   sekisho agent add claude --print-config claude-code
   ```

4. Configure a git remote through the proxy and push a branch that policy holds for approval. The policy target is `<host>/<owner>/<repo>:<ref>`, where the host comes from the remote's `base_url`.

   ```sh
   git remote add sekisho http://127.0.0.1:7470/git/github/owner/repo.git
   git push sekisho HEAD:main
   ```

5. Open `http://127.0.0.1:7470/login`, sign in with the admin id, the password and a TOTP code from the authenticator app you enrolled at first run, and approve the request. You can approve from the command line with `sekisho approvals approve <id>`, which asks for a TOTP code.

   After the approval line, the held push ends with `fatal: the remote end hung up unexpectedly`. That is expected because Sekisho refused the unapproved request. Repeat the push to use the approval.

6. Stop the server with Ctrl-C in its terminal. `sekisho policy reload` requires the server to be running, reads `SEKISHO_HOME` or the default home, and asks for a TOTP code.

The [quickstart](docs/quickstart.md) covers the remote, policy, hook, approval and audit setup in full.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Policy reference](docs/policy.md)
- [Git proxy reference](docs/git-proxy.md)
- [MCP gateway](docs/mcp.md)
- [Audit trail](docs/audit.md)
- [Approval notifications](docs/notifications.md)
- [Security](docs/security.md)

## More

- `sekisho grant add` issues a signed, time-boxed grant for an agent, tool and target.
- `sekisho audit rotate-key` rotates the audit signing key and records the rotation in the audit trail.

## License

Sekisho is licensed under the [Apache License 2.0](LICENSE).
