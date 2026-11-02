# Quickstart

This tutorial takes you through the first Sekisho journey. You start by installing a signed release, add a Claude Code agent, route a git remote through Sekisho, hold a push for approval, and verify the audit trail offline.

**Status:** Developer preview (v0.1). Expect rough edges; the audit format and policy schema may change before v1.

## Before you start

You need:

- A supported machine, Linux x86_64, Linux arm64 or macOS arm64.
- `git`, `curl`, `minisign`, and `tar`.
- One SHA-256 tool: `sha256sum`, `shasum` or `openssl`.
- `sudo` access if installing to a directory you cannot write to.
- A TOTP app for the admin account.
- A GitHub account and a repository you can push to.
- A GitHub token that can push to that repository.

## Install Sekisho

Download the installer and its signature, verify the installer with the release key, read it, then run it:

```sh
curl -fsSLO https://get.sekisho.sh/install.sh &&
  curl -fsSLO https://get.sekisho.sh/install.sh.minisig &&
  minisign -Vm install.sh -P RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh &&
  cat install.sh &&
  sh ./install.sh
```

Each command runs only if the one before it succeeded, so the installer runs only after `minisign` prints `Signature and comment signature verified`. From release 0.1.1, the same `install.sh` and `install.sh.minisig` are also attached to each GitHub release.

The installer downloads the latest release, verifies the minisign signature on `SHA256SUMS`, and checks the archive's SHA-256 before installing. It installs to `/usr/local/bin`. Run it as your normal user. It invokes `sudo` itself when the destination needs elevated permissions.

[Release 0.1.1](https://github.com/deep-thinking-lab/sekisho/releases/tag/v0.1.1) provides these assets:

- `sekisho-0.1.1-linux-x86_64.tar.gz`
- `sekisho-0.1.1-linux-arm64.tar.gz`
- `sekisho-0.1.1-darwin-arm64.tar.gz`
- `SHA256SUMS`
- `SHA256SUMS.minisig`
- `install.sh`
- `install.sh.minisig`

The installer pins minisign key ID `4BCB4340933E1FC4`. The [release public key](https://get.sekisho.sh/release-key.txt) is:

```text
RWTEHz6TQEPLS839E2TAO3h02KOMdbvpWJVSGYD/gunfc/A67iH/tSOh
```

Alternatively, build from source with `git` and a Rust toolchain (`cargo`):

```sh
git clone https://github.com/deep-thinking-lab/sekisho
cd sekisho
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

Check the installed version:

```sh
sekisho --version
```

Release 0.1.1 reports `sekisho 0.1.1`.

## Start Sekisho

Run Sekisho and create the private home directory:

```sh
sekisho up
```

The command asks for an admin id, password, and password confirmation. It then prints a TOTP enrollment URI, a TOTP secret, and the listening URL. The TOTP secret is shown once. Save it now before you close the terminal.

For scripted setup, run `sekisho up --admin-password-stdin` and send the id, password and confirmation as three lines on stdin.

Add the TOTP secret to your authenticator app. Open `http://127.0.0.1:7470/login` and keep the terminal open while you work through the rest of this guide. Press Ctrl-C in that terminal when you want to stop the server.

The default home is `~/.sekisho`. To use another directory, run `sekisho up --home /path/to/home` or set `SEKISHO_HOME`. It contains the database, policy, configuration, audit key, grant key, and local admin files. Sekisho creates the directory with mode `0700` and the files with mode `0600`.

For a remote browser, use HTTPS. The [security guide](security.md) shows a reverse proxy setup.

## Add a Claude Code agent

In a second terminal, add the agent and print the hook configuration:

```sh
sekisho agent add claude --print-config claude-code
```

The first output line is the agent token. Keep it out of shell history and source control. Add the token to the environment Claude Code runs in:

```sh
export SEKISHO_TOKEN='replace-with-the-agent-token'
```

The printed `.claude/settings.json` block wires `sekisho hook claude-code` into `PreToolUse`. Merge that block into the Claude Code settings file. If Sekisho is not at the default URL, set `SEKISHO_SERVER`. The same command prints a `.mcp.json` block for the experimental MCP gateway; see [MCP gateway](mcp.md).

```sh
export SEKISHO_SERVER='http://127.0.0.1:7470'
```

The hook sends a tool request to Sekisho and waits up to 120 seconds for an approval. If the request is still pending, Claude Code denies it and prints the approval URL.

After you wire the hook, every tool call is denied with `no rule` until the policy allows it. For example, these rules allow the common read-only tools inside one project. Replace `/path/to/project` with the project's real absolute path:

```toml
[[rule]]
name = "allow Claude Code Read in the project"
tool = "hook:claude-code/read"
target = "/path/to/project/**"
decision = "allow"

[[rule]]
name = "allow Claude Code Grep in the project"
tool = "hook:claude-code/grep"
target = "/path/to/project/**"
decision = "allow"

[[rule]]
name = "allow Claude Code Glob in the project"
tool = "hook:claude-code/glob"
target = "/path/to/project/**"
decision = "allow"
```

Keep a `target` on every hook rule. A rule without one matches any path on the machine.

The hook target is the real path the tool touches. Read, Edit, Write and MultiEdit use `file_path`. NotebookEdit uses `notebook_path`. Grep, Glob and LS use their search root: `path` or the working directory, plus the fixed directory part of a Glob pattern. Directories end in `/`, so `/path/to/project/**` also matches a search of the project root. Any other tool targets its one path-like argument, or the working directory if it has none.

The hook denies, rather than guesses, when a tool input has a path-like argument the target does not cover, more than one for an unknown tool, an empty or non-string path, or a path that starts with `~`. It also denies a Glob pattern containing `{`, `[`, `\` or a `..` segment, and an absolute pattern with a `/` after its first wildcard.

Bash uses `cwd:<working directory>/` as its target, so a file rule never allows shell commands by accident. To allow Bash in a project, write an explicit rule with `tool = "hook:claude-code/bash"` and `target = "cwd:/path/to/project/**"`. That target only says where the command starts. It does not limit what the command touches.

Sekisho always denies hook actions whose target is inside the Sekisho home, whatever the policy or grants say. The hook also refuses Bash commands that name the home. That check reads the command text, so it is a tripwire, not a boundary: a shell command can build the path at run time. If the agent runs as your OS user, it can reach the home through any tool you allow without approval, such as Bash. See [Run Sekisho as a separate OS user](security.md#run-sekisho-as-a-separate-os-user).

## Configure the upstream remote

Create a private directory and token file for the GitHub credential:

```sh
mkdir -m 700 -p "$HOME/.sekisho/upstreams"
```

```sh
printf '%s\n' 'replace-with-your-github-token' > "$HOME/.sekisho/upstreams/github.secret"
chmod 600 "$HOME/.sekisho/upstreams/github.secret"
```

Add a remote to `~/.sekisho/config.toml`:

```toml
[[remote]]
name = "github"
base_url = "https://github.com"
token_file = "upstreams/github.secret"
```

GitHub uses `https://api.github.com` for force detection by default. For another host, set `api_url` as described in the [git proxy reference](git-proxy.md).

Sekisho proves fast-forwards from the pushed commits, and uses the comparison API at `api_url` only when the pack alone is not enough. Any update it cannot prove is a fast-forward gets `force = true`, so the example policy denies it on `main` and the agent branch rule does not allow it.

Stop the server and start it again so it reads the configuration:

```sh
sekisho up
```

Point your repository at Sekisho instead of GitHub. Replace `owner` and `repo` with the repository path:

```sh
git remote add sekisho http://127.0.0.1:7470/git/github/owner/repo.git
```

The agent token is the password for the Sekisho remote. The username is ignored. Use the token from `sekisho agent add` when Git prompts for a password.

To use a different remote name, change the name in `config.toml` and the second path segment in the URL. The URL shape is `/git/<remote>/<owner>/<repo>.git`.

The remote sets `case_insensitive = true` by default, so Sekisho lowercases the owner and repository before it checks policy. Use lowercase names in the proxy URL and policy targets. Set `case_insensitive = false` if your remote needs the original case.

## Write the first policy

The generated policy contains example targets. Replace them with your repository. Policy targets use `<host>/<owner>/<repo>:<ref>`, where the host comes from the remote's `base_url`. For a remote with `base_url = "https://github.com"`, the host is `github.com`, and a target might be `github.com/owner/repo:refs/heads/main`. For a local upstream at `http://127.0.0.1:9000`, the host is `127.0.0.1`, and a target might be `127.0.0.1/owner/repo:refs/heads/main`.

This policy allows fetches, denies force pushes to `main`, allows agent branches with a budget, and holds `main` for one approver:

```toml
version = 1

[[rule]]
name = "fetch the repository"
tool = "git.fetch"
target = "github.com/owner/repo"
decision = "allow"

[[rule]]
name = "deny force pushes to main"
tool = "git.push"
target = "github.com/owner/repo:refs/heads/main"
params = { force = true }
decision = "deny"

[[rule]]
name = "allow agent branches"
tool = "git.push"
target = "github.com/owner/repo:refs/heads/agent/**"
params = { force = false }
decision = "allow"
budget = { max = 50, per = "1h" }

[[rule]]
name = "hold main for approval"
tool = "git.push"
target = "github.com/owner/repo:refs/heads/main"
decision = "ask"
approvers = 1
```

Save it as `~/.sekisho/policy.toml`. Validate the file before loading it:

```sh
sekisho policy check "$HOME/.sekisho/policy.toml"
```

Load the new policy:

```sh
sekisho policy reload
```

`sekisho policy reload` needs the server to be running. It uses `SEKISHO_HOME` when set or the default `~/.sekisho` home. It also needs a TOTP code from your authenticator app: on a terminal it prompts `TOTP code:`, and otherwise it reads the code as one line on stdin. There is no command line flag for the code. Sekisho keeps the previous policy when the new file is invalid. Each successful load writes an audit entry with the policy SHA-256.

## Hold a push

Create a commit and push it to `main`:

```sh
git push sekisho HEAD:main
```

Git stops with a message like:

```text
remote: Sekisho approval required: apr_...: http://127.0.0.1:7470/approvals/apr_...
fatal: the remote end hung up unexpectedly
```

Sekisho has not forwarded the push. The audit trail now records the action request, the decision, and the pending approval. The remote end hung up after the approval line because Sekisho refused the unapproved request. That is expected.

You can list and approve pending requests from the terminal:

```sh
sekisho approvals list
sekisho approvals approve apr_...
```

`sekisho approvals approve` and `sekisho approvals deny` ask for a TOTP code from your authenticator app the same way: a `TOTP code:` prompt on a terminal, otherwise one line on stdin. They never take it as an argument. Each code can be used once. The local admin token alone cannot approve, deny or reload the policy.

To use the web inbox instead, open `http://127.0.0.1:7470/login`, sign in with the admin id, the password and a TOTP code from your authenticator app, and approve the request. The approval is bound to the exact old and new commit IDs and the ref. A different commit needs a new approval. Two held pushes from different commits show as two rows in `sekisho approvals list` and the web inbox.

Repeat the same push:

```sh
git push sekisho HEAD:main
```

Sekisho consumes the approval during this push. An approval can be used once. If the upstream fails after Sekisho starts forwarding, the approval remains consumed and the retry is a new authorization.

If you need the approval URL in the held push to use a different host, set `public_url` in `config.toml` and restart the server:

```toml
public_url = "https://sekisho.example.com"
```

The default is `http://` followed by the server's bind address.

## Notifications

Sekisho can notify a webhook or Slack when an action waits for approval, and approvers can approve or deny from Slack. Both are part of the free Community edition. See [Approval notifications](notifications.md).

To stop the server, press Ctrl-C in its terminal.

## Export and verify the audit trail

Export the signed audit chain:

```sh
sekisho audit export --out audit.jsonl
```

The export writes the JSONL chain to `audit.jsonl` and prints the external public key to standard error:

```text
--pubkey audit=BASE64_PUBLIC_KEY
```

Record the value after `--pubkey`. Keep it outside the export. Copy `audit.jsonl` and the recorded value to the machine that will verify the trail:

```sh
sekisho audit verify audit.jsonl --pubkey 'audit=BASE64_PUBLIC_KEY'
```

A valid authenticated export prints a line that starts with `valid:` and exits with code 0. Verification with no external key exits with code 3 and returns `UNAUTHENTICATED`.

The [audit guide](audit.md) describes the export format, exit codes, and key handling.

## Run the scripted local journey

To exercise the same journey against a local bare repository, run:

```sh
scripts/demo.sh
```

The script creates a temporary home, serves a bare repository, starts Sekisho, adds an agent, proves an allowed branch push, holds a main push, approves it through the HTTP API, retries the push, exports the audit trail, and verifies it with the external key.
