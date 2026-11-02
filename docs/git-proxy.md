# Git proxy reference

The git proxy accepts git smart HTTP requests from agents, decides each ref update, and forwards authorized requests to the upstream remote. Sekisho holds the upstream credential.

**Status:** Developer preview (v0.1). Expect rough edges; the audit format and policy schema may change before v1.

## Configure a remote

Add remotes to `$SEKISHO_HOME/config.toml`, or to `~/.sekisho/config.toml` when `SEKISHO_HOME` is unset:

```toml
[[remote]]
name = "github"
base_url = "https://github.com"
token_file = "upstreams/github.secret"
case_insensitive = true
api_url = "https://api.github.com"
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | Yes | Name used in the proxy URL |
| `base_url` | Yes | Upstream HTTPS base URL. Plain HTTP is accepted only for a loopback host |
| `token_file` | Yes | Upstream token path, relative to the Sekisho home |
| `case_insensitive` | No | Lowercase the owner and repository before forwarding, default `true` |
| `api_url` | No | GitHub API base URL used when a push alone cannot prove a fast-forward |

The token file must be a regular file with mode `0600`. Its contents are the upstream bearer or personal access token. Sekisho sends the token to the upstream and never returns it to an agent.

Sekisho sends the upstream token with every request to `base_url` and `api_url`, so both must use HTTPS unless the host is loopback (`localhost`, `127.0.0.1` or `::1`). Startup fails otherwise. For GitHub, `api_url` defaults to `https://api.github.com`. For another host, set `api_url` explicitly. Without it, an update that the pushed pack alone cannot prove to be a fast-forward is treated as forced (`force = true`).

Restart `sekisho up` after changing `config.toml`.

## Proxy URL and authentication

Use this URL shape:

```text
http://127.0.0.1:7470/git/<remote>/<owner>/<repo>.git
```

The agent authenticates with the token returned by `sekisho agent add`. Git HTTP basic authentication sends the token as the password. The username is ignored. Sekisho resolves the agent from the token and never trusts an agent ID from the URL, headers or request body.

For example:

```sh
git remote add sekisho http://127.0.0.1:7470/git/github/acme/api.git
```

Use HTTPS in the proxy URL for a remote deployment. Do not put an upstream credential in the git remote.

## Request mapping

Sekisho maps smart HTTP requests to these actions:

| Git request | Action |
| --- | --- |
| `info/refs?service=git-upload-pack` | `git.fetch` |
| `git-upload-pack` | `git.fetch` |
| `info/refs?service=git-receive-pack` | Ref updates checked as `git.push` |
| `git-receive-pack` | Ref updates checked as `git.push` |

For fetch, the action target is the upstream host and repository path, such as `github.com/acme/api`. For push, each ref update has a target such as `github.com/acme/api:refs/heads/main`. Push parameters contain `old`, `new`, `delete`, and `force`.

Sekisho parses the pkt-line command list before forwarding a receive-pack request. It accepts request encodings `identity` and `gzip`. Any other content encoding is rejected. A request whose commands cannot be parsed is rejected and never forwarded. A push that names the same ref twice is rejected.

## All-or-nothing pushes

A push can contain several ref updates. Sekisho decides every update before it writes any grant use, budget count or approval consumption.

If any update is denied or still needs approval, Sekisho refuses the whole push. A refused push consumes no grants, budgets or approvals. The error names each approval ID and approval URL.

Once every update is authorized, Sekisho consumes the required grants, budget counts and single-use approvals, then starts forwarding the push. Those resources stay consumed if streaming fails, the push times out, or the upstream fails. Retrying the push is a new authorization.

For an update to an existing ref, `force` is `false` only when Sekisho proves the update is a fast-forward, meaning the old commit is an ancestor of the new one. Every other update has `force = true`, including any update Sekisho cannot prove. So a `force = true` deny rule catches every rewrite, and a `force = false` allow rule only matches proven fast-forwards.

Sekisho proves ancestry from the pushed pack first. It reads the commits in the pack, checks each commit id against the commit's content, and follows parent links from the new commit. If it reaches the old commit, the update is a fast-forward. If the whole history is in the pack and the old commit is not in it, the update is forced. If the history leaves the pack at commits the upstream already has, Sekisho asks the upstream compare API whether the old commit is an ancestor of one of them (at most 16 per update, and at most 32 distinct questions per push, each asked once). An error, timeout or missing API counts as not proven. Sekisho only calls the API when the policy decision depends on `force`.

To read the pack, Sekisho spools the rest of the push body to an unlinked `0600` file in the system temporary directory before deciding. Allow disk space for `body_limit` times the concurrent push limit.

Creating or deleting a ref uses `force = false`.

## Settings

Set these keys at the top level of `config.toml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `git_push_timeout_seconds` | `600` | Time limit for a push request |
| `git_max_concurrent_pushes` | `8` | Concurrent receive-pack requests |
| `git_body_limit_bytes` | `1073741824` | Maximum decoded push body size, 1 GiB |

When the concurrent push limit is full, Sekisho returns HTTP 503. The upstream client uses a 30 second read idle timeout.

Example:

```toml
git_push_timeout_seconds = 900
git_max_concurrent_pushes = 4
git_body_limit_bytes = 536870912
```

## Audit outcomes

For each ref update, the audit trail records the action request and decision with its action digest. After the upstream request, it records one of these outcomes:

- `outcome = "forwarded"` with the upstream HTTP `status`.
- `outcome = "upstream_failed"` with an `error_class`.

The `error_class` names the failure category, such as `timeout`, `connect`, `body`, `transport`, `worker` or `response_body`. An upstream failure is recorded, but it does not undo consumed approvals, grants or budget counts.

## Approval links

When a push is held, Git prints a link to the approval page. Set `public_url` at the top level of `config.toml` (for example `public_url = "https://sekisho.example.com"`) so the link works from other machines. Without it, Sekisho uses its bind address.
