# Policy reference

This page describes the policy file, policy decisions, budgets, grants, and the policy commands.

**Status:** Developer preview (v0.1). Expect rough edges; the audit format and policy schema may change before v1.

## Policy file

Sekisho reads `policy.toml` from its home directory. The default path is `~/.sekisho/policy.toml`. Set `SEKISHO_HOME` to use a different home. The `sekisho up --home <path>` option also chooses the home for that process.

The file has a schema version and an optional array of rules:

```toml
version = 1

[[rule]]
name = "allow agent branches"
tool = "git.push"
target = "github.com/acme/api:refs/heads/agent/**"
params = { force = false }
decision = "allow"
budget = { max = 50, per = "1h" }
```

The parser rejects unknown keys. It also rejects a missing version, a version other than `1`, duplicate rule names, a missing decision, and invalid field combinations.

## Decision order

`sekisho_core::decide` chooses exactly one decision for each action:

1. A matching `deny` rule wins, even when an earlier rule or a grant would allow the action.
2. A valid matching grant allows the action.
3. The first matching rule decides. An `allow` rule allows unless its budget is exhausted. An `ask` rule creates an approval request.
4. If no rule matches, Sekisho denies the action with the reason `no rule`.

Sekisho evaluates deny rules before grants and other rules. Grants can widen access to `allow`, but they cannot override a deny.

The server adds one built-in deny rule, `built-in: Sekisho state directory`, ahead of the policy file. It denies every `hook:` action whose target is the Sekisho home or a path inside it, by the configured path and by its real path. It also denies a search of any directory that contains the home, such as a Grep or Glob rooted at your home directory or `/`, and Bash started in one. On macOS that includes the data volume spellings, `/System/Volumes/Data`, `/System/Volumes` and `/System`, which contain the home through the firmlink. A policy file or grant cannot override it, and it does not change the policy digest.

Paths have one spelling for matching. On macOS, `canonicalize` keeps some aliases of the same file: the data volume firmlink root `/System/Volumes/Data` and the `/.nofollow`, `/.resolve` and `/.vol` prefixes. The hook rewrites `/System/Volumes/Data/...` to `/...` and refuses the other three. Deny rules also match a target with `/System/Volumes/Data` removed, and the built-in rule denies the three prefixes outright. The hook also compares the device and inode of the target and each existing parent with the Sekisho home, so a bind mount or other alias of the home is refused too. MCP tools called through the hook target the MCP server name, not a path, so these checks do not cover them: do not allow a filesystem MCP server to reach the home.

### Migrating policies to the new hook targets

From 0.1.1, hook targets name the path a tool touches instead of the working directory (see the [quickstart](quickstart.md#add-a-claude-code-agent)). Two forms changed: Bash targets `cwd:<real working directory>/`, and directory targets end in `/`.

Deny rules keep their meaning. A deny rule also matches the bare path behind `cwd:` and the directory without its trailing `/`, so a deny rule written for `/secret/**` or `/secret` still denies Bash started there and searches of that directory. Allow and ask rules match only the new target, so an allow rule written for file paths no longer allows Bash. To allow Bash again, add a rule with `tool = "hook:claude-code/bash"` and `target = "cwd:/path/to/project/**"`. The policy schema version stays `1`, because no existing rule becomes more permissive.

## Rule fields

Each rule requires `name`, one tool selector, and `decision`.

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | Yes | Unique rule name, 1 to 128 characters, with no leading or trailing whitespace |
| `tool` | One selector | Exact tool name |
| `tool_prefix` | One selector | Prefix of a tool name |
| `target` | No | Glob matched against the complete action target |
| `params` | No | Exact top-level parameter constraints |
| `decision` | Yes | `allow`, `ask` or `deny` |
| `budget` | No | Limit for an `allow` rule |
| `approvers` | No | Number of approvers for an `ask` rule |

Use exactly one of `tool` and `tool_prefix`.

Tool names use lowercase ASCII letters, digits, and the characters `.`, `_`, `:`, `/`, and `-`. A tool name is at most 128 bytes and contains no wildcard. A `tool_prefix` follows the same character rules and must end in `/`, `_`, `.` or `:`, so it stops at a segment boundary. `mcp:github/` matches the tools of the `github` server but not those of a server named `github-admin`. A prefix such as `mcp:github` is rejected.

```toml
[[rule]]
name = "read GitHub tools"
tool_prefix = "mcp:github/get_"
decision = "allow"
```

The prefix rule above is an example of matching. The MCP gateway is an experimental enforcement point in this preview. It checks MCP tool calls as `mcp:<server>/<tool>`. See [MCP gateway](mcp.md).

### Target globs

`target` is a glob matched against the complete target string. If you omit `target`, the rule matches any target.

`*` matches within one slash-separated segment. It does not cross a `/`.

`**` crosses slash-separated segments.

For a target such as `github.com/acme/api:refs/heads/agent/feature`:

| Pattern | Matches | Reason |
| --- | --- | --- |
| `github.com/acme/api:refs/heads/*` | No | `*` cannot cross the slash before `feature` |
| `github.com/acme/api:refs/heads/agent/**` | Yes | `**` crosses the remaining segments |
| `github.com/*/api:refs/heads/agent/**` | Yes | The first `*` stays within the `acme` segment |

### Parameter constraints

`params` checks exact equality on named top-level fields. The action must contain the field with the same JSON value.

```toml
params = { force = false }
```

A missing field fails the constraint. So does a different value. Constraints do not inspect nested fields.

## Decisions

### Allow

```toml
[[rule]]
name = "allow agent branches"
tool = "git.push"
target = "github.com/acme/api:refs/heads/agent/**"
params = { force = false }
decision = "allow"
```

When the rule matches and its budget is not exhausted, Sekisho allows the action.

### Ask

```toml
[[rule]]
name = "hold main for approval"
tool = "git.push"
target = "github.com/acme/api:refs/heads/main"
decision = "ask"
approvers = 1
```

`approvers` defaults to `1`. It must be `1` when present. The preview does not support multi-approver quorum.

An agent can hold at most 20 pending approvals. Past that, a request an `ask` rule would hold is denied with the reason `too many pending approvals`, and no approval or notification is created. At most 16 requests per agent wait for a decision at once; further requests get the `ask` answer and approval id immediately instead of waiting.

The approval is bound to the action digest. Changing the agent, tool, target or parameters produces a different digest and requires a new approval. When an approved action is used, Sekisho decides it again first, including for a request that was waiting for the approval. The approval is consumed only if the current policy and grants still ask for it and the agent still exists. A deny rule loaded or an agent removed while the request waited wins.

### Deny

```toml
[[rule]]
name = "deny force pushes to main"
tool = "git.push"
target = "github.com/acme/api:refs/heads/main"
params = { force = true }
decision = "deny"
```

Every matching deny rule is checked before grants and other rules. The first matching deny in file order supplies the rule name for the refusal.

## Budgets

A budget limits allowed executions for one agent and one rule in the current fixed time window:

```toml
budget = { max = 50, per = "1h" }
```

`max` is an integer from 1 through the maximum unsigned 32-bit value. `per` accepts a positive integer followed by `s`, `m`, `h` or `d`. The period must be between 1 second and 30 days.

Sekisho stores usage in SQLite and counts it on the server. The request cannot supply a count. Exhausted budgets deny the action with `budget exhausted`.

Budgets are allowed only on `allow` rules. Ask rules cannot carry a budget in this preview.

## Grants

A grant is a signed, time-limited allowance issued by a human. It is checked after deny rules and before normal policy rules.

### Add a grant

```sh
sekisho grant add --agent claude --tool git.push --target 'github.com/acme/api:refs/heads/release/*' --expires 2h --max-uses 3
```

The command prints the grant ID. Supported options are:

| Option | Meaning |
| --- | --- |
| `--agent` | Agent that can use the grant |
| `--tool` | Exact tool name |
| `--target` | Target glob with the same `*` and `**` rules as policy |
| `--param` | Top-level parameter constraint in `key=value` form, repeatable |
| `--expires` | Positive duration in seconds, minutes, hours or days |
| `--max-uses` | Optional maximum number of uses |

Without `--max-uses`, the grant has no use limit. It still expires at the time set by `--expires`.

Example with parameter constraints:

```sh
sekisho grant add --agent claude --tool git.push --target 'github.com/acme/api:refs/heads/release/*' --param force=false --expires 2h --max-uses 3
```

Grants are signed with the grant key in the Sekisho home. Sekisho stores the grant and writes its audit entry in one database transaction.

### List grants

```sh
sekisho grant list
```

The table shows the grant ID, agent, tool, target, uses, maximum uses, expiry timestamp, and status. Status is `active`, `pending`, `expired`, `exhausted` or `revoked`.

### Revoke a grant

```sh
sekisho grant revoke grt_0123456789abcdefghijklmnopqrst
```

Revocation writes a tombstone and an audit entry in one transaction. A revoked grant cannot authorize another action.

## Policy commands

Validate a policy file without loading it:

```sh
sekisho policy check "$HOME/.sekisho/policy.toml"
```

On success the command prints `ok: N rules` and exits 0. Add `--json` to print one JSON object per rule instead. A parse or validation error exits nonzero and prints the rule and field that failed.

Reload the policy for a running local server:

```sh
sekisho policy reload
```

Reload uses the local admin token and URL in the Sekisho home, plus a TOTP code from the admin's authenticator app. The command prompts for the code on a terminal and otherwise reads it from stdin. It never takes the code as an argument, because other processes of the same user can read arguments. Each code can be used once. Reload is available only for a loopback server. If the file is invalid, the reload fails and the previous policy stays active. At startup and on reload, Sekisho refuses a policy file that is a symlink or not a regular file, is not owned by the user Sekisho runs as, or is writable by group or others. It also refuses one whose directory is not owned by that user or is writable by group or others. Each failed TOTP attempt, including a code that was already used, counts toward a limit of five per 15 minutes. A successful load writes an audit entry containing the SHA-256 of the policy file.
