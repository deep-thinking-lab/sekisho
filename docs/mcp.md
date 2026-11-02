# MCP gateway

**Status:** Experimental in the developer preview (v0.1). Configuration keys and behavior may change before v1.

The MCP gateway puts Sekisho between an agent and the MCP servers it uses. The agent connects to one endpoint. Sekisho holds the upstream credentials, checks every tool call against policy, and forwards the call only when policy allows it.

## What it does

- Sekisho serves one MCP endpoint at `/mcp` (streamable HTTP). Agents authenticate with their Sekisho bearer token, as they do for the other agent routes. Human cookie sessions are refused.
- You declare upstream MCP servers in `config.toml`. Credentials stay in Sekisho and are never sent to the agent.
- Upstream tools appear to the agent as `<server>/<tool>`. A tool `get_issue` on the server `github` is `github/get_issue`.
- `tools/list` shows only the tools that the agent's policy does not deny. A tool that needs approval stays in the list. Hiding uses the tool name and server only, so a deny rule that depends on `params` does not hide the tool; it still refuses the call.
- Sekisho caches each server's tool discovery for `discovery_ttl_seconds`. Agents cannot make Sekisho start a process or send a credential on demand more often than that.
- Each call is decided through the same path as the other enforcement points: policy, single-use approvals, grants, budgets and the audit trail. Sekisho makes no upstream call before the decision.
- Upstream failures and timeouts are written to the audit trail. Repeated failures from one server are summarized at most once a minute.

## Try it with curl

Set the endpoint and an agent token:

```sh
export SEKISHO_TOKEN='...'
MCP_URL=http://127.0.0.1:7470/mcp
```

Initialize a stateless session:

```sh
curl -sS -m 10 "$MCP_URL" \
  -H "Authorization: Bearer $SEKISHO_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

Send the initialized notification:

```sh
curl -sS -m 10 "$MCP_URL" \
  -H "Authorization: Bearer $SEKISHO_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

List the tools the agent can see:

```sh
curl -sS -m 10 "$MCP_URL" \
  -H "Authorization: Bearer $SEKISHO_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

Call a tool:

```sh
curl -sS -m 180 "$MCP_URL" \
  -H "Authorization: Bearer $SEKISHO_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"github/get_issue","arguments":{"owner":"acme","repo":"api","number":42}}}'
```

An `ask` call blocks for up to `mcp_wait_seconds`, which defaults to 120. Sekisho sends keep-alive lines while it waits. Set curl's `-m` timeout higher than `mcp_wait_seconds`. The call example uses 180 seconds.

## Configure upstream servers

Add one `[[mcp]]` table per upstream in `~/.sekisho/config.toml` (or the `config.toml` in your Sekisho home). Restart `sekisho up` to load changes.

Common keys:

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | Yes | Server name used in tool names and as the policy target. Lowercase ASCII letters, digits, `.`, `_` and `-`. Must be unique. |
| `transport` | Yes | `http` or `stdio` |

An unknown key in an `[[mcp]]` table is rejected.

### HTTP upstream

| Key | Required | Meaning |
| --- | --- | --- |
| `url` | Yes | `http` or `https` URL. No embedded user name or password, no query and no fragment. |
| `token_file` | No | Path to a file holding the bearer token Sekisho sends upstream. A relative path is resolved against the Sekisho home. |

The token file must be a regular file with mode `0600`. Symlinks are refused. A server with a `token_file` must use `https`, unless the host is loopback (`localhost`, `127.0.0.1` or `::1`). Sekisho does not follow redirects.

```toml
[[mcp]]
name = "github"
transport = "http"
url = "https://mcp.example.com/github"
token_file = "mcp-github.token"
```

### stdio upstream

| Key | Required | Meaning |
| --- | --- | --- |
| `command` | Yes | Program to run |
| `args` | No | Arguments. Default: none. |
| `env` | No | Environment variables for the process. Default: none. |
| `secret_env` | No | Names of `env` variables whose values are secrets. Default: none. |

Sekisho starts the process with a clean environment that holds only the variables in `env`. Each name in `secret_env` must be present in `env`, and its value must be at least 8 characters. Sekisho removes the values of `secret_env` variables and token files from anything it returns to the agent. Other `env` values are not redacted.

```toml
[[mcp]]
name = "files"
transport = "stdio"
command = "/usr/local/bin/files-mcp"
args = ["--root", "/srv/project"]
env = { FILES_API_KEY = "replace-with-a-secret" }
secret_env = ["FILES_API_KEY"]
```

### Timeouts

These are top-level keys in `config.toml`, outside any table.

| Key | Default | Allowed | Meaning |
| --- | --- | --- | --- |
| `mcp_wait_seconds` | `120` | 0 to 300 | How long a call waits for an approval |
| `mcp_timeout_seconds` | `30` | 1 to 600 | Time limit for each upstream operation |

### Limits

The `[mcp_limits]` table sets size and cache limits. Every key is optional. An unknown key is rejected.

| Key | Default | Allowed | Meaning |
| --- | --- | --- | --- |
| `discovery_ttl_seconds` | `300` | 1 to 86400 | How long Sekisho caches an upstream's tool list |
| `request_bytes` | `1048576` (1 MiB) | 1 to 67108864 | Largest request body accepted at `/mcp`. A larger request gets HTTP 413. |
| `response_bytes` | `4194304` (4 MiB) | 1 to 67108864 | Largest upstream response, and largest serialized tool result or tool list, that Sekisho accepts. Larger responses fail and are audited. |

```toml
[mcp_limits]
discovery_ttl_seconds = 300
request_bytes = 1048576
response_bytes = 4194304
```

Fixed limits, not configurable in this preview:

- At most 16 MCP operations run at once across all agents, and at most 4 per agent. An operation over the cap returns a tool error saying the limit was reached.
- Discovery reads at most 100 pages and 1,000 tools from one server. A server over the tool limit fails discovery.
- Upstream tools with an empty name, a `/` in the name, or a name Sekisho cannot represent are skipped. The audit record for the list counts them.

## Policy

Each call becomes an action with these fields:

- `tool` is `mcp:<server>/<tool>`.
- `target` is the server name.
- `params` are the arguments the agent passed to the tool. Policy matches top-level parameters exactly, as described in the [policy reference](policy.md).

Allow read-only GitHub tools:

```toml
[[rule]]
name = "read GitHub tools"
tool_prefix = "mcp:github/get_"
decision = "allow"
```

Hold one tool for a human:

```toml
[[rule]]
name = "creating issues needs a human"
tool = "mcp:github/create_issue"
target = "github"
decision = "ask"
approvers = 1
```

Deny a tool outright:

```toml
[[rule]]
name = "no repository deletion"
tool = "mcp:github/delete_repository"
decision = "deny"
```

Without a matching rule, the call is denied.

## What the agent sees

The gateway reports refusals as MCP tool errors, so the agent can read them and carry on.

- **Deny:** the tool error reads `Sekisho deny: <reason>; rule: <rule name>`. Nothing reaches the upstream server.
- **Ask:** the call waits up to `mcp_wait_seconds` for a decision. If a human approves in time, Sekisho consumes the approval and forwards the call. If the request is still pending, the tool error reads `Sekisho ask: <reason>; approval: <id>, <public_url>/approvals/<id>`. Set `public_url` in `config.toml` so this link works from another machine. Approve it in the web inbox, then have the agent retry the same call. An approval is bound to the exact arguments and is used once.
- **Upstream failure:** the tool error reads `Sekisho upstream failed: <class>`, and the audit trail records the failure.

## Connect Claude Code

Add the agent and print its configuration:

```sh
sekisho agent add claude --print-config claude-code
```

The output holds the agent token, the `.claude/settings.json` hook block, and a `.mcp.json` block:

```json
{
  "mcpServers": {
    "sekisho": {
      "type": "http",
      "url": "http://127.0.0.1:7470/mcp",
      "headers": {
        "Authorization": "Bearer ${SEKISHO_TOKEN}"
      }
    }
  }
}
```

Put the block in `.mcp.json` in your project and export `SEKISHO_TOKEN` in the environment Claude Code runs in, as the quickstart describes. If Sekisho is not at `127.0.0.1:7470`, change the URL.
