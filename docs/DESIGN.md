# Sekisho design

Status: v0.1 design.

## 1. What Sekisho is

Sekisho is a self-hosted permission layer for AI agents. Agents never hold standing credentials. Every consequential action goes through Sekisho, which allows it, denies it, or holds it for a human to approve. Every decision lands in a signed audit trail the operator owns and can verify offline.

The name comes from the checkpoints on Edo-period roads, where travellers showed a permit before passing.

One sentence for the website: **Let agents act. Keep the keys.**

## 2. Who it is for

The head of platform or security at a regulated software company whose developers already use coding agents (Claude Code, Codex, OpenHands, in-house agents). They need to let agents push code, open tickets and call internal APIs without giving them long-lived tokens, and show an auditor who approved what.

## 3. The five-minute journey (the product's acceptance test)

```
curl -fsSLO https://get.sekisho.sh/install.sh{,.minisig} && minisign -Vm install.sh -P <key> && sh install.sh   # or: docker run ...
sekisho up                                      # creates ~/.sekisho, keys, admin user, sample policy; opens http://127.0.0.1:7470
sekisho agent add claude --print-config claude-code   # prints the hook + MCP config to paste
# agent tries `git push origin main` through the Sekisho git proxy
# -> browser shows "claude wants to push 3 commits to main" -> Approve
# -> push completes; Audit tab shows request, approval, consumption, all signed
sekisho audit export --out audit.jsonl && sekisho audit verify audit.jsonl
```

Nothing in this journey needs KVM, Kubernetes, a cloud account, another repo, or a model key.

## 4. Non-goals for v0.1

Running agents. Sandboxing code (that is Voxeltron's job). Hosting models. Multi-tenant SaaS. Delegated grant chains. Being a forge. Any feature without a named design partner asking for it.

## 5. Architecture

One binary, one process, one SQLite file.

```
                 ┌──────────────────────── sekisho (single binary) ─────────────────────────┐
 agent ──hook──▶ │ /v1/check            ┐                                                    │
 agent ──MCP───▶ │ /mcp (gateway)        ├─▶ Decide(Action) ─▶ allow ─▶ execute via upstream ─┼─▶ GitHub, MCP servers
 agent ──git───▶ │ /git/{remote}/{repo}  ┘        │   ask ─▶ Approval (bound to digest)       │    (Sekisho holds creds)
                 │                                 │   deny                                    │
 human ─browser▶ │ UI: inbox, audit, agents, grants, policy                                    │
                 │ Store: SQLite (WAL)   Audit: hash chain + Ed25519   Keys: 0600 files        │
                 └─────────────────────────────────────────────────────────────────────────────┘
```

Crates (a workspace with exactly two crates in v0.1):

| Crate | Contents | Rule |
|---|---|---|
| `sekisho-core` | Pure domain: `Action`, digest, policy parsing and evaluation, grant checks, approval state machine, audit entry hashing and signing, verification. | No I/O, no async, no clock reads (time is passed in). 100% of security logic lives here so it can be tested exhaustively. |
| `sekisho` | Binary: CLI (clap), server (axum), store (rusqlite), UI (askama + vendored htmx), enforcement points (hook, MCP gateway, git proxy). | Calls `sekisho-core` for every decision. Never re-implements a check. |

Approved dependencies (anything else needs architect sign-off): `tokio`, `axum`, `tower-http`, `rusqlite` (bundled), `serde`, `serde_json`, `serde_jcs`, `toml`, `sha1` (git object ids only), `sha2`, `ed25519-dalek`, `rand_core`, `argon2`, `totp-rs`, `askama`, `clap`, `tracing`, `tracing-subscriber`, `thiserror`, `anyhow` (binary only), `time`, `uuid`, `reqwest` (rustls), `rmcp`, `globset`, `hex`, `base64`, `flate2`, `proptest` (dev), `insta` (dev).

## 6. Domain model

### 6.1 Action

```rust
pub struct Action {
    pub agent_id: AgentId,          // who is asking
    pub tool: ToolName,             // "git.push", "git.fetch", "mcp:github/create_issue", "hook:claude-code/Bash"
    pub target: String,             // "github.com/acme/api:refs/heads/main", "github", "/repo/path"
    pub params: serde_json::Value,  // tool arguments, e.g. {"old":"<sha>","new":"<sha>","force":false}
}
```

`ToolName` is a validated string: lowercase, `[a-z0-9._:/-]`, max 128 bytes. No wildcards anywhere in names.

`Action` fields are private and an `Action` can only be created through a validating constructor (including when deserialized), so no code path can digest an unvalidated action.

**Numbers in `params`.** RFC 8785 canonicalizes every JSON number as an IEEE-754 double, so integers beyond 2^53 collapse: `9007199254740992` and `9007199254740993` would produce the same digest, and an approval for one would authorize the other. `Action` construction therefore rejects any integer in `params` (at any depth) whose magnitude exceeds 2^53 − 1. Callers that need larger integers (amounts in minor units, IDs) must pass them as strings. Found by the implementer of task 101. For the same reason, JCS writes `1.0` as `1` and `-0.0` as `0`, so `Action` construction also rejects a float with an integer value of at most 2^53 − 1 in magnitude, and negative zero. Send integers as integers.

**Action digest** = SHA-256 over the RFC 8785 (JCS) canonical JSON of `{"v":1,"agent_id":..,"tool":..,"target":..,"params":..}`. Hex encoded. This digest is what an approval is bound to. Any change to any field produces a different digest.

### 6.2 Policy

A TOML file (`~/.sekisho/policy.toml`). Rules are evaluated in order; the first matching rule decides. **No match means deny.**

```toml
version = 1

[[rule]]
name = "agents may push to their own branches"
tool = "git.push"
target = "github.com/acme/*:refs/heads/agent/**"   # globset pattern on target
params = { force = false }                          # exact-match constraints on top-level params
decision = "allow"
budget = { max = 50, per = "1h" }                   # counted server side, per agent per rule

[[rule]]
name = "pushes to main need a human"
tool = "git.push"
target = "github.com/acme/*:refs/heads/main"
decision = "ask"
approvers = 1                                       # v0.1 supports 1; quorum is v0.2

[[rule]]
name = "read-only MCP tools"
tool_prefix = "mcp:github/get_"                     # explicit prefix match, the only non-exact tool match
decision = "allow"
```

Rules:
- `tool` (exact) or `tool_prefix` (explicit prefix), never both.
- `target` is a glob matched with `globset` against the full target string. `*` matches within one `/`-separated segment and `**` crosses segments; grant `target_glob` follows the same rule. Absent means any target.
- `params` constraints are exact equality on named top-level keys. A missing key in the action fails the constraint.
- `decision` is `allow`, `ask` or `deny`.
- `budget` counts *allowed or approved executions*, stored in SQLite, keyed by (agent, rule name, window start). Never taken from the request.
- The policy file is loaded at startup and on `sekisho policy reload`. Each load writes an audit entry containing the SHA-256 of the file. An invalid file is rejected and the previous policy stays active.

### 6.3 Grants

A grant is a human-issued, time-limited allowance that sits *before* policy evaluation: `sekisho grant add --agent claude --tool git.push --target 'github.com/acme/api:refs/heads/release/*' --expires 2h --max-uses 3`.

```rust
pub struct Grant {
    pub id: GrantId, pub agent_id: AgentId, pub tool: ToolName, pub target_glob: String,
    pub params: BTreeMap<String, Value>, pub not_before: Timestamp, pub expires_at: Timestamp,
    pub max_uses: Option<u32>, pub issued_by: UserId, pub signature: Signature, // Ed25519 over JCS of all other fields
}
```

- Uses are counted server side. Revocation writes a tombstone row in the same transaction that writes the audit entry. A grant is valid only if: signature verifies, `not_before <= now < expires_at`, no tombstone, uses below max.
- Grants can only widen to `allow`. A policy `deny` rule always wins over a grant (evaluate denies first).

### 6.4 Decision procedure (in `sekisho-core`)

```
decide(action, policy, grants, counters, now) -> Decision { kind: Allow|Ask|Deny, rule: Option<String>, grant: Option<GrantId>, reason }
1. If any policy rule with decision=deny matches -> Deny.
2. If a valid grant matches (tool exact, target glob, params) and has uses left -> Allow (grant).
3. First matching rule: allow -> check budget -> Allow or Deny("budget exhausted"); ask -> Ask; 
4. No match -> Deny("no rule").
```

Pure function. Exhaustively property-tested.

### 6.5 Approval

State machine: `Pending -> Approved | Denied | Expired`, `Approved -> Consumed | Expired`. No other transitions.

```rust
pub struct Approval {
    pub id: ApprovalId, pub action: Action, pub action_digest: Digest, pub rule: String,
    pub requested_at: Timestamp, pub expires_at: Timestamp,          // default 15 minutes
    pub state: ApprovalState, pub decided_by: Option<UserId>, pub decided_at: Option<Timestamp>,
}
```

- Created only by the server when `decide` returns Ask. The requesting agent receives the approval id.
- Only a logged-in human user can approve or deny. Agents have no route to these endpoints. An approver can never be the same principal as `action.agent_id` (enforced in core, tested).
- Approve re-checks expiry. Deny is final.
- **Consumption is atomic and single-use**: the enforcement point recomputes the digest of the action it is about to execute and runs `UPDATE approvals SET state='consumed' WHERE id=? AND state='approved' AND action_digest=? AND expires_at>?`. Exactly one row must change, or the action is refused.
- An approval for a different digest is useless. That is the point.

### 6.6 Audit trail

Every state change writes one audit entry in the same SQLite transaction as the change. If the audit write fails, the transaction rolls back and the action is refused (fail closed).

```rust
pub struct AuditEntry {
    pub seq: u64, pub at: Timestamp, pub kind: AuditKind, // ActionRequested, Decided, ApprovalRequested, Approved, Denied, Expired,
                                                          // Consumed, GrantIssued, GrantRevoked, PolicyLoaded, UserLogin, AgentAdded, KeyRotated
    pub actor: Principal, pub subject: serde_json::Value, // includes action_digest / approval_id / grant_id / policy_sha256
    pub prev_hash: Digest, pub entry_hash: Digest, pub signature: Signature,
}
entry_hash = SHA-256( prev_hash || JCS({seq, at, kind, actor, subject}) )
signature  = Ed25519(audit_key, entry_hash)
```

- Genesis `prev_hash` is 32 zero bytes. `seq` is gapless.
- `sekisho audit export` writes JSONL entries plus a signed checkpoint `{seq, entry_hash, at, key_id, signature}` and the public key. `sekisho audit verify <file> [--pubkey]` checks every hash, signature and that `seq` has no gaps, and works without the server or database.
- Truncation is detectable against any previously exported checkpoint. The UI shows the latest checkpoint and encourages exporting it to somewhere else (v0.2: automatic anchoring to a webhook or S3).

### 6.7 Identity

- **Humans**: local users, Argon2id passwords plus mandatory TOTP for any user who can approve. Sessions are HTTP-only, SameSite=Strict cookies, 12h lifetime. Passkeys and OIDC are v0.2.
- **Agents**: created by `sekisho agent add <name>`. Each gets a random 32-byte token shown once; the database stores only its SHA-256. Tokens are sent as `Authorization: Bearer`. Token rotation via `sekisho agent rotate`.
- **Roles** (v0.1): `admin` (manage agents, grants, policy, users), `approver` (approve and deny), `viewer` (read audit). Checked in the server for every route, with a test per route.

### 6.8 Keys and secrets

`~/.sekisho/keys/`: `audit.ed25519`, `grant.ed25519` (separate keys), and upstream credentials (`upstreams/<name>.secret`). All files 0600, directory 0700; startup refuses to run if permissions are wider. Upstream credentials never leave the server process and are never logged (a redaction test covers logs and audit subjects). KMS and HSM signing are v0.2 paid features behind a `Signer` trait defined now.

## 7. Enforcement points

### 7.1 Check API and Claude Code hook

`POST /v1/check` with an agent token and an `Action` (agent id taken from the token, never the body). Returns `{decision, approval_id?, reason}`. With `?wait=60` the call blocks until the approval resolves or the wait ends.

`sekisho hook claude-code` is a subcommand Claude Code runs as a PreToolUse hook. It reads the hook JSON on stdin, maps it to an Action (`hook:claude-code/<ToolName>`, target = the real path the tool touches, from one fixed argument per known tool (`file_path`, `notebook_path`, or the search root `path` plus the literal prefix of a Glob pattern) or an unknown tool's single path-like argument, defaulting to cwd, with a trailing `/` on directories; Bash uses `cwd:<real dir>/`; ambiguous or extra path arguments are denied; deny rules also match the bare path behind `cwd:` and the directory without its `/`; params = tool input), calls `/v1/check?wait=120`, and prints the hook response (allow, deny with reason). This gives value on day one without any proxying.

### 7.2 MCP gateway

Sekisho exposes one MCP endpoint (streamable HTTP, `rmcp`) per agent at `/mcp`. Upstream MCP servers are declared in `config.toml` (stdio command or HTTP URL, with credentials held by Sekisho). `tools/list` returns upstream tools renamed `<server>/<tool>`. `tools/call` builds `Action{tool: "mcp:<server>/<tool>", target: "<server>", params: arguments}`, decides, and on Allow (or a consumed approval) forwards the call upstream. On Ask it waits up to the configured time and returns a clear tool error with the approval id if still pending.

### 7.3 Git push proxy

Agents use `https://<sekisho>/git/<remote>/<owner>/<repo>.git` with their agent token as the password. Sekisho reverse-proxies smart HTTP to the real remote using the stored credential.

- `info/refs` and `git-upload-pack` map to `git.fetch` with target `<host>/<owner>/<repo>`.
- `git-receive-pack`: Sekisho parses the pkt-line command list at the start of the request body (old sha, new sha, ref name per line) **before** forwarding. Each ref update becomes `Action{tool:"git.push", target:"<host>/<owner>/<repo>:<ref>", params:{old,new,delete,force}}`. `force` is `false` only when Sekisho proves `old` is an ancestor of `new`: first by walking hash-verified commit parents in the pushed pack, then, where that history leaves the pack, by asking the upstream compare API about the boundary commits. Anything unproven is `force = true` (fail closed). All updates in one push must be allowed, or the whole push is rejected with a git error message that names the approval id.
- Git clients gzip large request bodies (`Content-Encoding: gzip`). Decompress before parsing the command list, and refuse any encoding other than identity or gzip. A push whose commands cannot be parsed is rejected, never forwarded.
- The pack data is streamed through unchanged after the decision.

## 8. HTTP surface

| Route | Who | Purpose |
|---|---|---|
| `GET /` and UI routes | humans | inbox, approval detail, audit, agents, grants, policy (read only in UI for v0.1) |
| `POST /login`, `POST /logout` | humans | password plus TOTP |
| `POST /approvals/{id}/approve`, `/deny` | approver | CSRF-protected forms |
| `POST /v1/check` | agents | decision API |
| `/mcp` | agents | MCP gateway |
| `/git/...` | agents | git proxy |
| `GET /healthz` | anyone | liveness only, no version or config |

Binds `127.0.0.1:7470` by default. Binding any other address requires TLS configured or `--insecure-bind` with a printed warning.

## 9. Storage

SQLite in WAL mode, one file. Migrations embedded and applied at startup. Tables: `users`, `sessions`, `agents`, `grants`, `grant_tombstones`, `approvals`, `budget_counters`, `audit`, `meta`. All writes for one logical change happen in one transaction with its audit entry.

## 10. Regression tests carried over from Substrate

These defects were found in the old platform. Each becomes a named test in Phase 1 or 2, written before the implementation it guards.

| Test name | Old defect |
|---|---|
| `budget_is_counted_server_side` | Ultra trusted `invocations_so_far` and `cost_so_far_cents` from the request body. |
| `approval_is_bound_to_digest` | Ultra envelopes stored only mission and action string. |
| `approval_is_single_use` | Nothing consumed a granted envelope. |
| `approval_expires` | Envelopes never expired. |
| `agent_cannot_approve` and `approver_is_not_requester` | One shared operator token, no self-approval check. |
| `revocation_is_durable_before_effect` | Ultra removed grants from memory even if the journal delete failed. |
| `audit_write_failure_refuses_action` | Ultra and Kizuna continued when audit or signing failed. |
| `audit_chain_detects_edit`, `..._detects_truncation_against_checkpoint`, `..._is_signed` | Ultra's chain was unkeyed and unanchored. |
| `approval_state_is_in_chain` | Ultra envelopes were not chained, so a row could be flipped to granted. |
| `deny_beats_grant` | Grant precedence was unclear. |
| `agent_id_comes_from_token` | Tenant and caller identity came from client headers. |
| `healthz_leaks_nothing` | Several services leaked version and licence state. |

## 11. Explicitly deferred (v0.2 and later)

Slack and phone approvals, passkeys, OIDC and SSO, multi-approver quorum, HTTP egress credential proxy for SaaS APIs, Codex and OpenHands integration guides, KMS and HSM signers, automatic checkpoint anchoring, delegated grants for sub-agents with the subset rule, Voxeltron integration (Sekisho decides, Voxeltron runs).

## 12. Limits that keep this repo small

- Under 25,000 lines of Rust at v0.1, measured by `scripts/loc.sh` in CI. Exceeding it fails CI until the architect raises it in this file with a reason.
- Design docs: this file plus one page per accepted change, in `docs/decisions/`. No evidence files in the repo; evidence is CI output.
- A task gets at most three fix rounds. Then it goes back to the architect, who rescopes it or decides.
