# Approval notifications

Sekisho can send a message when an action is waiting for approval. Notifications are best effort. They are queued only after the approval transaction commits, so a slow or unavailable webhook cannot delay or fail the approval. A process crash after the commit can still lose a pending notification.

Notifications and Slack approvals are included in the free Community edition. Add `[[notify]]` entries to `~/.sekisho/config.toml`, then restart the server.

A webhook receives approval metadata and the full approval link:

```toml
[[notify]]
type = "webhook"
url = "https://approvals.example.com/sekisho"
token_file = "notify/token"
```

The URL must use HTTPS unless it points to a loopback host. `token_file` is optional and sends its contents as a bearer token. The token file must be a regular file with permissions no wider than `0600`.

The default webhook body contains `approval_id`, `agent_id`, `tool`, `target`, `rule`, `expires_at`, and `url`. Action parameters may contain secrets, so they are excluded by default. Set `include_params = true` only for a trusted destination:

```toml
[[notify]]
type = "webhook"
url = "https://trusted.example.com/sekisho"
include_params = true
```

For Slack, store an incoming webhook URL in a `0600` file outside `config.toml`:

```toml
[[notify]]
type = "slack"
webhook_url_file = "notify/slack-url"
```

Slack receives a short message with the agent, tool, target, and approval link. It never receives action parameters.

To add Approve and Deny buttons, enable interactivity in the same Slack app that owns the incoming webhook. Set its Interactivity Request URL to your public Sekisho URL followed by `/integrations/slack/actions`. Slack must be able to reach that URL.

Store the app's signing secret in a separate regular file with permissions no wider than `0600`. Map Slack user ids to existing Sekisho user ids:

```toml
[[notify]]
type = "slack"
webhook_url_file = "notify/slack-url"
interactive = true
signing_secret_file = "notify/slack-signing-secret"
slack_users = { "U012ABC" = "alice" }
```

Interactivity requires `interactive = true`, a signing secret, and a nonempty user mapping. Entries for the same Slack app must use the same user mapping and TOTP setting. Conflicting settings for one signing secret fail startup. The endpoint accepts only Slack-signed requests within five minutes of the server clock. Cookies and bearer tokens cannot authenticate this route. Mapped users must still have the Sekisho Approver role or Admin role. Existing self-approval rules still apply.

By default, `slack_requires_totp = true`. Buttons reply privately with a link to the web approval page, where the user signs in with TOTP. To let an Approve button decide immediately, set both `slack_requires_totp = false` and `include_params = true` on the Slack entry, so the approver sees the parameters they approve. With `slack_requires_totp = false` alone, Deny decides immediately but Approve still replies with the web link. One-click approval explicitly trusts the mapped Slack identity instead of requiring a Sekisho TOTP check for each Slack approval. Protect Slack accounts accordingly.

Immediate approvals and denials use the web inbox's database transaction and core transitions. Their audit records identify the mapped Sekisho user and include `channel = "slack"`. Approval consumption remains single use. Sekisho acknowledges verified button clicks before database work, then posts the result through Slack. After a successful decision, Sekisho replaces the original Slack message with the outcome and removes the buttons. Refusals appear only to the user who clicked. Replies use Slack's signed `response_url` and must share the configured incoming webhook's origin. Message updates are best effort and retry up to three times. They can be lost if the process stops after the decision commits.

### Slack app setup

1. Create a Slack app and enable Incoming Webhooks. Add a webhook to the channel that should receive requests and save its URL in a `0600` file (`webhook_url_file`).
2. For buttons, enable Interactivity. Set the Interactivity Request URL to `<public_url>/integrations/slack/actions`, where `public_url` is your Sekisho public URL. Slack must be able to reach it.
3. Copy the app's Signing Secret from Basic Information into a separate `0600` file (`signing_secret_file`).
4. Find each approver's Slack member id and map it to their Sekisho user id in `slack_users`.
5. Set `interactive = true`, then restart the server.

### Configuration reference

| Key | Applies to | Default | Meaning |
|-----|------------|---------|---------|
| `type` | all | required | `webhook` or `slack` |
| `url` | webhook | required | HTTPS unless loopback |
| `token_file` | webhook | none | Bearer token, regular file, `0600` or tighter |
| `webhook_url_file` | slack | required | Incoming webhook URL, `0600` or tighter |
| `interactive` | slack | `false` | Add Approve and Deny buttons |
| `signing_secret_file` | slack | none | Required when interactive |
| `slack_users` | slack | empty | Slack user id to Sekisho user id, required nonempty when interactive |
| `slack_requires_totp` | slack | `true` | See the trade-off below |
| `include_params` | webhook, interactive slack | `false` | Send action parameters. For Slack, shown with secrets redacted, and required for one-click approval; see below |

### Security trade-off of `slack_requires_totp = false`

With the default `true`, a button click never decides. It replies privately with a link to the web approval page, where the approver signs in with TOTP. With `false`, a verified click from a mapped Slack user approves or denies immediately, with no Sekisho TOTP check. Anyone who controls that Slack account, or a session on it, can approve. Use `false` only if you trust your Slack identity controls.

A Slack button can approve only when the approver can see what they approve there. That needs both `slack_requires_totp = false` and `include_params = true` on the Slack entry. With both, the message shows the action's canonical parameters and its action digest. Before posting, Sekisho redacts obvious secrets: `Bearer` tokens, GitHub (`ghp_`, `github_pat_` and similar), AWS (`AKIA`, `ASIA`) and Slack token prefixes, and the value of any `key=value` or `key: value` whose key looks like a secret. A key matches if it contains `token`, `password`, `passwd`, `secret`, `credential`, `apikey`, `privatekey`, `auth`, `cookie` or `session` anywhere, ignoring case and `_`, `-` and `.` (so `accessToken`, `DB_PASSWORD` and `x.auth.header` match), or has `key` as a whole word (`api_key`, `privateKey`, but not `monkey`). Matching errs broad. Redaction is best effort. If anything was redacted, the approver is not seeing exactly what they approve, so a button cannot approve that action and the message points to the web inbox. Parameters are still posted to Slack, a third party, so turn this on only if that is acceptable.

Without `include_params = true`, the message shows the action digest, tool and target, and asks the approver to open the web inbox. An Approve click then replies privately with the approval link. Deny still works from Slack.

Even with both settings, these actions need the web inbox with TOTP to approve: Bash commands, ref deletions, pushes whose `force` is not `false`, and actions whose parameters are longer than 1500 characters.

### Retries and audit

Each channel retries a failed delivery with backoff for at most three attempts. Successful sends are recorded as `NotifySent`. Failures are recorded as `NotifyFailed` with an error class, limited to one failure record per channel per minute. Webhook and Slack secrets are never written to the audit trail or logs.
