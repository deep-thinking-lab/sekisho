# Security

This page describes the security boundaries of the developer preview and the deployment checks that matter before you expose Sekisho to a network.

**Status:** Developer preview (v0.1). Expect rough edges; the audit format and policy schema may change before v1.

## Threat model

Sekisho is designed for an agent that can make mistakes or be prompt-injected. The agent gets a Sekisho token instead of standing GitHub or upstream credentials. Sekisho checks each action through `sekisho_core::decide`, holds sensitive actions for a human, and records the result in a signed audit chain.

The preview protects against:

- An agent pushing or deleting a git ref without an allow rule or a consumed approval.
- An agent choosing its own identity, grant use count or budget count.
- An agent using a grant after it expires, is exhausted or is revoked.
- A request changing its action after approval and reusing the approval.
- An audit row being edited or an earlier row being removed without breaking the chain.
- A removed tail being detected against a trusted checkpoint you kept outside the export.

Sekisho does not protect against:

- An agent that runs as the same OS user as Sekisho and has any unapproved way to run commands, such as an allowed Bash rule. That agent can read the Sekisho home, including upstream tokens, the grant key and `admin.token`. See [Run Sekisho as a separate OS user](#run-sekisho-as-a-separate-os-user).
- A compromised host, kernel, database file or Sekisho binary.
- An operator who can read the signing keys and rewrite the host state.
- An approver who knowingly approves a harmful action.
- A compromised upstream provider or remote repository.
- A leaked agent token before it is rotated.

The audit trail proves consistency and signature validity. It does not make an unsafe policy safe.

## Use HTTPS for remote browser access

The browser login uses a password and TOTP. Sign-in limits work per 15-minute window:

- Every failed sign-in gets the same HTTP 401 and body, whatever the limits below say, so a response never reveals whether the password was right or whether the account is throttled or locked.
- Failed sign-ins are counted per client address (IPv6 per /64), whatever was wrong. After 20, failures from that address are answered one second later. This slows an address down; it does not refuse a correct password with a correct TOTP code, and it never locks an account.
- After five failed sign-ins for a user, that user is soft throttled. Every attempt is still checked in full, and it succeeds only with the correct password and a correct TOTP code. An attacker without the password cannot lock an approver out.
- Ten wrong TOTP codes after a correct password lock the user for the rest of the window. Only someone who knows the password can cause this, and the lock is only considered once the password has verified.
- Past 1000 failed sign-ins across all users, each further failure is answered one second later. Successful sign-ins are not slowed.

Behind a reverse proxy, every request comes from the proxy's address. List the proxy in `config.toml` so Sekisho limits by the client address the proxy reports in `X-Forwarded-For`:

```toml
trusted_proxies = ["10.0.0.5"]
```

Sekisho uses the rightmost `X-Forwarded-For` address that is not a trusted proxy. Do not list an address that untrusted clients can connect from. If requests carry `X-Forwarded-For` while `trusted_proxies` is empty, Sekisho logs a warning and skips per-address limits, rather than treating the proxy as one client.

Session cookies are `HttpOnly` and `SameSite=Strict`. Sekisho adds `Secure` when it is bound to an address that is not loopback.

Plain HTTP is acceptable only when the browser and Sekisho are on the same loopback interface. For remote access, terminate TLS in front of Sekisho and make sure Sekisho sees a non-loopback bind address. This example uses `10.0.0.5` as the host's private address:

```sh
sekisho up --bind 10.0.0.5:7470 --insecure-bind
```

`--insecure-bind` disables Sekisho's own TLS guard because TLS is terminated by the reverse proxy. Do not expose port 7470 to the internet. Restrict the port to the proxy with a firewall or a private network.

Example Caddy configuration:

```caddyfile
sekisho.example.com {
	reverse_proxy 10.0.0.5:7470
}
```

Sekisho must bind off loopback, so session cookies carry `Secure`, and the firewall must allow only Caddy to reach the private address. Restrict port 7470 to the proxy. Do not bind `0.0.0.0` behind a proxy unless a firewall blocks every path except Caddy.

Do not place Sekisho behind a TLS proxy while leaving it bound to `127.0.0.1` if the browser is remote. That setup can still carry the cookie over HTTPS, but Sekisho cannot mark the cookie `Secure`, so an accidental plain HTTP request may expose it.

## Home directory permissions

Sekisho stores its SQLite database, policy, configuration, signing keys and local admin files under `~/.sekisho` by default.

The home and `keys` directory must not have permissions wider than `0700`. Files must not have permissions wider than `0600`. Sekisho refuses to start when either rule is broken.

Check the home:

```sh
stat -c '%a %n' "$HOME/.sekisho" "$HOME/.sekisho/keys"
```

On macOS, use:

```sh
stat -f '%Lp %N' "$HOME/.sekisho" "$HOME/.sekisho/keys"
```

The mode should start with `700`.

Check the sensitive files:

```sh
find "$HOME/.sekisho" -type f -exec stat -c '%a %n' {} \;
```

Every file should have mode `600`. Upstream credentials must be regular files with mode `600`.

On macOS, use:

```sh
find "$HOME/.sekisho" -type f -exec stat -f '%Lp %N' {} \;
```

Back up the private directory as a secret. The audit signing key, grant signing key and database are sensitive.

## Run Sekisho as a separate OS user

The Sekisho home holds the upstream tokens, the audit and grant signing keys, the database and `admin.token`. Sekisho keeps them from agents only if agents cannot read the home.

Run `sekisho up` as a dedicated OS user, such as `sekisho`, and run the agent as your own user. Give the agent its token through `SEKISHO_TOKEN`. The agent then cannot read the home, mint grants with `sekisho grant add`, or edit the policy.

If you run the agent as the same user, for example while you try the quickstart, Sekisho limits the damage but cannot remove it:

- Every hook action whose target is inside the home is denied by a built-in rule that no policy or grant can override.
- The hook refuses Bash commands that name the home. This is a text check, so a command that builds the path at run time gets past it.
- Every local admin route that changes state also needs the admin's TOTP code: `POST /admin/policy/reload`, `POST /admin/approvals/<id>/approve` and `POST /admin/approvals/<id>/deny`. Each code is used once, in the same transaction as the change. Only `GET /admin/approvals` works with the token alone. The CLI reads codes from a terminal prompt or stdin, never from arguments.
- Sekisho refuses a policy file that is a symlink, is not owned by Sekisho's user, or is writable by group or others, and one in a directory that is not owned by Sekisho's user or is writable by group or others. The checks run on the open file, so swapping the file during the load is refused.
- `sekisho grant add`, `sekisho policy reload` and anything else that reads the home directly still work for anything that can run commands as that user. Do not allow Bash or other command tools without approval in that setup.

## Agent tokens and upstream secrets

An agent token is shown once when you add or rotate an agent. Sekisho stores only its SHA-256 hash. Treat the token as a password and keep it out of shell history, source control and logs.

Use `sekisho agent rotate <name>` when a token may have leaked. The old token stops authenticating after rotation.

Upstream credentials stay in files under the Sekisho home. Sekisho uses them for requests to the remote and never returns them in a decision, approval or audit subject.

## Report a vulnerability

Send reports to `security@sekisho.sh`.
