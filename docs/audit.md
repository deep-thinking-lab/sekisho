# Audit trail

Sekisho writes a signed, hash-chained audit trail to SQLite. You can export the trail as JSONL and verify it offline without the Sekisho server or database.

**Status:** Developer preview (v0.2). Expect rough edges; the audit format and policy schema may change before v1.

## What Sekisho records

Every state change writes an audit entry in the same database transaction as the change. If the audit write fails, the transaction rolls back and Sekisho refuses the change.

An entry contains:

- `seq`, a gapless sequence number that starts at zero.
- `at`, the Unix timestamp.
- `kind`, the event type.
- `actor`, the principal that caused the event.
- `subject`, event details such as an action digest, approval ID, grant ID or policy SHA-256.
- `prev_hash`, the previous entry hash.
- `entry_hash`, the hash of this entry.
- `key_id`, the audit signing key identifier.
- `signature`, the Ed25519 signature.

The event kinds are:

- `ActionRequested`
- `Decided`
- `ApprovalRequested`
- `Approved`
- `Denied`
- `Expired`
- `Consumed`
- `GrantIssued`
- `GrantRevoked`
- `PolicyLoaded`
- `UserLogin`
- `AgentAdded`
- `KeyRotated`
- `AnchorSent`
- `AnchorFailed`
- `NotifySent`
- `NotifyFailed`

Action requests and decisions include the action digest. Approval events include the approval ID and action digest. Grant events include the grant ID and issuing user. Policy load events include the policy file SHA-256. Notification events include the channel, attempt, and status or error class.

The first entry uses 32 zero bytes as `prev_hash`. Each later entry includes the previous entry hash. Verification also checks that sequence numbers have no gaps and that timestamps do not move backwards.

## Export the trail

Export all entries to `audit.jsonl`:

```sh
sekisho audit export --out audit.jsonl
```

Start from the beginning of an available range:

```sh
sekisho audit export --out audit-from-zero.jsonl --from 0
```

The JSONL file contains one audit entry per line and a final JSON trailer. The trailer contains a signed checkpoint, the public keys embedded in the export, and any verified prefix required by the requested range.

The command prints the external public key to standard error:

```text
--pubkey audit=BASE64_PUBLIC_KEY
```

Record the value after `--pubkey` separately from the export. The value has the form `KEYID=BASE64`.

## Verify offline

Verify an export on a machine that has the Sekisho binary but no server or database:

```sh
sekisho audit verify audit.jsonl --pubkey 'audit=BASE64_PUBLIC_KEY'
```

For more than one trusted key, pass `--pubkey` more than once. You can also store keys in a file with one `KEYID BASE64` pair per line and pass it with `--pubkey-file`:

```sh
sekisho audit verify audit.jsonl --pubkey-file audit-keys.txt
```

A valid authenticated export prints a line that starts with `valid:`:

```text
valid: entries=42 first_seq=0 last_seq=41 time_range=...:.. keys=audit
```

The exact entry count, sequence range and timestamps depend on the export.

## Exit codes

`sekisho audit verify` uses these exit codes:

| Code | Meaning |
| --- | --- |
| 0 | The chain, checkpoint and signatures are valid, and the signatures were checked with an external key |
| 1 | The export is invalid, missing, unreadable, or contains a bad hash, signature, sequence or checkpoint |
| 2 | The command line or public key file has invalid usage |
| 3 | The chain and signatures are valid against embedded keys only, so the export is unauthenticated |

## Why you must supply the external key

The export contains the public keys needed to check its own signatures. An attacker who can replace the export can also replace those embedded keys.

Passing `--pubkey` or `--pubkey-file` makes the verifier use a key you kept outside the export. The signature then shows that the entry came from the holder of the matching private audit key.

Without an external key, the verifier can still detect accidental edits and internal inconsistencies. It cannot authenticate the signing key. That is why a valid embedded-only result returns `UNAUTHENTICATED` and exit code 3.

Keep a copy of the external public key and the latest trusted export outside the Sekisho host. The signed checkpoint in that export lets you detect truncation against a newer export.

## Anchor checkpoints automatically

Sekisho can send the latest signed checkpoint to a webhook. Add an `[anchor]` table to `config.toml`:

```toml
[anchor]
webhook_url = "https://audit.example.com/sekisho"
token_file = "anchor.token"
interval_seconds = 3600
every_entries = 1000
```

| Key | Required | Meaning |
| --- | --- | --- |
| `webhook_url` | Yes | Destination for checkpoint JSON. Sekisho requires `https`, or `http` to a loopback host. |
| `token_file` | No | File containing a bearer token. Sekisho sends the token in the `Authorization` header. A relative path is resolved against the Sekisho home. The file must be regular and no wider than mode `0600`. |
| `interval_seconds` | No | Maximum time between anchors. The default is `3600`, and the minimum is `60`. |
| `every_entries` | No | Maximum number of new audit entries between anchors. The default is `1000`, and the minimum is `1`. |

Sekisho sends a checkpoint when either threshold is reached. The request body is the same signed checkpoint format used in an export trailer. The request has the content type `sekisho-checkpoint`, and Sekisho does not follow redirects.

The anchor runs in a background task. A slow or unavailable webhook does not block audit writes. Sekisho retries failed requests with exponential backoff.

Each attempt adds an audit entry. `AnchorSent` records a successful HTTP status. `AnchorFailed` records an error class and the HTTP status when one is available. Checkpoints and retry state are derived from the signed audit chain, so they survive a server restart.

## Verify against a saved anchor

Save the JSON checkpoint received by your webhook. You can verify a full audit chain, a JSONL chain with no export trailer, or an export against that saved checkpoint:

```sh
sekisho audit verify audit.jsonl --against-checkpoint anchor.json --pubkey 'audit=BASE64_PUBLIC_KEY'
```

The saved checkpoint can be newer than the file under test. Verification fails when the file ends before the checkpoint, when the checkpoint entry is missing, or when the hash or signature does not match. A suffix export is accepted only when the saved checkpoint falls inside the range covered by its start checkpoint and exported entries.

The external key rules still apply. Use `--pubkey` or `--pubkey-file` so the saved checkpoint and chain signatures are checked against a trust anchor kept outside the export. A valid result checked only with embedded keys returns exit code 3.
