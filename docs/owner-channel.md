# Dedicated browser owner channel

ToolGate's browser gateway integration uses a dedicated credential, separate from
both `TOOLGATE_ADMIN_KEY` and every scoped execution key. It grants only bounded
verification-request reads and decisions. It grants no tool execution, vault,
configuration, spending or administration access.

Provision a fresh random credential of at least 32 characters through the host's
secret management. Supply the raw value only to the gateway as
`GATEWAY_TOOLGATE_OWNER_KEY`, and its lowercase SHA-256 hex digest to ToolGate as
`TOOLGATE_OWNER_KEY_SHA256`. ToolGate receives `X-ToolGate-Owner-Key` on these
server-to-server calls and compares its digest. Missing or malformed configuration
returns 503; absent/incorrect credentials return 401. Reusing an existing admin or
execution credential is rejected even if its digest was mistakenly configured.
No key is generated, returned or rotated by these HTTP routes. Host rotation
updates the pair and restarts the configured services; it does not undo decisions.

Neither `TOOLGATE_OWNER_KEY_SHA256` nor the reserved name `TOOLGATE_OWNER_KEY` is a
vault placeholder: provider-secret reads, writes, deletion and listing exclude
them. Do not store the raw owner credential in ToolGate's provider vault or send
it to a browser. The existing admin request routes remain host/operator interfaces;
there is no admin credential fallback in the owner channel.

## HTTP contract

All routes require the dedicated header:

- `GET /v2/owner/requests?limit=50&cursor=<request-id>` returns
  `{results: [...], next_cursor: null | string}`. Limit is 1–200. Only verification
  requests appear. Pagination orders immutable `(created_at, id)` descending;
  deciding an old request does not move it between pages. A 6 MiB projection budget
  may return fewer than `limit` records; always follow `next_cursor`.
- `GET /v2/owner/requests/{id}` returns the current projection below.
- `POST /v2/owner/requests/{id}/decision` accepts only
  `{status: "approved" | "rejected" | "dismissed", note?: string}`. Note is at most
  2,000 characters; unknown fields are rejected. Returns the current projection.

```text
id, kind: "verification", title, details, actor, severity, status,
created_at, updated_at,
decision: null | {status, actor, note, at},
action: {subject_type, subject_id, version, args},
approval: {expires_at, consumed_at, origin_valid},
reviewable: boolean,
unavailable_reason: null | "invalid_origin" | "invalid_action" |
  "arguments_unavailable" | "unsupported_subject" | "expired" |
  "consumed" | "already_decided"
```

Dates are timezone-aware ISO strings, or null when unavailable. Action identity,
version and args may be null for malformed/history-only records. Display labels
are bounded (title 500, details 2,000, actor 200, severity 32, decision note 2,000
characters). Arguments are the **complete** issued JSON object or null; they are
never silently truncated. Limits are 32 KiB UTF-8 JSON, depth 16 and 2,048 values
including object keys. Unsupported/malformed or oversized arguments make approval
unavailable. Numbers outside JavaScript's safe-integer magnitude are withheld so
browser JSON parsing cannot silently round the reviewed action. Treat all labels
and arguments as untrusted data, rendered as text.

The projection never returns the approval nonce, argument digest, originating
execution-key identity, arbitrary payload properties or any server credential.
Invalid immutable issuance also withholds arguments. `reviewable` permits approval
only for an intact, pending, unconsumed, unexpired **tool** request with a complete
valid action. Automation confirmations remain visible with `unsupported_subject`;
their workflow review is outside this increment. Reject/dismiss additionally work
for intact pending expired/unsupported-subject records with complete arguments.
They do not work on malformed or withheld action data.

Projection eligibility is checked inside the same `BEGIN IMMEDIATE` transaction
as the existing decision transition and audit event. A stale or modified origin
cannot become approved between the read and write. Decision actor is
`gateway-owner`. Existing immutable-origin verification, exact action/agent/version
binding and one-time consumption remain enforced when the execution channel later
invokes the tool. A decision does not invoke anything.

Historical expiry semantics remain unchanged: a pending record can be expired
without its stored status changing. `reviewable=false` and reason `expired` make
that explicit. Do not infer approval eligibility from `status` alone.

## Recovery and integration

There is no automatic retry. A request transitions from pending once; a duplicate
decision returns 409 with a static error and cannot restore a consumed approval.
After a missing acknowledgement, retain the exact request ID/status/note and GET
the detail. If still pending, that read alone does not prove the write was unsent;
only an explicit retry of the same decision is appropriate. Reconcile conflicts
by reading again. Never silently replace a pending decision with a different one.

The Pi gateway forwards list and detail reads at `/api/owner/requests...` and
requires its fresh operation-bound password proof on decisions. It never forwards
the browser cookie, password, CSRF or verification proof to ToolGate. Session
unlock and ToolGate approval are separate authority checks.

This channel does not cancel running actions, resume Pi turns, repair uncertain
external outcomes or provision spending jobs. Rejection does not itself update a
parked Pi turn. Resume remains a separate explicit operation. In particular, an
initial confirmation response lost before Pi saved its request ID cannot yet be
rediscovered by action ID; the execution journal is allocated after confirmation.
Do not present that case as safely retriable execution.

Run `python -m pytest toolgate/tests/test_owner_channel.py` together with the
approval-boundary, integrity, execution-journal and vault regression tests. Tests
use isolated databases and in-process requests; no network service is required.
