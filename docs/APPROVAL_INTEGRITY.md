# Approval integrity and persistent revocation

The invoke path was safe in isolation, but generic request creation could mint
its own verification with attacker-authored text, digest and expiry. Decisions
could also overwrite a newer consumption, and restart could undo revoked scopes.
These fixes cover the surrounding lifecycle rather than just the consume function.

## Issuance

`POST /v2/requests` and `POST /v2/admin/requests` accept informational kinds only:
`create-tool`, `create-automation`, `edit`, `delete`, `secret`, `warning`, `update`,
`suggestion`, and `info`. Other kinds fail with 422 (`ai_draft` remains retired,
410). Approval of an informational request cannot become an execution token.

Only the tool invoke and automation run paths call the verification issuer. They
supply ToolGate-authored text, validated exact arguments and the authenticated
caller. The issuer computes the binding, nonce and bounded expiry itself. It
inserts the request and its fingerprint into `v2_verification_origins` in the same
transaction as the creation event. The fingerprint covers immutable text, actor,
arguments, binding, expiry, and caller identity; only decision and consumption
state are excluded. Neither public request endpoint can write issuance provenance.

By default a request has no expiry (`expires_at: null`): it waits until the owner answers,
however long that takes. His approval opens a window in which the exact action may run once;
after that the approval is spent. The window is 15 minutes (`EXECUTION_WINDOW`) unless the owner
chose a shorter `run_window_minutes` (1-15, `/v2/owner/settings`; never longer). It is measured
from the recorded decision time, and the window in force at the decision is recorded beside it
(`decision.run_window_minutes`), both outside the fingerprint, so changing the setting never moves
an approval already given. A recorded window past 15 minutes or malformed makes the approval
unusable; one decided before the window was a setting has 15 minutes.
`default_confirmation_expiry_seconds` set to 15-900 bounds the wait instead, and such a request
cannot be approved once it has run out; its approval runs until that expiry, not the window.

Both decision and consumption verify this provenance. A forged or subsequently
altered verification cannot be authorized, even if the database contains an
otherwise plausible digest. The origin table is in the existing SQLite database
and therefore covered by the existing complete SQLite backup.

## Upgrade behavior

There is no trustworthy way to distinguish pre-fix legitimate verifications from
pre-fix forgeries. Startup cancels old pending and approved-but-unconsumed records
that lack intact issuance provenance, appending an invalidation event in the same
transaction. Original content and identifiers remain available in history. The
migration is idempotent; verifications issued by the new code remain valid.
Previously consumed history is retained and cannot be consumed again.

The owner must request fresh confirmation through the normal invoke/run path.
This is a deliberate compatibility break, not a silent migration of old authority.
Decision/consumption also reject old tokens before the startup migration runs.

## Transitions and races

Creation, decision, consumption and invalidation use `BEGIN IMMEDIATE`. Decisions
read the current status only after acquiring the writer lock. Generic `_put`
replacement of an existing request is forbidden. An approval decision therefore
cannot restore an earlier copy over a consumption. Competing owner/callback
choices return conflicts, and expired requests cannot be reported as newly approved.

Request creation, decision, consumption and invalidation commit their audit events
atomically. A failed audit insert rolls back the corresponding request transition.
The race drill pauses a real SQLite reader after it observes pending. The correct
implementation still holds the writer lock; the deliberately broken implementation
allows another decision and consumption before writing its stale copy. That mutant
is caught by a second consumption succeeding, not by a mock assertion.

An approval can still be consumed before a rate-limit denial, executor error or
crash. It is not refunded or retried automatically: once dispatch may have happened,
refunding can repeat an external action. Durable dispatch/reconciliation remains
separate work. Auxiliary callback telemetry is not the authoritative decision event.

## Withdrawing a request

A request with no expiry waits for the owner as long as it takes. When the chat that asked is
forgotten, nobody is waiting for the answer any more, so the agent that asked takes it back:

```text
POST /v2/agent/requests/{id}/withdraw
X-ToolGate-Execution-Key: <the key that invoked>
X-ToolGate-Agent: <the same agent, when the invocation presented one>
(no body)
```

- 200: the request as `GET /v2/agent/requests/{id}` shows it, now
  `{"status": "withdrawn", "decision": {"actor": <agent name>, "note": "Withdrawn by the agent
  that asked", "at": <time>}, ...}`. Withdrawing again gives the same answer and records nothing new.
- 404 `request not found`: no such request, a request another key or another agent of the same key
  made, an informational request, or one whose issuance is not intact. One answer for all, so a
  key learns nothing about requests that are not its own.
- 409 `REQUEST_NOT_PENDING`: the owner (or the system) already answered it; only a request still
  waiting for the owner can be withdrawn.

The caller must be exactly the actor that invoked (`created_by_agent_key`, the same check as
consumption), and the request must be an intact ToolGate-issued verification. The transition and
its `request_withdrawn` event commit together under the writer lock, like every other transition.
It is allowed in lockdown, because it only removes authority.

`withdrawn` is terminal. The owner channel no longer lists it, and its detail and decision routes
answer 404; the admin and callback decisions answer 409; an invocation that presents it as its
`approval_request_id` fails with `APPROVAL_INVALID`. The record and its events stay in history.

## Bootstrap and compose

Bootstrap inserts a key only when its hash does not exist. Repeated startup returns
the persisted record unchanged, including narrowed scopes and revoked status.
Concurrent first starts seed one identity. Missing scope configuration seeds an
empty scope list. Revoked rows remain as tombstones; an owner scope edit also leaves
a revoked key revoked. To restore access, explicitly issue a new execution key.

In `companion/docker-compose.yml`, replace the bootstrap scope line with:

```yaml
      TOOLGATE_BOOTSTRAP_SCOPES: ${PI_TOOLGATE_SCOPES:-}
```

This removes the wildcard fallback; an explicit deployment value still defines the
first-start seed. It does not narrow already-existing broad keys. Review those in
the owner interface. Do not delete revoked key rows to reset provisioning.
`companion/` was not edited by this patch.

## Verification

Run the suite with `python -m pytest toolgate/tests --ignore=toolgate/tests/test_module_contract.py -q`.
Run `python toolgate/scripts/mutation_check.py` to verify all ten deliberate defects
are caught. New cases cover generic approval forgery, late-decision resurrection,
and restart restoring authority. Additional tests cover callback races, malformed
legacy bindings, expiry, audit-write rollback, immutable issuance and concurrent
bootstrap. The drill mutates disposable source copies and first checks a passing
baseline.

Review evidence: 131 non-container tests and seven module-contract tests against a
live isolated Uvicorn server passed. All ten mutations were detected. New tests
and the mutation runner pass Ruff lint/format; existing modified modules introduce
no new lint findings. OpenAPI was regenerated. No Docker drill was run in this
session, and no other repository was modified.
