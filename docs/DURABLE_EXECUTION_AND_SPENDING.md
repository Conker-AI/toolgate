# Durable execution and spending

ToolGate records dispatch **before** calling an executor. Approval consumption,
that record, and any paid reservation commit in one SQLite transaction. An
external effect and its local receipt cannot share a transaction: this provides
at-most-once dispatch for a stable identity, not exactly-once effects at a provider.

## Caller contract

All outbound tools and all automations require `action_id`. Generate and persist
it in the caller **before the first request**; reuse it for transport retries,
approval resumption and status checks. Do not generate a fresh ID after a timeout.
The two local echo executors retain compatibility with callers without IDs.

```json
{"action_id":"turn-123-call-1","job_id":"job_from_owner","args":{},"approval_request_id":null}
```

The identity binds actor, subject, arguments, parent and job. Changing any of them
returns `ACTION_CONFLICT`; changing a tool version does not replace a recorded
result. Retries return the existing record without consuming approval, dispatching,
or charging again. Current authentication and scope checks still apply. A deleted
or disabled tool cannot be invoked to retrieve its old result; use the status API.

| Status | Meaning |
| --- | --- |
| `dispatching` / `IN_PROGRESS` | Dispatch was durably accepted; an outcome has not been recorded. |
| `completed` | A result was recorded; inspect its `code` for the result. |
| `outcome_unknown` / `OUTCOME_UNKNOWN` | Execution was interrupted or its outcome is ambiguous. Hold; never automatically redispatch. |

Startup changes unfinished dispatches to `outcome_unknown`. Executor exceptions
are conservative: even a timeout can follow a completed remote effect. A receipt
write failure also leaves the dispatch record intact. A missing record is not
proof that historical actions, from before this upgrade, never ran.

Owner: `GET /v2/actions` lists the newest 100 records. Originating execution key:
`GET /v2/agent/actions/{action_id}` returns its recorded status/result. Other keys
cannot read it. CLI: `toolgate action status <id> --json`. Invocation flags:
`--action-id <stable-id> [--job-id <owner-job>]`. MCP accepts the corresponding
fields inside its invocation envelope. Neither client retries automatically.

A workflow is recorded before its first step. Tool children get stable derived
IDs and inherit the parent's actor/job. Any uncertain child holds the workflow,
including inside a retry block. Restart does not resume partially executed
workflows. Records cannot be deleted, replaced, or have their identity rewritten;
completed receipts are immutable. Database administrators remain trusted.

## Owner spending configuration

Paid execution is disabled by default. All money values are **integer microUSD**
(1 USD = 1,000,000 microUSD). Price rates are microUSD **per million tokens**.
Only the admin key can configure these endpoints; execution keys cannot mint jobs,
change prices, raise caps or erase accounting:

1. `PUT /v2/spending/policy`: `enabled`, `cumulative_cap`, `max_job_cap`.
2. `PUT /v2/spending/prices/gemini-2.5-flash-lite`: `input_per_million`,
   `output_per_million`, `valid_until` (Unix seconds), `source` (HTTPS pricing URL).
   Supply known, nonzero prices expiring within 24 hours. There are no guessed
   prices or assumptions that a provider's free tier will cover a call.
3. `POST /v2/spending/jobs`: `actor_id` (execution-key ID), `root_action_id`, `cap`.
   Pass the returned `job_id` on that root invocation. A job cannot be reused by
   another actor/root, enlarged or reset. Server-created children share its ceiling.
4. `GET /v2/spending`: policy, total accounted-plus-reserved cost, and held cost.

The cumulative cap is lifetime accounting in this database, across all jobs and
keys. Toggling policy or issuing new jobs does not reset it. Raising its absolute
ceiling is an owner decision. Outstanding reservations count at full cost in both
ceilings. Transactions serialize competing reservations so concurrent calls cannot
both spend the same remainder.

The supported paid adapter is Gemini 2.5 Flash-Lite, text-only, one candidate,
thinking disabled, 1?20,000 prompt characters and 128?2,048 output tokens. It reserves
the full **1,048,576-token input window** plus the configured output bound at the
owner's recorded rates. This deliberately holds much more than most prompts cost;
it avoids an unverified character/token estimate or an extra token-count request.
The provider's published [model limits](https://ai.google.dev/gemini-api/docs/models/gemini-2.5-flash-lite)
and [thinking controls](https://ai.google.dev/gemini-api/docs/generate-content/thinking)
are the adapter contract, not dynamically discovered pricing. Check current
[provider prices](https://ai.google.dev/gemini-api/docs/pricing) when setting rates.

Known valid usage reconciles the reservation with the receipt, rounding upward to
microUSD. Missing, malformed or incomplete usage holds the full reservation even
when the tool returned a useful reply. Timeouts/crashes do likewise. A reported
input/output bound violation freezes paid dispatch and retains at least the
reservation. This cannot enforce a provider's own billing behavior or account for
requests made outside ToolGate; provider-side billing limits remain a separate
control. Discounted/cached usage is conservatively charged at the recorded rates.

## Deliberate limits and integration work

- Tavily and delegated MemoryGate `ask` are disabled: neither has a metered adapter
  here. Research can still use its free fallbacks. Gemini models other than the
  bounded adapter remain disabled, including previously registered models.
- Generic HTTP executors need an owner declaration `execution.billing =
  {"mode":"free"}`. Unknown/paid HTTP routes are blocked. Existing tools are not
  silently reclassified. This declaration is trusted owner configuration, not a
  claim supplied by the model. Local Ollama is assumed to be locally operated;
  routing that service through a paid proxy is outside this adapter contract.
- Pricing refresh and job creation are owner API operations; there is no dashboard
  editor or automatic pricing fetch in this patch. No real paid requests were used
  in tests. More economical token bounds need a verified tokenizer/counting path.
- Pi must persist/send action IDs and propagate job IDs. Its code and Companion
  were intentionally not edited. Callers without IDs now fail before outbound
  dispatch, rather than receiving a server-generated identity they could lose.
- Owners may release a local hold only after verifying the action did not execute:
  `POST /v2/spending/releases/{action_id}` with `confirmed_not_executed: true` and
  an `evidence` note describing the provider check. Only `outcome_unknown` actions
  with unresolved billing qualify. Identical repeats return the immutable receipt.
  The action remains non-retryable; no provider refund or successful reconciliation
  is claimed. A late provider reply disputes the release, restores conservative
  accounting (or known usage), and disables paid work. Stop active workers and
  verify the provider outcome before attesting; the server cannot verify that claim.
  Resolving a disputed release and reconciling nonzero owner-reported charges remain
  follow-up work. Never mint a replacement action to force a retry.
- Backup/restore must preserve all `v2_actions` and `v2_spend_*` tables. Restoring an
  old snapshot can omit later actions/costs; keep paid execution isolated until
  those are reconciled externally. This patch does not change Companion recovery.
- Existing rate limits remain separate from spending; this patch does not change
  B7/B8 policy or approval provenance. Retention/forgetting for execution arguments
  is also outside this patch.

## Verification

Run `python -m pytest toolgate/tests --ignore=toolgate/tests/test_module_contract.py`
and `python toolgate/scripts/mutation_check.py`. The drill modifies disposable
copies and requires the named behavior test to fail; collection errors do not count.
It covers durable dispatch, receipt replay, argument/actor binding, uncertain restart,
workflow retry holds, transactional approvals/reservations, caps shared by children,
concurrent jobs, missing usage, paid fallbacks, and provider bounds. Process-death
tests use an external effect file and `os._exit` before receipt recording.


## Scoped budget metadata for schedulers

`GET /v2/agent/spending/jobs/{job_id}` accepts an execution credential and returns
only `job_id`, `root_action_id`, and `cap` for that actor. Other actors and missing
records receive 404. It creates no grant and does not guarantee remaining credit:
the existing dispatch reservation enforces current policy, prices, root lineage
and cumulative/per-job ceilings. Pi can bind this existing authority to a held
scheduled run without receiving a ToolGate administrative key. Repeating schedules
still need separately authorized budgets for their distinct root actions.
