# Recurring spending allowances

The owner creates a finite allowance with `POST /v2/spending/allowances`
(admin key). It binds one actor to an exact target: kind, id, publishedVersion,
digest and arguments. Required limits are per_run_cap, total_cap, max_runs and
expires_at. Money uses integer microdollars. Inspect via GET on the allowance ID;
revoke with POST on its `/revoke` endpoint. These operations do not execute tools.

The scoped execution key allocates a budget using
`POST /v2/agent/spending/allowances/{id}/allocate`, with target and root_action_id.
Use the scheduler's durable run ID. Retrying the same root returns the original
budget; it never creates another. Every allocation permanently consumes its full
ceiling and one run, even if unused. Revocation/expiry blocks new reservations,
including children of allocated runs; already dispatched work is not cancelled.
The reservation transaction verifies the actual execution root against the grant.
Existing execution permissions and approval requirements still apply.

This extends the existing bounded paid adapter only; it does not enable arbitrary
paid providers. Pricing expiry and cumulative policy limits remain mandatory.
No live provider was called during verification. Allowances do not replenish or
refund themselves. Changing a published target or its arguments requires a new
owner allowance. A replay may recover a budget ID after revocation, but that ID
cannot authorize new spending.
