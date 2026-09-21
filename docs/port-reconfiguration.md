# Port reconfiguration contract

Docker Engine v1.45 defines `PortBindings` in HostConfig used by container create.
Container update accepts resource limits and restart policy, not published ports.
Therefore the existing dashboard's create/edit/remove mapping actions need a
reviewed replacement sequence, not an invented in-place update call.

Source: [Docker Engine v1.45 OpenAPI specification](https://docs.docker.com/reference/api/engine/version/v1.45.yaml),
`/containers/create`, `/containers/{id}/update`, and HostConfig/PortMap.

`toolgate.executors.port_plan.plan` is the pure change-preview component. It
accepts a full container ID, current normalized bindings and one create/edit/remove
operation. New bindings match the accepted editor: IPv4 loopback/all interfaces,
explicit ports 1–65535, TCP/UDP. Existing IPv6 bindings are preserved. Original
mapping edits/removals require an exact match. Unrelated mappings remain intact.
Wildcard conflicts are conservative; protocol-specific reuse is preserved.

The result includes exact before/after, changed/replacement/downtime flags and a
canonical digest of the original binding set. This digest detects binding changes
only: it is not a complete frozen container configuration or execution approval.
No host-port availability is claimed. Plans explicitly report execution not
implemented. Host/container network mode, automatic publishing and auto-remove
containers require a separate supported strategy rather than destructive guessing.

Remaining execution work:

1. Read actual configured-daemon container identity and bindings under scope.
2. Prepare and retain the full replacement specification privately; account for
   mounts, named/anonymous volumes, networks/aliases, restart policy and writable
   layer data. Never expose environment/credentials in the change preview.
3. Bind exact review to container identity and frozen configuration; verify current
   authority and reject stale configuration before effects.
4. Journal each replacement step before dispatch. Preserve the original container
   until verified replacement/recovery decisions; unknown outcomes never authorize
   automatic reruns. Report interruption, conflicts and downtime honestly.
5. Expose the operation through Pi and test independently before final UI wiring.

The pure planner's tests do not prove that replacement works. No Docker daemon,
container, publication or network was changed by this increment.

## Inspected preview adapter

`port_preview.preview` now reads the full allowlisted container ID through the
existing configured Docker Unix-socket transport. It uses one fixed GET, the
existing byte/deadline limits, no redirects and a configuration recheck. This is
an internal adapter; scoped endpoint/executor registration remains to be added.

Running containers use observed runtime publications, including assigned host
ports and IPv6. Stopped containers use concrete configured publications; unresolved
allocation requests cannot yet be frozen. Declared bindings missing from runtime
data, unsupported protocols and transitional states reject the preview rather
than silently changing its meaning. No environment, mounts or raw inspection
document is returned. The response still explicitly says execution is unimplemented.

70 focused preview/planner/lifecycle tests passed with synthetic HTTP, including
configuration revocation, duplicate JSON keys, oversized replies and no retries.
This does not verify Docker replacement, retention or real daemon behavior.

## Private replacement specification

`port_spec.prepare` constructs an internal create payload from the private inspect
document and exact mapping delta. ContainerConfig fields, resource/restart settings,
bind declarations, volume options and configured network aliases/IPAM are retained.
Anonymous volumes are resolved to their existing names rather than recreated empty.
Observed and declared volume identities must agree. External container namespace
dependencies, VolumesFrom and external container-ID files require a separate path.
Unsupported configurations fail before effects; they are not silently simplified.

The internal object hides its payload in repr and returns a separate public preview.
Its configuration fingerprint stays private and detects reviewed-config changes;
it does not bind writable file contents or authorize execution. The future executor
must recheck scope and source state, stop the source, commit its writable layer,
and pass the resulting immutable image ID to `create_body`. The original image tag
is deliberately insufficient. [Docker commit](https://docs.docker.com/reference/cli/docker/container/commit/)
does not include mounted volumes; those are reused separately. Tmpfs reset is
explicit in the preview. Volumes remain live shared storage, not snapshot backups.

67 specification/preview/planner tests pass on synthetic documents and HTTP.
Payload construction alone does not prove replacement fidelity on a real daemon.
Durable private storage, step journaling, network detach/reattach, rollback/unknown
reconciliation and managed replacement identity remain executor work. No raw
configuration should be included in public receipts, logs or API responses.

## Durable private payload and step records

`core.port_replacements` adds private payload/step tables beneath the existing
`v2_actions` identity. It requires an active `system.port-control` parent and the
same target container. Payload encryption reuses the existing vault key and salt;
the encrypted envelope binds the action and its fingerprint. Wrong-key,
cleartext and cross-action payload reads fail. Deployment backup must retain the
vault key/salt separately; losing them makes private recovery data unreadable.

Step claims commit before dispatch and require an authorization callback. Concurrent
or repeated claims never authorize another effect. Only ordered, observed previous
steps allow the next claim. Parent startup recovery blocks continuation and makes
unfinished steps read as outcome-unknown. Late observations improve evidence but
do not reopen the parent. Public step references accept only image/container IDs,
not arbitrary diagnostics. Payloads and completed observations have SQL immutability
guards. This is internal storage, not a new externally accessible owner API.

44 payload/journal/specification tests passed against temporary SQLite and the real
vault cipher with synthetic keys. Existing FastAPI/Starlette deprecation warnings
remain. The actual executor must enforce its planned step sequence, perform scope
checks, and use claims correctly; storage tests do not prove that integration.
No automatic rollback/retry or Docker effect is implemented by these records.

## Internal replacement executor

`executors.port_control.execute` now consumes a saved private specification and
uses the configured Unix-socket Docker adapter. Before effects it reinspects source
configuration and running state. It journals stop, writable-layer commit, retirement
of the original restart policy, rename, network disconnect, replacement create,
optional start and verification. The original container and snapshot image remain
for recovery. The replacement keeps the original restart policy. Full reviewed
network IDs address disconnect calls. Verification checks image, running state,
port bindings, mount identities and network IDs/aliases. Stopped sources produce
stopped replacements. It never deletes either container or shared volume data.

An authorization callback and configured-target recheck run before each claim.
Unknown replies halt the sequence; no automatic retry/rollback follows. A repeated
executor call with existing steps cannot dispatch. This adapter is not registered
as a callable tool yet: exact review admission, retained-container recovery and
managed-target lineage still require integration. Verification is an observation,
not an application health check or a complete equivalence proof for every Docker
option. Named network creation can race with operator changes; mismatched network
identity fails verification and requires review. Snapshot storage and retained
resources need owner-directed cleanup after recovery decisions.

52 executor/private-journal/lifecycle tests passed using a simulated Docker daemon
with real temporary SQLite/encryption. Coverage includes create/edit/remove,
running/stopped preservation, every mutation reply lost, revocation between steps,
stale source and wrong port/network observations. Scoped lint passes. No actual
Docker daemon was contacted; Linux deployment fidelity remains unverified.

## Exact review admission

`core.port_reviews` stores a five-minute, actor-bound snapshot of the exact prepared
change. A random review ID references an encrypted private payload and a separate
public mapping preview. Preview creation does not approve or run the change.
Review identity/expiry/content are immutable. Cross-actor lookup fails; expiry,
wrong keys, reused reviews and target mismatches prevent admission.

`consume_in_transaction` is intended for the existing execution journal's reserve
callback, after normal owner verification and parent insertion. It atomically
claims the review and attaches the private replacement payload to that action.
Failure rolls back both claims; concurrent action IDs cannot consume one review.
The executor still reinspects source configuration before effects. A consumed
review is never reused to recover an uncertain operation.

18 focused review/private-record tests passed using temporary SQLite and real
encryption. These internal helpers are not yet connected to scoped HTTP routes
or the callable tool; ordinary approval integration is still required. Expired
encrypted reviews are retained by this initial journal schema; lifecycle/retention
policy must be reconciled with the broader recovery work before completion.

## ToolGate API integration

The previous internal-only limitation is superseded: scoped
`POST /v2/agent/system/port-reviews` now inspects and stores an exact review;
`GET /v2/agent/system/port-reviews/{id}` returns its originating actor's public
preview with no-store headers. Both require active `system.port-control` scope and
policy. This permission does not provision a Docker target or alter existing scopes.

Invoke the reserved `system.port-control` tool with `container_id`, `review_id`
and a stable action ID. Existing owner confirmation displays the actual mapping
preview. Approval consumption, review consumption and private action payload
attachment share the journal transaction. The executor rechecks live authority and
published-definition availability per step. Reserved definition/dispatch guards
prevent removing confirmation or substituting another executor. Inherited workflow
approval is intentionally insufficient: this path requires direct exact approval.
Receipt replay uses the existing journal and never repeats a replacement.

67 boundary/executor/review/journal/publication/container-boundary checks passed;
the seven new boundary checks were rerun after the final preview-state correction.
All transport is simulated; real vault encryption uses synthetic keys/temporary
storage. Existing deprecation warnings remain. No frontend wiring or deployment.
Pi transport, retained-container recovery, replacement-target lineage and the
real-Docker verification/retention work remain incomplete.

## Managed replacement lineage

Verified replacement IDs are recorded privately against the action, source and
configured socket identity. Only a completed successful parent receipt activates
the relationship. Target discovery follows replacement chains from the current
operator allowlist and exposes the current leaf; retained ancestors are excluded.
Removing an allowed root revokes its derived descendants unless the operator
explicitly allows them separately. Changing socket configuration does not inherit
another socket's replacement IDs. The digest binds the socket path, not a daemon
cryptographic identity; operator control of that endpoint remains required.

Pending/unknown replacement sources are omitted from ordinary target discovery and
refused by lifecycle control. Distinct reviews cannot concurrently admit another
replacement for the same source. Uncertain operations require recovery instead of
automatic lease expiry. A new container from an uncertain parent is not granted
ordinary management authority just because its creation ID was observed.

63 lineage/lifecycle/executor/boundary/review checks pass with temporary SQLite,
synthetic vault keys and simulated Docker. Existing warnings remain. Scope checks
and host effects are not a cross-process atomic transaction: competing ordinary
lifecycle operations still need shared target admission to close their final
check-to-dispatch race. Recovery and real-Docker verification remain open.
