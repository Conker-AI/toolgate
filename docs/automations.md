# Automations

Typed JSON workflows built from tools and bounded control blocks: revisions, immutable publication, pinned execution and nested published automations.

## Automation Engine

### Definition revision compatibility

Tool and automation saves allocate `version` from the currently stored definition
under one SQLite writer transaction. A replacement increments that stored number;
the incoming `version` cannot reset or select it. Initial creation retains an
explicit positive initial version for existing import/bootstrap clients (default 1).
Legacy POST upserts retain their behavior, but also increment the stored version.

Owner clients can send `expected_version` with POST or PUT to require that exact
current version. A stale expectation returns HTTP 409 with
`detail.code = "DEFINITION_CONFLICT"` and `detail.current_version`, without changing
the definition or emitting its saved/updated event. PUT of a missing object remains
404; POST with an expectation but no existing object conflicts. Reload and review
the current definition before resubmitting a conflicted edit.

For compatibility, omitting `expected_version` remains an unconditional replacement
and does not protect against lost edits, although versions are still monotonic.
The existing dashboard remains in this compatibility mode until its later adapter
update. `version` is not a concurrency precondition. Existing live approvals continue
to bind the exact definition/version and fail closed after changes.

### Immutable definition history and publication

Owner-only `GET /v2/tools/{id}/versions` and the matching `/v2/automations/{id}/versions`
list saved revisions with publication state. `GET .../versions/{version}` returns the
saved definition; `?published=true` requires and returns an immutable publication
envelope. There is no fallback to the current version. History starts with the current
definition when this feature is installed; overwritten pre-upgrade definitions cannot
be reconstructed. Subsequent saves retain revisions atomically. Deleting a working
definition retains its history; recreating its ID allocates above retained versions.

`POST /v2/tools/{id}/publish` or `/v2/automations/{id}/publish` requires
`{"expected_version": 3}`. Publication requires an active, unblocked current definition
at that exact revision. It does not edit the draft, allocate a new revision, or execute
anything. Repeating a successful publication returns the same envelope without a
second event. Publications and revision history cannot be updated, deleted, or replaced.

An automation publication captures all referenced child-tool definitions under the
same writer transaction, including tools in inactive branches. Missing, inactive,
blocked, or incompatible dependencies fail publication. An optional `tool_version`
on a `tool_call` must match that tool's current version at publication; otherwise the
resolved current version is pinned in the envelope. Later tool changes never rewrite
the snapshot. Expanded workflows are limited to 500 blocks and four nested levels,
including nested automation calls and control-flow branches. Vault references
remain references; publication never resolves or copies vault credentials. Definition
fields still permit owner-authored literal configuration, so publications are not a
general secret scrubber: do not embed credentials in URLs, headers, arguments, or
other literal fields. Use supported vault-reference fields instead.

### Executing a published target

The existing agent routes `POST /v2/tools/{id}/invoke` and
`POST /v2/automations/{id}/run` accept `published_version`, a positive integer.
Include a stable `action_id`, exact `args`, and optional `job_id`. The requested
publication can also be guarded by `expected_publication_digest` (lowercase SHA-256).
It requires `published_version` and mismatches return `PUBLICATION_MISMATCH` before
approval creation/consumption or dispatch. Schedulers should persist and send both pins.
The requested
publication must exist: unavailable/revoked versions fail with
`PUBLICATION_UNAVAILABLE`, without falling back to a current draft. Omitting the
field deliberately retains legacy live-definition execution. A job integration must
persist and send the published version; ToolGate does not create or schedule jobs here.

Published workflows execute the saved workflow and pinned child definitions, even
after their working definitions are edited. Current agent scopes, lockdown, usage
limits and spending enforcement still apply. Every dispatch rechecks that the target
and children remain active, unblocked, and in the same definition lifetime. Any owner
authorization or policy change invalidates the publication for execution (even a
loosening); review and publish a new revision to resume. Deletion/recreation cannot
revive an old publication. Revocation prevents subsequent dispatches; it cannot undo
effects already dispatched.

The journal writer transaction also rechecks lockdown and the originating key's
current active state and required scope before every new root/child dispatch,
before consuming confirmation or reserving spending. Workflow children inherit the
required workflow scope: current child-tool scopes are never unioned with an old
workflow grant to keep a revoked workflow alive. A revocation between children stops
subsequent dispatches; already committed effects remain in the journal. Partial runs
are held for reconciliation instead of automatically restarting.

Owner confirmation binds the exact publication digest, arguments, originating agent,
version, and pinned child bindings. Dedicated owner review includes the publication
digest and child version/digest metadata, and rechecks current revocations before
approval. Published automation approvals are supported by this backend projection;
the separate gateway/frontend must explicitly support that shape before enabling its
review controls. Legacy live-automation review remains unavailable on that channel.

Execution receipts retain an immutable publication digest and definition version,
including uncertain outcomes. Reusing an action ID for another publication, or
switching between published and live execution, conflicts instead of dispatching.
Identical retries return the existing receipt; an unknown outcome never authorizes
redispatch. Existing journal records are upgraded additively and preserve their
original legacy invocation identity.

### Bounded nested published automations

`automation_call` requires literal `automation_id` and `published_version`, with an
optional exact `publication_digest` and an `args` object whose values can use the
existing expression references. Publication captures the referenced immutable
publication and its descendants, separately from other children: two nested calls
may intentionally pin different tool revisions without merging their tool maps.
Every branch resolves before publication. Missing publications, digest mismatches,
incompatible confirmation policy, repeated automation IDs along a dependency path
(including different revisions), and expanded depth/node overflows are rejected.

Nested calls run only through an explicitly published root. They receive isolated
variables, explicit validated arguments, and their own parent-linked journal receipt.
They share the root spending job and every ancestor's step/runtime ceilings; entering
a nested workflow never resets those ceilings. Current scopes must permit the root
and every captured nested automation, including inactive branches, and this
intersection is rechecked before each dispatch. Root confirmation binds all descendant
publication digests; an auto root cannot include a confirmation-required descendant.

Action identities derive deterministically from the parent action and bounded step
occurrence, so repeated loop calls have distinct paths. Uncertain nested outcomes hold
all ancestors and cannot be redispatched by a retry block. No new scheduler, background
worker, resumable continuation, or arbitrary-code executor is introduced.

Automations use a typed JSON workflow as their source of truth. The dashboard presents the same definition as a roadmap, layer map, draggable block editor, and editable code view.

Supported blocks are `tool_call`, `automation_call` (published roots only), `set`, `calculation`, `condition`, `switch`, bounded `loop`, bounded `retry`, `delay`, `notification`, and `return`. Expressions may reference `$args.<name>`, `$vars.<name>`, and `$last.<path>`. A tool's declared output is available as `$last.result.<output-name>` and its raw value remains available as `$last.result.result`. Nested depth, total steps, runtime, loop iterations, retry attempts, and delay duration are all capped.

## Confirmations and spending holds

Automation confirmations bind every referenced child definition and version, including nested branches. Changes before dispatch require fresh approval; accepted runs use the checked snapshot. Legacy automation approvals without child bindings are rejected.

Owners can release a verified no-execution hold using `POST /v2/spending/releases/{action_id}` with `confirmed_not_executed: true` and an evidence note. This changes local budget availability only; it never refunds a provider or permits redispatch. A late provider reply disputes the release, restores accounting, and freezes paid work.
