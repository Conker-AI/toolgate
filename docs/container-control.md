# Managed container lifecycle adapter

`toolgate.executors.container_control.control(container_id, action, *, transport=None)`
implements one start, stop, or restart of an explicitly managed container. It is not
a generic Docker client or a script runner. The caller must authorize and durably
journal the action before dispatch. The adapter does not retry.

Operator configuration (no defaults):

- `TOOLGATE_DOCKER_SOCKET`: absolute Unix-domain socket path.
- `TOOLGATE_MANAGED_CONTAINER_IDS`: JSON array of full lowercase 64-hex container IDs.

The fixed Docker Engine v1.45 endpoints inspect the exact ID, POST its lifecycle
action, then inspect again. Stop/restart use a ten-second graceful-stop timeout.
Configuration and current membership are checked again immediately before POST.
An environment change cannot cancel an already dispatched action. Container
replacement with a different ID requires explicit operator authorization.
The socket path is not a daemon identity: replacing a daemon behind the same path
is not detected and does not itself invalidate approvals. Deployment must prevent
unauthorized socket replacement; this adapter does not claim that guarantee.

Success returns `containerId`, `action`, `before`, `after`, `dispatched: true`, and
`outcome: observed`. States contain only status and running/paused/restarting/dead
booleans. This is a point-in-time observation, not proof of future stability.
Inspect Config, Env, diagnostic strings, names and mounts are never returned.

`ControlError` exposes static `code`, `message`, and `status` for pre-dispatch
failures. Any exception after POST begins becomes `OutcomeUnknown`, including a
non-success HTTP response or failed post-action inspection. Its code is
`container_outcome_unknown`; the caller must preserve uncertainty and reconcile
by inspection rather than replaying the mutation. A daemon response may be lost
after the effect happened. No raw transport error is surfaced.

Each response is bounded to 1 MiB. A 25-second operation deadline is checked
between reads; an individual blocking read can extend it by its 12-second timeout.
Redirects and environment proxies are disabled. Tests inject synthetic HTTP
transports; they do not open a real daemon socket. A Docker socket remains powerful
operator authority: the enclosing ToolGate service must isolate and protect it.
This adapter alone does not provide owner authentication or approval policy.

Protocol reference: [Docker Engine API v1.45](https://docs.docker.com/reference/api/engine/version/v1.45/).
