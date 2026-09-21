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
