# Managed systemd service lifecycle

The process-control adapter manages explicit services, not arbitrary PIDs. Configure both
`TOOLGATE_SYSTEMD_SCOPE=user|system` and `TOOLGATE_MANAGED_SERVICE_UNITS`, a JSON array
of exact `.service` names. There are no default targets or scope. Template instances such
as `worker@one.service` are supported; globs, paths, flags, bare templates, and escaped
names are deliberately unsupported. Operators should allowlist only services they intend
to control, accounting for those units' systemd dependencies and lifecycle hooks.

`targets()` lists configuration only, with stable IDs such as `system:worker.service`.
The scope is part of the identity: approval for a user service cannot authorize a system
service after configuration changes. `control(service_id, action, runner=None)` accepts
only start, stop, restart. The caller must enforce authority and reserve its durable
execution receipt before invoking this adapter. The adapter itself never retries.

Each action inspects exactly Id, LoadState, ActiveState, SubState, MainPID before and
after the mutation. Aliases whose resolved Id differs from the requested unit, masked,
unloaded and absent units are rejected before mutation. The allowlist and scope are
rechecked immediately before dispatch. The result contains the scoped serviceId, action,
before/after projections, `outcome: observed`, and `dispatched: true`. Observation means
the manager accepted the command and returned state; it does not promise application
health, reachability, or that the service stays running. MainPID is observational and
never becomes a signal target.

Execution uses fixed `/usr/bin/systemctl` argv, `--user` or `--system`, `--no-pager`,
`--no-ask-password`, and a `--` delimiter. No shell, sudo, login shell, prompt, arbitrary
command, or caller-selected bus is used. Stdin/stderr and mutation stdout go to DEVNULL.
Environment is constructed from PATH, C locale, and disabled color. User scope adds
`/run/user/<effective uid>` and its local session bus, derived from the server identity.
Inherited loader, remote host, bus, pager and systemd environment variables are discarded.
User scope requires that server identity's running user manager; system scope requires
the server process's existing system-manager permission. The adapter grants neither.

There is a shared 30-second deadline, supplied as remaining subprocess timeout for each
command. Subprocess creation itself may not be interruptible on every platform. Captured
inspection output is rejected beyond 16 KiB, but `subprocess.run` buffers it before that
check: this is a validation bound, **not a hard allocation bound**. Only five fixed
properties are requested from the local manager. Enforcing hard byte limits during reads
would require a streaming runner. Unit actions can continue in systemd even if the local
client times out or is killed.

Pre-dispatch failures raise static `ControlError` with code, message, status. Once mutation
dispatch begins, every failure (including nonzero exit, timeout or failed post-inspection)
raises independent `OutcomeUnknown`, never a known-no-effect result. The caller must keep
that receipt unknown and require inspection/explicit new intent rather than automatic
replay. Raw stderr, exception messages, service environment and command lines are omitted.

Focused tests use injected subprocess runners and explicitly forbid the real runner.
They do not manage host services. Linux/systemd deployment verification remains separate.
Command semantics: [official systemctl documentation](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
