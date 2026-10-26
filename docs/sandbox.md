# Agent sandbox: Terminal and Install packages

Two built-in tools give every agent a terminal without giving it the host:

| Tool | What it does | Default access |
|---|---|---|
| `sandbox.run` (Terminal) | Runs one shell command (`command`, optional `cwd` inside the workspace, `timeout_seconds` 1-100, default 30) | AI decides (`ai_review`) |
| `sandbox.install` (Install packages) | Installs `packages` (1-20 names, optional versions) with `manager` `pip` or `npm` | AI decides (`ai_review`) |

They are registered on startup once `TOOLGATE_SANDBOX_SOCKET` is set, and only when absent, so
the owner's access choices survive restarts. They follow the access layers like any tool (chat >
agent > tool default, the floor, Handled; see access-policy.md) and agent identities
(agent-access.md): an agent outside whose toolkit they are does not see them.

## How a call runs

1. ToolGate validates the arguments before any approval is asked for. The guard refuses commands
   that would break the sandbox itself: deleting the root filesystem or the whole workspace,
   killing every process, shutdown or reboot, fork bombs, formatting or writing devices. Package
   names are names and versions only: no URLs, paths, VCS links or options.
2. After the access decision, ToolGate sends one JSON request to the **sandbox runner** over the
   Unix socket at `TOOLGATE_SANDBOX_SOCKET`. The agent in the request is the caller's identity
   (`X-ToolGate-Agent`, or the agent a bound key belongs to; a key acting as itself is
   `companion`). No argument can name another agent or folder.
3. The runner, the only process that talks to Docker for this, admits the connection only if the
   kernel reports a UID in `SANDBOX_CLIENT_UIDS` (`SO_PEERCRED`), validates the request again,
   creates the agent's folder on first use and starts **one fresh container** for the command.
4. The container is watched for its time limit and the workspace quota, then its output is read
   (the last 64 KiB of each stream) and the container is removed. ToolGate returns `exitCode`,
   `stdout`, `stderr` (control sequences stripped, last 16000 characters), `timedOut`,
   `outOfMemory`, `workspaceFull`, `durationMs` and `truncated`.
5. If the answer is lost after the request was sent, the receipt is `OUTCOME_UNKNOWN` and reusing
   the action id never runs the command again.

## The container (toolgate/sandbox/spec.py)

| Setting | Value |
|---|---|
| Image | `SANDBOX_IMAGE`, pinned by digest (`sandbox/Dockerfile`: Debian, Python 3.11, Node 22, git, numpy, pandas, requests, pyyaml, beautifulsoup4, python-dateutil, openpyxl; no setuid programs) |
| Network | `none`: loopback only, for runs and installs |
| Mounts | the agent's folder (a subpath of the workspaces volume) at `/workspace`; installs add the package proxy's socket volume read-only at `/run/conker-proxy`. Nothing else: no Docker socket, no host paths |
| User | `65533:65533` (`SANDBOX_UID`, `SANDBOX_GID`), umask 007 |
| Privileges | every capability dropped, `no-new-privileges`, not privileged, no devices, private IPC and cgroup namespaces, Docker's default seccomp profile |
| Filesystem | read-only root; `/tmp` tmpfs (`SANDBOX_TMP_MB`, default 128) |
| Environment | the image's own non-secret ENV plus fixed paths and locale; never a credential |
| Memory | `SANDBOX_MEMORY_MB` (512; installs `SANDBOX_INSTALL_MEMORY_MB`, 1024), no swap |
| CPU | `SANDBOX_CPUS_MILLI` (1000 = one CPU) |
| Processes | `SANDBOX_PIDS` (128) |
| Files | largest file `SANDBOX_FILE_MB` (512), open files `SANDBOX_NOFILE` (1024), no core dumps |
| Workspace | `SANDBOX_WORKSPACE_MB` (2048) and `SANDBOX_WORKSPACE_FILES` (100000), checked every 2 s; a command that goes over is stopped, and a workspace already over may shrink but not grow |
| Time | per call (Terminal up to 100 s; installs 100 s), runner maximum `SANDBOX_MAX_SECONDS` (600) |
| Logs | json-file, at most 4 MiB, removed with the container |
| Concurrency | one command per agent at a time, `SANDBOX_CONCURRENT` (2) overall |

Python packages install into `/workspace/.venv` (which sees the image's libraries) and npm
packages into `/workspace/node_modules`; both are on `PATH` for later commands.

## The package proxy (toolgate/sandbox/proxy.py)

A GET/HEAD-only pull-through to three fixed upstreams over verified HTTPS: `pypi.org` (simple
index), `files.pythonhosted.org` (archives) and `registry.npmjs.org` (metadata and tarballs),
under fixed path shapes. Everything else answers 404 or 405 without leaving the process: other
hosts, other paths, uploads, publishing, audits, CONNECT tunnels. It listens on a Unix socket in
its own volume, admits only `PROXY_CLIENT_UIDS` (the sandbox UID), and logs every fetch and
refusal as one JSON line (`docker logs` of the proxy). Inside an install container a small
forwarder exposes that socket on `127.0.0.1:3128`; the container still has no network.

## Deployment

Run the runner and the proxy from the ToolGate image:
`python -m toolgate.sandbox.runner serve` (user 65533, `network_mode: none`, the Docker socket,
the control volume and the workspaces volume) and `python -m toolgate.sandbox.proxy serve` (user
65532, one egress network, its socket volume). ToolGate mounts the control volume and sets
`TOOLGATE_SANDBOX_SOCKET`. Conker's `docker-compose.sandbox.yml` is the reference deployment;
`sandbox/verify/compose.yml` is the same shape for tests. Requires Docker Engine 26+ (volume
subpaths). Runner settings: `SANDBOX_IMAGE`, `SANDBOX_CLIENT_UIDS`, `SANDBOX_WORKSPACES_VOLUME`,
`SANDBOX_WORKSPACES_PATH` (default `/workspaces`), `SANDBOX_PROXY_VOLUME`, `SANDBOX_SOCKET`,
`SANDBOX_DOCKER_SOCKET` and the limits above. The runner removes leftover sandbox containers when
it starts.

## Verification

`sandbox/verify` runs against the real Docker Engine in CI (job `sandbox`): network, mounts, user,
capabilities, read-only root, every limit, the proxy allowlist, the peer checks and per-agent
scoping, each asserted from Docker's inspect and from inside the container. Unit tests:
`toolgate/tests/test_sandbox_*.py`. Design record: Conker ADR-0013.
