"""The one container shape every sandbox command runs in. Nothing in a request can change it.

A request chooses only the agent (which picks the workspace folder), the command or packages, the
working folder inside the workspace and a time limit within the configured bound. Everything else
here is fixed configuration from the runner's environment, read once at startup:

- no network: `NetworkMode: none` (only loopback); installs add the package proxy's socket
  read-only, never a network;
- no secrets: the environment is `environment()` plus the image's own fixed, non-secret ENV
  (tool versions, locale); no env file, no credentials;
- no Docker socket and no host mounts: one volume subpath (the agent's own folder) at /workspace,
  plus, for installs only, the proxy socket volume read-only;
- a fixed non-root user, every capability dropped, no-new-privileges, not privileged, no devices;
- a read-only root filesystem with a small tmpfs at /tmp;
- limits on memory (no swap), CPU, processes, file size, open files, log size and time.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

DIGEST = re.compile(r"(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[a-f0-9]{64}")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
LABEL = "conker.sandbox"
PROXY_DIR = "/run/conker-proxy"
FORWARD_PORT = 3128
RUN = 'umask 0007; cd -- "$1" && exec /bin/bash -c "$2"'
PATH = (
    "/workspace/.venv/bin:/workspace/node_modules/.bin:"
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)


class ConfigError(ValueError):
    pass


def _int(env, name, default, low, high):
    raw = env.get(name, "")
    try:
        value = int(raw) if raw else default
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}")
    return value


@dataclass(frozen=True)
class Limits:
    memory_mb: int
    install_memory_mb: int
    cpus_milli: int
    pids: int
    tmp_mb: int
    file_mb: int
    nofile: int
    workspace_mb: int
    workspace_files: int
    max_seconds: int
    concurrent: int


@dataclass(frozen=True)
class Config:
    image: str
    uid: int
    gid: int
    workspaces_volume: str
    workspaces_path: str
    proxy_volume: str
    limits: Limits

    @classmethod
    def from_env(cls, env=None) -> Config:
        env = os.environ if env is None else env
        image = env.get("SANDBOX_IMAGE", "")
        # Pinned by digest (or a local image id): a tag could be moved under a running install.
        if not DIGEST.fullmatch(image):
            raise ConfigError("SANDBOX_IMAGE must be pinned: name@sha256:<digest> or sha256:<id>")
        volumes = {}
        for name in ("SANDBOX_WORKSPACES_VOLUME", "SANDBOX_PROXY_VOLUME"):
            volumes[name] = env.get(name, "")
            if not NAME.fullmatch(volumes[name]):
                raise ConfigError(f"{name} must be a Docker volume name")
        path = env.get("SANDBOX_WORKSPACES_PATH", "/workspaces")
        if not path.startswith("/") or ".." in path.split("/"):
            raise ConfigError("SANDBOX_WORKSPACES_PATH must be absolute")
        uid = _int(env, "SANDBOX_UID", 65533, 1000, 2**31 - 2)
        gid = _int(env, "SANDBOX_GID", 65533, 1000, 2**31 - 2)
        limits = Limits(
            memory_mb=_int(env, "SANDBOX_MEMORY_MB", 512, 64, 65536),
            install_memory_mb=_int(env, "SANDBOX_INSTALL_MEMORY_MB", 1024, 64, 65536),
            cpus_milli=_int(env, "SANDBOX_CPUS_MILLI", 1000, 100, 64000),
            pids=_int(env, "SANDBOX_PIDS", 128, 16, 4096),
            tmp_mb=_int(env, "SANDBOX_TMP_MB", 128, 8, 8192),
            file_mb=_int(env, "SANDBOX_FILE_MB", 512, 1, 65536),
            nofile=_int(env, "SANDBOX_NOFILE", 1024, 64, 65536),
            workspace_mb=_int(env, "SANDBOX_WORKSPACE_MB", 2048, 16, 1048576),
            workspace_files=_int(env, "SANDBOX_WORKSPACE_FILES", 100000, 100, 10000000),
            max_seconds=_int(env, "SANDBOX_MAX_SECONDS", 600, 5, 3600),
            concurrent=_int(env, "SANDBOX_CONCURRENT", 2, 1, 64),
        )
        return cls(
            image=image,
            uid=uid,
            gid=gid,
            workspaces_volume=volumes["SANDBOX_WORKSPACES_VOLUME"],
            workspaces_path=path.rstrip("/") or "/",
            proxy_volume=volumes["SANDBOX_PROXY_VOLUME"],
            limits=limits,
        )


def environment(install: bool = False) -> list[str]:
    """What the runner adds to the image's own ENV: paths and locale, never a credential."""
    values = [
        f"PATH={PATH}",
        "HOME=/tmp",
        "LANG=C.UTF-8",
        "TERM=dumb",
        "CONKER_SANDBOX=1",
        "NODE_PATH=/workspace/node_modules",
        "npm_config_cache=/tmp/.npm",
        "npm_config_update_notifier=false",
        "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "PIP_NO_INPUT=1",
    ]
    if install:
        values.append(f"CONKER_PROXY_SOCKET={PROXY_DIR}/proxy.sock")
        values.append(f"CONKER_PROXY_PORT={FORWARD_PORT}")
    return values


def container(
    config: Config, agent: str, argv: list[str], *, install: bool = False, request_id: str = ""
) -> dict:
    """The Docker Engine API create body. `agent` and `argv` must already be validated."""
    limits = config.limits
    memory = (limits.install_memory_mb if install else limits.memory_mb) * 1024 * 1024
    file_size = limits.file_mb * 1024 * 1024
    mounts = [
        {
            "Type": "volume",
            "Source": config.workspaces_volume,
            "Target": "/workspace",
            "ReadOnly": False,
            "VolumeOptions": {"NoCopy": True, "Subpath": agent},
        }
    ]
    if install:
        mounts.append(
            {
                "Type": "volume",
                "Source": config.proxy_volume,
                "Target": PROXY_DIR,
                "ReadOnly": True,
                "VolumeOptions": {"NoCopy": True},
            }
        )
    return {
        "Image": config.image,
        # The program is fixed here, so an image entrypoint cannot wrap or replace it.
        "Entrypoint": argv[:1],
        "Cmd": argv[1:],
        "User": f"{config.uid}:{config.gid}",
        "WorkingDir": "/workspace",
        "Env": environment(install),
        "Hostname": "sandbox",
        "NetworkDisabled": True,
        "AttachStdin": False,
        "AttachStdout": False,
        "AttachStderr": False,
        "OpenStdin": False,
        "Tty": False,
        "StopTimeout": 1,
        "Labels": {
            LABEL: "1",
            f"{LABEL}.agent": agent,
            f"{LABEL}.kind": "install" if install else "run",
            f"{LABEL}.request": request_id[:100],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "Mounts": mounts,
            "Binds": [],
            "VolumesFrom": [],
            "Devices": [],
            "DeviceRequests": [],
            "PortBindings": {},
            "PublishAllPorts": False,
            "Privileged": False,
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "CapAdd": [],
            "SecurityOpt": ["no-new-privileges:true"],
            "Init": True,
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "PidMode": "",
            "UTSMode": "",
            "UsernsMode": "",
            "GroupAdd": [],
            # exec: package builds run from /tmp; the workspace is executable anyway.
            "Tmpfs": {"/tmp": f"rw,exec,nosuid,nodev,size={limits.tmp_mb}m,mode=1777"},
            "ShmSize": 64 * 1024 * 1024,
            "Memory": memory,
            "MemorySwap": memory,
            "NanoCpus": limits.cpus_milli * 1_000_000,
            "PidsLimit": limits.pids,
            "Ulimits": [
                {"Name": "fsize", "Soft": file_size, "Hard": file_size},
                {"Name": "nofile", "Soft": limits.nofile, "Hard": limits.nofile},
                {"Name": "core", "Soft": 0, "Hard": 0},
            ],
            "OomScoreAdj": 500,
            "RestartPolicy": {"Name": "no"},
            "AutoRemove": False,
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "4m", "max-file": "1"}},
        },
    }


def run_argv(command: str, cwd: str) -> list[str]:
    """bash with the command as data: positional arguments, never spliced into a script."""
    folder = "/workspace/" + cwd if cwd else "/workspace"
    return ["/bin/bash", "-c", RUN, "conker-sandbox", folder, command]


def install_argv(manager: str, packages: list[str]) -> list[str]:
    return ["/usr/local/bin/conker-install", manager, "--", *packages]
