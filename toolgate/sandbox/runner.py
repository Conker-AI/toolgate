"""The sandbox runner: the only Conker process that talks to Docker for agent commands.

It listens on a Unix socket in a volume shared only with ToolGate, admits a connection only when
the kernel reports the peer's UID as one of `SANDBOX_CLIENT_UIDS` (SO_PEERCRED; reaching the path
is not authority), reads one JSON request, runs it in a fresh container built by `spec.container`
and answers with the bounded result. The container is removed afterwards, so no process outlives
its command. Usage: `python -m toolgate.sandbox.runner serve|health`.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
import uuid

from toolgate.sandbox import spec, validation
from toolgate.sandbox.docker_api import Docker, DockerError

MAX_REQUEST = 64 * 1024
KEEP_OUTPUT = 64 * 1024
DEFAULT_SOCKET = "/run/conker-sandbox/runner.sock"
RUN_KEYS = {"v", "op", "agent", "command", "cwd", "timeout", "request_id"}
INSTALL_KEYS = {"v", "op", "agent", "manager", "packages", "timeout", "request_id"}


class Failure(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def peer_uid(connection: socket.socket) -> int:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)[1]


# --- workspaces --------------------------------------------------------------------------------


def workspace(config: spec.Config, agent: str) -> str:
    """The agent's folder, created on first use. A symlink or non-folder in its place is refused."""
    path = os.path.join(config.workspaces_path, agent)
    # No chmod: it would clear the setgid bit inherited from the workspaces folder (the runner is
    # not in the owner's group), and that bit is what gives the owner the agent's files.
    with contextlib.suppress(FileExistsError):
        os.mkdir(path, 0o770)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise Failure("workspace_invalid", "The agent's workspace folder is not usable.")
    return path


def _scan(folder: str):
    try:
        return os.scandir(folder)
    except PermissionError:
        # A folder the agent closed to everyone (chmod 000) still counts. The runner runs as the
        # sandbox user, so it owns the folder and may open it again.
        try:
            os.chmod(folder, os.lstat(folder).st_mode & 0o7777 | 0o700)
            return os.scandir(folder)
        except OSError:
            return None
    except OSError:
        return None


def usage(path: str, file_cap: int) -> tuple[int, int]:
    """Allocated bytes and entries under `path`, without following links; stops past `file_cap`."""
    total, entries, stack = 0, 0, [path]
    while stack:
        iterator = _scan(stack.pop())
        if iterator is None:
            continue
        with iterator:
            for entry in iterator:
                entries += 1
                if entries > file_cap:
                    return total, entries
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                total += getattr(info, "st_blocks", 0) * 512 or info.st_size
                if stat.S_ISDIR(info.st_mode):
                    stack.append(entry.path)
    return total, entries


# --- running one request -----------------------------------------------------------------------


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


class Runner:
    def __init__(self, config: spec.Config, docker: Docker):
        self.config = config
        self.docker = docker
        self.slots = threading.BoundedSemaphore(config.limits.concurrent)
        self.locks: dict[str, threading.Lock] = {}
        self.guard = threading.Lock()

    def _lock(self, agent: str) -> threading.Lock:
        with self.guard:
            return self.locks.setdefault(agent, threading.Lock())

    def prepare(self) -> None:
        if os.getuid() != self.config.uid:
            # Workspace folders are created by this process and must belong to the sandbox user.
            raise Failure("misconfigured", "The runner must run as SANDBOX_UID.")
        if tuple(int(part) for part in self.docker.version().split(".")[:2]) < (1, 45):
            raise Failure("docker_too_old", "Docker Engine 26 or newer is required (API 1.45).")
        if not self.docker.has_image(self.config.image):
            if "@sha256:" not in self.config.image:
                raise Failure("image_unavailable", "The sandbox image is not on this machine.")
            self.docker.pull(self.config.image)
        # Containers left by a runner that died mid-command are removed, never resumed.
        for container in self.docker.labelled(spec.LABEL):
            self.docker.remove(container)

    def handle(self, request: dict) -> dict:
        op = request.get("op")
        if request.get("v") != 1 or op not in ("run", "install"):
            raise Failure("invalid_request", "Unknown request.")
        keys = RUN_KEYS if op == "run" else INSTALL_KEYS
        if set(request) - keys or not {"v", "op", "agent"} <= set(request):
            raise Failure("invalid_request", "Unexpected or missing fields.")
        try:
            agent = validation.agent(request["agent"])
            if op == "run":
                argv = spec.run_argv(
                    validation.command(request.get("command")), validation.cwd(request.get("cwd"))
                )
            else:
                argv = spec.install_argv(
                    request.get("manager"),
                    validation.packages(request.get("manager"), request.get("packages")),
                )
        except validation.Refused as exc:
            raise Failure(exc.code, str(exc)) from None
        timeout = request.get("timeout", 60)
        if type(timeout) is not int or not 1 <= timeout <= self.config.limits.max_seconds:
            raise Failure("invalid_timeout", "The time limit is outside the configured bound.")
        request_id = request.get("request_id", "")
        if not isinstance(request_id, str) or len(request_id) > 100:
            raise Failure("invalid_request", "request_id must be a short string.")
        lock = self._lock(agent)
        # Short waits: ToolGate's own deadline is the time limit plus one minute.
        if not lock.acquire(timeout=10):
            raise Failure("busy", "This agent's previous command is still running.")
        try:
            if not self.slots.acquire(timeout=10):
                raise Failure("busy", "The sandbox is busy; try again shortly.")
            try:
                return self._execute(agent, argv, op == "install", timeout, request_id)
            finally:
                self.slots.release()
        finally:
            lock.release()

    def _execute(self, agent, argv, install, timeout, request_id) -> dict:
        limits = self.config.limits
        path = workspace(self.config, agent)
        start_bytes, start_files = usage(path, limits.workspace_files)
        # A workspace already over its quota may shrink but not grow.
        byte_ceiling = max(limits.workspace_mb * 1024 * 1024, start_bytes)
        file_ceiling = max(limits.workspace_files, start_files)
        body = spec.container(self.config, agent, argv, install=install, request_id=request_id)
        name = f"conker-sandbox-{agent[:40]}-{uuid.uuid4().hex[:12]}"
        container = self.docker.create(body, name)
        started = time.monotonic()
        timed_out = exceeded = False
        try:
            try:
                self.docker.start(container)
            except DockerError as exc:
                # Docker answered: the container did not start. No answer: it may have.
                if str(exc).startswith("docker_unreachable"):
                    raise Failure("outcome_unknown", "The command may have started.") from None
                raise Failure("start_failed", f"The sandbox could not start ({exc}).") from None
            try:
                state, timed_out, exceeded = self._watch(
                    container, path, started + timeout, byte_ceiling, file_ceiling
                )
                out, err, out_total, err_total = self.docker.logs(container, KEEP_OUTPUT)
            except DockerError as exc:
                raise Failure(
                    "outcome_unknown", f"The command started; its result was lost ({exc})."
                ) from None
        finally:
            with contextlib.suppress(DockerError):
                self.docker.remove(container)
        used_bytes, used_files = usage(path, file_ceiling + 1)
        return {
            "ok": True,
            "exit_code": None if timed_out else state.get("ExitCode"),
            "timed_out": timed_out,
            "oom_killed": bool(state.get("OOMKilled")),
            "workspace_exceeded": exceeded
            or used_bytes > byte_ceiling
            or used_files > file_ceiling,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "stdout": _text(out),
            "stderr": _text(err),
            "stdout_truncated": out_total > len(out),
            "stderr_truncated": err_total > len(err),
            "workspace_bytes": used_bytes,
            "workspace_files": used_files,
        }

    def _watch(self, container, path, deadline, byte_ceiling, file_ceiling):
        timed_out = exceeded = killed = False
        next_check = time.monotonic() + 1.0
        kill_deadline = None
        while True:
            state = self.docker.inspect(container)["State"]
            if not state.get("Running"):
                return state, timed_out, exceeded
            now = time.monotonic()
            if not killed and now > deadline:
                timed_out = killed = True
            if not killed and now > next_check:
                used, files = usage(path, file_ceiling + 1)
                exceeded = killed = used > byte_ceiling or files > file_ceiling
                next_check = now + 2.0
            if killed and kill_deadline is None:
                self.docker.kill(container)
                kill_deadline = now + 15
            if kill_deadline is not None and now > kill_deadline:
                raise DockerError("container_did_not_stop")
            time.sleep(0.1)


# --- the socket server -------------------------------------------------------------------------


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        server: Server = self.server
        try:
            uid = peer_uid(self.connection)
            line = self.rfile.readline(MAX_REQUEST + 1)
            if len(line) > MAX_REQUEST or not line.endswith(b"\n"):
                raise Failure("invalid_request", "One JSON line of at most 64 KiB.")
            request = json.loads(line)
            if not isinstance(request, dict):
                raise Failure("invalid_request", "The request must be a JSON object.")
            if request.get("op") == "health":
                # The container's own health check may ask; nothing else is open to it.
                if uid not in server.clients and uid != os.getuid():
                    raise Failure("not_permitted", "This peer may not use the sandbox.")
                answer = {"ok": True, "ready": True}
            elif uid not in server.clients:
                raise Failure("not_permitted", "This peer may not use the sandbox.")
            else:
                answer = server.runner.handle(request)
        except Failure as exc:
            answer = {"ok": False, "code": exc.code, "message": str(exc)}
        except (ValueError, UnicodeDecodeError):
            answer = {"ok": False, "code": "invalid_request", "message": "Malformed request."}
        except DockerError as exc:
            answer = {"ok": False, "code": "docker_unavailable", "message": str(exc)[:300]}
        except Exception as exc:
            answer = {"ok": False, "code": "runner_error", "message": type(exc).__name__}
        with contextlib.suppress(OSError):
            self.wfile.write(json.dumps(answer).encode() + b"\n")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, runner: Runner, clients: set[int]):
        self.runner = runner
        self.clients = clients
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        super().__init__(path, Handler)
        # Anyone who can reach the path may connect; only the peer UID check admits.
        os.chmod(path, 0o666)


def _clients(raw: str) -> set[int]:
    try:
        uids = {int(part) for part in raw.split(",") if part.strip()}
    except ValueError:
        raise spec.ConfigError("SANDBOX_CLIENT_UIDS must list numeric UIDs") from None
    if not uids:
        raise spec.ConfigError("SANDBOX_CLIENT_UIDS must name ToolGate's UID")
    return uids


def serve() -> int:
    # New agent folders: rwx for the sandbox user and the owner's group, nothing for others.
    os.umask(0o007)
    config = spec.Config.from_env()
    clients = _clients(os.environ.get("SANDBOX_CLIENT_UIDS", ""))
    runner = Runner(config, Docker(os.environ.get("SANDBOX_DOCKER_SOCKET", "/var/run/docker.sock")))
    runner.prepare()
    path = os.environ.get("SANDBOX_SOCKET", DEFAULT_SOCKET)
    with Server(path, runner, clients) as server:
        print(json.dumps({"event": "sandbox_runner_ready", "image": config.image}), flush=True)
        server.serve_forever()
    return 0


def health() -> int:
    path = os.environ.get("SANDBOX_SOCKET", DEFAULT_SOCKET)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(path)
            connection.sendall(b'{"v": 1, "op": "health"}\n')
            answer = json.loads(connection.makefile("rb").readline(4096))
    except (OSError, ValueError):
        return 1
    return 0 if answer.get("ok") else 1


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    sys.exit(health() if command == "health" else serve() if command == "serve" else 2)
