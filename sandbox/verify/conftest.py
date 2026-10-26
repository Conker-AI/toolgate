"""Helpers for the sandbox verification suite. Runs inside the verifier container of compose.yml.

`sandbox(...)` sends one request to the real runner over its socket. `while_running(...)` starts
a command that stays alive for a few seconds and returns the Docker inspect of its container, so
tests can assert the exact settings a command ran under. `docker` talks to the same Engine.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import pickle
import socket
import threading
import time
import uuid

import pytest

from toolgate.sandbox.docker_api import Docker

SOCKET = os.environ.get("TOOLGATE_SANDBOX_SOCKET", "/run/conker-sandbox/runner.sock")


def sandbox(request: dict, timeout: float = 180) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(SOCKET)
        connection.sendall(json.dumps(request).encode() + b"\n")
        return json.loads(connection.makefile("rb").readline(2 * 1024 * 1024))


def run(agent: str, command: str, timeout: int = 30, cwd: str = "") -> dict:
    return sandbox(
        {"v": 1, "op": "run", "agent": agent, "command": command, "cwd": cwd, "timeout": timeout}
    )


def install(agent: str, manager: str, packages: list[str], timeout: int = 120) -> dict:
    return sandbox(
        {
            "v": 1,
            "op": "install",
            "agent": agent,
            "manager": manager,
            "packages": packages,
            "timeout": timeout,
        }
    )


@pytest.fixture(scope="session")
def docker() -> Docker:
    return Docker("/var/run/docker.sock")


def unique_agent(prefix: str = "verify") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def while_running(docker: Docker, agent: str, command: str = "sleep 6", install_request=None):
    """Inspect the container of a live request for `agent`; returns (inspect, final answer)."""
    answer: dict = {}

    def send():
        if install_request is not None:
            answer.update(sandbox(install_request))
        else:
            answer.update(run(agent, command, timeout=60))

    thread = threading.Thread(target=send)
    thread.start()
    inspect = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and inspect is None:
        for container in docker.labelled("conker.sandbox"):
            details = docker.inspect(container)
            if details["Config"]["Labels"].get("conker.sandbox.agent") == agent:
                inspect = details
                break
        time.sleep(0.1)
    thread.join(timeout=180)
    assert inspect is not None, f"no live sandbox container seen for {agent}: {answer}"
    return inspect, answer


def labelled(docker: Docker, label: str, value: str) -> list[str]:
    """Ids of every container (running or not) whose `label` equals `value`."""
    filters = json.dumps({"label": [f"{label}={value}"]})
    response = docker.client.get(
        "/v1.45/containers/json", params={"all": "1", "filters": filters}
    )
    response.raise_for_status()
    return [item["Id"] for item in response.json()]


def as_uid(uid: int, fn):
    """Run `fn()` in a forked child with the given UID/GID and return its result through a pipe."""
    import os

    parent_pipe, child_pipe = os.pipe()

    child_pid = os.fork()
    if child_pid == 0:
        # Child process
        try:
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
            result = fn()
            os.write(child_pipe, pickle.dumps(result))
            os._exit(0)
        except Exception as e:
            os.write(child_pipe, pickle.dumps(e))
            os._exit(1)

    # Parent process
    os.close(child_pipe)
    try:
        data = os.read(parent_pipe, 1024 * 1024)
        result = pickle.loads(data)
        if isinstance(result, Exception):
            raise result
        return result
    finally:
        os.close(parent_pipe)
        # Reap child
        with contextlib.suppress(BaseException):
            os.waitpid(child_pid, 0)


class ProxyHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects to the proxy Unix socket."""

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/run/conker-proxy/proxy.sock")


def proxy_request(method: str, path: str, headers=None) -> tuple[str, bytes]:
    """Send a request to the proxy as UID 65533 and return (status, body_bytes)."""
    def _request():
        conn = ProxyHTTPConnection("localhost")
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    try:
        return as_uid(65533, _request)
    except Exception as e:
        if "Connection refused" in str(e) or "closed" in str(e).lower():
            return "closed", b""
        raise


def service(name: str) -> dict:
    """Get Docker inspect of the compose service container."""
    docker = Docker("/var/run/docker.sock")
    containers = labelled(docker, "com.docker.compose.service", name)
    if containers:
        return docker.inspect(containers[0])
    raise ValueError(f"Service {name} not found")


def logs(name: str) -> str:
    """Get the service's stdout as text."""
    docker = Docker("/var/run/docker.sock")
    containers = labelled(docker, "com.docker.compose.service", name)
    if not containers:
        raise ValueError(f"Service {name} not found")

    # Use Docker.logs to get container logs (keep last 1MB)
    stdout, stderr, _, _ = docker.logs(containers[0], keep=1024*1024)
    return (stdout + stderr).decode('utf-8', errors='replace')
