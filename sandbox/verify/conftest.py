"""Helpers for the sandbox verification suite. Runs inside the verifier container of compose.yml.

`sandbox(...)` sends one request to the real runner over its socket. `while_running(...)` starts
a command that stays alive for a few seconds and returns the Docker inspect of its container, so
tests can assert the exact settings a command ran under. `docker` talks to the same Engine.
"""

from __future__ import annotations

import json
import os
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
