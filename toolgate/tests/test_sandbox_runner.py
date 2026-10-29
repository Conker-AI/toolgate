"""The sandbox runner without Docker: request checks, the container it asks for, time and quota
limits, uncertain outcomes, the workspace folder and the peer check. A fake Engine records every
call; sandbox/verify runs the same runner against the real one."""

import json
import os
import socket
import threading

import pytest

if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
    pytest.skip("the runner is Linux-only", allow_module_level=True)

from toolgate.sandbox import runner, spec
from toolgate.sandbox.docker_api import DockerError

pytestmark = pytest.mark.skipif(os.getuid() < 1000, reason="needs a non-root test user")
IMAGE = "registry.example/sandbox@sha256:" + "a" * 64


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.bodies = []
        self.running = 0  # inspect calls that still report Running
        self.on_inspect = None
        self.fail = {}
        self.api = "1.45"
        self.images = {IMAGE}
        self.leftovers = []

    def _maybe_fail(self, name):
        if name in self.fail:
            raise DockerError(self.fail[name])

    def version(self):
        return self.api

    def has_image(self, image):
        return image in self.images

    def pull(self, image):
        self.calls.append(("pull", image))

    def labelled(self, label):
        return list(self.leftovers)

    def create(self, body, name):
        self.calls.append(("create", name))
        self.bodies.append(body)
        return "c1"

    def start(self, container):
        self.calls.append(("start", container))
        self._maybe_fail("start")

    def inspect(self, container):
        if self.on_inspect:
            self.on_inspect()
        if self.running:
            self.running -= 1
            return {"State": {"Running": True}}
        return {"State": {"Running": False, "ExitCode": 0, "OOMKilled": False}}

    def kill(self, container):
        self.calls.append(("kill", container))
        self.running = 0

    def remove(self, container):
        self.calls.append(("remove", container))

    def logs(self, container, keep):
        self._maybe_fail("logs")
        return b"out\n", b"", 4, 0


@pytest.fixture
def make(tmp_path):
    def build(**env):
        config = spec.Config.from_env(
            {
                "SANDBOX_IMAGE": IMAGE,
                "SANDBOX_WORKSPACES_VOLUME": "ws",
                "SANDBOX_PROXY_VOLUME": "px",
                "SANDBOX_WORKSPACES_PATH": str(tmp_path),
                "SANDBOX_UID": str(os.getuid()),
                "SANDBOX_GID": str(os.getgid()),
                **env,
            }
        )
        docker = FakeDocker()
        return runner.Runner(config, docker), docker, config

    return build


def run_request(**overrides):
    return {"v": 1, "op": "run", "agent": "companion", "command": "ls", "timeout": 5, **overrides}


def names(docker):
    return [name for name, _ in docker.calls]


def test_a_run_asks_for_exactly_the_fixed_container_and_removes_it(make, tmp_path):
    sandbox, docker, config = make()
    answer = sandbox.handle(run_request(cwd="src", request_id="act-1"))
    assert (tmp_path / "companion").is_dir()
    expected = spec.container(
        config, "companion", spec.run_argv("ls", "src"), install=False, request_id="act-1"
    )
    assert docker.bodies == [expected]
    assert names(docker) == ["create", "start", "remove"]
    assert answer == {**answer, "ok": True, "exit_code": 0, "stdout": "out\n", "timed_out": False}


def test_an_install_adds_only_the_proxy_socket(make):
    sandbox, docker, _ = make()
    sandbox.handle(
        {"v": 1, "op": "install", "agent": "companion", "manager": "npm", "packages": ["left-pad"]}
    )
    body = docker.bodies[0]
    assert body["HostConfig"]["NetworkMode"] == "none"
    assert [mount["Target"] for mount in body["HostConfig"]["Mounts"]] == [
        "/workspace",
        "/run/conker-proxy",
    ]
    assert body["Entrypoint"] == ["/usr/local/bin/conker-install"]
    assert body["Cmd"] == ["npm", "--", "left-pad"]


@pytest.mark.parametrize(
    ("request_", "code"),
    [
        ({"op": "exec"}, "invalid_request"),
        ({"v": 2}, "invalid_request"),
        ({"image": "evil:latest"}, "invalid_request"),
        ({"privileged": True}, "invalid_request"),
        ({"binds": ["/:/host"]}, "invalid_request"),
        ({"agent": "../other"}, "invalid_agent"),
        ({"command": "rm -rf /"}, "guard_refused"),
        ({"cwd": "../other"}, "invalid_cwd"),
        ({"timeout": 0}, "invalid_timeout"),
        ({"timeout": "5"}, "invalid_timeout"),
        ({"timeout": 601}, "invalid_timeout"),
        ({"limits": {"memory_mb": "128"}}, "invalid_limits"),
        ({"limits": {"memory_mb": 32}}, "invalid_limits"),
        ({"limits": {"pids": 4096}}, "invalid_limits"),
        ({"limits": "max"}, "invalid_limits"),
    ],
)
def test_refused_requests_never_create_a_container(make, request_, code):
    sandbox, docker, _ = make()
    with pytest.raises(runner.Failure) as refused:
        sandbox.handle(run_request(**request_))
    assert refused.value.code == code
    assert docker.calls == []


def test_the_owners_lower_limits_shape_the_container_and_never_raise_it(make):
    sandbox, docker, config = make()
    sandbox.handle(run_request(limits={"memory_mb": 128, "cpus_milli": 500}))
    host = docker.bodies[0]["HostConfig"]
    assert (host["Memory"], host["MemorySwap"]) == (128 * 1024 * 1024, 128 * 1024 * 1024)
    assert host["NanoCpus"] == 500_000_000
    sandbox.handle(run_request(limits={"memory_mb": 65536, "cpus_milli": 64000}))
    assert docker.bodies[1] == spec.container(
        config, "companion", spec.run_argv("ls", ""), install=False, request_id=""
    )


def test_a_lower_workspace_size_stops_the_command(make, tmp_path):
    sandbox, docker, _ = make()
    docker.running = 10**6

    def grow():
        big = tmp_path / "companion" / "big.bin"
        if not big.exists():
            big.write_bytes(os.urandom(20 * 1024 * 1024))

    docker.on_inspect = grow
    answer = sandbox.handle(run_request(timeout=30, limits={"workspace_mb": 16}))
    assert answer["workspace_exceeded"] is True and "kill" in names(docker)


def test_refused_packages_never_create_a_container(make):
    sandbox, docker, _ = make()
    with pytest.raises(runner.Failure) as refused:
        sandbox.handle(
            {"v": 1, "op": "install", "agent": "a", "manager": "pip", "packages": ["git+https://x"]}
        )
    assert refused.value.code == "invalid_packages" and docker.calls == []


def test_the_time_limit_kills_the_command(make):
    sandbox, docker, _ = make()
    docker.running = 10**6
    answer = sandbox.handle(run_request(timeout=1))
    assert answer["timed_out"] is True and answer["exit_code"] is None
    assert names(docker) == ["create", "start", "kill", "remove"]


def test_writing_past_the_quota_stops_the_command(make, tmp_path):
    sandbox, docker, _ = make(SANDBOX_WORKSPACE_MB="16")
    (tmp_path / "companion").mkdir()
    (tmp_path / "companion" / "small.bin").write_bytes(os.urandom(3 * 1024 * 1024))
    docker.running = 10**6

    def grow():
        big = tmp_path / "companion" / "big.bin"
        if not big.exists():
            big.write_bytes(os.urandom(20 * 1024 * 1024))

    docker.on_inspect = grow
    answer = sandbox.handle(run_request(timeout=30))
    assert answer["workspace_exceeded"] is True and answer["timed_out"] is False
    assert "kill" in names(docker)


def test_a_lost_answer_after_start_is_unknown_and_the_container_still_goes(make):
    sandbox, docker, _ = make()
    docker.fail["logs"] = "docker_unreachable: ReadTimeout"
    with pytest.raises(runner.Failure) as lost:
        sandbox.handle(run_request())
    assert lost.value.code == "outcome_unknown" and names(docker)[-1] == "remove"


@pytest.mark.parametrize(
    ("error", "code"), [("docker_500: no such volume", "start_failed"), ("docker_unreachable: X", "outcome_unknown")]
)
def test_a_refused_start_is_a_failure_a_lost_one_unknown(make, error, code):
    sandbox, docker, _ = make()
    docker.fail["start"] = error
    with pytest.raises(runner.Failure) as failed:
        sandbox.handle(run_request())
    assert failed.value.code == code and names(docker)[-1] == "remove"


def test_a_symlink_in_place_of_the_workspace_is_refused(make, tmp_path):
    sandbox, docker, _ = make()
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", tmp_path / "companion")
    with pytest.raises(runner.Failure) as refused:
        sandbox.handle(run_request())
    assert refused.value.code == "workspace_invalid" and docker.calls == []


def test_the_quota_scan_counts_closed_folders_and_never_follows_links(tmp_path):
    root = tmp_path / "ws"
    (root / "closed").mkdir(parents=True)
    (root / "closed" / "data.bin").write_bytes(b"x" * 100_000)
    os.chmod(root / "closed", 0)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "huge.bin").write_bytes(b"y" * 1_000_000)
    os.symlink(outside, root / "link")
    used, entries = runner.usage(str(root), 1000)
    assert entries == 3  # closed/, closed/data.bin, link
    assert 100_000 <= used < 1_000_000


def test_prepare_checks_the_engine_and_clears_leftovers(make):
    sandbox, docker, _ = make()
    docker.api = "1.44"
    with pytest.raises(runner.Failure) as old:
        sandbox.prepare()
    assert old.value.code == "docker_too_old"
    docker.api, docker.images, docker.leftovers = "1.47", set(), ["old1"]
    sandbox.prepare()
    assert docker.calls == [("pull", IMAGE), ("remove", "old1")]


def test_an_unpinned_missing_image_is_never_pulled(make):
    sandbox, docker, _ = make(SANDBOX_IMAGE="sha256:" + "b" * 64)
    docker.images = set()
    with pytest.raises(runner.Failure) as missing:
        sandbox.prepare()
    assert missing.value.code == "image_unavailable" and docker.calls == []


def _ask(path, payload: bytes):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(path)
        connection.sendall(payload)
        return json.loads(connection.makefile("rb").readline())


@pytest.mark.parametrize("admitted", [True, False])
def test_only_the_configured_peer_uid_may_run(make, tmp_path, admitted):
    sandbox, docker, _ = make()
    path = str(tmp_path / "runner.sock")
    clients = {os.getuid()} if admitted else {os.getuid() + 1}
    with runner.Server(path, sandbox, clients) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            answer = _ask(path, json.dumps(run_request()).encode() + b"\n")
            health = _ask(path, b'{"v": 1, "op": "health"}\n')
            oversized = _ask(path, b'{"v": 1, "op": "run", "pad": "' + b"x" * 70000 + b'"}\n')
        finally:
            server.shutdown()
    assert health == {"ok": True, "ready": True}
    if admitted:
        assert answer["ok"] is True and names(docker)[0] == "create"
        assert oversized["code"] == "invalid_request"
    else:
        assert answer == {**answer, "ok": False, "code": "not_permitted"} and docker.calls == []


def test_an_out_of_memory_label_that_lands_after_the_exit_is_kept(make, monkeypatch):
    """Docker records the OOM kill from a separate event that can arrive just after the exit."""
    sandbox, docker, _ = make()
    states = iter(
        [
            {"Running": False, "ExitCode": 137, "OOMKilled": False},
            {"Running": False, "ExitCode": 137, "OOMKilled": True},
        ]
    )
    docker.inspect = lambda container: {"State": next(states)}
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)
    answer = sandbox.handle(run_request())
    assert (answer["exit_code"], answer["oom_killed"]) == (137, True)


def test_a_plain_kill_is_not_reported_as_out_of_memory(make, monkeypatch):
    sandbox, docker, _ = make()
    docker.inspect = lambda container: {
        "State": {"Running": False, "ExitCode": 137, "OOMKilled": False}
    }
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)
    answer = sandbox.handle(run_request())
    assert (answer["exit_code"], answer["oom_killed"]) == (137, False)
