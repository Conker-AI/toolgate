"""Lockdown tests: network, mounts, user, capabilities, read-only root, secrets, namespaces."""

import os
import time

from conftest import as_uid, labelled, run, service, unique_agent, while_running

from toolgate.sandbox.spec import environment


def test_network_none_mode_and_loopback_only(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer
    assert inspect["HostConfig"]["NetworkMode"] == "none"
    assert list(inspect["NetworkSettings"]["Networks"] or {}) in ([], ["none"])

    # Inside container: only lo interface
    net_check = run(agent, "ls /sys/class/net")
    assert net_check["stdout"].strip() == "lo", net_check

    # Network connectivity tests
    tests = [
        ("python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 443), timeout=2)'", "1.1.1.1:443"),
        ("python3 -c 'import socket; socket.create_connection((\"8.8.8.8\", 53), timeout=2)'", "8.8.8.8:53"),
        ("python3 -c 'import socket; socket.gethostbyname(\"pypi.org\")'", "resolve pypi.org"),
    ]

    for cmd, target in tests:
        result = run(agent, cmd)
        assert result["exit_code"] != 0, f"Should fail to connect to {target}"
        assert "FAIL" in result.get("stderr", "") or "error" in result.get("stderr", "").lower(), f"Expected error for {target}"


def test_mounts_workspace_volume_only(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer

    # Check mounts from inspect
    mounts = inspect["Mounts"]
    assert len(mounts) == 1, f"Expected 1 mount, got {len(mounts)}"
    assert mounts[0]["Type"] == "volume"
    assert mounts[0]["Name"] == "conker_verify_workspaces"
    assert mounts[0]["Destination"] == "/workspace"
    assert mounts[0]["RW"] is True

    # No docker.sock in mount sources
    for mount in mounts:
        if "Source" in mount:
            assert "docker.sock" not in mount["Source"], f"docker.sock found in mount source: {mount['Source']}"

    # Inside container: check paths don't exist
    forbidden_paths = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/conker-sandbox",
        "/run/conker-proxy"
    ]

    for path in forbidden_paths:
        result = run(agent, f"test -e {path} && echo EXISTS || echo MISSING")
        assert "MISSING" in result["stdout"], f"Path {path} should not exist"

    # Check /proc/mounts doesn't contain docker.sock
    mounts_check = run(agent, "cat /proc/mounts")
    assert "docker.sock" not in mounts_check["stdout"], "docker.sock found in /proc/mounts"


def test_user_nonroot_65533(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer
    assert inspect["Config"]["User"] == "65533:65533"

    # Inside container: check user IDs
    uid_result = run(agent, "id -u")
    gid_result = run(agent, "id -g")
    groups_result = run(agent, "id -G")

    assert uid_result["stdout"].strip() == "65533", f"Expected UID 65533, got {uid_result['stdout']}"
    assert gid_result["stdout"].strip() == "65533", f"Expected GID 65533, got {gid_result['stdout']}"
    assert groups_result["stdout"].strip() == "65533", f"Expected only group 65533, got {groups_result['stdout']}"


def test_capabilities_dropped_all(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer
    assert inspect["HostConfig"]["CapDrop"] == ["ALL"]
    assert inspect["HostConfig"]["CapAdd"] in ([], None)
    assert inspect["HostConfig"]["Privileged"] is False
    assert "no-new-privileges:true" in inspect["HostConfig"]["SecurityOpt"]

    # Inside container: check capabilities are all zero
    status = run(agent, "cat /proc/self/status")
    status_lines = status["stdout"].split('\n')

    fields = dict(line.split(":\t", 1) for line in status_lines if ":\t" in line)
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert fields[field] == "0000000000000000", f"{field} should be all zeros: {fields[field]}"

    # Check NoNewPrivs and Seccomp
    assert "NoNewPrivs:\t1" in status_lines, "NoNewPrivs should be 1"
    seccomp_line = next((line for line in status_lines if line.startswith("Seccomp:")), None)
    assert seccomp_line and "2" in seccomp_line, f"Expected Seccomp mode 2, got {seccomp_line}"


def test_readonly_rootfs(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer
    assert inspect["HostConfig"]["ReadonlyRootfs"] is True

    # Test writing to read-only paths fails
    readonly_paths = ["/etc/x", "/usr/x", "/x", "/opt/x"]
    for path in readonly_paths:
        result = run(agent, f"echo test > {path}")
        assert result["exit_code"] != 0, f"Should fail to write to {path}"
        assert "Read-only file system" in result["stderr"], f"Expected read-only error for {path}"

    # Test writable paths succeed
    writable_paths = ["/workspace/ok", "/tmp/ok"]
    for path in writable_paths:
        result = run(agent, f"echo test > {path} && cat {path}")
        assert result["exit_code"] == 0, f"Should succeed writing to {path}"
        assert result["stdout"].strip() == "test", f"Expected 'test' in {path}"


def test_no_secrets_in_environment(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer

    # Check environment inside container
    env_result = run(agent, "env")
    env_lines = env_result["stdout"].split('\n')

    # No secret variables
    secret_keywords = ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]
    for line in env_lines:
        for keyword in secret_keywords:
            if keyword in line:
                raise AssertionError(f"Found secret-like env var: {line}")

    # No verifier variables
    verifier_vars = ["TOOLGATE_SANDBOX_SOCKET", "VERIFY_WORKSPACES_VOLUME"]
    for var in verifier_vars:
        assert not any(line.startswith(var + "=") for line in env_lines), f"Verifier var {var} found in container"

    # Check Config.Env is subset of image env plus sandbox env
    container_env = set(inspect["Config"]["Env"])

    # Nothing beyond the image's own ENV and what the runner adds.
    image = docker.client.get(f"/v1.45/images/{os.environ['SANDBOX_IMAGE']}/json").json()
    allowed = set(image["Config"]["Env"]) | set(environment())
    assert container_env <= allowed, container_env - allowed
    expected_sandbox_vars = [
        "PATH=/workspace/.venv/bin:/workspace/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/tmp",
        "LANG=C.UTF-8",
        "TERM=dumb",
        "CONKER_SANDBOX=1"
    ]

    for var in expected_sandbox_vars:
        assert var in container_env, f"Expected sandbox env var {var} not found"


def test_namespaces_isolated(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer

    # Check namespace modes
    assert inspect["HostConfig"]["PidMode"] == ""
    assert inspect["HostConfig"]["IpcMode"] == "private"
    assert inspect["HostConfig"]["UTSMode"] == ""
    assert inspect["HostConfig"]["UsernsMode"] == ""

    # Inside container: check process count is limited
    ps_result = run(agent, "ps -e --no-headers | wc -l")
    proc_count = int(ps_result["stdout"].strip())
    assert proc_count <= 6, f"Expected at most 6 processes, got {proc_count}"

    # Check PID 1 is docker-init
    pid1_cmd = run(agent, "cat /proc/1/comm")
    assert "init" in pid1_cmd["stdout"].lower(), f"Expected PID 1 to be init, got {pid1_cmd['stdout']}"


def test_image_no_setuid_files():
    agent = unique_agent()
    # Check for setuid/setgid files
    result = run(agent, "find / -xdev -perm /6000 -type f 2>/dev/null")
    assert result["stdout"].strip() == "", f"Found setuid files: {result['stdout']}"


def test_container_removed_after_run(docker):
    agent = unique_agent()
    answer = run(agent, "echo test")
    assert answer["ok"], answer

    # Check no container with this agent label remains
    time.sleep(1)  # Give Docker time to clean up
    remaining = labelled(docker, "conker.sandbox.agent", agent)
    assert len(remaining) == 0, f"Container still exists for agent {agent}"


def test_runner_service_lockdown():
    runner_inspect = service("sandbox-runner")

    # Check runner service settings
    assert runner_inspect["HostConfig"]["NetworkMode"] == "none"
    assert runner_inspect["Config"]["User"] == "65533:65533"
    assert runner_inspect["HostConfig"]["ReadonlyRootfs"] is True
    assert runner_inspect["HostConfig"]["CapDrop"] == ["ALL"]
    assert "no-new-privileges:true" in runner_inspect["HostConfig"]["SecurityOpt"]

    # Check runner mounts
    runner_mounts = runner_inspect["Mounts"]
    mount_destinations = [m["Destination"] for m in runner_mounts]

    assert sorted(mount_destinations) == [
        "/run/conker-sandbox",
        "/var/run/docker.sock",
        "/workspaces",
    ]


def test_proxy_service_lockdown():
    proxy_inspect = service("package-proxy")

    # Check proxy service settings
    assert proxy_inspect["Config"]["User"] == "65532:65532"
    assert proxy_inspect["HostConfig"]["ReadonlyRootfs"] is True
    assert proxy_inspect["HostConfig"]["CapDrop"] == ["ALL"]
    assert "no-new-privileges:true" in proxy_inspect["HostConfig"]["SecurityOpt"]

    # Check proxy network
    proxy_networks = list(proxy_inspect["NetworkSettings"]["Networks"].keys())
    assert len(proxy_networks) == 1
    assert proxy_networks[0].endswith("_egress")

    # Check proxy mounts (no docker socket, only proxy volume)
    proxy_mounts = proxy_inspect["Mounts"]
    assert len(proxy_mounts) == 1
    assert proxy_mounts[0]["Destination"] == "/run/conker-proxy"


def test_runner_peer_check_unknown_uid():
    def _run_as_unknown_uid():
        from conftest import sandbox
        request = {"v": 1, "op": "run", "agent": "test", "command": "echo test", "timeout": 30}
        return sandbox(request)

    result = as_uid(1234, _run_as_unknown_uid)
    assert not result["ok"], "Should fail for unknown UID"
    assert result.get("code") == "not_permitted", f"Expected not_permitted, got {result}"
