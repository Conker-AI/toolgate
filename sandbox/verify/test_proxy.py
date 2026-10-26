"""Package proxy tests: pip, npm, allowlist, peer checks, install container shape."""

import time

from conftest import as_uid, install, logs, proxy_request, run, unique_agent, while_running


def test_pip_install_through_proxy():
    agent = unique_agent()
    answer = install(agent, "pip", ["six==1.17.0"])
    assert answer["ok"] and answer["exit_code"] == 0, answer

    # Check import works in later run
    check = run(agent, "python3 -c 'import six; print(six.__version__)'")
    assert check["stdout"].strip() == "1.17.0", check

    # Check proxy logs
    proxy_log = logs("package-proxy")
    assert "package_fetch" in proxy_log, "Expected package_fetch in proxy logs"
    assert "/pypi/simple/six/" in proxy_log, "Expected six simple fetch in logs"
    assert "/pypi/files/packages/" in proxy_log, "Expected package file fetch in logs"


def test_npm_install_through_proxy():
    agent = unique_agent()
    answer = install(agent, "npm", ["is-number@7.0.0"])
    assert answer["ok"] and answer["exit_code"] == 0, answer

    # Check require works
    check = run(agent, "node -e \"console.log(require('is-number'))\"")
    assert check["exit_code"] == 0, f"npm package check failed: {check}"


def test_install_container_shape(docker):
    agent = unique_agent()
    install_request = {
        "v": 1,
        "op": "install",
        "agent": agent,
        "manager": "pip",
        "packages": ["requests==2.32.3"],
        "timeout": 120,
    }

    inspect, answer = while_running(docker, agent, install_request=install_request)
    assert answer["ok"], answer

    # Check network is none
    assert inspect["HostConfig"]["NetworkMode"] == "none"

    # Check mounts: workspace volume + proxy volume read-only
    mounts = inspect["Mounts"]
    mount_destinations = [m["Destination"] for m in mounts]
    assert "/workspace" in mount_destinations
    assert "/run/conker-proxy" in mount_destinations

    # Check proxy mount is read-only
    proxy_mount = next(m for m in mounts if m["Destination"] == "/run/conker-proxy")
    assert proxy_mount["ReadOnly"] is True

    # Check user
    assert inspect["Config"]["User"] == "65533:65533"


def test_proxy_allowlist_pypi():
    # Test allowed PyPI requests as UID 65533
    status, body = proxy_request("GET", "/pypi/simple/six/")
    assert status == 200, f"Expected 200 for /pypi/simple/six/, got {status}"
    body_str = body.decode('utf-8')
    assert "/pypi/files/packages/" in body_str, "Expected package URLs in response"
    assert "https://files.pythonhosted.org" not in body_str, "Should not contain external URLs"


def test_proxy_allowlist_npm():
    # Test allowed npm request as UID 65533
    status, _body = proxy_request("GET", "/npm/is-number")
    assert status == 200, f"Expected 200 for /npm/is-number, got {status}"


def test_proxy_refused_methods():
    # Test refused methods as UID 65533
    refused_methods = [
        ("POST", "/npm/is-number"),
        ("PUT", "/npm/is-number"),
        ("DELETE", "/npm/is-number")
    ]

    for method, path in refused_methods:
        status, _ = proxy_request(method, path)
        assert status == 405, f"Expected 405 for {method} {path}, got {status}"


def test_proxy_refused_paths():
    # Test refused paths as UID 65533
    refused_paths = [
        ("GET", "/"),
        ("GET", "/http://example.com/"),
        ("GET", "/pypi/simple/../../etc/passwd"),
        ("GET", "/npm/-/npm/v1/security/advisories/bulk"),
        ("GET", "/github/x")
    ]

    for method, path in refused_paths:
        status, _ = proxy_request(method, path)
        assert status == 404, f"Expected 404 for {method} {path}, got {status}"


def test_proxy_absolute_form_request():
    # Test absolute-form request line as UID 65533
    def _absolute_request():
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect("/run/conker-proxy/proxy.sock")
            sock.send(b"GET http://example.com/ HTTP/1.0\r\n\r\n")
            response = sock.recv(1024)
            return response.decode('utf-8', errors='ignore')
        finally:
            sock.close()

    response = as_uid(65533, _absolute_request)
    # Should return 404 or 400
    assert "404" in response or "400" in response, f"Expected 404/400 for absolute-form, got: {response}"


def test_proxy_denied_logs():
    # Make some refused requests and check logs
    proxy_request("GET", "/")
    proxy_request("POST", "/npm/is-number")

    proxy_log = logs("package-proxy")
    assert "package_denied" in proxy_log, "Expected package_denied in proxy logs for refused requests"


def test_proxy_peer_check_verifier_uid():
    # Test as UID 0 (verifier) - should get closed
    def _request_as_uid0():
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect("/run/conker-proxy/proxy.sock")
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024)
            return response.decode('utf-8', errors='ignore')
        except Exception:
            return "closed"
        finally:
            sock.close()

    response = as_uid(0, _request_as_uid0)
    assert response == "closed", f"Expected 'closed' for UID 0, got {response}"


def test_refused_specs_no_container(docker):
    agent = unique_agent()

    # Try refused package spec - should not start container
    answer = install(agent, "pip", ["git+https://x"])
    assert not answer["ok"], "Should fail for refused package"
    assert answer.get("code") == "invalid_packages", f"Expected invalid_packages, got {answer}"

    # Check no container appeared
    time.sleep(1)
    containers = docker.find_by_label("conker.sandbox.agent", agent)
    assert len(containers) == 0, f"Container should not be created for refused spec: {containers}"
