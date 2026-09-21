import copy
import json

import httpx
import pytest

from toolgate.executors import container_control as docker
from toolgate.executors import port_preview as adapter
from toolgate.executors.port_plan import PlanError

CID = "a" * 64
MAPPING = {"hostAddress": "127.0.0.1", "hostPort": 9090,
           "containerPort": 90, "protocol": "tcp"}


def inspection():
    return {"Id": CID, "Config": {"Env": ["SECRET=private-value"]},
            "State": {"Running": True, "Status": "running", "Paused": False,
                      "Restarting": False, "Dead": False},
            "HostConfig": {"NetworkMode": "bridge", "PublishAllPorts": False,
                           "AutoRemove": False,
                           "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": ""}]}},
            "NetworkSettings": {"Ports": {
                "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "32768"},
                           {"HostIp": "::", "HostPort": "32768"}], "81/tcp": None}}}


def test_running_preview_uses_allocated_ports_and_preserves_ipv6():
    source = inspection()
    unchanged = copy.deepcopy(source)
    result = adapter.from_inspection(CID, source, "create", mapping=MAPPING)
    assert source == unchanged
    assert len(result["before"]) == 2 and len(result["after"]) == 3
    assert {x["hostAddress"] for x in result["before"]} == {"0.0.0.0", "::"}
    assert {x["hostPort"] for x in result["before"]} == {32768}
    assert result["downtimeExpected"] and result["bindingSource"] == "observed"
    assert "private-value" not in json.dumps(result) and "Config" not in result


def test_stopped_preview_requires_concrete_configuration():
    source = inspection()
    source["State"].update(Running=False, Status="exited")
    with pytest.raises(PlanError, match="different"):
        adapter.from_inspection(CID, source, "create", mapping=MAPPING)
    source["HostConfig"]["PortBindings"] = {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
    result = adapter.from_inspection(CID, source, "create", mapping=MAPPING)
    assert not result["downtimeExpected"] and result["bindingSource"] == "configured"
    assert result["before"][0]["hostPort"] == 8080


@pytest.mark.parametrize("ports", [None, {}, {"80/tcp": None}])
def test_missing_runtime_publication_cannot_erase_declared_binding(ports):
    source = inspection()
    source["NetworkSettings"]["Ports"] = ports
    with pytest.raises(PlanError):
        adapter.from_inspection(CID, source, "create", mapping=MAPPING)


@pytest.mark.parametrize("ports", [[], {"80/sctp": []}, {"70000/tcp": None},
                                   {"80/tcp": [{"HostIp": "", "HostPort": "1234"}]},
                                   {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "0"}]},
                                   {"80/tcp": [{"HostIp": "localhost", "HostPort": "80"}]},
                                   {"80/tcp": [None]}, {"80/tcp": "bad"}])
def test_invalid_or_unresolved_binding_is_never_silently_dropped(ports):
    source = inspection()
    source["NetworkSettings"]["Ports"] = ports
    with pytest.raises(PlanError):
        adapter.from_inspection(CID, source, "create", mapping=MAPPING)


@pytest.mark.parametrize("field,value", [("Paused", True), ("Restarting", True),
                                        ("Dead", True), ("Status", "removing")])
def test_transitional_container_needs_reinspection(field, value):
    source = inspection()
    source["State"][field] = value
    with pytest.raises(PlanError):
        adapter.from_inspection(CID, source, "create", mapping=MAPPING)


@pytest.mark.parametrize("change", ["identity", "state", "missing"])
def test_malformed_inspect_static_error(change):
    source = inspection()
    if change == "identity":
        source["Id"] = "b" * 64
    elif change == "state":
        source["State"]["Running"] = "private-value"
    else:
        del source["HostConfig"]
    with pytest.raises(docker.ControlError) as error:
        adapter.from_inspection(CID, source, "create", mapping=MAPPING)
    assert error.value.code == "invalid_response"
    assert "private-value" not in str(error.value)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/synthetic/docker.sock")
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps([CID]))


class Stream(httpx.SyncByteStream):
    def __init__(self, value):
        self.value = value

    def __iter__(self):
        yield self.value


def test_transport_is_fixed_get_and_redacted(configured):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, stream=Stream(json.dumps(inspection()).encode()))

    result = adapter.preview(CID, "create", mapping=MAPPING, transport=httpx.MockTransport(handle))
    assert len(seen) == 1 and seen[0].method == "GET"
    assert seen[0].url.path == f"/v1.45/containers/{CID}/json"
    assert "private-value" not in json.dumps(result)
    assert result["execution"] == "not_implemented"


@pytest.mark.parametrize("failure", ["revoked", "redirect", "duplicate", "oversized", "timeout"])
def test_transport_failure_is_bounded_static_and_not_retried(configured, monkeypatch, failure):
    seen = []

    def handle(request):
        seen.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("private-value")
        if failure == "revoked":
            monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", "[]")
        body = (b'{"Id":"private-value","Id":"duplicate"}' if failure == "duplicate"
                else b"x" * (docker.MAX_BYTES + 1) if failure == "oversized"
                else json.dumps(inspection()).encode())
        return httpx.Response(307 if failure == "redirect" else 200, stream=Stream(body))

    with pytest.raises(docker.ControlError) as error:
        adapter.preview(CID, "create", mapping=MAPPING, transport=httpx.MockTransport(handle))
    assert len(seen) == 1 and seen[0].method == "GET"
    assert "private-value" not in str(error.value)
