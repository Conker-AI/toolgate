import json

import httpx
import pytest

from toolgate.core import control_plane
from toolgate.executors import container_control as adapter

CID = "a" * 64


@pytest.fixture(autouse=True)
def configured(monkeypatch, tmp_path):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/synthetic/docker.sock")
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps([CID]))


def inspection():
    return {"Id": CID, "Config": {"Env": ["SECRET=never-return-this"]}, "State": {
        "Status": "running", "Running": True, "Paused": False, "Restarting": False,
        "Dead": False, "Error": "sensitive-diagnostic",
    }}


class Stream(httpx.SyncByteStream):
    def __init__(self, data):
        self.data = data

    def __iter__(self):
        yield self.data


def response(value):
    return httpx.Response(200, stream=Stream(json.dumps(value).encode()))


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_fixed_dispatch_observed_projection(action):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(204, stream=Stream(b"")) if request.method == "POST" else response(inspection())

    result = adapter.control(CID, action, transport=httpx.MockTransport(handle))
    assert [r.method for r in requests] == ["GET", "POST", "GET"]
    assert requests[1].url.path == f"/v1.45/containers/{CID}/{action}"
    assert dict(requests[1].url.params) == ({} if action == "start" else {"t": "10"})
    assert result["outcome"] == "observed"
    assert set(result["after"]) == {"status", "running", "paused", "restarting", "dead"}
    assert "SECRET" not in json.dumps(result)
    assert "sensitive" not in json.dumps(result)


@pytest.mark.parametrize("cid,action", [("abc", "start"), (CID, "kill"), (CID, []), (None, "stop")])
def test_bad_arguments(cid, action):
    with pytest.raises(adapter.ControlError, match="arguments"):
        adapter.control(cid, action)


@pytest.mark.parametrize("socket,ids,code", [
    ("", [CID], "not_configured"), ("relative", [CID], "invalid_configuration"),
    ("/foo/../sock", [CID], "invalid_configuration"), ("/sock", [], "not_managed"),
    ("/sock", ["short"], "invalid_configuration"),
])
def test_configuration_denies_before_transport(monkeypatch, socket, ids, code):
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", socket)
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps(ids))
    with pytest.raises(adapter.ControlError) as error:
        adapter.control(CID, "start")
    assert error.value.code == code


@pytest.mark.parametrize("change", ["revoke", "socket"])
def test_recheck_before_dispatch(monkeypatch, change):
    methods = []

    def handle(request):
        methods.append(request.method)
        monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS" if change == "revoke" else "TOOLGATE_DOCKER_SOCKET",
                           "[]" if change == "revoke" else "/different.sock")
        return response(inspection())

    with pytest.raises(adapter.ControlError):
        adapter.control(CID, "stop", transport=httpx.MockTransport(handle))
    assert methods == ["GET"]


@pytest.mark.parametrize("phase", ["post_error", "post_500", "post_redirect", "after_error", "after_invalid"])
def test_post_dispatch_never_retried_and_unknown(phase):
    methods = []

    def handle(request):
        methods.append(request.method)
        if len(methods) == 1:
            return response(inspection())
        if request.method == "POST":
            if phase == "post_error":
                raise httpx.ReadTimeout("SECRET")
            status = {"post_500": 500, "post_redirect": 307}.get(phase, 204)
            return httpx.Response(status, stream=Stream(b""))
        if phase == "after_error":
            raise httpx.ConnectError("SECRET")
        return response({"Id": "b" * 64})

    with pytest.raises(adapter.OutcomeUnknown) as error:
        adapter.control(CID, "restart", transport=httpx.MockTransport(handle))
    assert methods.count("POST") == 1
    assert "SECRET" not in str(error.value)


@pytest.mark.parametrize("kind", ["wrong_id", "bad_state", "oversized", "unavailable"])
def test_bad_inspection_never_mutates(kind):
    methods = []

    def handle(request):
        methods.append(request.method)
        value = inspection()
        if kind == "wrong_id":
            value["Id"] = "b" * 64
        if kind == "bad_state":
            value["State"]["Running"] = 1
        if kind == "oversized":
            return httpx.Response(200, stream=Stream(b"x" * (adapter.MAX_BYTES + 1)))
        if kind == "unavailable":
            return httpx.Response(404, stream=Stream(b"SECRET"))
        return response(value)

    with pytest.raises(adapter.ControlError):
        adapter.control(CID, "start", transport=httpx.MockTransport(handle))
    assert methods == ["GET"]


def test_pre_dispatch_transport_error_static():
    def handle(request):
        raise httpx.ConnectError("private socket path SECRET")

    with pytest.raises(adapter.ControlError) as error:
        adapter.control(CID, "start", transport=httpx.MockTransport(handle))
    assert error.value.code == "unavailable"
    assert "SECRET" not in str(error.value)


def test_post_response_limit_is_unknown():
    methods = []

    def handle(request):
        methods.append(request.method)
        if request.method == "GET":
            return response(inspection())
        return httpx.Response(204, stream=Stream(b"x" * (adapter.MAX_BYTES + 1)))

    with pytest.raises(adapter.OutcomeUnknown):
        adapter.control(CID, "stop", transport=httpx.MockTransport(handle))
    assert methods == ["GET", "POST"]


def test_deadline_before_dispatch(monkeypatch):
    now = [0.0]
    methods = []
    monkeypatch.setattr(adapter.time, "monotonic", lambda: now[0])

    def handle(request):
        methods.append(request.method)
        now[0] = 100.0
        return response(inspection())

    with pytest.raises(adapter.ControlError) as error:
        adapter.control(CID, "start", transport=httpx.MockTransport(handle))
    assert error.value.code == "deadline"
    assert methods == ["GET"]
