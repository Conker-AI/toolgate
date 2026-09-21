import copy
import json

import httpx
import pytest

from toolgate.executors import system_inventory as adapter


def envelope():
    section = {"status": "ok", "results": [], "truncated": False, "errors": []}
    return {
        "mode": "observed",
        "sampledAt": "2026-09-21T12:00:00+00:00",
        "ageSeconds": 0,
        "collectionSeconds": 0,
        "source": {
            "procfs": "/proc",
            "processScope": "collector-namespace",
            "networkScope": "collector-namespace",
            "containerScope": "configured-docker-daemon",
        },
        "status": "ok",
        "processes": copy.deepcopy(section),
        "containers": copy.deepcopy(section),
        "ports": copy.deepcopy(section),
        "capabilities": {
            "inspection": True,
            "processActions": False,
            "containerActions": False,
            "portMutation": False,
            "terminal": False,
            "files": False,
        },
        "unavailableFields": [],
    }


class Stream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks

    def __iter__(self):
        yield from self.chunks


@pytest.fixture(autouse=True)
def configuration(monkeypatch):
    monkeypatch.setenv("TOOLGATE_SYSTEMGATE_URL", "http://systemgate.internal:8040")
    monkeypatch.setenv("TOOLGATE_SYSTEMGATE_KEY", "synthetic-inventory-key")


def transport(value=None, status=200, headers=None):
    return httpx.MockTransport(
        lambda request: httpx.Response(
            status,
            headers=headers,
            stream=Stream(
                [json.dumps(value if value is not None else envelope()).encode()]
            ),
        )
    )


def test_fixed_authenticated_get_without_proxy_redirects(monkeypatch):
    seen = []
    monkeypatch.setenv("HTTP_PROXY", "http://must-not-use.invalid:8080")

    def handler(request):
        seen.append(request)
        return httpx.Response(200, stream=Stream([json.dumps(envelope()).encode()]))

    result = adapter.collect(19, transport=httpx.MockTransport(handler))
    assert result["mode"] == "observed"
    assert str(seen[0].url) == "http://systemgate.internal:8040/runtime?limit=19"
    assert seen[0].method == "GET"
    assert seen[0].headers["X-SystemGate-Key"] == "synthetic-inventory-key"
    assert "synthetic-inventory-key" not in str(result)
    assert seen[0].headers["Accept-Encoding"] == "identity"


@pytest.mark.parametrize("limit", [True, False, 0, 201, 1.0, "10", None])
def test_invalid_limits_never_dispatch(limit):
    with pytest.raises(adapter.InventoryError) as exc:
        adapter.collect(
            limit, transport=httpx.MockTransport(lambda r: pytest.fail("dispatched"))
        )
    assert exc.value.code == "invalid_limit" and exc.value.status == 422


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://name/path",
        "http://user:key@name",
        "https://name/?query=1",
        "https://name/#fragment",
        "file:///tmp/test",
        "http://name:70000",
        "http://na me",
    ],
)
def test_configuration_has_no_default_or_caller_path(monkeypatch, url):
    monkeypatch.setenv("TOOLGATE_SYSTEMGATE_URL", url)
    with pytest.raises(adapter.InventoryError):
        adapter.collect(
            transport=httpx.MockTransport(lambda r: pytest.fail("dispatched"))
        )


@pytest.mark.parametrize("status", [301, 302, 401, 403, 500])
def test_upstream_failures_are_static(status):
    with pytest.raises(adapter.InventoryError) as exc:
        adapter.collect(
            transport=transport(
                {"secret": "raw error"}, status, {"Location": "http://elsewhere"}
            )
        )
    assert str(exc.value) == "SystemGate inventory is unavailable."


@pytest.mark.parametrize(
    "change",
    [
        lambda x: x.update(ageSeconds=float("nan")),
        lambda x: x.update(collectionSeconds=float("inf")),
        lambda x: x.update(sampledAt="2026-09-21T12:00:00"),
        lambda x: x["capabilities"].update(terminal=True),
        lambda x: x.update(secret="synthetic-inventory-key"),
        lambda x: x["unavailableFields"].append("synthetic-inventory-key"),
        lambda x: x["processes"].update(errors=["raw upstream error"]),
        lambda x: x.update(status="partial"),
        lambda x: x["ports"].update(results=[{}]),
    ],
)
def test_invalid_envelopes_are_rejected(change):
    value = envelope()
    change(value)
    with pytest.raises(adapter.InventoryError) as exc:
        adapter.collect(transport=transport(value))
    assert exc.value.code == "invalid_response"
    assert "synthetic-inventory-key" not in str(exc.value)


def test_byte_cap_encoding_and_deadline(monkeypatch):
    monkeypatch.setattr(adapter, "MAX_BYTES", 10)
    with pytest.raises(adapter.InventoryError, match="response limit"):
        adapter.collect(transport=transport())
    monkeypatch.setattr(adapter, "MAX_BYTES", 1024 * 1024)
    with pytest.raises(adapter.InventoryError, match="invalid response"):
        adapter.collect(transport=transport(headers={"Content-Encoding": "gzip"}))
    times = iter([0, 11])
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(times))
    with pytest.raises(adapter.InventoryError, match="deadline"):
        adapter.collect(transport=transport())


def test_timeout_hides_transport_detail():
    def fail(request):
        raise httpx.ReadTimeout("synthetic-inventory-key private host")

    with pytest.raises(adapter.InventoryError) as exc:
        adapter.collect(transport=httpx.MockTransport(fail))
    assert exc.value.code == "unavailable"
    assert "private" not in str(exc.value) and exc.value.__cause__ is None


def test_partial_and_observed_rows():
    value = envelope()
    value["processes"]["results"] = [
        {
            "id": "process:42:0x1.ee00000000000p+6",
            "pid": 42,
            "createdAt": 123.5,
            "name": "worker",
            "status": "sleeping",
            "memoryBytes": 4000,
            "cpuPercent": None,
            "command": None,
            "user": None,
            "restarts": None,
            "containerId": None,
            "managed": False,
        }
    ]
    value["containers"].update(status="unavailable", errors=["collection_failed"])
    value["ports"].update(status="partial", errors=["container_bindings_unavailable"])
    value["status"] = "partial"
    assert adapter.collect(transport=transport(value))["status"] == "partial"
    value["processes"]["results"] *= 2
    with pytest.raises(adapter.InventoryError, match="invalid response"):
        adapter.collect(transport=transport(value))


def test_duplicate_json_keys_and_numeric_capability():
    raw = json.dumps(envelope()).replace(
        '"mode": "observed"', '"mode":"fixture","mode":"observed"'
    )
    with pytest.raises(adapter.InventoryError, match="invalid response"):
        adapter.collect(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, stream=Stream([raw.encode()]))
            )
        )
    value = envelope()
    value["capabilities"]["terminal"] = 0
    with pytest.raises(adapter.InventoryError, match="invalid response"):
        adapter.collect(transport=transport(value))
