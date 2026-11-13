"""An HTTP tool stops reading at its byte cap instead of downloading the whole body first
(hunt toolgate-1 F3)."""

import httpx
import pytest

from toolgate.api import dispatch, invocation
from toolgate.core import control_plane

CHUNK = 64 * 1024


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(dispatch, "public_url", lambda url: True)
    return {"id": "http", "name": "HTTP", "version": 1, "authorization": "auto", "status": "active",
            "inputs": [], "outputs": [], "execution": {
                "type": "http_json", "billing": {"mode": "free"}, "url": "https://api.example.com/x",
                "allowed_hosts": ["api.example.com"], "max_response_bytes": 4 * CHUNK}}


def upstream(monkeypatch, body):
    monkeypatch.setattr(dispatch, "public_client", lambda timeout, headers: httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body)),
        headers=headers))


def test_a_huge_body_is_cut_off_just_past_the_cap(tool, monkeypatch):
    pulled = []

    def endless():
        for _ in range(400):  # 25 MiB if it were all read
            pulled.append(CHUNK)
            yield b"x" * CHUNK

    upstream(monkeypatch, endless())
    result = invocation.invoke_tool(tool, {}, "Actor", actor_id="agent", action_id="huge")
    assert result["code"] == "OUTCOME_UNKNOWN"  # sent, so the upstream may have acted
    assert len(pulled) <= 6


def test_a_body_within_the_cap_is_parsed(tool, monkeypatch):
    upstream(monkeypatch, iter([b'{"items": ', b'[1, 2]}']))
    result = invocation.invoke_tool(tool, {}, "Actor", actor_id="agent", action_id="small")
    assert (result["code"], result["result"]["result"]) == ("OK", {"items": [1, 2]})
