"""An upstream that answers with the wrong shape is a refusal or a fallback, never an
unhandled error (hunt toolgate-3 F24, toolgate-4 F7)."""

import json
from unittest.mock import patch

import httpx
import pytest

from toolgate.core import control_plane
from toolgate.executors import mcp_http as mcp
from toolgate.executors import research
from toolgate.tests.mcp_peer import URL, peer  # noqa: F401 - pytest fixture used by name


@pytest.mark.parametrize("version", [[], {}, ["2025-06-18"], None, 7])
def test_an_mcp_server_with_an_odd_protocol_version_is_refused(peer, version):
    answer = peer.handle

    def odd_version(request):
        response = answer(request)
        if request.method == "POST" and json.loads(request.content)["method"] == "initialize":
            body = json.loads(response.content)
            body["result"]["protocolVersion"] = version
            return httpx.Response(response.status_code, headers=response.headers, json=body)
        return response

    peer.handle = odd_version
    with pytest.raises(mcp.MCPError, match="protocol version"):
        mcp.discover(URL, "MCP_BEARER")


def test_a_provider_answering_a_list_falls_back_to_the_next_one(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    fallback = [{
        "title": "Manual receipt workflow", "url": "https://www.reddit.com/r/accounting/comments/x/y/",
        "snippet": "We manually enter every receipt.", "source": "reddit", "published_at": None,
        "content_safety": {"risk": "low", "flags": []},
    }]
    malformed = AttributeError("'list' object has no attribute 'get'")
    with patch.object(research, "_reddit_subreddit_feed", side_effect=malformed), \
         patch.object(research, "_reddit_subreddit_searx", return_value=fallback):
        result = research.search("subreddit:accounting", "reddit", 5, 14)
    assert result["provider"] == "searxng_subreddit"
    assert "reddit_atom_feed: AttributeError" in result["fallback_failures"]
