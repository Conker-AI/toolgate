"""A SearXNG search keeps the owner's recency window (hunt toolgate-4 F3)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from toolgate.core import control_plane
from toolgate.executors import research_base, research_web


@pytest.mark.parametrize(("days", "window"), [
    (1, "day"), (3, "week"), (7, "week"), (14, "month"), (31, "month"), (90, "year"), (400, None),
])
def test_the_narrowest_searxng_window_that_covers_the_request(days, window):
    assert research_web._searx_time_range(days).get("time_range") == window


def test_rows_dated_before_the_window_are_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    now = datetime.now(UTC)
    answer = Mock(content=b"{}", raise_for_status=Mock())
    answer.json.return_value = {"results": [
        {"title": "Old", "url": "https://a.example.com/old", "content": "old",
         "publishedDate": (now - timedelta(days=20)).isoformat()},
        {"title": "New", "url": "https://a.example.com/new", "content": "new",
         "publishedDate": (now - timedelta(days=2)).isoformat()},
        {"title": "Undated", "url": "https://a.example.com/undated", "content": "undated"},
    ]}
    with patch.object(research_base, "_public_https_url", return_value=True), \
         patch.object(research_web.httpx, "get", return_value=answer) as get:
        rows = research_web._searx("invoice tools", "general", 5, 7, 5)
    assert get.call_args.kwargs["params"]["time_range"] == "week"
    assert [row["title"] for row in rows] == ["New", "Undated"]
