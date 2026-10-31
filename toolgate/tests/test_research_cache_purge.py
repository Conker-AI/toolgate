"""Purging research results reads only their expiry and leaves every other object alone."""
from unittest.mock import patch

import pytest

from toolgate.core import control_plane, research_cache

NOW = research_cache.datetime(2026, 10, 31, tzinfo=research_cache.UTC)


@pytest.fixture(autouse=True)
def _database(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "toolgate-test.db")


def _cached(expires_at) -> str:
    row = research_cache.cache_research_result(
        {"title": "Page", "url": "https://example.com/", "document": "x" * 20000}, expires_at
    )
    return row["id"]


def test_only_expired_or_unreadable_results_are_deleted():
    kept = _cached("2026-11-01T00:00:00+00:00")
    gone = [
        _cached("2026-10-30T00:00:00+00:00"),
        _cached("2026-10-31T00:00:00+00:00"),
        _cached("not a date"),
        _cached("2026-10-30T00:00:00"),
        _cached(None),
        _cached(17),
    ]
    no_expiry = {"url": "https://example.com/"}
    control_plane._put("research_result", "rr_no_expiry_field_here", no_expiry)
    control_plane._put("tool", gone[0], {"expires_at": "2000-01-01T00:00:00+00:00"})
    with patch.object(control_plane, "_row", side_effect=AssertionError("purge parsed a body")):
        assert research_cache.purge_expired_research_results(NOW) == len(gone) + 1
    assert research_cache.get_research_result(kept)["url"] == "https://example.com/"
    assert all(research_cache.get_research_result(identity) is None for identity in gone)
    assert control_plane.get("tool", gone[0]) is not None
    assert research_cache.purge_expired_research_results(NOW) == 0
