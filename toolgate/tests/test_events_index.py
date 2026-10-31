"""The event log is read newest first, so it carries an index on created_at.

Events are never deleted and the only other index on v2_events leads with
event_type, so without this one every `events()` call scans and sorts the
whole log.
"""

import pytest

from toolgate.core import control_plane as cp


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")


def test_newest_events_read_from_an_index_not_a_sort(tool):
    cp.event("a")
    cp.event("b")
    cp.event("c")
    with cp._conn() as conn:
        rows = conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM v2_events ORDER BY created_at DESC LIMIT ?",
            (10,),
        ).fetchall()
    plan = " ".join(row["detail"] for row in rows)
    assert "v2_events_newest" in plan
    assert "TEMP B-TREE" not in plan


def test_events_still_come_newest_first(tool, monkeypatch):
    times = iter(f"2026-10-31T00:00:0{second}+00:00" for second in range(3))
    monkeypatch.setattr(cp, "_now", lambda: next(times))
    cp.event("a")
    cp.event("b")
    cp.event("c")
    newest = cp.events(limit=2)
    assert [row["event_type"] for row in newest] == ["c", "b"]
    assert [row["event_type"] for row in cp.events(event_type="a")] == ["a"]
