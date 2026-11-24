"""The event log: write, list, count and latest.

Split from control_plane.py (a move): storage, the clock and the connection go through the `cp`
module, so a test that patches control_plane._now or _conn still reaches them. Import control_plane,
not this module; it re-exports these names."""

from __future__ import annotations

import json
import uuid
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta

from toolgate.core import control_plane as cp


def event(
    event_type: str,
    severity: str = "info",
    subject_type: str | None = None,
    subject_id: str | None = None,
    actor: str | None = None,
    payload: dict | None = None,
    *,
    connection=None,
) -> dict:
    """Record an event; pass the caller's `connection` to write it in the caller's transaction."""
    record = {
        "id": str(uuid.uuid4()),
        "event_type": event_type,
        "severity": severity,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "actor": actor,
        "payload": payload or {},
        "created_at": cp._now(),
    }
    with nullcontext(connection) if connection is not None else cp._conn() as conn:
        conn.execute(
            "INSERT INTO v2_events VALUES(?,?,?,?,?,?,?,?)",
            (
                record["id"],
                record["event_type"],
                record["severity"],
                record["subject_type"],
                record["subject_id"],
                record["actor"],
                json.dumps(record["payload"]),
                record["created_at"],
            ),
        )
    return record


def events(limit: int = 100, event_type: str | None = None) -> list[dict]:
    query, params = "SELECT * FROM v2_events", []
    if event_type:
        query += " WHERE event_type=?"
        params.append(event_type)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(min(max(limit, 1), 500))
    with cp._conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]


def event_count_since(event_type: str, subject_type: str, subject_id: str, seconds: int) -> int:
    cutoff = (datetime.now(UTC) - timedelta(seconds=max(seconds, 0))).isoformat()
    with cp._conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM v2_events "
            "WHERE event_type=? AND subject_type=? AND subject_id=? AND created_at>=?",
            (event_type, subject_type, subject_id, cutoff),
        ).fetchone()
    return int(row["count"])


def latest_event_at(event_type: str, subject_type: str, subject_id: str) -> datetime | None:
    with cp._conn() as conn:
        row = conn.execute(
            "SELECT created_at FROM v2_events WHERE event_type=? AND subject_type=? AND subject_id=? "
            "ORDER BY created_at DESC LIMIT 1",
            (event_type, subject_type, subject_id),
        ).fetchone()
    return datetime.fromisoformat(row["created_at"]) if row else None
