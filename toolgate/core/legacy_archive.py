"""Lossless retirement of the former AI workspace; never an execution source."""

from __future__ import annotations

import json

from toolgate.core import control_plane


def migrate() -> None:
    """Move sessions and proposals out of the live queue in one transaction.

    Store original SQLite rows, including their JSON text and timestamps. A
    future Pi importer must resolve collisions, not silently mint new IDs.
    """
    with control_plane._conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS v2_ai_archive (
            source_table TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
            original_row TEXT NOT NULL, PRIMARY KEY (source_table, kind, id)
        )""")
        rows = conn.execute(
            "SELECT * FROM v2_objects WHERE kind IN ('ai_session', 'request')"
        ).fetchall()
        retired = [
            dict(row)
            for row in rows
            if row["kind"] == "ai_session" or json.loads(row["body"]).get("kind") == "ai_draft"
        ]
        ids = {row["id"] for row in retired}
        events = [
            dict(row)
            for row in conn.execute("SELECT * FROM v2_events")
            if row["event_type"].startswith("ai_")
            or row["subject_type"] in {"ai_session", "planner"}
            or row["subject_id"] in ids
        ]
        for table, records in (("v2_objects", retired), ("v2_events", events)):
            for row in records:
                key = (table, row.get("kind", "event"), row["id"])
                original = json.dumps(row, ensure_ascii=False, sort_keys=True)
                existing = conn.execute(
                    "SELECT original_row FROM v2_ai_archive WHERE source_table=? AND kind=? AND id=?",
                    key,
                ).fetchone()
                if existing and existing[0] != original:
                    raise RuntimeError(
                        "AI archive ID collision; keep ToolGate stopped and compare the database with its backup"
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO v2_ai_archive VALUES (?,?,?,?)",
                    (*key, original),
                )
        for row in retired:
            conn.execute("DELETE FROM v2_objects WHERE kind=? AND id=?", (row["kind"], row["id"]))
        # Historical events remain visible in the ordinary audit log as well.
        settings = conn.execute(
            "SELECT body FROM v2_objects WHERE kind='settings' AND id='control-plane'"
        ).fetchone()
        if settings:
            body = json.loads(settings[0])
            for old, new in (
                ("planner_model", "generation_model"),
                ("planner_url", "generation_url"),
            ):
                if old in body:
                    body.setdefault(new, body.pop(old))
            conn.execute(
                "UPDATE v2_objects SET body=? WHERE kind='settings' AND id='control-plane'",
                (json.dumps(body),),
            )


def export() -> dict:
    """Return an owner-only handoff, preserving IDs, links and raw source rows."""
    with control_plane._conn() as conn:
        rows = conn.execute("SELECT * FROM v2_ai_archive ORDER BY source_table,kind,id").fetchall()
    return {
        "format": "toolgate.ai-archive",
        "version": 1,
        "source": "toolgate",
        "executable": False,
        "records": [
            {
                "source_table": row["source_table"],
                "kind": row["kind"],
                "id": row["id"],
                "row": json.loads(row["original_row"]),
            }
            for row in rows
        ],
    }
