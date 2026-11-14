"""The schema runs once per database, never less than before the ledger (schema_ledger.py)."""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from toolgate.core import control_plane, execution_journal, schema_ledger

# sha256 of the schema a fresh database gets (see _schema). A schema change needs a new step in
# schema_ledger.STEPS, then this pin; a database made before the change runs the new step.
SCHEMA_PIN = "9ea7b3f9100ed9e9ba2ac1fd33ec993a4d292b1450f50ef1d54b1de9c1de3735"


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "toolgate.db"
    monkeypatch.setattr(control_plane, "DB_PATH", path)
    return path


def _schema(path) -> str:
    with sqlite3.connect(path) as db:
        rows = db.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def _statements(path) -> list[str]:
    """What one control-plane connection runs before its caller's own statements."""
    seen: list[str] = []
    original = sqlite3.connect

    def traced(*args, **kwargs):
        connection = original(*args, **kwargs)
        connection.set_trace_callback(seen.append)
        return connection

    control_plane.sqlite3.connect = traced
    try:
        with control_plane._conn():
            pass
    finally:
        control_plane.sqlite3.connect = original
    return seen


def _ddl(statements: list[str]) -> list[str]:
    return [s for s in statements if s.lstrip().upper().startswith(("CREATE", "DROP", "ALTER"))]


def test_a_fresh_database_gets_the_whole_schema_and_its_ledger(database):
    with control_plane._conn() as conn:
        steps = [row["id"] for row in conn.execute("SELECT id FROM v2_schema_migrations")]
    assert steps == list(schema_ledger.STEPS)
    assert _schema(database) == SCHEMA_PIN


def test_a_current_database_runs_no_schema_on_a_new_connection(database):
    with control_plane._conn():
        pass
    statements = _statements(database)
    assert _ddl(statements) == []
    assert statements == [schema_ledger._STATE.replace("?", "'%s'") % schema_ledger.RETIRED]


def test_the_journal_and_spending_initializers_run_nothing_on_a_current_database(database):
    from toolgate.core import spending, spending_allowances

    with control_plane._conn():
        pass
    with sqlite3.connect(database) as conn:
        seen: list[str] = []
        conn.set_trace_callback(seen.append)
        execution_journal.initialize(conn)
        spending.initialize(conn)
        spending_allowances.initialize(conn)
    assert _ddl(seen) == []


def test_a_database_from_before_the_ledger_gets_its_schema_and_old_triggers_retired(database):
    with control_plane._conn():
        pass
    with sqlite3.connect(database) as db:  # as ToolGate 0.16 left it: no ledger, old triggers
        db.execute("DROP TABLE v2_schema_migrations")
        db.execute("DROP TRIGGER v2_actions_no_delete")
        for name in execution_journal.OLD_TRIGGERS:
            db.execute(
                f"CREATE TRIGGER {name} BEFORE UPDATE ON v2_actions "
                "BEGIN SELECT RAISE(ABORT, 'old'); END"
            )
    with control_plane._conn() as conn:
        triggers = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        }
        steps = [row["id"] for row in conn.execute("SELECT id FROM v2_schema_migrations")]
    assert "v2_actions_no_delete" in triggers
    assert not triggers & set(execution_journal.OLD_TRIGGERS)
    assert steps == list(schema_ledger.STEPS)
    assert _schema(database) == SCHEMA_PIN


def test_a_ledger_with_a_step_this_code_does_not_know_runs_the_schema_every_time(database):
    with control_plane._conn():
        pass
    with sqlite3.connect(database) as db:  # a newer ToolGate upgraded it, then it was rolled back
        db.execute("INSERT INTO v2_schema_migrations VALUES ('9999-newer', 0)")
        db.execute("DROP TRIGGER v2_publications_no_update")
    assert _ddl(_statements(database))
    with sqlite3.connect(database) as db:
        assert db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='v2_publications_no_update'"
        ).fetchone()
    assert _ddl(_statements(database)), "still not exactly this code's steps: it keeps running"


def test_the_immutability_triggers_hold_on_a_current_database(database):
    with control_plane._conn():
        pass
    with control_plane._conn() as conn:  # no schema ran on this connection
        conn.execute("INSERT INTO v2_publications VALUES ('tool','t',1,'{}')")
    with (
        pytest.raises(sqlite3.IntegrityError, match="publication is immutable"),
        control_plane._conn() as conn,
    ):
        conn.execute("UPDATE v2_publications SET body='x'")
