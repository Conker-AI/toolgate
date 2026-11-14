"""Which schema steps a ToolGate database has, so the schema runs once per database.

Before this ledger every connection ran the whole control-plane and journal schema (several
`executescript` calls, each an implicit commit), several times per request. Now a connection
reads the ledger (`v2_schema_migrations`, one row per step) and runs the schema only when the
database lacks a step this code knows: a new database, one made before the ledger, or one restored
from an older snapshot. The ledger lives in the database itself, never in the process, so a restore
can never leave a database without its tables or immutability triggers.

Every step is idempotent (`IF NOT EXISTS`, guarded upgrades), and a database whose ledger is not
exactly this code's steps runs them all again on every connection: a database a newer ToolGate
upgraded (a rollback) gets what ToolGate did before the ledger, never less. A change to any schema
needs a new step; tests/test_schema_ledger.py pins the schema a fresh database gets.
"""

from __future__ import annotations

import sqlite3
import time

# Add a step (and its DDL) for every schema change; never edit or remove one.
STEPS = ("0001-baseline",)
LEDGER = "CREATE TABLE IF NOT EXISTS v2_schema_migrations (id TEXT PRIMARY KEY, applied_at REAL NOT NULL)"
# Objects a step retires. A ToolGate from before the ledger (a rollback) creates them again and
# leaves the ledger as it was, so their presence also means the schema must run.
RETIRED = ("v2_action_identity_immutable", "v2_action_result_immutable")
_STATE = (
    "SELECT (SELECT group_concat(id, ' ') FROM v2_schema_migrations), "
    f"(SELECT count(*) FROM sqlite_master WHERE name IN ({','.join('?' * len(RETIRED))}))"
)


def current(conn) -> bool:
    """Whether the database has exactly this code's steps and none of the objects they retire."""
    try:
        applied, retired = conn.execute(_STATE, RETIRED).fetchone()
    except sqlite3.OperationalError:  # no ledger yet: a new database or one from before it
        return False
    return not retired and set((applied or "").split()) == set(STEPS)


def ensure(conn) -> None:
    """Run the schema unless the database already has every step. Called on a fresh connection,
    before any transaction: a step's `executescript` commits."""
    if current(conn):
        return
    _baseline(conn)
    conn.execute(LEDGER)
    conn.executemany(
        "INSERT OR IGNORE INTO v2_schema_migrations(id, applied_at) VALUES (?, ?)",
        [(step, time.time()) for step in STEPS],
    )
    conn.commit()


def _baseline(conn) -> None:
    """0001: everything ToolGate ran on each connection before the ledger, in the same order."""
    from toolgate.core import control_plane, execution_journal

    conn.executescript(control_plane.SCHEMA)
    execution_journal.apply(conn)
