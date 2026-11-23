"""The control plane's own tables and immutability triggers; schema_ledger runs them once.

control_plane re-exports SCHEMA, which schema_ledger reads as control_plane.SCHEMA.
"""

from __future__ import annotations

# The control plane's own tables and their immutability triggers (schema_ledger.BASELINE).
SCHEMA = """
    CREATE TABLE IF NOT EXISTS v2_objects (
      kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      PRIMARY KEY (kind, id)
    );
    CREATE TABLE IF NOT EXISTS v2_agent_keys (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
      scopes TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
      last_used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS v2_verification_origins (
      request_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS v2_events (
      id TEXT PRIMARY KEY, event_type TEXT NOT NULL, severity TEXT NOT NULL,
      subject_type TEXT, subject_id TEXT, actor TEXT, payload TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS v2_events_newest ON v2_events(created_at);
    CREATE TABLE IF NOT EXISTS v2_definition_versions (
      kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
      body TEXT NOT NULL, PRIMARY KEY(kind,id,version)
    );
    CREATE TABLE IF NOT EXISTS v2_publications (
      kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
      body TEXT NOT NULL, PRIMARY KEY(kind,id,version)
    );
    CREATE TRIGGER IF NOT EXISTS v2_versions_no_update BEFORE UPDATE ON v2_definition_versions
    BEGIN SELECT RAISE(ABORT, 'definition history is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS v2_versions_no_delete BEFORE DELETE ON v2_definition_versions
    BEGIN SELECT RAISE(ABORT, 'definition history is permanent'); END;
    CREATE TRIGGER IF NOT EXISTS v2_versions_no_replace BEFORE INSERT ON v2_definition_versions
    WHEN EXISTS(SELECT 1 FROM v2_definition_versions WHERE kind=NEW.kind AND id=NEW.id AND version=NEW.version)
    BEGIN SELECT RAISE(ABORT, 'definition revision already exists'); END;
    CREATE TRIGGER IF NOT EXISTS v2_publications_no_update BEFORE UPDATE ON v2_publications
    BEGIN SELECT RAISE(ABORT, 'publication is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS v2_publications_no_delete BEFORE DELETE ON v2_publications
    BEGIN SELECT RAISE(ABORT, 'publication is permanent'); END;
    CREATE TRIGGER IF NOT EXISTS v2_publications_no_replace BEFORE INSERT ON v2_publications
    WHEN EXISTS(SELECT 1 FROM v2_publications WHERE kind=NEW.kind AND id=NEW.id AND version=NEW.version)
    BEGIN SELECT RAISE(ABORT, 'publication already exists'); END;
"""
