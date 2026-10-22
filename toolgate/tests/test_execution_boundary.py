"""Retiring cognition must preserve history without preserving execution authority."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import approvals, control_plane, legacy_archive, vault


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_ADMIN_KEY", "archive-owner")
    monkeypatch.setenv("TOOLGATE_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", raising=False)
    control_plane._put(
        "ai_session",
        "original-session",
        {
            "messages": [
                {
                    "role": "user",
                    "content": "?????? ? keep my exact words",
                    "id": "original-message",
                }
            ],
            "proposal_request_id": "original-proposal",
            "draft": {"id": "retained-tool"},
        },
    )
    control_plane._put(
        "request",
        "original-proposal",
        {
            "kind": "ai_draft",
            "status": "pending",
            "payload": {
                "session_id": "original-session",
                "target_kind": "tool",
                "draft": {"id": "retained-tool", "execution": {"type": "echo"}},
            },
        },
    )
    control_plane.event(
        "ai_proposal_created",
        "info",
        "request",
        "original-proposal",
        "admin",
        {"session_id": "original-session"},
    )
    ordinary = approvals.create_request(
        "warning", "Still relevant", "Retain in queue", "admin"
    )
    return ordinary


def test_startup_retires_ai_routes_and_preserves_other_tools(store):
    with TestClient(server.app) as client:
        for method, path in [
            ("POST", "/v2/ai/conversation"),
            ("POST", "/v2/ai/proposals"),
            ("GET", "/v2/ai/sessions"),
            ("POST", "/v2/ai/sessions"),
            ("GET", "/v2/ai/sessions/original-session"),
            ("DELETE", "/v2/ai/sessions/original-session"),
            ("POST", "/v2/ai/sessions/original-session/messages"),
            ("POST", "/v2/ai/sessions/original-session/submit"),
        ]:
            assert (
                client.request(
                    method, path, json={}, headers={"X-ToolGate-Key": "archive-owner"}
                ).status_code
                == 404
            )
        assert not any(
            path.startswith("/v2/ai/")
            for path in client.get("/openapi.json").json()["paths"]
        )
        _, key = control_plane.issue_agent_key("search caller", ["tool:research.*"])
        tools = client.get(
            "/v2/agent/tools", headers={"X-ToolGate-Execution-Key": key}
        ).json()
        assert {"research.search", "research.fetch", "research.fetch-batch"} <= {
            t["id"] for t in tools
        }


def test_archive_export_is_lossless_idempotent_and_owner_only(store):
    with control_plane._conn() as conn:
        originals = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM v2_objects WHERE id IN ('original-session','original-proposal')"
            )
        ]
    with TestClient(server.app) as client:
        assert client.get("/v2/archives/ai").status_code == 401
        _, key = control_plane.issue_agent_key("agent", ["tool:*"])
        assert (
            client.get(
                "/v2/archives/ai", headers={"X-ToolGate-Execution-Key": key}
            ).status_code
            == 401
        )
        first = client.get(
            "/v2/archives/ai", headers={"X-ToolGate-Key": "archive-owner"}
        ).json()
        legacy_archive.migrate()
        assert first == legacy_archive.export()
    records = [
        record["row"]
        for record in first["records"]
        if record["source_table"] == "v2_objects"
    ]
    assert sorted(records, key=lambda r: r["id"]) == sorted(
        originals, key=lambda r: r["id"]
    )
    assert first["executable"] is False
    assert any(record["source_table"] == "v2_events" for record in first["records"])
    assert control_plane.list_objects("ai_session") == []
    assert [r["id"] for r in control_plane.list_objects("request")] == [store["id"]]


def test_archive_failure_rolls_back_every_retained_record(store):
    # A real SQLite abort after the first deletion exercises transaction recovery.
    with control_plane._conn() as conn:
        conn.execute("""CREATE TRIGGER fail_retirement BEFORE DELETE ON v2_objects
                        WHEN OLD.id='original-proposal' BEGIN SELECT RAISE(ABORT,'drill'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="drill"):
        legacy_archive.migrate()
    assert control_plane.get("ai_session", "original-session")
    assert control_plane.get("request", "original-proposal")
    with control_plane._conn() as conn:
        conn.execute("DROP TRIGGER fail_retirement")
    legacy_archive.migrate()
    assert (
        len(
            [
                r
                for r in legacy_archive.export()["records"]
                if r["source_table"] == "v2_objects"
            ]
        )
        == 2
    )


def test_collision_aborts_without_overwriting_the_archive(store):
    legacy_archive.migrate()
    original = legacy_archive.export()
    control_plane._put(
        "ai_session", "original-session", {"messages": ["different history"]}
    )
    with pytest.raises(RuntimeError, match="collision"):
        legacy_archive.migrate()
    assert legacy_archive.export() == original
    assert control_plane.get("ai_session", "original-session")["messages"] == [
        "different history"
    ]


def test_legacy_proposals_cannot_be_created_or_promoted_through_generic_requests(store):
    client = TestClient(server.app)
    owner = {"X-ToolGate-Key": "archive-owner"}
    # Also fails closed before startup migration, e.g. an old retained ID supplied directly.
    response = client.post(
        "/v2/requests/original-proposal/decision",
        json={"status": "approved"},
        headers=owner,
    )
    assert response.status_code == 410
    assert control_plane.get("tool", "retained-tool") is None
    assert control_plane.get("request", "original-proposal")["status"] == "pending"
    _, key = control_plane.issue_agent_key("agent", ["tool:*"])
    body = {
        "kind": "ai_draft",
        "title": "draft",
        "details": "legacy engine must stay gone",
    }
    for path, headers in [
        ("/v2/admin/requests", owner),
        ("/v2/requests", {"X-ToolGate-Execution-Key": key}),
    ]:
        assert client.post(path, json=body, headers=headers).status_code == 410
    client.close()


def test_generation_settings_migrate_without_changing_registered_tools(store):
    control_plane.update_settings(
        {"planner_url": "http://local-ollama:11434", "planner_model": "owner-model"},
        "admin",
    )
    legacy_archive.migrate()
    settings = control_plane.settings()
    assert settings["generation_url"] == "http://local-ollama:11434"
    assert settings["generation_model"] == "owner-model"
    assert "planner_url" not in settings and "planner_model" not in settings
