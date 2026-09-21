import sqlite3

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import owner_channel as owner
from toolgate.core import publications as pub


@pytest.fixture
def published(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "published-runs.db")
    tool = cp.create_tool({"id": "child", "name": "Child", "description": "Local echo",
                           "execution": {"type": "echo"}, "status": "active"})
    flow = cp.create_automation({"id": "flow", "name": "Flow", "description": "Local workflow",
                                 "status": "active", "workflow": [{"type": "tool_call", "tool_id": "child"}]})
    pub.publish("tool", "child", 1)
    pub.publish("automation", "flow", 1)
    agent, _ = cp.issue_agent_key("Caller", ["child", "automation:flow"])
    calls = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda tool, args: calls.append(tool) or {"ok": True, "result": {}})
    return tool, flow, agent, calls


def test_published_workflow_uses_exact_old_workflow_and_child_after_edits(published):
    tool, flow, agent, calls = published
    cp.update_tool("child", {**tool, "execution": {"type": "local_echo"}})
    cp.update_automation("flow", {**flow, "workflow": [{"type": "return", "value": "new"}]})
    payload = server.V2Invoke(action_id="published-run", published_version=1, job_id="scheduled-job")
    result = server.run_automation("flow", payload, agent)
    assert result["code"] == "OK"
    assert calls == [tool]
    assert result["publication"]["version"] == 1
    assert journal.get("published-run")["version"] == 1
    assert server.run_automation("flow", payload, agent) == result
    assert len(calls) == 1


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_publication_is_part_of_idempotency_identity(published, kind):
    tool, flow, agent, calls = published
    definition = tool if kind == "tool" else flow
    obj_id = definition["id"]
    run = server.run_tool if kind == "tool" else server.run_automation
    run(obj_id, server.V2Invoke(action_id="same", published_version=1), agent)
    getattr(cp, f"update_{kind}")(obj_id, definition)
    pub.publish(kind, obj_id, 2)
    for version in [2, None]:
        with pytest.raises(HTTPException) as error:
            run(obj_id, server.V2Invoke(action_id="same", published_version=version), agent)
        assert error.value.detail["code"] == "ACTION_CONFLICT"
    assert len(calls) == 1


@pytest.mark.parametrize("edit", ["blocked", "inactive", "policy", "confirmation", "delete", "recreate"])
def test_current_revocation_of_child_prevents_published_dispatch(published, edit):
    tool, _, agent, calls = published
    if edit in {"delete", "recreate"}:
        cp.remove("tool", "child")
        if edit == "recreate":
            cp.create_tool(tool)
    else:
        fields = {"blocked": {"authorization": "blocked"}, "inactive": {"status": "inactive"},
                  "policy": {"policy": {"usage_limits": {"max_per_day": 1}}},
                  "confirmation": {"authorization": "owner_confirmation"}}[edit]
        cp.update_tool("child", {**tool, **fields})
    with pytest.raises(pub.PublicationInvalid):
        server.run_automation("flow", server.V2Invoke(action_id="revoked", published_version=1), agent)
    assert calls == [] and journal.get("revoked") is None


def test_confirmation_binds_publication_and_survives_definition_only_edits(published):
    tool, flow, agent, calls = published
    tool = cp.update_tool("child", {**tool, "authorization": "owner_confirmation"})
    flow = cp.update_automation("flow", {**flow, "authorization": "owner_confirmation"})
    pub.publish("automation", "flow", 2)
    payload = server.V2Invoke(action_id="confirm", published_version=2)
    pending = server.run_automation("flow", payload, agent)
    request = cp.get("request", pending["request_id"])
    assert request["payload"]["binding"]["publication_digest"] == pub.get("automation", "flow", 2, published=True)["digest"]
    cp.decide_request(pending["request_id"], "approved", "owner")
    payload.approval_request_id = pending["request_id"]
    cp.update_tool("child", {**tool, "name": "Renamed after approval"})
    cp.update_automation("flow", {**flow, "name": "Renamed after approval"})
    result = server.run_automation("flow", payload, agent)
    assert result["code"] == "OK" and calls == [tool]


def test_live_approval_cannot_authorize_published_tool(published):
    tool, _, agent, calls = published
    tool = cp.update_tool("child", {**tool, "authorization": "owner_confirmation"})
    pub.publish("tool", "child", 2)
    pending = server.run_tool("child", server.V2Invoke(action_id="approve"), agent)
    cp.decide_request(pending["request_id"], "approved", "owner")
    with pytest.raises(HTTPException) as error:
        server.run_tool("child", server.V2Invoke(action_id="approve", published_version=2,
                        approval_request_id=pending["request_id"]), agent)
    assert error.value.detail["code"] == "APPROVAL_INVALID"
    assert calls == [] and journal.get("approve") is None
    assert cp.get("request", pending["request_id"])["payload"]["binding"]["consumed_at"] is None


def test_http_missing_publication_never_falls_back_and_validation_is_strict(published):
    _, _, agent, calls = published
    server.app.dependency_overrides[server.require_agent] = lambda: agent
    try:
        client = TestClient(server.app)
        url = "/v2/automations/flow/run"
        assert client.post(url, json={"action_id": "missing", "published_version": 99}).status_code == 409
        for invalid in [0, True, "1"]:
            assert client.post(url, json={"action_id": "invalid", "published_version": invalid}).status_code == 422
        assert client.post(url, json={"published_version": 1}).status_code == 422
        assert calls == []
    finally:
        server.app.dependency_overrides.pop(server.require_agent, None)


def test_current_scope_and_lockdown_still_apply(published):
    _, _, agent, calls = published
    with pytest.raises(HTTPException):
        server.run_automation("flow", server.V2Invoke(action_id="scope", published_version=1), {**agent, "scopes": []})
    cp.set_lockdown(True, "owner")
    with pytest.raises(HTTPException) as error:
        server.run_automation("flow", server.V2Invoke(action_id="lock", published_version=1), agent)
    assert error.value.detail["code"] == "LOCKED_DOWN"
    assert calls == []


def test_owner_published_review_projects_exact_target_and_rechecks_revocation(published):
    tool, flow, agent, _ = published
    flow = cp.update_automation("flow", {**flow, "authorization": "owner_confirmation",
                                         "inputs": [{"name": "exact", "type": "string"}]})
    publication = pub.publish("automation", "flow", 2)
    pending = server.run_automation("flow", server.V2Invoke(action_id="owner-review", published_version=2,
                                                          args={"exact": "arguments"}), agent)
    view = owner.get(pending["request_id"])
    assert view["reviewable"] and view["action"]["args"] == {"exact": "arguments"}
    assert view["action"]["publication"]["digest"] == publication["digest"]
    assert view["action"]["publication"]["dependencies"] == cp.child_bindings({"child": tool})
    cp.update_tool("child", {**tool, "authorization": "blocked"})
    assert owner.get(pending["request_id"])["unavailable_reason"] == "publication_unavailable"
    with pytest.raises(owner.OwnerError):
        owner.decide(pending["request_id"], "approved", "Reviewed")
    assert cp.get("request", pending["request_id"])["status"] == "pending"


def test_tampered_publication_digest_cannot_be_reviewed_or_consumed(published):
    import json
    _, flow, agent, calls = published
    flow = cp.update_automation("flow", {**flow, "authorization": "owner_confirmation"})
    pub.publish("automation", "flow", 2)
    payload = server.V2Invoke(action_id="tamper", published_version=2)
    pending = server.run_automation("flow", payload, agent)
    identity = pending["request_id"]
    assert owner.decide(identity, "approved", "Exact publication")["status"] == "approved"
    request = cp.get("request", identity)
    request["payload"]["binding"]["publication_digest"] = "0" * 64
    with cp._conn() as conn:
        conn.execute("UPDATE v2_objects SET body=? WHERE kind='request' AND id=?", (json.dumps(request), identity))
    assert owner.get(identity)["unavailable_reason"] == "invalid_origin"
    payload.approval_request_id = identity
    with pytest.raises(HTTPException) as error:
        server.run_automation("flow", payload, agent)
    assert error.value.detail["code"] == "APPROVAL_INVALID"
    assert calls == [] and journal.get("tamper") is None


def test_unknown_published_receipt_retains_identity_and_never_redispatches(published, monkeypatch):
    _, _, agent, calls = published
    def lost_reply(tool, args):
        calls.append(tool)
        raise TimeoutError("lost reply")
    monkeypatch.setattr(server, "_dispatch_tool", lost_reply)
    payload = server.V2Invoke(action_id="unknown", published_version=1)
    first = server.run_tool("child", payload, agent)
    assert first["code"] == "OUTCOME_UNKNOWN"
    assert first["definition_version"] == 1
    assert first["publication_digest"] == pub.get("tool", "child", 1, published=True)["digest"]
    assert server.run_tool("child", payload, agent) == first
    assert len(calls) == 1


def test_journal_upgrade_preserves_legacy_receipts(published):
    with cp._conn() as conn:
        conn.executescript(journal.SCHEMA.replace("    publication_digest TEXT,\n", ""))
        conn.execute("INSERT INTO v2_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            "legacy", journal.fingerprint("tool", "child", {}, "caller", None, None),
            "caller", "tool", "child", 1, "{}", None, None, "completed", '{"code":"OK"}', 1, 1))
    record = journal.existing("legacy", "tool", "child", {}, "caller")
    assert record["publication_digest"] is None
    assert journal.response(record) == {"code": "OK", "action_id": "legacy", "status": "completed"}
    with pytest.raises(journal.ExecutionConflict):
        journal.existing("legacy", "tool", "child", {}, "caller", publication_digest="0" * 64)


def test_revocation_race_at_dispatch_boundary_fails_without_effect(published, monkeypatch):
    tool, _, agent, calls = published
    original = journal.begin
    def revoke_then_begin(*args, **kwargs):
        cp.update_tool("child", {**tool, "authorization": "blocked"})
        return original(*args, **kwargs)
    monkeypatch.setattr(journal, "begin", revoke_then_begin)
    with pytest.raises(HTTPException):
        server.run_tool("child", server.V2Invoke(action_id="race", published_version=1), agent)
    assert calls == [] and journal.get("race") is None


def test_published_tool_owner_approval_and_journal_digest_immutability(published):
    tool, _, agent, calls = published
    tool = cp.update_tool("child", {**tool, "authorization": "owner_confirmation"})
    pub.publish("tool", "child", 2)
    payload = server.V2Invoke(action_id="tool-confirm", published_version=2)
    pending = server.run_tool("child", payload, agent)
    assert owner.get(pending["request_id"])["reviewable"]
    owner.decide(pending["request_id"], "approved", "Reviewed publication")
    payload.approval_request_id = pending["request_id"]
    assert server.run_tool("child", payload, agent)["code"] == "OK"
    assert calls == [tool]
    with pytest.raises(sqlite3.IntegrityError), cp._conn() as conn:
        conn.execute("UPDATE v2_actions SET publication_digest=? WHERE action_id=?", ("0" * 64, payload.action_id))
