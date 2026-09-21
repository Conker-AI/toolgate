import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import owner_channel as owner
from toolgate.core import publications as pub
from toolgate.core import spending


def call(identity, version=1, **fields):
    return {"type": "automation_call", "automation_id": identity, "published_version": version, **fields}


def save(identity, workflow, **fields):
    return cp.create_automation({"id": identity, "name": identity, "description": "Nested test",
                                 "status": "active", "workflow": workflow, **fields})


@pytest.fixture
def nested(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "nested.db")
    tool = cp.create_tool({"id": "tool", "name": "Tool", "status": "active", "execution": {"type": "echo"}})
    child = save("child", [{"type": "tool_call", "tool_id": "tool"}, {"type": "return", "value": "old"}])
    pub.publish("automation", "child", 1)
    root = save("root", [call("child")])
    publication = pub.publish("automation", "root", 1)
    agent, _ = cp.issue_agent_key("Caller", ["automation:root", "automation:child"])
    calls = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda tool, args: calls.append(tool) or {"ok": True, "result": {}})
    return tool, child, root, publication, agent, calls


def run(agent, version=1, action="root-action"):
    return server.run_automation("root", server.V2Invoke(action_id=action, published_version=version), agent)


def test_nested_snapshot_is_old_exact_definition_with_parent_receipts(nested):
    tool, child, _, publication, agent, calls = nested
    cp.update_tool("tool", {**tool, "execution": {"type": "local_echo"}})
    cp.update_automation("child", {**child, "workflow": [{"type": "return", "value": "new"}]})
    result = run(agent)
    assert result["code"] == "OK" and calls == [tool]
    child_result = result["steps"][0]["result"]
    assert child_result["result"]["result"] == "old"
    assert child_result["publication_digest"] == publication["automations"]["child@1"]["digest"]
    records = journal.list_actions()
    assert len(records) == 3
    child_record = next(record for record in records if record["subject_id"] == "child")
    tool_record = next(record for record in records if record["subject_id"] == "tool")
    assert child_record["parent_action_id"] == "root-action"
    assert tool_record["parent_action_id"] == child_record["action_id"]
    assert run(agent) == result and len(calls) == 1


def test_distinct_child_publications_do_not_merge_same_tool_id(nested):
    tool, child, root, _, agent, calls = nested
    changed_tool = cp.update_tool("tool", {**tool, "execution": {"type": "local_echo"}})
    second = save("second", child["workflow"])
    pub.publish("automation", "second", second["version"])
    root = cp.update_automation("root", {**root, "workflow": [call("child"), call("second")]})
    pub.publish("automation", "root", root["version"])
    agent = cp.update_agent_key_scopes(agent["id"], ["automation:root", "automation:child", "automation:second"])
    assert run(agent, 2)["code"] == "OK"
    assert calls == [tool, changed_tool]


def test_loop_calls_have_distinct_deterministic_paths(nested):
    _, _, root, _, agent, calls = nested
    root = cp.update_automation("root", {**root, "workflow": [
        {"type": "loop", "items": [1, 2], "max_iterations": 2, "steps": [call("child")]}]})
    pub.publish("automation", "root", 2)
    result = run(agent, 2)
    assert result["code"] == "OK" and len(calls) == 2
    records = journal.list_actions()
    assert len(records) == len({record["action_id"] for record in records}) == 5
    assert run(agent, 2) == result and len(calls) == 2


@pytest.mark.parametrize("scopes", [["automation:root"], ["automation:child"], ["tool"]])
def test_root_and_nested_scopes_are_intersected_before_any_dispatch(nested, scopes):
    _, _, _, _, agent, calls = nested
    agent = cp.update_agent_key_scopes(agent["id"], scopes)
    with pytest.raises(HTTPException) as error:
        run(agent)
    assert error.value.detail["code"] == "POLICY_DENIED"
    assert journal.list_actions() == [] and calls == []


def test_nested_dependency_revocation_and_digest_mismatch_fail(nested):
    _, child, root, _, agent, calls = nested
    changed = cp.update_automation("root", {**root, "workflow": [call("child", publication_digest="0" * 64)]})
    with pytest.raises(pub.PublicationInvalid):
        pub.publish("automation", "root", changed["version"])
    cp.update_automation("child", {**child, "authorization": "blocked"})
    with pytest.raises(pub.PublicationInvalid):
        run(agent)
    assert journal.list_actions() == [] and calls == []


def test_hidden_branch_dependencies_and_cross_version_cycles_rejected(nested):
    _, _, root, _, _, _ = nested
    changed = cp.update_automation("root", {**root, "workflow": [
        {"type": "condition", "left": False, "right": True, "then": [call("missing")]}]})
    with pytest.raises(pub.PublicationInvalid):
        pub.publish("automation", "root", changed["version"])
    changed = cp.update_automation("root", {**root, "workflow": [call("root", 1)]})
    with pytest.raises(pub.PublicationInvalid, match="cycles"):
        pub.publish("automation", "root", changed["version"])


def test_expanded_depth_and_node_limits(nested):
    save("wide", [{"type": "return", "value": 1}] * 250)
    pub.publish("automation", "wide", 1)
    save("too-wide", [call("wide"), call("wide")])
    with pytest.raises(pub.PublicationInvalid, match="500"):
        pub.publish("automation", "too-wide", 1)
    previous = "child"
    for index in range(1, 5):
        identity = f"level{index}"
        save(identity, [call(previous)])
        pub.publish("automation", identity, 1)
        previous = identity
    save("too-deep", [call(previous)])
    with pytest.raises(pub.PublicationInvalid, match="four"):
        pub.publish("automation", "too-deep", 1)


@pytest.mark.parametrize("limited", ["root", "child"])
def test_ancestor_and_child_step_limits_cannot_reset(nested, limited):
    _, child, root, _, agent, calls = nested
    if limited == "child":
        child = cp.update_automation("child", {**child, "policy": {"usage_limits": {"max_steps": 1}}})
        pub.publish("automation", "child", child["version"])
        root = {**root, "workflow": [call("child", child["version"])]}
    else:
        root = {**root, "policy": {"usage_limits": {"max_steps": 2}}}
    changed = cp.update_automation("root", root)
    pub.publish("automation", "root", changed["version"])
    assert run(agent, changed["version"])["code"] == "OUTCOME_UNKNOWN"
    assert len(calls) == 1


def test_root_deadline_survives_nested_entry(nested, monkeypatch):
    _, _, root, _, agent, calls = nested
    changed = cp.update_automation("root", {**root, "policy": {"usage_limits": {"max_runtime_seconds": 3}}})
    pub.publish("automation", "root", changed["version"])
    now = [0]
    monkeypatch.setattr(server.time, "monotonic", lambda: now[0])
    def dispatch(tool, args):
        calls.append(tool)
        now[0] = 4
        return {"ok": True, "result": {}}
    monkeypatch.setattr(server, "_dispatch_tool", dispatch)
    assert run(agent, changed["version"])["code"] == "OUTCOME_UNKNOWN"
    assert len(calls) == 1


def test_unknown_nested_call_inside_retry_never_repeats_effect(nested, monkeypatch):
    _, _, root, _, agent, calls = nested
    changed = cp.update_automation("root", {**root, "workflow": [
        {"type": "retry", "max_attempts": 3, "step": call("child")}]})
    pub.publish("automation", "root", changed["version"])
    def lost(tool, args):
        calls.append(tool)
        raise TimeoutError("lost receipt")
    monkeypatch.setattr(server, "_dispatch_tool", lost)
    first = run(agent, changed["version"])
    assert first["code"] == "OUTCOME_UNKNOWN" and len(calls) == 1
    assert run(agent, changed["version"]) == first and len(calls) == 1
    assert all(record["status"] == "outcome_unknown" for record in journal.list_actions())


def test_root_confirmation_binds_nested_publications(nested):
    _, child, root, _, agent, calls = nested
    child = cp.update_automation("child", {**child, "authorization": "owner_confirmation"})
    pub.publish("automation", "child", child["version"])
    root = cp.update_automation("root", {**root, "workflow": [call("child", child["version"])]})
    with pytest.raises(pub.PublicationInvalid):
        pub.publish("automation", "root", root["version"])
    root = cp.update_automation("root", {**root, "authorization": "owner_confirmation"})
    publication = pub.publish("automation", "root", root["version"])
    payload = server.V2Invoke(action_id="approval", published_version=root["version"])
    pending = server.run_automation("root", payload, agent)
    view = owner.get(pending["request_id"])
    assert view["action"]["publication"]["automations"] == pub.automation_bindings(publication)
    owner.decide(pending["request_id"], "approved", "All exact descendants")
    payload.approval_request_id = pending["request_id"]
    assert server.run_automation("root", payload, agent)["code"] == "OK" and len(calls) == 1


def test_live_nested_execution_is_rejected_without_dispatch(nested):
    _, _, _, _, agent, calls = nested
    with pytest.raises(HTTPException) as error:
        run(agent, None)
    assert error.value.detail["code"] == "PUBLICATION_REQUIRED"
    assert journal.list_actions() == [] and calls == []


@pytest.mark.parametrize("revoked", ["root_policy", "nested_scope"])
def test_mid_nested_revocation_stops_later_leaf_dispatch(nested, monkeypatch, revoked):
    _, child, root, _, agent, calls = nested
    child = cp.update_automation("child", {**child, "workflow": [
        {"type": "tool_call", "tool_id": "tool"}, {"type": "tool_call", "tool_id": "tool"}]})
    pub.publish("automation", "child", child["version"])
    root = cp.update_automation("root", {**root, "workflow": [call("child", child["version"])]})
    pub.publish("automation", "root", root["version"])
    def dispatch(tool, args):
        calls.append(tool)
        if revoked == "root_policy":
            cp.update_automation("root", {**root, "authorization": "blocked"})
        else:
            cp.update_agent_key_scopes(agent["id"], ["automation:root"])
        return {"ok": True, "result": {}}
    monkeypatch.setattr(server, "_dispatch_tool", dispatch)
    assert run(agent, root["version"])["code"] == "OUTCOME_UNKNOWN"
    assert len(calls) == 1


def test_nested_paid_leaves_share_root_job_ceiling(nested):
    tool, child, root, _, agent, calls = nested
    cp.update_tool("tool", {**tool, "execution": {"type": "gemini_generate", "model": spending.MODEL,
        "prompt_template": "hello", "secret_ref": "REFERENCE_ONLY", "max_tokens": 128}})
    child = cp.update_automation("child", child)
    pub.publish("automation", "child", child["version"])
    root = cp.update_automation("root", {**root, "workflow": [call("child", 2), call("child", 2)]})
    pub.publish("automation", "root", root["version"])
    spending.configure(True, 20_000_000, 1_100_000)
    spending.set_price(spending.MODEL, 1_000_000, 2_000_000, time.time() + 3600, "https://provider.example/pricing")
    job = spending.create_job(agent["id"], "paid-root", 1_100_000)["job_id"]
    payload = server.V2Invoke(action_id="paid-root", published_version=root["version"], job_id=job)
    result = server.run_automation("root", payload, agent)
    assert result["code"] == "OUTCOME_UNKNOWN" and len(calls) == 1
    with cp._conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM v2_spend_reservations WHERE job_id=?", (job,)).fetchone()[0] == 1
    assert server.run_automation("root", payload, agent) == result and len(calls) == 1


def test_nested_arguments_resolve_explicitly_without_sharing_variables(nested):
    _, child, root, _, agent, _ = nested
    child = cp.update_automation("child", {**child, "inputs": [{"name": "value", "type": "string", "required": True}],
        "workflow": [{"type": "set", "name": "secret", "value": "inner"},
                     {"type": "return", "value": "$args.value"}]})
    pub.publish("automation", "child", child["version"])
    root = cp.update_automation("root", {**root, "workflow": [
        {"type": "set", "name": "secret", "value": "outer"},
        call("child", child["version"], args={"value": "$vars.secret"}),
        {"type": "return", "value": "$vars.secret"}]})
    pub.publish("automation", "root", root["version"])
    result = run(agent, root["version"])
    assert result["result"]["result"] == "outer"
    child_result = result["steps"][1]["result"]
    assert child_result["result"]["result"] == "outer"
    assert child_result["variables"] == {"secret": "inner"}
    assert result["variables"] == {"secret": "outer"}


def test_http_nested_authoring_and_publication_contract(nested):
    client = TestClient(server.app)
    server.app.dependency_overrides[server.require_admin] = lambda: "admin"
    try:
        definition = {"id": "http-parent", "name": "HTTP parent", "description": "Nested source contract",
                      "status": "active", "workflow": [call("child")]}
        created = client.post("/v2/automations", json=definition)
        assert created.status_code == 200, created.text
        published = client.post("/v2/automations/http-parent/publish", json={"expected_version": 1})
        assert published.status_code == 200, published.text
        assert published.json()["automations"]["child@1"]["version"] == 1
        invalid = {**definition, "workflow": [call("child", True)]}
        assert client.put("/v2/automations/http-parent", json=invalid).status_code == 422
        assert cp.get("automation", "http-parent")["version"] == 1
    finally:
        server.app.dependency_overrides.pop(server.require_admin, None)
