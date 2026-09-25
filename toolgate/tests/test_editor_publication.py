import pytest
from fastapi import HTTPException

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import publications as pub
from toolgate.tests.test_editor_execution import linear


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "graphs.db")
    tool = cp.create_tool({"id": "echo", "name": "Echo", "description": "Test echo", "execution": {"type": "echo"},
                           "inputs": [{"name": "message", "type": "string", "required": False}]})
    agent, _ = cp.issue_agent_key("Graph caller", ["automation:graph", "automation:child"])
    return tool, agent


def save(identity, document, **fields):
    return cp.create_automation({"id": identity, "name": identity, "description": "Editor graph",
        "status": "active", "workflow": [{"type": "editor_graph", "document": document}], **fields})


def run(agent, **fields):
    return server.run_automation("graph", server.V2Invoke(action_id="graph-run", published_version=1, **fields), agent)


def test_published_graph_dispatches_pinned_tool_with_receipts_and_replay(registry):
    tool, agent = registry
    document = linear(("call", "tool_call", {"tool": "echo", "args": {"message": "$input.message"}}),
                      ("result", "return", {"value": "$steps.call.message"}))
    document["inputs"] = [{"name": "message", "type": "string", "required": True}]
    save("graph", document, inputs=document["inputs"])
    published = pub.publish("automation", "graph", 1, validate=server.require_valid_automation_definition)
    cp.update_tool("echo", {**tool, "execution": {"type": "local_echo"}})
    result = run(agent, args={"message": "$args.not_a_reference"})
    assert result["code"] == "OK", result
    assert result["result"]["result"] == "$args.not_a_reference"
    assert result["steps"][1]["output"] == {"message": "$args.not_a_reference"}
    assert run(agent, args={"message": "$args.not_a_reference"}) == result
    assert len(journal.list_actions()) == 2
    assert published["tools"]["echo"] == tool


def test_graph_requires_publication_and_live_scopes(registry):
    _, agent = registry
    save("graph", linear(("result", "return", {"value": 3})))
    with pytest.raises(HTTPException) as error:
        server.run_automation("graph", server.V2Invoke(action_id="no-publication"), agent)
    assert error.value.detail["code"] == "PUBLICATION_REQUIRED"
    pub.publish("automation", "graph", 1)
    agent = cp.update_agent_key_scopes(agent["id"], [])
    with pytest.raises(HTTPException) as error:
        run(agent)
    assert error.value.detail["code"] == "POLICY_DENIED"
    assert journal.list_actions() == []


def test_graph_failure_is_a_recorded_outcome_not_a_success(registry):
    _, agent = registry
    save("graph", linear(("math", "calculation", {"operator": "divide", "left": 1, "right": 0}),
                         ("result", "return", {"value": "$last"})))
    pub.publish("automation", "graph", 1)
    result = run(agent)
    assert result["code"] == "WORKFLOW_FAILED"
    assert result["steps"][-1]["nodeId"] == "math"
    assert result["steps"][-1]["status"] == "failed"
    assert run(agent) == result


def test_nested_graph_pins_child_and_requires_its_scope(registry):
    _, agent = registry
    save("child", linear(("result", "return", {"value": "child output"})))
    pub.publish("automation", "child", 1)
    save("graph", linear(("call", "workflow_call", {"toolId": "child", "version": 1, "args": {}}),
                         ("result", "return", {"value": "$last"})))
    pub.publish("automation", "graph", 1)
    assert run(agent)["result"]["result"] == "child output"
    agent = cp.update_agent_key_scopes(agent["id"], ["automation:graph"])
    with pytest.raises(HTTPException):
        run(agent)


def test_graph_dependencies_reject_revocation_and_confirmation_downgrade(registry):
    tool, agent = registry
    document = linear(("call", "tool_call", {"tool": "echo", "args": {}}),
                      ("result", "return", {"value": "$last"}))
    save("graph", document)
    cp.update_tool("echo", {**tool, "authorization": "owner_confirmation"})
    with pytest.raises(pub.PublicationInvalid, match="confirmation"):
        pub.publish("automation", "graph", 1)
    cp.update_tool("echo", {**tool, "authorization": "auto"})
    pub.publish("automation", "graph", 1)
    cp.remove("tool", "echo")
    with pytest.raises(pub.PublicationInvalid):
        run(agent)
    assert journal.list_actions() == []
