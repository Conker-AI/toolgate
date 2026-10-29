"""The document check applies publishing's rules and never saves, grants or runs anything."""

import pytest

from toolgate.core import control_plane as cp
from toolgate.core import editor_publication, publications
from toolgate.core import execution_journal as journal
from toolgate.tests.test_editor_drafts import document
from toolgate.tests.test_editor_execution import linear
from toolgate.tests.test_editor_owner_publication import publish, save
from toolgate.tests.test_owner_channel import ADMIN, HEADERS, gate  # noqa: F401

PATH = "/v2/editor/check"


def echo(identity="echo", **fields):
    return cp.create_tool(
        {
            "id": identity,
            "name": "Echo",
            "description": "Test echo",
            "execution": {"type": "echo"},
            "inputs": [{"name": "message", "type": "string", "required": False}],
            **fields,
        }
    )


def calling(tool="echo"):
    return linear(
        ("call", "tool_call", {"tool": tool, "args": {"message": "hi"}}),
        ("result", "return", {"value": "$last"}),
    )


def check(gate, value, headers=None):
    response = gate[0].post(
        PATH, json={"document": value}, headers=headers or {"X-ToolGate-Execution-Key": gate[2]}
    )
    assert response.status_code == 200, response.text
    return response.json()


def codes(result):
    return [(issue["code"], issue["nodeId"]) for issue in result["issues"]]


def state():
    with cp._conn() as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        counts = {
            table: conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in sorted(tables)
        }
        keys = [(row["id"], row["scopes"]) for row in conn.execute("SELECT * FROM v2_agent_keys")]
    return counts, keys


def test_valid_document_passes_for_execution_and_owner_keys_and_changes_nothing(gate):
    echo()
    before = state()
    assert check(gate, calling()) == {"valid": True, "issues": []}
    assert check(gate, calling(), headers=HEADERS) == {"valid": True, "issues": []}
    assert check(gate, {**calling(), "credentialRefs": ["connection:mail"]})["valid"] is False
    counts, keys = state()
    # Authentication may create its own empty tables; nothing else appears or changes.
    assert {table: counts[table] for table in before[0]} == before[0]
    assert all(counts[table] == 0 for table in counts.keys() - before[0].keys())
    assert keys == before[1]
    assert journal.list_actions() == []
    assert cp.list_objects("automation") == []


def test_check_needs_an_owner_or_execution_credential(gate):
    client, _agent, execution = gate
    body = {"document": document()}
    for headers in (
        {},
        {"X-ToolGate-Key": ADMIN},
        {"X-ToolGate-Execution-Key": ADMIN},
        {"X-ToolGate-Owner-Key": ADMIN},
        {"X-ToolGate-Owner-Key": "x" * 40, "X-ToolGate-Execution-Key": execution},
    ):
        assert client.post(PATH, json=body, headers=headers).status_code == 401
    malformed = {"X-ToolGate-Execution-Key": execution, "X-ToolGate-Agent": "Not An Agent"}
    assert client.post(PATH, json=body, headers=malformed).status_code == 403
    assert client.post(PATH, json={"document": "text"}, headers=HEADERS).status_code == 422
    assert (
        client.post(PATH, json={"document": {}, "save": True}, headers=HEADERS).status_code == 422
    )


def test_shape_errors_are_issues_that_name_the_step(gate):
    value = calling()
    value["nodes"][1]["type"] = "shell"
    del value["budgets"]
    result = check(gate, value)
    assert result["valid"] is False
    assert ("invalid_document", "call") in codes(result)
    assert ("invalid_document", None) in codes(result)
    assert all(set(issue) == {"code", "message", "nodeId"} for issue in result["issues"])
    assert any(issue["message"].startswith("budgets:") for issue in result["issues"])
    assert check(gate, {**document(), "name": " "})["issues"] == [
        {"code": "invalid_document", "message": "Give the draft a name", "nodeId": None}
    ]


def test_graph_and_definition_rules_are_issues(gate):
    value = linear(("lonely", "set", {"value": 1}), ("result", "return", {"value": "$last"}))
    value["edges"] = value["edges"][:1]
    result = check(gate, value)
    assert ("invalid_graph", "lonely") in codes(result)
    value = linear(("result", "return", {"value": 7}))
    value["inputs"] = [{"name": "my-input", "type": "string", "required": True}]
    assert codes(check(gate, value)) == [("invalid_definition", None)]


@pytest.mark.parametrize(
    "change,code",
    [
        (None, "tool_unavailable"),
        ({"status": "disabled"}, "tool_unavailable"),
        ({"authorization": "blocked"}, "tool_unavailable"),
        ({"execution": {"type": "shell"}}, "tool_invalid"),
    ],
)
def test_tool_calls_need_an_active_valid_tool(gate, change, code):
    if change is not None:
        echo(**change)
    result = check(gate, calling())
    assert codes(result) == [(code, "call")]
    assert "echo" in result["issues"][0]["message"]


def test_workflow_calls_need_an_available_publication(gate):
    echo()
    cp.create_automation(
        {
            "id": "child",
            "name": "Child",
            "description": "Child flow",
            "status": "active",
            "workflow": [{"type": "tool_call", "tool_id": "echo"}],
        }
    )
    value = linear(
        ("nested", "workflow_call", {"toolId": "child", "version": 1, "args": {}}),
        ("result", "return", {"value": "$last"}),
    )
    assert codes(check(gate, value)) == [("workflow_unavailable", "nested")]
    publications.publish("automation", "child", 1)
    assert check(gate, value)["valid"] is True
    cp.update_tool("echo", {**cp.get("tool", "echo"), "status": "disabled"})
    assert codes(check(gate, value)) == [("workflow_unavailable", "nested")]


def test_a_call_into_an_earlier_revision_of_itself_is_a_cycle(gate):
    client = gate[0]
    assert save(client).status_code == 200
    assert publish(client).status_code == 200
    value = linear(
        (
            "again",
            "workflow_call",
            {"toolId": editor_publication.automation_id("example"), "version": 1, "args": {}},
        ),
        ("result", "return", {"value": "$last"}),
    )
    result = check(gate, value)
    assert codes(result) == [("workflow_limit", None)]
    assert "cycle" in result["issues"][0]["message"]


@pytest.mark.parametrize("tool", ["echo", "missing"])
def test_check_and_publish_agree(gate, tool):
    client = gate[0]
    echo()
    value = calling(tool)
    assert save(client, value).status_code == 200
    published = publish(client).status_code == 200
    assert check(gate, value)["valid"] is published
