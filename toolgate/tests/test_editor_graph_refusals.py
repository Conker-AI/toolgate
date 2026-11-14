"""Editor graph validation: shapes a workflow can never execute are refused, with the message
that tells the owner which rule broke (and the node, where one is to blame)."""

from copy import deepcopy

import pytest

from toolgate.tests.test_editor_graph import branch_graph, check


def messages(value):
    return [issue["message"] for issue in check(value)]


def refuses(value, fragment, node_id=None):
    matching = [issue for issue in check(value) if fragment in issue["message"]]
    assert matching, check(value)
    if node_id is not None:
        assert any(issue["node_id"] == node_id for issue in matching)


def test_two_nodes_cannot_share_an_identity():
    value = branch_graph()
    value["nodes"].append(deepcopy(value["nodes"][2]))
    assert messages(value) == ["Node identities must be unique."]


def test_two_connections_cannot_share_an_identity():
    value = branch_graph()
    value["edges"][4]["id"] = "yes_end"
    refuses(value, "Connection identities must be unique.")


def test_a_connection_to_a_node_that_does_not_exist_is_refused():
    value = branch_graph()
    value["edges"][3]["target"] = "nowhere"
    refuses(value, "refers to a missing node")


def test_exactly_one_input_node_is_required():
    value = branch_graph()
    value["nodes"][0]["type"] = "set"
    value["nodes"][0]["config"] = {"value": 1}
    refuses(value, "exactly one Input node")
    value = branch_graph()
    second = deepcopy(value["nodes"][0])
    second["id"] = "second_input"
    value["nodes"].append(second)
    refuses(value, "exactly one Input node")


def test_nothing_may_flow_into_the_input_node():
    value = branch_graph()
    value["edges"][3]["target"] = "input"
    refuses(value, "Input cannot have incoming connections.", "input")


def test_a_return_node_cannot_continue_to_another_step():
    value = branch_graph()
    value["edges"].append({"id": "after", "source": "result", "target": "yes"})
    refuses(value, "Return cannot have outgoing connections.", "result")


@pytest.mark.parametrize(
    "edges",
    [
        [],
        [
            {"id": "a", "source": "yes", "target": "result"},
            {"id": "b", "source": "yes", "target": "no"},
        ],
    ],
)
def test_a_plain_step_needs_exactly_one_next_step(edges):
    value = branch_graph()
    value["edges"] = [edge for edge in value["edges"] if edge["source"] != "yes"] + edges
    refuses(value, "Connect exactly one next step", "yes")


def test_a_plain_step_cannot_carry_a_branch_label():
    value = branch_graph()
    value["edges"][3]["branch"] = "true"
    refuses(value, "without a branch label", "yes")


def test_field_names_must_be_unique_within_a_schema():
    value = branch_graph()
    value["inputs"].append(dict(value["inputs"][0]))
    refuses(value, "Field names must be unique")


def test_a_calculation_needs_a_supported_operator():
    value = branch_graph()
    value["nodes"][2].update(
        type="calculation", config={"operator": "power", "left": 1, "right": 2}
    )
    refuses(value, "supported calculation operator", "yes")
    value["nodes"][2]["config"]["operator"] = "add"
    assert check(value) == []


def test_a_condition_needs_a_supported_operator_and_a_right_value():
    value = branch_graph()
    value["nodes"][1]["config"] = {"operator": "matches", "left": "$input.enabled", "right": True}
    refuses(value, "supported condition operator", "choose")
    value["nodes"][1]["config"] = {"operator": "equals", "left": "$input.enabled"}
    refuses(value, "needs a right value", "choose")
    value["nodes"][1]["config"] = {"operator": "exists", "left": "$input.enabled"}
    assert check(value) == []


@pytest.mark.parametrize("target", ["", None, 5, "$input.enabled"])
def test_a_tool_call_must_name_a_literal_capability(target):
    value = branch_graph()
    value["nodes"][2].update(type="tool_call", config={"tool": target, "args": {}})
    refuses(value, "literal capability identity", "yes")


def test_a_tool_call_takes_an_argument_object():
    value = branch_graph()
    value["nodes"][2].update(
        type="tool_call", config={"tool": "web.search", "args": ["not", "an", "object"]}
    )
    refuses(value, "argument object", "yes")


@pytest.mark.parametrize("version", [0, -1, "1", None])
def test_a_workflow_call_needs_a_positive_integer_version(version):
    value = branch_graph()
    value["nodes"][2].update(
        type="workflow_call", config={"toolId": "other", "version": version, "args": {}}
    )
    refuses(value, "positive published version", "yes")


def test_a_step_cannot_reference_itself():
    value = branch_graph()
    value["nodes"][-1]["config"]["value"] = "$steps.result"
    refuses(value, "every path", "result")


def test_a_step_that_input_never_reaches_is_reported_as_disconnected():
    value = branch_graph()
    orphan = deepcopy(value["nodes"][2])
    orphan["id"] = "orphan"
    value["nodes"].append(orphan)
    value["edges"].append({"id": "orphan_end", "source": "orphan", "target": "result"})
    refuses(value, "disconnected from Input", "orphan")
