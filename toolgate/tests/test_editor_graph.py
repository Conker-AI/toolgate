from copy import deepcopy

from toolgate.core.editor_drafts import EditorDocument
from toolgate.core.editor_graph import validate_graph
from toolgate.tests.test_editor_drafts import document


def check(value):
    return validate_graph(EditorDocument.model_validate(value))


def branch_graph():
    value = document()
    value["inputs"] = [{"name": "enabled", "type": "boolean", "required": True}]
    template = value["nodes"][1]
    def node(identity, kind, config):
        return {**deepcopy(template), "id": identity, "type": kind, "config": config}
    value["nodes"] = [value["nodes"][0],
        node("choose", "condition", {"operator": "equals", "left": "$input.enabled", "right": True}),
        node("yes", "set", {"value": "yes"}), node("no", "set", {"value": "no"}),
        node("result", "return", {"value": "$last"})]
    value["edges"] = [
        {"id": "start", "source": "input", "target": "choose"},
        {"id": "true", "source": "choose", "target": "yes", "branch": "true"},
        {"id": "false", "source": "choose", "target": "no", "branch": "false"},
        {"id": "yes_end", "source": "yes", "target": "result"},
        {"id": "no_end", "source": "no", "target": "result"},
    ]
    return value


def test_valid_branches_merge_without_requiring_one_branch_output():
    assert check(branch_graph()) == []


def test_branch_only_reference_is_rejected_at_merge():
    value = branch_graph()
    value["nodes"][-1]["config"]["value"] = "$steps.yes"
    assert any("every path" in issue["message"] for issue in check(value))
    value["nodes"][-1]["config"]["value"] = "$steps.choose"
    assert check(value) == []


def test_each_condition_requires_both_distinct_branches():
    value = branch_graph()
    value["edges"][2]["branch"] = "true"
    assert any("both True and False" in issue["message"] for issue in check(value))


def test_disconnected_drafts_and_cycles_cannot_execute():
    assert check(document())
    value = branch_graph()
    value["edges"][3]["target"] = "choose"
    assert any("cycles" in issue["message"] for issue in check(value))


def test_invalid_references_and_configs_are_reported_with_node_identity():
    for reference in ("$input.missing", "$steps.result", "$steps", "$last.__proto__", "$vault.secret"):
        value = branch_graph()
        value["nodes"][-1]["config"]["value"] = reference
        assert any(issue["node_id"] == "result" for issue in check(value))
    value = branch_graph()
    value["nodes"][-1]["config"]["script"] = "arbitrary-code"
    assert any("unsupported fields" in issue["message"] for issue in check(value))


def test_literal_dollar_and_nested_reference_values():
    value = branch_graph()
    value["nodes"][-1]["config"]["value"] = {"literal": "$$vault.secret", "nested": ["$steps.choose", "$input.enabled"]}
    assert check(value) == []


def test_loop_limits_and_version_types_are_strict():
    for config in ({"items": [], "limit": True, "operation": "trim"},
                   {"items": [], "limit": 21, "operation": "trim"},
                   {"items": [], "limit": 2, "operation": "execute"}):
        value = branch_graph()
        value["nodes"][2].update(type="loop", config=config)
        assert any(issue["node_id"] == "yes" for issue in check(value))
    value = branch_graph()
    value["nodes"][2].update(type="workflow_call", config={"toolId": "other", "version": True, "args": {}})
    assert any("published version" in issue["message"] for issue in check(value))
