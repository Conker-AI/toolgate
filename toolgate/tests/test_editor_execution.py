from copy import deepcopy

import pytest

from toolgate.core.editor_drafts import EditorDocument
from toolgate.core.editor_execution import Budget, GraphExecutionError, execute
from toolgate.tests.test_editor_drafts import document
from toolgate.tests.test_editor_graph import branch_graph


def linear(*steps):
    value = document()
    template = value["nodes"][-1]
    value["nodes"] = [value["nodes"][0], *[
        {**deepcopy(template), "id": identity, "type": kind, "config": config}
        for identity, kind, config in steps]]
    value["edges"] = [{"id": f"edge_{i}", "source": left["id"], "target": right["id"]}
                      for i, (left, right) in enumerate(zip(value["nodes"], value["nodes"][1:], strict=False))]
    return value


@pytest.mark.parametrize("enabled,expected,skipped", [(True, "yes", "no"), (False, "no", "yes")])
def test_branch_result_and_receipts_follow_only_the_taken_path(enabled, expected, skipped):
    result = execute(EditorDocument.model_validate(branch_graph()), {"enabled": enabled})
    assert result["output"] == expected
    assert next(step for step in result["steps"] if step["nodeId"] == skipped)["status"] == "skipped"
    assert len([step for step in result["steps"] if step["status"] == "completed"]) == 4


def test_loop_values_and_calculation_preserve_editor_step_outputs():
    value = linear(("trim", "loop", {"items": [" one ", " two "], "limit": 2, "operation": "trim"}),
                   ("cost", "calculation", {"operator": "multiply", "left": "$steps.trim.count", "right": 3}),
                   ("result", "return", {"value": {"items": "$steps.trim.items", "cost": "$steps.cost"}}))
    result = execute(EditorDocument.model_validate(value), {})
    assert result["output"] == {"items": ["one", "two"], "cost": 6}


def test_failed_calculation_has_no_success_output_or_later_step():
    value = linear(("math", "calculation", {"operator": "divide", "left": 4, "right": 0}),
                   ("result", "return", {"value": "$last"}))
    with pytest.raises(GraphExecutionError) as error:
        execute(EditorDocument.model_validate(value), {})
    assert error.value.node_id == "math"
    assert [row["status"] for row in error.value.receipts] == ["completed", "failed"]
    assert "output" not in error.value.receipts[-1]


def test_no_capability_dispatch_without_explicit_boundary():
    value = linear(("call", "tool_call", {"tool": "real.tool", "args": {}}),
                   ("result", "return", {"value": "$last"}))
    with pytest.raises(GraphExecutionError, match="authorized capability"):
        execute(EditorDocument.model_validate(value), {})


def test_nested_calls_share_parent_budget_and_do_not_reset_limits():
    child = EditorDocument.model_validate(linear(("set", "set", {"value": 1}),
                                                ("result", "return", {"value": "$last"})))
    parent = linear(("call", "workflow_call", {"toolId": "child", "version": 1, "args": {}}),
                    ("result", "return", {"value": "$last"}))
    parent["budgets"]["maxSteps"] = 4
    budget = Budget()
    def dispatch(node, args, shared):
        assert node.config["version"] == 1
        return execute(child, args, budget=shared)["output"]
    with pytest.raises(GraphExecutionError, match="shared execution budget"):
        execute(EditorDocument.model_validate(parent), {}, dispatch=dispatch, budget=budget)
    assert budget.frames == []


def test_deadline_is_checked_after_capability_returns():
    value = linear(("call", "tool_call", {"tool": "real.tool", "args": {}}),
                   ("result", "return", {"value": "$last"}))
    now = [0.0]
    budget = Budget(clock=lambda: now[0])
    def dispatch(*_):
        now[0] = 10.0
        return "late"
    with pytest.raises(GraphExecutionError, match="shared execution budget"):
        execute(EditorDocument.model_validate(value), {}, dispatch=dispatch, budget=budget)
    assert budget.frames == []


def test_output_contract_rejects_a_completed_looking_wrong_result():
    value = linear(("result", "return", {"value": {"count": "wrong"}}))
    value["outputs"] = [{"name": "count", "type": "number", "required": True}]
    with pytest.raises(GraphExecutionError, match="declared type") as error:
        execute(EditorDocument.model_validate(value), {})
    assert error.value.receipts[-1]["status"] == "failed"


def test_invalid_graph_is_rejected_before_any_dispatch():
    value = branch_graph()
    value["nodes"][-1]["config"]["value"] = "$steps.yes"
    with pytest.raises(GraphExecutionError, match="every path"):
        execute(EditorDocument.model_validate(value), {"enabled": True}, dispatch=lambda *_: pytest.fail())


def test_final_envelope_is_bounded_without_duplicate_success_receipt():
    value = linear(("result", "return", {"value": "x" * 34000}))
    with pytest.raises(GraphExecutionError) as error:
        execute(EditorDocument.model_validate(value), {})
    assert [row["status"] for row in error.value.receipts] == ["completed", "failed"]
