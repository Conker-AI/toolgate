"""Workflow steps refuse what cannot run deterministically and stop where they must: bad
values, missing tools and publications, loop ceilings, early returns through every block."""

import time
from typing import cast

import pytest
from fastapi import HTTPException

from toolgate.api import workflows as wf
from toolgate.core import control_plane as cp


def state(**changes):
    return {"args": {}, "vars": {}, "results": [], "count": 0, "max_steps": 100,
            "started_at": time.monotonic(), "runtime_ceiling": 30, "automation_id": "auto.test", **changes}


def run(steps, current=None, approved=False):
    return wf._run_workflow_steps(steps, current if current is not None else state(), "agent", approved)


def refused(steps, current=None, approved=False):
    with pytest.raises(HTTPException) as caught:
        run(steps, current, approved)
    detail = cast(dict, caught.value.detail)
    return caught.value.status_code, detail["code"], detail["message"]


RETURN = {"type": "return", "value": "$vars.done"}


def test_paths_that_do_not_exist_resolve_to_nothing():
    current = state(args={"list": [1]})
    run([{"type": "set", "name": "a", "value": "$args.list.5"},
         {"type": "set", "name": "b", "value": "$args.missing.deep"}], current)
    assert current["vars"] == {"a": None, "b": None}


@pytest.mark.parametrize(("operator", "left", "right", "met"), [
    ("not_equals", 1, 2, True), ("contains", "abc", "b", True), ("in", "b", ["a", "b"], True),
    ("contains", "abc", "z", False),
])
def test_condition_operators(operator, left, right, met):
    current = state()
    run([{"type": "condition", "left": left, "operator": operator, "right": right,
          "then": [{"type": "set", "name": "hit", "value": True}], "else": [{"type": "set", "name": "hit", "value": False}]}],
        current)
    assert current["vars"]["hit"] is met


@pytest.mark.parametrize(("operator", "left", "right"), [("like", 1, 1), ("contains", 5, "a"), ("gt", "x", 1)])
def test_a_condition_that_cannot_compare_is_refused(operator, left, right):
    assert refused([{"type": "condition", "left": left, "operator": operator, "right": right}])[0:2] == (
        422, "VALIDATION_ERROR")


def test_an_unmet_condition_with_nothing_to_do_stops_the_automation():
    assert refused([{"type": "condition", "left": 1, "right": 2}])[1] == "POLICY_DENIED"


@pytest.mark.parametrize(("values", "operation", "words"), [
    ([1, "2"], "add", "must resolve to numbers"),
    ([True], "add", "must resolve to numbers"),
    ([1, 2], "power", "Unsupported calculation 'power'"),
    ([1, 0], "divide", "divided by zero"),
    ([10 ** 400, 1], "divide", "exceeded the numeric range"),
    ([1e308, 10.0], "multiply", "result must be finite"),
])
def test_calculations_refuse_values_they_cannot_compute_exactly(values, operation, words):
    status, code, message = refused([{"type": "calculation", "operation": operation, "values": values}])
    assert (status, code) == (422, "VALIDATION_ERROR") and words in message


def test_an_editor_graph_runs_only_from_a_published_version():
    assert refused([{"type": "editor_graph"}])[0:2] == (422, "PUBLICATION_REQUIRED")


def test_tools_must_be_in_the_snapshot_and_approved_when_they_ask():
    assert refused([{"type": "tool_call", "tool_id": "gone"}], state(tool_snapshot={}))[1] == "TOOL_UNAVAILABLE"
    asks = {"id": "mail.send", "status": "active", "authorization": "owner_confirmation"}
    assert refused([{"type": "tool_call", "tool_id": "mail.send"}],
                   state(tool_snapshot={"mail.send": asks}))[0] == 403


def test_a_graph_budget_is_charged_for_every_step():
    class Budget:
        charged = 0

        def charge(self):
            self.charged += 1

    budget = Budget()
    run([{"type": "set", "name": "a", "value": 1}, {"type": "delay", "seconds": 0}], state(graph_budget=budget))
    assert budget.charged == 2


def test_a_return_inside_any_block_ends_the_whole_workflow():
    for block in (
        {"type": "condition", "left": 1, "right": 1, "then": [RETURN]},
        {"type": "switch", "value": "a", "cases": {"a": [RETURN]}},
        {"type": "loop", "max_iterations": 3, "items": [1, 2], "steps": [RETURN]},
        {"type": "retry", "max_attempts": 2, "step": RETURN},
    ):
        current = state(vars={"done": "yes"})
        assert run([block, {"type": "set", "name": "after", "value": 1}], current) == {"code": "OK", "result": "yes"}
        assert "after" not in current["vars"] and current["results"][-1]["type"] == block["type"]


@pytest.mark.parametrize(("items", "code"), [("$args.text", "VALIDATION_ERROR"), ([1, 2, 3, 4], "POLICY_DENIED")])
def test_loops_need_an_array_inside_their_ceiling(items, code):
    current = state(args={"text": "abc"})
    assert refused([{"type": "loop", "max_iterations": 3, "items": items, "steps": []}], current)[1] == code


def test_a_loop_gives_back_the_variable_it_borrowed():
    current = state(vars={"item": "mine"})
    run([{"type": "loop", "max_iterations": 2, "items": [1, 2], "steps": []}], current)
    assert current["vars"]["item"] == "mine"


def test_retry_tries_again_only_after_a_temporary_failure(monkeypatch):
    calls = []

    def flaky(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise HTTPException(503, {"code": "UNAVAILABLE"})
        return {"code": "OK"}

    monkeypatch.setattr(wf, "invoke_tool", flaky)
    tool = {"id": "notes.add", "status": "active", "authorization": "auto"}
    current = state(tool_snapshot={"notes.add": tool})
    run([{"type": "retry", "max_attempts": 3, "delay_seconds": 0,
          "step": {"type": "tool_call", "tool_id": "notes.add"}}], current)
    assert len(calls) == 2 and current["results"][-1]["result"] == {"code": "RETRY_COMPLETE", "attempts": 2}

    def refuses(*_args, **_kwargs):
        calls.append(1)
        raise HTTPException(400, {"code": "VALIDATION_ERROR"})

    calls.clear()
    monkeypatch.setattr(wf, "invoke_tool", refuses)
    with pytest.raises(HTTPException):
        run([{"type": "retry", "max_attempts": 3, "step": {"type": "tool_call", "tool_id": "notes.add"}}],
            state(tool_snapshot={"notes.add": tool}))
    assert len(calls) == 1  # a refusal is final; only 429/502/503 are tried again


def test_a_notification_files_an_inbox_update(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    current = state(args={"who": "Ann"})
    run([{"type": "notification", "title": "Done", "message": "$args.who"}], current)
    assert current["last"]["code"] == "NOTIFICATION_CREATED"
    assert cp.get("request", current["last"]["request_id"])["kind"] == "update"


NESTED = {"type": "automation_call", "automation_id": "sub", "published_version": 1}


def nested(definition):
    return state(action_id="root", publication={"automations": {"sub@1": {"definition": definition}}})


def test_nested_automations_need_their_pinned_publication_approval_and_inputs():
    assert refused([NESTED], state(publication={"automations": {}}))[0:2] == (422, "PUBLICATION_REQUIRED")
    asks = {"authorization": "owner_confirmation"}
    assert refused([NESTED], nested(asks))[0:2] == (403, "POLICY_DENIED")
    needs = {"authorization": "auto", "inputs": [{"name": "text", "type": "string", "required": True}]}
    assert refused([NESTED], nested(needs))[0:2] == (422, "VALIDATION_ERROR")


def test_a_broken_editor_graph_reports_its_input_error():
    assert wf._automation_input_errors({"workflow": [{"type": "editor_graph"}]}, {}) != []
