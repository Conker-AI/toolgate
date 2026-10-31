"""Workflow runtime: runs automation steps, branches and nested automations through invoke_tool."""

import hashlib
import math
import time

from fastapi import HTTPException

from toolgate.api.deps import deny
from toolgate.api.invocation import (
    enforce_dispatch_usage_limits,
    invoke_tool,
    require_current_dispatch_authority,
)
from toolgate.core import (
    approvals,
    control_plane,
    editor_execution,
    editor_publication,
    publications,
    tool_settings,
)
from toolgate.core import execution_journal as journal


def _lookup_path(value, path: str):
    for part in path.split(".") if path else []:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def _workflow_value(value, state: dict):
    if isinstance(value, str) and value.startswith("$args."):
        return _lookup_path(state["args"], value[6:])
    if isinstance(value, str) and value.startswith("$vars."):
        return _lookup_path(state["vars"], value[6:])
    if isinstance(value, str) and value.startswith("$last"):
        return _lookup_path(state.get("last"), value[6:] if value.startswith("$last.") else "")
    if isinstance(value, list):
        return [_workflow_value(item, state) for item in value]
    if isinstance(value, dict):
        return {key: _workflow_value(item, state) for key, item in value.items()}
    return value


def _workflow_compare(actual, operator: str, expected) -> bool:
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        return expected in actual
    if operator == "in":
        return actual in expected
    if operator in {"gte", "lte", "gt", "lt"}:
        left, right = float(actual), float(expected)
        return {"gte": left >= right, "lte": left <= right, "gt": left > right, "lt": left < right}[
            operator
        ]
    raise ValueError(f"unsupported operator {operator}")


def _charge_workflow(state):
    for frame in (state, *state.get("ancestors", ())):
        frame["count"] += 1
        if frame["count"] > frame["max_steps"]:
            deny("POLICY_DENIED", "Automation exceeded its shared ancestor step ceiling")
        if time.monotonic() - frame["started_at"] > frame["runtime_ceiling"]:
            deny("POLICY_DENIED", "Automation exceeded its shared ancestor runtime ceiling")


def _run_editor_graph(step, state, actor, approval_granted):
    if not state.get("publication"):
        deny("PUBLICATION_REQUIRED", "Editor graphs require an immutable published version", 422)
    document = editor_publication.document_from_block(step)
    budget = state.setdefault("graph_budget", editor_execution.Budget())

    def dispatch(node, args, _budget):
        if node.type == "workflow_call":
            result = _invoke_nested_automation(
                {
                    "automation_id": node.config["toolId"],
                    "published_version": node.config["version"],
                },
                state,
                actor,
                approval_granted,
                resolved_args=args,
            )
        else:
            tool = state["tool_snapshot"].get(node.config["tool"])
            if not tool:
                deny(
                    "PUBLICATION_REQUIRED", "Graph capability is not pinned in its publication", 422
                )
            child_id = (
                "child_"
                + hashlib.sha256(f"{state['action_id']}:{state['count']}".encode()).hexdigest()
            )
            result = invoke_tool(
                tool,
                args,
                actor,
                approval_granted=approval_granted,
                actor_id=state["actor_id"],
                action_id=child_id,
                job_id=state.get("job_id"),
                parent_action_id=state["action_id"],
                authority_scope=state["authority_scope"],
                publication=state.get("root_publication", state["publication"]),
            )
        if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
            deny(
                "OUTCOME_UNKNOWN", "A graph child dispatch is uncertain; reconcile its receipt", 409
            )
        if result.get("code") != "OK":
            raise editor_execution.GraphValueError(
                "A graph capability did not complete successfully; inspect its receipt."
            )
        # Expose the executor output, not credentials or the journal envelope.
        payload = result.get("result", {})
        return payload.get("result") if isinstance(payload, dict) else payload

    try:
        result = editor_execution.execute(
            document,
            state["args"],
            dispatch=dispatch,
            budget=budget,
            on_step=lambda: _charge_workflow(state),
        )
    except editor_execution.GraphExecutionError as exc:
        state["results"] = exc.receipts
        return {"code": "WORKFLOW_FAILED", "message": str(exc), "node_id": exc.node_id}
    state["results"] = result["steps"]
    return {"code": "OK", "result": result["output"]}


def _run_workflow_steps(steps: list, state: dict, actor: str, approval_granted: bool):
    if len(steps) == 1 and steps[0].get("type") == "editor_graph":
        return _run_editor_graph(steps[0], state, actor, approval_granted)
    for step in steps:
        _charge_workflow(state)
        if state.get("graph_budget"):
            state["graph_budget"].charge()
        kind = step["type"]
        result = None
        if kind == "tool_call":
            tool = (
                state["tool_snapshot"].get(step["tool_id"])
                if "tool_snapshot" in state
                else control_plane.get("tool", step["tool_id"])
            )
            if not tool or tool.get("status") != "active":
                deny(
                    "TOOL_UNAVAILABLE", f"Workflow references unavailable tool '{step['tool_id']}'"
                )
            if tool.get("authorization") != "auto" and not approval_granted:
                deny(
                    "POLICY_DENIED",
                    f"Automation must require confirmation before calling '{tool['id']}'",
                )
            call_args = {
                field["name"]: state["args"][field["name"]]
                for field in tool.get("inputs", [])
                if field.get("name") in state["args"]
            }
            call_args.update(_workflow_value(step.get("args", {}), state))
            parent_id = state.get("action_id")
            child_id = (
                ("child_" + hashlib.sha256(f"{parent_id}:{state['count']}".encode()).hexdigest())
                if parent_id
                else None
            )
            result = invoke_tool(
                tool,
                call_args,
                actor,
                approval_granted=approval_granted,
                actor_id=state.get("actor_id"),
                action_id=child_id,
                job_id=state.get("job_id"),
                parent_action_id=parent_id,
                publication=state.get("root_publication", state.get("publication")),
                authority_scope=state.get("authority_scope"),
            )
            if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
                deny("OUTCOME_UNKNOWN", "A child dispatch is uncertain; this workflow is held", 409)
        elif kind == "automation_call":
            result = _invoke_nested_automation(step, state, actor, approval_granted)
        elif kind == "set":
            state["vars"][step.get("name", "value")] = _workflow_value(step.get("value"), state)
            result = {"code": "VALUE_SET", "name": step.get("name", "value")}
        elif kind == "calculation":
            values = [_workflow_value(value, state) for value in step.get("values", [])]
            operation = step.get("operation", "add")
            if not values or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or (isinstance(value, float) and not math.isfinite(value))
                for value in values
            ):
                deny("VALIDATION_ERROR", "Calculation values must resolve to numbers", 422)
            calculated = {
                "add": lambda: sum(values),
                "subtract": lambda: values[0] - sum(values[1:]),
                "multiply": lambda: __import__("math").prod(values),
                "divide": lambda: values[0] / __import__("math").prod(values[1:]),
                "min": lambda: min(values),
                "max": lambda: max(values),
            }.get(operation)
            if not calculated:
                deny("VALIDATION_ERROR", f"Unsupported calculation '{operation}'", 422)
            try:
                value = calculated()
            except ZeroDivisionError:
                deny("VALIDATION_ERROR", "Calculation divided by zero", 422)
            except OverflowError:
                deny("VALIDATION_ERROR", "Calculation exceeded the numeric range", 422)
            if isinstance(value, float) and not math.isfinite(value):
                deny("VALIDATION_ERROR", "Calculation result must be finite", 422)
            state["vars"][step.get("save_as", "calculation")] = value
            result = {"code": "CALCULATED", "result": value}
        elif kind == "condition":
            actual = _workflow_value(step.get("left", f"$args.{step.get('field', '')}"), state)
            expected = _workflow_value(step.get("right", step.get("value")), state)
            try:
                matches = _workflow_compare(actual, step.get("operator", "equals"), expected)
            except (TypeError, ValueError):
                deny("VALIDATION_ERROR", "Condition could not compare its configured values", 422)
            branch = step.get("then", []) if matches else step.get("else", [])
            result = {"code": "CONDITION_MET" if matches else "CONDITION_NOT_MET"}
            final = _run_workflow_steps(branch, state, actor, approval_granted)
            if final is not None:
                state["results"].append({"type": kind, "result": result})
                return final
            if not matches and not branch and step.get("on_false", "stop") == "stop":
                deny("POLICY_DENIED", "Automation condition was not met")
        elif kind == "switch":
            selected = str(_workflow_value(step.get("value"), state))
            branch = step.get("cases", {}).get(selected, step.get("default", []))
            result = {"code": "SWITCH_SELECTED", "case": selected}
            final = _run_workflow_steps(branch, state, actor, approval_granted)
            if final is not None:
                state["results"].append({"type": kind, "result": result})
                return final
        elif kind == "loop":
            items = _workflow_value(step.get("items"), state)
            if not isinstance(items, list):
                deny("VALIDATION_ERROR", "Loop items must resolve to an array", 422)
            if len(items) > step["max_iterations"]:
                deny("POLICY_DENIED", "Loop input exceeds its deterministic iteration ceiling")
            item_name = step.get("item_name", "item")
            had_previous = item_name in state["vars"]
            previous = state["vars"].get(item_name)
            try:
                for iterations, item in enumerate(items, 1):
                    state["vars"][item_name] = item
                    final = _run_workflow_steps(
                        step.get("steps", []), state, actor, approval_granted
                    )
                    if final is not None:
                        state["results"].append({
                            "type": kind,
                            "result": {"code": "LOOP_RETURNED", "iterations": iterations},
                        })
                        return final
            finally:
                if had_previous:
                    state["vars"][item_name] = previous
                else:
                    state["vars"].pop(item_name, None)
            result = {"code": "LOOP_COMPLETE", "iterations": len(items)}
        elif kind == "retry":
            last_error = None
            for attempt in range(step["max_attempts"]):
                try:
                    final = _run_workflow_steps([step["step"]], state, actor, approval_granted)
                    if final is not None:
                        state["results"].append({
                            "type": kind,
                            "result": {"code": "RETRY_COMPLETE", "attempts": attempt + 1},
                        })
                        return final
                    last_error = None
                    break
                except HTTPException as exc:
                    last_error = exc
                    if (
                        exc.status_code not in {429, 502, 503}
                        or attempt + 1 >= step["max_attempts"]
                    ):
                        raise
                    time.sleep(min(float(step.get("delay_seconds", 0)), 5))
            result = {
                "code": "RETRY_COMPLETE",
                "attempts": step["max_attempts"] if last_error else attempt + 1,
            }
        elif kind == "delay":
            time.sleep(float(step.get("seconds", 0)))
            result = {"code": "DELAY_COMPLETE", "seconds": step.get("seconds", 0)}
        elif kind == "notification":
            notification = approvals.create_request(
                "update",
                step.get("title", "Automation update"),
                str(_workflow_value(step.get("message", "Automation notification"), state)),
                actor,
                {"automation_id": state["automation_id"]},
                "info",
            )
            result = {"code": "NOTIFICATION_CREATED", "request_id": notification["id"]}
        elif kind == "return":
            return {"code": "OK", "result": _workflow_value(step.get("value"), state)}
        state["last"] = result
        state["results"].append({"type": kind, "result": result})
    return None


def _automation_input_errors(definition, args):
    workflow = definition.get("workflow", [])
    if len(workflow) == 1 and workflow[0].get("type") == "editor_graph":
        try:
            document = editor_publication.document_from_block(workflow[0])
            editor_execution.inputs(document.inputs, args)
            return []
        except ValueError as exc:
            return [str(exc)]
    return control_plane.validate_inputs(definition.get("inputs", []), args)


def _invoke_nested_automation(
    step: dict, state: dict, actor: str, approval_granted: bool, *, resolved_args=None
) -> dict:
    publication = (
        (state.get("publication") or {}).get("automations", {}).get(publications.nested_key(step))
    )
    if not publication:
        deny("PUBLICATION_REQUIRED", "Nested calls require a pinned publication", 422)
    definition = publication["definition"]
    if definition.get("authorization", "auto") != "auto" and not approval_granted:
        deny("POLICY_DENIED", "Nested automation requires root owner confirmation", 403)
    args = (
        resolved_args if resolved_args is not None else _workflow_value(step.get("args", {}), state)
    )
    errors = _automation_input_errors(definition, args)
    if errors:
        deny("VALIDATION_ERROR", "; ".join(errors), 422)
    action_id = (
        "child_" + hashlib.sha256(f"{state['action_id']}:{state['count']}".encode()).hexdigest()
    )
    root_publication = state.get("root_publication", state["publication"])

    def authorize(conn):
        require_current_dispatch_authority(conn, state["actor_id"], state["authority_scope"])
        publications.for_execution(
            conn, root_publication["kind"], root_publication["id"], root_publication["version"]
        )
        enforce_dispatch_usage_limits(conn, "automation", definition, "automation_executed")

    record, dispatch = journal.begin(
        action_id,
        "automation",
        definition["id"],
        args,
        state["actor_id"],
        definition["version"],
        job_id=state.get("job_id"),
        parent_action_id=state["action_id"],
        authorize=authorize,
        publication_digest=publication["digest"],
    )
    if not dispatch:
        result = journal.response(record)
        if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
            deny("OUTCOME_UNKNOWN", "Nested dispatch is uncertain; this workflow is held", 409)
        return result
    limits = definition.get("policy", {}).get("usage_limits", {})
    nested = {
        "automation_id": definition["id"],
        "tool_snapshot": publication["tools"],
        "publication": publication,
        "root_publication": root_publication,
        "authority_scope": state["authority_scope"],
        "action_id": action_id,
        "job_id": state.get("job_id"),
        "actor_id": state["actor_id"],
        "args": args,
        "vars": {},
        "last": None,
        "results": [],
        "count": 0,
        "ancestors": (state, *state.get("ancestors", ())),
        "max_steps": int(limits.get("max_steps", 100)),
        "started_at": time.monotonic(),
        "runtime_ceiling": tool_settings.seconds(
            min(int(limits.get("max_runtime_seconds", 30) or 30), 120)
        ),
    }
    if state.get("graph_budget"):
        nested["graph_budget"] = state["graph_budget"]
    try:
        final = _run_workflow_steps(definition.get("workflow", []), nested, actor, approval_granted)
    except Exception:  # hold any incomplete nested dispatch; never retry it.
        journal.unknown(action_id)
        deny("OUTCOME_UNKNOWN", "Nested workflow is incomplete; reconcile its receipt", 409)
    failed = isinstance(final, dict) and final.get("code") == "WORKFLOW_FAILED"
    envelope = {
        "code": "WORKFLOW_FAILED" if failed else "OK",
        "message": "Nested workflow failed" if failed else "Nested automation completed",
        "result": final,
        "steps": nested["results"],
        "variables": nested["vars"],
        "publication": {
            "kind": "automation",
            "id": definition["id"],
            "version": publication["version"],
            "digest": publication["digest"],
        },
    }
    record = journal.finish(action_id, envelope)
    control_plane.event(
        "automation_executed",
        "info",
        "automation",
        definition["id"],
        actor,
        {"steps": nested["count"], "version": definition["version"], "action_id": action_id},
    )
    return journal.response(record)
