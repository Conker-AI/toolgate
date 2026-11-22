"""Validation of workflow blocks inside tool and automation definitions."""

import re

from toolgate.core import editor_publication, publications

SUPPORTED_WORKFLOW_BLOCKS = {
    "tool_call",
    "automation_call",
    "condition",
    "switch",
    "loop",
    "calculation",
    "set",
    "delay",
    "retry",
    "notification",
    "return",
    "editor_graph",
}


def workflow_definition_errors(workflow: list, depth: int = 0) -> list[str]:
    if not isinstance(workflow, list):
        return ["workflow must be a list"]
    if depth > 4:
        return ["workflow nesting cannot exceed four levels"]
    errors = []
    for index, step in enumerate(workflow):
        prefix = f"step {index + 1}"
        if not isinstance(step, dict) or step.get("type") not in SUPPORTED_WORKFLOW_BLOCKS:
            errors.append(f"{prefix} has an unsupported block type")
            continue
        kind = step["type"]
        if kind == "editor_graph":
            if depth != 0 or len(workflow) != 1:
                errors.append("An editor graph must be the entire workflow definition")
            try:
                editor_publication.document_from_block(step)
            except ValueError as exc:
                errors.append(f"{prefix}: {exc}")
            continue
        if kind == "automation_call":
            try:
                publications.nested_key(step)
            except publications.PublicationInvalid as exc:
                errors.append(f"{prefix}: {exc}")
            if not isinstance(step.get("args", {}), dict):
                errors.append(f"{prefix} args must be an object")
            if "publication_digest" in step and (
                not isinstance(step["publication_digest"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", step["publication_digest"])
            ):
                errors.append(f"{prefix} publication_digest must be a SHA-256 digest")
        if kind == "tool_call":
            if not step.get("tool_id"):
                errors.append(f"{prefix} needs tool_id")
            if not isinstance(step.get("args", {}), dict):
                errors.append(f"{prefix} args must be an object")
        if kind == "set":
            if not isinstance(step.get("name"), str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]{0,79}", step.get("name", "")
            ):
                errors.append(f"{prefix} set name must be a variable identifier")
            if "value" not in step:
                errors.append(f"{prefix} set requires value")
        if kind == "calculation":
            if step.get("operation", "add") not in {
                "add",
                "subtract",
                "multiply",
                "divide",
                "min",
                "max",
            }:
                errors.append(f"{prefix} has an unsupported calculation operation")
            if not isinstance(step.get("values"), list) or not step.get("values"):
                errors.append(f"{prefix} calculation requires values")
        if kind == "condition":
            if "left" not in step and not step.get("field"):
                errors.append(f"{prefix} condition requires left or field")
            if step.get("operator", "equals") not in {
                "equals",
                "not_equals",
                "contains",
                "in",
                "gte",
                "lte",
                "gt",
                "lt",
            }:
                errors.append(f"{prefix} has an unsupported condition operator")
            if "right" not in step and "value" not in step:
                errors.append(f"{prefix} condition requires right or value")
        if kind == "loop":
            if (
                not isinstance(step.get("max_iterations"), int)
                or not 1 <= step["max_iterations"] <= 20
            ):
                errors.append(f"{prefix} max_iterations must be between 1 and 20")
            if "items" not in step:
                errors.append(f"{prefix} loop requires items")
            errors.extend(workflow_definition_errors(step.get("steps", []), depth + 1))
        if kind == "retry":
            if not isinstance(step.get("max_attempts"), int) or not 1 <= step["max_attempts"] <= 3:
                errors.append(f"{prefix} max_attempts must be between 1 and 3")
            if not isinstance(step.get("step"), dict):
                errors.append(f"{prefix} retry requires one step object")
            errors.extend(workflow_definition_errors([step.get("step")], depth + 1))
        if kind == "condition":
            errors.extend(workflow_definition_errors(step.get("then", []), depth + 1))
            errors.extend(workflow_definition_errors(step.get("else", []), depth + 1))
        if kind == "switch":
            if "value" not in step:
                errors.append(f"{prefix} switch requires value")
            cases = step.get("cases", {})
            if not isinstance(cases, dict) or len(cases) > 10:
                errors.append(f"{prefix} cases must be an object with at most 10 branches")
            else:
                for branch in cases.values():
                    errors.extend(workflow_definition_errors(branch, depth + 1))
            errors.extend(workflow_definition_errors(step.get("default", []), depth + 1))
        if kind == "delay" and (
            not isinstance(step.get("seconds", 0), (int, float))
            or not 0 <= step.get("seconds", 0) <= 30
        ):
            errors.append(f"{prefix} delay must be between 0 and 30 seconds")
        if kind == "return" and "value" not in step:
            errors.append(f"{prefix} return requires value")
    return errors


def workflow_tool_ids(workflow: list, block_type: str = "tool_call") -> list[str]:
    ids = []
    if not isinstance(workflow, list):
        return ids
    for step in workflow:
        if not isinstance(step, dict):
            continue
        field = "tool_id" if block_type == "tool_call" else "automation_id"
        if step.get("type") == "editor_graph":
            ids.extend(workflow_tool_ids(editor_publication.dependency_steps(step), block_type))
        if step.get("type") == block_type and isinstance(step.get(field), str):
            ids.append(step[field])
        for key in ("steps", "then", "else", "default"):
            ids.extend(workflow_tool_ids(step.get(key, []), block_type))
        if isinstance(step.get("step"), dict):
            ids.extend(workflow_tool_ids([step["step"]], block_type))
        cases = step.get("cases", {})
        if isinstance(cases, dict):
            for branch in cases.values():
                ids.extend(workflow_tool_ids(branch, block_type))
    return ids
