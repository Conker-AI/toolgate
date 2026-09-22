"""Executable-shape validation, separate from permissive editor draft storage."""
from __future__ import annotations

from .editor_drafts import EditorDocument


def validate_graph(document: EditorDocument) -> list[dict]:
    issues = []

    def issue(message, node_id=None):
        issues.append({"message": message, "node_id": node_id})

    nodes = {node.id: node for node in document.nodes}
    if len(nodes) != len(document.nodes):
        issue("Node identities must be unique.")
        return issues
    if len({edge.id for edge in document.edges}) != len(document.edges):
        issue("Connection identities must be unique.")
    outgoing = {identity: [] for identity in nodes}
    incoming = {identity: [] for identity in nodes}
    for edge in document.edges:
        if edge.source not in nodes or edge.target not in nodes:
            issue("A connection refers to a missing node.")
        else:
            outgoing[edge.source].append(edge)
            incoming[edge.target].append(edge)
    roots = [node.id for node in document.nodes if node.type == "input"]
    if len(roots) != 1:
        issue("Use exactly one Input node.")
    for node in document.nodes:
        edges = outgoing[node.id]
        if node.type == "input" and incoming[node.id]:
            issue("Input cannot have incoming connections.", node.id)
        if node.type == "return":
            if edges:
                issue("Return cannot have outgoing connections.", node.id)
        elif node.type == "condition":
            if len(edges) != 2 or {edge.branch for edge in edges} != {"true", "false"}:
                issue("Connect both True and False branches exactly once.", node.id)
        elif len(edges) != 1 or edges[0].branch is not None:
            issue("Connect exactly one next step without a branch label.", node.id)
    for fields in (document.inputs, document.outputs):
        if len({field.name for field in fields}) != len(fields):
            issue("Field names must be unique within each schema.")
    if issues:
        return issues

    visited, active, order = set(), set(), []

    def visit(identity):
        if identity in active:
            issue("Graph cycles are unsupported; use a bounded Loop node.", identity)
            return
        if identity in visited:
            return
        visited.add(identity)
        active.add(identity)
        for edge in outgoing[identity]:
            visit(edge.target)
        active.remove(identity)
        order.append(identity)

    visit(roots[0])
    for identity in nodes.keys() - visited:
        issue("Node is disconnected from Input.", identity)
    if issues:
        return issues
    # A step value is usable only if that step runs on every route to this node.
    dominators = {}
    for identity in reversed(order):
        parents = [dominators[edge.source] for edge in incoming[identity]]
        dominators[identity] = (set.intersection(*parents) if parents else set()) | {identity}

    allowed_configs = {
        "input": (set(), set()), "set": ({"value"}, set()), "return": ({"value"}, set()),
        "calculation": ({"operator", "left", "right"}, set()),
        "condition": ({"operator", "left"}, {"right"}),
        "loop": ({"items", "limit", "operation"}, set()),
        "tool_call": ({"tool", "args"}, set()),
        "workflow_call": ({"toolId", "version", "args"}, set()),
    }
    inputs = {field.name for field in document.inputs}
    for node in document.nodes:
        config = node.config
        required, optional = allowed_configs[node.type]
        if not required <= config.keys() or config.keys() - required - optional:
            issue("Step configuration has missing or unsupported fields.", node.id)
            continue
        if node.type == "calculation" and config["operator"] not in ("add", "subtract", "multiply", "divide"):
            issue("Choose a supported calculation operator.", node.id)
        if node.type == "condition":
            if config["operator"] not in ("equals", "greater", "less", "contains", "exists"):
                issue("Choose a supported condition operator.", node.id)
            if config["operator"] != "exists" and "right" not in config:
                issue("Comparison needs a right value.", node.id)
        if node.type == "loop":
            if (type(config["limit"]) is not int or not 1 <= config["limit"] <= document.budgets.maxLoopItems
                    or config["operation"] not in ("identity", "trim", "uppercase")):
                issue("Use a supported loop operation within the item budget.", node.id)
        if node.type in ("tool_call", "workflow_call"):
            target = config["tool"] if node.type == "tool_call" else config["toolId"]
            if not isinstance(target, str) or not target or target.startswith("$") or not isinstance(config["args"], dict):
                issue("Use a literal capability identity and an argument object.", node.id)
            if node.type == "workflow_call" and (type(config["version"]) is not int or config["version"] < 1):
                issue("Select a positive published version.", node.id)

        def references(value):
            if isinstance(value, dict):
                for child in value.values():
                    references(child)
            elif isinstance(value, list):
                for child in value:
                    references(child)
            elif isinstance(value, str) and value.startswith("$") and not value.startswith("$$"):
                root, *parts = value[1:].split(".")
                if root not in {"input", "steps", "last"} or any(
                        part in {"", "__proto__", "constructor", "prototype"} for part in parts):
                    issue("Use a valid input, step or previous-result reference.", node.id)
                elif root == "input" and parts and parts[0] not in inputs:
                    issue("Reference names an undeclared input.", node.id)
                elif root == "steps" and (not parts or parts[0] == node.id or parts[0] not in dominators[node.id]):
                    issue("Referenced step must run on every path to this node.", node.id)
        references(config)
    return issues
