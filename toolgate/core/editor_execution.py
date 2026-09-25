"""Bounded graph evaluator. Capability dispatch is supplied by ToolGate's boundary."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .editor_drafts import EditorDocument
from .editor_graph import validate_graph
from .editor_values import GraphValueError, bounded, compare, inputs, matches, resolve


class GraphExecutionError(GraphValueError):
    def __init__(self, message, node_id, receipts):
        super().__init__(message)
        self.node_id = node_id
        self.receipts = receipts


@dataclass
class Budget:
    """One shared counter stack across nested editor calls; no child resets it."""
    steps: int = 0
    items: int = 0
    frames: list = field(default_factory=list)
    clock: object = time.monotonic

    def check(self):
        for frame in self.frames:
            if (self.steps - frame[0] > frame[3].maxSteps
                    or self.items - frame[1] > frame[3].maxLoopItems
                    or self.clock() - frame[2] > frame[3].timeoutMs / 1000):
                raise GraphValueError("Workflow exceeded its shared execution budget.")

    def charge(self, *, item=False):
        self.steps += 1
        if item:
            self.items += 1
        self.check()


def execute(document: EditorDocument, supplied, *, dispatch=None, budget=None, on_step=None):
    """Dispatch callback receives the declared node, resolved args and shared budget.

    This function does not look up credentials or invoke capabilities itself. A
    caller must validate publications and supply its authorized dispatch boundary.
    Callback failures propagate unchanged: an uncertain action is never relabelled
    as a completed graph or retried here.
    """
    issues = validate_graph(document)
    if issues:
        raise GraphExecutionError(issues[0]["message"], issues[0]["node_id"], [])
    budget = budget if budget is not None else Budget()
    if len(budget.frames) >= 8:
        raise GraphExecutionError("Published graph nesting exceeds eight levels.", None, [])
    budget.frames.append((budget.steps, budget.items, budget.clock(), document.budgets))
    receipts, outputs = [], {}
    current = None
    def charge(*, item=False):
        budget.charge(item=item)
        if on_step:
            on_step()
    try:
        normalized = inputs(document.inputs, supplied)
        last = normalized
        nodes = {node.id: node for node in document.nodes}
        current = next(node for node in document.nodes if node.type == "input")
        while current is not None:
            charge()
            config = current.config
            branch = None
            def value(item, missing=False):
                return resolve(item, normalized, outputs, last, allow_missing=missing)
            if current.type == "input":
                output = normalized
            elif current.type in {"set", "return"}:
                output = value(config["value"])
            elif current.type == "calculation":
                left, right = value(config["left"]), value(config["right"])
                if type(left) not in (int, float) or type(right) not in (int, float):
                    raise GraphValueError("Calculation requires numeric operands.")
                if config["operator"] == "divide" and right == 0:
                    raise GraphValueError("Cannot divide by zero.")
                operations = {"add": lambda: left + right, "subtract": lambda: left - right,
                              "multiply": lambda: left * right, "divide": lambda: left / right}
                output = operations[config["operator"]]()
            elif current.type == "condition":
                output = compare(config["operator"], value(config["left"], config["operator"] == "exists"),
                                 value(config["right"]) if "right" in config else None)
                branch = "true" if output else "false"
            elif current.type == "loop":
                items = value(config["items"])
                if not isinstance(items, list):
                    raise GraphValueError("Loop input must be an array.")
                if len(items) > config["limit"]:
                    raise GraphValueError("Loop input exceeds its item limit; no partial list was processed.")
                mapped = []
                for item in items:
                    charge(item=True)
                    if config["operation"] == "identity":
                        mapped.append(item)
                    elif not isinstance(item, str):
                        raise GraphValueError("Trim and uppercase require string items.")
                    else:
                        mapped.append(item.strip() if config["operation"] == "trim" else item.upper())
                output = {"items": mapped, "count": len(mapped)}
            else:
                if dispatch is None:
                    raise GraphValueError("No authorized capability dispatch is configured.")
                args = value(config["args"])
                if not isinstance(args, dict):
                    raise GraphValueError("Capability arguments must resolve to an object.")
                output = dispatch(current, bounded(args), budget)
            # Check again after calls; exceeding a deadline never yields a success.
            budget.check()
            output = bounded(output)
            if current.type == "return":
                for item in document.outputs:
                    present = isinstance(output, dict) and item.name in output
                    if (not present and item.required) or (present and not matches(output[item.name], item.type)):
                        raise GraphValueError(f"Output does not match its declared type: {item.name}.")
            # Bound total receipt volume as well as each individual value.
            receipt = {"nodeId": current.id, "label": current.label, "type": current.type,
                       "status": "completed", "output": output}
            bounded([*receipts, receipt])
            if current.type == "return":
                skipped = [{"nodeId": node.id, "label": node.label, "type": node.type,
                            "status": "skipped"} for node in document.nodes
                           if node.id not in outputs and node.id != current.id]
                return bounded({"output": output, "steps": [*receipts, receipt, *skipped]})
            receipts.append(receipt)
            outputs[current.id] = output
            last = output
            edge = next(edge for edge in document.edges if edge.source == current.id and edge.branch == branch)
            current = nodes[edge.target]
        raise GraphValueError("Workflow did not reach Return.")
    except GraphExecutionError:
        raise
    except (GraphValueError, OverflowError) as error:
        message = str(error) if isinstance(error, GraphValueError) else "Calculation exceeded numeric bounds."
        if current:
            receipts.append({"nodeId": current.id, "label": current.label, "type": current.type,
                             "status": "failed", "error": message})
        raise GraphExecutionError(message, current.id if current else None, receipts) from error
    finally:
        budget.frames.pop()
