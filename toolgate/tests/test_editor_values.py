import pytest

from toolgate.core.editor_drafts import ToolField
from toolgate.core.editor_values import GraphValueError, bounded, compare, inputs, resolve


def test_defaults_missing_fields_and_exact_input_types():
    fields = [ToolField(name="count", type="number", required=True, default=2),
              ToolField(name="note", type="string", required=False)]
    assert inputs(fields, {}) == {"count": 2}
    for supplied in ({"count": True}, {"extra": 1}, {"note": None}):
        with pytest.raises(GraphValueError):
            inputs(fields, supplied)
    with pytest.raises(GraphValueError, match="Missing required"):
        inputs([ToolField(name="value", type="string", required=True)], {})


def test_references_preserve_values_and_do_not_mutate_step_state():
    steps = {"first": {"nested": [1, 2]}}
    assert resolve("$$input.literal", {}, steps, None) == "$input.literal"
    assert resolve("$steps.first.nested.1", {}, steps, None) == 2
    resolved = resolve("$steps.first", {}, steps, None)
    resolved["nested"].append(3)
    assert steps["first"]["nested"] == [1, 2]
    assert resolve({"answer": ["$input.value", "$last"]}, {"value": 4}, {}, 5) == {"answer": [4, 5]}


def test_missing_references_fail_except_for_explicit_existence_checks():
    for reference in ("$input.absent", "$steps.other", "$last.missing", "$input.items.01"):
        with pytest.raises(GraphValueError):
            resolve(reference, {"items": [0, 1]}, {}, None)
        assert resolve(reference, {"items": [0, 1]}, {}, None, allow_missing=True) is None
    for reference in ("$vault.secret", "$input.__proto__", "$input."):
        with pytest.raises(GraphValueError):
            resolve(reference, {}, {}, None, allow_missing=True)


def test_conditions_never_conflate_booleans_and_numbers():
    assert compare("equals", 1, 1.0)
    assert not compare("equals", True, 1)
    assert not compare("contains", [1, 2], True)
    assert compare("contains", [{"name": "a"}], {"name": "a"})
    assert compare("exists", False, None)
    assert not compare("exists", None, None)
    with pytest.raises(GraphValueError):
        compare("greater", "2", 1)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 9007199254740992, "x" * 65537],
                         ids=["nan", "infinity", "unsafe-integer", "oversized-text"])
def test_values_cannot_overflow_or_silently_round_in_browser_receipts(value):
    with pytest.raises(GraphValueError):
        bounded(value)


def test_structure_budget_and_copy_isolation():
    value = []
    for _ in range(22):
        value = [value]
    with pytest.raises(GraphValueError):
        bounded(value)
    original = {"a": [1]}
    result = bounded(original)
    result["a"].append(2)
    assert original == {"a": [1]}
