"""Workflow references and required inputs (hunt toolgate-2 F1, F6)."""

import pytest

from toolgate.api.workflows import _workflow_value
from toolgate.core import control_plane

STATE = {"args": {"who": "Ada"}, "vars": {"n": 2}, "last": {"name": "previous", "items": [5]}}


@pytest.mark.parametrize("text", ["$lastname", "$last week", "$latest", "$last_seen"])
def test_text_that_only_starts_like_last_stays_text(text):
    assert _workflow_value(text, STATE) == text


def test_last_and_its_paths_still_resolve():
    assert _workflow_value("$last", STATE) == STATE["last"]
    assert _workflow_value("$last.name", STATE) == "previous"
    assert _workflow_value({"x": ["$last.items.0", "$args.who"]}, STATE) == {"x": [5, "Ada"]}


SCHEMA = [{"name": "title", "type": "string", "required": True, "min_length": 3},
          {"name": "note", "type": "string"}]


def test_a_required_input_sent_as_null_is_missing():
    assert control_plane.validate_inputs(SCHEMA, {"title": None}) == ["'title' is required"]


def test_an_optional_input_may_still_be_null():
    assert control_plane.validate_inputs(SCHEMA, {"title": "Hello", "note": None}) == []
