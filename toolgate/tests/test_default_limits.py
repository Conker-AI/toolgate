"""A tool cannot exist without a ceiling.

The enforcement was always here - `enforce_usage_limits` checks per-minute,
per-hour and cooldown before every execution. What was missing is that a tool
created through the API with no policy got `{}`, and an absent limit reads as
unlimited. The seeded tools were fine; anything created afterwards, including
a tool Conker proposes, was not.
"""
import unittest

import pytest

from toolgate.core import control_plane
from toolgate.core.control_plane import DEFAULT_USAGE_LIMITS, with_default_limits


def test_a_tool_created_with_no_policy_still_gets_ceilings():
    limits = with_default_limits(None)["usage_limits"]
    assert limits == DEFAULT_USAGE_LIMITS
    assert all(limits[name] is not None for name in DEFAULT_USAGE_LIMITS)


def test_an_explicit_limit_is_never_overridden():
    """The point is not to cap what the owner chose. A tool that genuinely
    needs a higher ceiling says so, which makes it a decision rather than an
    oversight."""
    policy = with_default_limits({"usage_limits": {"max_per_minute": 600}})
    assert policy["usage_limits"]["max_per_minute"] == 600
    assert policy["usage_limits"]["max_per_hour"] == DEFAULT_USAGE_LIMITS["max_per_hour"]


def test_a_null_limit_is_treated_as_absent_not_as_unlimited():
    """`None` is exactly the shape the bug had: present in the dict, and read
    by the enforcer as "no ceiling"."""
    policy = with_default_limits({"usage_limits": {"max_per_hour": None}})
    assert policy["usage_limits"]["max_per_hour"] == DEFAULT_USAGE_LIMITS["max_per_hour"]


def test_a_zero_cooldown_survives():
    """Zero is a legitimate cooldown and must not be mistaken for missing."""
    policy = with_default_limits({"usage_limits": {"cooldown_seconds": 0}})
    assert policy["usage_limits"]["cooldown_seconds"] == 0


def test_unrelated_policy_keys_are_preserved():
    policy = with_default_limits({"destinations": ["api.example.com"]})
    assert policy["destinations"] == ["api.example.com"]
    assert policy["usage_limits"]["max_per_minute"] == DEFAULT_USAGE_LIMITS["max_per_minute"]


class ToolsAreRegisteredWithCeilings(unittest.TestCase):
    """Through `create_tool`, not through the helper.

    The helper being correct proves nothing if the registration path does not
    call it - which is exactly the shape the original bug had.
    """

    @pytest.fixture(autouse=True)
    def _use_tmp_path(self, tmp_path):  # pytest's temporary directory, set before setUp
        self.tmp_path = tmp_path

    def setUp(self):
        self.original_db = control_plane.DB_PATH
        control_plane.DB_PATH = self.tmp_path / "toolgate-test.db"

    def tearDown(self):
        control_plane.DB_PATH = self.original_db

    def test_a_tool_registered_with_no_policy_has_finite_ceilings(self):
        tool = control_plane.create_tool({"id": "proposed.tool", "name": "Proposed"})
        limits = tool["policy"]["usage_limits"]
        self.assertEqual(limits["max_per_minute"], DEFAULT_USAGE_LIMITS["max_per_minute"])
        self.assertEqual(limits["max_per_hour"], DEFAULT_USAGE_LIMITS["max_per_hour"])
        self.assertIsNotNone(limits["max_runtime_seconds"])

    def test_updating_a_tool_does_not_drop_its_ceilings(self):
        """`update_tool` rebuilds the record through `create_tool`, so an edit
        that omits policy must not quietly return the tool to unlimited."""
        control_plane.create_tool({"id": "edited.tool", "name": "Edited",
                                   "policy": {"usage_limits": {"max_per_minute": 2}}})
        updated = control_plane.update_tool("edited.tool", {"name": "Edited again"})
        self.assertIsNotNone(updated["policy"]["usage_limits"]["max_per_minute"])

    def test_an_automation_registered_with_no_policy_has_ceilings(self):
        automation = control_plane.create_automation({"id": "proposed.auto", "name": "Proposed"})
        self.assertIsNotNone(automation["policy"]["usage_limits"]["max_per_hour"])
