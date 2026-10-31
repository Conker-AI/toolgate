import time
import unittest
from unittest.mock import Mock, patch

import httpx
import pytest
from fastapi import HTTPException

from toolgate.api import definitions, dispatch, server, workflows
from toolgate.core import approvals, control_plane


class ControlPlaneTests(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _use_tmp_path(self, tmp_path):  # pytest's temporary directory, set before setUp
        self.tmp_path = tmp_path

    def setUp(self):
        self.original_db = control_plane.DB_PATH
        control_plane.DB_PATH = self.tmp_path / "toolgate-test.db"

    def tearDown(self):
        control_plane.DB_PATH = self.original_db

    def test_tool_and_automation_scopes_are_separate(self):
        tool_agent = {"scopes": ["tool:*"]}
        automation_agent = {"scopes": ["automation:*"]}
        self.assertTrue(control_plane.is_scoped(tool_agent, "weather"))
        self.assertFalse(control_plane.is_scoped(tool_agent, "automation:morning"))
        self.assertTrue(control_plane.is_scoped(automation_agent, "automation:morning"))
        self.assertFalse(control_plane.is_scoped(automation_agent, "weather"))

    def test_input_validation_rejects_unknown_and_wrong_typed_values(self):
        schema = [
            {"name": "count", "type": "integer", "required": True, "minimum": 1, "maximum": 3},
            {"name": "enabled", "type": "boolean", "required": True},
        ]
        errors = control_plane.validate_inputs(schema, {"count": "2", "enabled": 1, "extra": True})
        self.assertIn("'count' must be an integer", errors)
        self.assertIn("'enabled' must be true or false", errors)
        self.assertIn("'extra' is not an allowed argument", errors)

    def test_input_validation_rejects_an_object_input_that_is_not_an_object(self):
        schema = [{"name": "arguments", "type": "object", "required": True}]
        for value in ("x", ["a"], 3, True):
            self.assertEqual(
                ["'arguments' must be an object"],
                control_plane.validate_inputs(schema, {"arguments": value}),
            )
        self.assertEqual([], control_plane.validate_inputs(schema, {"arguments": {"a": 1}}))

    def test_verification_is_bound_to_action_and_consumed_once(self):
        request = approvals.create_verification_request(
            "Run test", "Bound action", "agent", "tool", "echo", {"value": 3}, 2, 60, "agent-key"
        )
        approvals.decide_request(request["id"], "approved", "owner")

        changed, reason = approvals.consume_verification(
            request["id"], "tool", "echo", {"value": 4}, 2, "agent", "agent-key"
        )
        self.assertFalse(changed)
        self.assertIn("does not match", reason)

        approved, reason = approvals.consume_verification(
            request["id"], "tool", "echo", {"value": 3}, 2, "agent", "agent-key"
        )
        self.assertTrue(approved, reason)
        replayed, reason = approvals.consume_verification(
            request["id"], "tool", "echo", {"value": 3}, 2, "agent", "agent-key"
        )
        self.assertFalse(replayed)
        self.assertIn("already been consumed", reason)


    def test_verification_consumption_is_bound_to_creator_agent_key(self):
        request = approvals.create_verification_request(
            "Run test", "Bound actor", "agent one", "tool", "echo", {"value": 3}, 2, 60, "agent-key-1"
        )
        approvals.decide_request(request["id"], "approved", "owner")

        stolen, reason = approvals.consume_verification(
            request["id"], "tool", "echo", {"value": 3}, 2, "agent two", "agent-key-2"
        )
        self.assertFalse(stolen)
        self.assertIn("originating agent", reason)

        approved, reason = approvals.consume_verification(
            request["id"], "tool", "echo", {"value": 3}, 2, "agent one", "agent-key-1"
        )
        self.assertTrue(approved, reason)

    def test_gemini_executor_keeps_key_in_header_and_returns_usage(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": '{"decision":"reject"}'}]}}],
            "usageMetadata": {"promptTokenCount": 42, "candidatesTokenCount": 8, "totalTokenCount": 50},
        }
        execution = {
            "type": "gemini_generate", "model": "gemini-2.5-flash-lite",
            "secret_ref": "GOOGLE_API_KEY", "prompt_template": "Review {prompt}",
            "max_tokens": 800, "temperature": 0, "timeout_seconds": 60,
        }
        with patch.object(server.vault, "get_key", return_value="secret-value"), patch.object(httpx, "post", return_value=response) as post:
            result = dispatch._execute_gemini(execution, {"prompt": "public evidence"})
        self.assertTrue(result["ok"])
        self.assertEqual('{"decision":"reject"}', result["result"]["text"])
        self.assertEqual(50, result["result"]["usage"]["total_tokens"])
        self.assertEqual("secret-value", post.call_args.kwargs["headers"]["x-goog-api-key"])
        self.assertNotIn("secret-value", str(post.call_args.kwargs["json"]))

    def test_array_contract_enforces_batch_size_and_item_pattern(self):
        schema = [{"name": "ids", "type": "array", "required": True, "min_items": 1, "max_items": 2,
                   "unique_items": True, "item_type": "string", "item_pattern": r"rr_[A-Za-z0-9_-]{20,40}"}]
        valid = ["rr_abcdefghijklmnopqrst", "rr_abcdefghijklmnopqrstu"]
        self.assertEqual([], control_plane.validate_inputs(schema, {"ids": valid}))
        self.assertTrue(control_plane.validate_inputs(schema, {"ids": ["bad"]}))
        self.assertTrue(control_plane.validate_inputs(schema, {"ids": [valid[0], valid[0]]}))

    def test_nested_workflow_executes_deterministically(self):
        workflow = [
            {"type": "set", "name": "base", "value": "$args.base"},
            {"type": "calculation", "operation": "add", "values": ["$vars.base", 2], "save_as": "total"},
            {"type": "condition", "left": "$vars.total", "operator": "gte", "right": 5,
             "then": [{"type": "set", "name": "large", "value": True}],
             "else": [{"type": "set", "name": "large", "value": False}]},
            {"type": "loop", "items": "$args.items", "item_name": "item", "max_iterations": 3,
             "steps": [{"type": "set", "name": "last_item", "value": "$vars.item"}]},
            {"type": "switch", "value": "$args.mode",
             "cases": {"fast": [{"type": "set", "name": "speed", "value": 2}]},
             "default": [{"type": "set", "name": "speed", "value": 1}]},
            {"type": "return", "value": {"total": "$vars.total", "large": "$vars.large",
                                             "last": "$vars.last_item", "speed": "$vars.speed"}},
        ]
        self.assertEqual([], definitions.workflow_definition_errors(workflow))
        state = {"automation_id": "test", "args": {"base": 3, "items": ["a", "b"], "mode": "fast"},
                 "vars": {}, "last": None, "results": [], "count": 0, "max_steps": 50,
                 "started_at": time.monotonic(), "runtime_ceiling": 5}
        result = workflows._run_workflow_steps(workflow, state, "test", False)
        self.assertEqual({"total": 5, "large": True, "last": "b", "speed": 2}, result["result"])

    def test_loop_ceiling_and_unsupported_blocks_are_rejected(self):
        errors = definitions.workflow_definition_errors([
            {"type": "loop", "items": [], "max_iterations": 21, "steps": []},
            {"type": "python", "code": "print('unsafe')"},
        ])
        self.assertTrue(any("between 1 and 20" in error for error in errors))
        self.assertTrue(any("unsupported block" in error for error in errors))

        state = {"automation_id": "test", "args": {"items": [1, 2]}, "vars": {}, "last": None,
                 "results": [], "count": 0, "max_steps": 1,
                 "started_at": time.monotonic(), "runtime_ceiling": 5}
        with self.assertRaises(HTTPException) as raised:
            workflows._run_workflow_steps([
                {"type": "set", "name": "one", "value": 1},
                {"type": "set", "name": "two", "value": 2},
            ], state, "test", False)
        self.assertEqual(403, raised.exception.status_code)

    def test_workflow_block_contracts_reject_display_only_ai_syntax(self):
        errors = definitions.workflow_definition_errors([
            {"type": "condition", "condition": "enabled == true", "then": [], "else": []},
            {"type": "set", "name": "bad-name", "value": "null"},
            {"type": "retry", "max_attempts": 2},
            {"type": "return"},
        ])
        combined = "; ".join(errors)
        self.assertIn("condition requires left or field", combined)
        self.assertIn("condition requires right or value", combined)
        self.assertIn("set name must be a variable identifier", combined)
        self.assertIn("retry requires one step object", combined)
        self.assertIn("return requires value", combined)

    def test_automation_rejects_missing_and_under_authorized_tools(self):
        base = {
            "id": "memory-review", "name": "Memory review", "description": "Test workflow references.",
            "inputs": [], "policy": {"usage_limits": {"max_steps": 10}},
            "authorization": "auto", "status": "draft", "schedule": None,
        }
        errors = definitions.automation_definition_errors({
            **base, "workflow": [{"type": "tool_call", "tool_id": "does-not-exist", "args": {}}],
        })
        self.assertIn("unavailable tool 'does-not-exist'", "; ".join(errors))

        control_plane.create_tool({
            "id": "sensitive-action", "name": "Sensitive action", "description": "Requires its owner.",
            "inputs": [], "outputs": [], "execution": {"type": "echo"},
            "authorization": "owner_confirmation", "status": "active",
        })
        errors = definitions.automation_definition_errors({
            **base, "workflow": [{"type": "tool_call", "tool_id": "sensitive-action", "args": {}}],
        })
        self.assertIn("auto automation cannot call 'sensitive-action'", "; ".join(errors))
        self.assertEqual([], definitions.automation_definition_errors({
            **base, "authorization": "owner_confirmation",
            "workflow": [{"type": "tool_call", "tool_id": "sensitive-action", "args": {}}],
        }))



    def test_tool_results_expose_declared_output_names(self):
        tool = {
            "id": "count", "name": "Count", "description": "Returns one count.",
            "inputs": [], "outputs": [{"name": "total", "type": "integer"}],
        }
        result = dispatch._shape_tool_result(tool, {"ok": True, "result": 7})
        self.assertEqual(7, result["total"])
        self.assertEqual(7, result["result"])
        with self.assertRaises(HTTPException) as raised:
            dispatch._shape_tool_result(
                {"outputs": [{"name": "first", "type": "integer"},
                             {"name": "second", "type": "integer"}]},
                {"ok": True, "result": {"first": 1}},
            )
        self.assertEqual(502, raised.exception.status_code)
