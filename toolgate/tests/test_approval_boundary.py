"""Approval-binding tests at the HTTP boundary.

The binding is the most load-bearing security property ToolGate has: an
approval names one exact action and is spent exactly once. These tests drive
the real routes over the real ASGI app against a real SQLite file, because a
mocked control plane would happily agree that a replay fails.
"""
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane, vault

ADMIN_KEY = "test-admin-key"
TOOL_ID = "approval.boundary-echo"

TOOL = {
    "id": TOOL_ID,
    "name": "Approval Boundary Echo",
    "description": "Local echo used to exercise the approval binding.",
    "category": "safe",
    "inputs": [{"name": "value", "type": "string", "required": True, "min_length": 1, "max_length": 120}],
    "outputs": [{"name": "proof", "type": "object"}],
    "execution": {"type": "local_echo"},
    "policy": {"usage_limits": {"max_per_minute": 60, "max_per_hour": 600}},
    "authorization": "owner_confirmation",
    "version": 1,
    "status": "active",
}


class ApprovalBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_patch = patch.object(control_plane, "DB_PATH", root / "toolgate-test.db")
        self.db_patch.start()
        self.env_patch = patch.object(vault, "ENV_PATH", root / "vault.env")
        self.env_patch.start()
        self.os_patch = patch.dict(os.environ, {
            "TOOLGATE_ADMIN_KEY": ADMIN_KEY,
            "TOOLGATE_VAULT_KEY_FILE": str(root / "vault.key"),
        })
        self.os_patch.start()
        # Not used as a context manager on purpose: the startup hook would
        # rebuild the built-in catalogue, which these tests do not need.
        self.client = TestClient(server.app)
        control_plane.create_tool(TOOL)
        _, self.agent_key = control_plane.issue_agent_key("boundary agent", ["tool:*"])
        _, self.other_key = control_plane.issue_agent_key("other agent", ["tool:*"])

    def tearDown(self):
        self.client.close()
        self.os_patch.stop()
        self.env_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def invoke(self, key: str, value: str, approval_request_id: str | None = None):
        body = {"args": {"value": value}}
        if approval_request_id:
            body["approval_request_id"] = approval_request_id
        return self.client.post(f"/v2/tools/{TOOL_ID}/invoke", json=body,
                                headers={"X-ToolGate-Execution-Key": key})

    def approve(self, request_id: str, status: str = "approved"):
        return self.client.post(f"/v2/requests/{request_id}/decision", json={"status": status},
                                headers={"X-ToolGate-Key": ADMIN_KEY})

    def mint(self, value: str = "hello", key: str | None = None) -> str:
        response = self.invoke(key or self.agent_key, value)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["code"], "CONFIRMATION_REQUIRED")
        return response.json()["request_id"]

    def assert_denied(self, response, fragment: str):
        self.assertEqual(response.status_code, 409)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "APPROVAL_INVALID")
        self.assertIn(fragment, detail["message"])

    def test_an_approval_is_spent_once_and_the_replay_is_refused(self):
        request_id = self.mint()
        self.approve(request_id)

        first = self.invoke(self.agent_key, "hello", request_id)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["code"], "OK")

        self.assert_denied(self.invoke(self.agent_key, "hello", request_id), "already been consumed")

    def test_an_unapproved_request_cannot_be_consumed(self):
        request_id = self.mint()

        self.assert_denied(self.invoke(self.agent_key, "hello", request_id), "is pending")

    def test_a_rejected_request_cannot_be_consumed(self):
        request_id = self.mint()
        self.approve(request_id, "rejected")

        self.assert_denied(self.invoke(self.agent_key, "hello", request_id), "is rejected")

    def test_changed_arguments_do_not_match_the_approved_action(self):
        request_id = self.mint("hello")
        self.approve(request_id)

        self.assert_denied(self.invoke(self.agent_key, "tampered", request_id), "does not match")
        # The failed attempt must not have spent the binding.
        self.assertEqual(self.invoke(self.agent_key, "hello", request_id).json()["code"], "OK")

    def test_a_bumped_tool_version_invalidates_an_unconsumed_approval(self):
        request_id = self.mint()
        self.approve(request_id)
        control_plane.update_tool(TOOL_ID, {**TOOL, "version": TOOL["version"]})

        self.assert_denied(self.invoke(self.agent_key, "hello", request_id), "does not match")

    def test_another_agent_key_cannot_spend_someone_elses_approval(self):
        request_id = self.mint()
        self.approve(request_id)

        self.assert_denied(self.invoke(self.other_key, "hello", request_id), "different originating agent")
        self.assertEqual(self.invoke(self.agent_key, "hello", request_id).json()["code"], "OK")

    def test_an_unknown_request_id_is_refused(self):
        self.assert_denied(
            self.invoke(self.agent_key, "hello", "00000000-0000-0000-0000-000000000000"),
            "was not found",
        )

    def test_an_expired_approval_is_refused(self):
        request_id = self.mint()
        self.approve(request_id)
        # Advance time without rewriting an immutable approval or sleeping out its lifetime.
        future = datetime.now(UTC) + timedelta(seconds=901)
        with patch("toolgate.core.control_plane.datetime") as clock:
            clock.now.return_value = future
            clock.fromisoformat.side_effect = datetime.fromisoformat
            self.assert_denied(self.invoke(self.agent_key, "hello", request_id), "has expired")

    def test_concurrent_consumption_succeeds_exactly_once(self):
        request_id = self.mint()
        self.approve(request_id)
        agent = control_plane.authenticate_agent(self.agent_key)

        def consume():
            return control_plane.consume_verification(
                request_id, "tool", TOOL_ID, {"value": "hello"}, TOOL["version"],
                agent["name"], agent["id"])

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = [future.result() for future in [pool.submit(consume) for _ in range(12)]]

        self.assertEqual([approved for approved, _ in outcomes].count(True), 1)
        self.assertTrue(all("already been consumed" in reason
                            for approved, reason in outcomes if not approved))

    def test_the_decision_route_will_not_re_approve_a_decided_request(self):
        request_id = self.mint()

        self.assertEqual(self.approve(request_id).status_code, 200)
        self.assertEqual(self.approve(request_id).status_code, 409)

    def test_consuming_an_approval_appends_history_without_rewriting_it(self):
        request_id = self.mint()
        self.approve(request_id)
        before = control_plane.events(limit=500)
        self.invoke(self.agent_key, "hello", request_id)
        after = control_plane.events(limit=500)

        self.assertGreater(len(after), len(before))
        # Earlier rows are immutable: the new events are appended, not edited.
        by_id = {event["id"]: event for event in after}
        for event in before:
            self.assertEqual(by_id[event["id"]], event)
        self.assertIn("verification_consumed", [event["event_type"] for event in after])


if __name__ == "__main__":
    unittest.main()
