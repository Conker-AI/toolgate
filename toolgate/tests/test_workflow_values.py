"""Runtime value contracts used by the visual workflow editor."""
import unittest

from fastapi import HTTPException

from toolgate.api import server


class WorkflowValueTests(unittest.TestCase):
    def state(self, variables=None):
        return {"automation_id": "value-test", "args": {}, "vars": variables or {},
                "last": None, "results": [], "count": 0, "max_steps": 50,
                "started_at": server.time.monotonic(), "runtime_ceiling": 5}

    def run_steps(self, steps, state):
        self.assertEqual([], server.workflow_definition_errors(steps))
        return server._run_workflow_steps(steps, state, "test", False)

    def test_membership_selects_the_matching_branch(self):
        for selected, expected in (("ready", "yes"), ("missing", "no")):
            with self.subTest(selected=selected):
                result = self.run_steps([{
                    "type": "condition", "left": selected, "operator": "in",
                    "right": ["ready", "waiting"],
                    "then": [{"type": "return", "value": "yes"}],
                    "else": [{"type": "return", "value": "no"}],
                }], self.state())
                self.assertEqual(expected, result["result"])

    def test_loop_restores_absent_null_and_existing_variables(self):
        for original in ({}, {"item": None}, {"item": "outer"}):
            for body in ([], [{"type": "return", "value": "$vars.item"}]):
                with self.subTest(original=original, body=body):
                    state = self.state(dict(original))
                    self.run_steps([{"type": "loop", "items": ["inner"],
                                     "max_iterations": 2, "steps": body}], state)
                    self.assertEqual(original, state["vars"])

    def test_loop_restores_variables_when_body_fails(self):
        state = self.state({"item": "outer"})
        with self.assertRaises(HTTPException):
            self.run_steps([{"type": "loop", "items": [1], "max_iterations": 2,
                             "steps": [{"type": "calculation", "operation": "divide",
                                        "values": [1, 0]}]}], state)
        self.assertEqual({"item": "outer"}, state["vars"])

    def test_calculation_rejects_nonfinite_input_and_output(self):
        for values in ([float("nan"), 1], [float("inf"), 1], [1e308, 1e308]):
            with self.subTest(values=values):
                state = self.state()
                with self.assertRaises(HTTPException) as error:
                    self.run_steps([{"type": "calculation", "operation": "multiply",
                                     "values": values, "save_as": "answer"}], state)
                self.assertEqual(422, error.exception.status_code)
                self.assertNotIn("answer", state["vars"])
                self.assertEqual([], state["results"])

    def test_nested_loop_restores_outer_item_for_following_steps(self):
        state = self.state()
        result = self.run_steps([
            {"type": "loop", "items": ["outer"], "max_iterations": 2, "steps": [
                {"type": "loop", "items": ["inner"], "max_iterations": 2, "steps": []},
                {"type": "set", "name": "observed", "value": "$vars.item"},
            ]},
            {"type": "return", "value": "$vars.observed"},
        ], state)
        self.assertEqual("outer", result["result"])
        self.assertNotIn("item", state["vars"])


if __name__ == "__main__":
    unittest.main()
