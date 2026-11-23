"""Mutation definitions for the drill, part 2: release, floor, withdraw, window, cards, levels, forget.

Same entry shape as mutations_core.py: (label, file, anchor, replacement, test). The runner in
mutation_check.py applies them after part 1.
"""

from __future__ import annotations

MUTANTS: list[tuple[str, str, str, str, str]] = []

MUTANTS.extend(
    [
        (
            "worker-can-release-spending",
            "toolgate/api/routes/spending.py",
            "    action_id: str, payload: ReservationRelease, _tier: str = Depends(require_admin)\n",
            "    action_id: str, payload: ReservationRelease, _tier: dict = Depends(require_agent)\n",
            "toolgate/tests/test_reservation_release.py::test_owner_release_frees_local_hold_without_allowing_redispatch",
        ),
        (
            "release-ignores-live-dispatch",
            "toolgate/core/spending.py",
            'or action["status"] != "outcome_unknown"',
            "",
            "toolgate/tests/test_reservation_release.py::test_release_requires_owner_evidence_and_inactive_dispatch",
        ),
        (
            "released-hold-still-consumes-budget",
            "toolgate/core/spending.py",
            "THEN 0 ELSE r.reserved END",
            "THEN r.reserved ELSE r.reserved END",
            "toolgate/tests/test_reservation_release.py::test_owner_release_frees_local_hold_without_allowing_redispatch",
        ),
        (
            "late-reply-does-not-dispute-release",
            "toolgate/core/spending.py",
            'if conn.execute("SELECT 1 FROM v2_spend_releases WHERE action_id=?", (action_id,)).fetchone():',
            "if False:",
            "toolgate/tests/test_reservation_release.py::test_late_reply_disputes_release_and_restores_budget_hold",
        ),
    ]
)


FLOOR = "toolgate/tests/test_mcp_floor.py::"
WITHDRAW = "toolgate/tests/test_request_withdraw.py::"
MUTANTS.extend(
    [
        (
            "MCP tools lifted off the floor",
            "toolgate/core/access_policy.py",
            '"process_control", "mcp_http"})',
            '"process_control"})',
            FLOOR + "test_an_mcp_invocation_with_a_delegate_run_still_parks_for_the_owner",
        ),
        (
            "delegate run skips the floor",
            "toolgate/core/access_policy.py",
            "if on_floor(tool) or not is_delegate(agent):",
            "if not is_delegate(agent):",
            FLOOR + "test_a_delegate_run_never_lifts_an_mcp_tool_off_the_floor",
        ),
        (
            "another key withdraws a request",
            "toolgate/core/approvals.py",
            'or record.get("payload", {}).get("created_by_agent_key") != actor_id',
            "or False",
            WITHDRAW + "test_another_key_another_agent_or_an_unknown_id_cannot_withdraw",
        ),
        (
            "withdraw overrides the owner's answer",
            "toolgate/core/approvals.py",
            """        if record.get("status") != "pending":
            raise ValueError(f"request is already {record.get('status')}")
        record["status"] = WITHDRAWN""",
            '        record["status"] = WITHDRAWN',
            WITHDRAW + "test_a_request_the_owner_answered_cannot_be_withdrawn[approved]",
        ),
        (
            "withdrawn request still in the owner's list",
            "toolgate/core/owner_channel.py",
            "\"AND json_extract(body,'$.status') IS NOT ?\"",
            '"AND ? IS NOT NULL"',
            WITHDRAW
            + "test_the_asking_key_withdraws_its_waiting_request_and_the_owner_no_longer_sees_it",
        ),
    ]
)

WINDOW = "toolgate/tests/test_run_window.py::"
LOCKDOWN = "toolgate/tests/test_owner_lockdown.py::"
MUTANTS.extend(
    [
        (
            "run window setting past 15 minutes",
            "toolgate/core/tool_settings.py",
            "run_window_minutes: Annotated[int, Field(ge=1, le=RUN_WINDOW_MINUTES)] | None = None",
            "run_window_minutes: Annotated[int, Field(ge=1)] | None = None",
            WINDOW + "test_a_window_longer_than_fifteen_minutes_is_refused[16]",
        ),
        (
            "recorded run window past 15 minutes",
            "toolgate/core/approvals.py",
            "if type(minutes) is not int or not 1 <= minutes <= MAX_RUN_WINDOW_MINUTES:",
            "if type(minutes) is not int or not 1 <= minutes:",
            WINDOW + "test_a_recorded_window_past_its_ceiling_or_malformed_never_runs[60]",
        ),
        (
            "owner's shorter run window ignored",
            "toolgate/core/approvals.py",
            'decision["run_window_minutes"] = tool_settings.run_window(conn)',
            'decision["run_window_minutes"] = MAX_RUN_WINDOW_MINUTES',
            WINDOW + "test_a_shorter_window_runs_out_sooner",
        ),
        (
            "run window read when the action starts",
            "toolgate/core/approvals.py",
            'minutes = decision.get("run_window_minutes", MAX_RUN_WINDOW_MINUTES)',
            (
                'minutes = __import__("toolgate.core.tool_settings", fromlist=["current"])'
                ".current().run_window_minutes or MAX_RUN_WINDOW_MINUTES"
            ),
            WINDOW + "test_an_approval_keeps_the_window_it_was_decided_under",
        ),
        (
            "lockdown switch without the owner key",
            "toolgate/api/routes/settings.py",
            '@router.post("/v2/owner/lockdown", dependencies=[Depends(require_owner)])',
            '@router.post("/v2/owner/lockdown")',
            LOCKDOWN + "test_only_the_owner_key_reads_or_turns_it",
        ),
    ]
)


CARDS = "toolgate/tests/test_ask_cards.py::"
OWNER_RUNS = "toolgate/tests/test_owner_runs.py::"
MUTANTS.extend(
    [
        (
            "agent tool list drops the owner's card",
            "toolgate/api/routes/agent.py",
            '"card": cards.get(tool["id"], ask_cards.DEFAULT),',
            '"card": ask_cards.DEFAULT,',
            CARDS + "test_the_agent_tool_list_carries_the_card_he_picked",
        ),
        (
            "published workflow drops its tools' cards",
            "toolgate/core/editor_catalogue.py",
            '"card": ask_cards.for_workflow(tools, cards),',
            '"card": ask_cards.DEFAULT,',
            CARDS + "test_a_published_workflow_shows_the_strongest_card_of_the_tools_it_runs",
        ),
        (
            "owner run without the owner key",
            "toolgate/api/routes/owner_runs.py",
            '@router.post("/v2/owner/tools/{tool_id}/runs", dependencies=[Depends(require_owner)])',
            '@router.post("/v2/owner/tools/{tool_id}/runs")',
            OWNER_RUNS + "test_only_the_owner_key_with_the_chat_key_runs",
        ),
        (
            "owner run lifts the floor",
            "toolgate/core/owner_runs.py",
            "return FLOOR if access_policy.on_floor(tool) else None",
            "return None",
            OWNER_RUNS + "test_the_floor_still_asks_when_he_presses_run",
        ),
        (
            "owner run read without the owner key",
            "toolgate/api/routes/owner_runs.py",
            '@router.get("/v2/owner/tools/{tool_id}/runs", dependencies=[Depends(require_owner)])',
            '@router.get("/v2/owner/tools/{tool_id}/runs")',
            OWNER_RUNS + "test_only_the_owner_key_with_the_chat_key_runs",
        ),
        (
            "owner run read unbounded",
            "toolgate/api/routes/owner_runs.py",
            "Query(default=20, ge=1, le=owner_runs.MAX_RUNS)",
            "Query(default=20, ge=1)",
            OWNER_RUNS + "test_recent_runs_are_this_tools_own_newest_first_and_bounded",
        ),
    ]
)


LEVELS = "toolgate/tests/test_approval_levels.py::"
MUTANTS.extend(
    [
        (
            "request level ignores the card",
            "toolgate/core/approvals.py",
            "level = max(level, approval_levels.CARD_LEVELS.get(card, approval_levels.SERIOUS))",
            "level = level",
            LEVELS + "test_the_level_is_never_below_the_card_the_inbox_shows[pay-3]",
        ),
        (
            "tool level ignores its name",
            "toolgate/core/approval_levels.py",
            "level = max(CARD_LEVELS.get(card, SERIOUS), _named(tool))",
            "level = CARD_LEVELS.get(card, SERIOUS)",
            LEVELS + "test_a_tool_he_never_labelled_is_judged_by_its_name",
        ),
        (
            "host controls not serious",
            "toolgate/core/approval_levels.py",
            "    if kind in SERIOUS_EXECUTIONS:\n        return SERIOUS\n",
            "",
            LEVELS + "test_what_a_tool_runs_raises_its_level",
        ),
        (
            "workflow level skips its tools",
            "toolgate/core/approval_levels.py",
            "            level = max(level, for_tool(tool, cards))\n    return level",
            "            pass\n    return level",
            LEVELS + "test_a_workflow_that_runs_a_delete_named_tool_is_serious",
        ),
        (
            "odd stored level trusted",
            "toolgate/core/approval_levels.py",
            "return value if type(value) is int and value in LEVELS else SERIOUS",
            "return value if value else SERIOUS",
            LEVELS + "test_a_missing_or_odd_stored_level_is_serious",
        ),
        (
            "owner view drops the level",
            "toolgate/core/owner_channel.py",
            '"approval_level": approval_levels.stored(payload.get("level")),',
            '"approval_level": 1,',
            LEVELS + "test_his_card_for_the_tool_sets_the_level[delete-3]",
        ),
    ]
)


FORGET = "toolgate/tests/test_forget_records.py::"
MUTANTS.extend(
    [
        (
            "forget reaches another key's actions",
            "toolgate/core/forgetting.py",
            'if agent_id is not None and row["actor_id"] != agent_id:',
            "if False:",
            FORGET + "test_another_keys_records_and_unknown_ids_look_the_same_and_stay",
        ),
        (
            "forget blanks a waiting request",
            "toolgate/core/forgetting.py",
            'elif record.get("status") == "pending" and record.get("kind") == "verification":',
            "elif False:",
            FORGET + "test_a_waiting_request_and_a_running_action_are_refused_and_left_as_they_are",
        ),
        (
            "forget blanks a running action",
            "toolgate/core/forgetting.py",
            'if "dispatching" in statuses:',
            "if False:",
            FORGET + "test_a_waiting_request_and_a_running_action_are_refused_and_left_as_they_are",
        ),
    ]
)
