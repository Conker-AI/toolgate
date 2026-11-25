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


CALENDAR_FETCH = "toolgate/tests/test_calendar_fetch.py::"
CALENDAR = "toolgate/tests/test_calendar_boundary.py::"
CALENDAR_PARSE = "toolgate/tests/test_calendar_parse.py::"
LIMITS = "toolgate/tests/test_calendar_limits.py::"
WINDOW = "toolgate/tests/test_calendar_window.py::"
MUTANTS.extend(
    [
        (
            "calendar address not checked for public https",
            "toolgate/executors/calendar_ics.py",
            "    if not public_url(str(parsed), deadline):",
            "    if False:",
            CALENDAR_FETCH
            + "test_a_host_that_resolves_inside_the_network_is_refused_before_any_request[private]",
        ),
        (
            "calendar redirect followed unchecked",
            "toolgate/executors/calendar_ics.py",
            'target = _https(urljoin(target, response.headers.get("location", "")), deadline)',
            'target = urljoin(target, response.headers.get("location", ""))',
            CALENDAR_FETCH + "test_a_redirect_is_checked_like_the_address_itself[private-host]",
        ),
        (
            "calendar body read past its cap",
            "toolgate/executors/calendar_ics.py",
            "        if len(body) > LIMIT_BYTES:",
            "        if False:",
            CALENDAR_FETCH + "test_a_body_over_2_mb_without_a_length_stops_reading_at_the_cap",
        ),
        (
            "calendar fetched through a client that logs the address",
            "toolgate/executors/calendar_ics.py",
            "response = sender.handle_request(request)",
            "response = httpx.Client(transport=sender).send(request, stream=True)",
            CALENDAR + "test_events_are_read_without_an_approval_card",
        ),
        (
            "calendar address open to other tools",
            "toolgate/core/vault.py",
            'raise KeyError(f"{placeholder} is read only by its built-in tool")',
            "pass",
            CALENDAR + "test_no_other_tool_can_name_the_address",
        ),
        (
            "calendar parser output taken unchecked",
            "toolgate/executors/calendar_ics.py",
            "return [_checked(event) for event in events]",
            "return events",
            CALENDAR_PARSE + "test_the_parent_refuses_an_answer_of_the_wrong_shape[extra-field]",
        ),
        (
            "calendar series share no overall budget",
            "toolgate/executors/calendar_parse.py",
            "found = _expand(series, start, end, min(seconds, left)) if left > 0 else None",
            "found = _expand(series, start, end, seconds)",
            CALENDAR_PARSE + "test_many_hostile_series_together_cost_only_themselves",
        ),
        (
            "calendar partial flag taken unchecked",
            "toolgate/executors/calendar_ics.py",
            " or type(partial) is not bool:",
            ":",
            CALENDAR_PARSE
            + "test_the_parent_refuses_an_answer_of_the_wrong_shape[partial-not-bool]",
        ),
        (
            "calendar titles not fenced",
            "toolgate/executors/calendar_ics.py",
            '"title": fenced("CALENDAR", "field=title", _clean(event["title"])),',
            '"title": _clean(event["title"]),',
            CALENDAR_PARSE + "test_titles_and_places_are_fenced_as_outside_text_they_cannot_close",
        ),
        (
            "calendar zone folder escapes the zone check",
            "toolgate/executors/calendar_ics.py",
            "    except Exception:  # OSError for a folder; KeyError or ValueError for the rest",
            "    except (KeyError, ValueError):",
            CALENDAR + "test_an_unknown_time_zone_is_refused_before_anything_is_fetched[America]",
        ),
        (
            "public https reads past the request deadline",
            "toolgate/core/public_https.py",
            "return self.stream.read(max_bytes, self._left(timeout))",
            "return self.stream.read(max_bytes, timeout)",
            CALENDAR_FETCH + "test_a_server_that_sends_its_headers_slowly_stops_at_the_deadline",
        ),
        (
            "calendar child counts from the call, not its start",
            "toolgate/executors/calendar_parse.py",
            "    deadline = (clock.monotonic() if started is None else started) + total",
            "    deadline = clock.monotonic() + total",
            LIMITS + "test_the_childs_time_counts_from_its_own_start",
        ),
        (
            "calendar child clock started after the libraries load",
            "toolgate/executors/calendar_parse.py",
            "sys.stdin.buffer.read(LIMIT_BYTES + 1), days, zone, today, started=STARTED",
            "sys.stdin.buffer.read(LIMIT_BYTES + 1), days, zone, today",
            LIMITS + "test_the_child_starts_its_clock_before_loading_the_libraries",
        ),
        (
            "calendar busy child read as unreadable",
            "toolgate/executors/calendar_ics.py",
            "    if done.returncode == BUSY:",
            "    if False:",
            LIMITS + "test_the_parent_reads_the_childs_busy_as_too_busy",
        ),
        (
            "calendar events read past the cap",
            "toolgate/executors/calendar_parse.py",
            "            if len(taken) < limit and len(block) <= room:",
            "            if True:",
            LIMITS + "test_only_the_first_events_are_read_and_the_rest_make_the_answer_partial",
        ),
        (
            "calendar zone folder in the file blanks it",
            "toolgate/executors/calendar_parse.py",
            "    tzp.use(_Zones())",
            "    pass",
            LIMITS + "test_a_zone_folder_named_in_the_file_is_an_unknown_zone[America]",
        ),
        (
            "calendar unusable X-WR-TIMEZONE kept",
            "toolgate/executors/calendar_parse.py",
            '        del calendar["X-WR-TIMEZONE"]  # floating times are then read in ZONE',
            "        pass",
            LIMITS + "test_an_x_wr_timezone_the_database_cannot_load_is_ignored",
        ),
        (
            "calendar one broken event blanks the file",
            "toolgate/executors/calendar_parse.py",
            "            pass  # one event or zone the engine cannot take: find what reads",
            '            raise Unreadable("unparsable") from None',
            LIMITS + "test_an_event_the_engine_cannot_take_costs_only_itself",
        ),
        (
            "calendar broken zone blanks the file",
            "toolgate/executors/calendar_parse.py",
            "        frames, groups = (zones, []), _groups(events, _block_uid)",
            "        frames, groups = (zones,), _groups(events, _block_uid)",
            LIMITS + "test_a_zone_the_engine_cannot_take_costs_only_its_own_times",
        ),
        (
            "calendar series the engine skips leave no partial",
            "toolgate/executors/calendar_parse.py",
            "    return every, partial or _missing(calendar, every)",
            "    return every, partial",
            LIMITS
            + "test_an_event_the_engine_skips_as_broken_makes_the_answer_partial[bogus-frequency]",
        ),
        (
            "calendar address looked up outside the deadline",
            "toolgate/executors/calendar_ics.py",
            "    if not public_url(str(parsed), deadline):",
            "    if not public_url(str(parsed)):",
            CALENDAR_FETCH + "test_a_slow_name_lookup_cannot_stretch_the_fetch",
        ),
        (
            "public https socket lookup outside the deadline",
            "toolgate/core/public_https.py",
            "        addresses = resolve_public(host, port, self.deadline)",
            "        addresses = resolve_public(host, port)",
            CALENDAR_FETCH + "test_the_sockets_own_lookup_stops_at_the_deadline_too",
        ),
        (
            "public https lookup waits out the resolver",
            "toolgate/core/public_https.py",
            "    worker.join(left)",
            "    worker.join()",
            CALENDAR_FETCH + "test_a_slow_name_lookup_cannot_stretch_the_fetch",
        ),
        (
            "public https lookup starts after the deadline",
            "toolgate/core/public_https.py",
            "    if left <= 0:\n        raise LookupTimeout(",
            "    if False:\n        raise LookupTimeout(",
            CALENDAR_FETCH
            + "test_no_lookup_starts_once_the_deadline_has_passed_and_other_callers_are_unchanged",
        ),
        (
            "calendar failing halves never split",
            "toolgate/executors/calendar_parse.py",
            "    if len(groups) <= 1:",
            "    if True:",
            LIMITS + "test_an_event_the_engine_cannot_take_costs_only_itself",
        ),
        (
            "calendar budget thread started for each budget",
            "toolgate/executors/calendar_parse.py",
            "            if self.thread is None or not self.thread.is_alive():",
            "            if True:",
            WINDOW + "test_a_thread_that_cannot_start_costs_no_events",
        ),
        (
            "calendar watchdog that ended left dead",
            "toolgate/executors/calendar_parse.py",
            "            if self.thread is None or not self.thread.is_alive():",
            "            if self.thread is None:",
            WINDOW + "test_a_watchdog_that_ended_is_started_again",
        ),
        (
            "calendar broken event searched one by one",
            "toolgate/executors/calendar_parse.py",
            "    middle = len(groups) // 2",
            "    middle = 1",
            WINDOW + "test_a_broken_event_among_2000_is_found_by_halves_not_by_reading_each_event",
        ),
        (
            "calendar series split from its moved occurrence",
            "toolgate/executors/calendar_parse.py",
            "        groups.setdefault(uid(item) or index, []).append(item)",
            "        groups.setdefault(index, []).append(item)",
            WINDOW
            + "test_a_series_and_its_moved_occurrence_stay_together_when_a_broken_event_is_left_out",
        ),
        (
            "calendar events outside the window count toward the cap",
            "toolgate/executors/calendar_parse.py",
            "                elif span[1] >= first and span[0] <= last:",
            "                elif True:",
            WINDOW + "test_events_that_cannot_touch_the_window_are_not_read_and_do_not_count",
        ),
        (
            "calendar repeating events read before single ones",
            "toolgate/executors/calendar_parse.py",
            "        (kept[1], singles + repeating, MAX_READ),",
            "        (kept[1], repeating + singles, MAX_READ),",
            WINDOW + "test_single_events_are_read_before_repeating_ones",
        ),
        (
            "calendar series expanded in file order",
            "toolgate/executors/calendar_parse.py",
            "    every = sorted(query.series, key=_repeats)",
            "    every = list(query.series)",
            WINDOW + "test_a_single_event_sharing_a_uid_does_not_move_its_series_ahead[whole]",
        ),
        (
            "calendar halves expanded in file order",
            "toolgate/executors/calendar_parse.py",
            "        return sorted(_readable(groups, read, frame is frames[0]), key=_repeats), True",
            "        return _readable(groups, read, frame is frames[0]), True",
            WINDOW + "test_a_single_event_sharing_a_uid_does_not_move_its_series_ahead[halves]",
        ),
        (
            "calendar window without its margin",
            "toolgate/executors/calendar_parse.py",
            "MARGIN = timedelta(days=2)",
            "MARGIN = timedelta(0)",
            WINDOW + "test_an_event_that_might_touch_the_window_is_always_read",
        ),
        (
            "calendar event end ignored",
            "toolgate/executors/calendar_parse.py",
            '    end = _day(found[b"DTEND"]) if b"DTEND" in found else start',
            "    end = start",
            WINDOW + "test_an_event_that_might_touch_the_window_is_always_read",
        ),
        (
            "calendar duration hours dropped",
            "toolgate/executors/calendar_parse.py",
            "            end = start + timedelta(days=length.days + 1)",
            "            end = start + timedelta(days=length.days)",
            WINDOW
            + "test_an_event_given_as_a_duration_is_read_while_its_hours_may_reach_the_window",
        ),
        (
            "calendar event duration ignored",
            "toolgate/executors/calendar_parse.py",
            "            end = start + timedelta(days=length.days + 1)",
            "            end = start",
            WINDOW + "test_an_event_that_might_touch_the_window_is_always_read",
        ),
        (
            "calendar other versions outside the window not read",
            "toolgate/executors/calendar_parse.py",
            "    singles += [block for block in outside if _block_uid(block) in uids]",
            "    singles += []",
            WINDOW + "test_a_newer_version_of_an_event_outside_the_window_still_counts",
        ),
    ]
)
