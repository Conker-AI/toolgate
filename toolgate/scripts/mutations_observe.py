"""Mutation definitions for the drill, part 3: the Observe class of imported MCP tools.

Same entry shape as mutations_core.py: (label, file, anchor, replacement, test). The runner in
mutation_check.py applies them after parts 1 and 2.
"""

from __future__ import annotations

OBSERVE = "toolgate/tests/test_mcp_observe.py::"
GUARD = "toolgate/core/mcp_observe.py"
MUTANTS: list[tuple[str, str, str, str, str]] = [
    (
        "an Act outward tool runs unasked",
        GUARD,
        "        or stated(current) != OBSERVE\n",
        "",
        OBSERVE + "test_a_new_import_is_act_outward_and_asks_for_the_exact_call_at_level_two",
    ),
    (
        "a stored Observe on a name that acts applies",
        GUARD,
        "            says_act_outward(name)\n            for name in",
        "            False\n            for name in",
        OBSERVE + "test_a_stored_observe_on_a_name_that_acts_still_asks",
    ),
    (
        "Observe survives another schema",
        GUARD,
        "        or {key: stored.get(key) for key in BOUND} != execution\n",
        "",
        OBSERVE + "test_a_stored_observe_for_another_schema_does_not_apply",
    ),
    (
        "Observe ignores his sensitive mark",
        GUARD,
        "    return not _marked_sensitive(conn, identity)",
        "    return True",
        OBSERVE + "test_an_ask_or_his_sensitive_mark_still_asks",
    ),
    (
        "Observe ignores an ask",
        GUARD,
        '    if decision is not None and decision.outcome == "ask":\n        return False\n',
        "",
        OBSERVE + "test_an_ask_or_his_sensitive_mark_still_asks",
    ),
    (
        "Observe reaches built-in executions",
        GUARD,
        '    if not isinstance(execution, dict) or execution.get("type") != "mcp_http":',
        "    if not isinstance(execution, dict):",
        OBSERVE + "test_observe_never_applies_outside_imported_mcp_tools",
    ),
    (
        "Observe reaches tools outside the MCP catalogue",
        GUARD,
        '    if not isinstance(tool, dict) or not MCP_ID.fullmatch(str(tool.get("id"))):',
        "    if not isinstance(tool, dict):",
        OBSERVE + "test_observe_never_applies_outside_imported_mcp_tools",
    ),
    (
        "a word with an ending can be Observe",
        GUARD,
        '_ENDINGS = ("", "s", "es", "d", "ed", "ing")',
        '_ENDINGS = ("",)',
        OBSERVE + "test_names_that_act[list_shared_drives]",
    ),
    (
        "a leading re or un hides the word",
        GUARD,
        '        if _says(word) or (word[:2] in ("re", "un") and _says(word[2:])):',
        "        if _says(word):",
        OBSERVE + "test_names_that_act[unsubscribe]",
    ),
    (
        "a glued name hides the word",
        GUARD,
        "    if len(found) == 1:",
        "    if False:",
        OBSERVE + "test_names_that_act[sendmessage]",
    ),
    (
        "dispatch skips the class recheck",
        "toolgate/api/invocation.py",
        '        if observed and not mcp_observe.runs_unasked(conn, tool, "owner_confirmation", decision):',
        "        if False:",
        OBSERVE + "test_a_class_change_during_a_call_is_caught_before_dispatch",
    ),
    (
        "a changed schema at a call keeps Observe",
        "toolgate/api/invocation.py",
        '        mcp_observe.revert(tool["id"], result["error_code"])',
        "        pass",
        OBSERVE + "test_a_changed_schema_at_a_call_reverts_to_act_outward_until_he_confirms_again",
    ),
    (
        "his discovery keeps a changed Observe",
        "toolgate/api/routes/mcp.py",
        "    mcp_observe.notice(payload.url, payload.secret_ref, discovered)\n",
        "",
        OBSERVE + "test_his_discovery_of_a_renamed_or_changed_tool_reverts_it",
    ),
    (
        "the class route marks a name that acts Observe",
        "toolgate/core/mcp_imports.py",
        "            if any(mcp_observe.says_act_outward(name) for name in names):",
        "            if False:",
        OBSERVE + "test_a_name_that_acts_can_never_be_marked_observe[changes0]",
    ),
    (
        "the class route ignores the version he saw",
        "toolgate/core/mcp_imports.py",
        '        if tool.get("version") != payload.expected_version:',
        "        if False:",
        OBSERVE + "test_only_the_owner_channel_marks_observe_for_the_version_it_saw",
    ),
    (
        "the class route opens to any caller",
        "toolgate/api/routes/mcp.py",
        '@router.post("/v2/owner/mcp/tools/{tool_id}/class", dependencies=[Depends(require_owner)])',
        '@router.post("/v2/owner/mcp/tools/{tool_id}/class")',
        OBSERVE + "test_only_the_owner_channel_marks_observe_for_the_version_it_saw",
    ),
]
