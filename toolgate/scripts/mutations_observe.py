"""Mutation definitions for the drill, part 3: the Observe class of imported MCP tools.

Same entry shape as mutations_core.py: (label, file, anchor, replacement, test). The runner in
mutation_check.py applies them after parts 1 and 2.
"""

from __future__ import annotations

OBSERVE = "toolgate/tests/test_mcp_observe.py::"
NAMES = "toolgate/tests/test_mcp_observe_names.py::"
GUARD = "toolgate/core/mcp_observe.py"
IMPORTS = "toolgate/core/mcp_imports.py"
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
        (
            "        or names_act(\n"
            '            (tool.get("id"), tool.get("name"), execution["tool_name"]),\n'
            '            stored.get("read_only_hint") is True,\n'
            "        )\n"
        ),
        "",
        OBSERVE + "test_a_stored_observe_on_a_name_that_acts_still_asks",
    ),
    (
        "a stored Observe gets the long shape without the hint he confirmed",
        GUARD,
        '            stored.get("read_only_hint") is True,\n',
        "            True,\n",
        OBSERVE + "test_a_longer_name_is_observe_only_when_its_server_says_read_only",
    ),
    (
        "Observe survives another schema",
        GUARD,
        "        or {key: stored.get(key) for key in BOUND} != execution\n",
        "",
        OBSERVE + "test_a_stored_observe_for_another_schema_does_not_apply",
    ),
    (
        "Observe without the advert he confirmed applies",
        GUARD,
        '        or not ADVERT.fullmatch(str(stored.get("advert_hash")))\n',
        "",
        OBSERVE + "test_a_stored_observe_without_the_advert_he_confirmed_does_not_apply",
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
        "the definition being run may carry a name that acts",
        GUARD,
        '        or says_act_outward(tool.get("name"), current["read_class"].get("read_only_hint") is True)\n',
        "",
        OBSERVE + "test_a_pinned_version_whose_name_acts_still_asks",
    ),
    (
        "the definition being run gets the long shape without the hint",
        GUARD,
        'current["read_class"].get("read_only_hint") is True)\n',
        "True)\n",
        OBSERVE + "test_a_pinned_long_name_needs_the_hint_its_tool_records",
    ),
    # How a name is read: each rule has a name that only it catches.
    (
        "a name not led by a read verb reads",
        GUARD,
        "    if not parts or parts[0] not in verbs:",
        "    if not parts:",
        NAMES + "test_names_that_act[kill-no-hint]",
    ),
    (
        "a name with no letters reads",
        GUARD,
        "    if not parts or parts[0] not in verbs:",
        "    if parts and parts[0] not in verbs:",
        NAMES + "test_names_that_act[punctuation-no-hint]",
    ),
    (
        "a longer name reads without the server's hint",
        GUARD,
        "    if len(parts) > 2 and not read_only_hint:\n        return True\n",
        "",
        NAMES + "test_longer_reads_need_the_servers_read_only_hint[get_weather_today]",
    ),
    (
        "query leads a read without the server's hint",
        GUARD,
        "    verbs = READ_VERBS | HINTED_READ_VERBS if read_only_hint else READ_VERBS",
        "    verbs = READ_VERBS | HINTED_READ_VERBS",
        NAMES + "test_longer_reads_need_the_servers_read_only_hint[query]",
    ),
    (
        "a connector joins a read to anything",
        GUARD,
        "        if part in CONNECTORS:\n            return True\n",
        "",
        NAMES + "test_names_that_act[get_and-no-hint]",
    ),
    (
        "a namespace that acts is ignored",
        GUARD,
        "    if any(_acts(part) or _leads(part) for segment in namespace for part in _parts(segment)):",
        "    if False:",
        NAMES + "test_names_that_act[send.list_messages-no-hint]",
    ),
    (
        "a namespace that leads is ignored",
        GUARD,
        "    if any(_acts(part) or _leads(part) for segment in namespace for part in _parts(segment)):",
        "    if any(_acts(part) for segment in namespace for part in _parts(segment)):",
        NAMES + "test_names_that_act[email.list_files-no-hint]",
    ),
    (
        "a word that acts after the read verb is missed",
        GUARD,
        "        if _acts(part):\n            return True\n",
        "",
        NAMES + "test_names_that_act[get_setvalue-no-hint]",
    ),
    (
        "a LEADS word before the last part reads",
        GUARD,
        "        if _leads(part) and not (index == len(rest) - 1 and _is_object(part)):",
        "        if _leads(part) and not _is_object(part):",
        NAMES + "test_names_that_act[get_message_user-read-only-hint]",
    ),
    (
        "a LEADS word with more glued to it reads",
        GUARD,
        "        if _leads(part) and not (index == len(rest) - 1 and _is_object(part)):",
        "        if _leads(part) and not index == len(rest) - 1:",
        NAMES + "test_names_that_act[get_messageuser-no-hint]",
    ),
    (
        "a long word glued inside a part is missed",
        GUARD,
        "    if any(stem in part for stem in _STEMS):",
        "    if any(part.startswith(stem) for stem in _STEMS):",
        NAMES + "test_names_that_act[get_quicksend-no-hint]",
    ),
    (
        "a long word with its e dropped is missed",
        GUARD,
        '        *((word[:-1] + "ing",) if word.endswith("e") else ()),\n',
        "",
        NAMES + "test_names_that_act[get_profileupdating-no-hint]",
    ),
    (
        "a long word with its y changed is missed",
        GUARD,
        '        *((word[:-1] + "ied",) if word.endswith("y") else ()),\n',
        "",
        NAMES + "test_names_that_act[get_threadreplied-no-hint]",
    ),
    (
        "a short word at the start of a part is missed",
        GUARD,
        "    return part.startswith(word) or any(part.endswith(form) for form in _forms(word))",
        "    return any(part.endswith(form) for form in _forms(word))",
        NAMES + "test_names_that_act[get_setvalue-no-hint]",
    ),
    (
        "a short word at the end of a part is missed",
        GUARD,
        "    return part.startswith(word) or any(part.endswith(form) for form in _forms(word))",
        "    return part.startswith(word)",
        NAMES + "test_names_that_act[get_rerun-no-hint]",
    ),
    (
        "a doubled consonant hides a short word",
        GUARD,
        '    forms = [word + ending for ending in (*_ENDINGS, word[-1] + "ed", word[-1] + "ing")]',
        "    forms = [word + ending for ending in _ENDINGS]",
        NAMES + "test_names_that_act[get_unpinned-no-hint]",
    ),
    (
        "a verb that hides in nouns is missed at a part's edge",
        GUARD,
        "_AT_EDGES = frozenset(word for word in ACTS if len(word) < 4) | ACTS_AT_EDGES",
        "_AT_EDGES = frozenset(word for word in ACTS if len(word) < 4)",
        NAMES + "test_names_that_act[get_ring-no-hint]",
    ),
    (
        "one name of a tool decides for all",
        GUARD,
        "    return any(says_act_outward(name, read_only_hint) for name in names)",
        "    return says_act_outward(names[0], read_only_hint)",
        NAMES + "test_a_tools_names_act_when_any_one_of_them_does",
    ),
    (
        "a look-alike letter outside ASCII reads",
        GUARD,
        "    if not text.isascii() or not text.isprintable():",
        "    if not text.isprintable():",
        NAMES + "test_names_that_act[cyrillic-s-no-hint]",
    ),
    (
        "a control character splits a word",
        GUARD,
        "    if not text.isascii() or not text.isprintable():",
        "    if not text.isascii():",
        NAMES + "test_names_that_act[control-character-read-only-hint]",
    ),
    (
        "annotations without readOnlyHint pass",
        GUARD,
        '        annotations.get("readOnlyHint") is not True\n',
        '        annotations.get("readOnlyHint", True) is not True\n',
        NAMES + "test_server_hints_that_say_a_tool_changes_things",
    ),
    (
        "a destructive hint passes beside readOnlyHint",
        GUARD,
        '        or annotations.get("destructiveHint", False) is not False\n',
        "",
        NAMES + "test_server_hints_that_say_a_tool_changes_things",
    ),
    (
        "dispatch skips the class recheck",
        "toolgate/api/invocation.py",
        '        if observed and not mcp_observe.runs_unasked(conn, tool, "owner_confirmation", decision):',
        "        if False:",
        OBSERVE + "test_a_class_change_during_a_call_is_caught_before_dispatch",
    ),
    (
        "an Observe call is sent without the advert he confirmed",
        "toolgate/api/invocation.py",
        '            result = _dispatch_tool(tool, args, advert=confirmed["advert"])',
        "            result = _dispatch_tool(tool, args)",
        OBSERVE + "test_a_changed_description_or_annotation_at_a_call_reverts_to_act_outward",
    ),
    (
        "the call ignores a changed advert",
        "toolgate/executors/mcp_http.py",
        '    if advert is not None and matches[0]["advertHash"] != advert:',
        "    if False:",
        OBSERVE + "test_a_changed_description_or_annotation_at_a_call_reverts_to_act_outward",
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
        "his discovery keeps a changed description",
        GUARD,
        '        elif advert_seen != stored.get("advert_hash"):',
        "        elif False:",
        OBSERVE + "test_his_discovery_of_a_changed_description_reverts_it",
    ),
    (
        "the class route asks the server about a name that acts",
        IMPORTS,
        "    if any(mcp_observe.says_act_outward(name, True) for name in names):\n        raise refused\n",
        "",
        OBSERVE + "test_a_name_that_acts_can_never_be_marked_observe[changes2]",
    ),
    (
        "the class route marks a long name Observe without the server's hint",
        IMPORTS,
        "    if mcp_observe.names_act(names, read_only_hint):\n        raise refused\n",
        "",
        OBSERVE + "test_a_longer_name_is_observe_only_when_its_server_says_read_only",
    ),
    (
        "the class route takes the hint as given when the server gives none",
        IMPORTS,
        '    read_only_hint = advertised.get("annotations") is not None',
        "    read_only_hint = True",
        OBSERVE + "test_a_longer_name_is_observe_only_when_its_server_says_read_only",
    ),
    (
        "the class route records the hint whether or not the server gave it",
        IMPORTS,
        '                "read_only_hint": read_only_hint,',
        '                "read_only_hint": True,',
        OBSERVE + "test_a_pinned_long_name_needs_the_hint_its_tool_records",
    ),
    (
        "the class route ignores a destructive hint",
        IMPORTS,
        '    if mcp_observe.hints_act(advertised.get("annotations")):',
        "    if False:",
        OBSERVE + "test_a_tool_its_server_says_changes_things_can_never_be_marked_observe",
    ),
    (
        "the class route binds a tool the server no longer advertises",
        IMPORTS,
        (
            '    mcp_observe.notice(execution["url"], execution["secret_ref"], discovered)\n'
            '    mcp_http.require_match(discovered["tools"], execution, '
            'discovered.get("unsupportedTools", []))\n'
        ),
        '    mcp_observe.notice(execution["url"], execution["secret_ref"], discovered)\n',
        OBSERVE + "test_observe_needs_the_server_to_still_advertise_the_tool_he_imported",
    ),
    (
        "the class route ignores the version he saw",
        IMPORTS,
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
