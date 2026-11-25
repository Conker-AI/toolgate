"""Mutants for read-only mail (mail.recent): each breaks one rule of executors/mail_imap.py or
mail_parse.py, and the named test must fail on it (scripts/mutation_check.py)."""

from __future__ import annotations

IMAP = "toolgate/executors/mail_imap.py"
PARSE = "toolgate/executors/mail_parse.py"
FETCH = "toolgate/tests/test_mail_fetch.py::"
CHILD = "toolgate/tests/test_mail_parse.py::"
BOUNDARY = "toolgate/tests/test_mail_boundary.py::"

MUTANTS = [
    (
        "mail INBOX opened with SELECT",
        IMAP,
        "session.send('EXAMINE \"INBOX\"')",
        "session.send('SELECT \"INBOX\"')",
        FETCH + "test_the_session_is_read_only_and_changes_no_flag",
    ),
    (
        "mail write commands not refused before sending",
        IMAP,
        "        if not read_only(command):",
        "        if False:",
        FETCH + "test_no_command_that_writes_can_be_sent[move]",
    ),
    (
        "mail body section that marks a message read allowed",
        IMAP,
        '        "BODY[" not in items.replace("BODY.PEEK[", "")',
        "        True",
        FETCH + "test_no_command_that_writes_can_be_sent[body]",
    ),
    (
        "mail RFC822 fetch allowed",
        IMAP,
        '        and re.search(r"RFC822(?!\\.SIZE|\\.HEADER)", items) is None',
        "        and True",
        FETCH + "test_no_command_that_writes_can_be_sent[rfc822-text]",
    ),
    (
        "mail read-only confirmation not required",
        IMAP,
        '    if not status.upper().startswith(b"OK [READ-ONLY]"):',
        '    if not status.upper().startswith(b"OK"):',
        FETCH + "test_a_server_that_does_not_confirm_read_only_is_not_read",
    ),
    (
        "mail host shape not checked",
        IMAP,
        "    if HOST.fullmatch(host) is None:",
        "    if False:",
        FETCH + "test_a_host_that_is_no_public_dns_name_is_refused_before_any_lookup[localhost]",
    ),
    (
        "mail addresses not checked for public",
        IMAP,
        "        addresses = public_addresses(host, PORT, deadline)",
        "        addresses = [found[4][0] for found in socket.getaddrinfo(host, PORT)]",
        FETCH
        + "test_a_host_that_resolves_inside_the_network_is_refused_before_any_connection"
        + "[127.0.0.2]",
    ),
    (
        "mail lookup outside the deadline",
        IMAP,
        "        addresses = public_addresses(host, PORT, deadline)",
        "        addresses = public_addresses(host, PORT)",
        FETCH + "test_a_slow_name_lookup_stops_at_the_deadline",
    ),
    (
        "mail certificate not verified",
        IMAP,
        "    context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, True",
        "    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE",
        FETCH + "test_a_certificate_the_trusted_roots_did_not_sign_is_refused",
    ),
    (
        "mail certificate name not checked",
        IMAP,
        "    context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, True",
        "    context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, False",
        FETCH + "test_a_certificate_for_another_name_is_refused",
    ),
    (
        "mail TLS older than 1.2 allowed",
        IMAP,
        "    context.minimum_version = ssl.TLSVersion.TLSv1_2",
        "    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED",
        FETCH + "test_tls_older_than_1_2_is_refused",
    ),
    (
        "mail read past the total cap",
        IMAP,
        (
            "        if self.received >= TOTAL_BYTES:\n"
            "            raise _Cut\n"
            "        self.sock.settimeout(_left(self.deadline))\n"
            "        chunk = self.sock.recv(min(65536, TOTAL_BYTES - self.received))"
        ),
        "        self.sock.settimeout(_left(self.deadline))\n        chunk = self.sock.recv(65536)",
        FETCH + "test_the_total_cap_stops_reading_with_what_came_whole",
    ),
    (
        "mail message kept past its cap",
        IMAP,
        "                data = self.response(MESSAGE_BYTES)",
        "                data = self.response(TOTAL_BYTES)",
        FETCH + "test_a_message_over_its_cap_is_dropped_and_the_rest_are_read",
    ),
    (
        "mail dropped message not partial",
        IMAP,
        "                    partial = True  # one message over its cap: dropped, the rest still read",
        "                    pass",
        FETCH + "test_the_fetch_itself_says_partial_when_it_drops_a_message",
    ),
    (
        "mail oldest matches read instead of the newest",
        IMAP,
        "    chosen = sorted(uid for uid in found if 0 < uid < 2**32)[-MAX_MESSAGES:]",
        "    chosen = sorted(uid for uid in found if 0 < uid < 2**32)[:MAX_MESSAGES]",
        FETCH + "test_more_matches_than_the_cap_give_the_newest_and_say_partial",
    ),
    (
        "mail more matches than read not partial",
        IMAP,
        " or (more and not reached),",
        ",",
        FETCH + "test_more_matches_than_the_cap_give_the_newest_and_say_partial",
    ),
    (
        "mail fields not fenced",
        IMAP,
        '    return fenced("MAIL", f"field={label}", text) if text else None',
        "    return text or None",
        CHILD + "test_the_parent_fences_and_cleans_what_the_child_read",
    ),
    (
        "mail invisible characters kept",
        IMAP,
        '    text = " ".join(strip_invisible(value).split())[: CHARS[kind]]',
        '    text = " ".join(value.split())[: CHARS[kind]]',
        CHILD + "test_the_parent_fences_and_cleans_what_the_child_read",
    ),
    (
        "mail child answer taken unchecked",
        IMAP,
        "        checked = [_checked(message, set(uids)) for message in messages]",
        "        checked = messages",
        CHILD + "test_the_parent_refuses_an_answer_of_the_wrong_shape[extra-field]",
    ),
    (
        "mail message not asked for accepted",
        IMAP,
        "    if type(uid) is not int or uid not in uids or type(attached) is not bool:",
        "    if type(uid) is not int or type(attached) is not bool:",
        CHILD + "test_the_parent_refuses_an_answer_of_the_wrong_shape[uid-not-asked]",
    ),
    (
        "mail duplicate messages accepted",
        IMAP,
        '        if len({message["uid"] for message in checked}) != len(checked):',
        "        if False:",
        CHILD + "test_the_parent_refuses_an_answer_of_the_wrong_shape[duplicate]",
    ),
    (
        "mail busy child read as unreadable",
        IMAP,
        "    if done.returncode == BUSY:",
        "    if False:",
        CHILD + "test_a_child_that_fails_is_a_fixed_failure[busy]",
    ),
    (
        "mail account open to other tools",
        "toolgate/core/vault.py",
        'raise KeyError(f"{placeholder} is read only by its built-in tool")',
        "pass",
        BOUNDARY + "test_no_other_tool_can_name_the_account",
    ),
    (
        "mail app password not a built-in secret",
        "toolgate/core/vault.py",
        '"MAIL_IMAP_USER", "MAIL_IMAP_PASSWORD"}',
        '"MAIL_IMAP_USER"}',
        BOUNDARY + "test_no_other_tool_can_name_the_account",
    ),
    (
        "mail name and executor not reserved",
        "toolgate/api/definitions.py",
        '        errors.append("mail.recent is reserved for the read-only mail executor")',
        "        pass",
        BOUNDARY + "test_the_name_and_executor_are_reserved_for_each_other",
    ),
    (
        "mail read through any definition",
        "toolgate/api/dispatch.py",
        '    if tool.get("id") != "mail.recent" or tool.get("execution") != {"type": "mail_imap"}:',
        "    if False:",
        BOUNDARY + "test_the_name_and_executor_are_reserved_for_each_other",
    ),
    (
        "mail tool routed by its executor only",
        "toolgate/api/dispatch.py",
        '    elif executor_type == "mail_imap" or tool.get("id") == "mail.recent":',
        '    elif executor_type == "mail_imap":',
        BOUNDARY + "test_the_name_and_executor_are_reserved_for_each_other",
    ),
    (
        "mail hours not checked by dispatch",
        "toolgate/api/dispatch.py",
        "    if type(hours) is not int or not 1 <= hours <= mail_imap.MAX_HOURS:",
        "    if False:",
        BOUNDARY + "test_dispatch_refuses_hours_the_definition_did_not_check",
    ),
    (
        "mail response nested too deep kept",
        PARSE,
        "                if deeper or len(stack) > MAX_DEPTH:",
        "                if False:",
        CHILD + "test_a_response_nested_too_deep_is_left_out_and_costs_only_itself",
    ),
    (
        "mail message gets the whole budget",
        PARSE,
        "                min(MESSAGE_SECONDS, left), lambda uid=uid: _message(uid, found[uid])",
        "                left, lambda uid=uid: _message(uid, found[uid])",
        CHILD + "test_a_message_that_runs_too_long_costs_only_itself",
    ),
    (
        "mail child counts from the call, not its start",
        PARSE,
        "    deadline = (clock.monotonic() if started is None else started) + total",
        "    deadline = clock.monotonic() + total",
        CHILD + "test_the_childs_time_counts_from_its_own_start",
    ),
    (
        "mail child clock started after its modules load",
        PARSE,
        "read(sys.stdin.buffer.read(LIMIT_BYTES + 1), wanted, started=STARTED)",
        "read(sys.stdin.buffer.read(LIMIT_BYTES + 1), wanted)",
        CHILD + "test_the_child_starts_its_clock_before_loading_its_modules",
    ),
    (
        "mail attachment disposition ignored",
        PARSE,
        '        if how == "attachment":',
        "        if False:",
        CHILD + "test_attachments_are_read_from_the_structure[csv]",
    ),
    (
        "mail attached text taken as the snippet",
        PARSE,
        '        if part.is_multipart() or part.get_content_disposition() == "attachment":',
        "        if part.is_multipart():",
        CHILD + "test_plain_text_is_preferred_and_an_attached_text_is_not_a_snippet",
    ),
    (
        "mail script and style read as text",
        PARSE,
        "        if tag in SKIPPED_TAGS:\n            self.skipping += 1",
        "        if False:\n            self.skipping += 1",
        CHILD + "test_html_is_read_as_its_visible_text",
    ),
    (
        "mail escape codec decodes a charset",
        PARSE,
        "        if codecs.lookup(name).name in ODD_CODECS:",
        "        if False:",
        CHILD + "test_subjects_are_decoded_in_their_charsets[escape-codec]",
    ),
    (
        "mail escape cut by the fetch kept",
        PARSE,
        '        body = CUT_ESCAPE.sub(b"", body)',
        "        body = body",
        CHILD + "test_an_escape_the_fetch_cut_in_two_is_dropped",
    ),
    (
        "mail 8-bit text read as ASCII",
        PARSE,
        "        data = part.get_payload(decode=True)",
        '        data = part.get_payload(decode=False).encode("ascii", "surrogateescape")',
        CHILD + "test_an_8bit_body_is_read_in_its_charset",
    ),
]
