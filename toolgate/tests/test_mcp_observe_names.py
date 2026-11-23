"""Which imported MCP tool names can never be Observe (core/mcp_observe.py says_act_outward).

Only a name that reads can be Observe: its own part starts with a read verb and nothing after it
connects or acts. Every other name asks the owner for every call, whatever he chose. A false
positive only asks; a false negative would let a tool act unasked, so every doubt asks."""

import pytest

from toolgate.core import approval_levels
from toolgate.core import mcp_observe as observe


def test_the_act_outward_words_hold_the_owner_list_and_every_word_that_raises_a_level():
    named = {"send", "post", "reply", "react", "delete", "remove", "write", "create", "update"}
    named |= {"move", "forward", "share", "invite", "pay", "buy", "draft"}
    assert named <= observe.ACT_OUTWARD_WORDS
    # Dangerous verbs act anywhere after the read verb, so get_x_then_kill-style tails ask.
    tails = {"kill", "terminate", "halt", "poweroff", "eval", "exec", "sql", "upsert", "register"}
    tails |= {"authorize", "sign", "deposit", "spend", "transact", "mint", "burn", "dispatch"}
    tails |= {"broadcast", "announce", "alert", "dial", "apply", "cleanup"}
    assert tails <= observe.ACTS
    assert approval_levels.OUTWARD_WORDS <= observe.ACT_OUTWARD_WORDS
    assert approval_levels.SERIOUS_WORDS <= observe.ACT_OUTWARD_WORDS
    assert not observe.READ_VERBS & (observe.ACT_OUTWARD_WORDS | observe.CONNECTORS)
    assert "check" not in observe.READ_VERBS


# Names an independent review found allowed as Observe before this rule set; all must act.
REVIEWED = [
    "bulk_sendmessage",
    "sendmessage_v2",
    "send2_user",
    "quicksend",
    "autopost",
    "tweet",
    "retweet",
    "comment",
    "sms_contact",
    "message_user",
    "email_contact",
    "dm_user",
    "compose_email",
    "start_call",
    "call_contact",
    "close_issue",
    "enable_rule",
    "toggle",
    "unlock_door",
    "kick_member",
    "report_user",
    "book_meeting",
    "change_status",
    "replace",
    "patch",
    "sync",
    "commit",
    "draft_email",
]
# The second review: a read verb first and something that acts after it, joined or not.
JOINED = [
    "get_and_message_user",
    "fetch_report_and_email",
    "read_mail_and_schedule_meeting",
    "get_and_stop_vm",
    "lookup_and_call",
    "view_and_comment",
    "search_and_order",
    "check_and_book",
    "read_and_lock",
    "getThenChatUser",
    "get_status_and_disarm",
    "get_x_then_kill",
    "read_mail_schedule_meeting",
]
# The second review: verbs no list named, which read before because nothing matched them.
UNNAMED = [
    "kill",
    "terminate_instance",
    "power_off",
    "halt",
    "disarm",
    "eval_js",
    "sql",
    "upsert",
    "register",
    "authorize",
    "sign_document",
    "deposit",
    "spend",
    "transact",
    "mint",
    "burn_token",
    "dispatch",
    "broadcast",
    "announce",
    "alert_user",
    "dial",
    "kubectl_apply",
    "terraform_apply",
    "files_cleanup",
]
# The same words after a read verb.
TAILS = [
    "get_vm_kill",
    "get_instance_terminate",
    "query_sql",
    "get_doc_sign",
    "get_token_burn",
    "get_vm_poweroff",
    "list_jobs_dispatch",
]


@pytest.mark.parametrize(
    "name",
    [
        *REVIEWED,
        *JOINED,
        *UNNAMED,
        *TAILS,
        "get_quicksend",
        "get_profile_updating",
        "get_thread_replied",
        "get_tag_add",
        "get_message_unpin",
        "get_status_retweet",
        "send.list_messages",
        "mcp.get-echo-delete",
        "echo",
        "send_message",
        "sendMessage",
        "SendMessage",
        "sendmessage",
        "sendSMS",
        "post_tweet",
        "posted_reply",
        "reply_to_thread",
        "replied_to_thread",
        "add_reaction",
        "get_or_add_label",
        "react",
        "delete_file",
        "DELETE_ALL",
        "remove_label",
        "write_file",
        "create_event",
        "update_event",
        "move_email",
        "forward_email",
        "share_document",
        "list_shared_drives",
        "updating_profile",
        "invite_user",
        "pay_invoice",
        "buy_ticket",
        "mark_read",
        "unsubscribe",
        "unpin_message",
        "rerun_job",
        "resend_invite",
        "respond_to_event",
        "uploadFile",
        "purchase",
        "transfer-funds",
        "publish.post",
        "gmail_draft",
        "Send a message",
        pytest.param("\u0455end", id="cyrillic-s-first"),
        # After a read verb a look-alike would hide the word that acts: get + end.
        pytest.param("get_\u0455end", id="cyrillic-s"),
        pytest.param("\uff53\uff45\uff4e\uff44", id="full-width-send"),
        pytest.param("get_s\u200bend", id="zero-width-space"),
        pytest.param("get_se\x00nd", id="control-character"),
        pytest.param("", id="empty"),
        pytest.param("--", id="punctuation"),
        pytest.param(None, id="none"),
        pytest.param(7, id="number"),
    ],
)
def test_names_that_act(name):
    assert observe.says_act_outward(name)


@pytest.mark.parametrize(
    "name",
    [
        "search",
        "fetch",
        "get_echo",
        "list_people",
        "read_chat",
        "list_messages",
        "read_message",
        "getMessage",
        "search_messages",
        "get_thread",
        "search_threads",
        "list_events",
        "listEvents",
        "get_event",
        "get_calendar_events",
        "get_freebusy",
        "list_calendars",
        "list_chats",
        "list_emails",
        "read_email",
        "list_labels",
        "list_drafts",
        "get_unread_count",
        "list_comments",
        "list_tweets",
        "list_replies",
        "list_calls",
        "list_sent",
        "get_report",
        "get_text",
        "get_contacts",
        "find_contact",
        "lookup_user",
        "get_settings",
        "get_address",
        "get_profile",
        "list_notebooks",
        "list_files",
        "read_file",
        "search_files",
        "get_file_metadata",
        "list_recent_files",
        "query_database",
        "describe_table",
        "Search messages",
        "Get echo",
        # A namespace before a dot is not the verb: the id and dotted tool names keep theirs.
        "mcp.list-messages",
        "social.list_chats",
        "mcp.social.read-chat",
        # NFKC first: a full-width name reads as its ASCII letters.
        pytest.param("\uff4c\uff49\uff53\uff54_messages", id="full-width-list"),
    ],
)
def test_names_that_read(name):
    assert not observe.says_act_outward(name)


# Reads that always ask (accepted false positives, listed in toolgate#126): not led by a read
# verb, glued, a word that acts inside another word, or a LEADS word past the read's object.
KNOWN_READS_THAT_ASK = [
    "echo",
    "research",
    "gmail_search",
    "dropbox_search",
    "display_profile",
    "retrieve_page",
    "download_file_content",
    "look_up_contact",
    "what_needs_me",
    "searchemails",
    "get_market_data",
    "list_reactions",
    "get_followers",
    "list_posts",
    "get_updates",
    "list_skills",
    "list_alerts",
    "list_transactions",
    "get_latest_release",
    "list_unread_messages",
]


@pytest.mark.parametrize("name", KNOWN_READS_THAT_ASK)
def test_known_reads_that_always_ask(name):
    assert observe.says_act_outward(name)


@pytest.mark.parametrize(
    ("annotations", "acts"),
    [
        (None, False),
        ({"readOnlyHint": True}, False),
        ({"readOnlyHint": True, "destructiveHint": False, "title": "Echo"}, False),
        ({}, True),
        ({"title": "Echo"}, True),
        ({"openWorldHint": False}, True),
        ({"idempotentHint": True}, True),
        ({"destructiveHint": False}, True),
        ({"readOnlyHint": True, "destructiveHint": True}, True),
        ({"destructiveHint": True}, True),
        ({"readOnlyHint": False}, True),
        ({"readOnlyHint": "true"}, True),
        ({"destructiveHint": None}, True),
        (["readOnlyHint"], True),
        ("read only", True),
    ],
)
def test_server_hints_that_say_a_tool_changes_things(annotations, acts):
    assert observe.hints_act(annotations) is acts
