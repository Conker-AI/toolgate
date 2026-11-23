"""Which imported MCP tool names can never be Observe (core/mcp_observe.py says_act_outward).

A name that says it acts asks the owner for every call, whatever he chose. A false positive only
asks; a false negative would let a tool act unasked, so every doubt reads as acting."""

import pytest

from toolgate.core import approval_levels
from toolgate.core import mcp_observe as observe


def test_the_act_outward_words_hold_the_owner_list_and_every_word_that_raises_a_level():
    named = {"send", "post", "reply", "react", "delete", "remove", "write", "create", "update"}
    named |= {"move", "forward", "share", "invite", "pay", "buy", "draft"}
    assert named <= observe.ACT_OUTWARD_WORDS
    assert approval_levels.OUTWARD_WORDS <= observe.ACT_OUTWARD_WORDS
    assert approval_levels.SERIOUS_WORDS <= observe.ACT_OUTWARD_WORDS
    assert not observe.READS & observe.ACT_OUTWARD_WORDS


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


@pytest.mark.parametrize(
    "name",
    [
        *REVIEWED,
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
        "slack_message_user",
        "gmail_draft",
        "Send a message",
        pytest.param("\u0455end", id="cyrillic-s"),
        pytest.param("\uff53\uff45\uff4e\uff44", id="full-width-send"),
        pytest.param("s\u200bend", id="zero-width-space"),
        pytest.param("se\x00nd", id="control-character"),
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
        "echo",
        "search",
        "fetch",
        "research",
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
        "gmail_search",
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
        "get_latest_release",
        "get_contacts",
        "find_contact",
        "lookup_user",
        "get_settings",
        "get_address",
        "get_profile",
        "display_profile",
        "list_notebooks",
        "list_files",
        "read_file",
        "search_files",
        "get_file_metadata",
        "list_recent_files",
        "download_file_content",
        "query_database",
        "describe_table",
        "retrieve_page",
        "retrieving_pages",
        "queries_list",
        "Search messages",
        # NFKC first: a full-width name reads as its ASCII letters.
        pytest.param("\uff4c\uff49\uff53\uff54_messages", id="full-width-list"),
    ],
)
def test_names_that_read(name):
    assert not observe.says_act_outward(name)


@pytest.mark.parametrize(
    "name", ["dropbox_search", "get_market_data", "list_reactions", "get_followers"]
)
def test_a_word_that_acts_inside_another_word_still_acts(name):
    # Accepted false positives: these ask for every call and can never be Observe.
    assert observe.says_act_outward(name)


@pytest.mark.parametrize(
    ("annotations", "acts"),
    [
        (None, False),
        ({}, False),
        ({"readOnlyHint": True, "destructiveHint": False, "title": "Echo"}, False),
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
