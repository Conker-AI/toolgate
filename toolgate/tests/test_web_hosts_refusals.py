"""Threat-list feeds and host checks on bad input: oversized or failing downloads, an unwritable
data folder, an unreadable list file and URLs with no usable host."""

from __future__ import annotations

import threading

import httpx
import pytest

from toolgate.core import web_hosts

FEED = "https://feed.test/hosts.txt"


def feed_client(handler):
    """A `public_client` stand-in that answers from `handler` without touching the network."""

    def build(**kwargs):
        return httpx.Client(transport=httpx.MockTransport(handler), **kwargs)

    return build


@pytest.fixture
def lists(tmp_path, monkeypatch):
    monkeypatch.setattr(web_hosts, "LIST_DIR", tmp_path)
    monkeypatch.setenv("TOOLGATE_THREAT_FEEDS", FEED)
    monkeypatch.setattr(web_hosts, "_attempted", {})
    monkeypatch.setattr(web_hosts, "_running", set())
    monkeypatch.setattr(web_hosts, "_loaded", {})
    return tmp_path


@pytest.mark.parametrize("char", ["7", "-", "́"])
def test_digits_hyphens_and_combining_marks_have_no_script_of_their_own(char):
    assert web_hosts._script(char) is None


def test_an_unassigned_character_counts_as_an_unknown_script():
    assert web_hosts._script("͸") == "UNKNOWN"


def test_a_feed_is_downloaded_and_parsed(monkeypatch):
    monkeypatch.setattr(
        web_hosts,
        "public_client",
        feed_client(lambda request: httpx.Response(200, content=b"0.0.0.0 evil.test\nbad.test\n")),
    )
    assert web_hosts._download(FEED) == {"evil.test", "bad.test"}


def test_a_feed_that_answers_with_an_error_is_not_read(monkeypatch):
    monkeypatch.setattr(
        web_hosts, "public_client", feed_client(lambda request: httpx.Response(503))
    )
    with pytest.raises(httpx.HTTPStatusError):
        web_hosts._download(FEED)


def test_a_feed_over_the_size_limit_is_refused_while_it_streams(monkeypatch):
    monkeypatch.setattr(web_hosts, "FEED_BYTES", 64)
    monkeypatch.setattr(
        web_hosts,
        "public_client",
        feed_client(lambda request: httpx.Response(200, content=b"evil.test\n" * 20)),
    )
    with pytest.raises(ValueError, match="larger than"):
        web_hosts._download(FEED)


def test_an_oversized_feed_leaves_the_last_list_in_place(lists, monkeypatch):
    path = web_hosts._feed_file(FEED)
    path.write_text("old.test\n", encoding="utf-8")
    monkeypatch.setattr(web_hosts, "FEED_BYTES", 64)
    monkeypatch.setattr(
        web_hosts,
        "public_client",
        feed_client(lambda request: httpx.Response(200, content=b"evil.test\n" * 20)),
    )
    assert web_hosts.refresh(FEED) is False
    assert path.read_text(encoding="utf-8") == "old.test\n"


def test_an_unwritable_data_folder_keeps_the_last_list(lists, monkeypatch):
    blocker = lists / "occupied"
    blocker.write_text("a file where the folder should be", encoding="utf-8")
    monkeypatch.setattr(web_hosts, "LIST_DIR", blocker)
    monkeypatch.setattr(web_hosts, "_download", lambda url: {"new.test"})
    assert web_hosts.refresh(FEED) is False
    assert blocker.read_text(encoding="utf-8") == "a file where the folder should be"


def test_the_background_refresh_always_releases_its_feed(lists, monkeypatch):
    def broken(url):
        raise RuntimeError("refresh crashed")

    monkeypatch.setattr(web_hosts, "refresh", broken)
    web_hosts._running.add(FEED)
    with pytest.raises(RuntimeError):
        web_hosts._refresh_in_background(FEED)
    assert FEED not in web_hosts._running


def test_a_finished_background_refresh_writes_the_list(lists, monkeypatch):
    monkeypatch.setattr(web_hosts, "_download", lambda url: {"fresh.test"})
    web_hosts._running.add(FEED)
    worker = threading.Thread(target=web_hosts._refresh_in_background, args=(FEED,))
    worker.start()
    worker.join(10)
    assert web_hosts._feed_file(FEED).read_text(encoding="utf-8") == "fresh.test\n"
    assert FEED not in web_hosts._running


def test_a_list_file_that_cannot_be_read_lists_nothing(lists):
    unreadable = web_hosts._feed_file(FEED)
    unreadable.mkdir()
    assert web_hosts._hosts(unreadable) == frozenset()


@pytest.mark.parametrize("url", ["https://[unclosed/", "file:///etc/hosts", "not a url", ""])
def test_a_url_with_no_usable_host_is_left_to_the_public_https_check(lists, url):
    assert web_hosts.refusal(url) is None
