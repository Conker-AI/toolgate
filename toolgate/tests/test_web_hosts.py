"""Lookalike hosts and threat-listed hosts never reach research results or page fetches."""

from __future__ import annotations

import os
import socket
import time
from types import SimpleNamespace

import pytest

from toolgate.core import web_hosts
from toolgate.executors import research_base


@pytest.mark.parametrize("host", [
    "xn--pple-43d.com",          # Cyrillic а + "pple"
    "xn--80ak6aa92e.com",        # аррӏе, all Cyrillic letters that look Latin
    "pаypal.com",                # raw Cyrillic а inside Latin
    "xn--zz.com",                # does not decode
    "xn--abc-.com",              # decodes to ASCII: not a real IDN
    "xn--apple.com",             # decodes to control characters
    "gοοgle.com",                # Greek omicrons inside Latin
])
def test_lookalikes_are_refused(host):
    assert web_hosts.lookalike(host)
    assert web_hosts.refusal(f"https://{host}/page") == "lookalike"


@pytest.mark.parametrize("host", [
    "example.com", "münchen.de", "xn--mnchen-3ya.de", "пример.рф", "яндекс.ru",
    "例え.jp", "東京ドーム.jp", "中文.tw", "한국.kr", "παράδειγμα.gr", "sub.example.co.uk",
    "1.2.3.4",
])
def test_real_names_pass(host):
    assert not web_hosts.lookalike(host)


def test_greek_lookalike_needs_a_greek_tld():
    assert web_hosts.lookalike("οκ.com")
    assert not web_hosts.lookalike("οκ.gr")


def test_parse_reads_hosts_files():
    text = "# comment\n0.0.0.0 Evil.Example.\n\nbad.test # note\n0.0.0.0 0.0.0.0\nnot a host!\n"
    assert web_hosts.parse(text) == {"evil.example", "bad.test"}


@pytest.fixture
def lists(tmp_path, monkeypatch):
    monkeypatch.setattr(web_hosts, "LIST_DIR", tmp_path)
    monkeypatch.setenv("TOOLGATE_THREAT_FEEDS", "https://feed.test/hosts.txt")
    monkeypatch.setattr(web_hosts, "_attempted", {})
    monkeypatch.setattr(web_hosts, "_running", set())
    started = []
    thread = lambda target, args, daemon: started.append(args) or _Idle()  # noqa: E731
    monkeypatch.setattr(web_hosts, "threading", SimpleNamespace(Thread=thread))
    return started


class _Idle:
    def start(self):
        pass


def test_listed_host_and_its_subdomains_are_refused(lists):
    web_hosts._feed_file("https://feed.test/hosts.txt").write_text("evil.test\n", encoding="utf-8")
    assert web_hosts.refusal("https://evil.test/") == "threat_list"
    assert web_hosts.refusal("https://a.b.evil.test/x") == "threat_list"
    assert web_hosts.refusal("https://notevil.test/") is None
    assert web_hosts.refusal("https://test/") is None


def test_missing_list_refuses_nothing_and_starts_one_refresh(lists):
    assert web_hosts.refusal("https://evil.test/") is None
    assert web_hosts.refusal("https://evil.test/") is None
    assert lists == [("https://feed.test/hosts.txt",)]


def test_fresh_list_is_not_downloaded_again(lists):
    web_hosts._feed_file("https://feed.test/hosts.txt").write_text("evil.test\n", encoding="utf-8")
    web_hosts.listed("example.com")
    assert lists == []
    old = time.time() - web_hosts.REFRESH_SECONDS - 5
    os.utime(web_hosts._feed_file("https://feed.test/hosts.txt"), (old, old))
    web_hosts.listed("example.com")
    assert lists == [("https://feed.test/hosts.txt",)]


def test_failed_or_empty_download_keeps_the_last_list(lists, monkeypatch):
    path = web_hosts._feed_file("https://feed.test/hosts.txt")
    path.write_text("evil.test\n", encoding="utf-8")

    def broken(url):
        raise OSError("down")

    monkeypatch.setattr(web_hosts, "_download", broken)
    assert not web_hosts.refresh("https://feed.test/hosts.txt")
    monkeypatch.setattr(web_hosts, "_download", lambda url: set())
    assert not web_hosts.refresh("https://feed.test/hosts.txt")
    assert path.read_text(encoding="utf-8") == "evil.test\n"
    monkeypatch.setattr(web_hosts, "_download", lambda url: {"new.test"})
    assert web_hosts.refresh("https://feed.test/hosts.txt")
    assert web_hosts.listed("new.test") and not web_hosts.listed("evil.test")


def test_feeds_setting(monkeypatch):
    monkeypatch.delenv("TOOLGATE_THREAT_FEEDS")
    assert web_hosts.feeds() == list(web_hosts.DEFAULT_FEEDS)
    monkeypatch.setenv("TOOLGATE_THREAT_FEEDS", "off")
    assert web_hosts.feeds() == []
    monkeypatch.setenv("TOOLGATE_THREAT_FEEDS", " https://a.test/x , https://b.test/y ")
    assert web_hosts.feeds() == ["https://a.test/x", "https://b.test/y"]


def test_research_drops_refused_hosts_before_dns(lists, monkeypatch):
    web_hosts._feed_file("https://feed.test/hosts.txt").write_text("evil.test\n", encoding="utf-8")

    def no_dns(*args, **kwargs):
        raise AssertionError("a refused host must not be resolved")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    assert research_base._normalize("t", "https://xn--pple-43d.com/", "s", "web") is None
    assert research_base._normalize("t", "https://cdn.evil.test/", "s", "web") is None
    assert not research_base._public_https_url("https://evil.test/redirect-target")
