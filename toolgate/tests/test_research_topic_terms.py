"""Filler words never shrink the owner's query to nothing (hunt toolgate-4 F4)."""

from unittest.mock import Mock

import pytest

from toolgate.core import control_plane
from toolgate.executors import research_base, research_sites


@pytest.fixture(autouse=True)
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")


def answer(payload: dict) -> Mock:
    response = Mock(status_code=200, content=b"{}")
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def test_filler_is_dropped_but_a_query_of_only_filler_is_kept():
    stop = research_base.QUERY_STOP_WORDS
    assert research_base.topic_terms("the invoice tool for teams", stop) == ["invoice"]
    assert research_base.topic_terms("email software", stop) == ["email", "software"]
    assert research_base.topic_terms("a to", stop) == []


def test_github_repositories_searches_a_query_made_of_filler_words(monkeypatch):
    sent = []

    def get(_url, **kwargs):
        sent.append(kwargs["params"]["q"])
        return answer({"items": []})

    monkeypatch.setattr(research_sites.vault, "get_key", Mock(side_effect=KeyError("GITHUB_TOKEN")))
    monkeypatch.setattr(research_sites.httpx, "get", get)
    research_sites._github_repositories("email software", "github_repositories", 5, 365, 5)
    assert sent and sent[0].startswith("email software ")


def test_appstore_catalog_accepts_a_query_made_of_filler_words(monkeypatch):
    sent = []

    def get(_url, **kwargs):
        sent.append(kwargs["params"]["term"])
        return answer({"results": []})

    monkeypatch.setattr(research_sites.httpx, "get", get)
    assert research_sites._appstore_catalog("small team tools", "appstore_catalog", 5, 3650, 5) == []
    assert sent == ["small team tools"]
