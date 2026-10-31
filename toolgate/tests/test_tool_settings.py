"""The owner's tool settings: only the owner key reads or saves them, every save names the revision
it replaces, no value goes past today's limit, and each one changes what tools do. The Terminal's
settings are also covered in test_sandbox_tools.py, test_sandbox_spec.py, test_sandbox_runner.py
and sandbox/verify (the real Docker Engine)."""

import sqlite3
import time
from contextlib import closing, contextmanager
from unittest.mock import Mock

import pytest

from toolgate.api import dispatch, invocation
from toolgate.core import control_plane as cp
from toolgate.core import research_cache, tool_settings
from toolgate.core.owner_channel import OwnerError
from toolgate.executors import mcp_http, pi_inference, research, research_base, research_web
from toolgate.executors import sandbox as sandbox_executor
from toolgate.sandbox import spec
from toolgate.tests.test_nested_publications import nested, run  # noqa: F401
from toolgate.tests.test_owner_channel import ADMIN, HEADERS, gate  # noqa: F401

TODAY = {
    "tool_seconds": None,
    "terminal_seconds": None,
    "terminal_memory_mb": None,
    "terminal_cpus": None,
    "terminal_workspace_mb": None,
    "web_safe_search": "moderate",
    "web_region": "",
    "web_skip_sites": [],
    "web_page_characters": None,
    "run_window_minutes": None,  # covered in test_run_window.py
}
CEILINGS = {
    "tool_seconds": 180,
    "terminal_seconds": 100,
    "terminal_memory_mb": 512,
    "terminal_cpus": 1,
    "terminal_workspace_mb": 2048,
    "web_page_characters": 20000,
    "run_window_minutes": 15,
}


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")


def save(client, settings, revision=0, headers=None):
    return client.put(
        "/v2/owner/settings",
        headers=HEADERS if headers is None else headers,
        json={"expected_revision": revision, "settings": settings},
    )


def choose(**settings):
    """Save settings straight to the store, as the owner route does."""
    revision = tool_settings.load()["revision"]
    update = tool_settings.Update(expected_revision=revision, settings=settings)
    return tool_settings.save(update)


# --- the owner route ---------------------------------------------------------------------------


def test_only_the_owner_key_reads_or_saves_them(gate):
    client, _, execution = gate
    for headers in (
        {},
        {"X-ToolGate-Key": ADMIN},
        {"X-ToolGate-Execution-Key": execution},
        {"X-ToolGate-Owner-Key": execution},
        {"X-ToolGate-Owner-Key": "wrong"},
    ):
        assert client.get("/v2/owner/settings", headers=headers).status_code == 401
        assert save(client, {"tool_seconds": 30}, headers=headers).status_code == 401
    assert tool_settings.load()["revision"] == 0


def test_before_the_first_save_they_are_todays_limits(gate):
    response = gate[0].get("/v2/owner/settings", headers=HEADERS)
    assert response.status_code == 200
    assert response.json() == {"settings": TODAY, "revision": 0}
    assert response.headers["Cache-Control"] == "no-store"


def test_a_save_names_the_revision_and_a_stale_one_is_refused(gate):
    client = gate[0]
    saved = save(client, {"tool_seconds": 30, "web_safe_search": "strict"})
    assert saved.status_code == 200, saved.text
    expected = {**TODAY, "tool_seconds": 30, "web_safe_search": "strict"}
    assert saved.json() == {"settings": expected, "revision": 1}
    assert client.get("/v2/owner/settings", headers=HEADERS).json() == saved.json()
    stale = save(client, {"tool_seconds": 60})
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "settings_revision_conflict"
    assert tool_settings.load() == saved.json()
    event = cp.events(event_type="tool_settings_updated")[0]
    assert event["payload"] == {"keys": ["tool_seconds", "web_safe_search"]}


def test_a_value_left_out_goes_back_to_todays_limit(gate):
    client = gate[0]
    assert save(client, {"tool_seconds": 30, "web_region": "us"}).status_code == 200
    assert save(client, {"web_region": "us"}, revision=1).json()["settings"] == {
        **TODAY,
        "web_region": "us",
    }


def test_the_ceilings_are_todays_limits_and_are_accepted(gate):
    config = spec.Config.from_env(
        {"SANDBOX_IMAGE": "sha256:" + "a" * 64, "SANDBOX_WORKSPACES_VOLUME": "w",
         "SANDBOX_PROXY_VOLUME": "p"}
    )  # fmt: skip
    assert config.limits.memory_mb == CEILINGS["terminal_memory_mb"]
    assert config.limits.cpus_milli == CEILINGS["terminal_cpus"] * 1000
    assert config.limits.workspace_mb == CEILINGS["terminal_workspace_mb"]
    assert CEILINGS["terminal_seconds"] == sandbox_executor.MAX_RUN_SECONDS
    assert CEILINGS["tool_seconds"] == pi_inference.TIMEOUT_SECONDS
    response = save(gate[0], CEILINGS)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "settings",
    [
        {"tool_seconds": 181},
        {"tool_seconds": 4},
        {"terminal_seconds": 101},
        {"terminal_seconds": 600},
        {"terminal_memory_mb": 513},
        {"terminal_memory_mb": 8192},
        {"terminal_memory_mb": 63},
        {"terminal_cpus": 1.1},
        {"terminal_cpus": 8},
        {"terminal_cpus": 0.05},
        {"terminal_workspace_mb": 2049},
        {"terminal_workspace_mb": 20000},
        {"terminal_workspace_mb": 15},
        {"web_page_characters": 20001},
        {"web_page_characters": 100000},
        {"web_page_characters": 999},
        {"web_safe_search": "none"},
        {"web_region": "usa"},
        {"web_region": "u1"},
        {"web_skip_sites": ["not a site"]},
        {"web_skip_sites": ["https://example.com/page"]},
        {"web_skip_sites": [f"site{index}.com" for index in range(51)]},
        {"tool_seconds": "30"},
        {"tool_seconds": True},
        {"tool_seconds": 30.0},
        {"terminal_pids": 10},
    ],
)
def test_a_value_past_its_ceiling_or_of_the_wrong_kind_is_refused(gate, settings):
    response = save(gate[0], settings)
    assert response.status_code == 422, response.text
    assert tool_settings.load() == {"settings": TODAY, "revision": 0}


def test_site_names_and_regions_are_tidied(gate):
    sites = [" WWW.Example.com ", "example.com", "news.site.org"]
    saved = save(gate[0], {"web_skip_sites": sites, "web_region": " IL "}).json()["settings"]
    assert saved["web_skip_sites"] == ["example.com", "news.site.org"]
    assert saved["web_region"] == "il"


def test_a_stored_value_this_version_no_longer_allows_reads_as_today(store):
    cp._put("settings", "tools", {"settings": {"tool_seconds": 999}, "revision": 3})
    assert tool_settings.current() == tool_settings.Settings()
    assert tool_settings.load() == {"settings": TODAY, "revision": 3}


def test_reading_them_never_creates_the_database(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "absent.db")
    assert tool_settings.current() == tool_settings.Settings()
    assert tool_settings.seconds(30) == 30
    assert not (tmp_path / "absent.db").exists()


def test_one_value_this_version_no_longer_allows_drops_only_that_value(store):
    stored = {"tool_seconds": 999, "web_skip_sites": ["example.com"], "web_safe_search": "strict",
              "a_retired_setting": True}
    cp._put("settings", "tools", {"settings": stored, "revision": 2})
    chosen = tool_settings.current()
    assert chosen.tool_seconds is None
    assert (chosen.web_skip_sites, chosen.web_safe_search) == (["example.com"], "strict")
    cp._put("settings", "tools", {"settings": ["not", "a", "document"], "revision": 3})
    assert tool_settings.current() == tool_settings.Settings()


def test_a_database_without_the_settings_table_reads_as_nothing_saved(tmp_path, monkeypatch):
    path = tmp_path / "gate.db"
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE other (x)")
    monkeypatch.setattr(cp, "DB_PATH", path)
    assert tool_settings.current() == tool_settings.Settings()


def test_a_database_that_cannot_be_read_refuses_rather_than_dropping_the_owners_limits(
    tmp_path, monkeypatch
):
    path = tmp_path / "gate.db"
    path.write_bytes(b"not a database " * 100)
    monkeypatch.setattr(cp, "DB_PATH", path)
    for read in (tool_settings.current, tool_settings.skip_sites, lambda: tool_settings.seconds(30)):
        with pytest.raises(OwnerError) as refused:
            read()
        assert (refused.value.code, refused.value.status) == ("settings_unreadable", 503)


def test_the_owner_route_says_when_the_settings_cannot_be_read(gate, monkeypatch):
    connect = sqlite3.connect

    def locked(target, *args, **kwargs):
        if "mode=ro" in str(target):
            raise sqlite3.OperationalError("database is locked")
        return connect(target, *args, **kwargs)

    monkeypatch.setattr(tool_settings.sqlite3, "connect", locked)
    response = gate[0].get("/v2/owner/settings", headers=HEADERS)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "settings_unreadable"


def test_a_save_whose_event_cannot_be_written_is_not_applied(store):
    choose(tool_seconds=30)
    with closing(sqlite3.connect(cp.DB_PATH)) as db:
        db.execute("CREATE TRIGGER no_events BEFORE INSERT ON v2_events "
                   "BEGIN SELECT RAISE(ABORT, 'events refused'); END")
        db.commit()
    with pytest.raises(sqlite3.Error):
        choose(tool_seconds=60)
    assert tool_settings.load()["revision"] == 1
    assert tool_settings.current().tool_seconds == 30


# --- tools.timeout: one tool call ----------------------------------------------------------------


def test_the_tool_limit_only_ever_lowers_a_tools_own(store):
    assert (tool_settings.seconds(30), tool_settings.call_seconds()) == (30, None)
    choose(tool_seconds=20)
    assert (tool_settings.seconds(30), tool_settings.seconds(10)) == (20, 10)
    assert tool_settings.call_seconds() == 20


def test_web_api_memory_and_ai_calls_wait_no_longer_than_the_limit(store, monkeypatch):
    choose(tool_seconds=7)
    waits = []

    @contextmanager
    def client(timeout, headers):
        waits.append(("http_json", timeout))
        answer = Mock(status_code=200, content=b"{}")
        answer.json.return_value = {}
        yield Mock(request=Mock(return_value=answer))

    def post(*_args, timeout, **_kwargs):
        waits.append(("post", timeout))
        return Mock(json=Mock(return_value={"response": "ok"}), raise_for_status=Mock())

    monkeypatch.setattr(dispatch, "public_client", client)
    monkeypatch.setattr(dispatch, "public_url", lambda _url: True)
    monkeypatch.setattr(dispatch.httpx, "post", post)
    monkeypatch.setattr(dispatch.vault, "get_key", lambda _ref: "secret")
    dispatch._execute_http_json(
        {"url": "https://example.com/x", "allowed_hosts": ["example.com"], "timeout_seconds": 30},
        {},
    )
    dispatch._execute_memorygate(
        {"operation": "query", "secret_ref": "MEMORYGATE_KEY"}, {"question": "q"}
    )
    monkeypatch.delenv("TOOLGATE_PI_URL", raising=False)
    dispatch._execute_ollama({"prompt_template": "Hi"}, {})
    assert waits == [("http_json", 7), ("post", 7), ("post", 7)]
    sent = {}
    monkeypatch.setattr(pi_inference, "configured", lambda: ("http://pi", "key"))
    monkeypatch.setattr(pi_inference, "generate", lambda *_a, **kw: sent.update(kw) or "ok")
    dispatch._execute_ollama({"prompt_template": "Hi"}, {})
    assert sent == {"timeout": 7}


def test_an_mcp_call_runs_within_the_limit_and_discovery_keeps_its_own(store, monkeypatch):
    assert mcp_http.Session("https://mcp.example.com/mcp").deadline - time.monotonic() > 29
    choose(tool_seconds=6)
    assert mcp_http.Session("https://mcp.example.com/mcp").deadline - time.monotonic() > 29
    opened = []

    class Recorder:
        def __init__(self, url, secret_ref=None, seconds=mcp_http.MAX_SECONDS):
            opened.append(seconds)
            raise mcp_http.MCPError("stop", "stop", 502)

    monkeypatch.setattr(mcp_http, "validate_execution", lambda _execution: None)
    monkeypatch.setattr(mcp_http, "validate_arguments", lambda *_args: None)
    monkeypatch.setattr(mcp_http, "Session", Recorder)
    execution = {"url": "https://mcp.example.com/mcp", "input_schema": {}}
    assert mcp_http.execute(execution, {"arguments": {}})["error_code"] == "stop"
    assert opened == [6]


def test_a_research_search_runs_within_the_limit(store, monkeypatch):
    timeouts = []

    def unavailable(_query, _source, _limit, _recency_days, timeout):
        timeouts.append(timeout)
        raise research.httpx.HTTPError("unavailable")

    for name in ("_reddit_subreddit_feed", "_reddit_subreddit_searx", "_reddit_subreddit_tavily"):
        monkeypatch.setattr(research, name, unavailable)
    choose(tool_seconds=5)
    with pytest.raises(research.ResearchError):
        research.search("subreddit:accounting", "reddit", 5, 14)
    assert timeouts and all(0 < timeout <= 5 for timeout in timeouts)


def test_a_research_bundle_stops_when_the_limit_is_reached(store, monkeypatch):
    now = [0.0]
    deadlines = []
    monkeypatch.setattr(research.time, "monotonic", lambda: now[0])

    def slow_search(_query, source, _limit, _recency, until=None):
        deadlines.append(until)
        now[0] += 4
        return {"result_count": 0, "provider": source, "fallback_failures": [], "results": []}

    monkeypatch.setattr(research, "search", slow_search)
    choose(tool_seconds=5)
    result = research.search_bundle("invoices", ["general", "reddit", "github"], 3, 90)
    assert deadlines == [5.0, 5.0]
    assert [row["status"] for row in result["source_reports"]] == [
        "completed",
        "completed",
        "failed",
    ]
    assert result["source_reports"][2]["error"] == "the tool time limit was reached"


def test_a_page_batch_stops_when_the_limit_is_reached(store, monkeypatch):
    now = [0.0]
    waits = []
    monkeypatch.setattr(research_base.time, "monotonic", lambda: now[0])

    def slow_fetch(result_id, _max_chars, timeout):
        waits.append(timeout)
        now[0] += 4
        return {"result_id": result_id, "content": "page"}

    monkeypatch.setattr(research_base, "fetch", slow_fetch)
    choose(tool_seconds=6)
    documents = research_base.fetch_batch(["a", "b", "c"], 2000)["documents"]
    assert waits == [6.0, 2.0]
    assert documents[2]["error"] == "the tool time limit was reached"


def test_a_workflow_run_stops_at_the_tool_limit(nested, monkeypatch):
    _, _, _, _, agent, calls = nested
    now = [0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    def dispatch_tool(tool, _args):
        calls.append(tool)
        now[0] += 6
        return {"ok": True, "result": {}}

    monkeypatch.setattr(invocation, "_dispatch_tool", dispatch_tool)
    assert run(agent, action="before")["code"] == "OK"  # its own ceiling is 30 seconds
    choose(tool_seconds=5)
    assert run(agent, action="after")["code"] == "OUTCOME_UNKNOWN"
    assert len(calls) == 2


# --- web search ----------------------------------------------------------------------------------


def searx_params(monkeypatch):
    sent = []

    def get(_url, params, **_kwargs):
        sent.append(params)
        return Mock(json=Mock(return_value={"results": []}), raise_for_status=Mock())

    monkeypatch.setattr(research_web.httpx, "get", get)
    return sent


def test_safe_search_and_region_reach_the_search_engine(store, monkeypatch):
    sent = searx_params(monkeypatch)
    research_web._searx("invoices", "general", 5, 90, 5)
    choose(web_safe_search="strict", web_region="il")
    research_web._searx("invoices", "general", 5, 90, 5)
    choose(web_safe_search="off")
    research_web._searx("invoices", "general", 5, 90, 5)
    assert [(params["safesearch"], params["language"]) for params in sent] == [
        (1, "en"),
        (2, "en-IL"),
        (0, "en"),
    ]


def test_skipped_sites_are_never_sources(store, monkeypatch):
    def rows(*urls):
        return [{"title": url, "url": url, "snippet": "", "source": "general"} for url in urls]

    monkeypatch.setattr(
        research, "_searx", lambda *_a: rows("https://news.example.com/a", "https://kept.org/b")
    )
    monkeypatch.setattr(research, "_hackernews", lambda *_a: rows("https://other.net/c"))
    choose(web_skip_sites=["example.com"])
    found = research.search("invoices", "general", 5, 90)
    assert [row["url"] for row in found["results"]] == ["https://kept.org/b"]
    choose(web_skip_sites=["example.com", "kept.org"])
    found = research.search("invoices", "general", 5, 90)
    assert (found["provider"], [row["url"] for row in found["results"]]) == (
        "hackernews",
        ["https://other.net/c"],
    )


def test_a_page_on_a_skipped_site_is_not_fetched_and_pages_keep_the_owners_size(store):
    page = research_cache.cache_research_result(
        {"title": "Page", "url": "https://www.example.com/a", "source": "general",
         "document": "evidence " * 2000},
        "2099-01-01T00:00:00+00:00",
    )  # fmt: skip
    assert research_base.fetch(page["id"], 20000)["content_stats"]["model_characters"] > 15000
    choose(web_page_characters=1000)
    assert research_base.fetch(page["id"], 20000)["content_stats"]["model_characters"] <= 1000
    choose(web_skip_sites=["example.com"])
    with pytest.raises(research.ResearchError, match="skips"):
        research_base.fetch(page["id"], 2000)
