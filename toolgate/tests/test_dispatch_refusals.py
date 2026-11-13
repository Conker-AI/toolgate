"""Typed executors fail as known failures with their own codes: a missing credential, an
upstream that breaks, research that refuses, lifecycle tools given the wrong arguments."""

from typing import cast

import httpx
import pytest
from fastapi import HTTPException

from toolgate.api import dispatch
from toolgate.executors import container_control, process_control, research_base


def tool(kind, **execution):
    return {"id": f"t.{kind}", "authorization": "owner_confirmation", "execution": {"type": kind, **execution}}


def refusal(call, *args):
    with pytest.raises(HTTPException) as caught:
        call(*args)
    detail = cast(dict, caught.value.detail)
    return caught.value.status_code, detail["code"]


def test_templates_render_inside_lists_and_keep_other_values():
    assert dispatch._render_template(["{a}", {"b": "{a}!"}, 3], {"a": "x"}) == ["x", {"b": "x!"}, 3]


def test_a_result_path_must_exist_in_the_upstream_answer():
    assert dispatch._extract_result({"data": {"items": [1]}}, "data.items") == [1]
    assert refusal(dispatch._extract_result, {"data": {}}, "data.items") == (502, "UPSTREAM_SCHEMA_ERROR")


def ok_research(monkeypatch):
    for name in ("search", "search_bundle"):
        monkeypatch.setattr(dispatch.research, name, lambda *_a: {"results": []})
    for name in ("fetch", "fetch_batch"):
        monkeypatch.setattr(research_base, name, lambda *_a: {"text": ""})


def failing_research(monkeypatch):
    def fail(*_a):
        raise research_base.ResearchError("source unavailable")

    for name in ("search", "search_bundle"):
        monkeypatch.setattr(dispatch.research, name, fail)
    for name in ("fetch", "fetch_batch"):
        monkeypatch.setattr(research_base, name, fail)


RESEARCH = [
    (tool("research_search"), {"query": "q"}, "RESEARCH_UNAVAILABLE", 502),
    (tool("research_bundle", sources=["web"]), {"query": "q"}, "RESEARCH_UNAVAILABLE", 502),
    (tool("research_fetch"), {"result_id": "r1"}, "RESEARCH_FETCH_DENIED", 422),
    (tool("research_fetch_batch"), {"result_ids": ["r1"]}, "RESEARCH_FETCH_DENIED", 422),
]


@pytest.mark.parametrize(("definition", "args", "code", "status"), RESEARCH)
def test_research_results_pass_through_and_refusals_keep_their_reason(monkeypatch, definition, args, code, status):
    ok_research(monkeypatch)
    assert dispatch._dispatch_tool(definition, args)["ok"] is True
    failing_research(monkeypatch)
    assert refusal(dispatch._dispatch_tool, definition, args) == (status, code)


def memorygate(monkeypatch, post):
    monkeypatch.setattr(dispatch.vault, "get_key", lambda _ref: "mg-read-key")
    monkeypatch.setattr(dispatch.httpx, "post", post)
    return tool("memorygate", operation="context", secret_ref="MG_KEY")


def test_memorygate_reads_need_their_credential(monkeypatch):
    def missing(_ref):
        raise KeyError(_ref)

    monkeypatch.setattr(dispatch.vault, "get_key", missing)
    assert refusal(dispatch._dispatch_tool, tool("memorygate", operation="ask", secret_ref="MG_KEY"),
                   {"question": "q"}) == (503, "SECRET_UNAVAILABLE")


def test_memorygate_answers_and_failures(monkeypatch):
    sent = {}

    def answer(url, **kwargs):
        sent.update(url=url, **kwargs)
        return httpx.Response(200, json={"items": []}, request=httpx.Request("POST", url))

    definition = memorygate(monkeypatch, answer)
    assert dispatch._dispatch_tool(definition, {"query": "q"}) == {"ok": True, "result": {"items": []}}
    assert sent["url"].endswith("/runtime/context") and sent["headers"]["X-MemoryGate-Key"] == "mg-read-key"
    assert sent["json"] == {"query": "q", "max_items": 12, "include_evidence": False}

    def broken(url, **_kwargs):
        return httpx.Response(500, request=httpx.Request("POST", url))

    definition = memorygate(monkeypatch, broken)
    assert refusal(dispatch._dispatch_tool, definition, {"query": "q"}) == (502, "MEMORYGATE_UNAVAILABLE")


def test_a_local_ai_answer_without_text_is_a_failure(monkeypatch):
    monkeypatch.setattr(dispatch.pi_inference, "configured", lambda: None)
    monkeypatch.setattr(dispatch.control_plane, "settings", lambda: {})
    monkeypatch.setattr(dispatch.httpx, "post",
                        lambda url, **_k: httpx.Response(200, json={}, request=httpx.Request("POST", url)))
    assert refusal(dispatch._dispatch_tool, tool("ollama_generate", prompt_template="Hi {name}"),
                   {"name": "Ann"}) == (502, "AI_UNAVAILABLE")


def test_hosted_ai_refuses_unbounded_models_and_prompts_before_sending():
    assert refusal(dispatch._execute_gemini, {"model": "other", "prompt_template": "x"}, {}) == (422, "AI_MODEL_DENIED")
    model = dispatch.spending.MODEL
    assert refusal(dispatch._execute_gemini, {"model": model, "prompt_template": "{text}"},
                   {"text": "x" * 20001}) == (422, "VALIDATION_ERROR")


@pytest.mark.parametrize(("kind", "module", "target"), [
    ("process_control", process_control, "service_id"),
    ("container_control", container_control, "container_id"),
])
def test_lifecycle_tools_take_exactly_their_two_arguments_and_report_refusals(monkeypatch, kind, module, target):
    definition = {"id": f"t.{kind}", "authorization": "owner_confirmation", "execution": {"type": kind}}
    assert dispatch._dispatch_tool(definition, {target: "x"})["error_code"] == "invalid_arguments"

    def refuse(*_a):
        raise module.ControlError("not_managed")

    monkeypatch.setattr(module, "control", refuse)
    result = dispatch._dispatch_tool(definition, {target: "x", "action": "restart"})
    assert result["ok"] is False and result["error_code"] == "not_managed"


def test_an_unknown_executor_never_runs():
    result = dispatch._dispatch_tool({"id": "t.x", "execution": {"type": "shell"}}, {})
    assert result == {"ok": False, "error": "No restricted executor is configured for this typed tool."}
