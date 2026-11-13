"""Every typed refusal of a tool or workflow definition: a definition that breaks one rule is
refused with that rule's words, before anything is saved or approved."""

import pytest

from toolgate.api import definitions as d


def tool(**changes):
    base = {
        "id": "notes.add", "name": "Add note", "description": "Adds a note.",
        "authorization": "auto", "status": "active",
        "inputs": [{"name": "text", "type": "string"}],
        "execution": {"type": "local_echo"},
    }
    return {**base, **changes}


def field(**changes):
    return [{"name": "text", "type": "string", **changes}]


def errors_of(definition):
    return d.tool_definition_errors(definition)


def test_the_base_definition_is_valid():
    assert errors_of(tool()) == []
    assert errors_of(tool(inputs=field(pattern="^[a-z]+$"))) == []


@pytest.mark.parametrize(("inputs", "words"), [
    ("text", "inputs must be a list"),
    ([{"name": f"f{i}"} for i in range(65)], "more than 64 fields"),
    ([5], "input 1 must be an object"),
    ([{"name": "a"}, {"name": "a"}], "input name 'a' is duplicated"),
    (field(type="date"), "type must be one of"),
    (field(type="integer", minimum="1"), "minimum must be numeric"),
    (field(type="integer", maximum=True), "maximum must be numeric"),
    (field(type="integer", minimum=5, maximum=1), "minimum cannot exceed maximum"),
    (field(min_length=-1), "min_length must be between 0 and 100000"),
    (field(max_length="9"), "max_length must be between 0 and 100000"),
    (field(min_length=5, max_length=2), "min_length cannot exceed max_length"),
    (field(pattern=5), "pattern must be text"),
    (field(pattern="x" * 501), "pattern must be text"),
    (field(pattern="("), "not valid regular expression syntax"),
    (field(allowed_values="hi"), "allowed_values must be a list"),
    (field(allowed_values=list(range(101))), "allowed_values must be a list"),
])
def test_input_fields_are_refused_for_each_broken_rule(inputs, words):
    assert any(words in error for error in errors_of(tool(inputs=inputs)))


@pytest.mark.parametrize("tool_id", ["N", "Notes", "-notes", 5])
def test_ids_are_lowercase_words(tool_id):
    assert any("id must be 2-80" in error for error in errors_of(tool(id=tool_id)))


def controlled(tool_id, kind, inputs):
    return tool(id=tool_id, authorization="owner_confirmation", execution={"type": kind}, inputs=inputs)


def strings(*names):
    return [{"name": name, "type": "string", "required": True} for name in names]


@pytest.mark.parametrize(("definition", "words"), [
    (controlled("system.port-control", "port_control", strings("container_id")),
     "Port replacement requires container_id and review_id strings"),
    (controlled("system.container-control", "container_control", strings("container_id")),
     "container_control requires string container_id and action inputs"),
    (controlled("system.process-control", "process_control",
                [*strings("service_id"), {"name": "action", "type": "integer", "required": True}]),
     "process_control requires string service_id and action inputs"),
    (controlled("system.files-list", "filesystem_inventory", strings("path")),
     "filesystem_inventory accepts root_id, path and limit"),
    (controlled("system.files-list", "filesystem_inventory", [{"name": "root_id", "type": "integer"}]),
     "filesystem_inventory input types are invalid"),
    (controlled("system.inventory", "system_inventory", strings("everything")),
     "system_inventory accepts only limit"),
    (controlled("system.inventory", "system_inventory", strings("limit")),
     "system_inventory.limit must be an integer"),
])
def test_host_executors_accept_only_their_fixed_inputs(definition, words):
    assert words in errors_of(definition)


def http(**execution):
    base = {"type": "http_json", "method": "GET", "url": "https://api.example/notes",
            "allowed_hosts": ["api.example"], "result_path": "data"}
    return tool(execution={**base, **execution})


@pytest.mark.parametrize(("definition", "words"), [
    (http(method="PUT"), "http_json supports GET and POST only"),
    (http(url="http://api.example/notes"), "http_json.url must be an absolute HTTPS URL"),
    (http(url=None), "http_json.url must be an absolute HTTPS URL"),
    (http(allowed_hosts=["other.example"]), "the URL host must be present in http_json.allowed_hosts"),
    (http(url="https://api.example/{note_id}"), "URL placeholders need declared inputs: note_id"),
    (http(timeout_seconds=31), "http_json.timeout_seconds must be between 1 and 30"),
    (http(max_response_bytes=10), "http_json.max_response_bytes must be between 1024 and 1048576"),
    (http(secret_headers={"Host": "API_KEY"}), "http_json.secret_headers must map safe header names"),
    (http(secret_headers={"X-Key": "lowercase"}), "http_json.secret_headers must map safe header names"),
    (tool(execution={"type": "memorygate", "operation": "erase", "secret_ref": "MG_KEY"}),
     "memorygate.operation must be context or ask"),
    (tool(inputs=strings("query"), execution={"type": "memorygate", "operation": "context",
                                               "secret_ref": "mg-key"}),
     "memorygate.secret_ref must name a ToolGate vault secret"),
    (tool(execution={"type": "ollama_generate", "prompt_template": "  "}),
     "ollama_generate.prompt_template is required"),
])
def test_outbound_executors_refuse_unsafe_or_incomplete_settings(definition, words):
    assert any(words in error for error in errors_of(definition))


def gemini(**execution):
    base = {"type": "gemini_generate", "prompt_template": "Sum up {text}", "model": next(iter(d.GEMINI_MODELS)),
            "secret_ref": "GEMINI_KEY"}
    return tool(authorization="owner_confirmation", execution={**base, **execution})


@pytest.mark.parametrize(("definition", "words"), [
    (gemini(prompt_template=""), "gemini_generate.prompt_template is required"),
    (gemini(prompt_template="Sum up {missing}"), "prompt placeholders need declared inputs: missing"),
    (gemini(secret_ref="key"), "gemini_generate.secret_ref must name a ToolGate vault secret"),
    (gemini(max_tokens=5000), "gemini_generate.max_tokens must be between 128 and 2048"),
    (gemini(temperature=True), "gemini_generate.temperature must be between 0 and 1"),
    (gemini(temperature=1.5), "gemini_generate.temperature must be between 0 and 1"),
    (gemini(timeout_seconds=1), "gemini_generate.timeout_seconds must be between 5 and 120"),
])
def test_gemini_settings_are_bounded(definition, words):
    assert words in errors_of(definition)


@pytest.mark.parametrize(("execution", "inputs", "words"), [
    ({"type": "research_search", "fixed_source": "nowhere"}, strings("query", "max_results", "recency_days"),
     "research_search.fixed_source is unsupported"),
    ({"type": "research_bundle", "sources": []}, strings("query", "max_per_source", "recency_days"),
     "research_bundle.sources must contain one to seven supported sources"),
    ({"type": "research_bundle", "sources": ["nowhere"]}, strings("query"),
     "research_bundle.sources must contain one to seven supported sources"),
    ({"type": "research_bundle", "sources": "web"}, strings("query"),
     "research_bundle requires declared inputs: max_per_source, recency_days"),
    ({"type": "research_fetch"}, strings("id"), "research_fetch requires a declared 'result_id' input"),
    ({"type": "research_fetch_batch"}, strings("id"),
     "research_fetch_batch requires a declared 'result_ids' input"),
])
def test_research_executors_name_what_they_miss(execution, inputs, words):
    assert words in errors_of(tool(execution=execution, inputs=inputs))


def test_an_external_mcp_tool_needs_its_server_settings_and_one_arguments_object():
    found = errors_of(tool(execution={"type": "mcp_http"}))
    assert "External MCP tools require one object input named arguments" in found
    assert len(found) >= 3  # the server settings and the owner confirmation are refused too


def test_unknown_executors_stop_the_check_early():
    found = errors_of(tool(execution={"type": "shell"}))
    assert len(found) == 1 and found[0].startswith("execution.type must be one of")


@pytest.mark.parametrize(("workflow", "words"), [
    ("steps", "workflow must be a list"),
    ([{"type": "editor_graph"}, {"type": "return", "value": 1}],
     "An editor graph must be the entire workflow definition"),
    ([{"type": "editor_graph"}], "step 1: "),
    ([{"type": "automation_call", "automation_id": "a", "args": "x"}], "step 1 args must be an object"),
    ([{"type": "automation_call", "automation_id": "a", "publication_digest": "abc"}],
     "step 1 publication_digest must be a SHA-256 digest"),
    ([{"type": "tool_call"}], "step 1 needs tool_id"),
    ([{"type": "tool_call", "tool_id": "t", "args": []}], "step 1 args must be an object"),
    ([{"type": "set", "name": "x"}], "step 1 set requires value"),
    ([{"type": "calculation", "operation": "power", "values": [1]}],
     "step 1 has an unsupported calculation operation"),
    ([{"type": "calculation", "values": []}], "step 1 calculation requires values"),
    ([{"type": "condition", "left": 1, "right": 2, "operator": "like"}],
     "step 1 has an unsupported condition operator"),
    ([{"type": "loop", "max_iterations": 3}], "step 1 loop requires items"),
    ([{"type": "retry", "max_attempts": 9, "step": {"type": "return", "value": 1}}],
     "step 1 max_attempts must be between 1 and 3"),
    ([{"type": "switch", "cases": {}}], "step 1 switch requires value"),
    ([{"type": "switch", "value": 1, "cases": {str(i): [] for i in range(11)}}],
     "step 1 cases must be an object with at most 10 branches"),
    ([{"type": "delay", "seconds": 31}], "step 1 delay must be between 0 and 30 seconds"),
    ([{"type": "delay", "seconds": "1"}], "step 1 delay must be between 0 and 30 seconds"),
])
def test_workflow_blocks_are_refused_for_each_broken_rule(workflow, words):
    assert any(words in error for error in d.workflow_definition_errors(workflow))


def test_workflows_cannot_nest_past_four_levels():
    deepest: list = [{"type": "return", "value": 1}]
    for _ in range(6):
        deepest = [{"type": "loop", "max_iterations": 1, "items": [], "steps": deepest}]
    assert "workflow nesting cannot exceed four levels" in d.workflow_definition_errors(deepest)


def test_tool_ids_are_found_in_every_branch_and_junk_is_skipped():
    workflow = ["junk", {"type": "switch", "value": 1, "cases": {"a": [{"type": "tool_call", "tool_id": "one"}]},
                         "default": [{"type": "tool_call", "tool_id": "two"}]},
                {"type": "retry", "step": {"type": "tool_call", "tool_id": "three"}}]
    assert sorted(d.workflow_tool_ids(workflow)) == ["one", "three", "two"]
    assert d.workflow_tool_ids("junk") == []  # type: ignore[arg-type]


@pytest.mark.parametrize("max_steps", [0, 501, "10"])
def test_an_automation_step_budget_is_bounded(max_steps):
    automation = {**tool(), "workflow": [], "policy": {"usage_limits": {"max_steps": max_steps}}}
    assert "policy.usage_limits.max_steps must be between 1 and 500" in d.automation_definition_errors(automation)
