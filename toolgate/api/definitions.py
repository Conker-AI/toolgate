"""Validation of tool and automation definitions before they are stored or published."""

import re
from urllib.parse import urlsplit

from fastapi import HTTPException

from toolgate.api.workflow_definitions import workflow_definition_errors, workflow_tool_ids
from toolgate.core import control_plane, spending
from toolgate.executors import mcp_http, research

SUPPORTED_TOOL_EXECUTORS = {
    "echo",
    "local_echo",
    "http_json",
    "memorygate",
    "ollama_generate",
    "gemini_generate",
    "research_search",
    "research_bundle",
    "research_fetch",
    "research_fetch_batch",
    "system_inventory",
    "filesystem_inventory",
    "container_control",
    "process_control",
    "port_control",
    "mcp_http",
    "sandbox_run",
    "sandbox_install",
    "calendar_ics",
    "mail_imap",
}


AUTHORIZATION_MODES = {"auto", "ai_review", "owner_confirmation", "blocked"}


CAPABILITY_STATUSES = {"draft", "active", "disabled"}


INPUT_TYPES = {"string", "integer", "number", "boolean", "array", "object"}


# Only a model with a bounded spending adapter can run; dispatch refuses any other one.
GEMINI_MODELS = {spending.MODEL}


def input_schema_errors(inputs) -> list[str]:
    if not isinstance(inputs, list):
        return ["inputs must be a list"]
    if len(inputs) > 64:
        return ["inputs cannot contain more than 64 fields"]
    errors, names = [], set()
    for index, field in enumerate(inputs):
        prefix = f"input {index + 1}"
        if not isinstance(field, dict):
            errors.append(f"{prefix} must be an object")
            continue
        name = field.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
            errors.append(f"{prefix} needs a valid identifier name")
        elif name in names:
            errors.append(f"input name '{name}' is duplicated")
        else:
            names.add(name)
        if field.get("type", "string") not in INPUT_TYPES:
            errors.append(f"{prefix} type must be one of: {', '.join(sorted(INPUT_TYPES))}")
        if "required" in field and not isinstance(field["required"], bool):
            errors.append(f"{prefix} required must be true or false")
        minimum, maximum = field.get("minimum"), field.get("maximum")
        if minimum is not None and (
            isinstance(minimum, bool) or not isinstance(minimum, (int, float))
        ):
            errors.append(f"{prefix} minimum must be numeric")
        if maximum is not None and (
            isinstance(maximum, bool) or not isinstance(maximum, (int, float))
        ):
            errors.append(f"{prefix} maximum must be numeric")
        if (
            isinstance(minimum, (int, float))
            and isinstance(maximum, (int, float))
            and minimum > maximum
        ):
            errors.append(f"{prefix} minimum cannot exceed maximum")
        min_length, max_length = field.get("min_length"), field.get("max_length")
        if min_length is not None and (
            not isinstance(min_length, int) or not 0 <= min_length <= 100000
        ):
            errors.append(f"{prefix} min_length must be between 0 and 100000")
        if max_length is not None and (
            not isinstance(max_length, int) or not 0 <= max_length <= 100000
        ):
            errors.append(f"{prefix} max_length must be between 0 and 100000")
        if isinstance(min_length, int) and isinstance(max_length, int) and min_length > max_length:
            errors.append(f"{prefix} min_length cannot exceed max_length")
        pattern = field.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str) or len(pattern) > 500:
                errors.append(f"{prefix} pattern must be text no longer than 500 characters")
            else:
                try:
                    re.compile(pattern)
                except re.error:
                    errors.append(f"{prefix} pattern is not valid regular expression syntax")
        allowed = field.get("allowed_values")
        if allowed is not None and (not isinstance(allowed, list) or len(allowed) > 100):
            errors.append(f"{prefix} allowed_values must be a list with at most 100 values")
    return errors


def capability_metadata_errors(capability: dict) -> list[str]:
    errors = []
    if not isinstance(capability.get("id"), str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]{1,79}", capability["id"]
    ):
        errors.append("id must be 2-80 lowercase letters, numbers, dots, or hyphens")
    if not isinstance(capability.get("name"), str) or not capability["name"].strip():
        errors.append("name is required")
    if not isinstance(capability.get("description"), str) or not capability["description"].strip():
        errors.append("description is required")
    if capability.get("authorization") not in AUTHORIZATION_MODES:
        errors.append(f"authorization must be one of: {', '.join(sorted(AUTHORIZATION_MODES))}")
    if capability.get("status") not in CAPABILITY_STATUSES:
        errors.append(f"status must be one of: {', '.join(sorted(CAPABILITY_STATUSES))}")
    errors.extend(input_schema_errors(capability.get("inputs")))
    return errors


def tool_definition_errors(tool: dict) -> list[str]:
    errors = capability_metadata_errors(tool)
    inputs = tool.get("inputs")
    if not isinstance(inputs, list):
        inputs = []
    input_names = {field.get("name") for field in inputs if isinstance(field, dict)}
    execution = tool.get("execution")
    if tool.get("id") == "system.inventory" and execution != {"type": "system_inventory"}:
        errors.append("system.inventory is reserved for the fixed read-only inventory executor")
    if tool.get("id") == "system.files-list" and execution != {"type": "filesystem_inventory"}:
        errors.append("system.files-list is reserved for configured-root metadata listing")
    if tool.get("id") == "system.container-control" and execution != {"type": "container_control"}:
        errors.append("system.container-control is reserved for managed container lifecycle")
    if tool.get("id") == "system.process-control" and execution != {"type": "process_control"}:
        errors.append("system.process-control is reserved for managed service lifecycle")
    if tool.get("id") == "system.port-control" and execution != {"type": "port_control"}:
        errors.append("system.port-control is reserved for reviewed port replacement")
    for reserved_id, kind in (
        ("sandbox.run", "sandbox_run"),
        ("sandbox.install", "sandbox_install"),
    ):
        uses_kind = isinstance(execution, dict) and execution.get("type") == kind
        if (tool.get("id") == reserved_id or uses_kind) and (
            tool.get("id") != reserved_id or execution != {"type": kind}
        ):
            errors.append(f"{reserved_id} is reserved for the agent sandbox executor {kind}")
    reads_calendar = isinstance(execution, dict) and execution.get("type") == "calendar_ics"
    if (tool.get("id") == "calendar.events" or reads_calendar) and (
        tool.get("id") != "calendar.events" or execution != {"type": "calendar_ics"}
    ):
        errors.append("calendar.events is reserved for the read-only calendar executor")
    reads_mail = isinstance(execution, dict) and execution.get("type") == "mail_imap"
    if (tool.get("id") == "mail.recent" or reads_mail) and (
        tool.get("id") != "mail.recent" or execution != {"type": "mail_imap"}
    ):
        errors.append("mail.recent is reserved for the read-only mail executor")
    if not isinstance(execution, dict) or execution.get("type") not in SUPPORTED_TOOL_EXECUTORS:
        errors.append(
            f"execution.type must be one of: {', '.join(sorted(SUPPORTED_TOOL_EXECUTORS))}"
        )
        return errors
    if execution["type"] == "mcp_http":
        try:
            mcp_http.validate_execution(execution)
        except mcp_http.MCPError as exc:
            errors.append(str(exc))
        if tool.get("authorization") != "owner_confirmation":
            errors.append("External MCP tools require owner_confirmation")
        if (
            input_names != {"arguments"}
            or len(inputs) != 1
            or inputs[0].get("type") != "object"
            or inputs[0].get("required") is not True
        ):
            errors.append("External MCP tools require one object input named arguments")
    elif execution["type"] == "port_control":
        if (
            execution != {"type": "port_control"}
            or tool.get("id") != "system.port-control"
            or tool.get("authorization") != "owner_confirmation"
        ):
            errors.append("Port replacement requires its reserved executor and owner confirmation")
        if input_names != {"container_id", "review_id"} or any(
            field.get("type") != "string" or field.get("required") is not True
            for field in inputs
            if isinstance(field, dict)
        ):
            errors.append("Port replacement requires container_id and review_id strings")
    elif execution["type"] in {"container_control", "process_control"}:
        kind = execution["type"]
        target = "container_id" if kind == "container_control" else "service_id"
        if execution != {"type": kind}:
            errors.append(f"{kind} uses only operator-configured managed targets")
        if tool.get("authorization") != "owner_confirmation":
            errors.append(f"{kind} requires owner_confirmation")
        if input_names != {target, "action"} or any(
            field.get("type") != "string" or field.get("required") is not True
            for field in inputs
            if isinstance(field, dict)
        ):
            errors.append(f"{kind} requires string {target} and action inputs")
    elif execution["type"] == "filesystem_inventory":
        if execution != {"type": "filesystem_inventory"}:
            errors.append("filesystem_inventory uses only operator-configured roots")
        if input_names - {"root_id", "path", "limit"} or "root_id" not in input_names:
            errors.append("filesystem_inventory accepts root_id, path and limit")
        for field in inputs:
            if isinstance(field, dict) and field.get("type") != (
                "integer" if field.get("name") == "limit" else "string"
            ):
                errors.append("filesystem_inventory input types are invalid")
    elif execution["type"] == "system_inventory":
        if execution != {"type": "system_inventory"}:
            errors.append("system_inventory uses only the operator-configured fixed endpoint")
        if input_names - {"limit"}:
            errors.append("system_inventory accepts only limit")
        for field in inputs:
            if (
                isinstance(field, dict)
                and field.get("name") == "limit"
                and field.get("type") != "integer"
            ):
                errors.append("system_inventory.limit must be an integer")
    elif execution["type"] == "http_json":
        method = str(execution.get("method", "")).upper()
        if method not in {"GET", "POST"}:
            errors.append("http_json supports GET and POST only")
        if method == "POST" and tool.get("authorization") != "owner_confirmation":
            errors.append("http_json POST tools require owner_confirmation")
        template = execution.get("url")
        parsed = urlsplit(template) if isinstance(template, str) else None
        if not parsed or parsed.scheme != "https" or not parsed.hostname:
            errors.append("http_json.url must be an absolute HTTPS URL")
        allowed_hosts = execution.get("allowed_hosts")
        if not isinstance(allowed_hosts, list) or not allowed_hosts:
            errors.append("http_json.allowed_hosts must contain at least one exact host")
        elif (
            parsed
            and parsed.hostname
            and parsed.hostname.lower() not in {str(host).lower() for host in allowed_hosts}
        ):
            errors.append("the URL host must be present in http_json.allowed_hosts")
        placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template or ""))
        missing = placeholders - input_names
        if missing:
            errors.append(f"URL placeholders need declared inputs: {', '.join(sorted(missing))}")
        if (
            not isinstance(execution.get("result_path"), str)
            or not execution["result_path"].strip()
        ):
            errors.append("http_json.result_path is required")
        timeout = execution.get("timeout_seconds", 10)
        if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 30:
            errors.append("http_json.timeout_seconds must be between 1 and 30")
        max_bytes = execution.get("max_response_bytes", 262144)
        if not isinstance(max_bytes, int) or not 1024 <= max_bytes <= 1048576:
            errors.append("http_json.max_response_bytes must be between 1024 and 1048576")
        secret_headers = execution.get("secret_headers", {})
        forbidden_headers = {
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "proxy-authorization",
            "proxy-authenticate",
            "upgrade",
        }
        if not isinstance(secret_headers, dict) or any(
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", name)
            or name.lower() in forbidden_headers
            or not isinstance(ref, str)
            or not re.fullmatch(r"[A-Z][A-Z0-9_]*", ref)
            for name, ref in secret_headers.items()
        ):
            errors.append("http_json.secret_headers must map safe header names to vault references")
    elif execution["type"] == "memorygate":
        operation = execution.get("operation")
        if operation not in {"context", "ask"}:
            errors.append("memorygate.operation must be context or ask")
        required_input = "query" if operation == "context" else "question"
        if operation in {"context", "ask"} and required_input not in input_names:
            errors.append(f"memorygate.{operation} requires a declared '{required_input}' input")
        if not isinstance(execution.get("secret_ref"), str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_]*", execution.get("secret_ref", "")
        ):
            errors.append("memorygate.secret_ref must name a ToolGate vault secret")
    elif execution["type"] == "ollama_generate":
        prompt_template = execution.get("prompt_template")
        if not isinstance(prompt_template, str) or not prompt_template.strip():
            errors.append("ollama_generate.prompt_template is required")
        else:
            placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", prompt_template))
            missing = placeholders - input_names
            if missing:
                errors.append(
                    f"prompt placeholders need declared inputs: {', '.join(sorted(missing))}"
                )
        max_tokens = execution.get("max_tokens", 256)
        if not isinstance(max_tokens, int) or not 8 <= max_tokens <= 1024:
            errors.append("ollama_generate.max_tokens must be between 8 and 1024")
        temperature = execution.get("temperature", 0.0)
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or not 0 <= temperature <= 2
        ):
            errors.append("ollama_generate.temperature must be between 0 and 2")
    elif execution["type"] == "gemini_generate":
        prompt_template = execution.get("prompt_template")
        if not isinstance(prompt_template, str) or not prompt_template.strip():
            errors.append("gemini_generate.prompt_template is required")
        else:
            placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", prompt_template))
            missing = placeholders - input_names
            if missing:
                errors.append(
                    f"prompt placeholders need declared inputs: {', '.join(sorted(missing))}"
                )
        if execution.get("model") not in GEMINI_MODELS:
            errors.append(
                f"gemini_generate.model must be one of: {', '.join(sorted(GEMINI_MODELS))}"
            )
        if not isinstance(execution.get("secret_ref"), str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_]*", execution.get("secret_ref", "")
        ):
            errors.append("gemini_generate.secret_ref must name a ToolGate vault secret")
        max_tokens = execution.get("max_tokens", 800)
        if not isinstance(max_tokens, int) or not 128 <= max_tokens <= 2048:
            errors.append("gemini_generate.max_tokens must be between 128 and 2048")
        temperature = execution.get("temperature", 0.0)
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or not 0 <= temperature <= 1
        ):
            errors.append("gemini_generate.temperature must be between 0 and 1")
        timeout = execution.get("timeout_seconds", 60)
        if not isinstance(timeout, (int, float)) or not 5 <= timeout <= 120:
            errors.append("gemini_generate.timeout_seconds must be between 5 and 120")
    elif execution["type"] == "research_search":
        fixed_source = execution.get("fixed_source")
        if fixed_source is not None and fixed_source not in research.SOURCE_DOMAINS:
            errors.append("research_search.fixed_source is unsupported")
        required = {"query", "max_results", "recency_days"}
        if fixed_source is None:
            required.add("source")
        missing = required - input_names
        if missing:
            errors.append(f"research_search requires declared inputs: {', '.join(sorted(missing))}")
    elif execution["type"] == "research_bundle":
        sources = execution.get("sources")
        if (
            not isinstance(sources, list)
            or not sources
            or len(sources) > 7
            or any(source not in research.SOURCE_DOMAINS for source in sources)
        ):
            errors.append("research_bundle.sources must contain one to seven supported sources")
        required = {"query", "max_per_source", "recency_days"}
        missing = required - input_names
        if missing:
            errors.append(f"research_bundle requires declared inputs: {', '.join(sorted(missing))}")
    elif execution["type"] == "research_fetch":
        if "result_id" not in input_names:
            errors.append("research_fetch requires a declared 'result_id' input")
    elif execution["type"] == "research_fetch_batch":
        if "result_ids" not in input_names:
            errors.append("research_fetch_batch requires a declared 'result_ids' input")
    return errors


def require_valid_tool_definition(tool: dict):
    errors = tool_definition_errors(tool)
    if errors:
        raise HTTPException(
            422,
            {
                "code": "INVALID_TOOL_DEFINITION",
                "message": "; ".join(errors),
                "next_action": "Complete the tool Workflow definition before saving or approving it",
            },
        )


def automation_definition_errors(automation: dict) -> list[str]:
    errors = capability_metadata_errors(automation)
    workflow_errors = workflow_definition_errors(automation.get("workflow", []))
    errors.extend(workflow_errors)
    if workflow_errors:
        return errors
    for tool_id in dict.fromkeys(workflow_tool_ids(automation.get("workflow", []))):
        tool = control_plane.get("tool", tool_id)
        if not tool or tool.get("status") != "active":
            errors.append(f"workflow references unavailable tool '{tool_id}'")
        elif automation.get("authorization") == "auto" and tool.get("authorization") != "auto":
            errors.append(
                f"auto automation cannot call '{tool_id}' because it requires {tool.get('authorization')}"
            )
    max_steps = automation.get("policy", {}).get("usage_limits", {}).get("max_steps", 100)
    if not isinstance(max_steps, int) or not 1 <= max_steps <= 500:
        errors.append("policy.usage_limits.max_steps must be between 1 and 500")
    runtime = automation.get("policy", {}).get("usage_limits", {}).get("max_runtime_seconds", 30)
    if isinstance(runtime, bool) or not isinstance(runtime, int) or not 1 <= runtime <= 120:
        errors.append("policy.usage_limits.max_runtime_seconds must be between 1 and 120")
    return errors


def require_valid_automation_definition(automation: dict):
    errors = automation_definition_errors(automation)
    if errors:
        raise HTTPException(
            422,
            {
                "code": "INVALID_AUTOMATION_DEFINITION",
                "message": "; ".join(errors),
                "next_action": "Correct the typed workflow before saving",
            },
        )
