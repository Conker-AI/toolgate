"""Dispatch of one approved tool call to its backend (HTTP, MemoryGate, Ollama, Gemini, research, system executors)."""

import hashlib
import os
import re
from urllib.parse import quote, urlsplit

import httpx
from fastapi import HTTPException

from toolgate.api.deps import deny
from toolgate.core import control_plane, spending, vault
from toolgate.core.public_https import DestinationDenied, public_client, public_url, resolve_public
from toolgate.executors import (
    container_control,
    filesystem_inventory,
    mcp_http,
    process_control,
    research,
    system_inventory,
)


def _public_destination(host: str) -> bool:
    try:
        resolve_public(host)
    except DestinationDenied:
        return False
    return True


def _render_template(value, args: dict):
    if isinstance(value, str):
        rendered = value
        for name in set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", value)):
            if name not in args:
                deny("VALIDATION_ERROR", f"Missing template argument '{name}'", 422)
            rendered = rendered.replace(f"{{{name}}}", str(args[name]))
        return rendered
    if isinstance(value, list):
        return [_render_template(item, args) for item in value]
    if isinstance(value, dict):
        return {key: _render_template(item, args) for key, item in value.items()}
    return value


def _extract_result(value, result_path: str | None):
    if not result_path:
        return value
    for part in result_path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            deny(
                "UPSTREAM_SCHEMA_ERROR",
                "The configured result field was absent from the upstream response",
                502,
            )
    return value


def _execute_http_json(execution: dict, args: dict) -> dict:
    template = execution["url"]
    placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template))
    url = template
    for name in placeholders:
        url = url.replace(f"{{{name}}}", quote(str(args[name]), safe=""))
    parsed = urlsplit(url)
    allowed_hosts = {str(host).lower() for host in execution["allowed_hosts"]}
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname.lower() not in allowed_hosts
    ):
        deny(
            "DESTINATION_DENIED",
            "The rendered destination is outside this tool's exact host allowlist",
        )
    if not public_url(url):
        deny(
            "DESTINATION_DENIED",
            "Public HTTP tools cannot reach private or unresolved network destinations",
        )
    headers = {"Accept": "application/json", "User-Agent": "ToolGate/2.0"}
    for header, secret_ref in execution.get("secret_headers", {}).items():
        try:
            headers[header] = vault.get_key(secret_ref)
        except KeyError:
            deny(
                "SECRET_UNAVAILABLE",
                f"Required vault reference '{secret_ref}' is not configured",
                503,
            )
    timeout = min(float(execution.get("timeout_seconds", 10)), 30)
    max_bytes = min(int(execution.get("max_response_bytes", 262144)), 1048576)
    try:
        with public_client(timeout=timeout, headers=headers) as client:
            response = client.request(
                str(execution.get("method", "GET")).upper(),
                url,
                json=_render_template(execution.get("body"), args)
                if execution.get("body") is not None
                else None,
            )
        if 300 <= response.status_code < 400:
            deny("DESTINATION_DENIED", "The upstream attempted an unapproved redirect", 502)
        if response.status_code >= 400:
            deny("UPSTREAM_ERROR", f"The upstream returned HTTP {response.status_code}", 502)
        if len(response.content) > max_bytes:
            deny("RESPONSE_TOO_LARGE", "The upstream response exceeded this tool's byte limit", 502)
        value = response.json()
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        deny("UPSTREAM_ERROR", f"The public API request failed: {type(exc).__name__}", 502)
    return {"ok": True, "result": _extract_result(value, execution.get("result_path"))}


def _execute_memorygate(execution: dict, args: dict) -> dict:
    operation = execution["operation"]
    base_url = os.environ.get("MEMORYGATE_URL", "http://memorygate-api:8020").rstrip("/")
    try:
        access_key = vault.get_key(execution["secret_ref"])
    except KeyError:
        deny("SECRET_UNAVAILABLE", "MemoryGate read credential is not configured", 503)
    agent_id = str(execution.get("agent_id", "default"))
    headers = {"X-MemoryGate-Key": access_key, "X-Agent-Id": agent_id}
    if operation == "context":
        body = {
            "query": args["query"],
            "max_items": args.get("max_items", 12),
            "include_evidence": args.get("include_evidence", False),
        }
    else:
        body = {
            "question": args["question"],
            "include_evidence": args.get("include_evidence", False),
        }
    try:
        response = httpx.post(
            f"{base_url}/runtime/{operation}", json=body, headers=headers, timeout=45
        )
        response.raise_for_status()
        result = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        deny("MEMORYGATE_UNAVAILABLE", f"MemoryGate {operation} failed: {type(exc).__name__}", 502)
    return {"ok": True, "result": result}


def _execute_ollama(execution: dict, args: dict) -> dict:
    url = (
        control_plane.settings().get("generation_url", "http://memorygate-ollama:11434").rstrip("/")
    )
    prompt = _render_template(execution["prompt_template"], args)
    try:
        response = httpx.post(
            f"{url}/api/generate",
            json={
                "model": execution.get("model")
                or control_plane.settings().get("generation_model", "qwen3:4b"),
                "prompt": prompt,
                "stream": False,
                "think": False,
                "options": {
                    "temperature": float(execution.get("temperature", 0.0)),
                    "num_predict": int(execution.get("max_tokens", 256)),
                    "num_ctx": 4096,
                },
            },
            timeout=180,
        )
        response.raise_for_status()
        text = response.json()["response"]
    except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
        deny("AI_UNAVAILABLE", f"Local AI tool failed: {type(exc).__name__}", 502)
    return {"ok": True, "result": text.strip()}


def _execute_gemini(execution: dict, args: dict) -> dict:
    model = execution["model"]
    if model != spending.MODEL:
        deny("AI_MODEL_DENIED", "This model has no bounded spending adapter", 422)
    prompt = _render_template(execution["prompt_template"], args)
    if not isinstance(prompt, str) or not 1 <= len(prompt) <= 20000:
        deny("VALIDATION_ERROR", "Hosted AI prompt must contain 1-20,000 characters", 422)
    try:
        api_key = vault.get_key(execution["secret_ref"])
    except KeyError:
        deny("SECRET_UNAVAILABLE", "Hosted AI credential is not configured", 503)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": float(execution.get("temperature", 0.0)),
            "maxOutputTokens": int(execution.get("max_tokens", 800)),
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingBudget": 0},
            "candidateCount": 1,
        },
    }
    try:
        response = httpx.post(
            url,
            json=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            timeout=min(float(execution.get("timeout_seconds", 60)), 120),
        )
        response.raise_for_status()
        payload = response.json()
        parts = payload["candidates"][0]["content"]["parts"]
        text = "".join(
            str(part.get("text") or "") for part in parts if isinstance(part, dict)
        ).strip()
        if not text:
            raise ValueError("empty model response")
        usage = payload.get("usageMetadata", {})
    except httpx.HTTPStatusError as exc:
        deny("AI_UNAVAILABLE", f"Hosted AI upstream returned HTTP {exc.response.status_code}", 502)
    except (httpx.HTTPError, KeyError, IndexError, ValueError, TypeError) as exc:
        deny("AI_UNAVAILABLE", f"Hosted AI tool failed: {type(exc).__name__}", 502)
    return {
        "ok": True,
        "result": {
            "text": text,
            "usage": {
                "prompt_tokens": usage.get("promptTokenCount"),
                "completion_tokens": usage.get("candidatesTokenCount"),
                "total_tokens": usage.get("totalTokenCount"),
                "thought_tokens": usage.get("thoughtsTokenCount", 0),
            },
            "model": model,
        },
    }


def _execute_research_search(execution: dict, args: dict) -> dict:
    try:
        result = research.search(
            args["query"],
            execution.get("fixed_source") or args.get("source", "general"),
            args.get("max_results", 8),
            args.get("recency_days", 30),
        )
    except research.ResearchError as exc:
        deny("RESEARCH_UNAVAILABLE", str(exc), 502, "Try another source or a narrower query")
    return {"ok": True, "result": result}


def _execute_research_bundle(execution: dict, args: dict) -> dict:
    try:
        result = research.search_bundle(
            args["query"],
            execution["sources"],
            args.get("max_per_source", 5),
            args.get("recency_days", 90),
        )
    except research.ResearchError as exc:
        deny("RESEARCH_UNAVAILABLE", str(exc), 502, "Try a narrower query or an atomic source tool")
    return {"ok": True, "result": result}


def _execute_research_fetch(args: dict) -> dict:
    try:
        result = research.fetch(args["result_id"], args.get("max_chars", 12000))
    except research.ResearchError as exc:
        deny(
            "RESEARCH_FETCH_DENIED", str(exc), 422, "Run research.search and use a fresh result_id"
        )
    return {"ok": True, "result": result}


def _execute_research_fetch_batch(args: dict) -> dict:
    try:
        result = research.fetch_batch(args["result_ids"], args.get("max_chars", 3500))
    except research.ResearchError as exc:
        deny("RESEARCH_FETCH_DENIED", str(exc), 422, "Run research.search and use fresh result IDs")
    return {"ok": True, "result": result}


def _execute_local_echo(args: dict) -> dict:
    value = str(args.get("value", ""))
    return {
        "ok": True,
        "result": {
            "digest": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "length": len(value),
        },
    }


def _shape_tool_result(tool: dict, result: dict) -> dict:
    if not result.get("ok") or "result" not in result:
        return result
    outputs = [
        item for item in tool.get("outputs", []) if isinstance(item, dict) and item.get("name")
    ]
    value = result["result"]
    for output in outputs:
        if isinstance(value, dict) and output["name"] in value:
            result.setdefault(output["name"], value[output["name"]])
        elif len(outputs) == 1:
            result.setdefault(output["name"], value)
    output_values = {
        item["name"]: result[item["name"]] for item in outputs if item["name"] in result
    }
    output_schema = [{**item, "required": True} for item in outputs]
    errors = control_plane.validate_inputs(output_schema, output_values)
    if errors:
        deny("UPSTREAM_SCHEMA_ERROR", "; ".join(errors), 502)
    return result


def _dispatch_tool(tool: dict, args: dict) -> dict:
    # v2 executes only typed, declared executors. Arbitrary Python is intentionally unsupported.
    executor_type = tool.get("execution", {}).get("type")
    if tool.get("id") == "system.port-control" or executor_type == "port_control":
        return {"ok": False, "error": "Port replacement requires reviewed journal admission."}
    if tool.get("id") == "system.files-list" and tool.get("execution") != {
        "type": "filesystem_inventory"
    }:
        return {
            "ok": False,
            "error": "The reserved directory listing definition is invalid.",
            "error_code": "invalid_files_definition",
        }
    if tool.get("id") == "system.inventory" and tool.get("execution") != {
        "type": "system_inventory"
    }:
        return {
            "ok": False,
            "error": "The reserved system inventory definition is invalid.",
            "error_code": "invalid_inventory_definition",
        }
    if (tool.get("id") == "system.container-control" or executor_type == "container_control") and (
        tool.get("execution") != {"type": "container_control"}
        or tool.get("authorization") != "owner_confirmation"
    ):
        return {
            "ok": False,
            "error": "Managed container control requires its fixed executor and owner confirmation.",
            "error_code": "invalid_container_definition",
        }
    if (tool.get("id") == "system.process-control" or executor_type == "process_control") and (
        tool.get("execution") != {"type": "process_control"}
        or tool.get("authorization") != "owner_confirmation"
    ):
        return {
            "ok": False,
            "error": "Managed service control requires its fixed executor and owner confirmation.",
            "error_code": "invalid_process_definition",
        }
    if executor_type == "echo":
        result = {"ok": True, "result": args}
    elif executor_type == "local_echo":
        result = _execute_local_echo(args)
    elif executor_type == "http_json":
        result = _execute_http_json(tool["execution"], args)
    elif executor_type == "mcp_http":
        result = mcp_http.execute(tool["execution"], args)
    elif executor_type == "memorygate":
        result = _execute_memorygate(tool["execution"], args)
    elif executor_type == "ollama_generate":
        result = _execute_ollama(tool["execution"], args)
    elif executor_type == "gemini_generate":
        result = _execute_gemini(tool["execution"], args)
    elif executor_type == "research_search":
        result = _execute_research_search(tool["execution"], args)
    elif executor_type == "research_bundle":
        result = _execute_research_bundle(tool["execution"], args)
    elif executor_type == "research_fetch":
        result = _execute_research_fetch(args)
    elif executor_type == "research_fetch_batch":
        result = _execute_research_fetch_batch(args)
    elif executor_type == "filesystem_inventory":
        if tool["execution"] != {"type": "filesystem_inventory"} or set(args) - {
            "root_id",
            "path",
            "limit",
        }:
            return {
                "ok": False,
                "error": "Provide root_id, path and bounded limit only.",
                "error_code": "invalid_arguments",
            }
        try:
            result = {
                "ok": True,
                "result": filesystem_inventory.list_directory(
                    args.get("root_id"), args.get("path", ""), args.get("limit", 200)
                ),
            }
        except filesystem_inventory.FileError as exc:
            result = {"ok": False, "error": str(exc), "error_code": exc.code}
    elif executor_type == "process_control":
        if set(args) != {"service_id", "action"}:
            return {
                "ok": False,
                "error": "Provide only service_id and action.",
                "error_code": "invalid_arguments",
            }
        try:
            result = {
                "ok": True,
                "result": process_control.control(args["service_id"], args["action"]),
            }
        except process_control.ControlError as exc:
            result = {"ok": False, "error": str(exc), "error_code": exc.code}
    elif executor_type == "container_control":
        if set(args) != {"container_id", "action"}:
            return {
                "ok": False,
                "error": "Provide only container_id and action.",
                "error_code": "invalid_arguments",
            }
        try:
            result = {
                "ok": True,
                "result": container_control.control(args["container_id"], args["action"]),
            }
        except container_control.ControlError as exc:
            result = {"ok": False, "error": str(exc), "error_code": exc.code}
        # OutcomeUnknown deliberately reaches the execution journal's uncertainty
        # handler. Reusing that action ID can never dispatch the mutation again.
    elif executor_type == "system_inventory":
        if tool["execution"] != {"type": "system_inventory"} or set(args) - {"limit"}:
            deny("VALIDATION_ERROR", "System inventory accepts only a bounded limit.", 422)
        try:
            result = {"ok": True, "result": system_inventory.collect(args.get("limit", 100))}
        except system_inventory.InventoryError as exc:
            # This executor only observes. A refused/failed read is a known
            # failure, not an ambiguous external mutation to reconcile.
            result = {"ok": False, "error": str(exc), "error_code": exc.code}
    else:
        result = {"ok": False, "error": "No restricted executor is configured for this typed tool."}
    result = _shape_tool_result(tool, result)
    return result
