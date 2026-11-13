#!/usr/bin/env python3
"""Destructive-safe end-to-end verification for a running local ToolGate v2 stack.

The script creates namespaced temporary capabilities and keys, validates the
security boundary, and removes those temporary objects before exiting. It never
prints or sends vault values except to their intended signed callback verifier.

It reads vault values through ``toolgate.core.vault`` rather than parsing
``.env``, because stored values are ciphertext. That means it has to run
somewhere the vault key is reachable -- inside the API container
(``docker compose exec api python toolgate/scripts/verify_v2.py``) or on a host
with ``TOOLGATE_VAULT_SECRET`` set.

It also needs objects the owner's install provides and the script does not create: the tools
``memorygate-context`` and ``github-repos-count`` (billing mode free) and a verification method
named "Home approval adapter". A run without them stops before it creates anything and names
what is missing.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import uuid
from pathlib import Path
from typing import cast

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from toolgate.core import vault  # noqa: E402

API = "http://127.0.0.1:8010"
TOOL_ID = "verify-owner-confirmation"
AI_TOOL_ID = "verify-local-ai"
AUTOMATION_ID = "verify-workflow"
INVALID_POST_ID = "verify-invalid-post"
REQUIRED_TOOLS = ("memorygate-context", "github-repos-count")
APPROVAL_METHOD = "Home approval adapter"
TEMPORARY_PATHS = (f"/v2/tools/{TOOL_ID}", f"/v2/tools/{AI_TOOL_ID}",
                   f"/v2/tools/{INVALID_POST_ID}", f"/v2/automations/{AUTOMATION_ID}")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    run_id = "verify-" + uuid.uuid4().hex
    agent_env = dotenv_values(Path.home() / ".config" / "toolgate" / "credentials.env")
    owner_key = vault.get_control_key("TOOLGATE_ADMIN_KEY")
    execution_key = agent_env.get("TOOLGATE_EXECUTION_KEY")
    try:
        # Decrypted through the vault: the stored form is ciphertext, and the
        # leak assertion below has to compare against the real value.
        callback_secret = vault.get_key("TOOLGATE_CALLBACK_SECRET")
        memory_secret = vault.get_key("MEMORYGATE_READ_KEY")
    except KeyError as exc:
        raise AssertionError(f"required local credentials are missing or unreadable: {exc}") from exc
    check(bool(owner_key and execution_key and callback_secret and memory_secret), "required local credentials are missing")

    # check() above raised unless both keys are non-empty strings.
    owner = {"X-ToolGate-Key": cast(str, owner_key)}
    agent = {"X-ToolGate-Execution-Key": cast(str, execution_key)}
    temporary_key_ids: list[str] = []
    pending_request_ids: list[str] = []
    client = httpx.Client(base_url=API, timeout=190)

    def admin(method: str, path: str, **kwargs) -> httpx.Response:
        return client.request(method, path, headers=owner, **kwargs)

    def execute(method: str, path: str, **kwargs) -> httpx.Response:
        return client.request(method, path, headers=agent, **kwargs)

    def delete_if_present(path: str) -> None:
        response = admin("DELETE", path)
        check(response.status_code in {200, 404}, f"cleanup failed for {path}: {response.status_code}")

    # The owner's lockdown is an emergency stop: never run over it, and lift only the one this
    # run sets itself.
    status = admin("GET", "/v2/status")
    if status.status_code != 200 or status.json().get("lockdown") is not False:
        client.close()
        raise AssertionError("ToolGate is in lockdown (or its status is unreadable); lift it yourself first")
    lockdown_set = False
    try:
        missing = [f"tool {tool_id}" for tool_id in REQUIRED_TOOLS
                   if admin("GET", f"/v2/tools/{tool_id}").status_code != 200]
        listed = admin("GET", "/v2/verification-methods")
        methods = listed.json() if listed.status_code == 200 else []
        method = next((item for item in methods if item.get("name") == APPROVAL_METHOD), None)
        if method is None:
            missing.append(f'verification method "{APPROVAL_METHOD}"')
        check(not missing, "this install lacks what the verifier needs: " + ", ".join(missing))
        method = cast(dict, method)  # check() above raised unless it was found
        for path in TEMPORARY_PATHS:
            delete_if_present(path)

        tool = {
            "id": TOOL_ID, "name": "Verification echo", "description": "Temporary exact-approval verifier.",
            "category": "controlled", "inputs": [{"name": "value", "type": "string", "required": True}],
            "outputs": [{"name": "value", "type": "string"}], "execution": {"type": "echo"},
            "policy": {"usage_limits": {"max_per_minute": 30, "max_runtime_seconds": 5}},
            "authorization": "owner_confirmation", "status": "active", "version": 1,
        }
        response = admin("POST", "/v2/tools", json=tool)
        check(response.status_code == 200, f"could not create verification tool: {response.text}")

        ai_tool = {
            "id": AI_TOOL_ID, "name": "Local AI verification", "description": "Temporary isolated Ollama verifier.",
            "category": "controlled", "inputs": [{"name": "prompt", "type": "string", "required": True, "max_length": 80}],
            "outputs": [{"name": "text", "type": "string"}],
            "execution": {"type": "ollama_generate", "prompt_template": "Reply briefly to: {prompt}",
                          "model": "qwen3:4b", "temperature": 0, "max_tokens": 32},
            "policy": {"usage_limits": {"max_per_minute": 5, "max_runtime_seconds": 120}},
            "authorization": "auto", "status": "active", "version": 1,
        }
        response = admin("POST", "/v2/tools", json=ai_tool)
        check(response.status_code == 200, f"could not create local AI verifier: {response.text}")

        workflow = [
            {"type": "set", "name": "base", "value": "$args.base"},
            {"type": "calculation", "operation": "add", "values": ["$vars.base", 2], "save_as": "total"},
            {"type": "condition", "left": "$vars.total", "operator": "gte", "right": 5,
             "then": [{"type": "set", "name": "large", "value": True}],
             "else": [{"type": "set", "name": "large", "value": False}]},
            {"type": "loop", "items": "$args.items", "item_name": "item", "max_iterations": 3,
             "steps": [{"type": "set", "name": "last_item", "value": "$vars.item"}]},
            {"type": "switch", "value": "$args.mode",
             "cases": {"fast": [{"type": "set", "name": "speed", "value": 2}]},
             "default": [{"type": "set", "name": "speed", "value": 1}]},
            {"type": "return", "value": {"total": "$vars.total", "large": "$vars.large",
                                             "last": "$vars.last_item", "speed": "$vars.speed"}},
        ]
        automation = {
            "id": AUTOMATION_ID, "name": "Workflow verification", "description": "Temporary deterministic workflow verifier.",
            "inputs": [{"name": "base", "type": "integer", "required": True},
                       {"name": "items", "type": "array", "required": True},
                       {"name": "mode", "type": "string", "required": True}],
            "workflow": workflow, "policy": {"usage_limits": {"max_steps": 50, "max_runtime_seconds": 10}},
            "authorization": "auto", "version": 1, "status": "active", "schedule": None,
        }
        response = admin("POST", "/v2/automations", json=automation)
        check(response.status_code == 200, f"could not create workflow verifier: {response.text}")

        invalid_post = {
            "id": INVALID_POST_ID, "name": "Invalid POST", "inputs": [], "outputs": [],
            "execution": {"type": "http_json", "method": "POST", "url": "https://api.github.com/user",
                          "allowed_hosts": ["api.github.com"], "result_path": "id"},
            "authorization": "auto", "status": "active",
        }
        response = admin("POST", "/v2/tools", json=invalid_post)
        check(response.status_code == 422, "unsafe POST definition was accepted without owner confirmation")

        response = execute("POST", "/v2/tools/memorygate-context/invoke",
                           json={"action_id": run_id + "-memory", "args": {"query": "ToolGate integration health", "max_items": 3, "include_evidence": False}})
        check(response.status_code == 200 and response.json().get("code") == "OK", "MemoryGate context failed through ToolGate")
        configured_http = admin("GET", "/v2/tools/github-repos-count").json()
        check(configured_http.get("execution", {}).get("billing") == {"mode": "free"},
              "Owner action required: review github-repos-count and declare execution.billing as mode=free before verification")
        response = execute("POST", "/v2/tools/github-repos-count/invoke",
                           json={"action_id": run_id + "-github", "args": {"username": "alexeybe1kin"}})
        check(response.status_code == 200 and isinstance(response.json()["result"]["result"], int), "public HTTPS executor failed")
        response = execute("POST", f"/v2/tools/{AI_TOOL_ID}/invoke", json={"action_id": run_id + "-ollama", "args": {"prompt": "say ToolGate is ready"}})
        check(response.status_code == 200 and response.json()["result"]["result"].strip(), "isolated Ollama executor failed")

        run_args = {"base": 3, "items": ["a", "b"], "mode": "fast"}
        response = execute("POST", f"/v2/automations/{AUTOMATION_ID}/run", json={"action_id": run_id + "-workflow", "args": run_args})
        check(response.status_code == 200, f"automation failed: {response.text}")
        check(response.json()["result"]["result"] == {"total": 5, "large": True, "last": "b", "speed": 2},
              "automation returned an unexpected result")

        for name, scopes in (("Tool-only verification", ["tool:*"]), ("Automation-only verification", ["automation:*"])):
            issued = admin("POST", "/v2/agent-keys", json={"name": name, "scopes": scopes})
            check(issued.status_code == 200, "temporary scoped key could not be created")
            record = issued.json()["record"]
            temporary_key_ids.append(record["id"])
            scoped = {"X-ToolGate-Execution-Key": issued.json()["key"]}
            tools = client.get("/v2/agent/tools", headers=scoped).json()
            automations = client.get("/v2/agent/automations", headers=scoped).json()
            if scopes == ["tool:*"]:
                check(any(item["id"] == TOOL_ID for item in tools) and not automations, "tool scope crossed into automations")
            else:
                check(any(item["id"] == AUTOMATION_ID for item in automations) and not tools, "automation scope crossed into tools")

        first_args = {"value": "approved-exactly-once"}
        response = execute("POST", f"/v2/tools/{TOOL_ID}/invoke", json={"args": first_args})
        check(response.status_code == 200 and response.json()["code"] == "CONFIRMATION_REQUIRED", "confirmation was not requested")
        request_id = response.json()["request_id"]
        pending_request_ids.append(request_id)
        request = next(item for item in admin("GET", "/v2/requests").json() if item["id"] == request_id)
        callback = {"method_id": method["id"], "request_id": request_id, "decision": "approved",
                    "nonce": request["payload"]["binding"]["nonce"]}
        timestamp = str(int(time.time()))
        canonical = json.dumps(callback, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        signature = hmac.new(callback_secret.encode(), f"{timestamp}.{canonical}".encode(), hashlib.sha256).hexdigest()
        response = client.post("/v2/verification/callback", json=callback,
                               headers={"X-ToolGate-Timestamp": timestamp, "X-ToolGate-Signature": f"sha256={signature}"})
        check(response.status_code == 200 and response.json()["status"] == "approved", "signed callback approval failed")

        response = execute("POST", f"/v2/tools/{TOOL_ID}/invoke",
                           json={"args": first_args, "approval_request_id": request_id})
        check(response.status_code == 200 and response.json()["code"] == "OK", "approved exact action did not execute")
        response = execute("POST", f"/v2/tools/{TOOL_ID}/invoke",
                           json={"args": first_args, "approval_request_id": request_id})
        check(response.status_code == 409 and response.json()["detail"]["code"] == "APPROVAL_INVALID", "approval replay was accepted")
        response = client.post("/v2/verification/callback", json=callback,
                               headers={"X-ToolGate-Timestamp": timestamp, "X-ToolGate-Signature": f"sha256={signature}"})
        check(response.status_code == 409, "callback replay was accepted")

        second_args = {"value": "bound-value"}
        response = execute("POST", f"/v2/tools/{TOOL_ID}/invoke", json={"args": second_args})
        second_id = response.json()["request_id"]
        pending_request_ids.append(second_id)
        response = admin("POST", f"/v2/requests/{second_id}/decision", json={"status": "approved", "note": "verification"})
        check(response.status_code == 200, "dashboard approval failed")
        response = execute("POST", f"/v2/tools/{TOOL_ID}/invoke",
                           json={"args": {"value": "changed-value"}, "approval_request_id": second_id})
        check(response.status_code == 409, "approval accepted changed arguments")
        response = execute("POST", f"/v2/tools/{TOOL_ID}/invoke",
                           json={"args": second_args, "approval_request_id": second_id})
        check(response.status_code == 200, "argument mismatch incorrectly consumed the approval")

        response = client.post("/v2/verification/callback", json=callback,
                               headers={"X-ToolGate-Timestamp": str(int(time.time())), "X-ToolGate-Signature": "sha256=invalid"})
        check(response.status_code == 401, "invalid callback signature was accepted")

        check(admin("POST", "/vault/secrets/MEMORYGATE_READ_KEY/reveal").status_code == 404,
              "vault reveal endpoint is still reachable")
        check(client.get("/v2/services", headers=agent).status_code == 401, "agent key reached an admin endpoint")
        check(client.post(f"/v2/tools/{TOOL_ID}/invoke", json={"args": first_args}).status_code == 401,
              "unauthenticated execution was accepted")

        exposed = json.dumps({"events": admin("GET", "/v2/events?limit=500").json(),
                              "tools": execute("GET", "/v2/agent/tools").json(),
                              "services": admin("GET", "/v2/services").json()})
        check(memory_secret not in exposed and callback_secret not in exposed, "a vault value leaked into an API response or event")

        lockdown_set = True
        response = admin("POST", "/v2/settings/lockdown?enabled=true&reason=end-to-end-verification")
        check(response.status_code == 200 and response.json()["lockdown"], "lockdown did not activate")
        check(execute("POST", "/v2/tools/github-repos-count/invoke", json={"args": {"username": "alexeybe1kin"}}).status_code == 423,
              "tool executed during lockdown")
        check(execute("POST", "/v2/requests", json={"kind": "info", "title": "blocked", "details": "blocked"}).status_code == 423,
              "agent request was accepted during lockdown")
        check(client.post("/v2/verification/callback", json=callback).status_code == 423,
              "verification callback was accepted during lockdown")
        response = admin("POST", "/v2/settings/lockdown?enabled=false&reason=end-to-end-verification-complete")
        check(response.status_code == 200 and not response.json()["lockdown"], "lockdown did not clear")
        lockdown_set = False

        print("ToolGate v2 live verification passed: executors, workflows, scopes, approvals, callbacks, redaction, and lockdown.")
    finally:
        try:
            if lockdown_set:
                admin("POST", "/v2/settings/lockdown?enabled=false&reason=verification-cleanup")
            for request_id in pending_request_ids:
                request = next((item for item in admin("GET", "/v2/requests").json() if item["id"] == request_id), None)
                if request and request.get("status") == "pending":
                    admin("POST", f"/v2/requests/{request_id}/decision", json={"status": "dismissed", "note": "verification cleanup"})
            for key_id in temporary_key_ids:
                admin("DELETE", f"/v2/agent-keys/{key_id}")
            for path in TEMPORARY_PATHS:
                delete_if_present(path)
        finally:
            client.close()


if __name__ == "__main__":
    main()
