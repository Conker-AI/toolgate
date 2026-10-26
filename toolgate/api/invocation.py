"""One tool invocation: authority and scope checks, usage limits, approval binding, spending preflight, journaled dispatch."""

import json
import uuid
from datetime import UTC, datetime

from toolgate.api.deps import deny
from toolgate.api.dispatch import _dispatch_tool, _render_template, _shape_tool_result
from toolgate.core import (
    access_policy,
    approvals,
    container_admission,
    control_plane,
    identities,
    port_reviews,
    publications,
    spending,
)
from toolgate.core import execution_journal as journal
from toolgate.executors import container_control, mcp_http, port_control, sandbox


def enforce_usage_limits(subject_type: str, subject: dict, event_type: str):
    limits = subject.get("policy", {}).get("usage_limits", {})
    per_minute = limits.get("max_per_minute")
    if per_minute is not None and control_plane.event_count_since(
        event_type, subject_type, subject["id"], 60
    ) >= int(per_minute):
        deny(
            "RATE_LIMITED",
            f"{subject['name']} reached its per-minute limit",
            429,
            "Wait before retrying",
        )
    per_hour = limits.get("max_per_hour")
    if per_hour is not None and control_plane.event_count_since(
        event_type, subject_type, subject["id"], 3600
    ) >= int(per_hour):
        deny(
            "RATE_LIMITED",
            f"{subject['name']} reached its hourly limit",
            429,
            "Wait before retrying",
        )
    cooldown = limits.get("cooldown_seconds")
    if cooldown:
        latest = control_plane.latest_event_at(event_type, subject_type, subject["id"])
        if latest and (datetime.now(UTC) - latest).total_seconds() < int(cooldown):
            deny("RATE_LIMITED", f"{subject['name']} is in cooldown", 429, "Wait before retrying")


def enforce_dispatch_usage_limits(conn, subject_type: str, subject: dict, event_type: str) -> None:
    try:
        journal.enforce_usage_limits(
            conn,
            subject_type,
            subject["id"],
            event_type,
            subject.get("policy", {}).get("usage_limits", {}),
        )
    except journal.UsageLimitExceeded as exc:
        reason = {
            "minute": "reached its per-minute limit",
            "hour": "reached its hourly limit",
            "cooldown": "is in cooldown",
        }[exc.limit]
        deny("RATE_LIMITED", f"{subject['name']} {reason}", 429, "Wait before retrying")


def require_current_dispatch_authority(
    conn, actor_id: str | None, capability: str | tuple[str, ...] | None
) -> None:
    """Called inside the journal writer transaction, before consuming or dispatching."""
    settings = conn.execute(
        "SELECT * FROM v2_objects WHERE kind='settings' AND id='control-plane'"
    ).fetchone()
    if settings and control_plane._row(settings).get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    if capability is not None:
        # The actor as it stands now: its key, and the agent identity it acted as.
        actor = identities.for_actor(conn, actor_id)
        if actor is None:
            deny("AGENT_REVOKED", "The originating agent key is no longer active", 403)
        required = (capability,) if isinstance(capability, str) else capability
        if not all(control_plane.is_scoped(actor, scope) for scope in required):
            deny("POLICY_DENIED", "The originating agent no longer has the required scope", 403)


def invoke_tool(
    tool: dict,
    args: dict,
    actor: str,
    *,
    approval_request_id: str | None = None,
    approval_granted: bool = False,
    actor_id: str | None = None,
    action_id: str | None = None,
    job_id: str | None = None,
    parent_action_id: str | None = None,
    publication: dict | None = None,
    authority_scope: str | tuple[str, ...] | None = None,
    decision: access_policy.Decision | None = None,
) -> dict:
    identity = actor_id or actor
    publication_digest = publication["digest"] if publication else None
    if action_id:
        try:
            previous = journal.existing(
                action_id,
                "tool",
                tool["id"],
                args,
                identity,
                job_id,
                parent_action_id,
                publication_digest=publication_digest,
            )
        except (journal.ExecutionConflict, ValueError) as exc:
            deny("ACTION_CONFLICT", str(exc), 409)
        if previous:
            return journal.response(previous)
    if control_plane.settings().get("lockdown"):
        control_plane.event(
            "execution_blocked", "critical", "tool", tool["id"], actor, {"code": "LOCKED_DOWN"}
        )
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423, "Ask the owner to unlock ToolGate")
    errors = control_plane.validate_inputs(tool.get("inputs", []), args)
    if tool.get("execution", {}).get("type") == "mcp_http":
        # MCP schemas stay exact; the legacy flat input validator is insufficient.
        try:
            mcp_http.validate_execution(tool["execution"])
            if set(args) != {"arguments"}:
                raise mcp_http.MCPError("invalid_arguments", "Provide only the arguments object.")
            mcp_http.validate_arguments(tool["execution"]["input_schema"], args["arguments"])
        except mcp_http.MCPError as exc:
            errors.append(str(exc))
        if tool.get("authorization") != "owner_confirmation":
            deny("POLICY_DENIED", "External MCP tools require owner confirmation", 403)
    sandboxed = tool.get("execution", {}).get("type") in sandbox.EXECUTIONS
    if sandboxed:
        kind = tool["execution"]["type"]
        if tool.get("id") != sandbox.EXECUTIONS[kind] or tool["execution"] != {"type": kind}:
            deny("POLICY_DENIED", "Sandbox tools run only from their reserved definitions", 403)
        # Before any approval is asked for: the guard refuses sandbox-breaking commands here.
        errors.extend(sandbox.check(tool, args))
    if errors:
        control_plane.event(
            "validation_failed", "warning", "tool", tool["id"], actor, {"errors": errors}
        )
        deny("VALIDATION_ERROR", "; ".join(errors), 422, "Run `toolgate tool <name> info`")
    authorization = access_policy.resolve(
        tool, tool.get("authorization", "auto"), decision, {"id": identity}
    )
    if decision is not None and authorization != tool.get("authorization", "auto"):
        # Who decided, so the owner can see every action that ran (or asked) by his policy.
        control_plane.event(
            "action_decided",
            "info",
            "tool",
            tool["id"],
            actor,
            {
                "outcome": decision.outcome,
                "decided_by": decision.decided_by,
                "reason": decision.reason,
                "action_id": action_id,
            },
        )
    is_port = (
        tool.get("id") == "system.port-control"
        or tool.get("execution", {}).get("type") == "port_control"
    )
    port_review = None
    if is_port:
        if (
            tool.get("id") != "system.port-control"
            or tool.get("execution") != {"type": "port_control"}
            or authorization != "owner_confirmation"
            or approval_granted
            or set(args) != {"container_id", "review_id"}
        ):
            deny(
                "POLICY_DENIED",
                "Port replacement requires its exact review and direct owner confirmation",
                403,
            )
        try:
            port_review = port_reviews.get(args["review_id"], identity)
        except port_reviews.ReviewError:
            deny("REVIEW_INVALID", "Create a current port-change review first", 409)
        if (
            port_review["expired"]
            or port_review["consumed"]
            or port_review["preview"]["containerId"] != args["container_id"]
        ):
            deny("REVIEW_INVALID", "Create a current port-change review for this container", 409)
    if authorization == "blocked":
        control_plane.event(
            "execution_blocked", "warning", "tool", tool["id"], actor, {"code": "POLICY_DENIED"}
        )
        deny("POLICY_DENIED", "This tool is permanently blocked by its owner policy")
    needs_owner = authorization in {"owner_confirmation", "ai_review"} and not approval_granted
    if needs_owner and not approval_request_id:
        expiry = int(control_plane.settings().get("default_confirmation_expiry_seconds", 60))
        request = approvals.create_verification_request(
            f"Run {tool['name']}",
            (
                "Replace the container using this exact inspected port change: "
                + json.dumps(port_review["preview"])
            )
            if is_port
            else "Owner confirmation is required for this exact immutable tool invocation.",
            actor,
            "tool",
            tool["id"],
            args,
            tool.get("version"),
            expiry,
            actor_id,
            publication_digest=publication_digest,
        )
        return {
            "code": "CONFIRMATION_REQUIRED",
            "message": "This exact action is queued for owner review.",
            "request_id": request["id"],
            "expires_at": request["payload"]["binding"]["expires_at"],
            "next_action": f"After approval, retry with --approval-request-id {request['id']}",
        }
    if not action_id:
        if tool.get("execution", {}).get("type") not in {"echo", "local_echo"}:
            deny(
                "ACTION_ID_REQUIRED",
                "Supply a stable action_id before dispatch; reuse it when checking or retrying",
                422,
            )
        action_id = "local_" + uuid.uuid4().hex

    try:
        price = _spending_preflight(tool, args)
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 403)

    def authorize(conn):
        require_current_dispatch_authority(conn, actor_id, authority_scope)
        if publication:
            publications.for_execution(
                conn, publication["kind"], publication["id"], publication["version"]
            )
        enforce_dispatch_usage_limits(conn, "tool", tool, "tool_executed")
        if authorization in {"owner_confirmation", "ai_review"} and not approval_granted:
            approved, reason = approvals.consume_verification_in_transaction(
                conn,
                approval_request_id,
                "tool",
                tool["id"],
                args,
                tool.get("version"),
                actor,
                actor_id,
                publication_digest=publication_digest,
            )
            if not approved:
                deny(
                    "APPROVAL_INVALID",
                    reason,
                    409,
                    "Request a new confirmation for this exact action",
                )

    def reserve(conn):
        if price:
            spending.reserve(conn, action_id, job_id, identity, parent_action_id, price)
        if is_port or tool.get("execution", {}).get("type") == "container_control":
            container_admission.reserve(conn, action_id, args.get("container_id"))
        if is_port:
            port_reviews.consume_in_transaction(conn, args["review_id"], identity, action_id)

    try:
        record, dispatch = journal.begin(
            action_id,
            "tool",
            tool["id"],
            args,
            identity,
            tool.get("version"),
            job_id=job_id,
            parent_action_id=parent_action_id,
            authorize=authorize,
            publication_digest=publication_digest,
            reserve=reserve,
        )
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 403)
    except (journal.ExecutionConflict, ValueError) as exc:
        deny("ACTION_CONFLICT", str(exc), 409)
    if not dispatch:
        return journal.response(record)
    try:
        if is_port:

            def step_authority(conn):
                require_current_dispatch_authority(conn, actor_id, authority_scope)
                if publication:
                    publications.for_execution(
                        conn, publication["kind"], publication["id"], publication["version"]
                    )
                row = conn.execute(
                    "SELECT body FROM v2_objects WHERE kind='tool' AND id='system.port-control'"
                ).fetchone()
                current = json.loads(row["body"]) if row else {}
                if (
                    current.get("status") != "active"
                    or current.get("authorization") != "owner_confirmation"
                    or current.get("execution") != {"type": "port_control"}
                ):
                    deny("POLICY_DENIED", "Port replacement policy changed", 403)

            try:
                result = {
                    "ok": True,
                    "result": port_control.execute(action_id, authorize=step_authority),
                }
            except container_control.ControlError as exc:
                result = {"ok": False, "error": str(exc), "error_code": exc.code}
        elif sandboxed:
            # The workspace follows the caller's identity, never an argument.
            agent = identities.workspace_for(actor_id)
            if agent is None:
                result = {"ok": False, "error": "The agent key is no longer active.",
                          "error_code": "agent_revoked"}
            else:
                result = _shape_tool_result(tool, sandbox.execute(tool, args, agent, action_id))
        else:
            result = _dispatch_tool(tool, args)
    except Exception:
        journal.unknown(action_id)
        return journal.response(journal.get(action_id))
    envelope = {
        "code": "OK" if result["ok"] else "TOOL_UNAVAILABLE",
        "message": "Tool completed" if result["ok"] else result["error"],
        "result": result,
    }
    if publication:
        envelope["publication"] = {
            "kind": publication["kind"],
            "id": publication["id"],
            "version": publication["version"],
            "digest": publication_digest,
        }
    usage = (
        result.get("result", {}).get("usage") if isinstance(result.get("result"), dict) else None
    )
    record = journal.finish(
        action_id,
        envelope,
        reconcile=(lambda conn: spending.reconcile(conn, action_id, usage)) if price else None,
    )
    control_plane.event(
        "tool_executed",
        "info" if result["ok"] else "warning",
        "tool",
        tool["id"],
        actor,
        {"ok": result["ok"], "action_id": action_id},
    )
    return journal.response(record)


def _spending_preflight(tool: dict, args: dict) -> dict | None:
    execution = tool.get("execution", {})
    kind = execution.get("type")
    if kind == "gemini_generate":
        prompt = _render_template(execution["prompt_template"], args)
        if not isinstance(prompt, str) or not 1 <= len(prompt) <= 20000:
            raise spending.BudgetDenied("Use a hosted prompt of 1-20,000 characters")
        return spending.quote(execution["model"], execution.get("max_tokens", 800))
    if kind == "http_json" and execution.get("billing") != {"mode": "free"}:
        raise spending.BudgetDenied(
            "The owner must declare this HTTP route free; paid HTTP adapters are disabled"
        )
    if kind == "memorygate" and execution.get("operation") != "context":
        raise spending.BudgetDenied(
            "Delegated MemoryGate generation has no enforceable spending adapter"
        )
    return None
