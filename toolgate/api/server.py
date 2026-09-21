"""ToolGate v2 API: a typed, owner-controlled agent capability boundary."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Annotated, Literal
from urllib.parse import quote, urlsplit

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictBool, StrictInt

from toolgate.core import (
    container_admission,
    control_plane,
    legacy_archive,
    owner_channel,
    port_finalization,
    port_reviews,
    publications,
    recovery_journal,
    spending,
    spending_allowances,
    vault,
)
from toolgate.core import execution_journal as journal
from toolgate.core.public_https import (
    DestinationDenied,
    public_client,
    public_url,
    resolve_public,
)
from toolgate.executors import (
    container_control,
    filesystem_inventory,
    port_control,
    port_recovery,
    process_control,
    research,
    system_inventory,
)
from toolgate.executors.port_plan import PlanError

SERVICE_VERSION = "0.3.0"

app = FastAPI(title="ToolGate", version=SERVICE_VERSION)


@app.exception_handler(publications.PublicationInvalid)
async def publication_invalid(_request: Request, exc: publications.PublicationInvalid):
    return JSONResponse(status_code=409, content={"detail": {
        "code": "PUBLICATION_UNAVAILABLE", "message": str(exc),
    }})


@app.exception_handler(control_plane.DefinitionConflict)
async def definition_conflict(_request: Request, exc: control_plane.DefinitionConflict):
    return JSONResponse(status_code=409, content={"detail": {
        "code": "DEFINITION_CONFLICT", "message": str(exc),
        "current_version": exc.current_version,
    }})


@app.exception_handler(owner_channel.OwnerError)
async def owner_error(_request: Request, error: owner_channel.OwnerError):
    return JSONResponse({"detail": {"code": error.code, "message": str(error)}},
                        status_code=error.status)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    if request.url.path.startswith("/v2/owner/"):
        return JSONResponse({"detail": {"code": "invalid_request",
                                       "message": "Send a supported owner request with bounded fields."}},
                            status_code=422)
    return await request_validation_exception_handler(request, error)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.environ.get(
        "TOOLGATE_DASHBOARD_ORIGINS", "http://localhost:8011,http://127.0.0.1:8011"
    ).split(",") if origin.strip()],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-ToolGate-Key", "X-ToolGate-Execution-Key",
                   "X-ToolGate-Timestamp", "X-ToolGate-Signature"],
)


def require_admin(x_toolgate_key: str | None = Header(None, alias="X-ToolGate-Key")) -> str:
    key = vault.get_control_key("TOOLGATE_ADMIN_KEY")
    if not key or not x_toolgate_key or not secrets.compare_digest(key, x_toolgate_key):
        raise HTTPException(401, "requires TOOLGATE_ADMIN_KEY")
    return "admin"


def require_agent(x_toolgate_execution_key: str | None = Header(None, alias="X-ToolGate-Execution-Key")) -> dict:
    agent = control_plane.authenticate_agent(x_toolgate_execution_key)
    if not agent:
        raise HTTPException(401, "missing or invalid X-ToolGate-Execution-Key")
    return agent


def require_owner(x_toolgate_owner_key: str | None = Header(None, alias="X-ToolGate-Owner-Key")):
    owner_channel.authenticate(x_toolgate_owner_key)


@app.on_event("startup")
def startup():
    with control_plane._conn() as conn:
        recovery_journal.assert_not_held(conn)
    control_plane.purge_legacy_state()
    try:
        legacy_archive.migrate()
    except (sqlite3.Error, ValueError) as exc:
        raise RuntimeError("AI archive migration failed; keep ToolGate stopped, preserve toolgate.db, "
                           "and inspect the migration error before retrying") from exc
    control_plane.invalidate_legacy_verifications()
    journal.recover_interrupted()
    generated = vault.ensure_control_keys()
    for name in generated:
        print(f"[toolgate] generated and persisted {name}; value intentionally not logged")
    # A vault that cannot encrypt must not quietly keep provider keys in the clear.
    try:
        moved = vault.encrypt_values_at_rest()
    except vault.VaultError as exc:
        raise RuntimeError(f"ToolGate refuses to start without a usable vault key. {exc}") from exc
    if moved:
        print(f"[toolgate] encrypted {moved} vault value(s) at rest; values intentionally not logged")
    bootstrap_key = os.environ.get("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", "").strip()
    if bootstrap_key:
        scopes = [scope.strip() for scope in os.environ.get("TOOLGATE_BOOTSTRAP_SCOPES", "").split(",") if scope.strip()]
        control_plane.ensure_bootstrap_agent_key(bootstrap_key, scopes)
    ensure_builtin_research_capabilities()
    ensure_builtin_system_capabilities()


def ensure_builtin_system_capabilities() -> None:
    """Register fixed operations without changing existing owner policy or key scopes."""
    if not control_plane.get("tool", "system.port-control"):
        control_plane.create_tool({
            "id": "system.port-control", "name": "Reviewed port replacement",
            "description": "Apply one inspected port change by replacing a managed container, retaining the original for recovery. Requires exact owner approval.",
            "category": "system", "authorization": "owner_confirmation", "status": "active",
            "inputs": [{"name": "container_id", "type": "string", "required": True},
                       {"name": "review_id", "type": "string", "required": True}],
            "outputs": [{"name": "observation", "type": "object"}],
            "execution": {"type": "port_control"},
            "policy": {"usage_limits": {"max_per_minute": 3, "cooldown_seconds": 0,
                        "max_per_hour": 12, "max_runtime_seconds": 180}},
        })
    if not control_plane.get("tool", "system.files-list"):
        control_plane.create_tool({
            "id": "system.files-list", "name": "Directory listing",
            "description": "List bounded directory metadata beneath an operator-configured root. No file contents, symlink traversal or writes.",
            "category": "safe", "authorization": "auto", "status": "active",
            "inputs": [{"name": "root_id", "type": "string", "required": True},
                       {"name": "path", "type": "string", "required": False, "default": ""},
                       {"name": "limit", "type": "integer", "required": False, "default": 200,
                        "minimum": 1, "maximum": 200}],
            "outputs": [{"name": "listing", "type": "object"}],
            "execution": {"type": "filesystem_inventory"},
            "policy": {"usage_limits": {"max_per_minute": 60, "cooldown_seconds": 0,
                        "max_per_hour": 1000, "max_runtime_seconds": 15}},
        })
    if not control_plane.get("tool", "system.inventory"):
        control_plane.create_tool({
            "id": "system.inventory", "name": "System inventory",
            "description": "Read bounded process, container and port observations from the configured SystemGate. No commands or mutations.",
            "category": "safe", "authorization": "auto", "status": "active",
            "inputs": [{"name": "limit", "type": "integer", "required": False,
                        "default": 100, "minimum": 1, "maximum": 200}],
            "outputs": [{"name": "inventory", "type": "object"}],
            "execution": {"type": "system_inventory"},
            "policy": {"usage_limits": {"max_per_minute": 12, "cooldown_seconds": 0,
                        "max_per_hour": 120, "max_runtime_seconds": 15}},
        })
    if not control_plane.get("tool", "system.container-control"):
        control_plane.create_tool({
            "id": "system.container-control", "name": "Managed container control",
            "description": "Start, stop or restart one explicitly managed container by its full ID. Requires exact owner approval; no shell or container creation.",
            "category": "system", "authorization": "owner_confirmation", "status": "active",
            "inputs": [{"name": "container_id", "type": "string", "required": True},
                       {"name": "action", "type": "string", "required": True,
                        "enum": ["start", "stop", "restart"]}],
            "outputs": [{"name": "observation", "type": "object"}],
            "execution": {"type": "container_control"},
            "policy": {"usage_limits": {"max_per_minute": 6, "cooldown_seconds": 0,
                        "max_per_hour": 30, "max_runtime_seconds": 45}},
        })
    if not control_plane.get("tool", "system.process-control"):
        control_plane.create_tool({
            "id": "system.process-control", "name": "Managed service control",
            "description": "Start, stop or restart one operator-managed systemd service. Requires exact owner approval; no arbitrary PID or shell command.",
            "category": "system", "authorization": "owner_confirmation", "status": "active",
            "inputs": [{"name": "service_id", "type": "string", "required": True},
                       {"name": "action", "type": "string", "required": True,
                        "enum": ["start", "stop", "restart"]}],
            "outputs": [{"name": "observation", "type": "object"}],
            "execution": {"type": "process_control"},
            "policy": {"usage_limits": {"max_per_minute": 6, "cooldown_seconds": 0,
                        "max_per_hour": 30, "max_runtime_seconds": 60}},
        })


def ensure_builtin_research_capabilities() -> None:
    source_values = ["appstore_catalog", "appstore_reviews", "discourse", "general", "reddit", "hackernews", "github", "github_repositories", "producthunt", "stackexchange", "stackoverflow", "youtube"]
    service = {
        "id": "research-web",
        "name": "Research Web",
        "description": "Bounded read-only discovery across public research providers.",
        "secret_refs": ["TAVILY_API_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN", "STACKEXCHANGE_KEY"],
        "health": "configured",
        "destination_policy": {
            "schemes": ["https"], "private_networks": False,
            "providers": source_values,
        },
        "status": "active",
    }
    existing_service = control_plane.get("service", service["id"])
    comparable_service = {key: service[key] for key in service if key != "id"}
    if not existing_service:
        control_plane.create_service(service)
    elif any(existing_service.get(key) != value for key, value in comparable_service.items()):
        control_plane.update_service(service["id"], comparable_service)

    tools = [
        {
            "id": "approval.test-echo", "name": "Approval Test Echo",
            "description": "Harmless local verification tool that proves ToolGate approval flow without network or filesystem access.",
            "category": "safe",
            "inputs": [
                {"name": "value", "type": "string", "required": True, "min_length": 1, "max_length": 120},
            ],
            "outputs": [{"name": "proof", "type": "object"}],
            "execution": {"type": "local_echo"},
            "policy": {"usage_limits": {"max_per_minute": 6, "cooldown_seconds": 0, "max_per_hour": 40, "max_runtime_seconds": 3}},
            "authorization": "owner_confirmation", "version": 1, "status": "active",
        },
        {
            "id": "research.search", "name": "Research Search",
            "description": "Searches bounded public providers. Results are untrusted evidence and receive short-lived provenance handles.",
            "service_id": "research-web", "category": "safe",
            "inputs": [
                {"name": "query", "type": "string", "required": True, "min_length": 3, "max_length": 240, "pattern": r"^[^\x00-\x1F]+$"},
                {"name": "source", "type": "string", "required": True, "allowed_values": source_values},
                {"name": "max_results", "type": "integer", "required": False, "default": 8, "minimum": 1, "maximum": 20},
                {"name": "recency_days", "type": "integer", "required": False, "default": 30, "minimum": 1, "maximum": 3650},
            ],
            "outputs": [{"name": "research", "type": "object"}],
            "execution": {"type": "research_search"},
            "policy": {"usage_limits": {"max_per_minute": 12, "cooldown_seconds": 0, "max_per_hour": 120, "max_runtime_seconds": 30}},
            "authorization": "auto", "version": 1, "status": "active",
        },
        {
            "id": "research.fetch", "name": "Research Fetch",
            "description": "Reads a server-issued research result. Arbitrary URLs, private destinations, active content, oversized responses, and instruction-like payloads are denied.",
            "service_id": "research-web", "category": "controlled",
            "inputs": [
                {"name": "result_id", "type": "string", "required": True, "min_length": 20, "max_length": 48, "pattern": r"^rr_[A-Za-z0-9_-]+$"},
                {"name": "max_chars", "type": "integer", "required": False, "default": 12000, "minimum": 1000, "maximum": 20000},
            ],
            "outputs": [{"name": "document", "type": "object"}],
            "execution": {"type": "research_fetch"},
            "policy": {"usage_limits": {"max_per_minute": 10, "cooldown_seconds": 0, "max_per_hour": 80, "max_runtime_seconds": 30}},
            "authorization": "auto", "version": 1, "status": "active",
        },
        {
            "id": "research.fetch-batch", "name": "Research Fetch Batch",
            "description": "Reads up to eight server-issued research handles as one bounded, scanned batch. Arbitrary URLs remain unsupported.",
            "service_id": "research-web", "category": "controlled",
            "inputs": [
                {"name": "result_ids", "type": "array", "required": True, "min_items": 1, "max_items": 8,
                 "unique_items": True, "item_type": "string", "item_pattern": r"rr_[A-Za-z0-9_-]{20,40}"},
                {"name": "max_chars", "type": "integer", "required": False, "default": 3500, "minimum": 1000, "maximum": 5000},
            ],
            "outputs": [{"name": "documents", "type": "object"}],
            "execution": {"type": "research_fetch_batch"},
            "policy": {"usage_limits": {"max_per_minute": 4, "cooldown_seconds": 0, "max_per_hour": 120, "max_runtime_seconds": 30}},
            "authorization": "auto", "version": 1, "status": "active",
        },
    ]
    atomic_sources = {
        "research.appstore-catalog": ("Apple App Store Catalog", "appstore_catalog"),
        "research.appstore-reviews": ("Apple App Store Reviews", "appstore_reviews"),
        "research.discourse": ("Automation Community Search", "discourse"),
        "research.web": ("Web Search", "general"),
        "research.reddit": ("Reddit Search", "reddit"),
        "research.hackernews": ("Hacker News Search", "hackernews"),
        "research.github-issues": ("GitHub Issue Search", "github"),
        "research.github-repositories": ("GitHub Repository Search", "github_repositories"),
        "research.stackexchange": ("Stack Exchange Search", "stackexchange"),
        "research.stackoverflow": ("Stack Overflow Search", "stackoverflow"),
        "research.youtube-comments": ("YouTube Comment Search", "youtube"),
        "research.producthunt": ("Product Hunt Search", "producthunt"),
    }
    atomic_inputs = [
        {"name": "query", "type": "string", "required": True, "min_length": 3, "max_length": 240, "pattern": r"^[^\x00-\x1F]+$"},
        {"name": "max_results", "type": "integer", "required": False, "default": 8, "minimum": 1, "maximum": 20},
        {"name": "recency_days", "type": "integer", "required": False, "default": 30, "minimum": 1, "maximum": 3650},
    ]
    for tool_id, (name, source) in atomic_sources.items():
        tools.append({
            "id": tool_id, "name": name,
            "description": f"Searches the bounded {name.removesuffix(' Search')} adapter and returns provenance-bound untrusted evidence.",
            "service_id": "research-web", "category": "safe", "inputs": atomic_inputs,
            "outputs": [{"name": "research", "type": "object"}],
            "execution": {"type": "research_search", "fixed_source": source},
            "policy": {"usage_limits": {"max_per_minute": 12, "cooldown_seconds": 0, "max_per_hour": 120, "max_runtime_seconds": 30}},
            "authorization": "auto", "version": 1, "status": "active",
        })
    bundle_profiles = {
        "research.scan-pain": ("Pain Signal Scan", ["discourse", "reddit", "hackernews", "youtube", "general"]),
        "research.scan-developer": ("Developer Friction Scan", ["github", "stackoverflow", "stackexchange", "hackernews", "general"]),
        "research.scan-competition": ("Competition Scan", ["general", "producthunt", "github_repositories"]),
    }
    bundle_inputs = [
        {"name": "query", "type": "string", "required": True, "min_length": 3, "max_length": 240, "pattern": r"^[^\x00-\x1F]+$"},
        {"name": "max_per_source", "type": "integer", "required": False, "default": 5, "minimum": 1, "maximum": 10},
        {"name": "recency_days", "type": "integer", "required": False, "default": 90, "minimum": 1, "maximum": 3650},
    ]
    for tool_id, (name, sources) in bundle_profiles.items():
        tools.append({
            "id": tool_id, "name": name,
            "description": "Runs a bounded reusable multi-source research profile while preserving per-result provenance and failures.",
            "service_id": "research-web", "category": "safe", "inputs": bundle_inputs,
            "outputs": [{"name": "research", "type": "object"}],
            "execution": {"type": "research_bundle", "sources": sources},
            "policy": {"usage_limits": {"max_per_minute": 4, "cooldown_seconds": 0, "max_per_hour": 40, "max_runtime_seconds": 60}},
            "authorization": "auto", "version": 1, "status": "active",
        })
    managed_fields = ("name", "description", "service_id", "category", "inputs", "outputs", "execution", "policy", "authorization", "status")
    for definition in tools:
        existing = control_plane.get("tool", definition["id"])
        if existing and all(existing.get(key) == definition.get(key) for key in managed_fields):
            continue
        if existing:
            definition = {**definition, "version": int(existing.get("version", 1)) + 1}
        saved = control_plane.create_tool(definition)
        control_plane.event("builtin_tool_synced", "info", "tool", definition["id"], "system", {"version": saved["version"]})


HEALTH_CACHE_SECONDS = 15
HEALTH_PROBE_TIMEOUT_SECONDS = 2.0
_HEALTHY_STATUSES = {"ok", "not_configured"}
_health_snapshot: dict | None = None


def _probe_control_plane() -> dict:
    """Open the control-plane database for real rather than assuming it is there."""
    try:
        control_plane.settings()
    except (sqlite3.Error, OSError, ValueError) as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}
    return {"status": "ok"}


def _probe_http(url: str, path: str) -> dict:
    """Coarse reachability of one upstream. Never returns the host or the body."""
    try:
        response = httpx.get(f"{url.rstrip('/')}{path}", timeout=HEALTH_PROBE_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        # "unavailable" is the contract's word for configured-but-not-working;
        # the exception class carries why. Status vocabulary is fixed so one
        # dashboard can render every module - nuance belongs in reason.
        return {"status": "unavailable", "reason": type(exc).__name__}
    if response.status_code >= 500:
        return {"status": "degraded", "reason": "upstream_5xx"}
    return {"status": "ok"}


def _memorygate_configured() -> bool:
    try:
        return bool(vault.get_key("MEMORYGATE_READ_KEY"))
    except KeyError:
        return False


def _run_dependency_checks() -> dict:
    checks = {"control_plane_db": _probe_control_plane(), "vault": vault.vault_status()}
    try:
        settings = control_plane.settings()
        generation_configured = bool(settings.get("generation_url")) or any(
            tool.get("status") == "active" and tool.get("execution", {}).get("type") == "ollama_generate"
            for tool in control_plane.list_objects("tool")
        )
    except (sqlite3.Error, OSError, ValueError):
        settings = {}
        generation_configured = False

    probes = {"searxng": (settings.get("research_searxng_url", "http://toolgate-searxng:8080"), "/healthz")}
    if _memorygate_configured():
        probes["memorygate"] = (os.environ.get("MEMORYGATE_URL", "http://memorygate-api:8020"), "/health")
    else:
        checks["memorygate"] = {"status": "not_configured"}

    if generation_configured:
        probes["generation"] = (settings.get("generation_url", "http://memorygate-ollama:11434"), "/api/tags")
    else:
        checks["generation"] = {"status": "not_configured"}

    with ThreadPoolExecutor(max_workers=len(probes)) as pool:
        results = {name: pool.submit(_probe_http, url, path) for name, (url, path) in probes.items()}
    checks.update({name: future.result() for name, future in results.items()})

    failing = sorted(name for name, check in checks.items() if check["status"] not in _HEALTHY_STATUSES)
    return {"status": "degraded" if failing else "ok", "degraded": failing, "checks": checks,
            "checked_at": datetime.now(timezone.utc).isoformat()}


@app.get("/health")
def health():
    """Unauthenticated liveness plus real dependency probes.

    Probe detail stays coarse -- a status word and an exception class, never a
    host, a credential or an upstream body -- because anyone can call this.
    Results are cached briefly so an anonymous caller cannot turn the endpoint
    into an outbound request amplifier; the age of the cached answer is
    reported rather than hidden.
    """
    global _health_snapshot
    now = time.monotonic()
    snapshot = _health_snapshot
    if snapshot is None or now - snapshot["probed_at"] >= HEALTH_CACHE_SECONDS:
        snapshot = {**_run_dependency_checks(), "probed_at": now}
        _health_snapshot = snapshot
    # Field names and order are fixed by the Conker module contract - see
    # docs/module-contract.md. "version" is this module's own version, not the
    # API revision: they mean different things, and a dashboard reading one
    # field for both is wrong about every module it does not special-case.
    return {"service": "toolgate", "version": SERVICE_VERSION,
            "status": snapshot["status"], "degraded": snapshot["degraded"],
            "checks": snapshot["checks"], "checked_at": snapshot["checked_at"],
            "age_seconds": round(now - snapshot["probed_at"], 1)}


@app.get("/auth/check")
def auth_check(_tier: str = Depends(require_admin)):
    return {"tier": "admin"}


class SecretCreate(BaseModel):
    name: str
    value: str


class SecretUpdate(BaseModel):
    value: str


@app.get("/vault/secrets")
def list_secrets(_tier: str = Depends(require_admin)):
    return vault.list_placeholders()


@app.post("/vault/secrets")
def create_secret(payload: SecretCreate, _tier: str = Depends(require_admin)):
    try:
        vault.set_secret(payload.name, payload.value, allow_existing=False)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    control_plane.event("secret_created", "info", "secret", payload.name, "admin")
    return {"name": payload.name}


@app.put("/vault/secrets/{name}")
def update_secret(name: str, payload: SecretUpdate, _tier: str = Depends(require_admin)):
    try:
        vault.set_secret(name, payload.value, allow_existing=True)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    control_plane.event("secret_updated", "warning", "secret", name, "admin")
    return {"name": name}


@app.delete("/vault/secrets/{name}")
def delete_secret(name: str, _tier: str = Depends(require_admin)):
    try:
        vault.delete_secret(name)
    except KeyError:
        raise HTTPException(404, "secret not found")
    control_plane.event("secret_deleted", "warning", "secret", name, "admin")
    return {"name": name}


@app.post("/settings/keys/admin/rotate")
def rotate_control_key(_tier: str = Depends(require_admin)):
    return {"which": "admin", "key": vault.rotate_control_key("TOOLGATE_ADMIN_KEY")}


class AgentKeyCreate(BaseModel):
    name: str
    scopes: list[str] = []


class AgentKeyScopes(BaseModel):
    scopes: list[str] = []


class V2Service(BaseModel):
    id: str | None = None
    name: str
    description: str = ""
    secret_refs: list[str] = []
    health: str = "unknown"
    destination_policy: dict = {}
    status: str = "active"


class V2Tool(BaseModel):
    id: str
    name: str | None = None
    description: str = ""
    service_id: str | None = None
    category: str = "controlled"
    inputs: list[dict] = []
    outputs: list[dict] = []
    execution: dict = {}
    policy: dict = {}
    authorization: str = "auto"
    version: StrictInt = Field(default=1, ge=1)
    expected_version: StrictInt | None = Field(default=None, ge=1)
    status: str = "active"


class V2Automation(BaseModel):
    id: str
    name: str | None = None
    description: str = ""
    inputs: list[dict] = []
    workflow: list[dict] = []
    policy: dict = {}
    authorization: str = "auto"
    schedule: str | None = None
    version: StrictInt = Field(default=1, ge=1)
    expected_version: StrictInt | None = Field(default=None, ge=1)
    status: str = "draft"


class V2Request(BaseModel):
    """Informational owner messages; verification is issued only by an invocation."""

    kind: str
    title: str
    details: str
    payload: dict = {}
    severity: str = "info"


class V2RequestDecision(BaseModel):
    status: str
    note: str = ""


class OwnerDecision(BaseModel):
    model_config = {"extra": "forbid"}
    status: Literal["approved", "rejected", "dismissed"]
    note: str = Field(default="", max_length=2000)


class V2Invoke(BaseModel):
    args: dict = {}
    approval_request_id: str | None = None
    action_id: str | None = None
    job_id: str | None = None
    published_version: StrictInt | None = Field(default=None, ge=1)
    expected_publication_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class V2Publish(BaseModel):
    expected_version: StrictInt = Field(ge=1)


class PortMapping(BaseModel):
    model_config = {"extra": "forbid"}
    hostAddress: str = Field(min_length=1, max_length=45)
    hostPort: StrictInt = Field(ge=1, le=65535)
    containerPort: StrictInt = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]


class PortReviewRequest(BaseModel):
    model_config = {"extra": "forbid"}
    container_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation: Literal["create", "edit", "remove"]
    mapping: PortMapping | None = None
    original: PortMapping | None = None


class V2Settings(BaseModel):
    generation_model: str = "qwen3:4b"
    event_retention_days: int = 90
    default_confirmation_expiry_seconds: int = 60
    producthunt_commercial_use_approved: bool = False


class VerificationMethodCreate(BaseModel):
    name: str
    secret_ref: str


class VerificationCallback(BaseModel):
    method_id: str
    request_id: str
    decision: str
    nonce: str


def deny(code: str, message: str, status: int = 403, next_action: str = ""):
    raise HTTPException(status, {"code": code, "message": message, "next_action": next_action})


SUPPORTED_TOOL_EXECUTORS = {
    "echo", "local_echo", "http_json", "memorygate", "ollama_generate", "gemini_generate",
    "research_search", "research_bundle", "research_fetch", "research_fetch_batch",
    "system_inventory",
    "filesystem_inventory",
    "container_control",
    "process_control",
    "port_control",
}
AUTHORIZATION_MODES = {"auto", "ai_review", "owner_confirmation", "blocked"}
CAPABILITY_STATUSES = {"draft", "active", "disabled"}
INPUT_TYPES = {"string", "integer", "number", "boolean", "array", "object"}
GEMINI_MODELS = {"gemini-3.5-flash-lite", "gemini-2.5-flash-lite"}
AI_CONFIRMATIONS = {
    "approve", "approved", "correct", "done", "good", "looks good", "perfect",
    "ship it", "that is correct", "that works", "yes",
}


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
        if minimum is not None and (isinstance(minimum, bool) or not isinstance(minimum, (int, float))):
            errors.append(f"{prefix} minimum must be numeric")
        if maximum is not None and (isinstance(maximum, bool) or not isinstance(maximum, (int, float))):
            errors.append(f"{prefix} maximum must be numeric")
        if isinstance(minimum, (int, float)) and isinstance(maximum, (int, float)) and minimum > maximum:
            errors.append(f"{prefix} minimum cannot exceed maximum")
        min_length, max_length = field.get("min_length"), field.get("max_length")
        if min_length is not None and (not isinstance(min_length, int) or not 0 <= min_length <= 100000):
            errors.append(f"{prefix} min_length must be between 0 and 100000")
        if max_length is not None and (not isinstance(max_length, int) or not 0 <= max_length <= 100000):
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
    if not isinstance(capability.get("id"), str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,79}", capability["id"]):
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
    if not isinstance(execution, dict) or execution.get("type") not in SUPPORTED_TOOL_EXECUTORS:
        errors.append(f"execution.type must be one of: {', '.join(sorted(SUPPORTED_TOOL_EXECUTORS))}")
        return errors
    if execution["type"] == "port_control":
        if (execution != {"type": "port_control"} or tool.get("id") != "system.port-control"
                or tool.get("authorization") != "owner_confirmation"):
            errors.append("Port replacement requires its reserved executor and owner confirmation")
        if input_names != {"container_id", "review_id"} or any(
                field.get("type") != "string" or field.get("required") is not True
                for field in inputs if isinstance(field, dict)):
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
                for field in inputs if isinstance(field, dict)):
            errors.append(f"{kind} requires string {target} and action inputs")
    elif execution["type"] == "filesystem_inventory":
        if execution != {"type": "filesystem_inventory"}:
            errors.append("filesystem_inventory uses only operator-configured roots")
        if input_names - {"root_id", "path", "limit"} or "root_id" not in input_names:
            errors.append("filesystem_inventory accepts root_id, path and limit")
        for field in inputs:
            if isinstance(field, dict) and field.get("type") != (
                    "integer" if field.get("name") == "limit" else "string"):
                errors.append("filesystem_inventory input types are invalid")
    elif execution["type"] == "system_inventory":
        if execution != {"type": "system_inventory"}:
            errors.append("system_inventory uses only the operator-configured fixed endpoint")
        if input_names - {"limit"}:
            errors.append("system_inventory accepts only limit")
        for field in inputs:
            if isinstance(field, dict) and field.get("name") == "limit" and field.get("type") != "integer":
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
        elif parsed and parsed.hostname and parsed.hostname.lower() not in {str(host).lower() for host in allowed_hosts}:
            errors.append("the URL host must be present in http_json.allowed_hosts")
        placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template or ""))
        missing = placeholders - input_names
        if missing:
            errors.append(f"URL placeholders need declared inputs: {', '.join(sorted(missing))}")
        if not isinstance(execution.get("result_path"), str) or not execution["result_path"].strip():
            errors.append("http_json.result_path is required")
        timeout = execution.get("timeout_seconds", 10)
        if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 30:
            errors.append("http_json.timeout_seconds must be between 1 and 30")
        max_bytes = execution.get("max_response_bytes", 262144)
        if not isinstance(max_bytes, int) or not 1024 <= max_bytes <= 1048576:
            errors.append("http_json.max_response_bytes must be between 1024 and 1048576")
        secret_headers = execution.get("secret_headers", {})
        forbidden_headers = {"host", "content-length", "connection", "transfer-encoding",
                             "proxy-authorization", "proxy-authenticate", "upgrade"}
        if not isinstance(secret_headers, dict) or any(
                not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", name)
                or name.lower() in forbidden_headers
                or not isinstance(ref, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", ref)
                for name, ref in secret_headers.items()):
            errors.append("http_json.secret_headers must map safe header names to vault references")
    elif execution["type"] == "memorygate":
        operation = execution.get("operation")
        if operation not in {"context", "ask"}:
            errors.append("memorygate.operation must be context or ask")
        required_input = "query" if operation == "context" else "question"
        if operation in {"context", "ask"} and required_input not in input_names:
            errors.append(f"memorygate.{operation} requires a declared '{required_input}' input")
        if not isinstance(execution.get("secret_ref"), str) or not re.fullmatch(
                r"[A-Z][A-Z0-9_]*", execution.get("secret_ref", "")):
            errors.append("memorygate.secret_ref must name a ToolGate vault secret")
    elif execution["type"] == "ollama_generate":
        prompt_template = execution.get("prompt_template")
        if not isinstance(prompt_template, str) or not prompt_template.strip():
            errors.append("ollama_generate.prompt_template is required")
        else:
            placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", prompt_template))
            missing = placeholders - input_names
            if missing:
                errors.append(f"prompt placeholders need declared inputs: {', '.join(sorted(missing))}")
        max_tokens = execution.get("max_tokens", 256)
        if not isinstance(max_tokens, int) or not 8 <= max_tokens <= 1024:
            errors.append("ollama_generate.max_tokens must be between 8 and 1024")
        temperature = execution.get("temperature", 0.0)
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)) or not 0 <= temperature <= 2:
            errors.append("ollama_generate.temperature must be between 0 and 2")
    elif execution["type"] == "gemini_generate":
        prompt_template = execution.get("prompt_template")
        if not isinstance(prompt_template, str) or not prompt_template.strip():
            errors.append("gemini_generate.prompt_template is required")
        else:
            placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", prompt_template))
            missing = placeholders - input_names
            if missing:
                errors.append(f"prompt placeholders need declared inputs: {', '.join(sorted(missing))}")
        if execution.get("model") not in GEMINI_MODELS:
            errors.append(f"gemini_generate.model must be one of: {', '.join(sorted(GEMINI_MODELS))}")
        if not isinstance(execution.get("secret_ref"), str) or not re.fullmatch(
                r"[A-Z][A-Z0-9_]*", execution.get("secret_ref", "")):
            errors.append("gemini_generate.secret_ref must name a ToolGate vault secret")
        max_tokens = execution.get("max_tokens", 800)
        if not isinstance(max_tokens, int) or not 128 <= max_tokens <= 2048:
            errors.append("gemini_generate.max_tokens must be between 128 and 2048")
        temperature = execution.get("temperature", 0.0)
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)) or not 0 <= temperature <= 1:
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
        if not isinstance(sources, list) or not sources or len(sources) > 7 or any(source not in research.SOURCE_DOMAINS for source in sources):
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
        raise HTTPException(422, {
            "code": "INVALID_TOOL_DEFINITION",
            "message": "; ".join(errors),
            "next_action": "Complete the tool Workflow definition before saving or approving it",
        })


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
            deny("UPSTREAM_SCHEMA_ERROR", "The configured result field was absent from the upstream response", 502)
    return value


def _execute_http_json(execution: dict, args: dict) -> dict:
    template = execution["url"]
    placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template))
    url = template
    for name in placeholders:
        url = url.replace(f"{{{name}}}", quote(str(args[name]), safe=""))
    parsed = urlsplit(url)
    allowed_hosts = {str(host).lower() for host in execution["allowed_hosts"]}
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower() not in allowed_hosts:
        deny("DESTINATION_DENIED", "The rendered destination is outside this tool's exact host allowlist")
    if not public_url(url):
        deny("DESTINATION_DENIED", "Public HTTP tools cannot reach private or unresolved network destinations")
    headers = {"Accept": "application/json", "User-Agent": "ToolGate/2.0"}
    for header, secret_ref in execution.get("secret_headers", {}).items():
        try:
            headers[header] = vault.get_key(secret_ref)
        except KeyError:
            deny("SECRET_UNAVAILABLE", f"Required vault reference '{secret_ref}' is not configured", 503)
    timeout = min(float(execution.get("timeout_seconds", 10)), 30)
    max_bytes = min(int(execution.get("max_response_bytes", 262144)), 1048576)
    try:
        with public_client(timeout=timeout, headers=headers) as client:
            response = client.request(str(execution.get("method", "GET")).upper(), url,
                                      json=_render_template(execution.get("body"), args)
                                      if execution.get("body") is not None else None)
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
        body = {"query": args["query"], "max_items": args.get("max_items", 12),
                "include_evidence": args.get("include_evidence", False)}
    else:
        body = {"question": args["question"], "include_evidence": args.get("include_evidence", False)}
    try:
        response = httpx.post(f"{base_url}/runtime/{operation}", json=body, headers=headers, timeout=45)
        response.raise_for_status()
        result = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        deny("MEMORYGATE_UNAVAILABLE", f"MemoryGate {operation} failed: {type(exc).__name__}", 502)
    return {"ok": True, "result": result}


def _execute_ollama(execution: dict, args: dict) -> dict:
    url = control_plane.settings().get("generation_url", "http://memorygate-ollama:11434").rstrip("/")
    prompt = _render_template(execution["prompt_template"], args)
    try:
        response = httpx.post(f"{url}/api/generate", json={
            "model": execution.get("model") or control_plane.settings().get("generation_model", "qwen3:4b"),
            "prompt": prompt, "stream": False, "think": False,
            "options": {"temperature": float(execution.get("temperature", 0.0)),
                        "num_predict": int(execution.get("max_tokens", 256)), "num_ctx": 4096},
        }, timeout=180)
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
            url, json=body,
            headers={"Accept": "application/json", "Content-Type": "application/json", "x-goog-api-key": api_key},
            timeout=min(float(execution.get("timeout_seconds", 60)), 120),
        )
        response.raise_for_status()
        payload = response.json()
        parts = payload["candidates"][0]["content"]["parts"]
        text = "".join(str(part.get("text") or "") for part in parts if isinstance(part, dict)).strip()
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
            args["query"], execution.get("fixed_source") or args.get("source", "general"),
            args.get("max_results", 8), args.get("recency_days", 30),
        )
    except research.ResearchError as exc:
        deny("RESEARCH_UNAVAILABLE", str(exc), 502, "Try another source or a narrower query")
    return {"ok": True, "result": result}


def _execute_research_bundle(execution: dict, args: dict) -> dict:
    try:
        result = research.search_bundle(
            args["query"], execution["sources"],
            args.get("max_per_source", 5), args.get("recency_days", 90),
        )
    except research.ResearchError as exc:
        deny("RESEARCH_UNAVAILABLE", str(exc), 502, "Try a narrower query or an atomic source tool")
    return {"ok": True, "result": result}


def _execute_research_fetch(args: dict) -> dict:
    try:
        result = research.fetch(args["result_id"], args.get("max_chars", 12000))
    except research.ResearchError as exc:
        deny("RESEARCH_FETCH_DENIED", str(exc), 422, "Run research.search and use a fresh result_id")
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


def enforce_usage_limits(subject_type: str, subject: dict, event_type: str):
    limits = subject.get("policy", {}).get("usage_limits", {})
    per_minute = limits.get("max_per_minute")
    if per_minute is not None and control_plane.event_count_since(event_type, subject_type, subject["id"], 60) >= int(per_minute):
        deny("RATE_LIMITED", f"{subject['name']} reached its per-minute limit", 429, "Wait before retrying")
    per_hour = limits.get("max_per_hour")
    if per_hour is not None and control_plane.event_count_since(event_type, subject_type, subject["id"], 3600) >= int(per_hour):
        deny("RATE_LIMITED", f"{subject['name']} reached its hourly limit", 429, "Wait before retrying")
    cooldown = limits.get("cooldown_seconds")
    if cooldown:
        latest = control_plane.latest_event_at(event_type, subject_type, subject["id"])
        if latest and (datetime.now(timezone.utc) - latest).total_seconds() < int(cooldown):
            deny("RATE_LIMITED", f"{subject['name']} is in cooldown", 429, "Wait before retrying")


def _shape_tool_result(tool: dict, result: dict) -> dict:
    if not result.get("ok") or "result" not in result:
        return result
    outputs = [item for item in tool.get("outputs", []) if isinstance(item, dict) and item.get("name")]
    value = result["result"]
    for output in outputs:
        if isinstance(value, dict) and output["name"] in value:
            result.setdefault(output["name"], value[output["name"]])
        elif len(outputs) == 1:
            result.setdefault(output["name"], value)
    output_values = {item["name"]: result[item["name"]] for item in outputs if item["name"] in result}
    output_schema = [{**item, "required": True} for item in outputs]
    errors = control_plane.validate_inputs(output_schema, output_values)
    if errors:
        deny("UPSTREAM_SCHEMA_ERROR", "; ".join(errors), 502)
    return result


def require_current_dispatch_authority(conn, actor_id: str | None, capability: str | tuple[str, ...] | None) -> None:
    """Called inside the journal writer transaction, before consuming or dispatching."""
    settings = conn.execute("SELECT * FROM v2_objects WHERE kind='settings' AND id='control-plane'").fetchone()
    if settings and control_plane._row(settings).get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    if capability is not None:
        row = conn.execute("SELECT * FROM v2_agent_keys WHERE id=?", (actor_id,)).fetchone()
        if not row or row["status"] != "active":
            deny("AGENT_REVOKED", "The originating agent key is no longer active", 403)
        required = (capability,) if isinstance(capability, str) else capability
        if not all(control_plane.is_scoped(control_plane.public_agent_key(row), scope) for scope in required):
            deny("POLICY_DENIED", "The originating agent no longer has the required scope", 403)


def invoke_tool(tool: dict, args: dict, actor: str, *, approval_request_id: str | None = None,
                approval_granted: bool = False, actor_id: str | None = None,
                action_id: str | None = None, job_id: str | None = None,
                parent_action_id: str | None = None, publication: dict | None = None,
                authority_scope: str | tuple[str, ...] | None = None) -> dict:
    identity = actor_id or actor
    publication_digest = publication["digest"] if publication else None
    if action_id:
        try:
            previous = journal.existing(action_id, "tool", tool["id"], args, identity,
                                        job_id, parent_action_id, publication_digest=publication_digest)
        except (journal.ExecutionConflict, ValueError) as exc:
            deny("ACTION_CONFLICT", str(exc), 409)
        if previous:
            return journal.response(previous)
    if control_plane.settings().get("lockdown"):
        control_plane.event("execution_blocked", "critical", "tool", tool["id"], actor, {"code": "LOCKED_DOWN"})
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423, "Ask the owner to unlock ToolGate")
    errors = control_plane.validate_inputs(tool.get("inputs", []), args)
    if errors:
        control_plane.event("validation_failed", "warning", "tool", tool["id"], actor, {"errors": errors})
        deny("VALIDATION_ERROR", "; ".join(errors), 422, "Run `toolgate tool <name> info`")
    authorization = tool.get("authorization", "auto")
    is_port = tool.get("id") == "system.port-control" or tool.get("execution", {}).get("type") == "port_control"
    port_review = None
    if is_port:
        if (tool.get("id") != "system.port-control" or tool.get("execution") != {"type": "port_control"}
                or authorization != "owner_confirmation" or approval_granted
                or set(args) != {"container_id", "review_id"}):
            deny("POLICY_DENIED", "Port replacement requires its exact review and direct owner confirmation", 403)
        try:
            port_review = port_reviews.get(args["review_id"], identity)
        except port_reviews.ReviewError:
            deny("REVIEW_INVALID", "Create a current port-change review first", 409)
        if (port_review["expired"] or port_review["consumed"]
                or port_review["preview"]["containerId"] != args["container_id"]):
            deny("REVIEW_INVALID", "Create a current port-change review for this container", 409)
    if authorization == "blocked":
        control_plane.event("execution_blocked", "warning", "tool", tool["id"], actor, {"code": "POLICY_DENIED"})
        deny("POLICY_DENIED", "This tool is permanently blocked by its owner policy")
    if authorization in {"owner_confirmation", "ai_review"} and not approval_granted:
        if not approval_request_id:
            expiry = int(control_plane.settings().get("default_confirmation_expiry_seconds", 60))
            request = control_plane.create_verification_request(
                f"Run {tool['name']}",
                ("Replace the container using this exact inspected port change: " + json.dumps(port_review["preview"]))
                if is_port else "Owner confirmation is required for this exact immutable tool invocation.",
                actor, "tool", tool["id"], args, tool.get("version"), expiry, actor_id,
                publication_digest=publication_digest)
            return {"code": "CONFIRMATION_REQUIRED", "message": "This exact action is queued for owner review.",
                    "request_id": request["id"], "expires_at": request["payload"]["binding"]["expires_at"],
                    "next_action": f"After approval, retry with --approval-request-id {request['id']}"}
    enforce_usage_limits("tool", tool, "tool_executed")
    if not action_id:
        if tool.get("execution", {}).get("type") not in {"echo", "local_echo"}:
            deny("ACTION_ID_REQUIRED", "Supply a stable action_id before dispatch; reuse it when checking or retrying", 422)
        action_id = "local_" + uuid.uuid4().hex

    try:
        price = _spending_preflight(tool, args)
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 403)

    def authorize(conn):
        require_current_dispatch_authority(conn, actor_id, authority_scope)
        if publication:
            publications.for_execution(conn, publication["kind"], publication["id"], publication["version"])
        if authorization in {"owner_confirmation", "ai_review"} and not approval_granted:
            approved, reason = control_plane.consume_verification_in_transaction(
                conn, approval_request_id, "tool", tool["id"], args, tool.get("version"), actor, actor_id,
                publication_digest=publication_digest)
            if not approved:
                deny("APPROVAL_INVALID", reason, 409, "Request a new confirmation for this exact action")
    def reserve(conn):
        if price:
            spending.reserve(conn, action_id, job_id, identity, parent_action_id, price)
        if is_port or tool.get("execution", {}).get("type") == "container_control":
            container_admission.reserve(conn, action_id, args.get("container_id"))
        if is_port:
            port_reviews.consume_in_transaction(conn, args["review_id"], identity, action_id)

    try:
        record, dispatch = journal.begin(action_id, "tool", tool["id"], args, identity,
                                         tool.get("version"), job_id=job_id,
                                         parent_action_id=parent_action_id, authorize=authorize,
                                         publication_digest=publication_digest,
                                         reserve=reserve)
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
                    publications.for_execution(conn, publication["kind"], publication["id"], publication["version"])
                row = conn.execute("SELECT body FROM v2_objects WHERE kind='tool' AND id='system.port-control'").fetchone()
                current = json.loads(row["body"]) if row else {}
                if (current.get("status") != "active" or current.get("authorization") != "owner_confirmation"
                        or current.get("execution") != {"type": "port_control"}):
                    deny("POLICY_DENIED", "Port replacement policy changed", 403)
            try:
                result = {"ok": True, "result": port_control.execute(action_id, authorize=step_authority)}
            except container_control.ControlError as exc:
                result = {"ok": False, "error": str(exc), "error_code": exc.code}
        else:
            result = _dispatch_tool(tool, args)
    except Exception:
        journal.unknown(action_id)
        return journal.response(journal.get(action_id))
    envelope = {"code": "OK" if result["ok"] else "TOOL_UNAVAILABLE",
                "message": "Tool completed" if result["ok"] else result["error"], "result": result}
    if publication:
        envelope["publication"] = {"kind": publication["kind"], "id": publication["id"],
                                   "version": publication["version"], "digest": publication_digest}
    usage = result.get("result", {}).get("usage") if isinstance(result.get("result"), dict) else None
    record = journal.finish(action_id, envelope, reconcile=(
        lambda conn: spending.reconcile(conn, action_id, usage)) if price else None)
    control_plane.event("tool_executed", "info" if result["ok"] else "warning", "tool", tool["id"], actor, {"ok": result["ok"], "action_id": action_id})
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
        raise spending.BudgetDenied("The owner must declare this HTTP route free; paid HTTP adapters are disabled")
    if kind == "memorygate" and execution.get("operation") != "context":
        raise spending.BudgetDenied("Delegated MemoryGate generation has no enforceable spending adapter")
    return None


def _dispatch_tool(tool: dict, args: dict) -> dict:
    # v2 executes only typed, declared executors. Arbitrary Python is intentionally unsupported.
    executor_type = tool.get("execution", {}).get("type")
    if tool.get("id") == "system.port-control" or executor_type == "port_control":
        return {"ok": False, "error": "Port replacement requires reviewed journal admission."}
    if tool.get("id") == "system.files-list" and tool.get("execution") != {"type": "filesystem_inventory"}:
        return {"ok": False, "error": "The reserved directory listing definition is invalid.",
                "error_code": "invalid_files_definition"}
    if tool.get("id") == "system.inventory" and tool.get("execution") != {"type": "system_inventory"}:
        return {"ok": False, "error": "The reserved system inventory definition is invalid.",
                "error_code": "invalid_inventory_definition"}
    if (tool.get("id") == "system.container-control" or executor_type == "container_control") and (
            tool.get("execution") != {"type": "container_control"}
            or tool.get("authorization") != "owner_confirmation"):
        return {"ok": False, "error": "Managed container control requires its fixed executor and owner confirmation.",
                "error_code": "invalid_container_definition"}
    if (tool.get("id") == "system.process-control" or executor_type == "process_control") and (
            tool.get("execution") != {"type": "process_control"}
            or tool.get("authorization") != "owner_confirmation"):
        return {"ok": False, "error": "Managed service control requires its fixed executor and owner confirmation.",
                "error_code": "invalid_process_definition"}
    if executor_type == "echo":
        result = {"ok": True, "result": args}
    elif executor_type == "local_echo":
        result = _execute_local_echo(args)
    elif executor_type == "http_json":
        result = _execute_http_json(tool["execution"], args)
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
        if tool["execution"] != {"type": "filesystem_inventory"} or set(args) - {"root_id", "path", "limit"}:
            return {"ok": False, "error": "Provide root_id, path and bounded limit only.",
                    "error_code": "invalid_arguments"}
        try:
            result = {"ok": True, "result": filesystem_inventory.list_directory(
                args.get("root_id"), args.get("path", ""), args.get("limit", 200))}
        except filesystem_inventory.FileError as exc:
            result = {"ok": False, "error": str(exc), "error_code": exc.code}
    elif executor_type == "process_control":
        if set(args) != {"service_id", "action"}:
            return {"ok": False, "error": "Provide only service_id and action.",
                    "error_code": "invalid_arguments"}
        try:
            result = {"ok": True, "result": process_control.control(args["service_id"], args["action"])}
        except process_control.ControlError as exc:
            result = {"ok": False, "error": str(exc), "error_code": exc.code}
    elif executor_type == "container_control":
        if set(args) != {"container_id", "action"}:
            return {"ok": False, "error": "Provide only container_id and action.",
                    "error_code": "invalid_arguments"}
        try:
            result = {"ok": True, "result": container_control.control(args["container_id"], args["action"])}
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



SUPPORTED_WORKFLOW_BLOCKS = {
    "tool_call", "automation_call", "condition", "switch", "loop", "calculation", "set",
    "delay", "retry", "notification", "return",
}


def workflow_definition_errors(workflow: list, depth: int = 0) -> list[str]:
    if not isinstance(workflow, list):
        return ["workflow must be a list"]
    if depth > 4:
        return ["workflow nesting cannot exceed four levels"]
    errors = []
    for index, step in enumerate(workflow):
        prefix = f"step {index + 1}"
        if not isinstance(step, dict) or step.get("type") not in SUPPORTED_WORKFLOW_BLOCKS:
            errors.append(f"{prefix} has an unsupported block type")
            continue
        kind = step["type"]
        if kind == "automation_call":
            try:
                publications.nested_key(step)
            except publications.PublicationInvalid as exc:
                errors.append(f"{prefix}: {exc}")
            if not isinstance(step.get("args", {}), dict):
                errors.append(f"{prefix} args must be an object")
            if "publication_digest" in step and (not isinstance(step["publication_digest"], str)
                    or not re.fullmatch(r"[a-f0-9]{64}", step["publication_digest"])):
                errors.append(f"{prefix} publication_digest must be a SHA-256 digest")
        if kind == "tool_call":
            if not step.get("tool_id"):
                errors.append(f"{prefix} needs tool_id")
            if not isinstance(step.get("args", {}), dict):
                errors.append(f"{prefix} args must be an object")
        if kind == "set":
            if not isinstance(step.get("name"), str) or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]{0,79}", step.get("name", "")):
                errors.append(f"{prefix} set name must be a variable identifier")
            if "value" not in step:
                errors.append(f"{prefix} set requires value")
        if kind == "calculation":
            if step.get("operation", "add") not in {"add", "subtract", "multiply", "divide", "min", "max"}:
                errors.append(f"{prefix} has an unsupported calculation operation")
            if not isinstance(step.get("values"), list) or not step.get("values"):
                errors.append(f"{prefix} calculation requires values")
        if kind == "condition":
            if "left" not in step and not step.get("field"):
                errors.append(f"{prefix} condition requires left or field")
            if step.get("operator", "equals") not in {
                    "equals", "not_equals", "contains", "in", "gte", "lte", "gt", "lt"}:
                errors.append(f"{prefix} has an unsupported condition operator")
            if "right" not in step and "value" not in step:
                errors.append(f"{prefix} condition requires right or value")
        if kind == "loop":
            if not isinstance(step.get("max_iterations"), int) or not 1 <= step["max_iterations"] <= 20:
                errors.append(f"{prefix} max_iterations must be between 1 and 20")
            if "items" not in step:
                errors.append(f"{prefix} loop requires items")
            errors.extend(workflow_definition_errors(step.get("steps", []), depth + 1))
        if kind == "retry":
            if not isinstance(step.get("max_attempts"), int) or not 1 <= step["max_attempts"] <= 3:
                errors.append(f"{prefix} max_attempts must be between 1 and 3")
            if not isinstance(step.get("step"), dict):
                errors.append(f"{prefix} retry requires one step object")
            errors.extend(workflow_definition_errors([step.get("step")], depth + 1))
        if kind == "condition":
            errors.extend(workflow_definition_errors(step.get("then", []), depth + 1))
            errors.extend(workflow_definition_errors(step.get("else", []), depth + 1))
        if kind == "switch":
            if "value" not in step:
                errors.append(f"{prefix} switch requires value")
            cases = step.get("cases", {})
            if not isinstance(cases, dict) or len(cases) > 10:
                errors.append(f"{prefix} cases must be an object with at most 10 branches")
            else:
                for branch in cases.values():
                    errors.extend(workflow_definition_errors(branch, depth + 1))
            errors.extend(workflow_definition_errors(step.get("default", []), depth + 1))
        if kind == "delay" and (not isinstance(step.get("seconds", 0), (int, float))
                                or not 0 <= step.get("seconds", 0) <= 30):
            errors.append(f"{prefix} delay must be between 0 and 30 seconds")
        if kind == "return" and "value" not in step:
            errors.append(f"{prefix} return requires value")
    return errors


def workflow_tool_ids(workflow: list, block_type: str = "tool_call") -> list[str]:
    ids = []
    if not isinstance(workflow, list):
        return ids
    for step in workflow:
        if not isinstance(step, dict):
            continue
        field = "tool_id" if block_type == "tool_call" else "automation_id"
        if step.get("type") == block_type and isinstance(step.get(field), str):
            ids.append(step[field])
        for key in ("steps", "then", "else", "default"):
            ids.extend(workflow_tool_ids(step.get(key, []), block_type))
        if isinstance(step.get("step"), dict):
            ids.extend(workflow_tool_ids([step["step"]], block_type))
        cases = step.get("cases", {})
        if isinstance(cases, dict):
            for branch in cases.values():
                ids.extend(workflow_tool_ids(branch, block_type))
    return ids


def automation_definition_errors(automation: dict) -> list[str]:
    errors = capability_metadata_errors(automation)
    errors.extend(workflow_definition_errors(automation.get("workflow", [])))
    for tool_id in dict.fromkeys(workflow_tool_ids(automation.get("workflow", []))):
        tool = control_plane.get("tool", tool_id)
        if not tool or tool.get("status") != "active":
            errors.append(f"workflow references unavailable tool '{tool_id}'")
        elif automation.get("authorization") == "auto" and tool.get("authorization") != "auto":
            errors.append(f"auto automation cannot call '{tool_id}' because it requires {tool.get('authorization')}")
    max_steps = automation.get("policy", {}).get("usage_limits", {}).get("max_steps", 100)
    if not isinstance(max_steps, int) or not 1 <= max_steps <= 500:
        errors.append("policy.usage_limits.max_steps must be between 1 and 500")
    return errors


def require_valid_automation_definition(automation: dict):
    errors = automation_definition_errors(automation)
    if errors:
        raise HTTPException(422, {"code": "INVALID_AUTOMATION_DEFINITION",
                                  "message": "; ".join(errors),
                                  "next_action": "Correct the typed workflow before saving"})


def _lookup_path(value, path: str):
    for part in path.split(".") if path else []:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def _workflow_value(value, state: dict):
    if isinstance(value, str) and value.startswith("$args."):
        return _lookup_path(state["args"], value[6:])
    if isinstance(value, str) and value.startswith("$vars."):
        return _lookup_path(state["vars"], value[6:])
    if isinstance(value, str) and value.startswith("$last"):
        return _lookup_path(state.get("last"), value[6:] if value.startswith("$last.") else "")
    if isinstance(value, list):
        return [_workflow_value(item, state) for item in value]
    if isinstance(value, dict):
        return {key: _workflow_value(item, state) for key, item in value.items()}
    return value


def _workflow_compare(actual, operator: str, expected) -> bool:
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        return expected in actual
    if operator in {"gte", "lte", "gt", "lt"}:
        left, right = float(actual), float(expected)
        return {"gte": left >= right, "lte": left <= right, "gt": left > right, "lt": left < right}[operator]
    raise ValueError(f"unsupported operator {operator}")


def _run_workflow_steps(steps: list, state: dict, actor: str, approval_granted: bool):
    for step in steps:
        for frame in (state, *state.get("ancestors", ())):
            frame["count"] += 1
            if frame["count"] > frame["max_steps"]:
                deny("POLICY_DENIED", "Automation exceeded its shared ancestor step ceiling")
            if time.monotonic() - frame["started_at"] > frame["runtime_ceiling"]:
                deny("POLICY_DENIED", "Automation exceeded its shared ancestor runtime ceiling")
        kind = step["type"]
        result = None
        if kind == "tool_call":
            tool = (state["tool_snapshot"].get(step["tool_id"]) if "tool_snapshot" in state
                    else control_plane.get("tool", step["tool_id"]))
            if not tool or tool.get("status") != "active":
                deny("TOOL_UNAVAILABLE", f"Workflow references unavailable tool '{step['tool_id']}'")
            if tool.get("authorization") != "auto" and not approval_granted:
                deny("POLICY_DENIED", f"Automation must require confirmation before calling '{tool['id']}'")
            call_args = {field["name"]: state["args"][field["name"]]
                         for field in tool.get("inputs", []) if field.get("name") in state["args"]}
            call_args.update(_workflow_value(step.get("args", {}), state))
            parent_id = state.get("action_id")
            child_id = ("child_" + hashlib.sha256(
                f"{parent_id}:{state['count']}".encode()).hexdigest()) if parent_id else None
            result = invoke_tool(tool, call_args, actor, approval_granted=approval_granted,
                                 actor_id=state.get("actor_id"), action_id=child_id,
                                 job_id=state.get("job_id"), parent_action_id=parent_id,
                                 publication=state.get("root_publication", state.get("publication")),
                                 authority_scope=state.get("authority_scope"))
            if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
                deny("OUTCOME_UNKNOWN", "A child dispatch is uncertain; this workflow is held", 409)
        elif kind == "automation_call":
            result = _invoke_nested_automation(step, state, actor, approval_granted)
        elif kind == "set":
            state["vars"][step.get("name", "value")] = _workflow_value(step.get("value"), state)
            result = {"code": "VALUE_SET", "name": step.get("name", "value")}
        elif kind == "calculation":
            values = [_workflow_value(value, state) for value in step.get("values", [])]
            operation = step.get("operation", "add")
            if not values or any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in values):
                deny("VALIDATION_ERROR", "Calculation values must resolve to numbers", 422)
            calculated = {
                "add": lambda: sum(values), "subtract": lambda: values[0] - sum(values[1:]),
                "multiply": lambda: __import__("math").prod(values),
                "divide": lambda: values[0] / __import__("math").prod(values[1:]),
                "min": lambda: min(values), "max": lambda: max(values),
            }.get(operation)
            if not calculated:
                deny("VALIDATION_ERROR", f"Unsupported calculation '{operation}'", 422)
            try:
                value = calculated()
            except ZeroDivisionError:
                deny("VALIDATION_ERROR", "Calculation divided by zero", 422)
            state["vars"][step.get("save_as", "calculation")] = value
            result = {"code": "CALCULATED", "result": value}
        elif kind == "condition":
            actual = _workflow_value(step.get("left", f"$args.{step.get('field', '')}"), state)
            expected = _workflow_value(step.get("right", step.get("value")), state)
            try:
                matches = _workflow_compare(actual, step.get("operator", "equals"), expected)
            except (TypeError, ValueError):
                deny("VALIDATION_ERROR", "Condition could not compare its configured values", 422)
            branch = step.get("then", []) if matches else step.get("else", [])
            result = {"code": "CONDITION_MET" if matches else "CONDITION_NOT_MET"}
            final = _run_workflow_steps(branch, state, actor, approval_granted)
            if final is not None:
                return final
            if not matches and not branch and step.get("on_false", "stop") == "stop":
                deny("POLICY_DENIED", "Automation condition was not met")
        elif kind == "switch":
            selected = str(_workflow_value(step.get("value"), state))
            branch = step.get("cases", {}).get(selected, step.get("default", []))
            result = {"code": "SWITCH_SELECTED", "case": selected}
            final = _run_workflow_steps(branch, state, actor, approval_granted)
            if final is not None:
                return final
        elif kind == "loop":
            items = _workflow_value(step.get("items"), state)
            if not isinstance(items, list):
                deny("VALIDATION_ERROR", "Loop items must resolve to an array", 422)
            if len(items) > step["max_iterations"]:
                deny("POLICY_DENIED", "Loop input exceeds its deterministic iteration ceiling")
            previous = state["vars"].get(step.get("item_name", "item"))
            for item in items:
                state["vars"][step.get("item_name", "item")] = item
                final = _run_workflow_steps(step.get("steps", []), state, actor, approval_granted)
                if final is not None:
                    return final
            if previous is not None:
                state["vars"][step.get("item_name", "item")] = previous
            result = {"code": "LOOP_COMPLETE", "iterations": len(items)}
        elif kind == "retry":
            last_error = None
            for attempt in range(step["max_attempts"]):
                try:
                    final = _run_workflow_steps([step["step"]], state, actor, approval_granted)
                    if final is not None:
                        return final
                    last_error = None
                    break
                except HTTPException as exc:
                    last_error = exc
                    if exc.status_code not in {429, 502, 503} or attempt + 1 >= step["max_attempts"]:
                        raise
                    time.sleep(min(float(step.get("delay_seconds", 0)), 5))
            result = {"code": "RETRY_COMPLETE", "attempts": step["max_attempts"] if last_error else attempt + 1}
        elif kind == "delay":
            time.sleep(float(step.get("seconds", 0)))
            result = {"code": "DELAY_COMPLETE", "seconds": step.get("seconds", 0)}
        elif kind == "notification":
            notification = control_plane.create_request("update", step.get("title", "Automation update"),
                str(_workflow_value(step.get("message", "Automation notification"), state)), actor,
                {"automation_id": state["automation_id"]}, "info")
            result = {"code": "NOTIFICATION_CREATED", "request_id": notification["id"]}
        elif kind == "return":
            return {"code": "OK", "result": _workflow_value(step.get("value"), state)}
        state["last"] = result
        state["results"].append({"type": kind, "result": result})
    return None


def _invoke_nested_automation(step: dict, state: dict, actor: str, approval_granted: bool) -> dict:
    publication = (state.get("publication") or {}).get("automations", {}).get(publications.nested_key(step))
    if not publication:
        deny("PUBLICATION_REQUIRED", "Nested calls require a pinned publication", 422)
    definition = publication["definition"]
    if definition.get("authorization", "auto") != "auto" and not approval_granted:
        deny("POLICY_DENIED", "Nested automation requires root owner confirmation", 403)
    args = _workflow_value(step.get("args", {}), state)
    errors = control_plane.validate_inputs(definition.get("inputs", []), args)
    if errors:
        deny("VALIDATION_ERROR", "; ".join(errors), 422)
    action_id = "child_" + hashlib.sha256(f"{state['action_id']}:{state['count']}".encode()).hexdigest()
    enforce_usage_limits("automation", definition, "automation_executed")
    root_publication = state.get("root_publication", state["publication"])
    def authorize(conn):
        require_current_dispatch_authority(conn, state["actor_id"], state["authority_scope"])
        publications.for_execution(conn, root_publication["kind"], root_publication["id"], root_publication["version"])
    record, dispatch = journal.begin(action_id, "automation", definition["id"], args, state["actor_id"],
                                    definition["version"], job_id=state.get("job_id"),
                                    parent_action_id=state["action_id"], authorize=authorize,
                                    publication_digest=publication["digest"])
    if not dispatch:
        result = journal.response(record)
        if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
            deny("OUTCOME_UNKNOWN", "Nested dispatch is uncertain; this workflow is held", 409)
        return result
    limits = definition.get("policy", {}).get("usage_limits", {})
    nested = {"automation_id": definition["id"], "tool_snapshot": publication["tools"],
              "publication": publication, "root_publication": root_publication,
              "authority_scope": state["authority_scope"], "action_id": action_id,
              "job_id": state.get("job_id"), "actor_id": state["actor_id"], "args": args,
              "vars": {}, "last": None, "results": [], "count": 0,
              "ancestors": (state, *state.get("ancestors", ())),
              "max_steps": int(limits.get("max_steps", 100)), "started_at": time.monotonic(),
              "runtime_ceiling": min(int(limits.get("max_runtime_seconds", 30) or 30), 120)}
    try:
        final = _run_workflow_steps(definition.get("workflow", []), nested, actor, approval_granted)
    except Exception:  # noqa: BLE001 - hold any incomplete nested dispatch; never retry it.
        journal.unknown(action_id)
        deny("OUTCOME_UNKNOWN", "Nested workflow is incomplete; reconcile its receipt", 409)
    envelope = {"code": "OK", "message": "Nested automation completed", "result": final,
                "steps": nested["results"], "variables": nested["vars"],
                "publication": {"kind": "automation", "id": definition["id"],
                                "version": publication["version"], "digest": publication["digest"]}}
    record = journal.finish(action_id, envelope)
    control_plane.event("automation_executed", "info", "automation", definition["id"], actor,
                        {"steps": nested["count"], "version": definition["version"]})
    return journal.response(record)


@app.get("/v2/status")
def status(_tier: str = Depends(require_admin)):
    requests = control_plane.list_objects("request")
    return {"lockdown": control_plane.settings().get("lockdown", False),
            "tools": len(control_plane.list_objects("tool")), "automations": len(control_plane.list_objects("automation")),
            "services": len(control_plane.list_objects("service")), "pending_requests": sum(r.get("status") == "pending" for r in requests)}


@app.post("/v2/settings/lockdown")
def set_lockdown(enabled: bool, reason: str = "", _tier: str = Depends(require_admin)):
    return control_plane.set_lockdown(enabled, "admin", reason)


@app.get("/v2/settings")
def get_settings(_tier: str = Depends(require_admin)):
    return {"generation_model": "qwen3:4b", "event_retention_days": 90,
            "default_confirmation_expiry_seconds": 60,
            "producthunt_commercial_use_approved": False, **control_plane.settings()}


@app.put("/v2/settings")
def update_settings(payload: V2Settings, _tier: str = Depends(require_admin)):
    return control_plane.update_settings(payload.model_dump(), "admin")


@app.get("/v2/verification-methods")
def list_verification_methods(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("verification_method")


@app.post("/v2/verification-methods")
def create_verification_method(payload: VerificationMethodCreate, _tier: str = Depends(require_admin)):
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", payload.secret_ref):
        raise HTTPException(422, "secret_ref must be a vault reference name")
    try:
        vault.get_key(payload.secret_ref)
    except KeyError:
        raise HTTPException(422, "secret_ref is not configured in ToolGate")
    method = control_plane.create_verification_method(payload.model_dump())
    control_plane.event("verification_method_created", "info", "verification_method", method["id"], "admin")
    return method


@app.delete("/v2/verification-methods/{method_id}")
def delete_verification_method(method_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("verification_method", method_id):
        raise HTTPException(404, "verification method not found")
    control_plane.event("verification_method_deleted", "warning", "verification_method", method_id, "admin")
    return {"deleted": True, "id": method_id}


@app.post("/v2/verification/callback")
def verification_callback(payload: VerificationCallback,
                          x_toolgate_timestamp: str | None = Header(None, alias="X-ToolGate-Timestamp"),
                          x_toolgate_signature: str | None = Header(None, alias="X-ToolGate-Signature")):
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    method = control_plane.get("verification_method", payload.method_id)
    if not method or method.get("status") != "active" or method.get("method_type") != "signed_callback":
        deny("VERIFICATION_METHOD_INVALID", "Verification method is unavailable", 401)
    try:
        timestamp = int(x_toolgate_timestamp or "")
    except ValueError:
        timestamp = 0
    canonical = json.dumps(payload.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    try:
        secret = vault.get_key(method["secret_ref"])
    except KeyError:
        deny("VERIFICATION_METHOD_INVALID", "Verification method secret is unavailable", 503)
    expected = hmac.new(secret.encode(), f"{timestamp}.{canonical}".encode(), hashlib.sha256).hexdigest()
    valid = abs(int(time.time()) - timestamp) <= 60 and bool(x_toolgate_signature) and hmac.compare_digest(
        x_toolgate_signature.removeprefix("sha256="), expected)
    if not valid:
        control_plane.event("verification_callback_rejected", "critical", "verification_method",
                            method["id"], "callback", {"reason": "invalid signature or timestamp"})
        failures = control_plane.event_count_since("verification_callback_rejected", "verification_method",
                                                   method["id"], 300)
        if failures >= 5:
            control_plane.set_lockdown(True, "system", "repeated invalid verification callbacks")
        deny("CALLBACK_SIGNATURE_INVALID", "Callback signature or timestamp is invalid", 401)
    request = control_plane.get("request", payload.request_id)
    binding = request.get("payload", {}).get("binding", {}) if request else {}
    if not request or request.get("kind") != "verification" or request.get("status") != "pending":
        deny("REQUEST_NOT_PENDING", "Verification request is not pending", 409)
    if not hmac.compare_digest(str(binding.get("nonce", "")), payload.nonce):
        deny("CALLBACK_NONCE_INVALID", "Callback nonce does not match this request", 409)
    if payload.decision not in {"approved", "rejected"}:
        raise HTTPException(422, "decision must be approved or rejected")
    try:
        record = control_plane.decide_request(payload.request_id, payload.decision,
                                              f"callback:{method['name']}")
    except ValueError as exc:
        deny("REQUEST_NOT_PENDING", str(exc), 409, "Refresh the request; do not retry a decided or expired approval")
    if not record:
        deny("REQUEST_NOT_PENDING", "Verification request no longer exists", 409, "Request fresh confirmation")
    control_plane.update_verification_method(method["id"], {"last_seen_at": datetime.now(timezone.utc).isoformat()})
    control_plane.event("verification_callback_accepted", "info", "verification_method",
                        method["id"], "callback", {"request_id": payload.request_id,
                                                    "decision": payload.decision})
    return {"status": record["status"], "request_id": record["id"]}


@app.get("/v2/archives/ai")
def export_ai_archive(_tier: str = Depends(require_admin)):
    return legacy_archive.export()


@app.get("/v2/agent-keys")
def list_agent_keys(_tier: str = Depends(require_admin)):
    return control_plane.list_agent_keys()


@app.post("/v2/agent-keys")
def create_agent_key(payload: AgentKeyCreate, _tier: str = Depends(require_admin)):
    record, raw = control_plane.issue_agent_key(payload.name, payload.scopes)
    return {"key": raw, "record": record}


@app.patch("/v2/agent-keys/{key_id}/scopes")
def update_agent_key_scopes(key_id: str, payload: AgentKeyScopes, _tier: str = Depends(require_admin)):
    record = control_plane.update_agent_key_scopes(key_id, payload.scopes)
    if not record:
        raise HTTPException(404, "agent key not found")
    return record


@app.delete("/v2/agent-keys/{key_id}")
def revoke_agent_key(key_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.revoke_agent_key(key_id):
        raise HTTPException(404, "agent key not found")
    return {"ok": True}


@app.get("/v2/services")
def list_services(_tier: str = Depends(require_admin)):
    tools = control_plane.list_objects("tool")
    automations = control_plane.list_objects("automation")
    return [{**service,
             "linked_tools": [tool["id"] for tool in tools if tool.get("service_id") == service["id"]],
             "linked_automations": [item["id"] for item in automations
                                    if any(step.get("tool_id") in {tool["id"] for tool in tools
                                           if tool.get("service_id") == service["id"]}
                                           for step in item.get("workflow", []) if isinstance(step, dict))]}
            for service in control_plane.list_objects("service")]


@app.post("/v2/services")
def create_service(payload: V2Service, _tier: str = Depends(require_admin)):
    service = control_plane.create_service(payload.model_dump())
    control_plane.event("service_saved", "info", "service", service["id"], "admin")
    return service


@app.post("/v2/services/{service_id}/check")
def check_service(service_id: str, _tier: str = Depends(require_admin)):
    service = control_plane.get("service", service_id)
    if not service:
        raise HTTPException(404, "service not found")
    health_url = service.get("destination_policy", {}).get("health_url")
    if not isinstance(health_url, str):
        raise HTTPException(422, "service has no health_url")
    parsed = urlsplit(health_url)
    allowed_internal = parsed.hostname in {"memorygate-api", "memorygate-ollama"} and parsed.scheme == "http"
    allowed_public = public_url(health_url)
    if not (allowed_internal or allowed_public):
        deny("DESTINATION_DENIED", "Service health destination is not allowed")
    try:
        if allowed_public:
            with public_client(timeout=10) as client:
                response = client.get(health_url)
        else:
            response = httpx.get(health_url, timeout=10, follow_redirects=False)
        healthy = 200 <= response.status_code < 300
    except httpx.HTTPError:
        healthy = False
    updated = control_plane.update_service(service_id, {
        "health": "healthy" if healthy else "unhealthy",
        "last_health_check_at": datetime.now(timezone.utc).isoformat(),
    })
    control_plane.event("service_health_checked", "info" if healthy else "warning",
                        "service", service_id, "admin", {"healthy": healthy})
    return updated


@app.get("/v2/tools")
def list_tools(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("tool")


@app.get("/v2/tools/{tool_id}")
def get_tool(tool_id: str, _tier: str = Depends(require_admin)):
    tool = control_plane.get("tool", tool_id)
    if not tool:
        raise HTTPException(404, "tool not found")
    return tool


@app.get("/v2/agent/tools")
def agent_tools(agent: dict = Depends(require_agent)):
    return [tool for tool in control_plane.list_objects("tool") if tool.get("status") == "active" and control_plane.is_scoped(agent, tool["id"])]


@app.get("/v2/agent/status")
def agent_status(agent: dict = Depends(require_agent)):
    return {"code": "OK", "message": "ToolGate is online", "id": agent["id"], "agent": agent["name"],
            "scopes": agent.get("scopes", []), "lockdown": control_plane.settings().get("lockdown", False)}


@app.get("/v2/agent/tools/{tool_id}")
def agent_tool_info(tool_id: str, agent: dict = Depends(require_agent)):
    tool = control_plane.get("tool", tool_id)
    if not tool or tool.get("status") != "active" or not control_plane.is_scoped(agent, tool_id):
        raise HTTPException(404, "tool not found or not permitted")
    return tool


def _port_review_authority(agent):
    tool = control_plane.get("tool", "system.port-control")
    if (not control_plane.is_scoped(agent, "system.port-control") or not tool
            or tool.get("status") != "active" or tool.get("authorization") != "owner_confirmation"
            or tool.get("execution") != {"type": "port_control"}):
        deny("POLICY_DENIED", "Active port replacement scope is required", 403)
    with control_plane._conn() as conn:
        require_current_dispatch_authority(conn, agent["id"], "system.port-control")
    return tool


@app.post("/v2/agent/system/port-reviews")
def create_port_review(payload: PortReviewRequest, agent: dict = Depends(require_agent)):
    tool = _port_review_authority(agent)
    enforce_usage_limits("tool", tool, "port_review_created")
    try:
        replacement = port_control.inspect_review(
            payload.container_id, payload.operation,
            mapping=payload.mapping.model_dump() if payload.mapping else None,
            original=payload.original.model_dump() if payload.original else None,
        )
        _port_review_authority(agent)
        result = port_reviews.create(agent["id"], replacement)
    except (container_control.ControlError, PlanError, port_reviews.ReviewError) as exc:
        deny("REVIEW_UNAVAILABLE", str(exc), 422)
    control_plane.event("port_review_created", "info", "tool", "system.port-control", agent["name"])
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/port-reviews/{review_id}")
def get_port_review(review_id: str, agent: dict = Depends(require_agent)):
    _port_review_authority(agent)
    try:
        result = port_reviews.get(review_id, agent["id"])
    except port_reviews.ReviewError:
        deny("REVIEW_UNAVAILABLE", "Port review is unavailable", 404)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/port-recovery/{action_id:path}")
def inspect_port_recovery(action_id: str, agent: dict = Depends(require_agent)):
    _port_review_authority(agent)
    try:
        result = port_recovery.inspect(action_id, agent["id"])
        _port_review_authority(agent)
    except (port_recovery.RecoveryError, ValueError):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery evidence is unavailable", 409)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


class PortFinalizationRequest(BaseModel):
    model_config = {"extra": "forbid"}
    action_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:/-]+$")
    approval_request_id: str | None = Field(default=None, min_length=1, max_length=160)


@app.post("/v2/agent/system/port-finalizations")
def finalize_port_recovery(payload: PortFinalizationRequest, agent: Annotated[dict, Depends(require_agent)]):
    tool = _port_review_authority(agent)
    parent = journal.get(payload.action_id)
    if (not parent or parent["actor_id"] != agent["id"] or parent["subject_type"] != "tool"
            or parent["subject_id"] != "system.port-control"):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery is unavailable", 409)
    # Lost recovery acknowledgements read the immutable receipt without another effect.
    if parent["status"] == "completed":
        return JSONResponse(journal.response(parent), headers={"Cache-Control": "no-store"})
    args = {"operation": "recover_verified_receipt", "action_id": payload.action_id,
            "fingerprint": parent["fingerprint"]}
    try:
        receipt = port_finalization.preview(payload.action_id, agent["id"])
        if not payload.approval_request_id:
            enforce_usage_limits("tool", tool, "port_finalization_requested")
            request = control_plane.create_verification_request(
                "Recover verified port replacement receipt",
                "Restore the recorded successful result and release its reservation. "
                "No container changes will run. Recovery may recheck Docker inspection. " + json.dumps(receipt),
                agent["name"], "tool", "system.port-control", args,
                tool.get("version"), 60, agent["id"])
            control_plane.event("port_finalization_requested", "info", "tool", "system.port-control", agent["name"])
            return JSONResponse({"code": "CONFIRMATION_REQUIRED", "request_id": request["id"],
                                 "expires_at": request["payload"]["binding"]["expires_at"]},
                                headers={"Cache-Control": "no-store"})

        def authorize(conn):
            require_current_dispatch_authority(conn, agent["id"], "system.port-control")
            row = conn.execute("SELECT * FROM v2_objects WHERE kind='tool' AND id='system.port-control'").fetchone()
            current = control_plane._row(row) if row else {}
            if (current.get("version") != tool.get("version") or current.get("status") != "active"
                    or current.get("authorization") != "owner_confirmation"
                    or current.get("execution") != {"type": "port_control"}):
                deny("POLICY_DENIED", "Port replacement policy changed", 403)
            approved, reason = control_plane.consume_verification_in_transaction(
                conn, payload.approval_request_id, "tool", "system.port-control",
                args, tool.get("version"), agent["name"], agent["id"])
            if not approved:
                deny("APPROVAL_INVALID", reason, 409)

        record = port_finalization.finalize(payload.action_id, agent["id"], authorize=authorize)
    except (ValueError, container_control.ControlError):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery is unavailable", 409)
    return JSONResponse(journal.response(record), headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/targets")
def agent_system_targets(agent: dict = Depends(require_agent)):
    tool_id = "system.container-control"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Managed container scope is required", 403)
    result = {"kind": "configured-targets", "status": "configured", "containers": [],
              "actions": [], "requiresApproval": True, "observed": False,
              "source": "toolgate/container-control"}
    tool = control_plane.get("tool", tool_id)
    if control_plane.settings().get("lockdown"):
        result["status"] = "locked_down"
    elif (not tool or tool.get("status") != "active"
          or tool.get("authorization") != "owner_confirmation"
          or tool.get("execution") != {"type": "container_control"}):
        result["status"] = "disabled"
    else:
        try:
            result["containers"] = container_control.targets()
            result["actions"] = ["start", "stop", "restart"]
        except container_control.ControlError as exc:
            result["status"] = exc.code
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/services")
def agent_system_services(agent: dict = Depends(require_agent)):
    tool_id = "system.process-control"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Managed service scope is required", 403)
    result = {"kind": "configured-targets", "status": "configured", "services": [],
              "actions": [], "requiresApproval": True, "observed": False,
              "source": "toolgate/process-control"}
    tool = control_plane.get("tool", tool_id)
    if control_plane.settings().get("lockdown"):
        result["status"] = "locked_down"
    elif (not tool or tool.get("status") != "active"
          or tool.get("authorization") != "owner_confirmation"
          or tool.get("execution") != {"type": "process_control"}):
        result["status"] = "disabled"
    else:
        try:
            result["services"] = process_control.targets()
            result["actions"] = ["start", "stop", "restart"]
        except process_control.ControlError as exc:
            result["status"] = exc.code
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/file-roots")
def agent_file_roots(agent: dict = Depends(require_agent)):
    tool_id = "system.files-list"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Directory listing scope is required", 403)
    tool = control_plane.get("tool", tool_id)
    if (control_plane.settings().get("lockdown") or not tool or tool.get("status") != "active"
            or tool.get("authorization") == "blocked"
            or tool.get("execution") != {"type": "filesystem_inventory"}):
        return JSONResponse({"mode": "unavailable", "code": "disabled", "roots": []},
                            headers={"Cache-Control": "no-store"})
    try:
        result = filesystem_inventory.roots()
    except filesystem_inventory.FileError as exc:
        result = {"mode": "unavailable", "code": exc.code, "roots": []}
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.post("/v2/tools")
def create_tool(payload: V2Tool, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_tool_definition(body)
    tool = control_plane.create_tool(body)
    control_plane.event("tool_saved", "info", "tool", tool["id"], "admin")
    return tool


@app.put("/v2/tools/{tool_id}")
def update_tool(tool_id: str, payload: V2Tool, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_tool_definition(body)
    tool = control_plane.update_tool(tool_id, body)
    if not tool:
        raise HTTPException(404, "tool not found")
    control_plane.event("tool_updated", "info", "tool", tool_id, "admin", {"version": tool["version"]})
    return tool


@app.delete("/v2/tools/{tool_id}")
def delete_tool(tool_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("tool", tool_id):
        raise HTTPException(404, "tool not found")
    control_plane.event("tool_deleted", "warning", "tool", tool_id, "admin")
    return {"deleted": True, "id": tool_id}


@app.post("/v2/tools/{tool_id}/invoke")
def run_tool(tool_id: str, payload: V2Invoke, agent: dict = Depends(require_agent)):
    publication = _requested_publication("tool", tool_id, payload)
    tool = publication["definition"] if publication else control_plane.get("tool", tool_id)
    if not tool:
        deny("TOOL_UNAVAILABLE", f"Tool '{tool_id}' was not found", 404, "Run `toolgate tool list`")
    if tool.get("status") != "active" or not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Your agent key is not allowed to use this tool", 403, "Ask the owner for scope")
    return invoke_tool(tool, payload.args, agent["name"], approval_request_id=payload.approval_request_id,
                       actor_id=agent["id"], action_id=payload.action_id, job_id=payload.job_id,
                       publication=publication, authority_scope=tool_id)


def _requested_publication(kind: str, obj_id: str, payload: V2Invoke) -> dict | None:
    if payload.published_version is None:
        if payload.expected_publication_digest is not None:
            deny("PUBLICATION_REQUIRED", "A publication digest requires published_version", 422)
        return None
    if not payload.action_id:
        deny("ACTION_ID_REQUIRED", "Published runs require a stable action_id", 422)
    with control_plane._conn() as conn:
        publication = publications.for_execution(conn, kind, obj_id, payload.published_version)
        if (payload.expected_publication_digest is not None
                and not secrets.compare_digest(payload.expected_publication_digest, publication["digest"])):
            deny("PUBLICATION_MISMATCH", "The selected publication does not match the expected digest", 409)
        return publication


def _publish_definition(kind: str, obj_id: str, payload: V2Publish):
    validator = require_valid_tool_definition if kind == "tool" else require_valid_automation_definition
    try:
        result = publications.publish(kind, obj_id, payload.expected_version, validate=validator,
                                      validate_tool=require_valid_tool_definition)
    except publications.PublicationInvalid as exc:
        raise HTTPException(422, {"code": "INVALID_PUBLICATION", "message": str(exc)}) from exc
    if result is None:
        raise HTTPException(404, "definition not found")
    return result


@app.post("/v2/tools/{tool_id}/publish", dependencies=[Depends(require_admin)])
def publish_tool(tool_id: str, payload: V2Publish):
    return _publish_definition("tool", tool_id, payload)


@app.post("/v2/automations/{automation_id}/publish", dependencies=[Depends(require_admin)])
def publish_automation(automation_id: str, payload: V2Publish):
    return _publish_definition("automation", automation_id, payload)


@app.get("/v2/tools/{tool_id}/versions", dependencies=[Depends(require_admin)])
def tool_versions(tool_id: str):
    return publications.history("tool", tool_id)


@app.get("/v2/automations/{automation_id}/versions", dependencies=[Depends(require_admin)])
def automation_versions(automation_id: str):
    return publications.history("automation", automation_id)


def _definition_version(kind: str, obj_id: str, version: int, published: bool):
    result = publications.get(kind, obj_id, version, published=published)
    if result is None:
        raise HTTPException(404, "definition version not found")
    return result


@app.get("/v2/tools/{tool_id}/versions/{version}", dependencies=[Depends(require_admin)])
def tool_version(tool_id: str, version: int, published: bool = False):
    return _definition_version("tool", tool_id, version, published)


@app.get("/v2/automations/{automation_id}/versions/{version}", dependencies=[Depends(require_admin)])
def automation_version(automation_id: str, version: int, published: bool = False):
    return _definition_version("automation", automation_id, version, published)


@app.get("/v2/automations")
def list_automations(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("automation")


@app.get("/v2/actions")
def list_actions(_tier: str = Depends(require_admin)):
    return {"results": journal.list_actions()}


@app.get("/v2/agent/spending/jobs/{job_id}")
def agent_spending_job(job_id: str, agent: dict = Depends(require_agent)):
    result = spending.agent_job(job_id, agent["id"])
    if result is None:
        raise HTTPException(404, "budget not found")
    return result


@app.get("/v2/agent/actions/{action_id:path}")
def agent_action(action_id: str, agent: dict = Depends(require_agent)):
    record = journal.get(action_id)
    if not record or record["actor_id"] != agent["id"]:
        raise HTTPException(404, "action not found")
    return journal.response(record)


@app.get("/v2/automations/{automation_id}")
def get_automation(automation_id: str, _tier: str = Depends(require_admin)):
    automation = control_plane.get("automation", automation_id)
    if not automation:
        raise HTTPException(404, "automation not found")
    return automation


@app.get("/v2/agent/automations")
def agent_automations(agent: dict = Depends(require_agent)):
    return [item for item in control_plane.list_objects("automation") if item.get("status") == "active" and control_plane.is_scoped(agent, f"automation:{item['id']}")]


@app.get("/v2/agent/automations/{automation_id}")
def agent_automation_info(automation_id: str, agent: dict = Depends(require_agent)):
    item = control_plane.get("automation", automation_id)
    if not item or item.get("status") != "active" or not control_plane.is_scoped(agent, f"automation:{automation_id}"):
        raise HTTPException(404, "automation not found or not permitted")
    return item


@app.post("/v2/automations")
def create_automation(payload: V2Automation, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_automation_definition(body)
    automation = control_plane.create_automation(body)
    control_plane.event("automation_saved", "info", "automation", automation["id"], "admin")
    return automation


@app.put("/v2/automations/{automation_id}")
def update_automation(automation_id: str, payload: V2Automation, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_automation_definition(body)
    automation = control_plane.update_automation(automation_id, body)
    if not automation:
        raise HTTPException(404, "automation not found")
    control_plane.event("automation_updated", "info", "automation", automation_id, "admin", {"version": automation["version"]})
    return automation


@app.delete("/v2/automations/{automation_id}")
def delete_automation(automation_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("automation", automation_id):
        raise HTTPException(404, "automation not found")
    control_plane.event("automation_deleted", "warning", "automation", automation_id, "admin")
    return {"deleted": True, "id": automation_id}


@app.post("/v2/automations/{automation_id}/run")
def run_automation(automation_id: str, payload: V2Invoke, agent: dict = Depends(require_agent)):
    publication = _requested_publication("automation", automation_id, payload)
    publication_digest = publication["digest"] if publication else None
    automation = publication["definition"] if publication else control_plane.get("automation", automation_id)
    if not automation or automation.get("status") != "active":
        deny("TOOL_UNAVAILABLE", "Automation is not active", 404)
    if not control_plane.is_scoped(agent, f"automation:{automation_id}"):
        deny("POLICY_DENIED", "Your agent key is not allowed to run this automation")
    if not publication and workflow_tool_ids(automation.get("workflow", []), "automation_call"):
        deny("PUBLICATION_REQUIRED", "Nested automation calls require an explicit published root version", 422)
    authority_scope = (tuple(dict.fromkeys(f"automation:{member['id']}" for member in publications.members(publication)))
                       if publication else (f"automation:{automation_id}",))
    if not all(control_plane.is_scoped(agent, scope) for scope in authority_scope):
        deny("POLICY_DENIED", "The agent needs every pinned nested automation scope", 403)
    if not payload.action_id:
        deny("ACTION_ID_REQUIRED", "Supply a stable action_id for this workflow run", 422)
    try:
        previous = journal.existing(payload.action_id, "automation", automation_id, payload.args,
                                    agent["id"], payload.job_id, publication_digest=publication_digest)
    except (journal.ExecutionConflict, ValueError) as exc:
        deny("ACTION_CONFLICT", str(exc), 409)
    if previous:
        return journal.response(previous)
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    errors = control_plane.validate_inputs(automation.get("inputs", []), payload.args)
    if errors:
        deny("VALIDATION_ERROR", "; ".join(errors), 422)
    authorization = automation.get("authorization", "auto")
    if authorization == "blocked":
        control_plane.event("execution_blocked", "warning", "automation", automation_id, agent["name"], {"code": "POLICY_DENIED"})
        deny("POLICY_DENIED", "This automation is permanently blocked by its owner policy")
    approval_granted = False
    tool_snapshot = {}
    if authorization != "auto":
        if not payload.approval_request_id:
            expiry = int(control_plane.settings().get("default_confirmation_expiry_seconds", 60))
            request = control_plane.create_verification_request(
                f"Run {automation['name']}",
                "Owner confirmation is required for this exact immutable automation run.",
                agent["name"], "automation", automation_id, payload.args,
                automation.get("version"), expiry, agent["id"], publication_digest=publication_digest)
            return {"code": "CONFIRMATION_REQUIRED", "message": "Automation queued for owner review",
                    "request_id": request["id"], "expires_at": request["payload"]["binding"]["expires_at"],
                    "next_action": f"After approval, retry with --approval-request-id {request['id']}"}
    enforce_usage_limits("automation", automation, "automation_executed")
    limits = automation.get("policy", {}).get("usage_limits", {})
    def authorize(conn):
        nonlocal approval_granted, tool_snapshot
        require_current_dispatch_authority(conn, agent["id"], authority_scope)
        if publication:
            tool_snapshot = publications.for_execution(conn, "automation", automation_id, publication["version"])["tools"]
        else:
            tool_snapshot = control_plane.automation_tool_snapshot(conn, automation_id, automation.get("version"))
        if authorization != "auto":
            approval_granted, reason = control_plane.consume_verification_in_transaction(
                conn, payload.approval_request_id, "automation", automation_id, payload.args,
                automation.get("version"), agent["name"], agent["id"], publication_digest=publication_digest)
            if not approval_granted:
                deny("APPROVAL_INVALID", reason, 409)
    try:
        record, dispatch = journal.begin(payload.action_id, "automation", automation_id,
                                         payload.args, agent["id"], automation.get("version"),
                                         job_id=payload.job_id, authorize=authorize, publication_digest=publication_digest)
    except (journal.ExecutionConflict, ValueError) as exc:
        deny("ACTION_CONFLICT", str(exc), 409)
    if not dispatch:
        return journal.response(record)
    state = {"automation_id": automation_id, "tool_snapshot": tool_snapshot, "action_id": payload.action_id,
             "publication": publication,
             "authority_scope": authority_scope,
             "job_id": payload.job_id, "actor_id": agent["id"], "args": payload.args, "vars": {}, "last": None,
             "results": [], "count": 0, "max_steps": int(limits.get("max_steps", 100)),
             "started_at": time.monotonic(),
             "runtime_ceiling": min(int(limits.get("max_runtime_seconds", 30) or 30), 120)}
    try:
        final = _run_workflow_steps(automation.get("workflow", []), state, agent["name"], approval_granted)
    except Exception:
        journal.unknown(payload.action_id)
        return journal.response(journal.get(payload.action_id))
    envelope = {"code": "OK", "message": "Automation completed", "result": final,
                "steps": state["results"], "variables": state["vars"]}
    if publication:
        envelope["publication"] = {"kind": "automation", "id": automation_id,
                                   "version": publication["version"], "digest": publication_digest}
    record = journal.finish(payload.action_id, envelope)
    control_plane.event("automation_executed", "info", "automation", automation_id, agent["name"],
                        {"steps": state["count"], "version": automation.get("version")})
    return journal.response(record)


@app.get("/v2/requests")
def list_requests(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("request")


@app.get("/v2/owner/requests", dependencies=[Depends(require_owner)])
def owner_requests(limit: int = Query(default=50, ge=1, le=200),
                   cursor: str | None = Query(default=None, min_length=1, max_length=128,
                                             pattern=r"^[A-Za-z0-9_-]+$")):
    return owner_channel.list_requests(limit, cursor)


@app.get("/v2/owner/requests/{request_id}", dependencies=[Depends(require_owner)])
def owner_request(request_id: str):
    return owner_channel.get(request_id)


@app.post("/v2/owner/requests/{request_id}/decision", dependencies=[Depends(require_owner)])
def owner_decision(request_id: str, payload: OwnerDecision):
    return owner_channel.decide(request_id, payload.status, payload.note)


@app.post("/v2/requests")
def create_agent_request(payload: V2Request, agent: dict = Depends(require_agent)):
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    if payload.kind == "ai_draft":
        deny("AI_DRAFT_RETIRED", "AI drafts belong in Pi", 410, "Use the owner tools API to register a reviewed capability")
    try:
        return control_plane.create_request(payload.kind, payload.title, payload.details, agent["name"],
                                            {**payload.payload, "created_by_agent_key": agent["id"]}, payload.severity)
    except ValueError as exc:
        deny("REQUEST_KIND_INVALID", str(exc), 422, "Invoke the exact tool or automation to request confirmation")


@app.get("/v2/agent/requests/{request_id}")
def agent_request_status(request_id: str, agent: dict = Depends(require_agent)):
    request = control_plane.get("request", request_id)
    if not request or request.get("payload", {}).get("created_by_agent_key") != agent["id"]:
        raise HTTPException(404, "request not found")
    return {"id": request["id"], "kind": request["kind"], "status": request["status"],
            "title": request["title"], "created_at": request["created_at"],
            "decision": request.get("decision")}


@app.post("/v2/admin/requests")
def create_admin_request(payload: V2Request, _tier: str = Depends(require_admin)):
    if payload.kind == "ai_draft":
        deny("AI_DRAFT_RETIRED", "AI drafts belong in Pi", 410, "Use the owner tools API to register a reviewed capability")
    try:
        return control_plane.create_request(payload.kind, payload.title, payload.details, "admin", payload.payload, payload.severity)
    except ValueError as exc:
        deny("REQUEST_KIND_INVALID", str(exc), 422, "Invoke the exact tool or automation to request confirmation")


@app.post("/v2/requests/{request_id}/decision")
def decide_request(request_id: str, payload: V2RequestDecision, _tier: str = Depends(require_admin)):
    if payload.status not in {"approved", "rejected", "dismissed"}:
        raise HTTPException(400, "status must be approved, rejected, or dismissed")
    existing = control_plane.get("request", request_id)
    if existing and existing.get("kind") == "ai_draft":
        deny("AI_DRAFT_RETIRED", "Legacy AI drafts are read-only history", 410,
             "Export /v2/archives/ai and recreate the capability through the owner tools API")
    try:
        record = control_plane.decide_request(request_id, payload.status, "admin", payload.note)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    if not record:
        raise HTTPException(404, "request not found")
    return record


@app.get("/v2/events")
def list_events(limit: int = 100, _tier: str = Depends(require_admin)):
    return control_plane.events(limit)


@app.get("/v2/agent/events")
def agent_events(limit: int = 50, _agent: dict = Depends(require_agent)):
    return [{key: event[key] for key in ("id", "event_type", "severity", "subject_type", "subject_id", "created_at")} for event in control_plane.events(limit)]


class SpendPolicy(BaseModel):
    enabled: StrictBool
    cumulative_cap: StrictInt
    max_job_cap: StrictInt


class SpendPrice(BaseModel):
    input_per_million: StrictInt
    output_per_million: StrictInt
    valid_until: float
    source: str


class SpendJob(BaseModel):
    actor_id: str
    root_action_id: str
    cap: StrictInt


@app.get("/v2/spending")
def spending_status(_tier: str = Depends(require_admin)):
    return spending.status()


@app.put("/v2/spending/policy")
def spending_policy(payload: SpendPolicy, _tier: str = Depends(require_admin)):
    try:
        return spending.configure(**payload.model_dump())
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@app.put("/v2/spending/prices/{model}")
def spending_price(model: str, payload: SpendPrice, _tier: str = Depends(require_admin)):
    try:
        spending.set_price(model, **payload.model_dump())
        return {"model": model, **payload.model_dump()}
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@app.post("/v2/spending/jobs")
def spending_job(payload: SpendJob, _tier: str = Depends(require_admin)):
    try:
        return spending.create_job(**payload.model_dump())
    except (spending.BudgetDenied, sqlite3.IntegrityError) as exc:
        deny("BUDGET_DENIED", str(exc), 422)


class SpendAllowance(BaseModel):
    model_config = {"extra": "forbid"}
    actor_id: str
    target: dict
    per_run_cap: StrictInt
    total_cap: StrictInt
    max_runs: StrictInt
    expires_at: float


class AllowanceAllocation(BaseModel):
    model_config = {"extra": "forbid"}
    root_action_id: str
    target: dict


@app.post("/v2/spending/allowances")
def create_spending_allowance(payload: SpendAllowance, _tier: str = Depends(require_admin)):
    try:
        return JSONResponse(spending_allowances.create(**payload.model_dump()),
                            headers={"Cache-Control": "no-store"})
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@app.get("/v2/spending/allowances/{allowance_id}")
def get_spending_allowance(allowance_id: str, _tier: str = Depends(require_admin)):
    value = spending_allowances.get(allowance_id)
    if value is None:
        deny("NOT_FOUND", "Allowance not found", 404)
    return JSONResponse(value, headers={"Cache-Control": "no-store"})


@app.post("/v2/spending/allowances/{allowance_id}/revoke")
def revoke_spending_allowance(allowance_id: str, _tier: str = Depends(require_admin)):
    try:
        return JSONResponse(spending_allowances.revoke(allowance_id),
                            headers={"Cache-Control": "no-store"})
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@app.post("/v2/agent/spending/allowances/{allowance_id}/allocate")
def allocate_spending_allowance(allowance_id: str, payload: AllowanceAllocation,
                               agent: dict = Depends(require_agent)):
    kind, identity = payload.target.get("kind"), payload.target.get("id")
    scope = f"automation:{identity}" if kind == "automation" else identity
    if not isinstance(scope, str) or not control_plane.is_scoped(agent, scope):
        deny("FORBIDDEN", "Target is outside this agent's scope", 403)
    try:
        value = spending_allowances.allocate(allowance_id, agent["id"],
            payload.root_action_id, payload.target)
        return JSONResponse(value, headers={"Cache-Control": "no-store"})
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


class ReservationRelease(BaseModel):
    confirmed_not_executed: StrictBool
    evidence: str


@app.post("/v2/spending/releases/{action_id:path}")
def release_reservation(action_id: str, payload: ReservationRelease, _tier: str = Depends(require_admin)):
    try:
        return spending.release_hold(action_id, payload.evidence, payload.confirmed_not_executed)
    except spending.BudgetDenied as exc:
        deny("RELEASE_DENIED", str(exc), 409)
