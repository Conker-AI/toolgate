"""Health endpoint with cached dependency probes."""

import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter

from toolgate.api.version import SERVICE_VERSION
from toolgate.core import control_plane, vault
from toolgate.executors import pi_inference

router = APIRouter()


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


def _probe_http(
    url: str, path: str, expected_service: str | None = None, relay_status: bool = True
) -> dict:
    """Coarse reachability of one upstream. Never returns the host or the body.

    With `expected_service`, the answer must be that module's health document; `relay_status`
    then decides whether its own status becomes this check's status or only its shape counts.
    """
    try:
        response = httpx.get(f"{url.rstrip('/')}{path}", timeout=HEALTH_PROBE_TIMEOUT_SECONDS)
    except (httpx.HTTPError, httpx.InvalidURL, UnicodeError) as exc:  # a malformed address too
        # "unavailable" is the contract's word for configured-but-not-working;
        # the exception class carries why. Status vocabulary is fixed so one
        # dashboard can render every module - nuance belongs in reason.
        return {"status": "unavailable", "reason": type(exc).__name__}
    if response.status_code >= 500:
        return {"status": "degraded", "reason": "upstream_5xx"}
    if not 200 <= response.status_code < 300:
        return {"status": "unavailable", "reason": "upstream_http_error"}
    if expected_service is not None:
        try:
            body = response.json()
        except ValueError:
            return {"status": "unavailable", "reason": "invalid_health_response"}
        if (
            not isinstance(body, dict)
            or body.get("service") != expected_service
            or body.get("status") not in {"ok", "degraded", "unavailable"}
        ):
            return {"status": "unavailable", "reason": "invalid_health_response"}
        if relay_status and body["status"] != "ok":
            return {"status": body["status"], "reason": "upstream_reports_" + body["status"]}
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
            tool.get("status") == "active"
            and tool.get("execution", {}).get("type") == "ollama_generate"
            for tool in control_plane.list_objects("tool")
        )
    except (sqlite3.Error, OSError, ValueError):
        settings = {}
        generation_configured = False

    # name -> the arguments of _probe_http for that check
    probes = {
        "searxng": (
            settings.get("research_searxng_url", "http://toolgate-searxng:8080"),
            "/healthz",
        )
    }
    if _memorygate_configured():
        probes["memorygate"] = (
            os.environ.get("MEMORYGATE_URL", "http://memorygate-api:8020"),
            "/health",
            "memorygate",
        )
    else:
        checks["memorygate"] = {"status": "not_configured"}

    pi = pi_inference.configured()
    if pi:
        # AI tools write through Pi's tool-text role, so Pi is the generation path and the model
        # behind the role (local or hosted) is Pi's to report. Only whether Pi answers as Pi
        # counts: Pi's own degraded parts (speech, memory) are not ToolGate's generation. The
        # check sends no key and makes no model call.
        probes["generation"] = (pi[0], "/health", "pi", False)
    elif generation_configured:
        probes["generation"] = (
            settings.get("generation_url", "http://memorygate-ollama:11434"),
            "/api/tags",
        )
    else:
        checks["generation"] = {"status": "not_configured"}

    with ThreadPoolExecutor(max_workers=len(probes)) as pool:
        results = {name: pool.submit(_probe_http, *probe) for name, probe in probes.items()}
    checks.update({name: future.result() for name, future in results.items()})
    if "generation" in results:
        checks["generation"]["via"] = "pi" if pi else "ollama"

    failing = sorted(
        name for name, check in checks.items() if check["status"] not in _HEALTHY_STATUSES
    )
    return {
        "status": "degraded" if failing else "ok",
        "degraded": failing,
        "checks": checks,
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.get("/health")
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
    return {
        "service": "toolgate",
        "version": SERVICE_VERSION,
        "status": snapshot["status"],
        "degraded": snapshot["degraded"],
        "checks": snapshot["checks"],
        "checked_at": snapshot["checked_at"],
        "age_seconds": round(now - snapshot["probed_at"], 1),
    }
