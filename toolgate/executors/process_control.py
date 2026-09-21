"""Manage explicitly allowlisted systemd services, never arbitrary PIDs or commands."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time

UNIT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:@[A-Za-z0-9_][A-Za-z0-9_.-]*)?\.service\Z")
MAX_BYTES = 16384
DEADLINE_SECONDS = 30.0
PROPERTIES = "Id,LoadState,ActiveState,SubState,MainPID"
ACTIVE = {"active", "reloading", "inactive", "failed", "activating", "deactivating",
          "maintenance", "refreshing"}


class ControlError(RuntimeError):
    def __init__(self, code):
        self.code = code
        self.status = 422 if code == "invalid_arguments" else 403 if code == "not_managed" else 503
        super().__init__({
            "invalid_arguments": "Invalid managed service lifecycle arguments.",
            "not_configured": "Managed service control is not configured.",
            "invalid_configuration": "Managed service configuration is invalid.",
            "not_managed": "This service is not authorized for lifecycle control.",
            "configuration_changed": "Service control configuration changed before dispatch.",
            "unavailable": "Service inspection is unavailable.",
            "invalid_response": "Service inspection returned an invalid response.",
            "response_limit": "Service inspection exceeded its response limit.",
            "deadline": "Service control exceeded its deadline before dispatch.",
        }[code])

    @property
    def message(self):
        return str(self)


class OutcomeUnknown(RuntimeError):
    code = "process_outcome_unknown"
    status = 502
    dispatched = True

    def __init__(self):
        super().__init__("Service action may have taken effect; inspect before taking further action.")

    @property
    def message(self):
        return str(self)


def _valid_unit(value):
    return isinstance(value, str) and len(value) <= 255 and UNIT.fullmatch(value) is not None


def _identity(value):
    if not isinstance(value, str) or ":" not in value:
        raise ControlError("invalid_arguments")
    scope, unit = value.split(":", 1)
    if scope not in {"user", "system"} or not _valid_unit(unit):
        raise ControlError("invalid_arguments")
    return scope, unit


def _configuration(service_id=None):
    scope = os.environ.get("TOOLGATE_SYSTEMD_SCOPE", "")
    raw = os.environ.get("TOOLGATE_MANAGED_SERVICE_UNITS", "")
    if not scope or not raw:
        raise ControlError("not_configured")
    try:
        if scope not in {"user", "system"} or len(raw) > 600000:
            raise ValueError()
        units = json.loads(raw)
        if not isinstance(units, list) or len(units) > 2000 or any(not _valid_unit(u) for u in units):
            raise ValueError()
    except (ValueError, RecursionError):
        raise ControlError("invalid_configuration") from None
    if service_id is not None:
        requested_scope, unit = _identity(service_id)
        if requested_scope != scope or unit not in units:
            raise ControlError("not_managed")
    return scope, frozenset(units)


def targets():
    """Configuration only; no systemctl, status inference, or inherited environment."""
    scope, units = _configuration()
    return sorted(f"{scope}:{unit}" for unit in units)


def _environment(scope):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0"}
    if scope == "user":
        # Use the process's actual effective identity, not caller/inherited bus destinations.
        uid = os.geteuid()
        env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
    return env


def _run(runner, scope, arguments, env, deadline, *, inspect=False):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ControlError("deadline")
    result = runner(
        ["/usr/bin/systemctl", f"--{scope}", "--no-pager", "--no-ask-password", *arguments],
        stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE if inspect else subprocess.DEVNULL,
        env=env, shell=False, timeout=remaining, check=False, close_fds=True,
    )
    if time.monotonic() > deadline:
        raise ControlError("deadline")
    if result.returncode != 0:
        raise ControlError("unavailable")
    return result.stdout if inspect else None


def _inspect(runner, scope, service_id, env, deadline):
    body = _run(runner, scope, ["show", f"--property={PROPERTIES}", "--", service_id],
                env, deadline, inspect=True)
    if not isinstance(body, bytes):
        raise ControlError("invalid_response")
    if len(body) > MAX_BYTES:
        raise ControlError("response_limit")
    try:
        fields = {}
        for line in body.decode("ascii").splitlines():
            key, value = line.split("=", 1)
            if key in fields:
                raise ValueError()
            fields[key] = value
        if (set(fields) != set(PROPERTIES.split(",")) or fields["Id"] != service_id
                or fields["LoadState"] != "loaded" or fields["ActiveState"] not in ACTIVE
                or not re.fullmatch(r"[a-z][a-z-]{0,63}", fields["SubState"])
                or not re.fullmatch(r"[0-9]{1,10}", fields["MainPID"])):
            raise ValueError()
        pid = int(fields["MainPID"])
        if pid > 2147483647:
            raise ValueError()
        return {"id": fields["Id"], "loadState": fields["LoadState"],
                "activeState": fields["ActiveState"], "subState": fields["SubState"], "mainPid": pid}
    except (ValueError, KeyError, UnicodeError):
        raise ControlError("invalid_response") from None


def control(service_id, action, *, runner=None):
    """One mutation only. Caller must authorize and reserve a durable receipt first."""
    _, unit = _identity(service_id)
    if not isinstance(action, str) or action not in {
        "start", "stop", "restart",
    }:
        raise ControlError("invalid_arguments")
    configuration = _configuration(service_id)
    runner = runner or subprocess.run
    deadline = time.monotonic() + DEADLINE_SECONDS
    dispatched = False
    try:
        scope = configuration[0]
        env = _environment(scope)
        before = _inspect(runner, scope, unit, env, deadline)
        if _configuration(service_id) != configuration:
            raise ControlError("configuration_changed")
        if time.monotonic() >= deadline:
            raise ControlError("deadline")
        dispatched = True
        _run(runner, scope, [action, "--", unit], env, deadline)
        after = _inspect(runner, scope, unit, env, deadline)
        return {"serviceId": service_id, "action": action, "before": before, "after": after,
                "outcome": "observed", "dispatched": True}
    except Exception as error:
        if dispatched:
            raise OutcomeUnknown() from None
        if isinstance(error, ControlError):
            raise
        raise ControlError("unavailable") from None
