"""Explicitly managed Docker lifecycle operations; never retry a mutation here."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time

import httpx

from toolgate.core import container_lineage

MAX_BYTES = 1024 * 1024
DEADLINE_SECONDS = 25.0
ID = re.compile(r"[a-f0-9]{64}\Z")
STATES = {"created", "running", "paused", "restarting", "removing", "exited", "dead"}


class ControlError(RuntimeError):
    def __init__(self, code):
        self.code = code
        self.status = 422 if code == "invalid_arguments" else 403 if code == "not_managed" else 503
        super().__init__({
            "invalid_arguments": "Invalid container lifecycle arguments.",
            "not_configured": "Managed container control is not configured.",
            "invalid_configuration": "Managed container configuration is invalid.",
            "not_managed": "This container is not authorized for lifecycle control.",
            "configuration_changed": "Container control configuration changed before dispatch.",
            "unavailable": "Container inspection is unavailable.",
            "invalid_response": "Container inspection returned an invalid response.",
            "response_limit": "Container inspection exceeded its response limit.",
            "deadline": "Container control exceeded its deadline before dispatch.",
            "replacement_pending": "Container replacement is pending or requires recovery.",
        }[code])

    @property
    def message(self):
        return str(self)


class OutcomeUnknown(RuntimeError):
    code = "container_outcome_unknown"
    status = 502
    dispatched = True

    def __init__(self):
        super().__init__("Container action may have taken effect; inspect before taking further action.")

    @property
    def message(self):
        return str(self)


def _configuration(container_id=None):
    socket = os.environ.get("TOOLGATE_DOCKER_SOCKET", "")
    raw = os.environ.get("TOOLGATE_MANAGED_CONTAINER_IDS", "")
    if not socket or not raw:
        raise ControlError("not_configured")
    if (not socket.startswith("/") or len(socket) > 1024
            or any(part in ("..", ".") for part in socket.split("/"))
            or any(ord(char) < 32 for char in socket)):
        raise ControlError("invalid_configuration")
    try:
        if len(raw) > 150000:
            raise ValueError()
        ids = json.loads(raw)
        if (not isinstance(ids, list) or len(ids) > 2000
                or any(not isinstance(item, str) or not ID.fullmatch(item) for item in ids)):
            raise ValueError()
    except (ValueError, RecursionError):
        raise ControlError("invalid_configuration") from None
    try:
        ids = container_lineage.targets(socket, ids)
    except (ValueError, KeyError, TypeError, AttributeError, OSError, sqlite3.Error):
        raise ControlError("invalid_configuration") from None
    if container_id is not None and container_id not in ids:
        raise ControlError("not_managed")
    return socket, frozenset(ids)


def targets():
    """Configuration only: no daemon call, socket path, or inferred live status."""
    _, identities = _configuration()
    return sorted(identity for identity in identities if not container_lineage.busy(identity))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _read(client, method, path, deadline, *, params=None, json_body=None):
    if time.monotonic() > deadline:
        raise ControlError("deadline")
    options = {"json": json_body} if json_body is not None else {}
    with client.stream(method, path, params=params, **options) as response:
        body = bytearray()
        for chunk in response.iter_raw():
            if time.monotonic() > deadline:
                raise ControlError("deadline")
            if len(body) + len(chunk) > MAX_BYTES:
                raise ControlError("response_limit")
            body.extend(chunk)
        if time.monotonic() > deadline:
            raise ControlError("deadline")
        return response.status_code, bytes(body)


def _inspect(client, container_id, deadline):
    status, body = _read(client, "GET", f"/v1.45/containers/{container_id}/json", deadline)
    if status != 200:
        raise ControlError("unavailable")
    try:
        value = json.loads(body, object_pairs_hook=_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict) or value.get("Id") != container_id:
            raise ValueError()
        state = value["State"]
        if not isinstance(state, dict) or state.get("Status") not in STATES:
            raise ValueError()
        result = {"status": state["Status"]}
        for field in ("Running", "Paused", "Restarting", "Dead"):
            if type(state.get(field)) is not bool:
                raise ValueError()
            result[field.lower()] = state[field]
        return result
    except (ValueError, KeyError, TypeError, RecursionError):
        raise ControlError("invalid_response") from None


def control(container_id, action, *, transport=None):
    """Run once against a full allowlisted ID. Caller must journal before calling."""
    if (not isinstance(container_id, str) or not ID.fullmatch(container_id)
            or not isinstance(action, str) or action not in {"start", "stop", "restart"}):
        raise ControlError("invalid_arguments")
    configuration = _configuration(container_id)
    if container_lineage.busy(container_id):
        raise ControlError("replacement_pending")
    dispatched = False
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        with httpx.Client(
            base_url="http://docker", transport=transport or httpx.HTTPTransport(uds=configuration[0]),
            timeout=httpx.Timeout(12.0, connect=2.0), trust_env=False,
            follow_redirects=False, headers={"Accept-Encoding": "identity"},
        ) as client:
            before = _inspect(client, container_id, deadline)
            if _configuration(container_id) != configuration:
                raise ControlError("configuration_changed")
            if container_lineage.busy(container_id):
                raise ControlError("replacement_pending")
            if time.monotonic() > deadline:
                raise ControlError("deadline")
            dispatched = True
            status, _ = _read(
                client, "POST", f"/v1.45/containers/{container_id}/{action}", deadline,
                params={"t": "10"} if action != "start" else None,
            )
            if status not in ({204} if action == "restart" else {204, 304}):
                raise OutcomeUnknown()
            after = _inspect(client, container_id, deadline)
            result = {"containerId": container_id, "action": action, "before": before,
                      "after": after, "outcome": "observed", "dispatched": True}
        return result
    except Exception as error:
        if dispatched:
            raise OutcomeUnknown() from None
        if isinstance(error, ControlError):
            raise
        raise ControlError("unavailable") from None
