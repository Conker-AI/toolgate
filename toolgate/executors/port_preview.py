"""Read-only port previews from the explicitly configured managed Docker daemon."""

import json
import re
import time

import httpx

from toolgate.executors import container_control as docker
from toolgate.executors.port_plan import PlanError, plan


def _bindings(value):
    """Normalize Docker's map without silently discarding an unsupported binding."""
    if value is None:
        return []
    if not isinstance(value, dict) or len(value) > 200:
        raise PlanError("invalid")
    result = []
    for key, entries in value.items():
        match = re.fullmatch(r"([1-9][0-9]{0,4})/(tcp|udp)", key)
        if not match or int(match[1]) > 65535:
            raise PlanError("unsupported")
        # Null is an exposed container port without any host publication.
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise PlanError("invalid")
        for entry in entries:
            if not isinstance(entry, dict):
                raise PlanError("invalid")
            port, address = entry.get("HostPort"), entry.get("HostIp")
            if (not isinstance(port, str)
                    or not re.fullmatch(r"[1-9][0-9]{0,4}", port)
                    or int(port) > 65535
                    or not isinstance(address, str) or not address):
                # Empty/zero ports are requests for daemon allocation. They cannot
                # be frozen as exact replacements without a resolved observation.
                raise PlanError("unsupported")
            result.append({"containerPort": int(match[1]), "protocol": match[2],
                           "hostAddress": address, "hostPort": int(port)})
            if len(result) > 200:
                raise PlanError("invalid")
    return result


def from_inspection(container_id, inspection, operation, *, mapping=None, original=None):
    """Project only port/state fields. The entire inspect document is private."""
    try:
        if not isinstance(inspection, dict) or inspection.get("Id") != container_id:
            raise ValueError()
        state, host = inspection["State"], inspection["HostConfig"]
        running = state["Running"]
        if type(running) is not bool or state["Status"] not in docker.STATES:
            raise ValueError()
        for field in ("Paused", "Restarting", "Dead"):
            if type(state[field]) is not bool:
                raise ValueError()
            if state[field]:
                raise PlanError("unsupported")
        if state["Status"] not in ("running", "created", "exited"):
            raise PlanError("unsupported")
        if running != (state["Status"] == "running"):
            raise ValueError()
        # A running daemon observation includes allocated host ports and explicit
        # IPv4/IPv6 bindings. A stopped container may have no runtime Ports map:
        # only concrete HostConfig bindings can be previewed in that case.
        bindings = inspection["NetworkSettings"]["Ports"] if running else host["PortBindings"]
        if running:
            declared = host["PortBindings"]
            if declared is not None and not isinstance(declared, dict):
                raise ValueError()
            for key, entries in (declared or {}).items():
                if entries and (not isinstance(bindings, dict) or not bindings.get(key)):
                    # Do not propose a replacement that loses a declared mapping
                    # because runtime publication data is absent or incomplete.
                    raise PlanError("unsupported")
        result = plan(
            container_id, _bindings(bindings), operation, mapping=mapping,
            original=original, running=running, network_mode=host["NetworkMode"],
            publish_all=host["PublishAllPorts"], auto_remove=host["AutoRemove"],
        )
        result["bindingSource"] = "observed" if running else "configured"
        return result
    except PlanError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError):
        raise docker.ControlError("invalid_response") from None


def preview(container_id, operation, *, mapping=None, original=None, transport=None):
    """GET-only; caller owns scoped admission. Never a replacement authorization."""
    if not isinstance(container_id, str) or not docker.ID.fullmatch(container_id):
        raise docker.ControlError("invalid_arguments")
    if operation not in ("create", "edit", "remove"):
        raise docker.ControlError("invalid_arguments")
    configuration = docker._configuration(container_id)
    deadline = time.monotonic() + docker.DEADLINE_SECONDS
    try:
        with httpx.Client(
            base_url="http://docker", transport=transport or httpx.HTTPTransport(uds=configuration[0]),
            timeout=httpx.Timeout(12.0, connect=2.0), trust_env=False,
            follow_redirects=False, headers={"Accept-Encoding": "identity"},
        ) as client:
            status, body = docker._read(
                client, "GET", f"/v1.45/containers/{container_id}/json", deadline,
            )
        if docker._configuration(container_id) != configuration:
            raise docker.ControlError("configuration_changed")
        if status != 200:
            raise docker.ControlError("unavailable")
        try:
            inspection = json.loads(
                body, object_pairs_hook=docker._pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError()),
            )
        except (ValueError, RecursionError):
            raise docker.ControlError("invalid_response") from None
        return from_inspection(container_id, inspection, operation, mapping=mapping, original=original)
    except (PlanError, docker.ControlError):
        raise
    except (httpx.HTTPError, OSError):
        raise docker.ControlError("unavailable") from None
