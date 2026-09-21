"""Read-only evidence for uncertain port replacements; never resumes effects."""

import re
import time

import httpx

from toolgate.core import execution_journal as journal
from toolgate.core import port_replacements as records
from toolgate.executors import container_control as docker
from toolgate.executors.port_control import _json
from toolgate.executors.port_plan import PlanError, _identity, _mapping
from toolgate.executors.port_preview import _bindings


class RecoveryError(ValueError):
    def __init__(self):
        super().__init__("Replacement recovery evidence is unavailable.")


def _observe(client, cid, deadline):
    try:
        status, body = docker._read(client, "GET", f"/v1.45/containers/{cid}/json", deadline)
        if status == 404:
            return {"containerId": cid, "presence": "missing"}
        value = _json(body) if status == 200 else None
        if not isinstance(value, dict) or value.get("Id") != cid:
            raise RecoveryError()
        state = value["State"]
        if state.get("Status") not in docker.STATES or any(type(state.get(key)) is not bool
                for key in ("Running", "Paused", "Restarting", "Dead")):
            raise RecoveryError()
        image = value.get("Image")
        if not isinstance(image, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise RecoveryError()
        result = {"containerId": cid, "presence": "present", "image": image,
                  "status": state["Status"], "running": state["Running"],
                  "paused": state["Paused"], "restarting": state["Restarting"], "dead": state["Dead"],
                  "bindings": None, "bindingsStatus": "unavailable"}
        try:
            bindings = value["NetworkSettings"]["Ports"] if state["Running"] else value["HostConfig"]["PortBindings"]
            result["bindings"] = sorted((_mapping(item) for item in _bindings(bindings)), key=_identity)
            result["bindingsStatus"] = "observed" if state["Running"] else "configured"
        except (KeyError, TypeError, ValueError, PlanError):
            pass
        return result
    except (httpx.HTTPError, OSError, docker.ControlError, RecoveryError, KeyError, TypeError, ValueError, AttributeError):
        return {"containerId": cid, "presence": "unavailable"}


def inspect(action_id, actor_id, *, transport=None):
    parent = journal.get(action_id)
    if (not parent or parent["actor_id"] != actor_id or parent["subject_type"] != "tool"
            or parent["subject_id"] != "system.port-control"):
        raise RecoveryError()
    result = {"actionId": action_id, "state": parent["status"], "steps": records.steps(action_id),
              "source": None, "replacement": None, "observedAt": None,
              "canResume": False, "canReleaseReservation": False}
    # Do not inspect a live executor mid-step or imply its lease can be taken over.
    if parent["status"] != "outcome_unknown":
        return {**result, "inspection": "not_required" if parent["status"] == "completed" else "in_progress"}
    replacement = records.load_private(action_id)
    cid = replacement.preview["containerId"]
    try:
        configuration = docker._configuration(cid)
        deadline = time.monotonic() + docker.DEADLINE_SECONDS
        candidate = next((step["reference"] for step in result["steps"]
                          if step["name"] == "create" and step["status"] == "observed"), None)
        if candidate is not None and (not isinstance(candidate, str) or not re.fullmatch(r"[a-f0-9]{64}", candidate)):
            raise RecoveryError()
        with httpx.Client(base_url="http://docker", trust_env=False, follow_redirects=False,
                          transport=transport or httpx.HTTPTransport(uds=configuration[0]),
                          timeout=httpx.Timeout(12.0, connect=2.0),
                          headers={"Accept-Encoding": "identity"}) as client:
            result["source"] = _observe(client, cid, deadline)
            result["replacement"] = (_observe(client, candidate, deadline) if candidate else
                                     {"containerId": None, "presence": "identity_unconfirmed"})
        if docker._configuration(cid) != configuration:
            raise RecoveryError()
        known = [result[key]["presence"] in ("present", "missing") for key in ("source", "replacement")]
        result.update(inspection="observed" if all(known) else "partial" if any(known) else "unavailable",
                      observedAt=time.time())
        # Equality is evidence only. Ports/image do not prove complete fidelity or
        # absence of in-flight external effects, so never finalize from this GET.
        current = result["replacement"]
        result["replacementBindingsMatch"] = (current.get("bindings") == replacement.preview["after"]
                                               if current.get("bindings") is not None else None)
        return result
    except (docker.ControlError, records.ReplacementError, OSError, httpx.HTTPError):
        raise RecoveryError() from None
