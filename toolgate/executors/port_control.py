"""Journaled Docker replacement. Internal executor, not an exposed capability yet."""

import hashlib
import json
import re
import time

import httpx

from toolgate.core import port_replacements as records
from toolgate.executors import container_control as docker
from toolgate.executors.port_plan import _identity, _mapping
from toolgate.executors.port_preview import _bindings


class ReplacementUnknown(RuntimeError):
    dispatched = True

    def __init__(self):
        super().__init__("Container replacement requires inspection; do not repeat the operation.")


def _json(body):
    try:
        return json.loads(body, object_pairs_hook=docker._pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError):
        raise docker.ControlError("invalid_response") from None


def _inspect(client, container_id, deadline):
    status, body = docker._read(client, "GET", f"/v1.45/containers/{container_id}/json", deadline)
    value = _json(body) if status == 200 else None
    if not isinstance(value, dict) or value.get("Id") != container_id:
        raise docker.ControlError("invalid_response")
    return value


def _mount_identity(mounts):
    return sorted((item["Type"], item.get("Name") if item["Type"] == "volume" else item.get("Source", ""),
                   item["Destination"], item.get("RW")) for item in mounts)


def execute(action_id, *, authorize, transport=None):
    """Run a previously saved specification once. Caller finishes parent receipt."""
    replacement = records.load_private(action_id)
    cid = replacement.preview["containerId"]
    configuration = docker._configuration(cid)
    if records.steps(action_id):
        raise ReplacementUnknown()
    # Checked deadline plus bounded per-read timeout, not a hard wall-clock limit.
    deadline = time.monotonic() + 180.0
    ordinal = -1
    claimed = False
    any_effect = False

    def check(conn):
        if docker._configuration(cid) != configuration:
            raise docker.ControlError("configuration_changed")
        authorize(conn)

    try:
        with httpx.Client(
            base_url="http://docker", transport=transport or httpx.HTTPTransport(uds=configuration[0]),
            timeout=httpx.Timeout(30.0, connect=2.0), trust_env=False,
            follow_redirects=False, headers={"Accept-Encoding": "identity"},
        ) as client:
            before = _inspect(client, cid, deadline)
            if not replacement.matches(before):
                raise docker.ControlError("configuration_changed")
            running = before["State"]["Running"]
            if (type(running) is not bool or before["State"]["Status"] not in ("running", "created", "exited")
                    or any(before["State"].get(key) is not False for key in ("Paused", "Restarting", "Dead"))):
                raise docker.ControlError("invalid_response")
            if running != replacement.preview["downtimeExpected"] and replacement.preview["changed"]:
                raise docker.ControlError("configuration_changed")
            if not replacement.preview["changed"]:
                return {"containerId": cid, "replacementId": None, "outcome": "unchanged", "dispatched": False}
            network_ids = []
            for endpoint in before["NetworkSettings"]["Networks"].values():
                network_id = endpoint.get("NetworkID")
                if not isinstance(network_id, str) or not re.fullmatch(r"[a-f0-9]{64}", network_id):
                    raise docker.ControlError("invalid_response")
                network_ids.append(network_id)

            def step(name, path, *, params=None, body=None, expected=(204,), reference_kind=None):
                nonlocal ordinal, claimed, any_effect
                ordinal += 1
                claimed = False
                if not records.begin_step(action_id, ordinal, name, authorize=check):
                    raise ReplacementUnknown()
                claimed = True
                any_effect = True
                status, response = docker._read(client, "POST", path, deadline, params=params, json_body=body)
                if status not in expected:
                    raise ReplacementUnknown()
                reference = None
                if reference_kind:
                    value = _json(response)
                    reference = value.get("Id") if isinstance(value, dict) else None
                    pattern = r"sha256:[a-f0-9]{64}" if reference_kind == "image" else r"[a-f0-9]{64}"
                    if not isinstance(reference, str) or not re.fullmatch(pattern, reference):
                        raise ReplacementUnknown()
                records.observed(action_id, ordinal, reference=reference)
                claimed = False
                return reference

            step("stop", f"/v1.45/containers/{cid}/stop", params={"t": "10"}, expected=(204, 304))
            stopped = _inspect(client, cid, deadline)
            # Docker may clear endpoint runtime fields on stop. Compare persistent
            # configuration here; the reviewed endpoint settings remain in body.
            if (stopped["State"]["Running"] is not False or any(
                    stopped.get(key) != before.get(key)
                    for key in ("Id", "Name", "Image", "Config", "HostConfig", "Mounts"))):
                raise ReplacementUnknown()
            snapshot = step("snapshot", "/v1.45/commit", params={"container": cid, "pause": "false"},
                            expected=(201,), reference_kind="image")
            step("retire", f"/v1.45/containers/{cid}/update",
                 body={"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}}, expected=(200,))
            backup_name = "conker-retained-" + hashlib.sha256(action_id.encode()).hexdigest()[:32]
            step("rename", f"/v1.45/containers/{cid}/rename", params={"name": backup_name})
            # Full network IDs from the reviewed source avoid mutable network-name
            # resolution when releasing an original static IP or MAC address.
            for network_id in network_ids:
                step("disconnect", f"/v1.45/networks/{network_id}/disconnect", body={"Container": cid, "Force": False}, expected=(200,))
            body = replacement.create_body(snapshot)
            new_id = step("create", "/v1.45/containers/create", params={"name": replacement.name},
                          body=body, expected=(201,), reference_kind="container")
            if new_id == cid:
                raise ReplacementUnknown()
            if running:
                step("start", f"/v1.45/containers/{new_id}/start", expected=(204, 304))
            ordinal += 1
            if not records.begin_step(action_id, ordinal, "verify", authorize=check):
                raise ReplacementUnknown()
            claimed = True
            after = _inspect(client, new_id, deadline)
            bindings = after["NetworkSettings"]["Ports"] if running else after["HostConfig"]["PortBindings"]
            normalized = sorted((_mapping(item) for item in _bindings(bindings)), key=_identity)
            expected_networks = before["NetworkSettings"]["Networks"]
            actual_networks = after["NetworkSettings"]["Networks"]
            networks_match = set(expected_networks) == set(actual_networks) and all(
                actual_networks[name].get("NetworkID") == endpoint.get("NetworkID")
                and set(endpoint.get("Aliases") or []).issubset(set(actual_networks[name].get("Aliases") or []))
                for name, endpoint in expected_networks.items()
            )
            if (after["State"]["Running"] is not running or after.get("Image") != snapshot
                    or normalized != replacement.preview["after"]
                    or not networks_match
                    or _mount_identity(after["Mounts"]) != _mount_identity(before["Mounts"])):
                raise ReplacementUnknown()
            records.observed(action_id, ordinal, reference=new_id)
            claimed = False
            return {"containerId": cid, "replacementId": new_id, "snapshotImage": snapshot,
                    "originalRetained": True, "outcome": "observed", "dispatched": True,
                    "bindings": normalized}
    except BaseException as error:
        # Includes cancellation/process-exit simulation. A lost reply or failed
        # journal write must never be turned into permission to repeat the effect.
        if any_effect:
            records.unknown(action_id, ordinal if claimed else -1)
            if not isinstance(error, Exception):
                raise
            raise ReplacementUnknown() from None
        if isinstance(error, (docker.ControlError, records.ReplacementError, ReplacementUnknown)):
            raise
        if not isinstance(error, Exception):
            raise
        raise docker.ControlError("unavailable") from None
