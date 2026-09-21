"""Recover final verification/receipts without repeating Docker mutations."""

import json
import time

import httpx

from toolgate.core import container_lineage
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_replacements as records
from toolgate.executors import container_control as docker
from toolgate.executors import port_control


def preview(action_id, actor_id, *, transport=None):
    """Return the receipt eligible for recovery; do not release the reservation."""
    return _recover(action_id, actor_id, authorize=None, transport=transport)


def finalize(action_id, actor_id, *, authorize, transport=None):
    """Internal owner-authorized primitive; uncertain mutations remain unknown.

    authorize(conn) must check/consume the exact recovery approval in this
    transaction. The caller must not expose this as an unverified read endpoint.
    """
    if not callable(authorize):
        raise records.ReplacementError()
    return _recover(action_id, actor_id, authorize=authorize, transport=transport)


def _reverify(action_id, replacement, configuration, steps, transport):
    """Only the final GET may be repeated; every preceding effect must be observed."""
    if (not steps or steps[-1]["name"] != "verify"
            or steps[-1]["status"] != "outcome_unknown"
            or any(step["status"] != "observed" for step in steps[:-1])):
        return False
    created = [step["reference"] for step in steps if step["name"] == "create"]
    snapshots = [step["reference"] for step in steps if step["name"] == "snapshot"]
    if len(created) != 1 or len(snapshots) != 1:
        raise records.ReplacementError()
    cid = replacement.preview["containerId"]
    before = records.load_verification_basis(action_id, configuration[0])
    try:
        deadline = time.monotonic() + docker.DEADLINE_SECONDS
        with httpx.Client(base_url="http://docker", trust_env=False, follow_redirects=False,
                          transport=transport or httpx.HTTPTransport(uds=configuration[0]),
                          timeout=httpx.Timeout(12.0, connect=2.0),
                          headers={"Accept-Encoding": "identity"}) as client:
            retained = port_control._inspect(client, cid, deadline)
            after = port_control._inspect(client, created[0], deadline)
        if (retained["State"]["Running"] is not False
                or retained["Image"] != before["Image"] or created[0] == cid):
            raise records.ReplacementError()
        port_control.verify_replacement(before, after, replacement, snapshots[0])
        if docker._configuration(cid) != configuration:
            raise records.ReplacementError()
        return True
    except (httpx.HTTPError, OSError, KeyError, TypeError, ValueError, RuntimeError,
            docker.ControlError):
        raise records.ReplacementError() from None


def _recover(action_id, actor_id, *, authorize, transport):
    initial = journal.get(action_id)
    if not initial or initial["actor_id"] != actor_id or initial["status"] != "outcome_unknown":
        raise records.ReplacementError()
    replacement = records.load_private(action_id)
    cid = replacement.preview["containerId"]
    configuration = docker._configuration(cid)
    original_steps = records.steps(action_id)
    reverified = _reverify(action_id, replacement, configuration, original_steps, transport)
    with cp._conn() as conn:
        records._initialize(conn)
        conn.executescript(container_lineage.SCHEMA)
        conn.execute("BEGIN IMMEDIATE")
        parent = records._parent(conn, action_id)
        if parent["actor_id"] != actor_id or parent["status"] != "outcome_unknown":
            raise records.ReplacementError()
        steps = conn.execute("SELECT * FROM v2_port_steps WHERE action_id=? ORDER BY ordinal",
                             (action_id,)).fetchall()
        current_steps = [{key: step[key] for key in ("ordinal", "name", "status", "reference")} for step in steps]
        for step in current_steps:
            if step["status"] == "dispatching":
                step["status"] = "outcome_unknown"
        if (current_steps != original_steps or not steps
                or any(step["status"] != "observed" for step in (steps[:-1] if reverified else steps))
                or [step["ordinal"] for step in steps] != list(range(len(steps)))
                or steps[-1]["name"] != "verify"):
            raise records.ReplacementError()
        created = [step["reference"] for step in steps if step["name"] == "create"]
        snapshots = [step["reference"] for step in steps if step["name"] == "snapshot"]
        if (len(created) != 1 or len(snapshots) != 1
                or (not reverified and steps[-1]["reference"] != created[0])):
            raise records.ReplacementError()
        lineage = conn.execute("SELECT * FROM v2_container_lineage WHERE action_id=?",
                               (action_id,)).fetchone()
        if ((not lineage and not reverified) or (lineage and (
                lineage["source_id"] != cid or lineage["target_id"] != created[0]
                or lineage["socket_digest"] != container_lineage._digest(configuration[0])))):
            raise records.ReplacementError()
        # Use durable verification or the shared full verification above, never
        # infer success from port equality alone or replay a mutating step.
        result = {"containerId": cid, "replacementId": created[0], "snapshotImage": snapshots[0],
                  "originalRetained": True, "outcome": "observed", "dispatched": True,
                  "bindings": replacement.preview["after"]}
        envelope = {"code": "OK", "message": "Tool completed",
                    "result": {"ok": True, "result": result}}
        if docker._configuration(cid) != configuration:
            raise records.ReplacementError()
        if authorize is None:
            return result
        authorize(conn)
        if reverified:
            conn.execute("UPDATE v2_port_steps SET status='observed',reference=?,updated_at=?"
                         " WHERE action_id=? AND ordinal=?",
                         (created[0], time.time(), action_id, steps[-1]["ordinal"]))
            if not lineage:
                conn.execute("INSERT INTO v2_container_lineage VALUES (?,?,?,?)",
                             (action_id, cid, created[0], container_lineage._digest(configuration[0])))
        conn.execute("UPDATE v2_actions SET status='completed',response=?,updated_at=? WHERE action_id=?",
                     (json.dumps(envelope, allow_nan=False), time.time(), action_id))
        return journal._row(conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone())
