"""Recover a lost final receipt from durable verification, without Docker effects."""

import json
import time

from toolgate.core import container_lineage
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_replacements as records
from toolgate.executors import container_control as docker


def finalize(action_id, actor_id, *, authorize):
    """Internal owner-authorized primitive; partial executions remain unknown.

    authorize(conn) must check/consume the exact recovery approval in this
    transaction. The caller must not expose this as an unverified read endpoint.
    """
    if not callable(authorize):
        raise records.ReplacementError()
    initial = journal.get(action_id)
    if not initial or initial["actor_id"] != actor_id or initial["status"] != "outcome_unknown":
        raise records.ReplacementError()
    replacement = records.load_private(action_id)
    cid = replacement.preview["containerId"]
    configuration = docker._configuration(cid)
    with cp._conn() as conn:
        records._initialize(conn)
        conn.executescript(container_lineage.SCHEMA)
        conn.execute("BEGIN IMMEDIATE")
        parent = records._parent(conn, action_id)
        if parent["actor_id"] != actor_id or parent["status"] != "outcome_unknown":
            raise records.ReplacementError()
        steps = conn.execute("SELECT * FROM v2_port_steps WHERE action_id=? ORDER BY ordinal",
                             (action_id,)).fetchall()
        if (not steps or any(step["status"] != "observed" for step in steps)
                or [step["ordinal"] for step in steps] != list(range(len(steps)))
                or steps[-1]["name"] != "verify"):
            raise records.ReplacementError()
        created = [step["reference"] for step in steps if step["name"] == "create"]
        snapshots = [step["reference"] for step in steps if step["name"] == "snapshot"]
        if len(created) != 1 or len(snapshots) != 1 or steps[-1]["reference"] != created[0]:
            raise records.ReplacementError()
        lineage = conn.execute("SELECT * FROM v2_container_lineage WHERE action_id=?",
                               (action_id,)).fetchone()
        if (not lineage or lineage["source_id"] != cid or lineage["target_id"] != created[0]
                or lineage["socket_digest"] != container_lineage._digest(configuration[0])):
            raise records.ReplacementError()
        # These observations were persisted by the full executor verification;
        # recovery neither infers success from port equality nor reruns a step.
        result = {"containerId": cid, "replacementId": created[0], "snapshotImage": snapshots[0],
                  "originalRetained": True, "outcome": "observed", "dispatched": True,
                  "bindings": replacement.preview["after"]}
        envelope = {"code": "OK", "message": "Tool completed",
                    "result": {"ok": True, "result": result}}
        if docker._configuration(cid) != configuration:
            raise records.ReplacementError()
        authorize(conn)
        conn.execute("UPDATE v2_actions SET status='completed',response=?,updated_at=? WHERE action_id=?",
                     (json.dumps(envelope, allow_nan=False), time.time(), action_id))
        return journal._row(conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone())
