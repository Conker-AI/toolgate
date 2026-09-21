import json

import pytest

from toolgate.core import container_lineage as lineage
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_replacements as records
from toolgate.core import vault
from toolgate.executors import container_control as docker
from toolgate.executors.port_spec import Replacement

ROOT, NEXT, LAST = "a" * 64, "b" * 64, "c" * 64
SOCKET = "/synthetic/docker.sock"


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_VAULT_SECRET", "synthetic-lineage-key")
    monkeypatch.setenv("TOOLGATE_VAULT_SALT", "a1" * 16)
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", SOCKET)
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps([ROOT]))


def link(source, target, action, completed=True):
    journal.begin(action, "tool", "system.port-control", {"container_id": source}, "actor", 1)
    records.save(action, Replacement({"containerId": source}, {}, "private", "name"))
    records.begin_step(action, 0, "verify", authorize=lambda conn: None)
    records.observed(action, 0, reference=target)
    lineage.record(action, source, target, SOCKET)
    if completed:
        journal.finish(action, {"code": "OK", "result": {"ok": True, "result": {
            "containerId": source, "replacementId": target, "outcome": "observed", "originalRetained": True}}})


def test_completed_chain_selects_current_leaf_and_retires_ancestors():
    assert docker.targets() == [ROOT]
    link(ROOT, NEXT, "first")
    assert docker.targets() == [NEXT]
    with pytest.raises(docker.ControlError):
        docker._configuration(ROOT)
    link(NEXT, LAST, "second")
    assert docker.targets() == [LAST]
    assert docker._configuration(LAST)[1] == frozenset([LAST])


def test_root_revocation_revokes_derived_target(monkeypatch):
    link(ROOT, NEXT, "first")
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", "[]")
    assert docker.targets() == []
    with pytest.raises(docker.ControlError):
        docker._configuration(NEXT)


def test_socket_change_does_not_inherit_previous_daemon_target(monkeypatch):
    link(ROOT, NEXT, "first")
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/synthetic/other.sock")
    assert docker.targets() == [ROOT]
    with pytest.raises(docker.ControlError):
        docker._configuration(NEXT)


def test_pending_or_unknown_parent_never_grants_child():
    link(ROOT, NEXT, "first", completed=False)
    assert docker.targets() == []
    journal.unknown("first")
    assert docker.targets() == []
    with pytest.raises(docker.ControlError):
        docker._configuration(NEXT)
    with pytest.raises(docker.ControlError) as error:
        docker.control(ROOT, "start")
    assert error.value.code == "replacement_pending"


def test_second_pending_source_replacement_is_rejected():
    link(ROOT, NEXT, "first", completed=False)
    journal.begin("second", "tool", "system.port-control", {"container_id": ROOT}, "actor", 1)
    with pytest.raises(records.ReplacementError):
        records.save("second", Replacement({"containerId": ROOT}, {}, "private", "name"))


def test_unverified_reference_cannot_become_lineage():
    journal.begin("first", "tool", "system.port-control", {"container_id": ROOT}, "actor", 1)
    records.save("first", Replacement({"containerId": ROOT}, {}, "private", "name"))
    with pytest.raises(records.ReplacementError):
        lineage.record("first", ROOT, NEXT, SOCKET)
    assert docker.targets() == []
