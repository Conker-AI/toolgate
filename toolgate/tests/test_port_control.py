import copy
import json

import httpx
import pytest

from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_replacements as records
from toolgate.core import vault
from toolgate.executors import container_control as docker
from toolgate.executors import port_control
from toolgate.executors.port_spec import prepare
from toolgate.tests.test_port_spec import CID, IMAGE, MAPPING, source

NEW = "e" * 64


class Stream(httpx.SyncByteStream):
    def __init__(self, value):
        self.value = value

    def __iter__(self):
        yield self.value


class Daemon:
    def __init__(self):
        self.original = source()
        self.replacement = None
        self.requests = []
        self.fail = None
        self.bad_verification = False
        self.bad_network = False
        self.action_id = "change-1"

    def handle(self, request):
        self.requests.append(request)
        path = request.url.path
        if request.method == "POST":
            assert records.steps(self.action_id)[-1]["status"] == "dispatching"
        if self.fail and path.endswith(self.fail):
            raise httpx.ReadTimeout("private-value")
        response = None
        status = 204
        if request.method == "GET":
            status = 200
            response = self.replacement if NEW in path else self.original
            if NEW in path and self.bad_verification:
                response = copy.deepcopy(response)
                response["NetworkSettings"]["Ports"] = {}
            if NEW in path and self.bad_network:
                response = copy.deepcopy(response)
                response["NetworkSettings"]["Networks"]["custom"]["NetworkID"] = "f" * 64
        elif path.endswith("/stop"):
            self.original["State"].update(Running=False, Status="exited")
        elif path.endswith("/commit"):
            assert self.original["State"]["Running"] is False
            status, response = 201, {"Id": IMAGE}
        elif path.endswith("/rename"):
            self.original["Name"] = "/" + request.url.params["name"]
        elif path.endswith("/update"):
            self.original["HostConfig"]["RestartPolicy"] = json.loads(request.content)["RestartPolicy"]
            status = 200
        elif path.endswith("/disconnect"):
            assert json.loads(request.content) == {"Container": CID, "Force": False}
            self.original["NetworkSettings"]["Networks"] = {}
            status = 200
        elif path.endswith("/create"):
            body = json.loads(request.content)
            assert body["Image"] == IMAGE
            assert body["HostConfig"]["Mounts"][0]["Source"] == "anonymous-data"
            assert body["Env"] == ["SECRET=private-value"]
            self.replacement = source()
            self.replacement.update(Id=NEW, Image=IMAGE, HostConfig=body["HostConfig"])
            self.replacement["State"].update(Running=False, Status="created")
            self.replacement["NetworkSettings"]["Ports"] = body["HostConfig"]["PortBindings"]
            status, response = 201, {"Id": NEW}
        elif path.endswith("/start"):
            assert NEW in path
            self.replacement["State"].update(Running=True, Status="running")
        else:
            raise AssertionError(path)
        return httpx.Response(status, stream=Stream(json.dumps(response).encode() if response else b""))


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_VAULT_SECRET", "synthetic-port-key")
    monkeypatch.setenv("TOOLGATE_VAULT_SALT", "a1" * 16)
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/synthetic/docker.sock")
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps([CID]))
    daemon = Daemon()
    journal.begin("change-1", "tool", "system.port-control", {"container_id": CID}, "actor", 1)
    records.save("change-1", prepare(CID, daemon.original, "create", mapping=MAPPING))
    return daemon


def run(daemon, authorize=lambda conn: None):
    return port_control.execute(daemon.action_id, authorize=authorize, transport=httpx.MockTransport(daemon.handle))


def test_actual_executor_uses_journal_and_preserves_original(setup):
    result = run(setup)
    assert result["replacementId"] == NEW and result["originalRetained"]
    assert setup.original["State"]["Running"] is False
    assert setup.original["HostConfig"]["RestartPolicy"]["Name"] == "no"
    assert setup.replacement["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    assert [x["name"] for x in records.steps("change-1")] == ["stop", "snapshot", "retire", "rename", "disconnect", "create", "start", "verify"]
    assert all(x["status"] == "observed" for x in records.steps("change-1"))
    assert all(request.method != "DELETE" for request in setup.requests)
    assert "private-value" not in json.dumps(result)
    count = len(setup.requests)
    with pytest.raises(port_control.ReplacementUnknown):
        run(setup)
    assert len(setup.requests) == count


@pytest.mark.parametrize("phase", ["/stop", "/commit", "/update", "/rename", "/disconnect", "/create", "/start"])
def test_lost_reply_halts_and_never_retries_any_effect(setup, phase):
    setup.fail = phase
    with pytest.raises(port_control.ReplacementUnknown) as error:
        run(setup)
    assert "private-value" not in str(error.value)
    assert journal.get("change-1")["status"] == "outcome_unknown"
    count = len(setup.requests)
    with pytest.raises(port_control.ReplacementUnknown):
        run(setup)
    assert len(setup.requests) == count
    assert sum(request.url.path.endswith(phase) for request in setup.requests) == 1


def test_stale_source_rejected_before_mutation(setup):
    setup.original["Config"]["Env"] = ["changed"]
    with pytest.raises(docker.ControlError) as error:
        run(setup)
    assert error.value.code == "configuration_changed"
    assert all(request.method == "GET" for request in setup.requests)
    assert records.steps("change-1") == []


def test_wrong_port_observation_is_not_claimed_success(setup):
    setup.bad_verification = True
    with pytest.raises(port_control.ReplacementUnknown):
        run(setup)
    assert records.steps("change-1")[-1]["status"] == "outcome_unknown"


def test_network_name_rebound_to_other_identity_is_not_success(setup):
    setup.bad_network = True
    with pytest.raises(port_control.ReplacementUnknown):
        run(setup)
    assert records.steps("change-1")[-1]["status"] == "outcome_unknown"


@pytest.mark.parametrize("running", [True, False])
@pytest.mark.parametrize("operation", ["edit", "remove"])
def test_edit_and_remove_preserve_original_running_state(setup, running, operation):
    setup.action_id = "change-2"
    setup.original["State"].update(Running=running, Status="running" if running else "exited")
    ports = {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
    setup.original["HostConfig"]["PortBindings"] = ports
    setup.original["NetworkSettings"]["Ports"] = copy.deepcopy(ports)
    options = {"original": MAPPING}
    if operation == "edit":
        options["mapping"] = {**MAPPING, "hostPort": 9090}
    replacement = prepare(CID, setup.original, operation, **options)
    journal.begin(setup.action_id, "tool", "system.port-control", {"container_id": CID}, "actor", 1)
    records.save(setup.action_id, replacement)
    result = run(setup)
    assert result["bindings"] == replacement.preview["after"]
    assert setup.replacement["State"]["Running"] is running
    assert any(step["name"] == "start" for step in records.steps(setup.action_id)) is running


def test_revocation_between_steps_stops_further_effects(setup, monkeypatch):
    count = 0

    def authorize(conn):
        nonlocal count
        count += 1
        if count == 2:
            raise PermissionError("revoked")
    with pytest.raises(port_control.ReplacementUnknown):
        run(setup, authorize)
    assert [request.url.path.rsplit("/", 1)[-1] for request in setup.requests if request.method == "POST"] == ["stop"]
    assert journal.get("change-1")["status"] == "outcome_unknown"
