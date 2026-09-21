import json
import subprocess
from types import SimpleNamespace

import pytest

from toolgate.executors import process_control as adapter

UNIT = "conker-worker.service"
ID = f"system:{UNIT}"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("TOOLGATE_SYSTEMD_SCOPE", "system")
    monkeypatch.setenv("TOOLGATE_MANAGED_SERVICE_UNITS", json.dumps([UNIT]))
    # Even a mistakenly omitted injection must never affect a real service.
    monkeypatch.setattr(adapter.subprocess, "run", lambda *a, **kw: pytest.fail("Real runner forbidden"))


def body(**overrides):
    fields = {"Id": UNIT, "LoadState": "loaded", "ActiveState": "active",
              "SubState": "running", "MainPID": "42"}
    fields.update(overrides)
    return "\n".join(f"{k}={v}" for k, v in fields.items()).encode() + b"\n"


def runner(calls):
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=body())
    return run


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_fixed_argv_projection_and_no_inherited_environment(monkeypatch, action):
    monkeypatch.setenv("LD_PRELOAD", "secret")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "tcp:host=bad")
    monkeypatch.setenv("SYSTEMD_HOST", "bad")
    calls = []
    result = adapter.control(ID, action, runner=runner(calls))
    assert len(calls) == 3
    prefix = ["/usr/bin/systemctl", "--system", "--no-pager", "--no-ask-password"]
    assert calls[0][0] == prefix + ["show", f"--property={adapter.PROPERTIES}", "--", UNIT]
    assert calls[1][0] == prefix + [action, "--", UNIT]
    assert calls[2][0] == calls[0][0]
    for _, kw in calls:
        assert kw["stdin"] == kw["stderr"] == subprocess.DEVNULL
        assert kw["shell"] is False and kw["close_fds"] is True
        assert 0 < kw["timeout"] <= adapter.DEADLINE_SECONDS
        assert set(kw["env"]) == {"PATH", "LANG", "LC_ALL", "SYSTEMD_COLORS"}
    assert calls[1][1]["stdout"] == subprocess.DEVNULL
    assert result == {"serviceId": ID, "action": action, "outcome": "observed", "dispatched": True,
                      "before": result["after"], "after": {
                          "id": UNIT, "loadState": "loaded", "activeState": "active",
                          "subState": "running", "mainPid": 42}}


def test_user_manager_uses_effective_identity_not_inherited_bus(monkeypatch):
    monkeypatch.setenv("TOOLGATE_SYSTEMD_SCOPE", "user")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/untrusted")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "tcp:host=bad")
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 1234, raising=False)
    calls = []
    adapter.control(f"user:{UNIT}", "start", runner=runner(calls))
    assert calls[0][0][1] == "--user"
    assert calls[0][1]["env"]["XDG_RUNTIME_DIR"] == "/run/user/1234"
    assert calls[0][1]["env"]["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1234/bus"


@pytest.mark.parametrize("unit", ["--root.service", "/foo.service", "../foo.service", "*.service",
                                   "a?.service", "a@.service", "a.service\n", "a.socket", "a.service x",
                                   "a\\x.service", "a;whoami.service", "a:other.service"])
def test_invalid_units_never_execute(unit):
    with pytest.raises(adapter.ControlError) as error:
        adapter.control("system:" + unit, "start")
    assert error.value.code == "invalid_arguments"


@pytest.mark.parametrize("identity,action", [(UNIT, "start"), (None, "start"), (ID, []), (ID, "kill")])
def test_bad_arguments(identity, action):
    with pytest.raises(adapter.ControlError) as error:
        adapter.control(identity, action)
    assert error.value.code == "invalid_arguments"


@pytest.mark.parametrize("scope,units,code", [
    ("", [UNIT], "not_configured"), ("remote", [UNIT], "invalid_configuration"),
    ("system", [], "not_managed"), ("system", ["*.service"], "invalid_configuration"),
    ("user", [UNIT], "not_managed"), ("system", {}, "invalid_configuration"),
])
def test_config_denial(scope, units, code, monkeypatch):
    monkeypatch.setenv("TOOLGATE_SYSTEMD_SCOPE", scope)
    monkeypatch.setenv("TOOLGATE_MANAGED_SERVICE_UNITS", json.dumps(units))
    with pytest.raises(adapter.ControlError) as error:
        adapter.control(ID, "start")
    assert error.value.code == code


def test_targets_are_config_only_scoped_sorted(monkeypatch):
    monkeypatch.setenv("TOOLGATE_MANAGED_SERVICE_UNITS", json.dumps([UNIT, "a@b.service", UNIT]))
    assert adapter.targets() == ["system:a@b.service", ID]


@pytest.mark.parametrize("changed", ["scope", "units"])
def test_configuration_revoked_after_inspect_prevents_mutation(monkeypatch, changed):
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        if changed == "scope":
            monkeypatch.setenv("TOOLGATE_SYSTEMD_SCOPE", "user")
        else:
            monkeypatch.setenv("TOOLGATE_MANAGED_SERVICE_UNITS", "[]")
        return SimpleNamespace(returncode=0, stdout=body())
    with pytest.raises(adapter.ControlError):
        adapter.control(ID, "start", runner=run)
    assert len(calls) == 1


@pytest.mark.parametrize("data", [body(Id="alias.service"), body(LoadState="not-found"),
                                  body(LoadState="masked"), body(MainPID="-2"), body(MainPID="9999999999"),
                                  body(ActiveState="secret"), body(SubState="bad\nvalue"),
                                  body() + b"Id=other.service\n", b"x" * (adapter.MAX_BYTES + 1)])
def test_invalid_preinspection_blocks(data):
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=data)
    with pytest.raises(adapter.ControlError):
        adapter.control(ID, "start", runner=run)
    assert len(calls) == 1


@pytest.mark.parametrize("failure_at", [1, 2, 3])
def test_static_errors_and_no_retry(failure_at):
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        if len(calls) == failure_at:
            raise RuntimeError("sensitive diagnostic")
        return SimpleNamespace(returncode=0, stdout=body())
    expected = adapter.ControlError if failure_at == 1 else adapter.OutcomeUnknown
    with pytest.raises(expected) as error:
        adapter.control(ID, "restart", runner=run)
    assert "sensitive" not in str(error.value)
    assert len(calls) == failure_at


def test_failed_mutation_exit_unknown_without_retry():
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        return SimpleNamespace(returncode=int(len(calls) == 2), stdout=body())
    with pytest.raises(adapter.OutcomeUnknown):
        adapter.control(ID, "stop", runner=run)
    assert len(calls) == 2


def test_deadline_before_dispatch(monkeypatch):
    ticks = iter([0, 0, 31])
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(ticks))
    calls = []
    with pytest.raises(adapter.ControlError) as error:
        adapter.control(ID, "start", runner=runner(calls))
    assert error.value.code == "deadline" and len(calls) == 1
