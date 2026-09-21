import copy
import json

import pytest

from toolgate.executors.port_plan import PlanError
from toolgate.executors.port_spec import prepare

CID = "a" * 64
IMAGE = "sha256:" + "b" * 64
MAPPING = {"hostAddress": "127.0.0.1", "hostPort": 8080, "containerPort": 80, "protocol": "tcp"}


def source():
    return {"Id": CID, "Name": "/application", "Image": "sha256:" + "c" * 64,
            "Config": {"Env": ["SECRET=private-value"], "Image": "old:tag",
                       "Cmd": ["serve"], "User": "1000", "WorkingDir": "/app",
                       "Healthcheck": {"Test": ["CMD", "check"]}, "Volumes": {"/data": {}}},
            "State": {"Status": "running", "Running": True, "Paused": False,
                      "Restarting": False, "Dead": False},
            "HostConfig": {"NetworkMode": "custom", "PublishAllPorts": False,
                           "AutoRemove": False, "PortBindings": {}, "Memory": 123456,
                           "RestartPolicy": {"Name": "unless-stopped"},
                           "Binds": ["/host/files:/files:ro"], "ReadonlyRootfs": True},
            "Mounts": [{"Type": "volume", "Name": "anonymous-data", "Destination": "/data", "RW": True},
                       {"Type": "bind", "Source": "/host/files", "Destination": "/files", "RW": False}],
            "NetworkSettings": {"Ports": {}, "Networks": {"custom": {
                "NetworkID": "d" * 64, "EndpointID": "volatile", "IPAddress": "172.20.0.2",
                "IPAMConfig": {"IPv4Address": "172.20.0.2"}, "Aliases": ["app"],
                "MacAddress": "02:42:ac:14:00:02", "DriverOpts": {"custom": "value"}}}}}


def test_replacement_preserves_settings_volumes_networks_and_requires_snapshot():
    inspection = source()
    before = copy.deepcopy(inspection)
    replacement = prepare(CID, inspection, "create", mapping=MAPPING)
    body = replacement.create_body(IMAGE)
    assert inspection == before
    assert body["Image"] == IMAGE and body["Env"] == ["SECRET=private-value"]
    for key in ("Cmd", "User", "WorkingDir", "Healthcheck", "Volumes"):
        assert body[key] == inspection["Config"][key]
    for key in ("Memory", "RestartPolicy", "Binds", "ReadonlyRootfs"):
        assert body["HostConfig"][key] == inspection["HostConfig"][key]
    assert body["HostConfig"]["Mounts"] == [{"Type": "volume", "Source": "anonymous-data",
                                             "Target": "/data", "ReadOnly": False,
                                             "VolumeOptions": {"NoCopy": True}}]
    endpoint = body["NetworkingConfig"]["EndpointsConfig"]["custom"]
    assert endpoint["Aliases"] == ["app"] and endpoint["IPAMConfig"]["IPv4Address"] == "172.20.0.2"
    assert "EndpointID" not in endpoint and "IPAddress" not in endpoint
    assert "private-value" not in repr(replacement)
    assert "private-value" not in json.dumps(replacement.preview)
    assert replacement.preview["writableLayer"] == "snapshot_required"
    body["Env"].append("modified")
    assert replacement.create_body(IMAGE)["Env"] == ["SECRET=private-value"]


@pytest.mark.parametrize("image", ["old:tag", "", None, "sha256:short"])
def test_original_image_or_unresolved_snapshot_is_rejected(image):
    replacement = prepare(CID, source(), "create", mapping=MAPPING)
    with pytest.raises(PlanError):
        replacement.create_body(image)


def test_explicit_anonymous_mount_resolved_without_losing_options():
    inspection = source()
    inspection["HostConfig"]["Mounts"] = [{"Type": "volume", "Target": "/data",
                                           "ReadOnly": False, "VolumeOptions": {"NoCopy": True}}]
    mounts = prepare(CID, inspection, "create", mapping=MAPPING).create_body(IMAGE)["HostConfig"]["Mounts"]
    assert len(mounts) == 1 and mounts[0]["Source"] == "anonymous-data"
    assert mounts[0]["VolumeOptions"] == {"NoCopy": True}


def test_named_volume_bind_is_not_duplicated():
    inspection = source()
    inspection["HostConfig"]["Binds"].append("anonymous-data:/data:rw")
    assert prepare(CID, inspection, "create", mapping=MAPPING).create_body(IMAGE)["HostConfig"]["Mounts"] == []


def test_tmpfs_loss_is_explicit():
    inspection = source()
    inspection["Mounts"].append({"Type": "tmpfs", "Destination": "/scratch"})
    inspection["HostConfig"]["Tmpfs"] = {"/scratch": "rw,size=65536"}
    replacement = prepare(CID, inspection, "create", mapping=MAPPING)
    assert replacement.preview["tmpfsData"] == "reset_on_replacement"
    assert replacement.create_body(IMAGE)["HostConfig"]["Tmpfs"] == {"/scratch": "rw,size=65536"}


@pytest.mark.parametrize("change", ["env", "mount", "restart", "network", "name", "image"])
def test_stale_configuration_detected(change):
    inspection = source()
    replacement = prepare(CID, inspection, "create", mapping=MAPPING)
    if change == "env":
        inspection["Config"]["Env"] = ["changed"]
    elif change == "mount":
        inspection["Mounts"][0]["Name"] = "different"
    elif change == "restart":
        inspection["HostConfig"]["RestartPolicy"] = {"Name": "always"}
    elif change == "network":
        inspection["NetworkSettings"]["Networks"]["custom"]["Aliases"] = ["changed"]
    elif change == "name":
        inspection["Name"] = "/changed"
    else:
        inspection["Image"] = IMAGE
    assert not replacement.matches(inspection)


def test_volatile_state_does_not_invalidate_configuration():
    inspection = source()
    replacement = prepare(CID, inspection, "create", mapping=MAPPING)
    inspection["State"].update(Status="exited", Running=False)
    inspection["NetworkSettings"]["Networks"]["custom"]["EndpointID"] = "changed"
    assert replacement.matches(inspection)


@pytest.mark.parametrize("field,value", [("VolumesFrom", ["other"]),
                                        ("ContainerIDFile", "/external"),
                                        ("PidMode", "container:other"),
                                        ("IpcMode", "container:other")])
def test_external_dependencies_are_not_silently_reconstructed(field, value):
    inspection = source()
    inspection["HostConfig"][field] = value
    with pytest.raises(PlanError, match="different"):
        prepare(CID, inspection, "create", mapping=MAPPING)


def test_unrecognized_config_not_silently_lost():
    inspection = source()
    inspection["Config"]["FutureOption"] = "private-value"
    with pytest.raises(PlanError) as error:
        prepare(CID, inspection, "create", mapping=MAPPING)
    assert "private-value" not in str(error.value)


def test_malformed_reinspection_never_matches():
    replacement = prepare(CID, source(), "create", mapping=MAPPING)
    assert not replacement.matches({}) and not replacement.matches(None)


@pytest.mark.parametrize("declaration", ["bind", "mount"])
def test_volume_identity_disagreement_is_rejected(declaration):
    inspection = source()
    if declaration == "bind":
        inspection["HostConfig"]["Binds"].append("different-volume:/data:rw")
    else:
        inspection["HostConfig"]["Mounts"] = [{"Type": "volume", "Target": "/data", "Source": "different-volume"}]
    with pytest.raises(PlanError):
        prepare(CID, inspection, "create", mapping=MAPPING)
