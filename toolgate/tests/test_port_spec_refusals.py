"""Container replacement preparation refuses configurations it cannot recreate faithfully.

Every case starts from a valid inspection, breaks one thing, and expects a refusal with the
code the planner promises: `invalid` for malformed data, `unsupported` for shapes that need a
different reconfiguration path. A refused container is never half-prepared."""

import copy

import pytest

import toolgate.executors.container_control  # noqa: F401  (loads the module cycle in its working order)
from toolgate.executors.port_plan import PlanError
from toolgate.executors.port_spec import prepare
from toolgate.tests.test_port_spec import CID, MAPPING, source


def refused(code, change):
    inspection = source()
    change(inspection)
    with pytest.raises(PlanError) as error:
        prepare(CID, inspection, "create", mapping=MAPPING)
    assert error.value.code == code


def set_host(key, value):
    return lambda inspection: inspection["HostConfig"].__setitem__(key, value)


def set_top(key, value):
    return lambda inspection: inspection.__setitem__(key, value)


def set_config(key, value):
    return lambda inspection: inspection["Config"].__setitem__(key, value)


def set_mounts(mounts):
    return set_top("Mounts", mounts)


def volume(destination, name="anonymous-data", rw=True):
    return {"Type": "volume", "Name": name, "Destination": destination, "RW": rw}


@pytest.mark.parametrize(
    "change",
    [
        set_top("Mounts", "not-a-list"),
        set_top("Mounts", [volume(f"/v{index}", name=f"v{index}") for index in range(201)]),
        set_host("Mounts", "not-a-list"),
        set_host("Binds", "not-a-list"),
        set_host("Mounts", ["not-a-mapping"]),
        set_host("Mounts", [{"Type": "volume", "Target": 7}]),
        set_host(
            "Mounts", [{"Type": "volume", "Target": "/data"}, {"Type": "volume", "Target": "/data"}]
        ),
        set_host("Binds", [5]),
        set_host("Binds", ["/host/files:/files:ro", "/other:/files:ro"]),
        set_host("Binds", ["/host/files:/data:ro"]),
        set_mounts(["not-a-mapping"]),
        set_mounts([volume("relative/path")]),
        set_mounts([volume(7)]),
        set_mounts([volume("/data"), volume("/data", name="again")]),
        set_mounts([volume("/data", name="")]),
        set_mounts([volume("/data", name=None)]),
        set_mounts([volume("/data", rw="yes")]),
    ],
)
def test_malformed_mount_data_is_refused_as_invalid(change):
    refused("invalid", change)


def test_a_bind_that_names_a_volume_other_than_the_mounted_one_is_refused():
    def change(inspection):
        inspection["HostConfig"]["Binds"] = ["other-volume:/data:rw"]

    refused("invalid", change)


@pytest.mark.parametrize(
    "declaration",
    [
        {"Type": "bind", "Source": "/host", "Target": "/data"},
        {"Type": "volume", "Target": "/data", "Source": "someone-else"},
    ],
)
def test_a_declared_mount_must_agree_with_the_volume_actually_mounted(declaration):
    refused("invalid", set_host("Mounts", [declaration]))


@pytest.mark.parametrize("binds", [["/only-one-part"], ["/a:relative"], ["/a:/b:ro:extra"]])
def test_a_bind_the_planner_cannot_read_is_unsupported(binds):
    refused("unsupported", set_host("Binds", binds))


@pytest.mark.parametrize(
    "mounts",
    [
        [{"Type": "bind", "Source": "/undeclared", "Destination": "/elsewhere", "RW": True}],
        [{"Type": "tmpfs", "Destination": "/scratch"}],
        [{"Type": "npipe", "Destination": "/pipe"}],
    ],
)
def test_a_mount_with_no_declaration_to_recreate_it_is_unsupported(mounts):
    def change(inspection):
        inspection["Mounts"] = mounts
        inspection["HostConfig"]["Binds"] = []

    refused("unsupported", change)


def test_a_bind_declared_in_mounts_is_recreated_from_that_declaration():
    inspection = source()
    inspection["Mounts"] = [{"Type": "bind", "Source": "/host", "Destination": "/work", "RW": True}]
    inspection["HostConfig"]["Binds"] = []
    inspection["HostConfig"]["Mounts"] = [{"Type": "bind", "Source": "/host", "Target": "/work"}]
    body = prepare(CID, inspection, "create", mapping=MAPPING).create_body("sha256:" + "e" * 64)
    assert body["HostConfig"]["Mounts"] == [{"Type": "bind", "Source": "/host", "Target": "/work"}]


@pytest.mark.parametrize(
    "change",
    [
        set_top("Name", "no-leading-slash"),
        set_top("Name", "/bad name"),
        set_top("Name", 5),
        set_config("ExposedPorts", ["80/tcp"]),
        set_top("NetworkSettings", {"Ports": {}, "Networks": ["custom"]}),
        set_top("NetworkSettings", {"Ports": {}, "Networks": {"custom": "not-a-mapping"}}),
        set_top("NetworkSettings", {"Ports": {}, "Networks": {"": {"NetworkID": "d" * 64}}}),
        set_top(
            "NetworkSettings",
            {
                "Ports": {},
                "Networks": {f"net{index}": {"NetworkID": "d" * 64} for index in range(65)},
            },
        ),
    ],
)
def test_malformed_identity_or_network_data_is_refused_as_invalid(change):
    refused("invalid", change)


def test_a_config_that_is_not_a_mapping_is_unsupported():
    refused("unsupported", set_top("Config", []))


@pytest.mark.parametrize("missing", ["Mounts", "Name"])
def test_an_inspection_missing_a_required_section_is_refused_as_invalid(missing):
    inspection = source()
    del inspection[missing]
    with pytest.raises(PlanError) as error:
        prepare(CID, inspection, "create", mapping=MAPPING)
    assert error.value.code == "invalid"


def test_a_refused_preparation_leaves_the_inspection_untouched():
    inspection = source()
    inspection["HostConfig"]["Binds"] = ["/only-one-part"]
    before = copy.deepcopy(inspection)
    with pytest.raises(PlanError):
        prepare(CID, inspection, "create", mapping=MAPPING)
    assert inspection == before
