import pytest

from toolgate.executors.port_plan import PlanError, plan

ID = "a" * 64


def binding(host=8080, target=80, address="127.0.0.1", protocol="tcp"):
    return {
        "hostAddress": address,
        "hostPort": host,
        "containerPort": target,
        "protocol": protocol,
    }


def test_create_edit_remove_preserve_other_bindings_and_report_replacement():
    first, keep = binding(), binding(5353, 53, protocol="udp")
    created = plan(ID, [keep], "create", mapping=first, running=True)
    assert created["requiresReplacement"] and created["downtimeExpected"]
    edited = plan(ID, created["after"], "edit", original=first, mapping=binding(8081))
    assert keep in edited["after"] and first not in edited["after"]
    removed = plan(ID, edited["after"], "remove", original=binding(8081))
    assert removed["after"] == [keep]
    assert removed["hostAvailability"] == "not_checked"


def test_unchanged_edit_does_not_require_replacement():
    value = binding()
    result = plan(ID, [value], "edit", original=value, mapping=value, running=True)
    assert not result["changed"] and not result["requiresReplacement"]
    assert not result["downtimeExpected"]


@pytest.mark.parametrize(
    "value",
    [
        binding(True),
        binding(0),
        binding(65536),
        binding(protocol="sctp"),
        binding(address="localhost"),
        binding(address="192.168.1.2"),
    ],
)
def test_invalid_new_mapping_rejected(value):
    with pytest.raises(PlanError):
        plan(ID, [], "create", mapping=value)


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "::"])
def test_overlapping_bindings_conflict(address):
    with pytest.raises(PlanError, match="conflict"):
        plan(ID, [binding(address=address)], "create", mapping=binding(target=90))


def test_tcp_and_udp_can_share_number_and_digest_is_order_independent():
    first, second = binding(), binding(protocol="udp")
    result = plan(ID, [first], "create", mapping=second)
    a = plan(ID, result["after"], "remove", original=first)
    b = plan(ID, list(reversed(result["after"])), "remove", original=first)
    assert a == b


@pytest.mark.parametrize(
    "options",
    [
        {"network_mode": "host"},
        {"network_mode": "none"},
        {"network_mode": "container:other"},
        {"publish_all": True},
        {"auto_remove": True},
    ],
)
def test_unsupported_recreation_modes_are_explicit(options):
    with pytest.raises(PlanError, match="different"):
        plan(ID, [], "create", mapping=binding(), **options)


def test_stale_original_is_not_silently_recreated():
    with pytest.raises(PlanError, match="no longer"):
        plan(ID, [], "edit", original=binding(), mapping=binding(8081))
