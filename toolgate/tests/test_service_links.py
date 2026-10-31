"""A service's linked automations include tools called inside nested workflow branches."""

from unittest.mock import patch

from toolgate.api.routes import services


def _objects(tool=(), automation=(), service=()):
    data = {"tool": list(tool), "automation": list(automation), "service": list(service)}
    return lambda kind: data[kind]


def _tool(tool_id, service_id):
    return {"id": tool_id, "service_id": service_id}


def _list_services(tool=(), automation=(), service=()):
    with patch.object(
        services.control_plane,
        "list_objects",
        side_effect=_objects(tool=tool, automation=automation, service=service),
    ):
        return services.list_services(_tier="admin")


def test_a_tool_called_inside_a_branch_links_its_automation():
    rows = _list_services(
        tool=[_tool("t1", "svc"), _tool("t2", "other")],
        automation=[
            {
                "id": "a1",
                "workflow": [
                    {
                        "type": "condition",
                        "then": [{"type": "tool_call", "tool_id": "t1"}],
                        "else": [],
                    }
                ],
            },
            {
                "id": "a2",
                "workflow": [
                    {"type": "loop", "steps": [{"type": "tool_call", "tool_id": "t1"}]}
                ],
            },
            {"id": "a3", "workflow": [{"type": "tool_call", "tool_id": "t2"}]},
        ],
        service=[{"id": "svc"}],
    )
    assert rows == [{"id": "svc", "linked_tools": ["t1"], "linked_automations": ["a1", "a2"]}]


def test_a_top_level_tool_call_still_links():
    rows = _list_services(
        tool=[_tool("t1", "svc")],
        automation=[{"id": "a1", "workflow": [{"type": "tool_call", "tool_id": "t1"}]}],
        service=[{"id": "svc"}],
    )
    assert rows == [{"id": "svc", "linked_tools": ["t1"], "linked_automations": ["a1"]}]


def test_a_service_with_no_tools_links_nothing():
    rows = _list_services(
        tool=[_tool("t1", "other")],
        automation=[{"id": "a1", "workflow": [{"type": "tool_call", "tool_id": "t1"}]}],
        service=[{"id": "svc"}],
    )
    assert rows == [{"id": "svc", "linked_tools": [], "linked_automations": []}]
