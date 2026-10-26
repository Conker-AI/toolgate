"""First end-to-end proof: a command runs in the sandbox and an install goes through the proxy."""

from conftest import install, run, unique_agent, while_running


def test_a_command_runs_as_the_sandbox_user_in_its_workspace():
    agent = unique_agent()
    answer = run(agent, "id -u; pwd; echo hello > note.txt; cat note.txt")
    assert answer["ok"], answer
    assert answer["exit_code"] == 0, answer
    assert answer["stdout"].split() == ["65533", "/workspace", "hello"]


def test_the_container_has_no_network_and_one_mount(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer
    assert inspect["HostConfig"]["NetworkMode"] == "none"
    assert [mount["Destination"] for mount in inspect["Mounts"]] == ["/workspace"]


def test_pip_install_goes_through_the_proxy():
    agent = unique_agent()
    answer = install(agent, "pip", ["six==1.17.0"])
    assert answer["ok"] and answer["exit_code"] == 0, answer
    check = run(agent, "python -c 'import six; print(six.__version__)'")
    assert check["stdout"].strip() == "1.17.0", check
