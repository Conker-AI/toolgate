"""Resource limits tests: memory, CPU, processes, time, file size, tmp, open files, workspace quota."""

import time

from conftest import labelled, run, unique_agent, while_running


def test_memory_limit_oom(docker):
    agent = unique_agent()
    # Try to allocate 600MB (limit is 256MB)
    answer = run(agent, "python3 -c 'b=bytearray(600*1024*1024); print(\"OK\")'", timeout=30)

    # Should be OOM killed
    assert answer.get("oom_killed") is True, f"Expected OOM killed, got {answer}"
    assert answer.get("exit_code") == 137, f"Expected exit code 137 (OOM), got {answer.get('exit_code')}"

    # Check container memory limit
    inspect, _ = while_running(docker, agent, "sleep 1")
    assert inspect["HostConfig"]["Memory"] == 256 * 1024 * 1024, "Memory limit should be 256MB"
    assert inspect["HostConfig"]["MemorySwap"] == 256 * 1024 * 1024, "MemorySwap should equal Memory"


def test_cpu_limit_one_core(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer

    # Check CPU limit
    assert inspect["HostConfig"]["NanoCpus"] == 1_000_000_000, "Should have 1 CPU core"

    # Check cgroup CPU limit inside container
    cpu_check = run(agent, "cat /sys/fs/cgroup/cpu.max")
    assert cpu_check["stdout"].strip() == "100000 100000", f"Expected '100000 100000', got {cpu_check['stdout']}"


def test_processes_limit_64(docker):
    agent = unique_agent()
    inspect, answer = while_running(docker, agent)
    assert answer["ok"], answer

    # Check processes limit
    assert inspect["HostConfig"]["PidsLimit"] == 64, "Pids limit should be 64"

    # Check cgroup pids limit inside container
    pids_check = run(agent, "cat /sys/fs/cgroup/pids.max")
    assert pids_check["stdout"].strip() == "64", f"Expected pids.max=64, got {pids_check['stdout']}"

    # Try to start 200 processes
    result = run(agent, "for i in {1..200}; do sleep 5 & done; wait")
    assert result["exit_code"] != 0, "Should fail when starting too many processes"
    assert "Resource temporarily unavailable" in result["stderr"], "Expected resource limit error"


def test_time_limit(docker):
    agent = unique_agent()
    start_time = time.time()
    answer = run(agent, "sleep 30", timeout=3)  # Command takes 30s, timeout is 3s
    end_time = time.time()
    duration_ms = int((end_time - start_time) * 1000)

    assert answer.get("timed_out") is True, f"Expected timeout, got {answer}"
    assert answer.get("exit_code") is None, f"Expected no exit code on timeout, got {answer.get('exit_code')}"
    assert duration_ms < 15000, f"Expected duration < 15s, got {duration_ms}ms"

    # Check no container remains
    time.sleep(1)
    remaining = labelled(docker, "conker.sandbox.agent", agent)
    assert len(remaining) == 0, f"Container still exists after timeout for agent {agent}"


def test_file_size_limit():
    agent = unique_agent()
    # Try to write 80MB (limit is 64MB)
    result = run(agent, "head -c 80M /dev/zero > big.bin")
    # SIGXFSZ: the shell reports 128 + 25.
    assert result["exit_code"] == 153, result

    # Check file size is at most 64MB if it exists
    size_check = run(agent, "test -f big.bin && stat -c %s big.bin || echo 0")
    size_bytes = int(size_check["stdout"].strip())
    assert size_bytes <= 64 * 1024 * 1024, f"File size {size_bytes} exceeds 64MB limit"


def test_tmp_size_limit():
    agent = unique_agent()
    # Try to write 40MB to /tmp (limit is 32MB)
    result = run(agent, "head -c 40M /dev/zero > /tmp/x")
    assert result["exit_code"] != 0, result
    assert "No space left on device" in result["stderr"], result


def test_open_files_limit():
    agent = unique_agent()
    result = run(agent, "ulimit -n")
    assert result["stdout"].strip() == "1024", f"Expected open files limit 1024, got {result['stdout']}"


def test_workspace_quota():
    agent = unique_agent()

    # Write 5 x 60MB files (total 300MB, limit is 256MB)
    for i in range(5):
        result = run(agent, f"dd if=/dev/zero of=file{i}.bin bs=1M count=60 2>/dev/null; echo OK{i}")
        if i < 4:  # First 4 should succeed
            assert result["exit_code"] == 0, f"File {i} should succeed"
            assert f"OK{i}" in result["stdout"]
        else:  # 5th should trigger quota
            assert result.get("workspace_exceeded") is True, f"Expected workspace exceeded on file {i}"

    # Try to write 10MB more - should be stopped
    result = run(agent, "dd if=/dev/zero of=more.bin bs=1M count=10 2>/dev/null; echo MORE")
    assert result.get("workspace_exceeded") is True, "Should still be over quota"

    # Clean up and check quota is reset
    run(agent, "rm -f *.bin")
    result = run(agent, "true")
    assert result.get("workspace_exceeded") is False, "Quota should be reset after cleanup"


def test_concurrency_per_agent():
    agent = unique_agent()

    # Start two simultaneous 5-second commands
    import threading
    import time

    results = []

    def run_command(cmd_id):
        result = run(agent, f"echo start{cmd_id} && sleep 5 && echo end{cmd_id}", timeout=10)
        results.append((cmd_id, result, time.time()))

    start_time = time.time()

    # Start two threads
    thread1 = threading.Thread(target=run_command, args=(1,))
    thread2 = threading.Thread(target=run_command, args=(2,))

    thread1.start()
    thread2.start()

    # Wait for both to complete
    thread1.join()
    thread2.join()

    end_time = time.time()
    total_time = (end_time - start_time) * 1000  # Convert to ms

    # Either they run sequentially (>= 9s total) or second gets busy error
    if len(results) == 2:
        if all(r.get("ok") for _, r, _ in results):
            # Both succeeded, check they ran sequentially
            assert total_time >= 9000, f"Expected sequential execution (>=9s), got {total_time}ms"
        else:
            # At least one got busy error
            busy_found = any(r.get("code") == "busy" for _, r, _ in results)
            assert busy_found, f"Expected busy error for concurrent execution, got results: {results}"
    else:
        raise AssertionError(f"Expected 2 results, got {len(results)}")
