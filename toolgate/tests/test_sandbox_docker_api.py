"""The sandbox runner's Docker client: every failure is a DockerError, never a silent success.

Docker is replaced by an httpx MockTransport, so each test fixes exactly what the daemon
answers. An unreachable socket, a refused status, a pull that reports an error or runs past its
deadline, and a log read that fails all raise DockerError with a short reason. The calls that
tolerate "already gone" (kill, remove) accept only those answers. Log frames are split by stream,
reassembled across chunks, cut to the tail the runner asked for and read only up to a limit.
"""

import struct

import httpx
import pytest

from toolgate.sandbox import docker_api
from toolgate.sandbox.docker_api import Docker, DockerError


def docker(handler) -> Docker:
    return Docker("/unused.sock", transport=httpx.MockTransport(handler))


def answer(status: int, **kwargs):
    return lambda request: httpx.Response(status, **kwargs)


def frame(kind: int, payload: bytes) -> bytes:
    return bytes([kind, 0, 0, 0]) + struct.pack(">I", len(payload)) + payload


def chunked(body: bytes, size: int) -> httpx.SyncByteStream:
    class Chunks(httpx.SyncByteStream):
        def __iter__(self):
            for start in range(0, len(body), size):
                yield body[start : start + size]

    return Chunks()


def test_an_unreachable_socket_is_a_docker_error_on_every_call():
    def refuse(request):
        raise httpx.ConnectError("no socket", request=request)

    client = docker(refuse)
    calls = (
        client.version,
        lambda: client.has_image("img"),
        lambda: client.pull("img"),
        lambda: client.create({}, "name"),
        lambda: client.start("c1"),
        lambda: client.inspect("c1"),
        lambda: client.kill("c1"),
        lambda: client.remove("c1"),
        lambda: client.labelled("toolgate.sandbox"),
        lambda: client.logs("c1", 10),
    )
    for call in calls:
        with pytest.raises(DockerError, match="docker_unreachable: ConnectError"):
            call()


def test_a_refused_status_names_the_code_and_cuts_the_body():
    with pytest.raises(DockerError) as error:
        docker(answer(500, text="x" * 1000)).inspect("c1")
    assert str(error.value) == "docker_500: " + "x" * 300
    with pytest.raises(DockerError, match="docker_409"):
        docker(answer(409, text="name in use")).create({}, "name")
    with pytest.raises(DockerError, match="docker_500"):
        docker(answer(500)).start("c1")


def test_kill_and_remove_accept_only_already_gone_answers():
    for status in (204, 404, 409):
        docker(answer(status)).kill("c1")
        docker(answer(status)).remove("c1")
    for status in (200, 500):
        with pytest.raises(DockerError):
            docker(answer(status)).kill("c1")
        with pytest.raises(DockerError):
            docker(answer(status)).remove("c1")


def test_has_image_quotes_the_whole_name_and_reads_404_as_missing():
    seen = []

    def handler(request):
        seen.append(request.url.raw_path.decode())
        return httpx.Response(404 if "missing" in seen[-1] else 200)

    client = docker(handler)
    assert client.has_image("ghcr.io/x/y@sha256:abc") is True
    assert client.has_image("missing/../../containers") is False
    assert seen == [
        "/v1.45/images/ghcr.io%2Fx%2Fy%40sha256%3Aabc/json",
        "/v1.45/images/missing%2F..%2F..%2Fcontainers/json",
    ]
    with pytest.raises(DockerError, match="docker_500"):
        docker(answer(500)).has_image("img")


def test_requests_carry_only_the_runner_s_own_parameters():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path.endswith("/create"):
            return httpx.Response(201, json={"Id": "abc"})
        if request.url.path.endswith("/containers/json"):
            return httpx.Response(200, json=[{"Id": "one"}, {"Id": "two"}])
        return httpx.Response(200, json={"ApiVersion": "1.45"})

    client = docker(handler)
    assert client.version() == "1.45"
    assert client.create({"Image": "img"}, "box-1") == "abc"
    assert client.labelled("toolgate.sandbox") == ["one", "two"]
    assert seen[1].url.params["name"] == "box-1"
    assert seen[2].url.params["filters"] == '{"label": ["toolgate.sandbox=1"]}'
    assert seen[2].url.params["all"] == "1"


def test_a_pull_fails_on_a_refusal_an_error_line_or_its_deadline(monkeypatch):
    with pytest.raises(DockerError, match="pull_404"):
        docker(answer(404)).pull("img")
    reporting = answer(200, text='{"status":"Pulling"}\n{"error":"manifest unknown"}\n')
    with pytest.raises(DockerError, match="pull_failed"):
        docker(reporting).pull("img")

    clock = iter([0.0, 10.0])
    monkeypatch.setattr(docker_api.time, "monotonic", lambda: next(clock))
    with pytest.raises(DockerError, match="pull_deadline"):
        docker(answer(200, text='{"status":"Pulling"}\n')).pull("img", deadline_s=5)


def test_a_clean_pull_returns_and_asks_for_the_named_image():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, text='{"status":"Pulling"}\n{"status":"Done"}\n')

    docker(handler).pull("ghcr.io/x/y@sha256:abc")
    assert seen[0].url.params["fromImage"] == "ghcr.io/x/y@sha256:abc"


def test_logs_split_streams_across_chunks_and_keep_only_the_tail():
    body = frame(1, b"hello ") + frame(2, b"oops") + frame(1, b"world") + frame(3, b"stdin?")
    stream = chunked(body, 5)  # frames cut mid-header and mid-payload
    client = docker(lambda request: httpx.Response(200, stream=stream))
    out, err, out_total, err_total = client.logs("c1", keep=8)
    assert (out, err) == (b"lo world", b"oops")
    assert (out_total, err_total) == (11, 4)  # stream 3 is neither stdout nor stderr


def test_logs_stop_reading_at_the_limit_and_refuse_a_bad_status(monkeypatch):
    monkeypatch.setattr(docker_api, "LOG_READ_MAX", 20)
    body = frame(1, b"a" * 10) + frame(1, b"b" * 10)  # 18 bytes per frame
    stream = chunked(body, 18)
    out, _, total, _ = docker(lambda request: httpx.Response(200, stream=stream)).logs("c1", 100)
    assert (out, total) == (b"a" * 10, 10)  # the chunk past the limit is never read
    with pytest.raises(DockerError, match="logs_404"):
        docker(answer(404)).logs("c1", 10)
