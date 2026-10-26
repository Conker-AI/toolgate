"""The few Docker Engine API calls the sandbox runner makes, over the local Unix socket.

Create, start, inspect, kill, read logs and remove containers the runner itself labelled, and
pull its one pinned image. Nothing here accepts a container body from outside the runner.
"""

from __future__ import annotations

import json
import struct
import time
from urllib.parse import quote

import httpx

API = "/v1.45"
LOG_READ_MAX = 8 * 1024 * 1024


class DockerError(RuntimeError):
    pass


class Docker:
    def __init__(self, socket_path: str, transport: httpx.BaseTransport | None = None):
        self.client = httpx.Client(
            base_url="http://docker",
            transport=transport or httpx.HTTPTransport(uds=socket_path),
            timeout=httpx.Timeout(30.0, connect=5.0),
            trust_env=False,
            follow_redirects=False,
        )

    def _call(self, method, path, *, ok=(200,), **options):
        try:
            response = self.client.request(method, API + path, **options)
        except httpx.HTTPError as exc:
            raise DockerError(f"docker_unreachable: {type(exc).__name__}") from None
        if response.status_code not in ok:
            raise DockerError(f"docker_{response.status_code}: {response.text[:300]}")
        return response

    def version(self) -> str:
        return self._call("GET", "/version").json().get("ApiVersion", "0")

    def has_image(self, image: str) -> bool:
        return (
            self._call("GET", f"/images/{quote(image, safe='')}/json", ok=(200, 404)).status_code
            == 200
        )

    def pull(self, image: str, deadline_s: float = 900.0) -> None:
        # Pulled by digest, so the content is fixed however the tag moves.
        end = time.monotonic() + deadline_s
        try:
            with self.client.stream(
                "POST",
                API + "/images/create",
                params={"fromImage": image},
                timeout=httpx.Timeout(60.0, connect=5.0),
            ) as response:
                if response.status_code != 200:
                    raise DockerError(f"pull_{response.status_code}")
                for line in response.iter_lines():
                    if time.monotonic() > end:
                        raise DockerError("pull_deadline")
                    if '"error"' in line:
                        raise DockerError("pull_failed")
        except httpx.HTTPError as exc:
            raise DockerError(f"docker_unreachable: {type(exc).__name__}") from None

    def create(self, body: dict, name: str) -> str:
        response = self._call(
            "POST", "/containers/create", ok=(201,), params={"name": name}, json=body
        )
        return response.json()["Id"]

    def start(self, container: str) -> None:
        self._call("POST", f"/containers/{container}/start", ok=(204, 304))

    def inspect(self, container: str) -> dict:
        return self._call("GET", f"/containers/{container}/json").json()

    def kill(self, container: str) -> None:
        # 409: it already stopped, which is what was wanted.
        self._call(
            "POST", f"/containers/{container}/kill", ok=(204, 404, 409), params={"signal": "KILL"}
        )

    def remove(self, container: str) -> None:
        self._call("DELETE", f"/containers/{container}", ok=(204, 404, 409), params={"force": "1"})

    def labelled(self, label: str) -> list[str]:
        filters = json.dumps({"label": [f"{label}=1"]})
        response = self._call("GET", "/containers/json", params={"all": "1", "filters": filters})
        return [item["Id"] for item in response.json()]

    def logs(self, container: str, keep: int) -> tuple[bytes, bytes, int, int]:
        """The last `keep` bytes of stdout and of stderr, plus each stream's total size."""
        streams = {1: bytearray(), 2: bytearray()}
        totals = {1: 0, 2: 0}
        buffer = bytearray()
        read = 0
        try:
            with self.client.stream(
                "GET", f"{API}/containers/{container}/logs", params={"stdout": "1", "stderr": "1"}
            ) as response:
                if response.status_code != 200:
                    raise DockerError(f"logs_{response.status_code}")
                for chunk in response.iter_raw():
                    read += len(chunk)
                    if read > LOG_READ_MAX:
                        break
                    buffer.extend(chunk)
                    while len(buffer) >= 8:
                        kind, size = buffer[0], struct.unpack(">I", bytes(buffer[4:8]))[0]
                        if len(buffer) < 8 + size:
                            break
                        payload = bytes(buffer[8 : 8 + size])
                        del buffer[: 8 + size]
                        if kind in streams:
                            totals[kind] += len(payload)
                            streams[kind].extend(payload)
                            if len(streams[kind]) > keep:
                                del streams[kind][: len(streams[kind]) - keep]
        except httpx.HTTPError as exc:
            raise DockerError(f"docker_unreachable: {type(exc).__name__}") from None
        return bytes(streams[1]), bytes(streams[2]), totals[1], totals[2]
