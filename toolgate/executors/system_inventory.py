"""Fixed read-only private SystemGate transport, separate from public HTTP tools."""

from __future__ import annotations

import json
import math
import os
import time
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_BYTES = 1024 * 1024
DEADLINE_SECONDS = 10.0
Text = Annotated[str, Field(max_length=256)]
Number = Annotated[float, Field(ge=0, allow_inf_nan=False)]
PortNumber = Annotated[int, Field(ge=1, le=65535)]


class InventoryError(RuntimeError):
    def __init__(self, code):
        self.code = code
        self.status = (
            422
            if code == "invalid_limit"
            else 503
            if code in ("not_configured", "invalid_configuration")
            else 502
        )
        super().__init__(
            {
                "invalid_limit": "Inventory limit must be an integer from 1 to 200.",
                "not_configured": "SystemGate inventory is not configured.",
                "invalid_configuration": "SystemGate inventory configuration is invalid.",
                "unavailable": "SystemGate inventory is unavailable.",
                "response_limit": "SystemGate inventory exceeded its response limit.",
                "deadline": "SystemGate inventory exceeded its read deadline.",
                "invalid_response": "SystemGate inventory returned an invalid response.",
            }[code]
        )

    @property
    def message(self):
        return str(self)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Process(Strict):
    id: Text
    pid: Annotated[int, Field(gt=0)]
    createdAt: Number
    name: Annotated[str, Field(max_length=160)]
    status: Annotated[str, Field(max_length=40)]
    memoryBytes: Number | None
    cpuPercent: None
    command: None
    user: None
    restarts: None
    containerId: None
    managed: Literal[False]

    @field_validator("managed", mode="before")
    @classmethod
    def strict_managed(cls, value):
        if value is not False:
            raise ValueError("managed")
        return value

    @model_validator(mode="after")
    def identity(self):
        if self.id != f"process:{self.pid}:{float(self.createdAt).hex()}":
            raise ValueError("identity")
        return self


class Container(Strict):
    id: Annotated[str, Field(min_length=1, max_length=128)]
    name: Annotated[str, Field(max_length=160)]
    image: Text
    status: Annotated[str, Field(max_length=40)]
    processId: None
    restarts: None
    managed: Literal[False]

    @field_validator("managed", mode="before")
    @classmethod
    def strict_managed(cls, value):
        if value is not False:
            raise ValueError("managed")
        return value


class Port(Strict):
    id: Annotated[str, Field(pattern=r"^(listener|binding):[a-f0-9]{64}$")]
    kind: Literal["listener", "container-binding"]
    hostAddress: Annotated[str, Field(max_length=64)]
    hostPort: PortNumber
    targetPort: PortNumber | None
    protocol: Literal["tcp", "udp"]
    processId: Text | None
    containerId: Annotated[str, Field(max_length=128)] | None
    listening: bool | None
    bound: bool | None

    @model_validator(mode="after")
    def observations(self):
        if self.kind == "container-binding":
            if (
                self.containerId is None
                or self.targetPort is None
                or self.processId is not None
                or self.listening is not None
                or self.bound is not None
                or not self.id.startswith("binding:")
            ):
                raise ValueError("binding")
        elif (
            self.containerId is not None
            or self.targetPort is not None
            or self.bound is not True
            or self.listening is not (True if self.protocol == "tcp" else None)
            or not self.id.startswith("listener:")
        ):
            raise ValueError("listener")
        return self


ErrorCode = Literal[
    "process_identity_unavailable",
    "process_changed_during_collection",
    "process_unavailable",
    "collection_failed",
    "process_link_unavailable",
    "listener_collection_failed",
    "container_identity_unavailable",
    "invalid_container_binding",
    "container_unavailable",
    "container_bindings_unavailable",
    "client_close_failed",
]


class Section(Strict):
    status: Literal["ok", "partial", "unavailable"]
    truncated: bool
    errors: Annotated[list[ErrorCode], Field(max_length=16)]


class Processes(Section):
    results: Annotated[list[Process], Field(max_length=200)]


class Containers(Section):
    results: Annotated[list[Container], Field(max_length=200)]


class Ports(Section):
    results: Annotated[list[Port], Field(max_length=200)]


class Source(Strict):
    procfs: Annotated[str, Field(max_length=4096)]
    processScope: Literal["configured-procfs", "collector-namespace"]
    networkScope: Literal["collector-namespace"]
    containerScope: Literal["configured-docker-daemon"]


class Capabilities(Strict):
    inspection: Literal[True]
    processActions: Literal[False]
    containerActions: Literal[False]
    portMutation: Literal[False]
    terminal: Literal[False]
    files: Literal[False]

    @field_validator("*", mode="before")
    @classmethod
    def strict_boolean(cls, value):
        if type(value) is not bool:
            raise ValueError("capability")
        return value


class Envelope(Strict):
    mode: Literal["observed"]
    sampledAt: Annotated[str, Field(max_length=64)]
    ageSeconds: Number
    collectionSeconds: Number
    source: Source
    status: Literal["ok", "partial"]
    processes: Processes
    containers: Containers
    ports: Ports
    capabilities: Capabilities
    unavailableFields: Annotated[list[Text], Field(max_length=32)]

    @model_validator(mode="after")
    def consistency(self):
        timestamp = datetime.fromisoformat(self.sampledAt)
        if timestamp.tzinfo is None or not math.isfinite(timestamp.timestamp()):
            raise ValueError("timestamp")
        sections = [self.processes, self.containers, self.ports]
        expected = (
            "partial"
            if any(s.status != "ok" or s.truncated for s in sections)
            else "ok"
        )
        if self.status != expected:
            raise ValueError("status")
        for section in sections:
            if (section.status == "ok" and section.errors) or (
                section.status == "unavailable" and section.results
            ):
                raise ValueError("section")
            ids = [r.id for r in section.results]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate")
        processes = {p.id for p in self.processes.results}
        containers = {c.id for c in self.containers.results}
        if any(
            (p.processId is not None and p.processId not in processes)
            or (p.containerId is not None and p.containerId not in containers)
            for p in self.ports.results
        ):
            raise ValueError("references")
        return self


def _configuration():
    url = os.environ.get("TOOLGATE_SYSTEMGATE_URL", "").strip()
    key = os.environ.get("TOOLGATE_SYSTEMGATE_KEY", "")
    if not url or not key:
        raise InventoryError("not_configured")
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or any(ord(c) <= 32 or ord(c) >= 127 for c in url)
            or not 1 <= (parsed.port or 80) <= 65535
            or len(key) > 4096
            or any(ord(c) < 32 or ord(c) >= 127 for c in key)
        ):
            raise ValueError("configuration")
    except ValueError:
        raise InventoryError("invalid_configuration") from None
    return url.rstrip("/") + "/runtime", key


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def collect(limit=100, *, transport=None):
    if type(limit) is not int or not 1 <= limit <= 200:
        raise InventoryError("invalid_limit")
    url, key = _configuration()
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        with httpx.Client(  # noqa: SIM117 - Stream lifetime is nested within its client.
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(1.0, connect=3.0),
        ) as client:
            with client.stream(
                "GET",
                url,
                params={"limit": limit},
                headers={
                    "X-SystemGate-Key": key,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            ) as response:
                if response.status_code != 200:
                    raise InventoryError("unavailable")
                if (
                    response.headers.get("content-encoding", "identity").lower()
                    != "identity"
                ):
                    raise InventoryError("invalid_response")
                raw = bytearray()
                for chunk in response.iter_raw():
                    if time.monotonic() > deadline:
                        raise InventoryError("deadline")
                    if len(raw) + len(chunk) > MAX_BYTES:
                        raise InventoryError("response_limit")
                    raw.extend(chunk)
                if time.monotonic() > deadline:
                    raise InventoryError("deadline")
        data = json.loads(raw, object_pairs_hook=_object)
        if key in json.dumps(data, ensure_ascii=False):
            raise InventoryError("invalid_response")
        result = Envelope.model_validate(data).model_dump()
        if any(
            len(result[s]["results"]) > limit
            for s in ("processes", "containers", "ports")
        ):
            raise InventoryError("invalid_response")
        return result
    except InventoryError:
        raise
    except (httpx.HTTPError, OSError):
        raise InventoryError("unavailable") from None
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise InventoryError("invalid_response") from None
