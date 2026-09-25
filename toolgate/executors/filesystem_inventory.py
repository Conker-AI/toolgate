"""Metadata-only listing of operator-configured Linux directories."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from datetime import UTC, datetime

MAX_SCAN = 2000
CAPABILITIES = {"list": True, "read": False, "write": False}


class FileError(RuntimeError):
    def __init__(self, code):
        self.code = code
        self.status = {
            "invalid_arguments": 422, "not_configured": 503,
            "invalid_configuration": 503, "unknown_root": 404,
            "unsupported_platform": 503, "unavailable": 503,
        }[code]
        super().__init__({
            "invalid_arguments": "File listing arguments are invalid.",
            "not_configured": "File roots are not configured.",
            "invalid_configuration": "File root configuration is invalid.",
            "unknown_root": "File root is not configured.",
            "unsupported_platform": "File listing requires the Linux directory backend.",
            "unavailable": "Directory metadata is unavailable.",
        }[code])

    @property
    def message(self):
        return str(self)


def _component(value):
    return (
        isinstance(value, str) and 0 < len(value) <= 255
        and value not in (".", "..")
        and not any(c in "/\\" or ord(c) < 32 or ord(c) == 127
                    or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    )


def _relative(value):
    return isinstance(value, str) and len(value) <= 4096 and (
        value == "" or all(_component(c) for c in value.split("/"))
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _roots():
    raw = os.environ.get("TOOLGATE_FILE_ROOTS", "")
    if not raw:
        raise FileError("not_configured")
    try:
        if len(raw) > 32768:
            raise ValueError
        configured = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(configured, dict) or not 1 <= len(configured) <= 64:
            raise ValueError
        for key, value in configured.items():
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", key):
                raise ValueError
            if not isinstance(value, str) or not value.startswith("/"):
                raise ValueError
            if not _relative(value[1:]):
                raise ValueError
        return configured
    except (ValueError, TypeError, RecursionError):
        raise FileError("invalid_configuration") from None


def roots():
    """Configuration only; this does not assert that any directory exists."""
    return {
        "mode": "configured",
        "roots": [{"id": key, "path": path} for key, path in sorted(_roots().items())],
        "capabilities": dict(CAPABILITIES),
    }


class LinuxBackend:
    def open_root(self):
        if not sys.platform.startswith("linux"):
            raise FileError("unsupported_platform")
        return os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    def open_child(self, fd, name):
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=fd)

    def close(self, fd):
        os.close(fd)

    def scan(self, fd):
        return os.scandir(fd)

    def mode(self, fd, name):
        return os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode


def list_directory(root_id, path="", limit=200, *, backend=None):
    if (not isinstance(root_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", root_id)
            or not _relative(path) or type(limit) is not int or not 1 <= limit <= 200):
        raise FileError("invalid_arguments")
    configured = _roots()
    if root_id not in configured:
        raise FileError("unknown_root")
    backend = backend or LinuxBackend()
    fd = None
    try:
        fd = backend.open_root()
        components = [c for c in configured[root_id].split("/") if c]
        components.extend(path.split("/") if path else [])
        for component in components:
            child = backend.open_child(fd, component)
            backend.close(fd)
            fd = child
        entries = []
        truncated = False
        with backend.scan(fd) as iterator:
            for scanned, entry in enumerate(iterator):
                if scanned >= MAX_SCAN or len(entries) >= limit:
                    truncated = True
                    break
                name = entry.name
                if not _component(name):
                    truncated = True
                    continue
                mode = backend.mode(fd, name)
                kind = ("symlink" if stat.S_ISLNK(mode) else "directory" if stat.S_ISDIR(mode)
                        else "file" if stat.S_ISREG(mode) else "other")
                relative = f"{path}/{name}" if path else name
                if len(relative) > 4096:
                    truncated = True
                    continue
                entries.append({"name": name, "path": relative, "kind": kind})
        return {
            "mode": "observed", "rootId": root_id, "path": path,
            "entries": sorted(entries, key=lambda item: (item["kind"] != "directory", item["name"])),
            "truncated": truncated, "sampledAt": datetime.now(UTC).isoformat(),
        }
    except OSError:
        raise FileError("unavailable") from None
    finally:
        if fd is not None:
            backend.close(fd)
