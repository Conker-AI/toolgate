"""The proxy's cooldown: package metadata without the releases of the last few days.

Malicious versions of real packages are usually found and pulled within days. The package proxy
passes each PyPI index page and npm document through these filters, so pip and npm never see a
release younger than the cooldown and pick an older one, for the package asked for and for every
dependency. A release with no readable date is hidden too. Stdlib only, so tests import it on any
platform (proxy.py needs Unix sockets).
"""

from __future__ import annotations

import json
import os
from datetime import datetime

DAYS = 7
MAX_DAYS = 90
PYPI_JSON = "application/vnd.pypi.simple.v1+json"


def days() -> int:
    """PROXY_COOLDOWN_DAYS: empty or unset is DAYS; otherwise a whole number 0..MAX_DAYS."""
    raw = os.environ.get("PROXY_COOLDOWN_DAYS", "").strip()
    if not raw:
        return DAYS
    if not raw.isdigit() or int(raw) > MAX_DAYS:
        raise ValueError(f"PROXY_COOLDOWN_DAYS must be 0..{MAX_DAYS}")
    return int(raw)


def _old_enough(value, cutoff: float) -> bool:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() <= cutoff
    except (TypeError, ValueError, OverflowError, OSError):
        return False


def _document(body: bytes) -> dict:
    doc = json.loads(body)  # a JSONDecodeError is a ValueError
    if not isinstance(doc, dict):
        raise ValueError("metadata is not a JSON object")
    return doc


def _compact(doc: dict) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode()


def filter_pypi(body: bytes, now: float, days: int) -> tuple[bytes | None, int]:
    """A PEP 691 simple page without files uploaded in the last `days` days, and how many were
    removed. None when no file is left."""
    if days == 0:
        return body, 0
    doc = _document(body)
    files = doc.get("files")
    if not isinstance(files, list):
        raise ValueError("no file list")
    cutoff = now - days * 86400
    kept = [f for f in files if isinstance(f, dict) and _old_enough(f.get("upload-time"), cutoff)]
    removed = len(files) - len(kept)
    if not kept:
        return None, removed
    doc["files"] = kept
    return _compact(doc), removed


def filter_npm(body: bytes, now: float, days: int) -> tuple[bytes | None, int]:
    """A full npm document without versions published in the last `days` days, and how many were
    removed. Tags that named a removed version go; `latest` moves to the newest stable version
    left (or the newest of any kind). None when no version is left."""
    if days == 0:
        return body, 0
    doc = _document(body)
    versions = doc.get("versions")
    if not isinstance(versions, dict):
        raise ValueError("no version list")
    stamps = doc.get("time")
    stamps = stamps if isinstance(stamps, dict) else {}
    cutoff = now - days * 86400
    kept = {v: data for v, data in versions.items() if _old_enough(stamps.get(v), cutoff)}
    removed = len(versions) - len(kept)
    if not kept:
        return None, removed
    doc["versions"] = kept
    tags = doc.get("dist-tags")
    tags = {t: v for t, v in tags.items() if v in kept} if isinstance(tags, dict) else {}
    if "latest" not in tags:
        newest = sorted(kept, key=lambda v: str(stamps.get(v)))
        stable = [v for v in newest if "-" not in v]
        tags["latest"] = (stable or newest)[-1]
    doc["dist-tags"] = tags
    return _compact(doc), removed
