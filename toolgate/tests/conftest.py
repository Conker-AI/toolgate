"""Keeps every test out of the repository: tests write only into pytest's temporary directories.

A test's files belong in `tmp_path`, which pytest keeps under the OS temp directory. Folders
written into the checkout instead are left behind, and on Windows a sandboxed run can lock them
so they cannot be deleted. So an audit hook watches each test while it runs: a write into the
repository (a file opened for writing, a new folder, a rename, a delete, a SQLite database) is
stopped at the write and fails that test, naming the path. Python's `__pycache__` and pytest's
`.pytest_cache` are left alone. A run whose temporary directory would sit inside the repository
(`--basetemp=.test-runs/...`, or TMPDIR pointing into it) is refused before any test starts.

Child processes are not watched; a test that starts one passes it `tmp_path` paths explicitly.
"""

from __future__ import annotations

import os
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
_ROOT = os.path.normcase(str(REPO))
_EXEMPT = {"__pycache__", ".pytest_cache"}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

_running: list[str] = []  # node id of the test in progress, if any
_writes: dict[str, list[str]] = {}


class RepositoryWrite(RuntimeError):
    """Raised at the write when a test tries to change the repository."""


def inside(raw) -> str | None:
    """The normalised path when `raw` names a place in the repository (exempt folders aside)."""
    if isinstance(raw, int):
        return None
    try:
        path = os.path.normcase(os.path.abspath(os.fsdecode(raw)))
    except (TypeError, ValueError):
        return None
    if path != _ROOT and not path.startswith(_ROOT + os.sep):
        return None
    if _EXEMPT & set(path[len(_ROOT) :].split(os.sep)):
        return None
    return path


def _database(raw) -> list:
    """The file a `sqlite3.connect` argument would write; nothing for memory or read-only."""
    if isinstance(raw, bytes):
        raw = raw.decode()
    if not isinstance(raw, str):
        return [raw]
    if raw in ("", ":memory:"):
        return []
    if not raw.startswith("file:"):
        return [raw]
    url = urllib.parse.urlsplit(raw)
    if urllib.parse.parse_qs(url.query).get("mode", [""])[0] in ("ro", "memory"):
        return []
    return [urllib.request.url2pathname(url.path)]


def _plain(*dir_fds) -> bool:
    """True when no dir_fd was given (audit events report the default as -1)."""
    return all(fd in (None, -1) for fd in dir_fds)


def targets(event: str, args: tuple) -> list:
    """The paths an audited operation would change. Paths relative to a dir_fd are skipped."""
    if event == "open":
        path, mode, flags = args
        writes = flags & _WRITE_FLAGS or (isinstance(mode, str) and set(mode) & set("wax+"))
        return [path] if writes else []
    if event == "sqlite3.connect":
        return _database(args[0])
    if event == "os.mkdir":  # Path.mkdir(exist_ok=True) on an existing folder changes nothing
        return [args[0]] if _plain(args[2]) and not os.path.exists(args[0]) else []
    if event in ("os.remove", "os.rmdir", "shutil.rmtree"):
        return [args[0]] if _plain(args[1]) else []
    if event in ("os.rename", "os.replace"):  # os.replace is audited as os.rename
        return list(args[:2]) if _plain(*args[2:4]) else []
    if event in ("os.symlink", "os.link"):
        return [args[1]] if _plain(*args[2:]) else []
    if event == "os.truncate":
        return [args[0]]
    return []


_EVENTS = {
    "open", "sqlite3.connect", "os.mkdir", "os.remove", "os.rmdir", "os.rename", "os.replace",
    "os.symlink", "os.link", "os.truncate", "shutil.rmtree",
}  # fmt: skip


def _audit(event: str, args: tuple) -> None:
    if not _running or event not in _EVENTS:
        return
    for raw in targets(event, args):
        if path := inside(raw):
            _writes.setdefault(_running[0], []).append(f"{event} {path}")
            raise RepositoryWrite(f"Tests may not write into the repository: {path}")


sys.addaudithook(_audit)


def take_writes(nodeid: str) -> list[str]:
    """The repository writes recorded for a test, cleared so they no longer fail it."""
    return _writes.pop(nodeid, [])


def pytest_configure(config: pytest.Config) -> None:
    roots = {
        "--basetemp": config.option.basetemp,
        "the temporary directory": os.environ.get("PYTEST_DEBUG_TEMPROOT") or tempfile.gettempdir(),
    }
    for name, root in roots.items():
        if root and inside(root):
            raise pytest.UsageError(
                f"{name} ({root}) is inside the repository. Tests keep their files in pytest's "
                "tmp_path; leave --basetemp unset or point it outside the checkout."
            )


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None):
    _running[:] = [item.nodeid]
    try:
        return (yield)
    finally:
        _running.clear()
        _writes.pop(item.nodeid, None)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    report = yield
    if writes := take_writes(item.nodeid):
        listed = "\n  ".join(writes)
        message = f"Wrote into the repository; keep test files in tmp_path:\n  {listed}"
        report.outcome = "failed"
        if report.longrepr is None:
            report.longrepr = message
        else:
            report.sections.append(("repository writes", message))
    return report
