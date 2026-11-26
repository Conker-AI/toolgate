"""Time and memory limits for the parsers that read outside files in a child process of their own
(`calendar_parse.py`, `mail_parse.py`), and the parent's one way of starting such a child.

The parent (`run`) starts `python -I -B <script>` with the bytes on stdin and nothing of
ToolGate's environment (no keys), and kills it after its seconds. The child bounds its own work
with `within` (one watchdog thread for every budget; when it cannot start, nothing is read) and
caps its address space with `limit_memory` (Linux only).

This module imports only the standard library. A child script runs isolated (`-I`: neither its
folder nor the working directory is on `sys.path`), so it appends its own folder to `sys.path`
(after the standard library, which therefore cannot be shadowed) and imports this file by name;
ToolGate and its tests import it as `toolgate.executors.child_guard`.
"""

from __future__ import annotations

import _thread
import os
import sys
import threading
import time as clock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class Busy(Exception):
    """The time ran out."""


class _Watch:
    """The child's one watchdog thread, for every budget (one is in force at a time). A thread
    for each budget stopped starting after a few dozen on Linux, under the address-space limit
    (an 8 MB stack each, kept a while after the thread ends), and the work it guarded then
    looked broken. When this one cannot start, nothing is read (fail closed)."""

    def __init__(self) -> None:
        self.ready = threading.Condition()
        self.budget: _Budget | None = None
        self.thread: threading.Thread | None = None

    def watch(self, budget: _Budget) -> None:
        with self.ready:
            if self.thread is None or not self.thread.is_alive():
                thread = threading.Thread(target=self._run, daemon=True)
                thread.start()
                self.thread = thread
            self.budget = budget
            self.ready.notify()

    def _run(self) -> None:
        with self.ready:
            while True:
                budget = self.budget
                if budget is None:
                    self.ready.wait()
                elif clock.monotonic() < budget.ends:
                    self.ready.wait(budget.ends - clock.monotonic())
                else:
                    self.budget = None
                    if budget.armed:
                        budget.armed, budget.fired = False, True
                        _thread.interrupt_main()


WATCH = _Watch()


class _Budget:
    """Interrupts the main thread (KeyboardInterrupt) when the work runs past its seconds."""

    def __init__(self, seconds: float) -> None:
        self.ends = clock.monotonic() + seconds
        self.armed = True
        self.fired = False

    def __enter__(self) -> _Budget:
        WATCH.watch(self)
        return self

    def __exit__(self, *_exc) -> None:
        with WATCH.ready:
            self.armed = False
            if WATCH.budget is self:
                WATCH.budget = None
            WATCH.ready.notify()


def within(seconds: float, work):
    """`work()`, or Busy when it runs past `seconds` (or none are left)."""
    if seconds <= 0:
        raise Busy
    budget, taken = _Budget(seconds), False
    try:
        with budget:
            result = work()
    except KeyboardInterrupt:
        taken = True
        raise Busy from None
    finally:
        if budget.fired and not taken:
            _settle()
    return result


def _settle() -> None:
    """A fired interrupt is on the way: take it here, not later. Busy either way (a library that
    swallowed it still ran out of time)."""
    try:
        for _ in range(200):
            clock.sleep(0.005)
    except KeyboardInterrupt:
        pass
    raise Busy


def limit_memory(limit: int) -> None:
    """At most `limit` bytes of address space for this process (Linux; elsewhere the parent's
    timeout still applies)."""
    try:
        import resource
    except ImportError:
        return
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ValueError, OSError):
        return


def environment() -> dict[str, str]:
    """Nothing of ToolGate's environment (its keys) reaches the child; Windows needs its root."""
    root = os.environ.get("SYSTEMROOT")
    return {"SYSTEMROOT": root} if root else {}


def run(script: Path, args: list[str], body: bytes, seconds: float):
    """`script` in a child process of its own, isolated, `body` on its stdin, killed after
    `seconds` (subprocess.TimeoutExpired). The finished process, its stdout as bytes."""
    import subprocess  # here, not above: the children load this module and need no subprocess

    return subprocess.run(
        [sys.executable, "-I", "-B", str(script), *args],
        input=body,
        capture_output=True,
        timeout=seconds,
        env=environment(),
        check=False,
    )
