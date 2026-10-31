"""ToolGate's side of the agent sandbox: the terminal and install tools, sent to the runner.

ToolGate holds no Docker socket for this. It sends one typed request per call to the sandbox
runner over the Unix socket in `TOOLGATE_SANDBOX_SOCKET` and returns the bounded result. The
agent comes from the caller's identity, never from the arguments, so an agent can only ever reach
its own workspace folder. A call that may have run but whose answer was lost raises
OutcomeUnknown, which the journal keeps uncertain: a command is never sent twice.
"""

from __future__ import annotations

import json
import os
import re
import socket

from toolgate.core import tool_settings
from toolgate.sandbox import validation

EXECUTIONS = {"sandbox_run": "sandbox.run", "sandbox_install": "sandbox.install"}
MAX_RUN_SECONDS = tool_settings.TERMINAL_SECONDS
DEFAULT_RUN_SECONDS = 30
MAX_ANSWER = 1024 * 1024
KEEP = 16000
# Terminal control sequences and other control characters, except newline and tab.
CONTROL = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|[\x00-\x08\x0b-\x1f\x7f]"
)


class SandboxError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class OutcomeUnknown(RuntimeError):
    code = "sandbox_outcome_unknown"

    def __init__(self):
        super().__init__("The command may have run; check the workspace before running it again.")


def _seconds(args: dict) -> int:
    """The time limit; absent or null means the default, as models often send null. The most is
    the owner's Terminal limit when it is lower than the Terminal's own."""
    most = tool_settings.terminal_seconds()
    seconds = args.get("timeout_seconds")
    if seconds is None:
        return min(DEFAULT_RUN_SECONDS, most)
    if type(seconds) is not int or not 1 <= seconds <= most:
        raise validation.Refused("invalid_timeout", f"timeout_seconds is 1 to {most}.")
    return seconds


def check(tool: dict, args: dict) -> list[str]:
    """Argument problems, before any approval is asked for. The guard runs here."""
    try:
        if tool["execution"]["type"] == "sandbox_run":
            if set(args) - {"command", "cwd", "timeout_seconds"}:
                return ["Provide only command, cwd and timeout_seconds."]
            validation.command(args.get("command"))
            validation.cwd(args.get("cwd", ""))
            _seconds(args)
        else:
            if set(args) - {"manager", "packages"}:
                return ["Provide only manager and packages."]
            validation.packages(args.get("manager"), args.get("packages"))
    except validation.Refused as exc:
        return [str(exc)]
    return []


def _clean(text: str) -> tuple[str, bool]:
    text = CONTROL.sub("", text)
    if len(text) > KEEP:
        return text[-KEEP:], True
    return text, False


def _send(request: dict, timeout: float) -> dict:
    path = os.environ.get("TOOLGATE_SANDBOX_SOCKET", "")
    if not path:
        raise SandboxError("not_configured", "The agent sandbox is not set up on this server.")
    sent = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(path)
            connection.settimeout(timeout)
            connection.sendall(json.dumps(request).encode() + b"\n")
            # Not before: sendall raises only while its last byte, the newline, is unsent, and the
            # runner runs no request without one (test_a_request_cut_before_its_newline_never_runs).
            sent = True
            raw = connection.makefile("rb").readline(MAX_ANSWER + 1)
        if len(raw) > MAX_ANSWER or not raw.endswith(b"\n"):
            raise ValueError("bad answer")
        answer = json.loads(raw)
        if not isinstance(answer, dict):
            raise ValueError("bad answer")
    except (OSError, ValueError):
        if sent:
            raise OutcomeUnknown() from None
        raise SandboxError("unavailable", "The agent sandbox is not reachable.") from None
    if not answer.get("ok"):
        if answer.get("code") == "outcome_unknown":
            raise OutcomeUnknown()
        raise SandboxError(
            str(answer.get("code", "refused"))[:60], str(answer.get("message", ""))[:500]
        )
    return answer


def execute(tool: dict, args: dict, agent: str, action_id: str) -> dict:
    """Run the call for `agent` (from the caller's identity). Returns the tool result envelope."""
    kind = tool["execution"]["type"]
    try:
        agent = validation.agent(agent)
        if kind == "sandbox_run":
            seconds = _seconds(args)
            request = {
                "v": 1,
                "op": "run",
                "agent": agent,
                "command": validation.command(args.get("command")),
                "cwd": validation.cwd(args.get("cwd", "")),
                "timeout": seconds,
                "request_id": action_id[:100],
            }
        else:
            seconds = tool_settings.seconds(MAX_RUN_SECONDS)
            request = {
                "v": 1,
                "op": "install",
                "agent": agent,
                "manager": args.get("manager"),
                "packages": validation.packages(args.get("manager"), args.get("packages")),
                "timeout": seconds,
                "request_id": action_id[:100],
            }
    except validation.Refused as exc:
        return {"ok": False, "error": str(exc), "error_code": exc.code}
    limits = tool_settings.terminal_limits(install=kind == "sandbox_install")
    if limits:
        # Lower than the runner's own, never higher: the runner keeps its limit when that is less.
        request["limits"] = limits
    try:
        answer = _send(request, seconds + 60)
    except SandboxError as exc:
        return {"ok": False, "error": str(exc), "error_code": exc.code}
    stdout, cut_out = _clean(str(answer.get("stdout", "")))
    stderr, cut_err = _clean(str(answer.get("stderr", "")))
    run = {
        "exitCode": answer.get("exit_code"),
        "timedOut": bool(answer.get("timed_out")),
        "outOfMemory": bool(answer.get("oom_killed")),
        "workspaceFull": bool(answer.get("workspace_exceeded")),
        "durationMs": int(answer.get("duration_ms") or 0),
        "stdout": stdout,
        "stderr": stderr,
        "truncated": cut_out
        or cut_err
        or bool(answer.get("stdout_truncated"))
        or bool(answer.get("stderr_truncated")),
        "workspaceBytes": int(answer.get("workspace_bytes") or 0),
    }
    if kind == "sandbox_install":
        run["manager"] = request["manager"]
        run["packages"] = request["packages"]
        run["installed"] = run["exitCode"] == 0 and not run["timedOut"]
    return {"ok": True, "result": run}
