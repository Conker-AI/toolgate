"""What a sandbox request may contain. Checked in ToolGate before approval and again in the runner.

The guard refuses commands that would break the sandbox itself or wipe the agent's workspace:
deleting the root filesystem, killing every process, shutting down, fork bombs, formatting or
overwriting devices. It is a courtesy check, not the boundary: each command runs in a fresh
container with a read-only root, no network, no capabilities and hard limits, and that is what
holds when a command slips past these patterns.
"""

from __future__ import annotations

import re
import shlex

AGENT = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_COMMAND = 8000
MAX_CWD = 255
CWD_PART = re.compile(r"[A-Za-z0-9._@+-][A-Za-z0-9._@+ -]{0,99}")
MAX_PACKAGES = 20
# Names and version constraints only: no URLs, paths, options, direct references or VCS links.
PIP_SPEC = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?"
    r"(?:\[[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)*\])?"
    r"(?:(?:===|==|~=|!=|>=|<=|<|>)[A-Za-z0-9.*+!_-]{1,40}"
    r"(?:,(?:===|==|~=|!=|>=|<=|<|>)[A-Za-z0-9.*+!_-]{1,40}){0,4})?"
)
NPM_SPEC = re.compile(
    r"(?:@[a-z0-9][a-z0-9._~-]{0,99}/)?[a-z0-9][a-z0-9._~-]{0,99}"
    r"(?:@[A-Za-z0-9.^~<>=*|+ -]{1,60})?"
)
MANAGERS = ("pip", "npm")


class Refused(ValueError):
    """A request outside what the sandbox accepts; `code` is stable, the message is for people."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def agent(value) -> str:
    if not isinstance(value, str) or not AGENT.fullmatch(value):
        raise Refused("invalid_agent", "Agent ids are lowercase letters, digits and underscores.")
    return value


def cwd(value) -> str:
    """A folder inside the workspace, relative, without `..`: '' is the workspace itself."""
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > MAX_CWD or "\x00" in value:
        raise Refused("invalid_cwd", "The working folder must be a short relative path.")
    parts = [part for part in value.strip("/").split("/") if part not in ("", ".")]
    if value.startswith("/") or any(part == ".." or not CWD_PART.fullmatch(part) for part in parts):
        raise Refused(
            "invalid_cwd", "The working folder must be relative to the workspace, without '..'."
        )
    return "/".join(parts)


def packages(manager, values) -> list[str]:
    if manager not in MANAGERS:
        raise Refused("invalid_manager", "Packages install with pip or npm.")
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_PACKAGES:
        raise Refused("invalid_packages", f"Name 1 to {MAX_PACKAGES} packages.")
    pattern = PIP_SPEC if manager == "pip" else NPM_SPEC
    cleaned = []
    for value in values:
        if not isinstance(value, str) or not pattern.fullmatch(value) or value.startswith("-"):
            raise Refused(
                "invalid_packages",
                "Name registry packages only, optionally with a version: no URLs, paths or options.",
            )
        cleaned.append(value)
    if len(set(cleaned)) != len(cleaned):
        raise Refused("invalid_packages", "Name each package once.")
    return cleaned


def command(value) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_COMMAND:
        raise Refused("invalid_command", f"Give a command of 1 to {MAX_COMMAND} characters.")
    if "\x00" in value:
        raise Refused("invalid_command", "The command contains a NUL byte.")
    reason = guard(value)
    if reason:
        raise Refused("guard_refused", f"Refused: {reason}. The sandbox would not survive it.")
    return value


# --- the guard ---------------------------------------------------------------------------------

SEPARATORS = re.compile(r"\|\||&&|[;|&\n(){}`]|\$\(")
SHUTDOWN = {"shutdown", "reboot", "halt", "poweroff", "telinit", "kexec", "killall5"}
SYSTEMCTL_STOPS = {"poweroff", "reboot", "halt", "kexec", "emergency", "rescue", "suspend"}
WRAPPERS = {"sudo", "doas", "exec", "nohup", "time", "env", "command", "builtin", "nice", "timeout"}
FORK_BOMB = re.compile(r"([^\s(){};|&]+)\s*\(\s*\)\s*\{[^}]*\1\s*\|\s*\1[^}]*&")
DEVICE_WRITE = re.compile(r">\s*/dev/(?:sd|hd|vd|xvd|nvme|mmcblk|dm-|md|loop)")
# The filesystem root, everything under it, and the workspace itself.
PROTECTED = {
    "/",
    "/*",
    "/.",
    "/..",
    "/workspace",
    "/workspace/",
    "/workspace/*",
    "/workspace/.",
    "~",
}
# pkill/killall arguments that match every process.
EVERYTHING = {".", ".*", "^", "", "-u", "--user", "-U", "--uid"}


def _words(segment: str) -> list[str]:
    try:
        words = shlex.split(segment, comments=True)
    except ValueError:
        words = segment.split()
    while words and (words[0] in WRAPPERS or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0])):
        words = words[1:]
        while words and words[0].startswith("-"):
            words = words[1:]
    if words:
        words[0] = words[0].rsplit("/", 1)[-1]
    return words


def _short_flags(words: list[str]) -> str:
    return "".join(word[1:] for word in words if word.startswith("-") and not word.startswith("--"))


def _segment_reason(words: list[str]) -> str | None:
    if not words:
        return None
    name, rest = words[0], words[1:]
    targets = [word for word in rest if not word.startswith("-")]
    recursive = "r" in _short_flags(rest).lower() or "--recursive" in rest
    if name == "rm" and (
        "--no-preserve-root" in rest or (recursive and any(t in PROTECTED for t in targets))
    ):
        return "deleting the root filesystem or the whole workspace"
    if name == "find" and targets[:1] and targets[0] in PROTECTED and "-delete" in rest:
        return "deleting the root filesystem or the whole workspace"
    if name in ("chmod", "chown", "chgrp") and recursive and any(t in PROTECTED for t in targets):
        return "changing permissions of the whole filesystem"
    # PID -1 is every process the caller may signal.
    if name == "kill" and "-1" in rest and (rest.index("-1") > 0 or rest[:1] == ["--"]):
        return "killing every process"
    if name in ("pkill", "killall") and any(word in EVERYTHING for word in rest):
        return "killing every process"
    if name in SHUTDOWN:
        return "shutting down"
    if name == "init" and targets[:1] and targets[0] in ("0", "6", "1", "S", "s"):
        return "shutting down"
    if name == "systemctl" and any(t in SYSTEMCTL_STOPS for t in targets):
        return "shutting down"
    if name.startswith("mkfs") or name in ("wipefs", "fdisk", "sfdisk", "parted", "shred"):
        return "formatting or wiping a device"
    if name == "dd" and any(word.startswith("of=/dev/") for word in rest):
        return "overwriting a device"
    return None


def guard(text: str) -> str | None:
    """Why this command is refused, or None. Best effort; the container limits are the boundary."""
    if FORK_BOMB.search(text):
        return "a fork bomb"
    if DEVICE_WRITE.search(text):
        return "overwriting a device"
    for segment in SEPARATORS.split(text):
        reason = _segment_reason(_words(segment))
        if reason:
            return reason
    return None
