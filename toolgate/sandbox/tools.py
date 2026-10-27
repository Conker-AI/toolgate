"""The sandbox's two built-in tools: Terminal (`sandbox.run`) and Install packages."""

import os

from toolgate.core import control_plane

TERMINAL_DESCRIPTION = (
    "Run a shell command in this agent's own sandbox: a fresh Linux container with Python, Node "
    "and git, no network, only the agent's workspace folder at /workspace (shared with the "
    "owner), and limits on CPU, memory, processes, disk and time. The command travels inside a "
    "JSON string: quote with single quotes inside it, for example python3 -c 'print(1)'."
)
# Descriptions ToolGate itself once registered. Only these are refreshed on start; an owner's
# own edit to the description is never overwritten.
PREVIOUS_TERMINAL_DESCRIPTIONS = (
    (
        "Run a shell command in this agent's own sandbox: a fresh Linux container with Python, "
        "Node and git, no network, only the agent's workspace folder at /workspace (shared with "
        "the owner), and limits on CPU, memory, processes, disk and time."
    ),
)


def ensure_builtin_sandbox_capabilities() -> None:
    """The terminal and install tools, once a sandbox runner is configured. Registered only when
    absent, so the owner's access choices survive restarts. Default: AI decides."""
    if not os.environ.get("TOOLGATE_SANDBOX_SOCKET"):
        return
    existing = control_plane.get("tool", "sandbox.run")
    if existing and existing.get("description") in PREVIOUS_TERMINAL_DESCRIPTIONS:
        # Small local models broke the JSON on nested double quotes; the new text tells them how.
        control_plane.update_tool(
            "sandbox.run",
            {**existing, "description": TERMINAL_DESCRIPTION, "expected_version": existing.get("version", 1)},
        )
    if not control_plane.get("tool", "sandbox.run"):
        control_plane.create_tool(
            {
                "id": "sandbox.run",
                "name": "Terminal",
                "description": TERMINAL_DESCRIPTION,
                "category": "controlled",
                "authorization": "ai_review",
                "status": "active",
                "inputs": [
                    {
                        "name": "command",
                        "type": "string",
                        "required": True,
                        "min_length": 1,
                        "max_length": 8000,
                    },
                    {
                        "name": "cwd",
                        "type": "string",
                        "required": False,
                        "default": "",
                        "max_length": 255,
                    },
                    {
                        "name": "timeout_seconds",
                        "type": "integer",
                        "required": False,
                        "default": 30,
                        "minimum": 1,
                        "maximum": 100,
                    },
                ],
                "outputs": [{"name": "run", "type": "object"}],
                "execution": {"type": "sandbox_run"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 30,
                        "cooldown_seconds": 0,
                        "max_per_hour": 600,
                        "max_runtime_seconds": 170,
                    }
                },
            }
        )
    if not control_plane.get("tool", "sandbox.install"):
        control_plane.create_tool(
            {
                "id": "sandbox.install",
                "name": "Install packages",
                "description": "Install Python (pip) or Node (npm) packages into this agent's workspace from the official registries, through the package proxy: the only time the sandbox reaches the internet. Every download is logged.",
                "category": "controlled",
                "authorization": "ai_review",
                "status": "active",
                "inputs": [
                    {
                        "name": "manager",
                        "type": "string",
                        "required": True,
                        "allowed_values": ["pip", "npm"],
                    },
                    {
                        "name": "packages",
                        "type": "array",
                        "required": True,
                        "min_items": 1,
                        "max_items": 20,
                        "unique_items": True,
                        "item_type": "string",
                    },
                ],
                "outputs": [{"name": "run", "type": "object"}],
                "execution": {"type": "sandbox_install"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 6,
                        "cooldown_seconds": 0,
                        "max_per_hour": 60,
                        "max_runtime_seconds": 170,
                    }
                },
            }
        )
