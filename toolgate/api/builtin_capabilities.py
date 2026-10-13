"""Built-in system and research capabilities that ToolGate registers on startup."""

from toolgate.core import control_plane


def ensure_builtin_system_capabilities() -> None:
    """Register fixed operations without changing existing owner policy or key scopes."""
    if not control_plane.get("tool", "system.port-control"):
        control_plane.create_tool(
            {
                "id": "system.port-control",
                "name": "Reviewed port replacement",
                "description": "Apply one inspected port change by replacing a managed container, retaining the original for recovery. Requires exact owner approval.",
                "category": "system",
                "authorization": "owner_confirmation",
                "status": "active",
                "inputs": [
                    {"name": "container_id", "type": "string", "required": True},
                    {"name": "review_id", "type": "string", "required": True},
                ],
                "outputs": [{"name": "observation", "type": "object"}],
                "execution": {"type": "port_control"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 3,
                        "cooldown_seconds": 0,
                        "max_per_hour": 12,
                        "max_runtime_seconds": 180,
                    }
                },
            }
        )
    if not control_plane.get("tool", "system.files-list"):
        control_plane.create_tool(
            {
                "id": "system.files-list",
                "name": "Directory listing",
                "description": "List bounded directory metadata beneath an operator-configured root. No file contents, symlink traversal or writes.",
                "category": "safe",
                "authorization": "auto",
                "status": "active",
                "inputs": [
                    {"name": "root_id", "type": "string", "required": True},
                    {"name": "path", "type": "string", "required": False, "default": ""},
                    {
                        "name": "limit",
                        "type": "integer",
                        "required": False,
                        "default": 200,
                        "minimum": 1,
                        "maximum": 200,
                    },
                ],
                "outputs": [{"name": "listing", "type": "object"}],
                "execution": {"type": "filesystem_inventory"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 60,
                        "cooldown_seconds": 0,
                        "max_per_hour": 1000,
                        "max_runtime_seconds": 15,
                    }
                },
            }
        )
    if not control_plane.get("tool", "system.inventory"):
        control_plane.create_tool(
            {
                "id": "system.inventory",
                "name": "System inventory",
                "description": "Read bounded process, container and port observations from the configured SystemGate. No commands or mutations.",
                "category": "safe",
                "authorization": "auto",
                "status": "active",
                "inputs": [
                    {
                        "name": "limit",
                        "type": "integer",
                        "required": False,
                        "default": 100,
                        "minimum": 1,
                        "maximum": 200,
                    }
                ],
                "outputs": [{"name": "inventory", "type": "object"}],
                "execution": {"type": "system_inventory"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 12,
                        "cooldown_seconds": 0,
                        "max_per_hour": 120,
                        "max_runtime_seconds": 15,
                    }
                },
            }
        )
    if not control_plane.get("tool", "system.container-control"):
        control_plane.create_tool(
            {
                "id": "system.container-control",
                "name": "Managed container control",
                "description": "Start, stop or restart one explicitly managed container by its full ID. Requires exact owner approval; no shell or container creation.",
                "category": "system",
                "authorization": "owner_confirmation",
                "status": "active",
                "inputs": [
                    {"name": "container_id", "type": "string", "required": True},
                    {
                        "name": "action",
                        "type": "string",
                        "required": True,
                        "enum": ["start", "stop", "restart"],
                    },
                ],
                "outputs": [{"name": "observation", "type": "object"}],
                "execution": {"type": "container_control"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 6,
                        "cooldown_seconds": 0,
                        "max_per_hour": 30,
                        "max_runtime_seconds": 45,
                    }
                },
            }
        )
    if not control_plane.get("tool", "system.process-control"):
        control_plane.create_tool(
            {
                "id": "system.process-control",
                "name": "Managed service control",
                "description": "Start, stop or restart one operator-managed systemd service. Requires exact owner approval; no arbitrary PID or shell command.",
                "category": "system",
                "authorization": "owner_confirmation",
                "status": "active",
                "inputs": [
                    {"name": "service_id", "type": "string", "required": True},
                    {
                        "name": "action",
                        "type": "string",
                        "required": True,
                        "enum": ["start", "stop", "restart"],
                    },
                ],
                "outputs": [{"name": "observation", "type": "object"}],
                "execution": {"type": "process_control"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 6,
                        "cooldown_seconds": 0,
                        "max_per_hour": 30,
                        "max_runtime_seconds": 60,
                    }
                },
            }
        )


def ensure_builtin_research_capabilities() -> None:
    source_values = [
        "appstore_catalog",
        "appstore_reviews",
        "discourse",
        "general",
        "reddit",
        "hackernews",
        "github",
        "github_repositories",
        "producthunt",
        "stackexchange",
        "stackoverflow",
        "youtube",
    ]
    service = {
        "id": "research-web",
        "name": "Research Web",
        "description": "Bounded read-only discovery across public research providers.",
        "secret_refs": ["TAVILY_API_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN", "STACKEXCHANGE_KEY"],
        "health": "configured",
        "destination_policy": {
            "schemes": ["https"],
            "private_networks": False,
            "providers": source_values,
        },
        "status": "active",
    }
    existing_service = control_plane.get("service", service["id"])
    comparable_service = {key: service[key] for key in service if key != "id"}
    if not existing_service:
        control_plane.create_service(service)
    elif any(existing_service.get(key) != value for key, value in comparable_service.items()):
        control_plane.update_service(service["id"], comparable_service)

    tools = [
        {
            "id": "approval.test-echo",
            "name": "Approval Test Echo",
            "description": "Harmless local verification tool that proves ToolGate approval flow without network or filesystem access.",
            "category": "safe",
            "inputs": [
                {
                    "name": "value",
                    "type": "string",
                    "required": True,
                    "min_length": 1,
                    "max_length": 120,
                },
            ],
            "outputs": [{"name": "proof", "type": "object"}],
            "execution": {"type": "local_echo"},
            "policy": {
                "usage_limits": {
                    "max_per_minute": 6,
                    "cooldown_seconds": 0,
                    "max_per_hour": 40,
                    "max_runtime_seconds": 3,
                }
            },
            "authorization": "owner_confirmation",
            "version": 1,
            "status": "active",
        },
        {
            "id": "research.search",
            "name": "Research Search",
            "description": "Searches bounded public providers. Results are untrusted evidence and receive short-lived provenance handles.",
            "service_id": "research-web",
            "category": "safe",
            "inputs": [
                {
                    "name": "query",
                    "type": "string",
                    "required": True,
                    "min_length": 3,
                    "max_length": 240,
                    "pattern": r"^[^\x00-\x1F]+$",
                },
                {
                    "name": "source",
                    "type": "string",
                    "required": True,
                    "allowed_values": source_values,
                },
                {
                    "name": "max_results",
                    "type": "integer",
                    "required": False,
                    "default": 8,
                    "minimum": 1,
                    "maximum": 20,
                },
                {
                    "name": "recency_days",
                    "type": "integer",
                    "required": False,
                    "default": 30,
                    "minimum": 1,
                    "maximum": 3650,
                },
            ],
            "outputs": [{"name": "research", "type": "object"}],
            "execution": {"type": "research_search"},
            "policy": {
                "usage_limits": {
                    "max_per_minute": 12,
                    "cooldown_seconds": 0,
                    "max_per_hour": 120,
                    "max_runtime_seconds": 30,
                }
            },
            "authorization": "auto",
            "version": 1,
            "status": "active",
        },
        {
            "id": "research.fetch",
            "name": "Research Fetch",
            "description": "Reads a server-issued research result. Arbitrary URLs, private destinations, active content, oversized responses, and instruction-like payloads are denied.",
            "service_id": "research-web",
            "category": "controlled",
            "inputs": [
                {
                    "name": "result_id",
                    "type": "string",
                    "required": True,
                    "min_length": 20,
                    "max_length": 48,
                    "pattern": r"^rr_[A-Za-z0-9_-]+$",
                },
                {
                    "name": "max_chars",
                    "type": "integer",
                    "required": False,
                    "default": 12000,
                    "minimum": 1000,
                    "maximum": 20000,
                },
            ],
            "outputs": [{"name": "document", "type": "object"}],
            "execution": {"type": "research_fetch"},
            "policy": {
                "usage_limits": {
                    "max_per_minute": 10,
                    "cooldown_seconds": 0,
                    "max_per_hour": 80,
                    "max_runtime_seconds": 30,
                }
            },
            "authorization": "auto",
            "version": 1,
            "status": "active",
        },
        {
            "id": "research.fetch-batch",
            "name": "Research Fetch Batch",
            "description": "Reads up to eight server-issued research handles as one bounded, scanned batch. Arbitrary URLs remain unsupported.",
            "service_id": "research-web",
            "category": "controlled",
            "inputs": [
                {
                    "name": "result_ids",
                    "type": "array",
                    "required": True,
                    "min_items": 1,
                    "max_items": 8,
                    "unique_items": True,
                    "item_type": "string",
                    "item_pattern": r"rr_[A-Za-z0-9_-]{20,40}",
                },
                {
                    "name": "max_chars",
                    "type": "integer",
                    "required": False,
                    "default": 3500,
                    "minimum": 1000,
                    "maximum": 5000,
                },
            ],
            "outputs": [{"name": "documents", "type": "object"}],
            "execution": {"type": "research_fetch_batch"},
            "policy": {
                "usage_limits": {
                    "max_per_minute": 4,
                    "cooldown_seconds": 0,
                    "max_per_hour": 120,
                    "max_runtime_seconds": 30,
                }
            },
            "authorization": "auto",
            "version": 1,
            "status": "active",
        },
    ]
    atomic_sources = {
        "research.appstore-catalog": ("Apple App Store Catalog", "appstore_catalog"),
        "research.appstore-reviews": ("Apple App Store Reviews", "appstore_reviews"),
        "research.discourse": ("Automation Community Search", "discourse"),
        "research.web": ("Web Search", "general"),
        "research.reddit": ("Reddit Search", "reddit"),
        "research.hackernews": ("Hacker News Search", "hackernews"),
        "research.github-issues": ("GitHub Issue Search", "github"),
        "research.github-repositories": ("GitHub Repository Search", "github_repositories"),
        "research.stackexchange": ("Stack Exchange Search", "stackexchange"),
        "research.stackoverflow": ("Stack Overflow Search", "stackoverflow"),
        "research.youtube-comments": ("YouTube Comment Search", "youtube"),
        "research.producthunt": ("Product Hunt Search", "producthunt"),
    }
    atomic_inputs = [
        {
            "name": "query",
            "type": "string",
            "required": True,
            "min_length": 3,
            "max_length": 240,
            "pattern": r"^[^\x00-\x1F]+$",
        },
        {
            "name": "max_results",
            "type": "integer",
            "required": False,
            "default": 8,
            "minimum": 1,
            "maximum": 20,
        },
        {
            "name": "recency_days",
            "type": "integer",
            "required": False,
            "default": 30,
            "minimum": 1,
            "maximum": 3650,
        },
    ]
    for tool_id, (name, source) in atomic_sources.items():
        tools.append(
            {
                "id": tool_id,
                "name": name,
                "description": f"Searches the bounded {name.removesuffix(' Search')} adapter and returns provenance-bound untrusted evidence.",
                "service_id": "research-web",
                "category": "safe",
                "inputs": atomic_inputs,
                "outputs": [{"name": "research", "type": "object"}],
                "execution": {"type": "research_search", "fixed_source": source},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 12,
                        "cooldown_seconds": 0,
                        "max_per_hour": 120,
                        "max_runtime_seconds": 30,
                    }
                },
                "authorization": "auto",
                "version": 1,
                "status": "active",
            }
        )
    bundle_profiles = {
        "research.scan-pain": (
            "Pain Signal Scan",
            ["discourse", "reddit", "hackernews", "youtube", "general"],
        ),
        "research.scan-developer": (
            "Developer Friction Scan",
            ["github", "stackoverflow", "stackexchange", "hackernews", "general"],
        ),
        "research.scan-competition": (
            "Competition Scan",
            ["general", "producthunt", "github_repositories"],
        ),
    }
    bundle_inputs = [
        {
            "name": "query",
            "type": "string",
            "required": True,
            "min_length": 3,
            "max_length": 240,
            "pattern": r"^[^\x00-\x1F]+$",
        },
        {
            "name": "max_per_source",
            "type": "integer",
            "required": False,
            "default": 5,
            "minimum": 1,
            "maximum": 10,
        },
        {
            "name": "recency_days",
            "type": "integer",
            "required": False,
            "default": 90,
            "minimum": 1,
            "maximum": 3650,
        },
    ]
    for tool_id, (name, sources) in bundle_profiles.items():
        tools.append(
            {
                "id": tool_id,
                "name": name,
                "description": "Runs a bounded reusable multi-source research profile while preserving per-result provenance and failures.",
                "service_id": "research-web",
                "category": "safe",
                "inputs": bundle_inputs,
                "outputs": [{"name": "research", "type": "object"}],
                "execution": {"type": "research_bundle", "sources": sources},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 4,
                        "cooldown_seconds": 0,
                        "max_per_hour": 40,
                        "max_runtime_seconds": 60,
                    }
                },
                "authorization": "auto",
                "version": 1,
                "status": "active",
            }
        )
    managed_fields = (
        "name",
        "description",
        "service_id",
        "category",
        "inputs",
        "outputs",
        "execution",
        "policy",
        "authorization",
        "status",
    )
    for definition in tools:
        existing = control_plane.get("tool", definition["id"])
        if existing and all(existing.get(key) == definition.get(key) for key in managed_fields):
            continue
        if existing:
            definition = {**definition, "version": int(existing.get("version", 1)) + 1}
        saved = control_plane.create_tool(definition)
        control_plane.event(
            "builtin_tool_synced",
            "info",
            "tool",
            definition["id"],
            "system",
            {"version": saved["version"]},
        )
