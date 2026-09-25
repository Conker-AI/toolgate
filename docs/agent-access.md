# Agent access: CLI and MCP

Agents reach ToolGate with a scoped execution key, through the standard-library CLI or the opt-in authenticated MCP bridge. Neither has access to the owner vault or the database.

## Agent CLI

The CLI reads its execution credential from `~/.config/toolgate/credentials.env` by default:

```dotenv
TOOLGATE_URL=http://127.0.0.1:8010
TOOLGATE_EXECUTION_KEY=tgx_replace_with_scoped_key
```

The CLI uses only the Python standard library, so agents do not need to install ToolGate's API dependencies. It reads only the scoped credentials file and never loads the owner vault file.

Core commands:

```text
toolgate status
toolgate tool list
toolgate tool <name> info
toolgate tool <name> --action-id <stable-id> --argument value
toolgate automation list
toolgate automation <name> info
toolgate automation <name> run --action-id <stable-id> --argument value
toolgate request create-tool "Describe the capability needed"
toolgate request status <id>
toolgate update
toolgate watch
```

Add `--json` to any command for a stable machine-readable contract. Values such as integers, arrays, objects, booleans, and `null` are coerced from JSON. Confirmation responses include a `request_id` and exact retry command using `--approval-request-id`.

## Authenticated MCP bridge

MCP is opt-in; normal Compose installs start no bridge. Configure a separate scoped
execution key and explicitly run `python toolgate/mcp/toolgate_mcp.py`. Missing,
invalid, revoked and admin keys fail closed. There is no operator bypass.

See [MCP setup](AUTHENTICATED_MCP.md) and
`integrations/mcp/toolgate.scoped.mcp.json`. Tool inputs use
`{"args": {"query": "..."}, "approval_request_id": "optional-exact-request"}`.
Discovery, calls and request status all use the authenticated agent HTTP routes.
