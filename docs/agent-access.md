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

## Agent identities

Each Conker agent has its own identity under the chat's key: the agent's toolkit as scopes, always
capped by the key's own scopes, so defining identities can only partition what the key already
may do.

- The key sets an agent's toolkit with `PUT /v2/agent/identities/{agent}` (`{"scopes": [...]}`) and
  lists them with `GET /v2/agent/identities`. Agent ids are lowercase letters, digits and `_`.
- A call that sends `X-ToolGate-Agent: <agent>` acts as that agent: tool lists, policy summaries,
  invocations and the dispatch-time re-check all use the agent's scopes. Outside them a tool
  answers 404 "No such tool". An agent with no identity sees nothing; `companion` keeps the
  key's full view unless narrowed. A malformed agent id is refused (403).
- The owner mints a key bound to one agent for its CLI or MCP use:
  `POST /v2/owner/agents/{agent}/keys` (owner key plus the chat's key; the raw key is shown once),
  lists them with `GET /v2/owner/agents/{agent}/keys` and revokes one with
  `POST /v2/owner/agent-keys/{id}/revoke`. A bound key always acts as its agent (it cannot present
  another, define identities or mint keys), follows the agent's toolkit as it changes, and stops
  working when the chat's key is revoked. With it, `toolgate tool list` and MCP `tools/list` show
  only that agent's tools.
- Grants (MCP access, workflow access) belong to the chat's key, never to an agent or bound key.
