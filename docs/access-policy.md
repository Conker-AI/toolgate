# Access policy: who may decide, and the floor

Conker decides each action's access from the owner's own settings (the chat, the agent, the tool
default); Pi resolves that and tells ToolGate the outcome with the invocation. ToolGate enforces
what must hold even if that resolution is wrong.

## Decisions on an invocation

`POST /v2/tools/{id}/invoke` accepts an optional `decision`:

```json
{"outcome": "run", "decided_by": "chat", "reason": "Full access in this chat"}
```

- `outcome: "ask"` from any key makes this exact action wait for the owner, even for an `auto` tool.
- `outcome: "run"` lets the action skip the owner's confirmation, but only when the presenting
  key is a **policy delegate** and the tool is not on the **floor**. Otherwise it is ignored and the
  tool's own authorization applies (an `owner_confirmation` tool still asks).
- `blocked` stays blocked. Published workflows (`/v2/automations/{id}/run`) keep the authorization
  the owner chose when publishing; decisions apply to single tools.
- `decided_by` is one of `tool_default`, `agent`, `chat`, `ai_reviewer`, `owner_request`. Every
  decision that changed the outcome is recorded as an `action_decided` event with who decided and why.

## The floor

A tool is on the floor when the owner marked it sensitive (`POST /v2/owner/tools/{id}/sensitive`,
`{"sensitive": true}`), when it runs one of the fixed system controls that carry their own exact
review (`port_control`, `container_control`, `process_control`), or when it calls a tool on an
external MCP server (`mcp_http`). No decision skips the owner for these. Agent tool listings
(`GET /v2/agent/tools`) include `"sensitive": true|false`.

External MCP tools are on the floor because what they do is decided by a server outside the
owner's control: an imported tool is always `owner_confirmation`, and no per-tool switch lets a
delegate's `run` skip the owner. Unmarking it sensitive does not take it off the floor.

## Inbox buttons

The owner picks which buttons his Inbox shows when a tool asks him: `POST
/v2/owner/tools/{id}/card` with `{"template": "do" | "send" | "publish" | "ship" | "run" | "delete" |
"pay" | "save"}` (Do it / Don't, Send it / Don't send, Publish / Not yet, Ship it / Not yet, Run it /
Don't run, Delete / Keep it, Pay / Don't pay, Save / Don't save). The list is fixed so that no tool,
and no AI drafting one, can label the approve button with something else. It is an owner setting
kept beside the floor, not part of the tool, so the tool's version and bound approvals do not change.
Each request copies the template when it is made (`card` in the owner channel's projection); `GET
/v2/owner/access` lists every template that is not `do` as `cards`. The Terminal (`sandbox.run`)
starts with `run`.

## Delegates

Only the owner makes a key a delegate: `POST /v2/owner/access/delegate` with `{"enabled": true}`,
presenting the owner key and the execution key to change. `GET /v2/owner/access` shows the presented
key's state, the sensitive tools and the fixed floor executors. A key reads its own state from `GET /v2/agent/status`
(`policyDelegate`), so a caller can skip resolving decisions that would be ignored.

## Which tools a key may use

A key uses only the tools in its scopes; a fresh deployment key has none unless its deployment seeds
some. The owner switches one tool on or off for the chat's own key with `POST
/v2/owner/tools/{id}/access` (`{"enabled": true|false, "expected_digest": "<the tool's digest>"}`),
presenting the owner key and that execution key; `GET` on the same path shows the state and the
digest. A grant adds `tool:<id>`; a revoke removes it, and is refused while a broader grant (such as
`tool:*`) still covers the tool. An agent identity or a key bound to one agent cannot change the
key: agents only narrow it. Imported MCP tools keep their own route, `/v2/owner/mcp/tools/{id}/access`.

## No existence leak

Invoking a tool that does not exist and one outside the key's scope give the same answer: 404
`TOOL_UNAVAILABLE`, "No such tool". `toolgate tool list` and `tool info` already show only the
key's scope.
