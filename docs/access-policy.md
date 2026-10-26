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
`{"sensitive": true}`), or when it runs one of the fixed system controls that carry their own exact
review (`port_control`, `container_control`, `process_control`). No decision skips the owner for
these. Agent tool listings (`GET /v2/agent/tools`) include `"sensitive": true|false`.

## Delegates

Only the owner makes a key a delegate: `POST /v2/owner/access/delegate` with `{"enabled": true}`,
presenting the owner key and the execution key to change. `GET /v2/owner/access` shows the presented
key's state, the sensitive tools and the fixed floor executors.

## No existence leak

Invoking a tool that does not exist and one outside the key's scope give the same answer: 404
`TOOL_UNAVAILABLE`, "No such tool". `toolgate tool list` and `tool info` already show only the
key's scope.
