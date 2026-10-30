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
(`GET /v2/agent/tools`) include `"sensitive": true|false` and `"card"` (see Inbox buttons).

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

Agents read the same value. Each item of `GET /v2/agent/tools` has `"card"`: the template the owner
picked for that tool (`do` when he picked none). A published workflow has no template of its own, so
each item of `GET /v2/agent/published-workflows` has `"card"`: the strongest template among the tools
it runs, its nested workflows' tools included, strongest first `pay`, `delete`, `ship`, `publish`,
`send`, `save`, `run`, else `do`. A workflow that sends through his "send" tool is listed as `send`.
Pi's reviewer reads it: when the AI decides, a tool whose card is `send` or `publish` (reaches a
person) or `ship`, `delete` or `pay` (can't be undone) always asks him, from his own choice rather
than from a model's answer. The workflow's own Inbox request still shows `do`; only the listing
derives it.

## Running a tool by hand

The owner runs one tool himself with the owner key and the chat's own execution key:

```
POST /v2/owner/tools/{id}/runs
X-ToolGate-Owner-Key: <owner key>
X-ToolGate-Execution-Key: <the chat's own key>

{"action_id": "owner_<32 hex>", "args": {...}, "approval_request_id": "<id>"}   (last one optional)
```

- `action_id` is the run's identity: `owner_` and 32 lowercase hex characters, made once per press
  of Run. Repeating it returns the journal's receipt and never runs the tool twice; the same id with
  other arguments is 409 `ACTION_CONFLICT`. `args` is a JSON object of at most 32 KB. Nothing else
  is accepted, in particular no `decision`: his runs carry no AI decision.
- It runs any active tool, whether or not Conker's key may use it; the run is recorded under the
  chat's key (its journal row, its Terminal workspace, its spending), and the key must still be
  active when it runs. A key acting as an agent (`X-ToolGate-Agent`) or bound to one is 403
  `execution_unavailable`. A missing, turned-off or unknown tool is 404 `TOOL_UNAVAILABLE`.
- Asking is the agent invoke's: the tool's own authorization applies, `blocked` is 403
  `POLICY_DENIED`, lockdown is 423, and a tool on the floor always asks, even when its own setting is
  `auto`. A tool that asks answers `{"code": "CONFIRMATION_REQUIRED", "request_id", "expires_at",
  "message", "next_action"}` and its request waits in his Inbox (`actor: "owner"`, with the tool's
  card). After he approves, send the same body with `approval_request_id`; before that, or with an
  approval that does not match this exact action, the answer is 409 `APPROVAL_INVALID` and nothing
  runs. Every other answer is the invoke route's: `{"code": "OK" | "TOOL_UNAVAILABLE", "message",
  "result", "action_id", "status"}`, or `OUTCOME_UNKNOWN` when a dispatch did not report back.
- Errors are `{"detail": {"code", "message"}}`; the owner key missing or wrong is 401
  `owner_credential_required`, the execution key missing or wrong is 401.

The owner reads a tool's recent runs from the journal with the owner key alone:

```
GET /v2/owner/tools/{id}/runs?limit=20        (1-50, default 20)

{"items": [{"action_id", "actor_id", "parent_action_id", "version", "status",
            "created_at", "args", "response"}]}
```

Newest first, by any key (Conker's, another agent's, his own runs, and runs inside a workflow, which
have a `parent_action_id`). `status` is `dispatching`, `completed` or `outcome_unknown`;
`created_at` is ISO 8601; `args` and `response` are exactly what the journal stores (the response
the run returned), nothing more. A run still waiting for his approval is not in the journal yet: it
is in his Inbox. An unknown tool id has no runs (`{"items": []}`).

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
