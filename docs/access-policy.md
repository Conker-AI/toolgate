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
owner's control: an imported tool is always `owner_confirmation`, and no delegate's `run` skips
the owner. Unmarking it sensitive does not take it off the floor.

## Observe or Act outward (imported MCP tools)

Each imported tool has a read class (`core/mcp_observe.py`, ADR-0006). **Act outward**, the
default for every import and for every tool imported before the class existed, asks the owner for
every call, bound to its exact arguments (approval level 2, or 3 for a name that deletes or pays).
**Observe** runs without his card; scope, lockdown, usage limits, spending, the action journal
and the audit log apply exactly as before (`tool_executed` carries `"read_class": "observe"`).

- He sets it per tool on the owner channel: `POST /v2/owner/mcp/tools/{id}/class` with
  `{"read_class": "observe" | "act_outward", "expected_version": N}`. A stale version is 409,
  and every change is a new tool version with an `mcp_class_changed` event. Import never sets
  it, and an admin catalogue save of the tool drops it (back to Act outward).
- Observe is an access grant: Pi's gateway asks his password for it (ADR-0010); Act outward only
  takes power away and needs the session. The `conker` CLI sets only `act_outward`, because it
  cannot ask his password.
- Only a tool whose ToolGate id, name and MCP tool name all have the shape of a read can be
  Observe; any other is refused (422 `act_outward_name`) and never treated as Observe.
  `says_act_outward` is a shape rule, not a word list, and fails closed. A name is split at
  anything that is not a letter (digits too) and at camelCase; words before a dot are its
  namespace (`mcp.` in the id, `social.` in `social.list_chats`) and must not act or lead.
  - **Without annotations** from the server the name is exactly a read verb, or a read verb and
    one part: `get_weather`, `list_emails`, `read_chat`, `search_docs`. Three parts or more ask.
  - **With annotations** that say `readOnlyHint: true` and `destructiveHint` absent or false
    (see below) it may be longer (`get_calendar_events`, `list_unread_messages`), and may start
    with `query`.
  - Read verbs (`READ_VERBS`): get, list, search, read, fetch, view, lookup, find, describe,
    show, count, inspect, browse, preview, summarize/summarise, stat, status. Verbs that commonly
    execute what they are given (check, run, exec, eval, query, sql) are not; `query` leads a
    name only with the read-only hint.
  - Either way no part after the verb is a connector (and, then, or, plus, to, also, after,
    with, via) or holds a word that acts (`ACTS`: send, post, reply, delete, pay, kill, exec,
    refresh, rotate, invoke, trade and similar; one of four letters or more anywhere in the part
    with its `-ing`/`-ied` forms, a shorter one, or one of `ACTS_AT_EDGES` such as ring, play,
    lock, sync, change, when the part is, starts with or ends with it: `get_setvalue`,
    `get_rerun`, `get_doorlock`).
  - A `LEADS` word (message, email, chat, call, order, start, patch, report, ...) is only the
    last part, exactly: `get_messages` reads, `get_message_user`, `get_messageuser` and
    `get_start_instance` ask.
  - After NFKC normalisation it holds only printable ASCII (a Cyrillic look-alike, an invisible
    or control character asks).
  The server's hint is what he confirmed: it is part of the advert Observe is bound to and is
  stored with the class (`read_only_hint`); a stored Observe without it gets the short shape.
  Reads that therefore always ask: names not led by a read verb (`echo`, `research`,
  `gmail_search`, `retrieve_page`, `download_file_content`, `look_up_contact`), glued names
  (`searchemails`, `list_notebooks`), and a word that acts inside or at the edge of another
  (`get_settings`, `get_address`, `get_market_data`, `list_posts`, `get_updates`,
  `list_skills`, `list_pages`, `list_models`, `get_string`, `get_display`, `get_context`,
  `get_current_user`, `list_connections`, `list_builds`, `list_backups`). Without the hint, every
  longer read asks too.
- He can only mark Observe what the server still advertises as imported: the class route
  checks the names first (with the hint's longer shape), then rediscovers the endpoint (409
  `schema_changed` otherwise). When the server gives annotations, Observe needs
  `readOnlyHint: true` and `destructiveHint` absent or false; empty annotations, a title only,
  or only `openWorldHint`/`idempotentHint` ask (422 `act_outward_hint`). Without annotations the
  names must have the short shape.
- Observe is bound to the endpoint, credential reference, MCP tool name and schema hash he saw,
  and to the hash of the tool's description and annotations (`advert_hash`). When the server
  advertises anything else, at a call (`schema_changed`, `advert_changed`; nothing is sent) or
  at any discovery of that endpoint, the tool goes back to Act outward (`mcp_class_reverted`)
  until he confirms again.
- Anyone's `ask` and his sensitive mark still ask. Built-in tools never have a read class.
- The class is read from the stored tool for every call, again inside the dispatch transaction,
  and never from a pinned publication. A switch back to Act outward that commits after that
  last read does not stop a call already admitted under Observe; it is sent unless its advert
  changed, and his next call asks. `GET /v2/agent/tools` lists an Observe tool as
  `"authorization": "auto"`, `"sensitive": false`; `GET /v2/owner/mcp/tools` shows `read_class`.

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
