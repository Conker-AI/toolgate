# Workflow editor: check, publish, and Conker's access

The visual editor's documents (`EditorDocument`, `toolgate/core/editor_drafts.py`) are saved as
drafts, which carry no authority, and published into the immutable automation registry
(`toolgate/core/editor_publication.py`). Two parts of that path are for callers other than the
editor screen: a read-only check, and publishing with "Let Conker use this tool".

## Checking a document

`POST /v2/editor/check` checks one document by the rules publishing applies, without saving it.
Pi's tool drafter calls it before the owner sees a draft and repairs what it reports.

- **Credentials:** the execution key (`X-ToolGate-Execution-Key`, optionally with
  `X-ToolGate-Agent`), like Pi's other ToolGate calls, or the owner key (`X-ToolGate-Owner-Key`).
  When the owner header is sent, only the owner key is checked.
- **Body:** `{"document": <EditorDocument>}`. Any other field, or a document that is not a JSON
  object, is 422. A document of the wrong shape is not: its problems come back as issues.
- **Answer (200):**

```json
{"valid": false, "issues": [
  {"code": "tool_unavailable", "message": "Tool 'web.lookup' does not exist or is not active.", "nodeId": "lookup"}
]}
```

`valid` is true only when `issues` is empty. Issues come in a fixed order (shape, graph, credentials,
definition, steps in document order, limits), at most 50. `nodeId` names the step when there is
one, otherwise it is `null`. The codes:

| Code | Meaning |
|---|---|
| `invalid_document` | Not an `EditorDocument`: a missing or wrong field, a bound exceeded. The message starts with the field path when there is one, e.g. `budgets: Field required`. When this appears, no other check ran. |
| `invalid_graph` | A rule of `validate_graph`: one Input, connections, branches, references, step configuration. |
| `credentials_not_allowed` | `credentialRefs` is not empty; credentials are bound on registered tools. |
| `invalid_definition` | The workflow definition publishing would store breaks a registry rule, such as an input name that is not an identifier. |
| `tool_unavailable` | A `tool_call` names a tool that does not exist, is not active, or is blocked. |
| `tool_invalid` | A `tool_call` names a tool whose own definition does not validate; the owner must fix the tool. |
| `workflow_unavailable` | A `workflow_call` names a workflow version that is not published, or one whose tools were revoked. |
| `workflow_limit` | The expanded workflow breaks a publishing limit: more than 500 steps, more than four levels of nesting, or a call into itself (any version). |

The check saves nothing, grants nothing and runs nothing. It reads tools and publications in one
read transaction and writes no event; the only trace is the normal request handling (an execution
key's last-used time). Two publish-time rules stay with publishing because they depend on the
owner's choice there: an `auto` workflow cannot call a tool that asks the owner, and the draft's
saved revision must match.

## Publishing with "Let Conker use this tool"

`POST /v2/owner/editor-drafts/{id}/publish` stays owner-only. Its body gains one field:

```json
{"expected_revision": 3, "expected_publication_version": 1,
 "authorization": "owner_confirmation", "conkerMayUse": true}
```

`conkerMayUse` defaults to `false`, which publishes exactly as before. When it is `true`:

- the request must also present the chat's own execution key (`X-ToolGate-Execution-Key`); without
  it the answer is 401 and nothing is published;
- in the publish transaction, the published document is marked `agentVisible: true` (the saved
  draft keeps its own value and revision), and that key gets the workflow's scopes, exactly as the
  owner's access switch for a published workflow (`POST /v2/owner/editor-drafts/{id}/access` with
  `enabled: true`) gives them: `automation:<id>` for the workflow and each workflow it calls,
  recorded as an `editor_access_granted` event. The publication was made in the same transaction,
  so the grant is always for its exact digest;
- grants belong to the chat's own key: a key acting as an agent (`X-ToolGate-Agent`) or bound to
  one is refused with 403 `execution_unavailable` (an unknown or revoked key is 401). A refused
  grant rolls the whole publication back: no definition, publication, history row, scope or event
  is left.

The answer adds two fields:

```json
{"draft_id": "example", "revision": 3, "automation_id": "editor-…", "version": 2,
 "digest": "…", "published_at": "…",
 "toolId": "workflow:editor-…:2:…", "conkerMayUse": true}
```

`toolId` is the id Conker's tool list shows for this publication (`GET
/v2/agent/published-workflows`); it is returned whether or not Conker may use it. `conkerMayUse` says
whether this publish let Conker use it. `false` never revokes an earlier grant: the owner revokes
with the access switch.

Repeating a publish of a revision that is already published returns the same publication. With
`conkerMayUse: true` the grant is applied again (it changes nothing when already there); if that
revision was published hidden from agents, the answer is 409 `publication_conflict`, because a
publication cannot change. Save the draft again and publish the new revision.
