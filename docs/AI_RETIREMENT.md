# Retiring ToolGate cognition (A2)

Back up ToolGate's complete authoritative store before upgrading. On startup,
ToolGate moves `ai_session` objects and `request` objects of kind `ai_draft` into
`v2_ai_archive`, alongside copies of their related audit events. The migration
runs under one SQLite `BEGIN IMMEDIATE` transaction. A conflict or failure aborts
startup and rolls back retirement. Retry only after resolving the reported cause.
Original audit events remain in the ordinary event log.

The archive stores original SQLite rows, including the exact JSON body text and
original identifiers and timestamps. Session-to-proposal and draft-to-capability
references survive. The archive is part of the same SQLite database already
captured by Conker backup. No active tool or automation is removed. Former AI
proposals cannot be approved into capabilities; recreate reviewed definitions
through the ordinary owner tool/automation API if needed.

`GET /v2/archives/ai` requires the owner admin credential. It returns:

```json
{
  "format": "toolgate.ai-archive",
  "version": 1,
  "source": "toolgate",
  "executable": false,
  "records": [{
    "source_table": "v2_objects",
    "kind": "ai_session",
    "id": "original-session-id",
    "row": {
      "kind": "ai_session",
      "id": "original-session-id",
      "body": "{\"id\":\"original-session-id\",\"messages\":[]}",
      "created_at": "original timestamp",
      "updated_at": "original timestamp"
    }
  }]
}
```

Event records use `source_table: v2_events`, `kind: event`, and the original event
row fields. Treat exports as private conversation history. Preserve the source
namespace and every original ID on import; reject conflicting IDs rather than
reassigning them. Keep original message objects in order (older messages may lack
individual IDs). Archived pending/approved states describe history and confer no
permission to execute or resume anything.

**This patch does not import into Pi.** That repository is being changed
independently. Its importer must persist these rows and references, make retained
conversations readable, verify counts/content, and record import completion before
any source archive deletion. ToolGate exposes no archive deletion or resumption
endpoint. A2's cross-repository migration remains open until that importer exists.

Deleted: the planner, every `/v2/ai/*` route and schema, session mutation helpers,
AI-draft promotion, the AI Builder and unused planning modal, and MCP skill/context
injection. There is no dormant orchestration engine behind a switch.

Kept: bounded search/fetch adapters, including deterministic source profiles and
fallbacks, now under `toolgate/executors/research*.py`; typed Ollama/Gemini calls;
owner-authored deterministic workflows; owner-only capability registration; the
ordinary approval boundary. Search contains no LLM planner. Atomic generation
returns text and usage, never dispatches model-selected tools or owns a session.
The former `planner_*` settings migrate to `generation_*` for these existing tools.

Deferred: Pi's historical importer and runtime context/skill assembly; broader
research egress isolation and provider-policy work; existing workflow authority
and unfinished-execution recovery defects. This patch does not claim to solve
those by renaming modules or by archiving records.

## Validation for review

- 117 tests passed in the non-container suite, including real loopback HTTP and
  a separate stdio process. Six additional module-contract tests passed against
  a live isolated Uvicorn server; health and archival tests passed again after
  the final startup/health changes.
- `python toolgate/scripts/mutation_check.py` caught all seven deliberate defects:
  catalogue scope bypass, invocation scope bypass, cross-agent status access,
  partial archival commit, lossy archival, a reintroduced AI route, and credential
  forwarding on a redirect. The runner verifies a passing baseline first and
  requires the named behavior test to fail, not a collection error.
- New/replaced Python modules pass Ruff lint and format. Existing touched modules
  have 22 pre-existing lint findings and zero added findings under the local rules.
- Generated `docs/openapi.json` matches the application. The research executor is
  unchanged apart from its package location. `git diff --check` passes.
- Dashboard build remains unverified locally: Vite is absent and the offline npm
  cache lacks the required packages. Run `npm --prefix dashboard install` and
  `npm --prefix dashboard run build` in the review environment. No Docker drill
  was run for this patch; the live HTTP checks above used Uvicorn directly.
