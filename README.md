# ToolGate

ToolGate is a local, single-owner control plane for AI agent capabilities. It keeps provider credentials outside the agent, exposes only typed capabilities, enforces deterministic policy before execution, and records a redacted audit trail for every important decision.

The project is designed for one owner and one primary local agent. ToolGate is the only capability boundary the agent needs: providers, local services, MemoryGate, approvals, and emergency controls remain behind it.

## Control Plane

| Object | Purpose |
| --- | --- |
| **Service** | Provider identity, write-only secret references, destination policy, health, and linked capabilities. |
| **Tool** | One atomic typed operation using a restricted executor. Tools cannot orchestrate other tools. |
| **Automation** | A versioned deterministic workflow composed from tools and bounded control blocks. |
| **Request** | Owner-reviewable verification, warning, proposal, update, or historical decision. |

The dashboard includes a command center, live execution activity, services, tool and automation editors, requests, verification adapters, security controls, secrets, and settings.

## What Is In This Repository

- `toolgate/api/`: FastAPI owner and agent API, restricted executors, automation runtime, verification callbacks, built-in research tool sync.
- `toolgate/executors/`: bounded search and fetch adapters.
- `toolgate/core/`: SQLite control-plane storage, policy helpers, vault integration, legacy AI archival, and runtime paths.
- `toolgate/cli/`: standard-library agent CLI for scoped execution keys.
- `toolgate/mcp/`: opt-in authenticated stdio transport over the scoped HTTP execution API.
- `dashboard/`: React and Vite owner dashboard for services, tools, automations, requests, secrets, security controls.
- `integrations/mcp/`: scoped MCP client example, never enabled by Compose.
- `docs/`: integration notes and dashboard screenshots.
- `toolgate/tests/`: deterministic tests for the control plane, security model, workflow engine, research adapters, and MCP adapter.
- `toolgate/scripts/`: live verification utilities for a running local stack.

## Dashboard Screenshots

![ToolGate Command Center](docs/screenshots/dashboard-command-center.png)

| Security Center | Secrets |
| --- | --- |
| ![ToolGate Security Center](docs/screenshots/dashboard-security-center.png) | ![ToolGate Secrets screen](docs/screenshots/dashboard-secrets.png) |

## Execution durability and spending

Outbound calls require a caller-persisted `action_id`. Paid routes stay disabled until
the owner configures prices, both ceilings and an agent/root-bound job. Workflow
children share that job. Interrupted dispatches are held as `outcome_unknown`; missing
billing telemetry keeps its reservation. See [the API contract and limitations](docs/DURABLE_EXECUTION_AND_SPENDING.md).

## Security Model

- Agents authenticate with rotatable execution keys and explicit `tool:*`, `tool:<id>`, `automation:*`, or `automation:<id>` scopes.
- Management endpoints require the separate admin key. Agent keys cannot manage services, secrets, policies, verification methods, or requests.
- Vault values are write-only **and encrypted at rest**. ToolGate lists reference names, no API reveals a value, and the stored value is a Fernet token whose key is derived from an install-time secret held outside the values file.
- `/health` runs real dependency probes. It reports `degraded` and names the failing dependency instead of returning a hardcoded `ok`.
- Inputs are validated deterministically by type, range, length, pattern, and allowed values before execution.
- Rate, cooldown, runtime, workflow-step, destination, response-size, loop, retry, and delay ceilings are enforced in code.
- Sensitive actions bind approval to the exact object type, object ID, version, argument digest, nonce, and expiry.
- An approval is atomically consumed once. Replays and changed arguments fail closed.
- Verification requests originate only from invocation. Generic agent and admin requests are informational and cannot mint execution approvals.
- Decisions and consumption serialize against the same SQLite writer lock; each request transition commits its audit event atomically.
- Deployment bootstrap seeds missing keys with no scopes by default. Restart never changes existing scopes or revocation state.
- Signed verification callbacks use HMAC-SHA256, a 60-second timestamp window, a per-request nonce, and immutable action binding.
- Lockdown blocks agent execution, new agent requests, verification callbacks, and ToolGate-mediated MemoryGate access.
- Logs and API responses contain references and redacted outcomes, never injected secret values.
- Browser access is restricted to configured local dashboard origins.

The MCP bridge has the same identity, scope, approval, lockdown and limit enforcement as the HTTP API. It has no local database or vault access.

ToolGate reduces agent and prompt-injection risk, but it cannot protect a host that is already fully compromised. Keep the API private, protect the admin key, and use OS/container isolation as the outer security boundary.

## Bounded Web Research

Research tools accept typed queries and fixed source names, not arbitrary URLs. Search results become short-lived server-issued handles; the fetch tool resolves only those handles, revalidates every HTTPS redirect and public destination, restricts content types, and stops while streaming once 512 KiB of decompressed content is reached.

Public fetches and `http_json` use the same socket-level boundary. Every DNS answer must be
globally routable; CGNAT/Tailscale, private, loopback, link-local, multicast, reserved and metadata
destinations are rejected, as are IPv6 transition addresses that can encode another destination.
The connection uses a validated numeric address, retaining the original HTTP Host, TLS SNI and
certificate verification. Environment proxies are disabled for these public requests. Every
research redirect is checked again; `http_json` refuses redirects entirely. Public service-health
probes use the same transport. Explicit internal MemoryGate probes retain their separate policy.

These checks do not require a reachable tailnet. Tests control DNS and the socket boundary and
prove that denied destinations are never connected to; deployment routing and actual tailnet
reachability still require a check on the owner's host. Host egress rules remain a separate layer.

HTML is reduced before model use: scripts, styles, SVG, hidden elements, navigation, forms, page chrome, cookie prompts, subscription prompts, and repeated lines are removed. Unicode control characters are normalized, search-provider markup is stripped, long encoded blobs and instruction/exfiltration patterns are blocked, and surviving text is enclosed in an explicit untrusted-content boundary. These controls reduce both tokens and attack surface, but retrieved content must still be treated as hostile evidence rather than instructions.

Product Hunt can be used as an optional read-only competition provider. Because Product Hunt requires separate permission for commercial API use, ToolGate keeps it disabled until the owner confirms that approval in Settings and stores `PRODUCTHUNT_TOKEN` through Secrets. The token remains in ToolGate; the caller receives only locally filtered, redacted product metadata. SearXNG remains the automatic fallback.

Business research is exposed as small reusable tools instead of one monolithic
search action. Atomic tools cover broad web search, Reddit, Hacker News, GitHub
issues, Stack Overflow, YouTube comments, and Product Hunt. Bounded composition
tools combine them into pain, developer, and competition scans while preserving
the source report and failures from every provider.

`TAVILY_API_KEY` powers broad discovery, `GOOGLE_API_KEY` powers bounded YouTube
video and public-comment retrieval, `GITHUB_TOKEN` raises GitHub search limits,
and `STACKEXCHANGE_KEY` raises Stack Overflow limits. Reddit uses its public
read-only JSON search endpoint. Source APIs fall back first to domain-scoped
Tavily and then local SearXNG when direct access is unavailable. Product Hunt
remains permission-gated and uses the same bounded fallback chain. Every result
is normalized, HTML-stripped, injection-scanned,
deduplicated, and represented by a short-lived provenance handle. Invalid or
missing optional credentials fail closed or fall back without exposing values.

## Restricted Executors

Tool definitions can use these first-class executors:

- `echo`: returns validated arguments for local deterministic capabilities and testing.
- `local_echo`: returns a digest and length only, for proving the approval path without touching the network or the filesystem.
- `http_json`: bounded GET or owner-confirmed POST requests to exact public HTTPS hosts; redirects and private destinations are denied.
- `memorygate`: fixed-host, read-only `context` or `ask` operations using a vault-held MemoryGate credential.
- `ollama_generate`: bounded generation through the internal Ollama service with declared prompt inputs and no secret access.
- `gemini_generate`: bounded generation through an allowlisted hosted Gemini model, with the key injected as a header from the vault.
- `research_search`: one bounded provider search returning short-lived provenance handles.
- `research_bundle`: a reusable multi-source research profile that preserves per-source reports and failures.
- `research_fetch`: resolves exactly one server-issued research handle. It does not accept URLs.
- `research_fetch_batch`: resolves up to eight handles as one bounded, scanned batch.

Arbitrary agent-supplied Python and legacy script execution are intentionally unsupported.

## Automation Engine

### Definition revision compatibility

Tool and automation saves allocate `version` from the currently stored definition
under one SQLite writer transaction. A replacement increments that stored number;
the incoming `version` cannot reset or select it. Initial creation retains an
explicit positive initial version for existing import/bootstrap clients (default 1).
Legacy POST upserts retain their behavior, but also increment the stored version.

Owner clients can send `expected_version` with POST or PUT to require that exact
current version. A stale expectation returns HTTP 409 with
`detail.code = "DEFINITION_CONFLICT"` and `detail.current_version`, without changing
the definition or emitting its saved/updated event. PUT of a missing object remains
404; POST with an expectation but no existing object conflicts. Reload and review
the current definition before resubmitting a conflicted edit.

For compatibility, omitting `expected_version` remains an unconditional replacement
and does not protect against lost edits, although versions are still monotonic.
The existing dashboard remains in this compatibility mode until its later adapter
update. `version` is not a concurrency precondition. Existing live approvals continue
to bind the exact definition/version and fail closed after changes.

### Immutable definition history and publication

Owner-only `GET /v2/tools/{id}/versions` and the matching `/v2/automations/{id}/versions`
list saved revisions with publication state. `GET .../versions/{version}` returns the
saved definition; `?published=true` requires and returns an immutable publication
envelope. There is no fallback to the current version. History starts with the current
definition when this feature is installed; overwritten pre-upgrade definitions cannot
be reconstructed. Subsequent saves retain revisions atomically. Deleting a working
definition retains its history; recreating its ID allocates above retained versions.

`POST /v2/tools/{id}/publish` or `/v2/automations/{id}/publish` requires
`{"expected_version": 3}`. Publication requires an active, unblocked current definition
at that exact revision. It does not edit the draft, allocate a new revision, or execute
anything. Repeating a successful publication returns the same envelope without a
second event. Publications and revision history cannot be updated, deleted, or replaced.

An automation publication captures all referenced child-tool definitions under the
same writer transaction, including tools in inactive branches. Missing, inactive,
blocked, or incompatible dependencies fail publication. An optional `tool_version`
on a `tool_call` must match that tool's current version at publication; otherwise the
resolved current version is pinned in the envelope. Later tool changes never rewrite
the snapshot. Expanded workflows are limited to 500 blocks and four nested levels,
including nested automation calls and control-flow branches. Vault references
remain references; publication never resolves or copies vault credentials. Definition
fields still permit owner-authored literal configuration, so publications are not a
general secret scrubber: do not embed credentials in URLs, headers, arguments, or
other literal fields. Use supported vault-reference fields instead.

### Executing a published target

The existing agent routes `POST /v2/tools/{id}/invoke` and
`POST /v2/automations/{id}/run` accept `published_version`, a positive integer.
Include a stable `action_id`, exact `args`, and optional `job_id`. The requested
publication must exist: unavailable/revoked versions fail with
`PUBLICATION_UNAVAILABLE`, without falling back to a current draft. Omitting the
field deliberately retains legacy live-definition execution. A job integration must
persist and send the published version; ToolGate does not create or schedule jobs here.

Published workflows execute the saved workflow and pinned child definitions, even
after their working definitions are edited. Current agent scopes, lockdown, usage
limits and spending enforcement still apply. Every dispatch rechecks that the target
and children remain active, unblocked, and in the same definition lifetime. Any owner
authorization or policy change invalidates the publication for execution (even a
loosening); review and publish a new revision to resume. Deletion/recreation cannot
revive an old publication. Revocation prevents subsequent dispatches; it cannot undo
effects already dispatched.

The journal writer transaction also rechecks lockdown and the originating key's
current active state and required scope before every new root/child dispatch,
before consuming confirmation or reserving spending. Workflow children inherit the
required workflow scope: current child-tool scopes are never unioned with an old
workflow grant to keep a revoked workflow alive. A revocation between children stops
subsequent dispatches; already committed effects remain in the journal. Partial runs
are held for reconciliation instead of automatically restarting.

Owner confirmation binds the exact publication digest, arguments, originating agent,
version, and pinned child bindings. Dedicated owner review includes the publication
digest and child version/digest metadata, and rechecks current revocations before
approval. Published automation approvals are supported by this backend projection;
the separate gateway/frontend must explicitly support that shape before enabling its
review controls. Legacy live-automation review remains unavailable on that channel.

Execution receipts retain an immutable publication digest and definition version,
including uncertain outcomes. Reusing an action ID for another publication, or
switching between published and live execution, conflicts instead of dispatching.
Identical retries return the existing receipt; an unknown outcome never authorizes
redispatch. Existing journal records are upgraded additively and preserve their
original legacy invocation identity.

### Bounded nested published automations

`automation_call` requires literal `automation_id` and `published_version`, with an
optional exact `publication_digest` and an `args` object whose values can use the
existing expression references. Publication captures the referenced immutable
publication and its descendants, separately from other children: two nested calls
may intentionally pin different tool revisions without merging their tool maps.
Every branch resolves before publication. Missing publications, digest mismatches,
incompatible confirmation policy, repeated automation IDs along a dependency path
(including different revisions), and expanded depth/node overflows are rejected.

Nested calls run only through an explicitly published root. They receive isolated
variables, explicit validated arguments, and their own parent-linked journal receipt.
They share the root spending job and every ancestor's step/runtime ceilings; entering
a nested workflow never resets those ceilings. Current scopes must permit the root
and every captured nested automation, including inactive branches, and this
intersection is rechecked before each dispatch. Root confirmation binds all descendant
publication digests; an auto root cannot include a confirmation-required descendant.

Action identities derive deterministically from the parent action and bounded step
occurrence, so repeated loop calls have distinct paths. Uncertain nested outcomes hold
all ancestors and cannot be redispatched by a retry block. No new scheduler, background
worker, resumable continuation, or arbitrary-code executor is introduced.

Automations use a typed JSON workflow as their source of truth. The dashboard presents the same definition as a roadmap, layer map, draggable block editor, and editable code view.

Supported blocks are `tool_call`, `automation_call` (published roots only), `set`, `calculation`, `condition`, `switch`, bounded `loop`, bounded `retry`, `delay`, `notification`, and `return`. Expressions may reference `$args.<name>`, `$vars.<name>`, and `$last.<path>`. A tool's declared output is available as `$last.result.<output-name>` and its raw value remains available as `$last.result.result`. Nested depth, total steps, runtime, loop iterations, retry attempts, and delay duration are all capped.

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

See [MCP setup](docs/AUTHENTICATED_MCP.md) and
`integrations/mcp/toolgate.scoped.mcp.json`. Tool inputs use
`{"args": {"query": "..."}, "approval_request_id": "optional-exact-request"}`.
Discovery, calls and request status all use the authenticated agent HTTP routes.

## Retiring the AI workspace

Pi owns conversations, planning, proposals and context assembly. `/v2/ai/*` and
the AI Builder are removed, along with the planner and MCP skill injection.
Startup atomically archives retained sessions, AI proposals and related events
with their original IDs, raw JSON, timestamps and references. AI proposals leave
the live queue and can no longer register capabilities by approval.

The owner can export the archive at `GET /v2/archives/ai`. This is a lossless
handoff format, **not a completed import into Pi**. See
[the migration contract](docs/AI_RETIREMENT.md) before upgrading or importing.

Search, handle-bound fetch, deterministic workflows and atomic model calls remain
execution capabilities. None owns a conversation, chooses a goal, or dispatches
model-selected actions. The research adapters now live in `toolgate/executors/`.

## Local Deployment

1. Create the local environment file:

```powershell
Copy-Item toolgate\.env.example toolgate\.env
```

2. Create the shared Docker network the compose file joins, if it does not exist yet:

```powershell
docker network create conker_net
```

3. Start the API, dashboard and SearXNG. The compose file lives in `toolgate/` and its build context is the repository root, so run it from there:

```powershell
Set-Location toolgate
docker compose up -d --build
```

4. Open `http://localhost:8011`. The API is available at `http://localhost:8010`.

Blank control keys are generated and persisted on first API startup, but their values are intentionally never printed to logs. Read the local `toolgate/.env` file once to sign into the dashboard, then protect that file with host permissions.

### The vault key

Vault values are stored encrypted. The key that decrypts them is derived from an install-time secret that never lives in the values file:

- `TOOLGATE_VAULT_SECRET` in the environment, if set. Preferred: a Docker secret or an orchestrator-supplied value that never touches the data directory at all.
- Otherwise the key file named by `TOOLGATE_VAULT_KEY_FILE`, created `0600` with a fresh random secret on first start. The compose file points this at a dedicated `toolgate-vault` volume rather than at the bind-mounted source directory, so a copy of that directory does not carry the key that decrypts it.

Running outside Docker with neither set, the key file defaults to `toolgate/vault.key`, beside the values it protects -- which only helps against a stray copy of `.env`. Set `TOOLGATE_VAULT_SECRET`, or move the key file, for anything you care about.

**Back the key up with the data.** Losing it means losing every stored provider credential; they have to be entered again. `docker compose down -v` deletes the volume, and with it the key.

An install that predates encryption is migrated on its next start: cleartext values in `.env` are rewritten as `enc:v1:` tokens and the count is logged, never the values. If no key can be read or written, ToolGate **refuses to start** rather than falling back to cleartext.

### Health

`GET /health` is unauthenticated and runs real probes: the control-plane database, the vault, SearXNG, and -- when a MemoryGate credential is configured -- MemoryGate. Configured generation or an active Ollama tool also probes Ollama.

```json
{
  "status": "degraded",
  "version": "v2",
  "degraded": ["generation"],
  "checks": {
    "control_plane_db": {"status": "ok"},
    "vault": {"status": "ok", "key_source": "key_file"},
    "searxng": {"status": "ok"},
    "memorygate": {"status": "ok"},
    "generation": {"status": "unreachable", "reason": "ConnectError"}
  },
  "checked_at": "2026-09-05T11:08:05.185008+00:00",
  "age_seconds": 0.0
}
```

`status` is `ok` only when nothing configured is failing. Detail stays coarse -- a status word and an exception class, never a host, a credential or an upstream body -- because anyone can call this. Results are cached for 15 seconds so an anonymous caller cannot use the endpoint as an outbound request amplifier, and `age_seconds` reports how old the answer is rather than hiding it.

## MemoryGate

MemoryGate is registered as an internal service on the shared `conker_net` Docker network. ToolGate stores a dedicated MemoryGate read credential under `MEMORYGATE_READ_KEY` and exposes only approved read tools. The agent never receives direct MemoryGate credentials.


The default internal endpoints are:

- MemoryGate API: `http://memorygate-api:8020`
- Ollama: `http://memorygate-ollama:11434`

They can be changed with owner-controlled environment settings without exposing the destination to agent arguments.

Upgrading to the approval-integrity fix cancels old unconsumed verification requests.
Their issuance could have been forged; request fresh confirmation through the invoke
path. History is retained. See [approval integrity and upgrade notes](docs/APPROVAL_INTEGRITY.md).

## Verification Callback

Create a write-only vault secret and register a callback method in the Verification screen. A phone, ring, or home adapter signs the canonical JSON body:

```text
HMAC_SHA256(secret, "<unix_timestamp>.<canonical_json_body>")
```

Send the digest as `X-ToolGate-Signature: sha256=<hex>` and the Unix timestamp as `X-ToolGate-Timestamp`. The body contains `method_id`, `request_id`, `decision`, and the request nonce. Five invalid callback signatures within five minutes automatically enable lockdown.

## Verification

Install the pinned API requirements and pytest, then run the behavioral suite:

```powershell
python -m pytest toolgate/tests --ignore=toolgate/tests/test_module_contract.py -q
```

Prove the A2/B5 tests detect broken behavior in disposable source copies:

```powershell
python toolgate/scripts/mutation_check.py
```

Run one file:

```powershell
python -m unittest toolgate.tests.test_approval_boundary -v
```

The suite is not all in-memory: the approval binding is driven over the ASGI app against a real SQLite database -- including a twelve-thread race that must produce exactly one success -- and `/health` is checked against an upstream that is genuinely stopped mid-test.

With both Docker stacks running, execute the live boundary verifier. It reads vault values through the vault rather than parsing `.env`, so it has to run where the vault key is — inside the API container:

```powershell
Set-Location toolgate
docker compose exec api python toolgate/scripts/verify_v2.py
```

The live verifier creates temporary namespaced capabilities and keys, tests executors, workflows, scope isolation, exact approvals, callback replay resistance, redaction, and lockdown, then removes its temporary objects.

## Project Layout

```text
dashboard/                 React and Vite owner dashboard
dashboard/server.py        Local dashboard static server
docs/AUTHENTICATED_MCP.md
docs/screenshots/          Dashboard screenshots used by this README
integrations/mcp/          Example MCP client configuration
toolgate/api/              FastAPI control-plane, agent API, and execution runtime
toolgate/cli/              Agent-facing CLI
toolgate/core/             Vault, policy, persistence, and legacy archive modules
toolgate/executors/        Typed research search and fetch adapters
toolgate/mcp/              Authenticated opt-in MCP transport
toolgate/scripts/          Operational verification utilities
toolgate/searxng/          Local SearXNG configuration used by research fallback
toolgate/tests/            Deterministic security, workflow, research, and MCP tests
```

ToolGate v2 deliberately starts from a clean control-plane model. Deprecated legacy registries, unrestricted scripts, and old execution paths are not migrated.

Automation confirmations bind every referenced child definition and version, including nested branches. Changes before dispatch require fresh approval; accepted runs use the checked snapshot. Legacy automation approvals without child bindings are rejected.

Owners can release a verified no-execution hold using `POST /v2/spending/releases/{action_id}` with `confirmed_not_executed: true` and an evidence note. This changes local budget availability only; it never refunds a provider or permits redispatch. A late provider reply disputes the release, restores accounting, and freezes paid work.
