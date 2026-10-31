# Changelog

## Unreleased

- **Research refuses an oversized JSON answer before parsing it.** Every research provider now reads
  its JSON through one check: a body over 4 MiB is refused with "<provider> response exceeded the
  safe size limit" and is not parsed (the App Store keeps its own 1 MiB check). Where a provider
  already skipped a failed request (a Discourse host, a Stack Exchange site, a YouTube video's
  comments, a community snapshot, a Discourse topic), it skips an oversized one the same way;
  elsewhere the provider fails as on an HTTP error. The unused Reddit JSON search and
  `AI_CONFIRMATIONS` are gone.
- **Two settings saves at once no longer undo each other.** Lockdown, the control-plane settings, a
  service and a verification method are read, changed and written under one write lock, so a
  settings save at the same moment as turning lockdown on can no longer turn it back off. A tool
  input declared as an object now refuses a value that is not one.
- **Tool settings hold when they cannot be read.** A settings database that is there but cannot be
  read (locked past the wait, damaged) refuses with 503 `settings_unreadable` instead of running
  tools on the defaults, so no tool goes past the owner's limits or onto a site they skip. One stored
  value this version no longer allows now drops only that value; the others still apply. A settings
  save and a tool access grant are written in the same transaction as their audit event.
- **Agent notes to the owner have bounded fields.** `POST /v2/requests` (and the operator's
  request route) refuses with 422 a `title` over 500 characters, `details` over 8,000, a `kind` over
  64, a `payload` over 32 KiB as JSON, and a `severity` other than `info`, `warning` or `critical`,
  so one agent key cannot fill the owner's queue or the audit log.
- **A tool secret cannot name ToolGate's own configuration.** A secret reference to the admin key,
  the bootstrap key, the vault secret or any other configuration key is refused, so a tool or
  verification method cannot send them out. `.env` is created owner-only (0600) and startup
  tightens an older file where it can.

## 0.11.0

- **Agents read the owner's Inbox card.** Each item of `GET /v2/agent/tools` has `card`, the button
  template the owner picked for that tool (`do` when none), and each item of `GET
  /v2/agent/published-workflows` has `card`, the strongest template among the tools the workflow
  runs. Pi's reviewer takes its "reaches a person / can't be undone" stop from it (send, publish,
  ship, delete, pay always ask), so that stop now fires.
- **The owner runs a tool by hand.** `POST /v2/owner/tools/{id}/runs` (owner key and the chat's own
  execution key; body `{"action_id": "owner_<32 hex>", "args", "approval_request_id"?}`) runs any
  active tool, built-in or MCP, with the same asking as an agent's invoke: a tool that asks makes an
  approval request and the same run resumes after he approves; a tool on the floor always asks;
  blocked stays blocked. `GET /v2/owner/tools/{id}/runs?limit=` (owner key, 1-50) reads that tool's
  newest runs from the journal. Shapes in docs/access-policy.md.

## 0.10.0

- **How long an approved action has to start.** The owner's settings (`/v2/owner/settings`) gain
  `run_window_minutes` (1-15; null keeps today's 15 minutes; never longer). Once the owner approves
  a request that waited for them, the exact action must start within it, and still runs once. Each
  approval records the window in force when it was decided (`decision.run_window_minutes`), so a
  change applies to approvals decided after it and never moves one already given; a recorded window
  past 15 minutes is refused where it is used. A request with its own bounded expiry keeps that
  expiry.
- **The lockdown switch on the owner key.** `GET /v2/owner/lockdown` answers `{"lockdown",
  "reason", "changed_by"}` and `POST /v2/owner/lockdown` with exactly `{"enabled": true|false}`
  turns it on or off: the same lockdown as the operator's `/v2/settings/lockdown` (which stays).
  Pi's gateway is meant to pass "on" with the owner's session alone and "off" only with the
  owner's password proof.
- **The owner's tool settings.** `GET /v2/owner/settings` and `PUT /v2/owner/settings` (owner key
  only; the body is `{"expected_revision", "settings"}` and a stale revision is refused with 409
  `settings_revision_conflict`). Each value has a hard ceiling at today's limit, so a setting can
  make tools stricter or put them back, never give them more; a number left null keeps today's
  limit. `tool_seconds` (5-180) lowers every time limit ToolGate sets for one call: web, MCP,
  MemoryGate and AI requests, research searches, fetches and bundles, workflow runs, Terminal
  commands and installs. `terminal_seconds` (5-100), `terminal_memory_mb` (64-512),
  `terminal_cpus` (0.1-1) and `terminal_workspace_mb` (16-2048) shape Terminal commands from the
  next one, with no restart: the runner takes them as `limits` and keeps its own limit when that is
  lower. `web_safe_search` (off, moderate, strict; moderate as before) and `web_region` (a
  two-letter country code; empty as before) reach SearXNG. `web_skip_sites` (up to 50) are never
  used as sources and their pages are not fetched. `web_page_characters` (1000-20000) is the most
  text one fetched page gives the model.
- **Check a workflow document without saving it.** `POST /v2/editor/check` (execution key or owner
  key) answers `{"valid", "issues": [{"code", "message", "nodeId"}]}` by the rules publishing
  applies: the document's shape, the graph, that every `tool_call` names an active tool and every
  `workflow_call` a published workflow, and publishing's size and cycle limits. It saves, grants
  and runs nothing. See docs/workflow-editor.md.
- **"Let Conker use this tool" when publishing.** The editor's publish takes `conkerMayUse`
  (default `false`). When `true`, with the chat's execution key on the request, the publication is
  visible to agents and that key gets the workflow's scopes in the same transaction, as the owner's
  access switch gives them; a refused grant publishes nothing. The answer adds `toolId` (the id
  Conker's tool list shows) and `conkerMayUse`.
- **AI tools through Pi.** With `TOOLGATE_PI_URL` and `TOOLGATE_PI_SERVICE_KEY` set, an
  `ollama_generate` tool gets its text from Pi's `tool-text` model role (`POST /inference`), so the
  owner picks that model in Pi's Settings; Pi's role decides the temperature. Pi being unavailable
  is the usual `AI_UNAVAILABLE` failure. Without them, the tool calls Ollama directly as before.
- **Health reports Pi as the AI path when Pi is configured.** With `TOOLGATE_PI_URL` and
  `TOOLGATE_PI_SERVICE_KEY` set, the `generation` check probes Pi's `/health` (no key sent, no
  model call; it must answer as Pi) instead of Ollama, so Ollama's state is no longer reported as
  ToolGate's. The check names its path in `via` (`pi` or `ollama`). A malformed address is
  `unavailable` rather than an error.
- **`docs/openapi.json` is generated.** `toolgate/scripts/export_openapi.py` writes it from the app
  (keys sorted) and CI's `--check` fails when it differs from the code. It had fallen behind at
  0.2.2.
- **External MCP tools always ask the owner.** `mcp_http` is on the access floor, so a policy
  delegate's `run` decision no longer turns an imported MCP tool into an automatic action; it parks
  for the owner, as an imported tool always has. `GET /v2/owner/access` lists it in
  `floorExecutions`, and agent tool listings mark these tools `sensitive`.
- **The agent that asked can withdraw its approval request.** `POST
  /v2/agent/requests/{id}/withdraw` (the key and agent that invoked; no body) moves a request still
  waiting for the owner to `withdrawn`, records `request_withdrawn`, and takes it out of the owner
  channel (list, detail and decision). It can never be approved or run. Idempotent; another key,
  an unknown id or an informational request is 404, an answered request 409 `REQUEST_NOT_PENDING`.
  For Pi to call when a chat is forgotten. See docs/APPROVAL_INTEGRITY.md.
- Tests keep their files in pytest's `tmp_path` only. `toolgate/tests/conftest.py` stops and
  fails any test that writes into the repository, and refuses a `--basetemp` inside it. Two
  spending tests used to write an admin key into `toolgate/.env` when they started the app.

## 0.9.1

- The Terminal accepts the arguments small local models actually send: a working folder of `/`
  means the workspace itself (like `/workspace`), and a null `timeout_seconds` means the default
  30 seconds. A time limit outside 1-100 is now refused before any approval is asked, not after.

## 0.9.0

- **Inbox buttons per tool.** The owner picks a button template for each tool (`POST
  /v2/owner/tools/{id}/card`): do, send, publish, ship, run, delete, pay or save (Send it / Don't
  send, Publish / Not yet, ...). Each request copies it (`card` in the owner channel) so the Inbox
  shows his buttons; `GET /v2/owner/access` lists them. A fixed list, kept beside the floor and
  outside the tool definition. The Terminal starts with Run it / Don't run.

## 0.8.1

- The Terminal's description now says to write the command as typed in bash and never wrap it in
  quotes as a whole. The earlier wording made a small model quote the entire command
  (`'echo hi'`), which bash then could not find. ToolGate's earlier texts are refreshed on start.

## 0.8.0

- **Requests wait for the owner.** An owner confirmation request no longer expires by default
  (`expires_at: null`); it waits until he answers, since he may look once or twice a day. His
  approval opens a 15-minute window for the exact action to run once. Setting
  `default_confirmation_expiry_seconds` (15-900) still bounds the wait. See
  docs/APPROVAL_INTEGRITY.md.

## 0.7.0

- The Terminal's description tells the model to quote with single quotes inside the command (it
  travels in a JSON string). Small local models broke the JSON on nested double quotes, and the
  request was refused unrun. An existing Terminal still carrying ToolGate's earlier text gets the
  new text on start; an owner's own edit is kept.

- The sandbox runner waits up to a second for Docker's out-of-memory label after a command is
  killed with SIGKILL that the runner did not send; the label can land just after the exit, and
  an out-of-memory kill was sometimes reported as a plain kill.

- **Owner tool access:** `GET`/`POST /v2/owner/tools/{id}/access` lets the owner switch any tool on
  or off for the chat's own key (`tool:<id>`), checked against the tool's exact digest; the MCP
  route uses the same code. A fresh key could otherwise use nothing until scopes were edited by
  hand. See docs/access-policy.md.

- An owner confirmation request now waits 15 minutes (the longest approvals allow) instead of
  one minute, so the owner can answer from a phone. `default_confirmation_expiry_seconds`
  still overrides it.

- Terminal and Install packages accept `/workspace` (and paths under it) as the working folder:
  it is where the workspace is mounted inside the sandbox, and models name it that way. Any
  other absolute path, and `..`, are still refused.

## 0.6.0

- **Agent sandbox:** two built-in tools, Terminal (`sandbox.run`) and Install packages
  (`sandbox.install`), default AI decides, registered once `TOOLGATE_SANDBOX_SOCKET` is set. Each
  command runs in a fresh container started by the new sandbox runner
  (`python -m toolgate.sandbox.runner`), the only holder of the Docker socket: no network, only
  the calling agent's workspace folder, user 65533, no capabilities, no-new-privileges, read-only
  root, limits on memory, CPU, processes, file size, workspace size and time. Installs reach PyPI
  and npm only through the GET-only package proxy (`python -m toolgate.sandbox.proxy`). A guard
  refuses sandbox-breaking commands before approval. New image `toolgate-sandbox`
  (`sandbox/Dockerfile`), published with each release. See docs/sandbox.md.

- The compose service runs with a read-only root, every capability dropped except DAC_OVERRIDE
  (its data is in the developer's bind-mounted folder) and no-new-privileges; `/tmp` is a tmpfs.
  CI's contract job runs it that way.

- **Agent identities:** each agent acts under its own identity (`X-ToolGate-Agent`), scoped to its
  toolkit and capped by the key; tool lists, invocations and dispatch-time checks follow it. The
  owner can mint a key bound to one agent for its CLI or MCP (`/v2/owner/agents/{agent}/keys`),
  which only ever sees that agent's tools. See docs/agent-access.md.

- **Access policy:** an invocation may carry the owner's resolved `decision` (`run` or `ask`).
  `ask` from any key tightens; `run` skips the owner's confirmation only for a key he made a
  policy delegate, never for tools on the floor (marked sensitive, or the fixed system controls).
  Decisions that changed the outcome are recorded as `action_decided` events. Owner routes:
  `/v2/owner/access`, `/v2/owner/access/delegate`, `/v2/owner/tools/{id}/sensitive`. See
  docs/access-policy.md.
- Invoking a tool outside the key's scope now answers 404 "No such tool", the same as a missing
  tool, so a key never learns what exists beyond its scope.

## 0.5.1

- The image no longer carries the base image's setuptools and wheel. The service never
  imports them, and their vendored copies had published advisories (wheel 0.45.1,
  jaraco.context 5.3.0) that the new image scan found. CI now checks that the built image
  still imports its app.
- Compose pins SearXNG 2026.10.19, replacing a months-old digest the image scan flagged.

## 0.5.0

- Add owner-reviewed external MCP tools: `/v2/owner/mcp/discover`, `/import`, `/tools`, and
  each tool's `state` and `access`. Discovery and import pin each tool's schema and never
  grant an execution scope; the owner enables a tool and its access separately. Bounded
  nullable and alternative input schemas are supported; unsupported tools are isolated, and
  a server that echoes a decoded credential back is detected.
- **Contract change:** replacing an existing tool or workflow through `POST /v2/tools` or
  `POST /v2/automations` now needs `expected_version`, checked under the same lock as the
  write (409 `DEFINITION_CONFLICT` otherwise), so a stale save can no longer replace a newer
  edit. Creating a new definition still needs no version.
- `server.py` is split into router modules, and approvals, invocation, dispatch, definitions
  and the research executor live in their own modules. Routes, models and behaviour are
  unchanged; the mutation drill follows the moved code and runs on every build.
- Update the dashboard's build tooling (Vite 8.3.5 and its dependencies) for published
  advisories.
- A weekly security check (`.github/workflows/security.yml`) audits every dependency this
  repository ships against the public advisory databases each Monday and whenever they
  change, and fails loudly.

## 0.4.0

- Publish revision-safe workflow drafts, validation, immutable publications and
  owner-reviewed access and execution through the existing durable action ledger.
- Expose scoped workflow capabilities and bounded owner policy summaries without
  leaking credentials or expanding the execution boundary.

- Add a scoped, secret-free policy summary whose digest covers the full effective tool definitions,
  scope patterns and lockdown state. Setup review can now detect policy drift without exposing
  executor destinations, headers or credentials.

- Reserve per-minute, hourly and cooldown capacity atomically with the durable
  dispatch journal. Concurrent distinct actions can no longer pass the same
  usage-limit check, while idempotent retries continue to reuse one slot.

## 0.3.0

ToolGate becomes only an execution boundary, and the money and approval paths
are made durable.

- **The AI layer is gone.** Sessions, planner, research-as-reasoning and the
  proposals engine are removed; Pi is the only thing that thinks. Search and
  fetch remain as executors. A mutation drill fails if the AI routes return.
- **Scoped identity over the MCP bridge** — the unscoped console that listed and
  ran every tool, and reached MemoryGate credentials, is replaced by an
  authenticated bridge on the same scoped path.
- **Durable execution.** A stable action id and dispatch record are created
  before dispatch; the same id and arguments returns the existing status,
  different arguments fail, and an ambiguous interruption holds as
  outcome-unknown rather than being guessed.
- **Spend caps.** Paid routes stay disabled until per-job and cumulative
  ceilings exist; a conservative upper bound is reserved before each request,
  spanning a workflow and its children; unknown or expired pricing blocks; an
  owner can release a verified-unused hold.
- **Approval integrity hardened.** Verification requests can be created only by
  the invoke path, decisions serialize with consumption, a stale write cannot
  revive a consumed approval, bootstrap never resurrects a revoked or narrowed
  key, and an approved automation is bound to the exact child-tool versions it
  was granted against.
- **Public-HTTPS egress enforced at the socket** — private, loopback,
  link-local, carrier-grade-NAT (Tailscale) and metadata addresses are rejected
  after DNS resolution and every redirect, with the socket pinned to the
  validated address.
- Every registered tool gets finite rate ceilings by default.


- F10: Add owner-attested, audited local hold releases while preserving unknown action identity; contradictory late replies freeze paid dispatch.

- Bind automation approval to child definitions and execute the checked snapshot, preventing an owner edit from widening an existing approval.

- Persist stable tool/workflow dispatch identities before execution; atomically consume approval and reserve paid cost. Replays return recorded status; ambiguous interruptions hold without redispatch.
- Add owner-only cumulative/per-job microUSD caps and immutable job/reservation accounting. Bound Gemini 2.5 Flash-Lite requests and reconcile known usage; disable unaccounted paid routes.
- Add action/job fields to HTTP, CLI and MCP and agent-specific status lookup. See `docs/DURABLE_EXECUTION_AND_SPENDING.md` for required caller changes and unsupported routes.

Versions are the module's own, not the API revision — the two mean different
things, and a dashboard reading one field for both is wrong about every module
it does not special-case. A change to the shape of `/health` or any endpoint is
a contract change and gets its own entry.

## Unreleased

- Reject CGNAT/Tailscale and metadata destinations in public HTTPS research,
  HTTP tools and public service-health probes. Validate all DNS answers at
  connection time, pin the socket to a validated IP and disable environment
  proxies. Preserve TLS hostname verification and check every research redirect.

- Close forged verification creation through both generic request endpoints. Only
  invocation can issue a verification, with immutable issuance provenance.
- Cancel old unconsumed verifications on upgrade; their origin cannot be trusted.
  Preserve history and require fresh confirmation. Check provenance again at
  decision and consumption, including before startup migration has run.
- Serialize request decisions with consumption and disallow generic request
  replacement. Creation, decision and consumption commit their audit events in
  the same transaction. Expired approvals and callback races return conflicts.
- Bootstrap is insert-only, defaults to no scopes, and preserves narrowed/revoked
  keys. Editing scopes no longer reactivates a revoked key; mint a new key instead.
- Extend the mutation drill to ten cases, including forged approvals, a stale
  decision resurrecting consumption, and bootstrap restoring authority.


- Remove `/v2/ai/*`, the AI Builder, planner, automatic AI-draft promotion and
  MCP MemoryGate skill injection. Pi owns cognition.
- Archive retained AI sessions/proposals and related events transactionally in
  `v2_ai_archive`; preserve original rows and IDs. Owner-only `/v2/archives/ai`
  exports a versioned handoff. Pi import is still required separately.
- Move deterministic research adapters to `toolgate/executors/research.py`;
  existing tool IDs and executor contracts continue to work.
- Replace the unscoped in-process MCP console with an opt-in authenticated HTTP
  bridge. No vault access, admin fallback, redirect following or automatic retry.
  Tool calls now nest inputs under `args`; normalized names have stable suffixes.
- Rename `planner_model`/`planner_url` settings to `generation_model`/
  `generation_url`, preserving configured values on upgrade for atomic Ollama
  tools. `/health` keeps its envelope; its optional `planner` check is replaced
  by `generation`, independent of MemoryGate credentials.

## 0.2.2

Secrets no longer ship inside the image.

- **The image carried a real `.env` and a working database.** `COPY toolgate
  ./toolgate` sweeps the whole package directory, and ToolGate keeps its data
  *inside* that directory - so every build baked in the admin key, the vault
  salt, the MemoryGate read key, a GitHub token, a Tavily key, and an 86KB
  `toolgate.db` of encrypted secrets and audit history. Published that way in
  0.2.0 and 0.2.1, which are being deleted from the registry; the credentials
  are being rotated. The gitignore was correct throughout - Docker's `COPY`
  simply does not read it.
- **`.dockerignore`, with every pattern anchored `**/`.** The first attempt
  used a bare `.env`, which matches only the root of the build context. The
  file that leaked was one level down, so the build looked fixed and leaked
  exactly as before.
- **CI builds the image and searches it**, rather than trusting the ignore
  file still matches after someone moves a path. Scoped to `/app`: a
  filesystem-wide hunt for `*.pem` matches the OS certificate store, and a
  check that cries wolf is a check somebody turns off.
- **`/health` reported `0.2.0` while the module shipped as v0.2.1.** Fixed.
  Same class of defect as the leak: the code saying something untrue about
  itself.

## 0.2.1

Publish workflow only: attestation is skipped while the repository is private,
so a successful image push is no longer reported as a failure.

## 0.2.0

**The vault stored provider credentials in plaintext.** "Write-only" is a
property of the HTTP surface — no route returns a value — but that says nothing
about the file, and anyone with file access read every key. Values are now
Fernet tokens behind an `enc:v1:` prefix, with the key derived by scrypt from an
install-time secret held deliberately *outside* the values file: either
`TOOLGATE_VAULT_SECRET`, or a `0600` key file on its own volume, so copying the
data directory does not carry the key that decrypts it. The scrypt salt sits
beside the values because a salt is not a secret and keeping it there is what
lets a passphrase survive a restart. `encrypt_values_at_rest()` migrates an
existing plaintext file.

**`/health` probed nothing** and returned a fixed answer, so a dependency could
be gone while health said otherwise. It now probes the control plane database,
the vault, searxng, MemoryGate and the planner, reporting `degraded` naming what
failed. It distinguishes `not_configured` from `unavailable`, because "nothing
here yet" and "it broke" are different facts and collapsing them is how a
dashboard starts lying. Answers are cached with their age, since the route is
unauthenticated.

**`/health` now answers in the shared module contract shape** — adding `service`
and changing `version` from the API revision `"v2"` to this module's own version.

**The stdio MCP bridge is renamed and described honestly.** Behaviour is
unchanged: it reads no execution key, never calls `is_scoped`, and attributes
everything to one hardcoded actor. It is now the single-operator console bridge
and says so in its first paragraph, alongside what still applies — lockdown,
validation, approval binding, limits and audit. Agents use the keyed HTTP API,
which enforces the identity and scope this cannot. See
`docs/SINGLE_OPERATOR_MCP_BRIDGE.md`.

Also fixes a pre-existing test failure on Windows, where runtime paths were
compared as strings across a platform separator difference.

## 0.1.0

First release. Services, tools, automations and requests; per-tool policy;
rotatable scoped execution keys; approvals bound to an exact object, version,
argument digest, nonce and expiry, consumed once; signed verification callbacks;
lockdown mode; redacted audit trail; stdio MCP bridge.
