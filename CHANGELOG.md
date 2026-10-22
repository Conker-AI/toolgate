# Changelog

## Unreleased

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
