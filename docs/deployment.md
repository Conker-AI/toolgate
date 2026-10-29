# Deploying ToolGate

Running ToolGate with Docker Compose, protecting the vault key, reading health, and upgrade notes.

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

## AI tools through Pi

Tools of the `ollama_generate` type write text with a model. When both of these are set in
ToolGate's environment, that text comes from Pi's `tool-text` model role, so the owner picks the
model for it in one place (Settings > Models > Model roles), hosted or local:

```dotenv
TOOLGATE_PI_URL=http://pi-api:8050      # Pi on the shared conker_net network
TOOLGATE_PI_SERVICE_KEY=...             # ToolGate's service key for Pi
```

ToolGate then sends `POST <TOOLGATE_PI_URL>/inference` with the header `X-Pi-Service-Key` and
`{"role": "tool-text", "system": "", "prompt": <the tool's rendered prompt>, "max_tokens": <the
tool's max_tokens>, "json": false, "request_id": "toolgate:<random>"}`, and the tool's result is
Pi's `text`, trimmed, as before. Pi stores the key's SHA-256 under `toolgate` in
`PI_SERVICE_KEYS_SHA256`.

- **The role decides the model and temperature.** The tool's `max_tokens` (8-1024) is sent; its
  `model` and `temperature` are still validated as before (temperature 0-2) but are not sent,
  since Pi's role settings decide them. A rendered prompt over 64,000 characters is refused (422
  `VALIDATION_ERROR`) before anything is sent.
- **Failures are the usual AI tool failure.** Pi answering 503 (`no_model`: no model picked for the
  role, or `unavailable`: the provider failed), any other non-200 answer, no answer within 180
  seconds, or an unreadable answer all end the tool call with 502 `AI_UNAVAILABLE` and a plain
  reason. ToolGate does not then try Ollama itself: with Pi configured, Pi is the one place that
  chooses.
- **The key stays out of sight.** It travels only in the request header; it is never logged,
  never in an error or a result, and never a vault secret: both settings are runtime configuration,
  so the vault does not encrypt them, list them or let a tool's `secret_ref` read the key. Supply
  the key from the environment (compose `environment:` or a Docker secret) rather than `.env`.
- **The fallback.** When either setting is missing, ToolGate calls Ollama directly as it always
  has: `generation_url` (default `http://memorygate-ollama:11434`) with the tool's `model` or
  `generation_model`, its `temperature` and `max_tokens`. The health check's `generation` probe
  still looks at that Ollama address.

## Retiring the AI workspace

Pi owns conversations, planning, proposals and context assembly. `/v2/ai/*` and
the AI Builder are removed, along with the planner and MCP skill injection.
Startup atomically archives retained sessions, AI proposals and related events
with their original IDs, raw JSON, timestamps and references. AI proposals leave
the live queue and can no longer register capabilities by approval.

The owner can export the archive at `GET /v2/archives/ai`. This is a lossless
handoff format, **not a completed import into Pi**. See
[the migration contract](AI_RETIREMENT.md) before upgrading or importing.

Search, handle-bound fetch, deterministic workflows and atomic model calls remain
execution capabilities. None owns a conversation, chooses a goal, or dispatches
model-selected actions. The research adapters now live in `toolgate/executors/`.
