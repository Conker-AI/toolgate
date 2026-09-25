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
