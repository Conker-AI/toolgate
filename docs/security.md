# ToolGate security model

How ToolGate keeps an agent's reach bounded: identity and scopes, the vault, exact single-use approvals, destination and content controls for research, and signed verification callbacks.

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

## Verification Callback

Create a write-only vault secret and register a callback method in the Verification screen. A phone, ring, or home adapter signs the canonical JSON body:

```text
HMAC_SHA256(secret, "<unix_timestamp>.<canonical_json_body>")
```

Send the digest as `X-ToolGate-Signature: sha256=<hex>` and the Unix timestamp as `X-ToolGate-Timestamp`. The body contains `method_id`, `request_id`, `decision`, and the request nonce. Five invalid callback signatures within five minutes automatically enable lockdown.

## MemoryGate

MemoryGate is registered as an internal service on the shared `conker_net` Docker network. ToolGate stores a dedicated MemoryGate read credential under `MEMORYGATE_READ_KEY` and exposes only approved read tools. The agent never receives direct MemoryGate credentials.


The default internal endpoints are:

- MemoryGate API: `http://memorygate-api:8020`
- Ollama: `http://memorygate-ollama:11434`

They can be changed with owner-controlled environment settings without exposing the destination to agent arguments.

Upgrading to the approval-integrity fix cancels old unconsumed verification requests.
Their issuance could have been forged; request fresh confirmation through the invoke
path. History is retained. See [approval integrity and upgrade notes](APPROVAL_INTEGRITY.md).
