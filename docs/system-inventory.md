# SystemGate inventory executor

`toolgate.executors.system_inventory.collect(limit=100)` is a fixed read-only
adapter for SystemGate's `/runtime` contract. It does not register a tool or grant
execution scopes. The API registration uses the existing definition, scope,
approval and execution journal machinery separately.

Operator configuration is mandatory:

- `TOOLGATE_SYSTEMGATE_URL`: HTTP(S) origin only, with optional port. No default,
  credentials, path prefix, query, or fragment. Trusted private service origins
  are intentional here; generic public HTTP destination policy remains unchanged.
- `TOOLGATE_SYSTEMGATE_KEY`: server-side SystemGate credential. Never a caller
  argument, returned field, stored tool definition, or logged error detail.

The sole argument is an exact integer limit from 1 to 200; booleans and coerced
strings/floats are rejected. The adapter sends GET `/runtime?limit=N` and a fixed
`X-SystemGate-Key` header. It accepts no caller URL/path/header/body and disables
environment proxies and redirects. No retries occur. Response compression is
rejected and the body is streamed with a 1 MiB limit. Connect timeout is three
seconds and read/write/pool timeouts one second. A ten-second monotonic deadline
is checked between chunks and at body completion; a blocking read can overrun it
by the one-second socket timeout. This is not a preemptive thread cancellation.

Responses must match the read-only observed inventory envelope. Validation checks
bounded rows/strings, exact fields, finite nonnegative times, timezone-aware sample
time, PID+creation identities, unique row IDs, associations to included rows,
section/top-level failure consistency, port observation semantics, and false
mutation capabilities. Unknown/error text is not trusted as a service diagnostic.
The adapter rejects duplicate JSON object keys. Any occurrence of the configured
key in parsed output rejects the response. Upstream failure bodies are not
returned. `InventoryError` exposes static `code`, `message`, and `status` only.

Successful partial responses retain the original partial status and explicit
unknown fields. They are not upgraded to healthy or interpreted as proof of
network reachability. The adapter does not inspect local devices, execute shell
commands, alter ports/containers, or retry uncertain operations.

Tests: `python -m pytest toolgate/tests/test_system_inventory.py -q`. All HTTP is
synthetic MockTransport; no private database, live daemon, or service is required.
The optional Python-only `transport` injection is for testing, never a tool input.
