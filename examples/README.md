# Examples

These examples run locally without external infrastructure. They use real signed assertions and the
public software development kit interfaces, while keeping identities, enrollments, credentials, and
keys in memory.

| Example | Demonstrates |
| --- | --- |
| [`agent_service.py`](./agent_service.py) | Inspect, Enroll, Status, a JWT-authenticated request, API-key/Basic/OAuth Bearer grants, authenticated resource access, and rejection after credential revocation through the ASGI adapter |
| [`hosted_platform.py`](./hosted_platform.py) | Platform discovery, Service DID resolution, identity provisioning, DID publication, delegated signing verified with the published public key, listing, suspension, and refused signing after suspension |

Run them from the repository root after installing the development environment:

```sh
uv sync --all-groups --locked
uv run python examples/agent_service.py
uv run python examples/hosted_platform.py
```

No external account, API token, running server, or payment is required. Both examples use HTTPS URLs,
but their HTTP transports run in process: `MockTransport` serves the example DID documents and
`ASGITransport` calls the Service application. They exercise DID lookup, key selection and real
signature verification, not a network TLS handshake.

The Agent and Service example runs every built-in credential profile. Each profile supplies an issuer
callback and the same `ServiceCredentialStore` to its corresponding `stored_*_grant_type()` factory.
The example first uses `fetch_protected_resource()` with the dedicated `AEP-Authorization` carrier.
Before any session credentials exist, the Agent uses the advertised JWT method. The credential loop
then uses the lower-level `authentication_headers()` API and an explicitly selected Grant Type.
Each issuer grants only the example's `account:read` scope rather than trusting arbitrary requested
scopes. Each credential is revoked by its identifier, and reuse must return `401`.

The Platform example deliberately keeps its private key in process. A production Platform supplies a
`KeyStore` backed by its key-management system and maps the Platform methods to authenticated HTTP
routes.

Successful runs print one result per step and exit with status zero. Unexpected enrollment, resource,
listing, signature, lifecycle, or revocation outcomes raise an exception and fail the command.

## Adapting the examples to an application

- Publish the Agent DID document where its DID resolves, and connect the Service application to
  your HTTP server. Replace the two in-process transports with real network transports.
- The example DID resolvers trust a fixed local URL map. A production resolver needs HTTPS with
  TLS 1.3 or later, certificate verification, bounded response sizes and timeouts, and a safe
  redirect policy. Reuse validated DID metadata according to your application's caching policy.
- Keep Agent signing keys and Service-issued credentials in protected storage. The sample's
  generated key and all memory stores disappear when the process exits. Persist enrollment,
  credential, replay and idempotency state where multiple requests or instances can share it.
- Decide which Agents may enroll, which scopes they may receive, and which application operations
  they may perform. Successful AEP authentication establishes a principal, not application permission.
- For a Platform, replace `AllowAuthenticatedCaller` with your permission checks and construct
  `RequestContext.principal` from validated route authentication, never from caller-supplied JSON.
  Use the SDK's default unique identifier generators instead of the sample's fixed identifiers.
  Keep lifecycle management on privileged Platform routes, not in the Agent workflow.
