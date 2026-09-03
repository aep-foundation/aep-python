# Examples

These examples run locally without external infrastructure. They use real signed assertions and the
public software development kit interfaces, while keeping identities, enrollments, credentials, and
keys in memory.

| Example | Demonstrates |
| --- | --- |
| [`agent_service.py`](./agent_service.py) | Agent inspection, enrollment, API-key, Basic, and OAuth Bearer grants, authenticated Service access, credential revocation, and rejected reuse through the ASGI adapter |
| [`hosted_platform.py`](./hosted_platform.py) | Hosted identity Platform discovery, Service DID resolution, provisioning, DID document publication, delegated signing, identity listing, and lifecycle management |

Run them from the repository root after installing the development environment:

```sh
uv sync --all-groups --locked
uv run python examples/agent_service.py
uv run python examples/hosted_platform.py
```

Both examples resolve `did:web` documents through HTTP clients using HTTPS URLs. Their in-memory
transports make the examples deterministic without bypassing DID resolution. Production
integrations use a normal HTTP client with their cache and network policy. Replace all memory stores
with durable implementations before deployment.

The Agent and Service example runs every built-in credential profile. Each profile supplies an issuer
callback and the same `ServiceCredentialStore` to its corresponding `stored_*_grant_type()` factory.
The example authenticates with each issued credential, revokes it, and confirms that reuse is rejected.

The Platform example deliberately keeps its private key in process. A production Platform supplies a
`KeyStore` backed by its key-management system and maps the Platform methods to authenticated HTTP
routes.
