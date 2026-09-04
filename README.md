# Agent Enrollment Protocol for Python

[![CI](https://github.com/aep-foundation/aep-python/actions/workflows/ci.yml/badge.svg)](https://github.com/aep-foundation/aep-python/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/agent-enrollment-protocol)](https://pypi.org/project/agent-enrollment-protocol/)
[![Codecov](https://codecov.io/gh/aep-foundation/aep-python/graph/badge.svg)](https://codecov.io/gh/aep-foundation/aep-python)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Official Python software development kit for the
[Agent Enrollment Protocol](https://www.aep.foundation/), the open protocol for Agent enrollment,
Service-issued credentials, and authenticated Agent access.

## Installation

```sh
python -m pip install agent-enrollment-protocol
```

Python 3.11 or newer is required. The distribution provides one typed package with modules for each
integration role:

| Goal | Module |
| --- | --- |
| Use protocol models, validation, identity, and assertions | `agent_enrollment_protocol.core` |
| Inspect, enroll with, and authenticate to Services | `agent_enrollment_protocol.agent` |
| Integrate enrollment and authentication into a Service | `agent_enrollment_protocol.service` |
| Host managed Agent identities and delegated signing | `agent_enrollment_protocol.platform` |

Core is synchronous and transport-independent. Agent, Service, Platform, and their integration
interfaces are asynchronous. Applications provide durable stores and security policy through typed
protocols.

Framework integrations are optional and remain separate from Core and role behavior.

## Runnable examples

The repository includes self-contained examples that exercise real signed protocol flows without
external infrastructure:

```sh
uv run python examples/agent_service.py
uv run python examples/hosted_platform.py
```

The first example composes an Agent, Service, every built-in credential profile, protected resource,
and the framework-neutral ASGI adapter. The second demonstrates hosted identity Platform discovery,
Service DID resolution, provisioning, DID publication, delegated signing, and identity listing. See
[`examples/README.md`](./examples/README.md) for the integration boundaries and production
replacements.

The Service module includes stored credential profiles for each built-in Grant Type:

| Grant Type | Factory |
| --- | --- |
| API key | `stored_api_key_grant_type()` |
| Basic | `stored_basic_grant_type()` |
| OAuth Bearer | `stored_oauth_bearer_grant_type()` |

Each factory accepts application-owned credential issuance and storage implementations. The included
memory store is intended for examples and local development.

Concrete Grant Types and extensions can define additional Grant and Revoke request members. Pass
those members through `GrantOptions.parameters` or `RevokeOptions.parameters`; the Agent retains
control of the standard Grant Type and Revoke selector fields.

## Service ASGI integration

`agent_enrollment_protocol.adapters` provides a framework-neutral ASGI integration with no
additional dependency. `AepAsgiApplication` serves Inspect and every command advertised by the
Service. It enforces the command methods, media type, request-body limit, and idempotency header
boundary, and supplies cache metadata and conditional requests for Inspect.

`AepAuthenticationMiddleware` protects a downstream ASGI application and exposes the authenticated
Agent principal through `principal_from_scope()`. Place the protocol application outside the
authentication middleware so AEP's own command routes remain directly accessible:

```python
from agent_enrollment_protocol.adapters import (
    AepAsgiApplication,
    AepAuthenticationMiddleware,
    principal_from_scope,
)

protected_application = AepAuthenticationMiddleware(
    application,
    service,
    resource_origin="https://service.example",
)
asgi_application = AepAsgiApplication(service, protected_application)
```

The downstream application can obtain its immutable principal from the ASGI scope:

```python
principal = principal_from_scope(scope)
if principal is None:
    raise RuntimeError("The route requires AEP authentication")
```

Use a separate unprotected application branch for public resources. For local development,
`allow_insecure_loopback=True` permits an HTTP `localhost` or loopback resource origin; production
origins require HTTPS.

## Agent with a hosted identity Platform

`PlatformIdentityProvider` lets an Agent use a remote AEP Platform for Service-scoped identity
custody and delegated assertion signing. It discovers the Platform, recovers an existing active
identity before provisioning one, caches discovery metadata according to HTTP cache directives,
and supplies the resulting signer directly to `Agent`.

```python
import os

from agent_enrollment_protocol.agent import (
    Agent,
    AgentOptions,
    PlatformIdentityProvider,
    PlatformIdentityProviderOptions,
)


async def authentication_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {os.environ['AEP_PLATFORM_ACCESS_TOKEN']}"}


async with PlatformIdentityProvider(
    PlatformIdentityProviderOptions(
        authentication_headers=authentication_headers,
        platform_url="https://platform.example",
    )
) as identities:
    async with Agent(AgentOptions(identity_provider=identities)) as agent:
        result = await agent.service("https://service.example").enroll()
```

The Platform authentication callback is evaluated for each private request so applications can
refresh short-lived credentials. Supply `pending_sign_resolver` when the Platform can return
`202 Accepted` during delegated signing. The resolver receives the immutable retry interval and
opaque Platform context; returning updated context starts the next signing stage with a distinct
idempotency key. Without a resolver, pending signing raises `PlatformSignPendingError` for the
application to continue explicitly.

## Hosted identity Platform

`agent_enrollment_protocol.platform` implements discovery, Service-scoped Agent identity
provisioning, DID document publication, identity listing and lifecycle, delegated signing, and
optional hosted verification.

Applications supply caller authorization, Service DID resolution, key custody, and durable stores.
The included memory stores are suitable for local development, not production key custody or
durable idempotency.

```python
from datetime import timedelta

from agent_enrollment_protocol.core import SigningAlgorithm
from agent_enrollment_protocol.platform import DiscoveryOptions, Platform, PlatformOptions

platform = Platform(
    PlatformOptions(
        authorizer=authorizer,
        did_host="platform.example",
        did_url_template="https://platform.example/agents/{agent_did_id}/did.json",
        discovery=DiscoveryOptions(
            endpoint_base="/v1/aep",
            lifecycle_endpoint="/v1/aep/agent-identities/{agent_identity_id}",
            list_endpoint="/v1/aep/agent-identities",
            platform_name="Example Platform",
            provision_endpoint="/v1/aep/agent-identities",
            sign_endpoint="/v1/aep/agent-identities/{agent_identity_id}/sign",
        ),
        key_store=key_store,
        maximum_lifetime=timedelta(minutes=5),
        service_did_resolver=service_did_resolver,
        signing_algorithms=(SigningAlgorithm.ES256,),
    )
)
```

Map `platform.discovery()` to `/.well-known/aep-platform` and the remaining methods to the paths
advertised by `DiscoveryOptions`. Authenticate private Platform routes before constructing their
`RequestContext`; the Platform also invokes the supplied authorizer for every private operation.
Enable hosted verification only with a replay store.

## Development

Install the locked development environment and run the complete merge gate:

```sh
uv sync --all-groups --locked
make verify
```

Run the shared Agent, Service, and Platform conformance suites against the public Python APIs:

```sh
make conformance
```

The command reads the adjacent `../aep-specs` checkout by default and writes role reports to
`.conformance/reports/`. Set `AEP_SPECS_DIR` when the specifications are checked out elsewhere.

Run bidirectional Agent, Service, and Platform interoperability against the Node.js SDK:

```sh
make interoperability
```

The command reads the adjacent `../aep-node` checkout by default and writes a four-row evidence
report to `.interop/reports/aep-python-node-interoperability.json`. Set `AEP_NODE_DIR` when the
Node.js SDK is checked out elsewhere.

See [`aep-specs`](https://github.com/aep-foundation/aep-specs) for the normative drafts, schemas,
registries, examples, and test vectors.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

MIT.
