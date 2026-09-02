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

## Development

Install the locked development environment and run the complete merge gate:

```sh
uv sync --all-groups --locked
make verify
```

See [`aep-specs`](https://github.com/aep-foundation/aep-specs) for the normative drafts, schemas,
registries, examples, and test vectors.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

MIT.
