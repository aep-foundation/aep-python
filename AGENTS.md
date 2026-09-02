# AGENTS.md

## Repository

This repository contains the official Python distribution for AEP. The
`agent_enrollment_protocol` package has four role modules:

- `core`: transport-independent models, validation, identity, assertions, and HTTP primitives.
- `agent`: Agent enrollment, credential, and protected-resource authentication workflows.
- `service`: Service enrollment, credential issuance, and request authentication integration.
- `platform`: Platform-hosted Agent identity management and delegated signing.

Framework adapters live under `agent_enrollment_protocol.adapters` and remain optional. The
normative protocol is maintained in `aep-foundation/aep-specs`. Check that source before changing
wire behavior. Use `aep-node` only as reference evidence after the specification and recorded user
decisions.

## Verification

Run `make verify` before merging. Public APIs must be typed, documented, and backed by tests and
authoritative protocol behavior.

## Conventions

- Support Python 3.11 and newer; continuous integration covers the minimum and current stable
  versions.
- Keep Core synchronous and independent of asynchronous runtimes and HTTP clients.
- Keep Agent, Service, Platform, transports, stores, and policies asynchronous.
- Keep Agent hosted-identity support dependent on Core wire contracts, not Platform implementation
  code.
- Use strict, frozen Pydantic models and immutable nested collections for protocol data.
- Use `typing.Protocol` for caller-provided transports, stores, policies, clocks, and signers.
- Keep Service integration independent of ASGI, FastAPI, Flask, Django, and other frameworks.
- Return typed exceptions rather than logging from library modules.
- Do not implement JOSE or JWT cryptography directly; use the approved dependencies.
- Do not add a runtime JSON Schema engine. AEP uses bounded native wire validation.
- Declare every directly imported package as a direct dependency and keep development tools locked.
- Describe current behavior; do not leave speculative or historical comments.
- Keep public APIs small, idiomatic, and backed by tests.
