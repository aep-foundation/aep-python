from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from agent_enrollment_protocol.core import (
    AepAssertionError,
    AgentStatus,
    AssertionOperation,
    ClaimValues,
    ClientAssertionClaims,
    EnrollmentDecisionStatus,
    EnrollRequest,
    GrantRequest,
    GrantTypeConfig,
    InspectClaims,
    RevokeRequest,
)
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    AuthenticatedPrincipal,
    AuthenticationKind,
    CommandOptions,
    CredentialAuthenticationInput,
    EnrollmentDecision,
    EnrollmentRecord,
    GrantContext,
    GrantTypeDefinition,
    IdempotencyInput,
    MemoryEnrollmentStore,
    MemoryIdempotencyStore,
    MemoryReplayStore,
    ProtectedResourceRequest,
    ReplayRecord,
    RevokeContext,
    Service,
    ServiceOptions,
    StaticEnrollmentPolicy,
    StoredResponse,
)

NOW = datetime(2026, 9, 2, 12, tzinfo=UTC)
AGENT_DID = "did:web:agent.example"
SERVICE_DID = "did:web:service.example"


class Verifier:
    def __init__(self) -> None:
        self.contexts: list[AssertionVerificationContext] = []
        self.fail = False

    async def verify(
        self, assertion: str, context: AssertionVerificationContext
    ) -> ClientAssertionClaims:
        self.contexts.append(context)
        if self.fail:
            raise AepAssertionError("invalid")
        return ClientAssertionClaims.model_validate_json(_decode(assertion.split(".")[1]))


class GrantHandler:
    def __init__(self) -> None:
        self.grants: list[tuple[GrantRequest, GrantContext]] = []
        self.revocations: list[tuple[RevokeRequest, RevokeContext]] = []
        self.response = b'{"credential_id":"credential-1","api_key":"secret","header":"X-Key"}'

    async def grant(self, request: GrantRequest, context: GrantContext) -> bytes:
        self.grants.append((request, context))
        return self.response

    async def revoke(self, request: RevokeRequest, context: RevokeContext) -> None:
        self.revocations.append((request, context))


class Authenticator:
    def __init__(self) -> None:
        self.presented = False
        self.principal: AuthenticatedPrincipal | None = None

    async def authenticate(
        self, request: CredentialAuthenticationInput
    ) -> AuthenticatedPrincipal | None:
        return self.principal

    async def has_presentation(self, request: CredentialAuthenticationInput) -> bool:
        return self.presented


def _service(**changes: Any) -> tuple[Service, Verifier]:
    verifier = Verifier()
    options = ServiceOptions(
        service_did=SERVICE_DID,
        identity_methods=("did:web",),
        verifier=verifier,
        clock=lambda: NOW,
        identifier=lambda: "enrollment-1",
    )
    return Service(replace(options, **changes)), verifier


def _assertion(
    operation: AssertionOperation,
    *,
    jti: str,
    agent_did: str = AGENT_DID,
    audience: str = SERVICE_DID,
    resource: str | None = None,
    issued_at: int | None = None,
    expires_at: int | None = None,
    algorithm: str = "EdDSA",
    key_id: str | None = None,
    token_type: str = "JWT",
) -> str:
    now = int(NOW.timestamp())
    header = {"alg": algorithm, "kid": key_id or f"{agent_did}#key-1", "typ": token_type}
    payload: dict[str, object] = {
        "aud": audience,
        "exp": expires_at if expires_at is not None else now + 120,
        "iat": issued_at if issued_at is not None else now,
        "iss": agent_did,
        "jti": jti,
        "op": operation.value,
        "sub": agent_did,
    }
    if resource is not None:
        payload["resource"] = resource
    return f"{_encode(header)}.{_encode(payload)}.signature"


def _encode(value: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def _decode(value: str) -> str:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()


def _options(operation: AssertionOperation, jti: str, *, key: str | None = None) -> CommandOptions:
    return CommandOptions(client_assertion=_assertion(operation, jti=jti), idempotency_key=key)


@pytest.mark.asyncio
async def test_enroll_status_and_replay_protection() -> None:
    service, verifier = _service(
        claims=InspectClaims(required=("contact.email",), preferred=("person.first_name",))
    )
    body = (
        EnrollRequest(
            agent_did=AGENT_DID,
            claims=ClaimValues.model_validate({"contact.email": "agent@example.com"}),
            idempotency_key="enroll-1",
        )
        .model_dump_json(by_alias=True, exclude_none=True)
        .encode()
    )

    enrolled = await service.enroll(
        body, _options(AssertionOperation.ENROLL, "one", key="enroll-1")
    )
    assert enrolled.status == 200
    assert enrolled.body is not None and enrolled.body.status is AgentStatus.ACTIVE
    assert verifier.contexts[0].operation is AssertionOperation.ENROLL

    replay = await service.enroll(body, _options(AssertionOperation.ENROLL, "one", key="enroll-1"))
    assert replay.status == 401
    assert replay.problem is not None and replay.problem.code == "not_recognized"

    status = await service.status(_options(AssertionOperation.STATUS, "two"))
    assert status.status == 200
    assert status.body is not None and status.body.since == "2026-09-02T12:00:00Z"


@pytest.mark.asyncio
async def test_requirements_idempotency_and_lifecycle() -> None:
    service, _ = _service(claims=InspectClaims(required=("contact.email",)))
    body = b'{"agent_did":"did:web:agent.example","idempotency_key":"same"}'
    first = await service.enroll(body, _options(AssertionOperation.ENROLL, "a", key="same"))
    assert first.status == 422
    assert first.problem is not None
    assert first.problem.requirements_pending == ("contact.email",)

    replayed = await service.enroll(body, _options(AssertionOperation.ENROLL, "b", key="same"))
    assert replayed == first

    changed = b'{"agent_did":"did:web:agent.example","claims":{"contact.email":"a@b.co"}}'
    conflict = await service.enroll(changed, _options(AssertionOperation.ENROLL, "c", key="same"))
    assert conflict.status == 409
    assert conflict.problem is not None and conflict.problem.code == "idempotency_conflict"

    suspended, _ = _service(
        enrollment_policy=StaticEnrollmentPolicy(
            EnrollmentDecision(
                status=EnrollmentDecisionStatus.PENDING,
                owner_action_required=True,
                requirements_pending=("review",),
                verification_pending=("email",),
            )
        )
    )
    pending = await suspended.enroll(
        b'{"agent_did":"did:web:agent.example"}',
        _options(AssertionOperation.ENROLL, "d", key="pending"),
    )
    assert pending.body is not None and pending.body.owner_action_required == "true"
    assert pending.body.verification_pending == ("email",)


@pytest.mark.asyncio
async def test_grant_revoke_and_authentication() -> None:
    handler = GrantHandler()
    authenticator = Authenticator()
    definition = GrantTypeDefinition(
        grant_type="api-key",
        handler=handler,
        authenticator=authenticator,
        config=GrantTypeConfig(supports_per_credential_revoke="true"),
    )
    service, _ = _service(
        authentication_methods=("aep-jwt", "api-key"),
        grant_types=(definition,),
        inspect_url="https://service.example/.well-known/aep",
    )
    await service.enroll(
        b'{"agent_did":"did:web:agent.example"}',
        _options(AssertionOperation.ENROLL, "enroll", key="enroll"),
    )
    grant = await service.grant(
        b'{"grant_type":"api-key"}',
        _options(AssertionOperation.GRANT, "grant", key="grant"),
    )
    assert grant.status == 200
    assert grant.body == {
        "credential_id": "credential-1",
        "api_key": "secret",
        "header": "X-Key",
    }
    assert handler.grants[0][1].agent_did == AGENT_DID

    revoked = await service.revoke(
        b'{"grant_type":"api-key","credential_id":"credential-1"}',
        _options(AssertionOperation.REVOKE, "revoke", key="revoke"),
    )
    assert revoked.status == 200
    assert len(handler.revocations) == 1

    resource = "https://service.example/private"
    jwt = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={
                "Authorization": (
                    "AEP "
                    + _assertion(
                        AssertionOperation.AUTHENTICATE,
                        jti="authenticate",
                        resource=resource,
                    )
                )
            },
            method="GET",
            url=resource,
        )
    )
    assert jwt.authenticated
    assert jwt.principal is not None
    assert jwt.principal.authentication_kind is AuthenticationKind.AEP_JWT

    authenticator.presented = True
    authenticator.principal = AuthenticatedPrincipal(
        agent_did=AGENT_DID,
        authentication_kind=AuthenticationKind.SESSION_CREDENTIAL,
        authentication_method="api-key",
        credential_id="credential-1",
        grant_type="api-key",
        scopes=("read",),
    )
    credential = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers={"X-Key": "secret"}, method="GET", url=resource)
    )
    assert credential.authenticated and credential.principal == authenticator.principal

    authenticator.presented = False
    authenticator.principal = None
    missing = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers={}, method="GET", url=resource)
    )
    assert missing.response is not None
    assert missing.response.problem is not None
    assert missing.response.problem.code == "authentication_required"


@pytest.mark.asyncio
async def test_memory_stores_are_atomic_and_expire() -> None:
    replay = MemoryReplayStore()
    replay_record = ReplayRecord(expires_at=11, jwt_id="jti", subject=AGENT_DID)
    assert await replay.consume(replay_record, 10)
    assert not await replay.consume(replay_record, 10)
    with pytest.raises(ValueError, match="invalid record"):
        await replay.consume(replace(replay_record, expires_at=10), 10)

    enrollment = MemoryEnrollmentStore()
    calls = 0

    async def create() -> EnrollmentRecord:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return _record()

    results = await asyncio.gather(
        enrollment.find_or_create(AGENT_DID, create),
        enrollment.find_or_create(AGENT_DID, create),
    )
    assert calls == 1
    assert sorted(created for _, created in results) == [False, True]
    assert await enrollment.find(AGENT_DID) == _record()
    assert await enrollment.save(replace(_record(), status=AgentStatus.SUSPENDED)) == replace(
        _record(), status=AgentStatus.SUSPENDED
    )

    clock = [NOW]
    idempotency = MemoryIdempotencyStore(lambda: clock[0])
    calls = 0

    async def operation() -> StoredResponse:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return StoredResponse(b"{}", "application/aep+json", clock[0], {}, 200)

    value = IdempotencyInput(AGENT_DID, "enroll", "key", "sha256:one")
    simultaneous = await asyncio.gather(
        idempotency.execute(value, operation), idempotency.execute(value, operation)
    )
    assert calls == 1
    assert {item.state.value for item in simultaneous} == {"created", "replayed"}
    conflict = await idempotency.execute(replace(value, request_hash="sha256:two"), operation)
    assert conflict.state.value == "conflict"
    clock[0] += timedelta(hours=2)
    await idempotency.execute(value, operation)
    assert calls == 2

    with pytest.raises(ValueError, match="invalid input"):
        await idempotency.execute(replace(value, agent_did=""), operation)

    naive = MemoryIdempotencyStore(lambda: NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="offset-aware"):
        await naive.execute(value, operation)


def _record() -> EnrollmentRecord:
    return EnrollmentRecord(
        agent_did=AGENT_DID,
        claims=None,
        created_at=NOW,
        enrollment_id="enrollment-1",
        owner_action_required=False,
        requirements_pending=(),
        since=NOW,
        status=AgentStatus.ACTIVE,
        updated_at=NOW,
        verification_pending=(),
    )
