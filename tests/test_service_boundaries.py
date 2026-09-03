from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import timedelta
from typing import Any, cast

import pytest

from agent_enrollment_protocol.core import (
    AgentStatus,
    AssertionOperation,
    ClientAssertionClaims,
    OpenApiPathMatching,
    OpenApiReference,
    OpenApiTrailingSlash,
    SigningAlgorithm,
)
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    AuthenticatedPrincipal,
    AuthenticationKind,
    ClaimValueLimits,
    CommandOptions,
    EnrollmentRecord,
    GrantTypeDefinition,
    IdempotencyInput,
    IdempotencyResult,
    IdempotencyState,
    MemoryEnrollmentStore,
    ProtectedResourceRequest,
    Service,
    ServiceOptions,
    ServiceResult,
    StoredResponse,
)

from .test_service import (
    AGENT_DID,
    NOW,
    SERVICE_DID,
    Authenticator,
    GrantHandler,
    Verifier,
    _assertion,
    _options,
    _record,
    _service,
)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"service_did": ""}, "Service DID"),
        ({"identity_methods": ()}, "identity method"),
        ({"identity_methods": ("did:web", "did:web")}, "identity method"),
        ({"signing_algorithms": (SigningAlgorithm.EDDSA,)}, "signing algorithms"),
        (
            {"signing_algorithms": (SigningAlgorithm.EDDSA, SigningAlgorithm.EDDSA)},
            "signing algorithms",
        ),
        ({"clock_tolerance": timedelta(seconds=-1)}, "clock tolerance"),
        ({"clock_tolerance": timedelta(milliseconds=1)}, "clock tolerance"),
        ({"maximum_assertion_lifetime": timedelta(seconds=301)}, "assertion lifetime"),
        ({"claim_value_limits": ClaimValueLimits(maximum_member_count=0)}, "claim limits"),
        ({"inspect_url": "http://service.example/aep"}, "absolute HTTPS"),
        ({"inspect_url": "https://user@service.example/aep"}, "absolute HTTPS"),
        ({"authentication_methods": tuple(f"method-{index}" for index in range(17))}, "limit"),
        ({"authentication_methods": ("api-key",)}, "matching authenticator"),
    ],
)
def test_rejects_invalid_service_options(changes: dict[str, object], message: str) -> None:
    verifier = Verifier()
    base = ServiceOptions(
        service_did="did:web:service.example",
        identity_methods=("did:web",),
        verifier=verifier,
    )
    with pytest.raises(ValueError, match=message):
        Service(replace(base, **cast(Any, changes)))


def test_inspect_document_is_independent_and_validates_definitions() -> None:
    handler = GrantHandler()
    service, _ = _service(
        extensions=("https://example.com/extension",),
        grant_types=(GrantTypeDefinition("api-key", handler),),
    )
    first = service.inspect_document
    second = service.inspect_document
    assert first is not second
    assert first.commands.supported == ("enroll", "grant", "inspect", "revoke", "status")
    assert first.extensions is not None

    documented, _ = _service(
        openapi=OpenApiReference(
            url="/openapi.json",
            path_matching=OpenApiPathMatching(trailing_slash=OpenApiTrailingSlash.STRICT),
        )
    )
    assert documented.inspect_document.http.openapi is not None

    local, _ = _service(
        allow_insecure_loopback=True,
        inspect_url="http://localhost:8080/.well-known/aep",
        service_did="did:web:localhost%3A8080",
    )
    assert local.inspect_document.service.did == "did:web:localhost%3A8080"
    with pytest.raises(ValueError, match="does not match"):
        _service(inspect_url="https://other.example/.well-known/aep")

    with pytest.raises(ValueError, match="unique identifier"):
        _service(
            grant_types=(
                GrantTypeDefinition("api-key", handler),
                GrantTypeDefinition("api-key", handler),
            )
        )


@pytest.mark.asyncio
async def test_command_input_failures_do_not_disclose_identity() -> None:
    service, verifier = _service()
    verifier.fail = True
    unauthorized = await service.enroll(
        b"{}", CommandOptions(client_assertion="invalid", idempotency_key="key")
    )
    assert unauthorized.problem is not None and unauthorized.problem.code == "not_recognized"

    verifier.fail = False
    malformed = await service.enroll(
        b"not-json", _options(AssertionOperation.ENROLL, "malformed", key="key")
    )
    assert malformed.problem is not None and malformed.problem.code == "invalid_request"

    mismatch = await service.enroll(
        b'{"agent_did":"did:web:other.example"}',
        _options(AssertionOperation.ENROLL, "mismatch", key="key"),
    )
    assert mismatch.status == 400

    no_key = await service.enroll(
        b'{"agent_did":"did:web:agent.example"}',
        _options(AssertionOperation.ENROLL, "no-key"),
    )
    assert no_key.status == 400

    conflicting_key = await service.enroll(
        b'{"agent_did":"did:web:agent.example","idempotency_key":"body"}',
        _options(AssertionOperation.ENROLL, "different-key", key="header"),
    )
    assert conflicting_key.status == 400

    limited, _ = _service(claim_value_limits=ClaimValueLimits(maximum_encoded_bytes=2))
    oversized = await limited.enroll(
        b'{"agent_did":"did:web:agent.example","claims":{"contact.email":"a@b.co"}}',
        _options(AssertionOperation.ENROLL, "large", key="key"),
    )
    assert oversized.status == 400

    unidentified, _ = _service(identifier=lambda: "")
    with pytest.raises(ValueError, match="empty identifier"):
        await unidentified.enroll(
            b'{"agent_did":"did:web:agent.example"}',
            _options(AssertionOperation.ENROLL, "empty-id", key="empty-id"),
        )


@pytest.mark.asyncio
async def test_status_and_lifecycle_boundaries() -> None:
    empty, _ = _service()
    absent = await empty.status(_options(AssertionOperation.STATUS, "absent"))
    assert absent.status == 401

    for status, code in (
        (AgentStatus.SUSPENDED, "identity_suspended"),
        (AgentStatus.TERMINATED, "identity_terminated"),
        (AgentStatus.UNAVAILABLE, "identity_unavailable"),
    ):
        store = MemoryEnrollmentStore()
        await store.save(replace(_record(), status=status))
        service, _ = _service(enrollment_store=store)
        result = await service.enroll(
            b'{"agent_did":"did:web:agent.example"}',
            _options(AssertionOperation.ENROLL, f"enroll-{status}", key=f"key-{status}"),
        )
        assert result.problem is not None and result.problem.code == code

    with pytest.raises(ValueError, match="UTC offsets"):
        replace(_record(), since=NOW.replace(tzinfo=None))


@pytest.mark.asyncio
async def test_grant_and_revoke_failures_and_all_grant_types() -> None:
    first = GrantHandler()
    second = GrantHandler()
    store = MemoryEnrollmentStore()
    await store.save(
        replace(
            _record(),
            owner_action_required=True,
            requirements_pending=("review",),
            status=AgentStatus.PENDING,
            verification_pending=("email",),
        )
    )
    service, _ = _service(
        enrollment_store=store,
        grant_types=(
            GrantTypeDefinition("zeta", second),
            GrantTypeDefinition("alpha", first),
        ),
    )
    pending = await service.grant(
        b'{"grant_type":"alpha"}',
        _options(AssertionOperation.GRANT, "pending", key="pending"),
    )
    assert pending.problem is not None and pending.problem.code == "verification_pending"
    assert pending.problem.owner_action_required == "true"
    assert pending.problem.requirements_pending == ("review",)
    assert pending.problem.verification_pending == ("email",)

    unsupported = await service.grant(
        b'{"grant_type":"other"}',
        _options(AssertionOperation.GRANT, "unsupported", key="unsupported"),
    )
    assert unsupported.problem is not None and unsupported.problem.code == "unsupported_grant_type"

    malformed = await service.grant(
        b"{}", _options(AssertionOperation.GRANT, "malformed", key="malformed")
    )
    assert malformed.status == 400

    await store.save(_record())
    invalid_selector = await service.revoke(
        b'{"grant_type":"alpha","credential_id":"one"}',
        _options(AssertionOperation.REVOKE, "selector", key="selector"),
    )
    assert invalid_selector.status == 400

    all_result = await service.revoke(
        b'{"all_grant_types":"true"}',
        _options(AssertionOperation.REVOKE, "all", key="all"),
    )
    assert all_result.status == 200
    assert first.revocations[0][1].grant_type == "alpha"
    assert second.revocations[0][1].grant_type == "zeta"

    empty, _ = _service(grant_types=(GrantTypeDefinition("alpha", first),))
    grant_absent = await empty.grant(
        b'{"grant_type":"alpha"}',
        _options(AssertionOperation.GRANT, "grant-absent", key="grant-absent"),
    )
    assert grant_absent.status == 401
    revoke_absent = await empty.revoke(
        b'{"grant_type":"alpha"}',
        _options(AssertionOperation.REVOKE, "revoke-absent", key="revoke-absent"),
    )
    assert revoke_absent.status == 401
    revoke_unsupported = await service.revoke(
        b'{"grant_type":"other"}',
        _options(AssertionOperation.REVOKE, "revoke-other", key="revoke-other"),
    )
    assert revoke_unsupported.status == 400
    revoke_malformed = await service.revoke(
        b"{}", _options(AssertionOperation.REVOKE, "revoke-bad", key="revoke-bad")
    )
    assert revoke_malformed.status == 400

    unauthorized_grant = await service.grant(b"{}", CommandOptions(""))
    unauthorized_revoke = await service.revoke(b"{}", CommandOptions(""))
    assert unauthorized_grant.status == unauthorized_revoke.status == 401


@pytest.mark.asyncio
async def test_assertion_and_protected_resource_boundaries() -> None:
    store = MemoryEnrollmentStore()
    await store.save(_record())
    service, _ = _service(authentication_methods=("aep-jwt",), enrollment_store=store)
    invalid_tokens = (
        _assertion(AssertionOperation.STATUS, jti="type", token_type="at+jwt"),
        _assertion(AssertionOperation.STATUS, jti="alg", algorithm="none"),
        _assertion(AssertionOperation.STATUS, jti="kid", key_id="did:web:other.example#key"),
        _assertion(AssertionOperation.STATUS, jti="aud", audience="did:web:other.example"),
        _assertion(AssertionOperation.ENROLL, jti="op"),
        _assertion(
            AssertionOperation.STATUS,
            jti="future",
            issued_at=int(NOW.timestamp()) + 31,
            expires_at=int(NOW.timestamp()) + 60,
        ),
        _assertion(
            AssertionOperation.STATUS,
            jti="expired",
            issued_at=int(NOW.timestamp()) - 100,
            expires_at=int(NOW.timestamp()) - 31,
        ),
    )
    for token in invalid_tokens:
        result = await service.status(CommandOptions(token))
        assert result.status == 401

    resource = "https://service.example/private"
    ambiguous = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={"Authorization": ("Bearer one", "Basic two")},
            method="GET",
            url=resource,
        )
    )
    assert ambiguous.response is not None
    assert ambiguous.response.problem is not None
    assert ambiguous.response.problem.code == "not_recognized"

    malformed = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers={"AEP-Authorization": "bad"}, method="GET", url=resource)
    )
    assert malformed.response is not None

    duplicates = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={"AEP-Authorization": ("AEP one", "AEP two")},
            method="GET",
            url=resource,
        )
    )
    assert duplicates.response is not None

    both = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={"AEP-Authorization": "AEP one", "Authorization": "Bearer two"},
            method="GET",
            url=resource,
        )
    )
    assert both.response is not None

    no_jwt, _ = _service()
    unsupported = await no_jwt.authenticate_protected_resource(
        ProtectedResourceRequest(headers={"Authorization": "AEP one"}, method="GET", url=resource)
    )
    assert unsupported.response is not None
    assert unsupported.response.problem is not None
    assert unsupported.response.problem.code == "unsupported_authentication_method"

    unknown = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={
                "Authorization": "AEP "
                + _assertion(
                    AssertionOperation.AUTHENTICATE,
                    jti="missing-agent",
                    agent_did="did:web:missing.example",
                    resource=resource,
                )
            },
            method="GET",
            url=resource,
        )
    )
    assert unknown.response is not None

    with pytest.raises(ValueError, match="absolute HTTPS"):
        await service.authenticate_protected_resource(
            ProtectedResourceRequest(headers={}, method="GET", url="http://example.com")
        )
    with pytest.raises(ValueError, match="required"):
        await service.authenticate_protected_resource(
            ProtectedResourceRequest(headers={}, method="GET", url=cast(str, None))
        )

    dedicated = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={"AEP-Authorization": "Bearer session", "Authorization": "Payment challenge"},
            method="GET",
            url=resource,
        )
    )
    assert dedicated.response is not None

    unrelated = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={"Authorization": "Payment challenge"}, method="GET", url=resource
        )
    )
    assert unrelated.response is not None

    ipv6 = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers={}, method="GET", url="https://[::1]:8443/private")
    )
    assert ipv6.response is not None
    assert "https://[::1]:8443/.well-known/aep" in ipv6.response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_credential_authentication_rejects_invalid_principals() -> None:
    handler = GrantHandler()
    authenticator = Authenticator()
    definition = GrantTypeDefinition("api-key", handler, authenticator=authenticator)
    store = MemoryEnrollmentStore()
    await store.save(_record())
    service, _ = _service(
        authentication_methods=("api-key",),
        enrollment_store=store,
        grant_types=(definition,),
    )
    resource = "https://service.example/private"
    authenticator.principal = AuthenticatedPrincipal(
        agent_did="",
        authentication_kind=AuthenticationKind.SESSION_CREDENTIAL,
        authentication_method="api-key",
        grant_type="api-key",
    )
    with pytest.raises(ValueError, match="invalid principal"):
        await service.authenticate_protected_resource(
            ProtectedResourceRequest(headers={"X-Key": "one"}, method="GET", url=resource)
        )

    authenticator.principal = replace(authenticator.principal, agent_did="did:web:missing.example")
    missing = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers={"X-Key": "one"}, method="GET", url=resource)
    )
    assert missing.response is not None


@pytest.mark.asyncio
async def test_custom_boundaries_are_validated() -> None:
    class EmptyIdempotencyStore:
        async def execute(
            self,
            value: IdempotencyInput,
            operation: Callable[[], Awaitable[StoredResponse]],
        ) -> IdempotencyResult:
            del value, operation
            return IdempotencyResult(None, IdempotencyState.CREATED)

    service, _ = _service(idempotency_store=EmptyIdempotencyStore())
    with pytest.raises(ValueError, match="omitted"):
        await service.enroll(
            b'{"agent_did":"did:web:agent.example"}',
            _options(AssertionOperation.ENROLL, "missing-response", key="key"),
        )

    naive, _ = _service(clock=lambda: NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="offset-aware"):
        await naive.status(_options(AssertionOperation.STATUS, "naive-clock"))

    class InvalidClaimsVerifier:
        async def verify(
            self, assertion: str, context: AssertionVerificationContext
        ) -> ClientAssertionClaims:
            del assertion, context
            return ClientAssertionClaims.model_construct(
                aud=SERVICE_DID,
                exp=1,
                iat=2,
                iss=AGENT_DID,
                jti="bad",
                op=AssertionOperation.STATUS,
                sub=AGENT_DID,
            )

    invalid = Service(
        ServiceOptions(
            service_did="did:web:service.example",
            identity_methods=("did:web",),
            verifier=InvalidClaimsVerifier(),
            clock=lambda: NOW,
        )
    )
    result = await invalid.status(CommandOptions(_assertion(AssertionOperation.STATUS, jti="bad")))
    assert result.status == 401

    with pytest.raises(ValueError, match="identifiers"):
        replace(_record(), enrollment_id="")


@pytest.mark.asyncio
async def test_invalid_grant_payloads_and_stored_responses() -> None:
    handler = GrantHandler()
    store = MemoryEnrollmentStore()
    await store.save(_record())
    service, _ = _service(
        enrollment_store=store,
        grant_types=(GrantTypeDefinition("api-key", handler),),
    )
    for index, response in enumerate((b"not-json", b"[]", b'{"credential_id":""}')):
        handler.response = response
        with pytest.raises(ValueError):
            await service.grant(
                b'{"grant_type":"api-key"}',
                _options(AssertionOperation.GRANT, f"bad-grant-{index}", key=f"bad-{index}"),
            )

    class ArrayIdempotencyStore:
        async def execute(
            self,
            value: IdempotencyInput,
            operation: Callable[[], Awaitable[StoredResponse]],
        ) -> IdempotencyResult:
            del value, operation
            return IdempotencyResult(
                StoredResponse(b"[]", "application/aep+json", NOW, {}, 200),
                IdempotencyState.REPLAYED,
            )

    replayed, _ = _service(
        enrollment_store=store,
        grant_types=(GrantTypeDefinition("api-key", handler),),
        idempotency_store=ArrayIdempotencyStore(),
    )
    with pytest.raises(ValueError, match="JSON object"):
        await replayed.grant(
            b'{"grant_type":"api-key"}',
            _options(AssertionOperation.GRANT, "array", key="array"),
        )


@pytest.mark.asyncio
async def test_claim_structure_limits() -> None:
    cases = (
        (ClaimValueLimits(maximum_string_length=2), {"custom": "long"}),
        (ClaimValueLimits(maximum_member_count=1), {"one": 1, "two": 2}),
        (ClaimValueLimits(maximum_object_depth=1), {"custom": {"nested": True}}),
        (ClaimValueLimits(maximum_string_length=2), {"long-key": True}),
        (ClaimValueLimits(maximum_object_depth=1), {"custom": [[True]]}),
    )
    for index, (limits, claims) in enumerate(cases):
        service, _ = _service(claim_value_limits=limits)
        body = (
            '{"agent_did":"did:web:agent.example","claims":' + json.dumps(claims) + "}"
        ).encode()
        result = await service.enroll(
            body,
            _options(AssertionOperation.ENROLL, f"limit-{index}", key=f"limit-{index}"),
        )
        assert result.status == 400


@pytest.mark.asyncio
async def test_memory_enrollment_factory_failure_wakes_waiters() -> None:
    store = MemoryEnrollmentStore()
    calls = 0

    async def fail() -> EnrollmentRecord:
        nonlocal calls
        calls += 1
        raise RuntimeError("failed")

    with pytest.raises(RuntimeError, match="failed"):
        await store.find_or_create(AGENT_DID, fail)
    assert calls == 1

    async def mismatch() -> EnrollmentRecord:
        return replace(_record(), agent_did="did:web:other.example")

    with pytest.raises(ValueError, match="mismatched"):
        await store.find_or_create(AGENT_DID, mismatch)


def test_service_result_and_stored_response_copy_caller_values() -> None:
    headers = {"X-Test": "one"}
    result: ServiceResult[object] = ServiceResult(200, headers=headers)
    headers["X-Test"] = "two"
    assert result.headers["X-Test"] == "one"

    body = bytearray(b"{}")
    stored = StoredResponse(cast(bytes, body), "application/aep+json", NOW, headers, 200)
    body[0] = 0
    assert stored.body == b"{}"
    with pytest.raises(ValueError, match="UTC offset"):
        StoredResponse(b"{}", "application/aep+json", NOW.replace(tzinfo=None), {}, 200)
