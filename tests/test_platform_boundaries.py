from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, cast

import pytest

from agent_enrollment_protocol.core import (
    AssertionOperation,
    ManagedAgentStatus,
    PlatformAgentIdentity,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignCompleted,
    PlatformSignPending,
    PlatformSignRequest,
    PlatformVerificationRequest,
    PlatformVerificationResponse,
    ProblemDetails,
    SigningAlgorithm,
)
from agent_enrollment_protocol.platform import (
    DidVerificationMethod,
    IdempotentOperation,
    IdentityListQuery,
    IdentityListResult,
    IdentityRecord,
    MemoryIdentityStore,
    MemoryPlatformIdempotencyStore,
    MemoryReplayStore,
    Platform,
    PlatformIdempotencyInput,
    PlatformIdempotencyResult,
    PlatformIdempotencyState,
    PlatformResult,
    RequestContext,
    StoredResponse,
    create_did_document,
    create_service_scoped_agent_did,
)
from agent_enrollment_protocol.platform.document import create_discovery_document, render_did_url
from tests.test_platform import (
    NOW,
    SERVICE_DID,
    AllowAuthorizer,
    KeyStore,
    context,
    options,
    provisioned,
)


def record(**changes: Any) -> IdentityRecord:
    values: dict[str, Any] = {
        "agent_did": "did:web:platform.example:agents:one",
        "agent_did_id": "one",
        "agent_identity_id": "pai_one",
        "created_at": NOW,
        "did_document_url": "https://platform.example/agents/one/did.json",
        "key_id": "did:web:platform.example:agents:one",
        "principal": "owner",
        "service_did": SERVICE_DID,
        "signing_algorithms": (SigningAlgorithm.ES256,),
        "status": ManagedAgentStatus.ACTIVE,
        "updated_at": NOW,
    }
    values.update(changes)
    return IdentityRecord(**values)


@pytest.mark.parametrize(
    "host,prefix,identifier",
    [
        ("", "agents", "one"),
        ("example.com", "agents", ""),
        ("user@example.com", "agents", "one"),
        ("example.com/path", "agents", "one"),
    ],
)
def test_invalid_did_inputs(host: str, prefix: str, identifier: str) -> None:
    with pytest.raises(ValueError, match="DID host"):
        create_service_scoped_agent_did(host, prefix, identifier)


def test_did_helpers() -> None:
    assert create_service_scoped_agent_did("example.com", "/a/b/", "a b").endswith(":a:b:a%20b")
    with pytest.raises(ValueError, match="placeholder"):
        render_did_url("https://example.com/did.json", "one")
    for template in (
        "http://example.com/{agent_did_id}",
        "https://user@example.com/{agent_did_id}",
        "https://example.com/{agent_did_id}#fragment",
    ):
        with pytest.raises(ValueError, match="absolute HTTPS"):
            render_did_url(template, "one")
    identity = record()
    method = DidVerificationMethod(
        controller=identity.agent_did,
        id=identity.key_id,
        public_key_jwk={"kty": "EC"},
        type="JsonWebKey2020",
    )
    document = create_did_document(identity, method)
    assert document["verificationMethod"][0]["publicKeyJwk"] == {"kty": "EC"}
    for invalid in (
        replace(method, id="wrong"),
        replace(method, controller="wrong"),
        replace(method, type=""),
        replace(method, public_key_jwk={}),
    ):
        with pytest.raises(ValueError, match="does not match"):
            create_did_document(identity, invalid)


def test_discovery_boundaries() -> None:
    base = options().discovery
    for field in (
        "endpoint_base",
        "lifecycle_endpoint",
        "list_endpoint",
        "provision_endpoint",
        "sign_endpoint",
    ):
        with pytest.raises(ValueError, match="absolute path"):
            create_discovery_document(
                replace(base, **{field: "https://bad.example/path"}),
                did_url_template="https://platform.example/{agent_did_id}",
                hosted_verification=False,
                signing_algorithms=(SigningAlgorithm.ES256,),
                default_lifetime_seconds=300,
            )
    with pytest.raises(ValueError, match="flag and endpoint"):
        create_discovery_document(
            base,
            did_url_template="https://platform.example/{agent_did_id}",
            hosted_verification=True,
            signing_algorithms=(SigningAlgorithm.ES256,),
            default_lifetime_seconds=300,
        )
    hosted = replace(base, hosted_verification_endpoint="relative")
    with pytest.raises(ValueError, match="absolute path"):
        create_discovery_document(
            hosted,
            did_url_template="https://platform.example/{agent_did_id}",
            hosted_verification=True,
            signing_algorithms=(SigningAlgorithm.ES256,),
            default_lifetime_seconds=300,
        )
    with pytest.raises(ValueError, match="name"):
        create_discovery_document(
            replace(base, platform_name=""),
            did_url_template="https://platform.example/{agent_did_id}",
            hosted_verification=False,
            signing_algorithms=(SigningAlgorithm.ES256,),
            default_lifetime_seconds=300,
        )
    document = create_discovery_document(
        replace(
            base,
            hosted_verification_endpoint="/verify",
            platform_did="did:web:platform.example",
        ),
        did_url_template="https://platform.example/{agent_did_id}",
        hosted_verification=True,
        signing_algorithms=(SigningAlgorithm.ES256,),
        default_lifetime_seconds=60,
    )
    assert document.platform.did == "did:web:platform.example"


@pytest.mark.asyncio
async def test_memory_identity_store_boundaries() -> None:
    store = MemoryIdentityStore()

    async def create() -> IdentityRecord:
        return record()

    for principal, service in (("", SERVICE_DID), ("owner", "")):
        with pytest.raises(ValueError, match="scope"):
            await store.find_or_create(principal, service, create)
    with pytest.raises(ValueError, match="requested scope"):
        await store.find_or_create("other", SERVICE_DID, create)
    with pytest.raises(ValueError, match="invalid record"):
        await store.find_or_create("owner", SERVICE_DID, lambda: _return(record(agent_did="")))
    with pytest.raises(ValueError, match="invalid record"):
        await store.find_or_create(
            "owner", SERVICE_DID, lambda: _return(record(key_id="did:web:wrong"))
        )

    saved, _ = await store.find_or_create("owner", SERVICE_DID, create)
    assert await store.find_by_agent_did(saved.agent_did) == saved
    assert await store.find_by_agent_did("missing") is None
    assert await store.find_by_agent_did_id(saved.agent_did_id) == saved
    assert await store.find_by_agent_did_id("missing") is None
    assert await store.get("missing") is None
    assert (await store.list("owner", IdentityListQuery(descending=True))).total == 1
    assert (
        await store.list("owner", IdentityListQuery(status=ManagedAgentStatus.SUSPENDED))
    ).total == 0
    for query in (IdentityListQuery(limit=-1), IdentityListQuery(offset=-1)):
        with pytest.raises(ValueError, match="list query"):
            await store.list("owner", query)
    with pytest.raises(ValueError, match="list query"):
        await store.list("", IdentityListQuery())
    with pytest.raises(ValueError, match="update"):
        await store.update_status("pai_one", ManagedAgentStatus.ACTIVE, NOW.replace(tzinfo=None))
    assert await store.update_status("missing", ManagedAgentStatus.ACTIVE, NOW) is None

    duplicate_store = MemoryIdentityStore()
    await duplicate_store.find_or_create("owner", SERVICE_DID, create)
    with pytest.raises(ValueError, match="unique"):
        await duplicate_store.find_or_create(
            "owner",
            "did:web:other.example",
            lambda: _return(replace(record(), service_did="did:web:other.example")),
        )


async def _return(value: IdentityRecord) -> IdentityRecord:
    return value


@pytest.mark.asyncio
async def test_memory_idempotency_and_replay_boundaries() -> None:
    current = [NOW]
    store = MemoryPlatformIdempotencyStore(lambda: current[0])
    value = PlatformIdempotencyInput("key", IdempotentOperation.SIGN, "owner", "hash")
    response = StoredResponse(200, "application/aep+json", b"{}", NOW)
    calls = 0

    async def execute() -> StoredResponse:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return response

    results = await asyncio.gather(store.execute(value, execute), store.execute(value, execute))
    assert calls == 1
    assert {result.state for result in results} == {
        PlatformIdempotencyState.CREATED,
        PlatformIdempotencyState.REPLAYED,
    }
    conflict = await store.execute(replace(value, request_hash="other"), execute)
    assert conflict.state is PlatformIdempotencyState.CONFLICT
    current[0] += timedelta(hours=1, seconds=1)
    assert (await store.execute(value, execute)).state is PlatformIdempotencyState.CREATED
    for invalid in (
        replace(value, principal=""),
        replace(value, idempotency_key=""),
        replace(value, request_hash=""),
    ):
        with pytest.raises(ValueError, match="input"):
            await store.execute(invalid, execute)
    naive = MemoryPlatformIdempotencyStore(lambda: NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="offset-aware"):
        await naive.execute(value, execute)

    replay = MemoryReplayStore()
    assert await replay.consume("one", NOW + timedelta(seconds=1), NOW)
    assert not await replay.consume("one", NOW + timedelta(seconds=1), NOW)
    assert not await replay.consume("expired", NOW, NOW)
    assert await replay.consume("two", NOW + timedelta(seconds=2), NOW + timedelta(seconds=1))
    for key, expiry, now in (
        ("", NOW, NOW),
        ("one", NOW.replace(tzinfo=None), NOW),
        ("one", NOW, NOW.replace(tzinfo=None)),
    ):
        with pytest.raises(ValueError, match="replay input"):
            await replay.consume(key, expiry, now)


@pytest.mark.parametrize(
    "change,message",
    [
        ({"signing_algorithms": ()}, "unique"),
        ({"signing_algorithms": (SigningAlgorithm.ES256, SigningAlgorithm.ES256)}, "unique"),
        ({"maximum_lifetime": timedelta(milliseconds=1)}, "whole number"),
        ({"maximum_lifetime": timedelta(seconds=301)}, "configured maximum"),
        ({"default_lifetime": timedelta(seconds=301)}, "configured maximum"),
        ({"hosted_verification": True}, "replay store"),
    ],
)
def test_platform_configuration_boundaries(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Platform(options(**change))


def test_unsupported_platform_algorithm() -> None:
    with pytest.raises(ValueError, match="not supported"):
        Platform(options(signing_algorithms=(cast(SigningAlgorithm, "RS256"),)))


def test_required_platform_collaborators() -> None:
    for field in ("authorizer", "key_store", "service_did_resolver"):
        with pytest.raises(ValueError, match="required"):
            Platform(options(**{field: None}))


@pytest.mark.asyncio
async def test_platform_operation_boundaries() -> None:
    platform = Platform(options())
    identity_id, _ = await provisioned(platform)
    assert (
        await platform.sign(
            "missing",
            PlatformSignRequest(jti="one", op=AssertionOperation.STATUS, service_did=SERVICE_DID),
            context("missing"),
        )
    ).status == 404
    assert (
        await platform.sign(
            identity_id,
            PlatformSignRequest(
                jti="one", op=AssertionOperation.STATUS, service_did="did:web:other.example"
            ),
            context("wrong-service"),
        )
    ).status == 404
    assert (
        await platform.update_identity(
            "missing", PlatformLifecycleRequest(status=ManagedAgentStatus.ACTIVE), context(key=None)
        )
    ).status == 404

    class RejectTransition:
        async def can_sign(self, identity: IdentityRecord, context: RequestContext) -> bool:
            return True

        async def can_transition(
            self, identity: IdentityRecord, status: ManagedAgentStatus, context: RequestContext
        ) -> bool:
            return False

        async def can_verify(self, identity: IdentityRecord, context: RequestContext) -> bool:
            return False

    rejected = Platform(options(lifecycle_policy=RejectTransition()))
    rejected_id, _ = await provisioned(rejected)
    assert (
        await rejected.update_identity(
            rejected_id,
            PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
            context(key=None),
        )
    ).status == 403

    class PermissiveLifecycle(RejectTransition):
        async def can_transition(
            self,
            identity: IdentityRecord,
            status: ManagedAgentStatus,
            context: RequestContext,
        ) -> bool:
            return True

    permissive = Platform(options(lifecycle_policy=PermissiveLifecycle()))
    permissive_id, _ = await provisioned(permissive)
    await permissive.update_identity(
        permissive_id,
        PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
        context(key=None),
    )
    assert (
        await permissive.sign(
            permissive_id,
            PlatformSignRequest(
                jti="inactive",
                op=AssertionOperation.STATUS,
                service_did=SERVICE_DID,
            ),
            context("inactive"),
        )
    ).status == 403

    class VanishingStore(MemoryIdentityStore):
        async def update_status(
            self, agent_identity_id: str, status: ManagedAgentStatus, updated_at: datetime
        ) -> IdentityRecord | None:
            return None

    vanishing = Platform(options(identity_store=VanishingStore()))
    vanishing_id, _ = await provisioned(vanishing)
    assert (
        await vanishing.update_identity(
            vanishing_id,
            PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
            context(key=None),
        )
    ).status == 404

    generated = Platform(options(agent_did_id_generator=None, identifier=None, clock=None))
    generated_result = await generated.provision(
        PlatformProvisionRequest(service_did=SERVICE_DID), context("generated")
    )
    assert generated_result.status == 200

    prefixed = Platform(options(identifier=lambda: "pai_existing"))
    prefixed_result = await prefixed.provision(
        PlatformProvisionRequest(service_did=SERVICE_DID), context("prefixed")
    )
    assert isinstance(prefixed_result.body, PlatformAgentIdentity)
    assert prefixed_result.body.agent_identity_id == "pai_existing"

    for change in (
        {"identifier": lambda: ""},
        {"agent_did_id_generator": lambda: ""},
        {"clock": lambda: NOW.replace(tzinfo=None)},
    ):
        invalid = Platform(options(**change))
        with pytest.raises(ValueError):
            await invalid.provision(
                PlatformProvisionRequest(service_did=SERVICE_DID), context("invalid")
            )

    class MismatchedStore(MemoryIdentityStore):
        async def find_or_create(
            self, principal: str, service_did: str, factory: Any
        ) -> tuple[IdentityRecord, bool]:
            return replace(record(), principal="other"), True

    mismatched = Platform(options(identity_store=MismatchedStore()))
    with pytest.raises(ValueError, match="mismatched"):
        await mismatched.provision(
            PlatformProvisionRequest(service_did=SERVICE_DID), context("mismatched")
        )

    class UnauthorizedListStore(MemoryIdentityStore):
        async def list(self, principal: str, query: IdentityListQuery) -> IdentityListResult:
            return IdentityListResult((replace(record(), principal="other"),), 1)

    unauthorized = Platform(options(identity_store=UnauthorizedListStore()))
    with pytest.raises(ValueError, match="unauthorized"):
        await unauthorized.list(IdentityListQuery(), context(key=None))


@pytest.mark.asyncio
async def test_sign_handler_validation() -> None:
    cases: tuple[PlatformResult[Any], ...] = (
        PlatformResult(
            200,
            PlatformSignPending(status="pending", retry_after_seconds="1"),
            "application/aep+json",
        ),
        PlatformResult(
            200,
            PlatformSignCompleted(
                status="completed",
                agent_did="did:web:platform.example:agents:agent-one",
                client_assertion="jwt",
                expires_at="2026-01-02T03:09:05.500Z",
                issued_at="2026-01-02T03:04:05Z",
                jti="one",
                service_did=SERVICE_DID,
            ),
            "application/aep+json",
        ),
        PlatformResult(
            202,
            ProblemDetails(type="urn:aep:error:x", title="x", status=202, code="x"),
            "application/problem+json",
        ),
        PlatformResult(
            200,
            PlatformSignCompleted(
                status="completed",
                agent_did="did:web:wrong",
                client_assertion="jwt",
                expires_at="2026-01-02T03:09:05Z",
                issued_at="2026-01-02T03:04:05Z",
                jti="one",
                service_did=SERVICE_DID,
            ),
            "application/aep+json",
        ),
    )
    for index, result in enumerate(cases):

        async def handler(*_: Any, selected: PlatformResult[Any] = result) -> PlatformResult[Any]:
            return selected

        platform = Platform(options(sign_handler=handler))
        identity_id, _ = await provisioned(platform)
        with pytest.raises(ValueError):
            await platform.sign(
                identity_id,
                PlatformSignRequest(
                    jti="one", op=AssertionOperation.STATUS, service_did=SERVICE_DID
                ),
                context(f"sign-{index}"),
            )


@pytest.mark.asyncio
async def test_sign_handler_optional_and_completed_fields() -> None:
    received: list[PlatformSignRequest] = []

    async def unhandled(*_: Any) -> None:
        request = _[0].request
        received.append(request)
        if request.platform_context is not None:
            request.platform_context["changed"] = True
        return None

    platform = Platform(options(sign_handler=unhandled))
    identity_id, _ = await provisioned(platform)
    authenticated = await platform.sign(
        identity_id,
        PlatformSignRequest(
            jti="auth",
            lifetime_seconds="30",
            op=AssertionOperation.AUTHENTICATE,
            platform_context={"handle": "opaque"},
            resource="https://service.example/private",
            service_did=SERVICE_DID,
        ),
        context("auth"),
    )
    assert isinstance(authenticated.body, PlatformSignCompleted)
    assert authenticated.body.platform_context == {"handle": "opaque"}
    assert received[0].platform_context == {"changed": True, "handle": "opaque"}

    good = PlatformSignCompleted(
        status="completed",
        agent_did=authenticated.body.agent_did,
        client_assertion="jwt",
        expires_at="2026-01-02T03:04:35Z",
        issued_at="2026-01-02T03:04:05Z",
        jti="custom",
        service_did=SERVICE_DID,
    )

    async def completed(*_: Any) -> PlatformResult[Any]:
        return PlatformResult(200, good, "application/aep+json")

    custom = Platform(options(sign_handler=completed))
    custom_id, _ = await provisioned(custom)
    result = await custom.sign(
        custom_id,
        PlatformSignRequest(
            jti="custom",
            lifetime_seconds="30",
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
        ),
        context("custom"),
    )
    assert isinstance(result.body, PlatformSignCompleted)
    assert result.body.jti == "custom"


@pytest.mark.asyncio
async def test_idempotency_store_must_supply_response() -> None:
    class EmptyStore:
        async def execute(
            self, value: PlatformIdempotencyInput, operation: Any
        ) -> PlatformIdempotencyResult:
            return PlatformIdempotencyResult(None, PlatformIdempotencyState.CREATED)

    platform = Platform(options(idempotency_store=EmptyStore()))
    with pytest.raises(ValueError, match="no response"):
        await platform.provision(PlatformProvisionRequest(service_did=SERVICE_DID), context())


@pytest.mark.asyncio
async def test_hosted_verification_rejects_unrecognized_assertions() -> None:
    keys = KeyStore()
    discovery = replace(options().discovery, hosted_verification_endpoint="/verify")
    authorizer = AllowAuthorizer()
    platform = Platform(
        options(
            authorizer=authorizer,
            discovery=discovery,
            hosted_verification=True,
            key_store=keys,
            replay_store=MemoryReplayStore(),
        )
    )
    identity_id, _ = await provisioned(platform)
    signed = await platform.sign(
        identity_id,
        PlatformSignRequest(jti="one", op=AssertionOperation.STATUS, service_did=SERVICE_DID),
        context("sign"),
    )
    assert isinstance(signed.body, PlatformSignCompleted)
    assertion = signed.body.client_assertion
    wrong_principal = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=assertion, op=AssertionOperation.STATUS, service_did=SERVICE_DID
        ),
        context("verify-one", principal="other"),
    )
    assert isinstance(wrong_principal.body, PlatformVerificationResponse)
    assert wrong_principal.body.verified is False
    authorizer.allowed = False
    denied = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=assertion, op=AssertionOperation.STATUS, service_did=SERVICE_DID
        ),
        context("verify-two"),
    )
    assert isinstance(denied.body, PlatformVerificationResponse)
    assert denied.body.verified is False

    authorizer.allowed = True
    assertion = signed.body.client_assertion
    encoded_header, encoded_payload, signature = assertion.split(".")
    first = "A" if signature[0] != "A" else "B"
    wrong_key_assertion = f"{encoded_header}.{encoded_payload}.{first}{signature[1:]}"
    invalid_signature = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=wrong_key_assertion,
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
        ),
        context("verify-three"),
    )
    assert isinstance(invalid_signature.body, PlatformVerificationResponse)
    assert invalid_signature.body.verified is False

    header, _, signature = signed.body.client_assertion.split(".")
    import base64
    import json

    bad_payload = (
        base64.urlsafe_b64encode(json.dumps({"iss": 1, "sub": 1}).encode()).rstrip(b"=").decode()
    )
    malformed_identity = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=f"{header}.{bad_payload}.{signature}",
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
        ),
        context("verify-four"),
    )
    assert isinstance(malformed_identity.body, PlatformVerificationResponse)
    assert malformed_identity.body.verified is False

    with pytest.raises(ValueError, match="offset-aware"):
        await platform.sign(
            identity_id,
            PlatformSignRequest(
                jti="naive",
                op=AssertionOperation.STATUS,
                service_did=SERVICE_DID,
            ),
            replace(context("naive"), current_time=NOW.replace(tzinfo=None)),
        )
