from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, cast

import pytest

from agent_enrollment_protocol.core import (
    AssertionOperation,
    ClientAssertionClaims,
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
    did_web_document_url,
    sign_client_assertion,
)
from agent_enrollment_protocol.platform import (
    AuthorizationOperation,
    AuthorizationRequest,
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
    SignHandlerInput,
    StoredResponse,
    create_did_document,
    create_service_scoped_agent_did,
)
from agent_enrollment_protocol.platform.document import create_discovery_document, render_did_url
from agent_enrollment_protocol.platform.platform import _lifecycle_error
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


@pytest.mark.parametrize(
    "jwk",
    [
        {"crv": "P-256", "d": "private", "kty": "EC", "x": "AQ", "y": "AQ"},
        {"crv": "Ed25519", "d": "private", "kty": "OKP", "x": "AQ"},
        {"kty": "RSA", "n": "AQ", "e": "AQ", "p": "private"},
        {"kty": "RSA", "n": "AQ", "e": "AQ", "qi": "private"},
        {"k": "symmetric", "kty": "oct"},
    ],
)
def test_did_document_refuses_private_key_material(jwk: dict[str, str]) -> None:
    # PLT-DID-002: the DID document is served to anyone who resolves the Agent DID, so a key store
    # that returned a JWK still carrying its private members would publish the signing key itself.
    identity = record()
    method = DidVerificationMethod(
        controller=identity.agent_did,
        id=identity.key_id,
        public_key_jwk=jwk,
        type="JsonWebKey2020",
    )
    with pytest.raises(ValueError, match="only public key material"):
        create_did_document(identity, method)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (ManagedAgentStatus.TERMINATED, "identity_terminated"),
        (ManagedAgentStatus.SUSPENDED, "identity_suspended"),
        (ManagedAgentStatus.REVOKED, "identity_suspended"),
        (ManagedAgentStatus.ACTIVE, "identity_unavailable"),
    ],
)
def test_lifecycle_errors_use_registered_codes(status: ManagedAgentStatus, code: str) -> None:
    # CORE-ERR-009 registers identity_suspended, identity_terminated and identity_unavailable, and
    # no identity_revoked or identity_active, so a revoked identity reports the suspended code.
    assert _lifecycle_error(status) == code


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


@pytest.mark.parametrize(
    "template",
    [
        "https://other.example/agents/{agent_did_id}/did.json",
        "https://platform.example/other/{agent_did_id}/did.json",
        "https://platform.example/agents/{agent_did_id}/key.json",
    ],
)
def test_platform_rejects_did_templates_that_do_not_resolve_the_minted_did(template: str) -> None:
    with pytest.raises(ValueError, match="must match"):
        Platform(options(did_url_template=template))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host,prefix", [("platform.example", "a/b"), ("platform.example:8443", "")]
)
async def test_custom_did_configuration_matches_ordinary_resolution(host: str, prefix: str) -> None:
    path = f"{prefix}/" if prefix else ""
    platform = Platform(
        options(
            did_host=host,
            did_path_prefix=prefix,
            did_url_template=f"https://{host}/{path}{{agent_did_id}}/did.json",
        )
    )
    identity_id, did = await provisioned(platform)
    identity = await platform.get_identity(identity_id, context(key=None))
    assert identity.body is not None
    assert identity.body.did_document_url == did_web_document_url(did)
    document = await platform.did_document("agent-one")
    assert document.body is not None and document.body["id"] == did


@pytest.mark.asyncio
async def test_cached_private_results_reauthorize_without_repeating_operations() -> None:
    class CountedKeys(KeyStore):
        def __init__(self) -> None:
            super().__init__()
            self.signatures = 0

        async def sign(self, identity: IdentityRecord, claims: ClientAssertionClaims) -> str:
            self.signatures += 1
            return await super().sign(identity, claims)

    authorizer = AllowAuthorizer()
    keys = CountedKeys()
    current = [NOW]
    platform = Platform(
        options(
            authorizer=authorizer,
            key_store=keys,
            clock=lambda: current[0],
            discovery=replace(options().discovery, hosted_verification_endpoint="/verify"),
            hosted_verification=True,
            replay_store=MemoryReplayStore(),
        )
    )
    provision_request = PlatformProvisionRequest(service_did=SERVICE_DID)
    provision_context = context("provision")
    provision_result = await platform.provision(provision_request, provision_context)
    assert provision_result.body is not None
    identity_id = provision_result.body.agent_identity_id
    sign_request = PlatformSignRequest(
        jti="cached", op=AssertionOperation.STATUS, service_did=SERVICE_DID
    )
    sign_context = context("sign")
    sign_result = await platform.sign(identity_id, sign_request, sign_context)
    assert isinstance(sign_result.body, PlatformSignCompleted)
    verify_request = PlatformVerificationRequest(
        client_assertion=sign_result.body.client_assertion,
        op=AssertionOperation.STATUS,
        service_did=SERVICE_DID,
    )
    verify_context = context("verify")
    verify_result = await platform.verify(verify_request, verify_context)
    assert verify_result.body is not None and verify_result.body.verified
    before = len(authorizer.requests)
    assert await platform.provision(provision_request, provision_context) == provision_result
    assert await platform.sign(identity_id, sign_request, sign_context) == sign_result
    assert await platform.verify(verify_request, verify_context) == verify_result
    assert len(authorizer.requests) == before + 3

    authorizer.allowed = False
    before = len(authorizer.requests)
    assert (await platform.provision(provision_request, provision_context)).status == 404
    assert (await platform.sign(identity_id, sign_request, sign_context)).status == 404
    denied = await platform.verify(verify_request, verify_context)
    assert denied.body is not None
    assert denied.body.to_wire() == {
        "reason": "not_recognized",
        "service_did": SERVICE_DID,
        "verified": False,
    }
    assert len(authorizer.requests) == before + 3

    authorizer.allowed = True
    current[0] += timedelta(minutes=10)
    await platform.update_identity(
        identity_id,
        PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
        context(key=None),
    )
    assert await platform.provision(provision_request, provision_context) == provision_result
    assert await platform.sign(identity_id, sign_request, sign_context) == sign_result
    assert await platform.verify(verify_request, verify_context) == verify_result
    assert keys.signatures == 1 and len(keys.created) == 1
    fresh = await platform.sign(identity_id, sign_request, context("fresh"))
    assert fresh.status == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [{"principal": ""}, {"idempotency_key": None}])
async def test_private_sign_and_verify_require_authenticated_retry_context(
    missing: dict[str, Any],
) -> None:
    platform = Platform(
        options(
            discovery=replace(options().discovery, hosted_verification_endpoint="/verify"),
            hosted_verification=True,
            replay_store=MemoryReplayStore(),
        )
    )
    identity_id, _ = await provisioned(platform)
    caller = replace(context("missing"), **missing)
    signed = await platform.sign(
        identity_id,
        PlatformSignRequest(jti="missing", op=AssertionOperation.STATUS, service_did=SERVICE_DID),
        caller,
    )
    verified = await platform.verify(
        PlatformVerificationRequest(
            client_assertion="a.b.c", op=AssertionOperation.STATUS, service_did=SERVICE_DID
        ),
        caller,
    )
    assert signed.status == verified.status == 400
    assert signed.problem is not None and signed.problem.code == "invalid_request"
    assert verified.problem is not None and verified.problem.code == "invalid_request"


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

    for change in ({"identifier": lambda: ""}, {"agent_did_id_generator": lambda: ""}):
        invalid = Platform(options(**change))
        with pytest.raises(ValueError):
            await invalid.provision(
                PlatformProvisionRequest(service_did=SERVICE_DID), context("invalid")
            )

    # The Discovery Last-Modified validator is stamped when the document is built, so a clock that
    # cannot produce one is refused at construction rather than at the first command.
    with pytest.raises(ValueError, match="offset-aware"):
        Platform(options(clock=lambda: NOW.replace(tzinfo=None)))

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

    class MismatchedLookupStore(MemoryIdentityStore):
        async def get(self, agent_identity_id: str) -> IdentityRecord | None:
            del agent_identity_id
            return replace(record(), agent_identity_id="pai_other", principal="owner-one")

        async def find_by_agent_did_id(self, agent_did_id: str) -> IdentityRecord | None:
            del agent_did_id
            return replace(record(), agent_did_id="other")

    mismatched_lookup = Platform(options(identity_store=MismatchedLookupStore()))
    with pytest.raises(ValueError, match="mismatched"):
        await mismatched_lookup.get_identity("pai_one", context(key=None))
    with pytest.raises(ValueError, match="mismatched"):
        await mismatched_lookup.did_document("one")

    class MismatchedUpdateStore(MemoryIdentityStore):
        async def update_status(
            self,
            agent_identity_id: str,
            status: ManagedAgentStatus,
            updated_at: datetime,
        ) -> IdentityRecord | None:
            updated = await super().update_status(agent_identity_id, status, updated_at)
            return None if updated is None else replace(updated, service_did="did:web:other")

    mismatched_update = Platform(options(identity_store=MismatchedUpdateStore()))
    update_id, _ = await provisioned(mismatched_update)
    with pytest.raises(ValueError, match="mismatched"):
        await mismatched_update.update_identity(
            update_id,
            PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
            context(key=None),
        )

    class InvalidListStore(MemoryIdentityStore):
        async def list(self, principal: str, query: IdentityListQuery) -> IdentityListResult:
            del principal, query
            item = replace(record(), principal="owner-one")
            return IdentityListResult((item, item), 1)

    invalid_list = Platform(options(identity_store=InvalidListStore()))
    with pytest.raises(ValueError, match="invalid list"):
        await invalid_list.list(IdentityListQuery(), context(key=None))

    class MalformedListStore(MemoryIdentityStore):
        async def list(self, principal: str, query: IdentityListQuery) -> IdentityListResult:
            del principal, query
            item = replace(record(), created_at=NOW.replace(tzinfo=None), principal="owner-one")
            return IdentityListResult((item,), 1)

    malformed_list = Platform(options(identity_store=MalformedListStore()))
    with pytest.raises(ValueError, match="unauthorized"):
        await malformed_list.list(IdentityListQuery(), context(key=None))


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [-86400, 0, 86400])
@pytest.mark.parametrize("lowercase", [False, True])
async def test_custom_signing_timestamps_use_core_parsing_and_the_platform_clock(
    offset: int, lowercase: bool
) -> None:
    keys = KeyStore()

    async def handler(value: SignHandlerInput, caller: RequestContext) -> PlatformResult[Any]:
        result = await _completed_sign_result(keys, value, NOW + timedelta(seconds=offset))
        if lowercase:
            assert result.body is not None
            return replace(
                result,
                body=result.body.model_copy(
                    update={
                        "issued_at": result.body.issued_at.lower(),
                        "expires_at": result.body.expires_at.lower(),
                    }
                ),
            )
        return result

    platform = Platform(options(key_store=keys, sign_handler=handler))
    identity_id, _ = await provisioned(platform)
    request = PlatformSignRequest(
        jti="custom-time",
        op=AssertionOperation.STATUS,
        service_did=SERVICE_DID,
        lifetime_seconds="30",
    )
    if offset:
        with pytest.raises(ValueError, match="invalid client assertion"):
            await platform.sign(identity_id, request, context("custom-time"))
    else:
        result = await platform.sign(identity_id, request, context("custom-time"))
        assert result.status == 200 and isinstance(result.body, PlatformSignCompleted)
        assert result.body.issued_at == (
            "2026-01-02t03:04:05z" if lowercase else "2026-01-02T03:04:05Z"
        )


async def _completed_sign_result(
    keys: KeyStore, value: SignHandlerInput, issued: datetime
) -> PlatformResult[PlatformSignCompleted]:
    claims = ClientAssertionClaims(
        aud=SERVICE_DID,
        exp=int(issued.timestamp()) + 30,
        iat=int(issued.timestamp()),
        iss=value.identity.agent_did,
        sub=value.identity.agent_did,
        jti=value.request.jti,
        op=value.request.op,
    )
    return PlatformResult(
        200,
        PlatformSignCompleted(
            status="completed",
            agent_did=value.identity.agent_did,
            client_assertion=await keys.sign(value.identity, claims),
            expires_at=(issued + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            jti=value.request.jti,
            service_did=SERVICE_DID,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("handled", [False, True])
async def test_signing_uses_the_platform_clock_after_the_custom_handler(handled: bool) -> None:
    current = [NOW]
    keys = KeyStore()

    async def handler(
        value: SignHandlerInput, caller: RequestContext
    ) -> PlatformResult[PlatformSignCompleted] | None:
        current[0] += timedelta(seconds=2)
        return await _completed_sign_result(keys, value, current[0]) if handled else None

    platform = Platform(options(key_store=keys, sign_handler=handler, clock=lambda: current[0]))
    identity_id, _ = await provisioned(platform)
    result = await platform.sign(
        identity_id,
        PlatformSignRequest(
            jti="delayed",
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
            lifetime_seconds="30",
        ),
        replace(context("delayed"), current_time=None),
    )
    assert result.status == 200 and isinstance(result.body, PlatformSignCompleted)
    assert result.body.issued_at == "2026-01-02T03:04:07Z"


@pytest.mark.asyncio
@pytest.mark.parametrize("pending", [False, True])
@pytest.mark.parametrize(
    "content_type,headers,problem,accepted",
    [
        ("application/aep+json", {}, None, True),
        ("Application/Aep+Json; charset=utf-8", {"X-Request-ID": "one"}, None, True),
        ("text/plain", {}, None, False),
        ("application/aep+json", {"rEtRy-AfTeR": "300"}, None, False),
        (
            "application/aep+json",
            {},
            ProblemDetails(type="urn:aep:error:x", title="x", code="x", status=400),
            False,
        ),
    ],
)
async def test_custom_signing_response_metadata_matches_the_protocol(
    pending: bool,
    content_type: str,
    headers: dict[str, str],
    problem: ProblemDetails | None,
    accepted: bool,
) -> None:
    keys = KeyStore()

    async def handler(value: SignHandlerInput, caller: RequestContext) -> PlatformResult[Any]:
        result: PlatformResult[Any] = (
            PlatformResult(202, PlatformSignPending(status="pending", retry_after_seconds="5"))
            if pending
            else await _completed_sign_result(keys, value, NOW)
        )
        return replace(result, content_type=content_type, headers=headers, problem=problem)

    platform = Platform(options(key_store=keys, sign_handler=handler))
    identity_id, _ = await provisioned(platform)
    request = PlatformSignRequest(
        jti="metadata", op=AssertionOperation.STATUS, service_did=SERVICE_DID, lifetime_seconds="30"
    )
    if accepted:
        result = await platform.sign(identity_id, request, context("metadata"))
        assert result.status == (202 if pending else 200)
        assert result.headers == headers and result.content_type == content_type
        assert await platform.sign(identity_id, request, context("metadata")) == result
    else:
        with pytest.raises(ValueError, match="response must"):
            await platform.sign(identity_id, request, context("metadata"))


@pytest.mark.asyncio
async def test_sign_handler_validation() -> None:
    cases: tuple[PlatformResult[Any], ...] = (
        PlatformResult(200),
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

    keys = KeyStore()

    async def completed(value: Any, request_context: Any) -> PlatformResult[Any]:
        del request_context
        claims = ClientAssertionClaims(
            aud=SERVICE_DID,
            exp=int(NOW.timestamp()) + 30,
            iat=int(NOW.timestamp()),
            iss=value.identity.agent_did,
            jti="custom",
            op=AssertionOperation.STATUS,
            sub=value.identity.agent_did,
        )
        return PlatformResult(
            200,
            PlatformSignCompleted(
                status="completed",
                agent_did=value.identity.agent_did,
                client_assertion=await keys.sign(value.identity, claims),
                expires_at="2026-01-02T03:04:35Z",
                issued_at="2026-01-02T03:04:05Z",
                jti="custom",
                service_did=SERVICE_DID,
            ),
            "application/aep+json",
        )

    custom = Platform(options(key_store=keys, sign_handler=completed))
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

    class InvalidSigner(KeyStore):
        async def sign(self, identity: IdentityRecord, claims: ClientAssertionClaims) -> str:
            del identity, claims
            return "not-a-jwt"

    invalid_signer = Platform(options(key_store=InvalidSigner()))
    invalid_id, _ = await provisioned(invalid_signer)
    with pytest.raises(ValueError, match="invalid client assertion"):
        await invalid_signer.sign(
            invalid_id,
            PlatformSignRequest(
                jti="invalid", op=AssertionOperation.STATUS, service_did=SERVICE_DID
            ),
            context("invalid-signer"),
        )

    class MismatchedSigner(KeyStore):
        async def sign(self, identity: IdentityRecord, claims: ClientAssertionClaims) -> str:
            return await super().sign(identity, claims.model_copy(update={"jti": "other"}))

    mismatched_signer = Platform(options(key_store=MismatchedSigner()))
    signer_id, _ = await provisioned(mismatched_signer)
    with pytest.raises(ValueError, match="mismatched assertion claims"):
        await mismatched_signer.sign(
            signer_id,
            PlatformSignRequest(
                jti="mismatched", op=AssertionOperation.STATUS, service_did=SERVICE_DID
            ),
            context("mismatched-signer"),
        )


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
async def test_trusted_service_verification_does_not_grant_identity_management() -> None:
    class TrustedServiceAuthorizer:
        async def authorize(self, request: AuthorizationRequest, caller: RequestContext) -> bool:
            if request.operation is AuthorizationOperation.VERIFY:
                return caller.principal == "trusted-service"
            return bool(caller.principal)

    platform = Platform(
        options(
            authorizer=TrustedServiceAuthorizer(),
            discovery=replace(options().discovery, hosted_verification_endpoint="/verify"),
            hosted_verification=True,
            replay_store=MemoryReplayStore(),
        )
    )
    identity_id, agent_did = await provisioned(platform)
    sign_request = PlatformSignRequest(
        jti="trusted-service", op=AssertionOperation.STATUS, service_did=SERVICE_DID
    )
    signed = await platform.sign(identity_id, sign_request, context("sign"))
    assert isinstance(signed.body, PlatformSignCompleted)
    request = PlatformVerificationRequest(
        client_assertion=signed.body.client_assertion,
        op=AssertionOperation.STATUS,
        service_did=SERVICE_DID,
    )
    denied = await platform.verify(request, context("denied", principal="untrusted-service"))
    assert denied.body is not None
    assert denied.body.to_wire() == {
        "verified": False,
        "reason": "not_recognized",
        "service_did": SERVICE_DID,
    }
    caller = context("verify", principal="trusted-service")
    mismatched = await platform.verify(
        request.model_copy(update={"service_did": "did:web:other.example"}), caller
    )
    assert mismatched.body is not None and not mismatched.body.verified
    verified = await platform.verify(request, replace(caller, idempotency_key="valid"))
    assert verified.body is not None and verified.body.verified
    assert verified.body.agent_did == agent_did
    assert verified.body.agent_identity_id == identity_id
    replayed = await platform.verify(request, replace(caller, idempotency_key="replay"))
    assert replayed.body is not None and not replayed.body.verified
    anonymous = await platform.verify(request, replace(caller, principal=""))
    assert anonymous.status == 400

    assert (await platform.get_identity(identity_id, caller)).status == 404
    listed = await platform.list(IdentityListQuery(), caller)
    assert listed.status == 200
    assert listed.body is not None and listed.body.count == "0" and listed.body.total == "0"
    assert (
        await platform.sign(
            identity_id, sign_request, replace(caller, idempotency_key="cannot-sign")
        )
    ).status == 404
    assert (
        await platform.update_identity(
            identity_id,
            PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
            caller,
        )
    ).status == 404
    identity = await platform.get_identity(identity_id, context(key=None))
    assert identity.body is not None and identity.body.status is ManagedAgentStatus.ACTIVE


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
    authorizer.allowed = False
    wrong_principal = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=assertion, op=AssertionOperation.STATUS, service_did=SERVICE_DID
        ),
        context("verify-one", principal="other"),
    )
    assert isinstance(wrong_principal.body, PlatformVerificationResponse)
    assert wrong_principal.body.verified is False
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

    unknown_did = "did:web:platform.example:agents:unknown"
    unknown_assertion = sign_client_assertion(
        ClientAssertionClaims(
            aud=SERVICE_DID,
            exp=int(NOW.timestamp()) + 30,
            iat=int(NOW.timestamp()),
            iss=unknown_did,
            jti="unknown",
            op=AssertionOperation.STATUS,
            sub=unknown_did,
        ),
        key=keys.key,
        algorithm=SigningAlgorithm.ES256,
    )
    unknown = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=unknown_assertion,
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
        ),
        context("verify-unknown"),
    )
    assert isinstance(unknown.body, PlatformVerificationResponse)
    assert unknown.body.verified is False

    class MismatchedVerificationStore(MemoryIdentityStore):
        async def find_by_agent_did(self, agent_did: str) -> IdentityRecord | None:
            identity = await super().find_by_agent_did(agent_did)
            return (
                None
                if identity is None
                else replace(identity, agent_did="did:web:other", key_id="did:web:other")
            )

    mismatched_store = MismatchedVerificationStore()
    mismatched = Platform(
        options(
            discovery=discovery,
            hosted_verification=True,
            identity_store=mismatched_store,
            key_store=keys,
            replay_store=MemoryReplayStore(),
        )
    )
    mismatched_id, _ = await provisioned(mismatched)
    mismatched_signed = await mismatched.sign(
        mismatched_id,
        PlatformSignRequest(
            jti="mismatched", op=AssertionOperation.STATUS, service_did=SERVICE_DID
        ),
        context("mismatched-sign"),
    )
    assert isinstance(mismatched_signed.body, PlatformSignCompleted)
    with pytest.raises(ValueError, match="mismatched"):
        await mismatched.verify(
            PlatformVerificationRequest(
                client_assertion=mismatched_signed.body.client_assertion,
                op=AssertionOperation.STATUS,
                service_did=SERVICE_DID,
            ),
            context("mismatched-verify"),
        )

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
