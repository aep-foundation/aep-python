from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from agent_enrollment_protocol.core import (
    AssertionOperation,
    ClientAssertionClaims,
    ManagedAgentStatus,
    PlatformAgentIdentity,
    PlatformAgentIdentityListResponse,
    PlatformDiscoveryDocument,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignCompleted,
    PlatformSignPending,
    PlatformSignRequest,
    PlatformVerificationRequest,
    PlatformVerificationResponse,
    SigningAlgorithm,
    sign_client_assertion,
)
from agent_enrollment_protocol.platform import (
    AuthorizationRequest,
    DidVerificationMethod,
    DiscoveryOptions,
    IdentityListQuery,
    IdentityRecord,
    MemoryIdentityStore,
    MemoryReplayStore,
    Platform,
    PlatformOptions,
    PlatformResult,
    RequestContext,
)

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
SERVICE_DID = "did:web:service.example"


class AllowAuthorizer:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.requests: list[AuthorizationRequest] = []

    async def authorize(self, request: AuthorizationRequest, context: RequestContext) -> bool:
        self.requests.append(request)
        return self.allowed


class Resolver:
    def __init__(self, resolved: bool = True) -> None:
        self.resolved = resolved

    async def resolve(self, service_did: str) -> bool:
        return self.resolved and service_did == SERVICE_DID


class KeyStore:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.created: list[IdentityRecord] = []

    async def create_key(self, identity: IdentityRecord) -> None:
        self.created.append(identity)

    async def did_verification_method(self, identity: IdentityRecord) -> DidVerificationMethod:
        numbers = self.key.public_key().public_numbers()
        size = (self.key.key_size + 7) // 8
        import base64

        def encode(value: int) -> str:
            return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()

        return DidVerificationMethod(
            controller=identity.agent_did,
            id=identity.key_id,
            public_key_jwk={
                "crv": "P-256",
                "kty": "EC",
                "x": encode(numbers.x),
                "y": encode(numbers.y),
            },
            type="JsonWebKey2020",
        )

    async def sign(self, identity: IdentityRecord, claims: ClientAssertionClaims) -> str:
        return sign_client_assertion(
            claims,
            key=self.key,
            algorithm=SigningAlgorithm.ES256,
            key_id=identity.key_id,
        )

    async def verification_key(self, identity: IdentityRecord) -> Any:
        del identity
        return self.key.public_key()


def options(**changes: Any) -> PlatformOptions:
    values: dict[str, Any] = {
        "agent_did_id_generator": lambda: "agent-one",
        "authorizer": AllowAuthorizer(),
        "clock": lambda: NOW,
        "did_host": "platform.example",
        "did_path_prefix": "agents",
        "did_url_template": "https://platform.example/agents/{agent_did_id}/did.json",
        "discovery": DiscoveryOptions(
            endpoint_base="/v1/aep",
            lifecycle_endpoint="/v1/aep/agent-identities/{agent_identity_id}",
            list_endpoint="/v1/aep/agent-identities",
            platform_name="Example Platform",
            provision_endpoint="/v1/aep/agent-identities",
            sign_endpoint="/v1/aep/agent-identities/{agent_identity_id}/sign",
        ),
        "identifier": lambda: "identity-one",
        "key_store": KeyStore(),
        "service_did_resolver": Resolver(),
        "signing_algorithms": (SigningAlgorithm.ES256,),
    }
    values.update(changes)
    return PlatformOptions(**values)


def context(key: str | None = "key-one", principal: str = "owner-one") -> RequestContext:
    return RequestContext(principal=principal, idempotency_key=key, current_time=NOW)


async def provisioned(platform: Platform) -> tuple[str, str]:
    result = await platform.provision(PlatformProvisionRequest(service_did=SERVICE_DID), context())
    assert result.status == 200
    body = result.body
    assert isinstance(body, PlatformAgentIdentity)
    return body.agent_identity_id, body.agent_did


@pytest.mark.asyncio
async def test_platform_happy_path() -> None:
    keys = KeyStore()
    platform = Platform(options(key_store=keys))
    discovery = platform.discovery()
    assert discovery.status == 200
    assert discovery.headers["Cache-Control"] == "max-age=300"
    assert isinstance(discovery.body, PlatformDiscoveryDocument)
    assert discovery.body.platform.name == "Example Platform"

    identity_id, agent_did = await provisioned(platform)
    repeated = await platform.provision(
        PlatformProvisionRequest(service_did=SERVICE_DID), context()
    )
    assert isinstance(repeated.body, PlatformAgentIdentity)
    assert repeated.body.agent_identity_id == identity_id
    assert len(keys.created) == 1

    listed = await platform.list(IdentityListQuery(limit=0), context(key=None))
    assert isinstance(listed.body, PlatformAgentIdentityListResponse)
    assert listed.body.count == "1"
    fetched = await platform.get_identity(identity_id, context(key=None))
    assert isinstance(fetched.body, PlatformAgentIdentity)
    assert fetched.body.agent_did == agent_did

    document = await platform.did_document("agent-one")
    assert document.content_type == "application/did+json"
    assert isinstance(document.body, dict)
    assert document.body["id"] == agent_did

    signed = await platform.sign(
        identity_id,
        PlatformSignRequest(jti="jti-one", op=AssertionOperation.ENROLL, service_did=SERVICE_DID),
        context("sign-one"),
    )
    assert signed.status == 200
    assert isinstance(signed.body, PlatformSignCompleted)
    assert signed.body.agent_did == agent_did

    suspended = await platform.update_identity(
        identity_id,
        PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
        context(key=None),
    )
    assert isinstance(suspended.body, PlatformAgentIdentity)
    assert suspended.body.status is ManagedAgentStatus.SUSPENDED
    blocked = await platform.sign(
        identity_id,
        PlatformSignRequest(jti="jti-two", op=AssertionOperation.STATUS, service_did=SERVICE_DID),
        context("sign-two"),
    )
    assert blocked.status == 403
    assert blocked.problem is not None
    assert blocked.problem.code == "identity_suspended"
    assert (await platform.did_document("agent-one")).status == 404


@pytest.mark.asyncio
async def test_hosted_verification_and_replay() -> None:
    keys = KeyStore()
    replay = MemoryReplayStore()
    discovery = replace(
        options().discovery,
        hosted_verification_endpoint="/v1/aep/verifications",
    )
    platform = Platform(
        options(
            discovery=discovery,
            hosted_verification=True,
            key_store=keys,
            replay_store=replay,
        )
    )
    identity_id, _ = await provisioned(platform)
    signed = await platform.sign(
        identity_id,
        PlatformSignRequest(
            jti="verify-one", op=AssertionOperation.ENROLL, service_did=SERVICE_DID
        ),
        context("sign-one"),
    )
    assert isinstance(signed.body, PlatformSignCompleted)
    assertion = signed.body.client_assertion
    request = PlatformVerificationRequest(
        client_assertion=assertion,
        op=AssertionOperation.ENROLL,
        service_did=SERVICE_DID,
    )
    verified = await platform.verify(request, context("verify-one"))
    assert isinstance(verified.body, PlatformVerificationResponse)
    assert verified.body.verified is True
    replayed = await platform.verify(request, context("verify-two"))
    assert isinstance(replayed.body, PlatformVerificationResponse)
    assert replayed.body.verified is False
    malformed = await platform.verify(
        PlatformVerificationRequest(
            client_assertion="bad.token.value",
            op=AssertionOperation.ENROLL,
            service_did=SERVICE_DID,
        ),
        context("verify-three"),
    )
    assert isinstance(malformed.body, PlatformVerificationResponse)
    assert malformed.body.reason == "not_recognized"

    later = await platform.sign(
        identity_id,
        PlatformSignRequest(
            jti="verify-later",
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
        ),
        context("sign-later"),
    )
    assert isinstance(later.body, PlatformSignCompleted)
    await platform.update_identity(
        identity_id,
        PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
        context(key=None),
    )
    inactive = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=later.body.client_assertion,
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
        ),
        context("verify-inactive"),
    )
    assert isinstance(inactive.body, PlatformVerificationResponse)
    assert inactive.body.verified is False


@pytest.mark.asyncio
async def test_authorization_and_request_failures() -> None:
    denied = Platform(options(authorizer=AllowAuthorizer(False)))
    request = PlatformProvisionRequest(service_did=SERVICE_DID)
    assert (await denied.provision(request, context())).status == 404
    assert (await denied.provision(request, context(key=None))).status == 400

    unresolved = Platform(options(service_did_resolver=Resolver(False)))
    assert (await unresolved.provision(request, context())).status == 400

    platform = Platform(options())
    identity_id, _ = await provisioned(platform)
    assert (await platform.get_identity("missing", context(key=None))).status == 404
    assert (
        await platform.get_identity(identity_id, context(key=None, principal="other"))
    ).status == 404
    assert (await platform.list(IdentityListQuery(limit=101), context(key=None))).status == 400
    assert (
        await platform.list(IdentityListQuery(service_did="bad"), context(key=None))
    ).status == 400
    assert (await platform.list(IdentityListQuery(), context(key=None, principal=""))).status == 404

    conflict = await platform.provision(
        PlatformProvisionRequest(service_did="did:web:other.example"), context()
    )
    assert conflict.status == 409
    assert (
        await platform.verify(
            PlatformVerificationRequest(
                client_assertion="a.b.c", op=AssertionOperation.STATUS, service_did=SERVICE_DID
            ),
            context("verify"),
        )
    ).status == 404


@pytest.mark.asyncio
async def test_custom_pending_signer_and_lifetime() -> None:
    async def pending(*_: Any) -> PlatformResult[Any]:
        return PlatformResult(
            202,
            PlatformSignPending(status="pending", retry_after_seconds="5"),
            "application/aep+json",
        )

    platform = Platform(
        options(
            default_lifetime=timedelta(seconds=60),
            sign_handler=pending,
            maximum_lifetime=timedelta(seconds=60),
        )
    )
    identity_id, _ = await provisioned(platform)
    result = await platform.sign(
        identity_id,
        PlatformSignRequest(
            jti="pending",
            lifetime_seconds="60",
            op=AssertionOperation.STATUS,
            service_did=SERVICE_DID,
        ),
        context("pending"),
    )
    assert result.status == 202
    with pytest.raises(ValueError, match="configured maximum"):
        await platform.sign(
            identity_id,
            PlatformSignRequest(
                jti="long",
                lifetime_seconds="61",
                op=AssertionOperation.STATUS,
                service_did=SERVICE_DID,
            ),
            context("long"),
        )


@pytest.mark.asyncio
async def test_identity_creation_is_coalesced() -> None:
    store = MemoryIdentityStore()
    calls = 0

    async def create() -> IdentityRecord:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return IdentityRecord(
            agent_did="did:web:platform.example:agent",
            agent_did_id="agent",
            agent_identity_id="pai_one",
            created_at=NOW,
            did_document_url="https://platform.example/agent/did.json",
            key_id="did:web:platform.example:agent",
            principal="owner",
            service_did=SERVICE_DID,
            signing_algorithms=(SigningAlgorithm.ES256,),
            status=ManagedAgentStatus.ACTIVE,
            updated_at=NOW,
        )

    results = await asyncio.gather(
        store.find_or_create("owner", SERVICE_DID, create),
        store.find_or_create("owner", SERVICE_DID, create),
    )
    assert calls == 1
    assert [created for _, created in results] == [True, False]
