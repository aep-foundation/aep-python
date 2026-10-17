from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agent_enrollment_protocol.core import (
    AssertionOperation,
    ClientAssertionClaims,
    ManagedAgentStatus,
    PlatformAgentIdentity,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignCompleted,
    PlatformSignRequest,
    SigningAlgorithm,
    VerifyClientAssertionOptions,
    did_web_document_url,
    select_did_web_public_jwk,
    sign_client_assertion,
    verify_client_assertion,
)
from agent_enrollment_protocol.platform import (
    AuthorizationRequest,
    DidVerificationMethod,
    DiscoveryOptions,
    IdentityListQuery,
    IdentityRecord,
    Platform,
    PlatformOptions,
    RequestContext,
)

SERVICE_DID = "did:web:service.example"


class AllowAuthenticatedCaller:
    async def authorize(self, request: AuthorizationRequest, context: RequestContext) -> bool:
        del request
        return bool(context.principal)


class DidWebServiceResolver:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def resolve(self, service_did: str) -> bool:
        try:
            response = await self._client.get(did_web_document_url(service_did))
            response.raise_for_status()
            document = response.json()
        except (httpx.HTTPError, ValueError):
            return False
        return isinstance(document, dict) and document.get("id") == service_did


class EphemeralKeyStore:
    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePrivateKey] = {}

    async def create_key(self, identity: IdentityRecord) -> None:
        self._keys[identity.agent_identity_id] = ec.generate_private_key(ec.SECP256R1())

    async def did_verification_method(self, identity: IdentityRecord) -> DidVerificationMethod:
        key = self._key(identity).public_key()
        numbers = key.public_numbers()
        size = (key.key_size + 7) // 8

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
            key=self._key(identity),
            algorithm=SigningAlgorithm.ES256,
            key_id=identity.key_id,
        )

    async def verification_key(self, identity: IdentityRecord) -> Any:
        return self._key(identity).public_key()

    def _key(self, identity: IdentityRecord) -> ec.EllipticCurvePrivateKey:
        try:
            return self._keys[identity.agent_identity_id]
        except KeyError as error:
            raise ValueError("The hosted identity has no signing key") from error


async def run(client: httpx.AsyncClient) -> None:
    # These fixed identifiers and permissive authorizer serve one local caller. Production
    # routes authenticate callers and supply their identity and permissions to the Platform.
    platform = Platform(
        PlatformOptions(
            agent_did_id_generator=lambda: "agent-one",
            authorizer=AllowAuthenticatedCaller(),
            did_host="platform.example",
            did_path_prefix="agents",
            did_url_template="https://platform.example/agents/{agent_did_id}/did.json",
            discovery=DiscoveryOptions(
                endpoint_base="/v1/aep",
                lifecycle_endpoint="/v1/aep/agent-identities/{agent_identity_id}",
                list_endpoint="/v1/aep/agent-identities",
                platform_name="Example Platform",
                provision_endpoint="/v1/aep/agent-identities",
                sign_endpoint="/v1/aep/agent-identities/{agent_identity_id}/sign",
            ),
            identifier=lambda: "identity-one",
            key_store=EphemeralKeyStore(),
            service_did_resolver=DidWebServiceResolver(client),
            signing_algorithms=(SigningAlgorithm.ES256,),
        )
    )
    context = RequestContext(
        principal="developer-one",
        idempotency_key="provision-one",
        current_time=datetime.now(UTC),
    )

    discovery = platform.discovery()
    if discovery.status != 200 or discovery.body is None:
        raise RuntimeError("The Platform did not return discovery metadata")
    print("Discovery:", discovery.body.platform.name)

    provisioned = await platform.provision(
        PlatformProvisionRequest(service_did=SERVICE_DID), context
    )
    identity = provisioned.body
    if provisioned.status != 200 or not isinstance(identity, PlatformAgentIdentity):
        raise RuntimeError("The Platform did not provision an Agent identity")
    print("Provision:", identity.agent_did)

    document = await platform.did_document("agent-one")
    if (
        document.status != 200
        or not isinstance(document.body, dict)
        or document.body.get("id") != identity.agent_did
    ):
        raise RuntimeError("The Platform did not publish a DID document")
    print("DID document:", document.body["id"])

    signed = await platform.sign(
        identity.agent_identity_id,
        PlatformSignRequest(
            jti="assertion-one",
            op=AssertionOperation.ENROLL,
            service_did=SERVICE_DID,
        ),
        RequestContext(
            principal="developer-one",
            idempotency_key="sign-one",
            current_time=datetime.now(UTC),
        ),
    )
    if signed.status != 200 or not isinstance(signed.body, PlatformSignCompleted):
        raise RuntimeError("The Platform did not return a signed assertion")
    # Verify with the published public key, not the key store's private signing key.
    public_jwk = select_did_web_public_jwk(
        document.body, did=identity.agent_did, key_id=identity.key_id
    )
    verified = verify_client_assertion(
        signed.body.client_assertion,
        key=jwt.PyJWK.from_dict(public_jwk).key,
        options=VerifyClientAssertionOptions(
            audience=SERVICE_DID,
            issuer=identity.agent_did,
            subject=identity.agent_did,
            operation=AssertionOperation.ENROLL,
        ),
    )
    if verified.jti != signed.body.jti:
        raise RuntimeError("The signed assertion does not match its public metadata")
    print("Sign:", signed.body.agent_did, signed.body.jti)

    listed = await platform.list(
        IdentityListQuery(service_did=SERVICE_DID),
        RequestContext(principal="developer-one", current_time=datetime.now(UTC)),
    )
    if (
        listed.status != 200
        or listed.body is None
        or listed.body.count != "1"
        or len(listed.body.data) != 1
        or listed.body.data[0].agent_identity_id != identity.agent_identity_id
    ):
        raise RuntimeError("The Platform did not list the provisioned identity")
    print("List:", listed.body.count, "identity")

    suspended = await platform.update_identity(
        identity.agent_identity_id,
        PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
        RequestContext(principal="developer-one", current_time=datetime.now(UTC)),
    )
    if (
        suspended.status != 200
        or not isinstance(suspended.body, PlatformAgentIdentity)
        or suspended.body.status is not ManagedAgentStatus.SUSPENDED
    ):
        raise RuntimeError("The Platform did not update the hosted identity")
    print("Lifecycle:", suspended.body.status.value)
    refused = await platform.sign(
        identity.agent_identity_id,
        PlatformSignRequest(
            jti="assertion-after-suspension", op=AssertionOperation.ENROLL, service_did=SERVICE_DID
        ),
        RequestContext(
            principal="developer-one",
            idempotency_key="sign-after-suspension",
            current_time=datetime.now(UTC),
        ),
    )
    if (
        refused.status != 403
        or refused.problem is None
        or refused.problem.code != "identity_suspended"
    ):
        raise RuntimeError("The suspended identity was not refused for signing")
    print("Suspended signing:", refused.status, refused.problem.code)


async def main() -> None:
    def resolve_service_did(request: httpx.Request) -> httpx.Response:
        if str(request.url) != did_web_document_url(SERVICE_DID):
            return httpx.Response(404)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/did+json"},
            json={"@context": ["https://www.w3.org/ns/did/v1"], "id": SERVICE_DID},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(resolve_service_did)) as client:
        await run(client)


if __name__ == "__main__":
    asyncio.run(main())
