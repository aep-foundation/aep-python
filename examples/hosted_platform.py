from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from typing import Any

import httpx
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
    did_web_document_url,
    sign_client_assertion,
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
    print("Discovery:", discovery.body.platform.name if discovery.body else "missing")

    provisioned = await platform.provision(
        PlatformProvisionRequest(service_did=SERVICE_DID), context
    )
    identity = provisioned.body
    if not isinstance(identity, PlatformAgentIdentity):
        raise RuntimeError("The Platform did not provision an Agent identity")
    print("Provision:", identity.agent_did)

    document = await platform.did_document("agent-one")
    if not isinstance(document.body, dict):
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
    if not isinstance(signed.body, PlatformSignCompleted):
        raise RuntimeError("The Platform did not return a signed assertion")
    print("Sign:", signed.body.agent_did, signed.body.jti)

    listed = await platform.list(
        IdentityListQuery(service_did=SERVICE_DID),
        RequestContext(principal="developer-one", current_time=datetime.now(UTC)),
    )
    print("List:", listed.body.count if listed.body else "missing", "identity")

    suspended = await platform.update_identity(
        identity.agent_identity_id,
        PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
        RequestContext(principal="developer-one", current_time=datetime.now(UTC)),
    )
    if not isinstance(suspended.body, PlatformAgentIdentity):
        raise RuntimeError("The Platform did not update the hosted identity")
    print("Lifecycle:", suspended.body.status.value)


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
