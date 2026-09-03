from __future__ import annotations

import asyncio
import base64
import json
import secrets
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_enrollment_protocol.adapters import (
    AepAsgiApplication,
    AepAuthenticationMiddleware,
    AsgiReceive,
    AsgiScope,
    AsgiSend,
    principal_from_scope,
)
from agent_enrollment_protocol.agent import (
    Agent,
    AgentOptions,
    AssertionSigner,
    AuthenticationOptions,
    EnrollOptions,
    GrantOptions,
    HttpxTransport,
    IdentityRequest,
    RevokeOptions,
    ServiceIdentity,
)
from agent_enrollment_protocol.core import (
    AEP_AUTHENTICATION_METHOD_JWT,
    AEP_CLAIM_NAME_CONTACT_EMAIL,
    AEP_CLAIM_NAME_PERSON_FIRST_NAME,
    AEP_GRANT_TYPE_API_KEY,
    AEP_GRANT_TYPE_BASIC,
    AEP_GRANT_TYPE_OAUTH_BEARER,
    AEP_IDENTITY_METHOD_DID_WEB,
    AepAssertionError,
    ApiKeyGrantResponse,
    BasicGrantResponse,
    ClaimValues,
    ClientAssertionClaims,
    GrantRequest,
    GrantTypeConfig,
    InspectClaims,
    OAuthBearerGrantResponse,
    SigningAlgorithm,
    VerifyClientAssertionOptions,
    decode_jwt_unverified,
    did_web_document_url,
    select_did_web_public_jwk,
    sign_client_assertion,
    verify_client_assertion,
)
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    GrantContext,
    MemoryServiceCredentialStore,
    Service,
    ServiceOptions,
    StoredCredentialGrantTypeOptions,
    stored_api_key_grant_type,
    stored_basic_grant_type,
    stored_oauth_bearer_grant_type,
)

AGENT_DID = "did:web:agent.example"
SERVICE_DID = "did:web:service.example"
SERVICE_ORIGIN = "https://service.example"
RESOURCE = f"{SERVICE_ORIGIN}/account"


class LocalIdentityProvider:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
        return ServiceIdentity(
            agent_did=AGENT_DID,
            identity_method=AEP_IDENTITY_METHOD_DID_WEB,
            service_did=request.service_did,
            signing_algorithms=(SigningAlgorithm.EDDSA,),
        )

    async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
        async def sign(
            claims: ClientAssertionClaims, algorithms: tuple[SigningAlgorithm, ...]
        ) -> str:
            if SigningAlgorithm.EDDSA not in algorithms:
                raise ValueError("The Service does not accept the example signing algorithm")
            return sign_client_assertion(
                claims,
                key=self._key,
                algorithm=SigningAlgorithm.EDDSA,
                key_id=f"{identity.agent_did}#key-1",
            )

        return sign


class DidWebVerifier:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def verify(
        self, assertion: str, context: AssertionVerificationContext
    ) -> ClientAssertionClaims:
        try:
            header, payload = decode_jwt_unverified(assertion)
            issuer = payload.get("iss")
            key_id = header.get("kid")
            if not isinstance(issuer, str) or not isinstance(key_id, str):
                raise ValueError("The assertion does not identify a DID-web verification method")
            response = await self._client.get(did_web_document_url(issuer))
            response.raise_for_status()
            document = response.json()
            if not isinstance(document, dict) or document.get("id") != issuer:
                raise ValueError("The resolved DID document does not identify the assertion issuer")
            jwk = select_did_web_public_jwk(document, did=issuer, key_id=key_id)
            key = jwt.PyJWK.from_dict(jwk).key
        except (AepAssertionError, httpx.HTTPError, jwt.PyJWTError, ValueError) as error:
            raise AepAssertionError("Invalid AEP client assertion.") from error
        return verify_client_assertion(
            assertion,
            key=key,
            options=VerifyClientAssertionOptions(
                algorithms=context.algorithms,
                audience=context.service_did,
                issuer=issuer,
                subject=issuer,
                operation=context.operation,
                resource=context.resource,
                current_time=int(context.current_time.timestamp()),
                clock_tolerance_seconds=int(context.clock_tolerance.total_seconds()),
            ),
        )


async def protected_resource(scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
    del receive
    principal = principal_from_scope(scope)
    if principal is None:
        raise RuntimeError("The protected route requires an AEP principal")
    body = json.dumps(
        {
            "agent_did": principal.agent_did,
            "authentication_method": principal.authentication_method,
            "message": "Authenticated Service resource",
        },
        separators=(",", ":"),
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def agent_did_document(key: Ed25519PrivateKey) -> dict[str, Any]:
    key_id = f"{AGENT_DID}#key-1"
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    encoded = base64.urlsafe_b64encode(public_key).rstrip(b"=").decode()
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "assertionMethod": [key_id],
        "id": AGENT_DID,
        "verificationMethod": [
            {
                "controller": AGENT_DID,
                "id": key_id,
                "publicKeyJwk": {"crv": "Ed25519", "kty": "OKP", "x": encoded},
                "type": "JsonWebKey2020",
            }
        ],
    }


async def main() -> None:
    key = Ed25519PrivateKey.generate()
    credential_store = MemoryServiceCredentialStore()

    async def issue_api_key(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        return ApiKeyGrantResponse(
            api_key=secrets.token_urlsafe(24),
            credential_id=secrets.token_hex(16),
            expires_at=(context.current_time + timedelta(hours=1))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            header="X-Agent-Key",
            scopes=request.requested_scopes,
        )

    async def issue_basic(request: GrantRequest, context: GrantContext) -> BasicGrantResponse:
        return BasicGrantResponse(
            credential_id=secrets.token_hex(16),
            expires_at=(context.current_time + timedelta(hours=1))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            password=secrets.token_urlsafe(24),
            scopes=request.requested_scopes,
            username="example-agent",
        )

    async def issue_oauth(request: GrantRequest, context: GrantContext) -> OAuthBearerGrantResponse:
        return OAuthBearerGrantResponse(
            access_token=secrets.token_urlsafe(24),
            credential_id=secrets.token_hex(16),
            expires_at=(context.current_time + timedelta(hours=1))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            scopes=request.requested_scopes,
            token_type="Bearer",
        )

    grant_types = (
        stored_api_key_grant_type(
            StoredCredentialGrantTypeOptions(
                config=GrantTypeConfig.model_validate({"header_names": ["x-agent-key"]}),
                issue=issue_api_key,
                store=credential_store,
            )
        ),
        stored_basic_grant_type(
            StoredCredentialGrantTypeOptions(issue=issue_basic, store=credential_store)
        ),
        stored_oauth_bearer_grant_type(
            StoredCredentialGrantTypeOptions(issue=issue_oauth, store=credential_store)
        ),
    )

    def resolve_agent_did(request: httpx.Request) -> httpx.Response:
        if str(request.url) != did_web_document_url(AGENT_DID):
            return httpx.Response(404)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/did+json"},
            json=agent_did_document(key),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(resolve_agent_did)) as did_client:
        service = Service(
            ServiceOptions(
                service_did=SERVICE_DID,
                identity_methods=(AEP_IDENTITY_METHOD_DID_WEB,),
                verifier=DidWebVerifier(did_client),
                authentication_methods=(
                    AEP_GRANT_TYPE_API_KEY,
                    AEP_GRANT_TYPE_BASIC,
                    AEP_GRANT_TYPE_OAUTH_BEARER,
                    AEP_AUTHENTICATION_METHOD_JWT,
                ),
                claims=InspectClaims(
                    required=(AEP_CLAIM_NAME_CONTACT_EMAIL,),
                    preferred=(AEP_CLAIM_NAME_PERSON_FIRST_NAME,),
                ),
                grant_types=grant_types,
                inspect_url=f"{SERVICE_ORIGIN}/.well-known/aep",
            )
        )
        application = AepAsgiApplication(
            service,
            AepAuthenticationMiddleware(
                protected_resource,
                service,
                resource_origin=SERVICE_ORIGIN,
            ),
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url=SERVICE_ORIGIN,
        ) as client:
            transport = HttpxTransport(client)
            agent = Agent(
                AgentOptions(
                    identity_provider=LocalIdentityProvider(key),
                    command_transport=transport,
                    inspect_transport=transport,
                )
            )
            session = agent.service(SERVICE_ORIGIN)

            inspection = await session.inspect()
            print("Inspect:", ", ".join(inspection.document.commands.supported))

            enrollment = await session.enroll(
                EnrollOptions(
                    claims=ClaimValues.model_validate(
                        {
                            AEP_CLAIM_NAME_CONTACT_EMAIL: "agent@example.com",
                            AEP_CLAIM_NAME_PERSON_FIRST_NAME: "Example",
                        }
                    )
                )
            )
            print("Enroll:", enrollment.body.status.value)

            for grant_type in (
                AEP_GRANT_TYPE_API_KEY,
                AEP_GRANT_TYPE_BASIC,
                AEP_GRANT_TYPE_OAUTH_BEARER,
            ):
                grant = await session.grant(
                    GrantOptions(
                        grant_type=grant_type,
                        requested_scopes=("account:read",),
                    )
                )
                credential = grant.body.credential
                if credential is None:
                    raise RuntimeError(f"The Service did not return a {grant_type} credential")
                print("Grant:", grant.body.grant_type, credential.credential_id)

                headers: Mapping[str, str] = await session.authentication_headers(
                    AuthenticationOptions(resource=RESOURCE, grant_type=grant_type)
                )
                response = await client.get(RESOURCE, headers=headers)
                response.raise_for_status()
                resource: dict[str, Any] = response.json()
                print(
                    "Resource:",
                    resource["message"],
                    f"({resource['authentication_method']})",
                )

                await session.revoke(
                    RevokeOptions(
                        credential_id=credential.credential_id,
                        grant_type=grant_type,
                    )
                )
                print("Revoke:", grant_type, credential.credential_id)

                revoked = await client.get(RESOURCE, headers=headers)
                if revoked.status_code != 401:
                    raise RuntimeError(
                        f"The revoked {grant_type} credential still accessed the resource"
                    )
                print("Revoked resource access:", grant_type, revoked.status_code)


if __name__ == "__main__":
    asyncio.run(main())
