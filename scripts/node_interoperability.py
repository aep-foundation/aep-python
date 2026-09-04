#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import base64
import json
from collections.abc import Mapping
from datetime import timedelta
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel

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
    AuthenticationOptions,
    GrantOptions,
    PlatformIdentityProvider,
    PlatformIdentityProviderOptions,
    RevokeOptions,
)
from agent_enrollment_protocol.core import (
    AEP_GRANT_TYPE_API_KEY,
    ApiKeyGrantResponse,
    ClientAssertionClaims,
    GrantRequest,
    GrantTypeConfig,
    ManagedAgentStatus,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignRequest,
    SigningAlgorithm,
    VerifyClientAssertionOptions,
    decode_jwt_unverified,
    did_web_document_url,
    select_did_web_public_jwk,
    sign_client_assertion,
    verify_client_assertion,
)
from agent_enrollment_protocol.core.errors import AepAssertionError
from agent_enrollment_protocol.platform import (
    AuthorizationRequest,
    DidVerificationMethod,
    DiscoveryOptions,
    IdentityListQuery,
    IdentityRecord,
    Platform,
    PlatformOptions,
    PlatformResult,
    RequestContext,
)
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    GrantContext,
    MemoryServiceCredentialStore,
    Service,
    ServiceOptions,
    StoredCredentialGrantTypeOptions,
    stored_api_key_grant_type,
)

PLATFORM_AUTHORIZATION = "Bearer demo-agent"
PRINCIPAL = "interop-agent"


class DidWebVerifier:
    async def verify(
        self, assertion: str, context: AssertionVerificationContext
    ) -> ClientAssertionClaims:
        try:
            header, payload = decode_jwt_unverified(assertion)
            issuer = payload.get("iss")
            key_id = header.get("kid")
            if not isinstance(issuer, str) or not isinstance(key_id, str):
                raise ValueError("assertion does not identify a DID verification method")
            document_url = did_web_document_url(issuer, allow_insecure_loopback=True)
            async with httpx.AsyncClient() as client:
                response = await client.get(document_url)
                response.raise_for_status()
                document = response.json()
            if not isinstance(document, dict):
                raise ValueError("DID document is not an object")
            public_jwk = select_did_web_public_jwk(document, did=issuer, key_id=key_id)
            key = jwt.PyJWK.from_dict(public_jwk).key
        except (AepAssertionError, httpx.HTTPError, jwt.PyJWTError, ValueError) as error:
            raise AepAssertionError("Invalid AEP client assertion.") from error
        return verify_client_assertion(
            assertion,
            key=key,
            options=VerifyClientAssertionOptions(
                algorithms=context.algorithms,
                audience=context.service_did,
                clock_tolerance_seconds=int(context.clock_tolerance.total_seconds()),
                current_time=int(context.current_time.timestamp()),
                issuer=issuer,
                operation=context.operation,
                resource=context.resource,
                subject=issuer,
            ),
        )


class InteropAuthorizer:
    async def authorize(self, request: AuthorizationRequest, context: RequestContext) -> bool:
        del request
        return context.authorization == PLATFORM_AUTHORIZATION and context.principal == PRINCIPAL


class InteropServiceDidResolver:
    def __init__(self, service_did: str) -> None:
        self._service_did = service_did

    async def resolve(self, service_did: str) -> bool:
        return service_did == self._service_did


class EphemeralKeyStore:
    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePrivateKey] = {}

    async def create_key(self, identity: IdentityRecord) -> None:
        if identity.agent_identity_id in self._keys:
            raise ValueError("identity key already exists")
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
            algorithm=SigningAlgorithm.ES256,
            key=self._key(identity),
            key_id=identity.key_id,
        )

    async def verification_key(self, identity: IdentityRecord) -> Any:
        return self._key(identity).public_key()

    def _key(self, identity: IdentityRecord) -> ec.EllipticCurvePrivateKey:
        try:
            return self._keys[identity.agent_identity_id]
        except KeyError as error:
            raise ValueError("identity key is unavailable") from error


class InteropApplication:
    def __init__(self, listen: str) -> None:
        origin = f"http://{listen}"
        encoded_host = listen.replace(":", "%3A")
        self._service_did = f"did:web:{encoded_host}:services:store"
        self._platform = self._create_platform(listen)
        service = self._create_service(origin)
        self._protected = AepAuthenticationMiddleware(
            self._protected_resource,
            service,
            allow_insecure_loopback=True,
            resource_origin=origin,
        )
        self._application = AepAsgiApplication(service, self._route)

    async def __call__(self, scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
        await self._application(scope, receive, send)

    def _create_service(self, origin: str) -> Service:
        credentials = MemoryServiceCredentialStore()

        async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
            return ApiKeyGrantResponse(
                api_key="interop-secret",
                credential_id="interop-credential",
                expires_at=(context.current_time + timedelta(hours=1))
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                header="x-api-key",
                scopes=request.requested_scopes,
            )

        api_key = stored_api_key_grant_type(
            StoredCredentialGrantTypeOptions(
                config=GrantTypeConfig.model_validate({"header_names": ["x-api-key"]}),
                issue=issue,
                store=credentials,
            )
        )
        return Service(
            ServiceOptions(
                allow_insecure_loopback=True,
                authentication_methods=(AEP_GRANT_TYPE_API_KEY,),
                grant_types=(api_key,),
                identity_methods=("did:web",),
                inspect_url=f"{origin}/.well-known/aep",
                service_did=self._service_did,
                verifier=DidWebVerifier(),
            )
        )

    def _create_platform(self, listen: str) -> Platform:
        encoded_host = listen.replace(":", "%3A")
        return Platform(
            PlatformOptions(
                authorizer=InteropAuthorizer(),
                did_host=listen,
                did_path_prefix="agents",
                did_url_template=f"https://{listen}/agents/{{agent_did_id}}/did.json",
                discovery=DiscoveryOptions(
                    endpoint_base="/platform/",
                    lifecycle_endpoint="/platform/agent-identities/{agent_identity_id}",
                    list_endpoint="/platform/agent-identities",
                    platform_did=f"did:web:{encoded_host}",
                    platform_name="Python Interoperability Platform",
                    provision_endpoint="/platform/agent-identities",
                    sign_endpoint="/platform/agent-identities/{agent_identity_id}/sign",
                ),
                key_store=EphemeralKeyStore(),
                service_did_resolver=InteropServiceDidResolver(self._service_did),
                signing_algorithms=(SigningAlgorithm.ES256,),
            )
        )

    async def _route(self, scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
        path = _scope_string(scope, "path")
        method = _scope_string(scope, "method")
        if path in {"/api/resource", "/api/profile"}:
            await self._protected(scope, receive, send)
            return
        if method == "GET" and path == "/health":
            await _send_json(send, 200, {"ok": True})
            return
        if method == "GET" and path == "/.well-known/aep-platform":
            await _send_platform_result(send, self._platform.discovery())
            return
        if method == "GET" and path == "/platform/agent-identities":
            await _send_platform_result(
                send,
                await self._platform.list(
                    _list_query(_scope_string(scope, "query_string")),
                    _request_context(scope),
                ),
            )
            return
        if method == "POST" and path == "/platform/agent-identities":
            request = PlatformProvisionRequest.model_validate_json(await _request_body(receive))
            await _send_platform_result(
                send, await self._platform.provision(request, _request_context(scope))
            )
            return
        if path.startswith("/platform/agent-identities/"):
            await self._identity_route(path, method, scope, receive, send)
            return
        if method == "GET" and path.startswith("/agents/") and path.endswith("/did.json"):
            agent_did_id = path.removeprefix("/agents/").removesuffix("/did.json")
            await _send_platform_result(send, await self._platform.did_document(agent_did_id))
            return
        if method == "GET" and path == "/services/store/did.json":
            await _send_json(
                send,
                200,
                {"@context": ["https://www.w3.org/ns/did/v1"], "id": self._service_did},
                content_type="application/did+json",
            )
            return
        await _send_json(send, 404, {"error": "not found"})

    async def _identity_route(
        self,
        path: str,
        method: str,
        scope: AsgiScope,
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        suffix = path.removeprefix("/platform/agent-identities/")
        if suffix.endswith("/sign") and method == "POST":
            identity_id = suffix.removesuffix("/sign")
            sign_request = PlatformSignRequest.model_validate_json(await _request_body(receive))
            sign_result = await self._platform.sign(
                identity_id, sign_request, _request_context(scope)
            )
            await _send_platform_result(send, sign_result)
            return
        elif method == "GET" and "/" not in suffix:
            identity_result = await self._platform.get_identity(suffix, _request_context(scope))
            await _send_platform_result(send, identity_result)
            return
        elif method == "PATCH" and "/" not in suffix:
            lifecycle_request = PlatformLifecycleRequest.model_validate_json(
                await _request_body(receive)
            )
            lifecycle_result = await self._platform.update_identity(
                suffix, lifecycle_request, _request_context(scope)
            )
            await _send_platform_result(send, lifecycle_result)
            return
        else:
            await _send_json(send, 404, {"error": "not found"})

    async def _protected_resource(
        self, scope: AsgiScope, receive: AsgiReceive, send: AsgiSend
    ) -> None:
        del receive
        if principal_from_scope(scope) is None:
            raise RuntimeError("protected route has no authenticated principal")
        path = _scope_string(scope, "path")
        if path == "/api/resource" and scope.get("method") == "GET":
            await _send_json(send, 200, {"available": True})
        elif path == "/api/profile" and scope.get("method") == "POST":
            await _send_json(send, 200, {"updated": True})
        else:
            await _send_json(send, 404, {"error": "not found"})

    async def _lifespan(self, receive: AsgiReceive, send: AsgiSend) -> None:
        while True:
            message_type = (await receive()).get("type")
            if message_type == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message_type == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
            else:
                raise RuntimeError("invalid ASGI lifespan message")


async def run_agent(platform_url: str, service_url: str) -> None:
    provider = PlatformIdentityProvider(
        PlatformIdentityProviderOptions(
            allow_insecure_loopback=True,
            authorization=PLATFORM_AUTHORIZATION,
            platform_url=platform_url,
        )
    )
    agent = Agent(
        AgentOptions(
            allow_insecure_loopback=True,
            identity_provider=provider,
        )
    )
    try:
        session = agent.service(service_url)
        inspection = await session.inspect()
        if not inspection.document.service.did.startswith("did:web:"):
            raise RuntimeError("Node Service did not advertise a did:web Service DID")
        enrolled = await session.enroll()
        granted = await session.grant(
            GrantOptions(
                grant_type=AEP_GRANT_TYPE_API_KEY,
                requested_scopes=("read:resource", "write:profile"),
            )
        )
        credential = granted.body.credential
        if not isinstance(credential, ApiKeyGrantResponse):
            raise RuntimeError("Node Service did not return an API-key credential")
        resource = f"{service_url.rstrip('/')}/api/resource"
        headers = await session.authentication_headers(
            AuthenticationOptions(
                credential_id=credential.credential_id,
                grant_type=AEP_GRANT_TYPE_API_KEY,
                resource=resource,
            )
        )
        async with httpx.AsyncClient() as client:
            response = await client.get(resource, headers=headers)
        response.raise_for_status()
        await session.revoke(
            RevokeOptions(
                credential_id=credential.credential_id,
                grant_type=AEP_GRANT_TYPE_API_KEY,
            )
        )
        async with httpx.AsyncClient() as client:
            revoked_response = await client.get(resource, headers=headers)
        try:
            await session.authentication_headers(
                AuthenticationOptions(
                    credential_id=credential.credential_id,
                    grant_type=AEP_GRANT_TYPE_API_KEY,
                    resource=resource,
                )
            )
        except ValueError:
            revoked = True
        else:
            revoked = False
        print(
            json.dumps(
                {
                    "agent": "python",
                    "credential_mode": granted.body.grant_type,
                    "enrollment": enrolled.body.status.value,
                    "platform": "node",
                    "protected_resource_status": response.status_code,
                    "revoked": revoked,
                    "revoked_resource_status": revoked_response.status_code,
                    "service": "node",
                },
                separators=(",", ":"),
            )
        )
    finally:
        await agent.aclose()
        await provider.aclose()


def _request_context(scope: AsgiScope) -> RequestContext:
    headers = _headers(scope)
    authorization = headers.get("authorization")
    return RequestContext(
        authorization=authorization,
        idempotency_key=headers.get("idempotency-key"),
        principal=PRINCIPAL if authorization == PLATFORM_AUTHORIZATION else "",
    )


def _list_query(raw_query: str) -> IdentityListQuery:
    values = parse_qs(raw_query)
    status_value = values.get("status", [""])[0]
    return IdentityListQuery(
        descending=values.get("descending", [""])[0] == "true",
        limit=int(values.get("limit", ["100"])[0]),
        offset=int(values.get("offset", ["0"])[0]),
        service_did=values.get("service_did", [None])[0],
        status=ManagedAgentStatus(status_value) if status_value else None,
    )


def _headers(scope: AsgiScope) -> dict[str, str]:
    return {
        name.decode("latin-1").lower(): value.decode("latin-1")
        for name, value in cast(list[tuple[bytes, bytes]], scope.get("headers", []))
    }


def _scope_string(scope: AsgiScope, name: str) -> str:
    value = scope.get(name, "")
    if name == "query_string" and isinstance(value, bytes):
        return value.decode("ascii")
    if not isinstance(value, str):
        raise RuntimeError(f"ASGI {name} is invalid")
    return value


async def _request_body(receive: AsgiReceive) -> bytes:
    body = bytearray()
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            raise RuntimeError("invalid ASGI request message")
        chunk = message.get("body", b"")
        if not isinstance(chunk, bytes):
            raise RuntimeError("invalid ASGI request body")
        body.extend(chunk)
        if len(body) > 1 << 20:
            raise ValueError("interoperability request is too large")
        if not message.get("more_body", False):
            break
    return bytes(body)


async def _send_platform_result(send: AsgiSend, result: PlatformResult[Any]) -> None:
    value: object = result.problem if result.problem is not None else result.body
    if isinstance(value, BaseModel):
        value = value.model_dump(by_alias=True, exclude_none=True, mode="json")
    await _send_json(
        send,
        result.status,
        value,
        content_type=result.content_type,
        headers=result.headers,
    )


async def _send_json(
    send: AsgiSend,
    status: int,
    value: object,
    *,
    content_type: str = "application/json",
    headers: Mapping[str, str] | None = None,
) -> None:
    body = json.dumps(value, separators=(",", ":")).encode()
    response_headers = {**(headers or {}), "Content-Length": str(len(body))}
    response_headers["Content-Type"] = content_type
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (name.lower().encode("ascii"), content.encode("latin-1"))
                for name, content in response_headers.items()
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    agent = subcommands.add_parser("agent")
    agent.add_argument("--platform-url", required=True)
    agent.add_argument("--service-url", required=True)
    server = subcommands.add_parser("server")
    server.add_argument("--listen", default="127.0.0.1:4320")
    arguments = parser.parse_args()
    if arguments.command == "agent":
        asyncio.run(run_agent(arguments.platform_url, arguments.service_url))
        return
    parsed = urlsplit(f"//{arguments.listen}")
    if parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.port is None:
        raise ValueError("interoperability server requires a loopback host and port")
    uvicorn.run(
        InteropApplication(arguments.listen),
        host=parsed.hostname,
        port=parsed.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
