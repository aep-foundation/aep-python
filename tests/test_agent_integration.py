from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_enrollment_protocol.adapters import AepAsgiApplication, AepAuthenticationMiddleware
from agent_enrollment_protocol.agent import (
    Agent,
    AgentCommandError,
    AgentOptions,
    AssertionSigner,
    AuthenticationOptions,
    CredentialRecord,
    FetchProtectedResourceOptions,
    GrantOptions,
    HttpxTransport,
    MemoryCredentialStore,
    PlatformIdentityProvider,
    PlatformIdentityProviderOptions,
    RevokeOptions,
    ServiceIdentity,
    fetch_protected_resource,
)
from agent_enrollment_protocol.agent.types import IdentityRequest
from agent_enrollment_protocol.core import (
    ApiKeyGrantResponse,
    AssertionOperation,
    ClientAssertionClaims,
    GrantRequest,
    GrantTypeConfig,
    HttpRequest,
    PlatformProvisionRequest,
    PlatformSignRequest,
    RevokeRequest,
    SigningAlgorithm,
    VerifyClientAssertionOptions,
    decode_jwt_unverified,
    sign_client_assertion,
    verify_client_assertion,
)
from agent_enrollment_protocol.platform import IdentityListQuery, Platform, RequestContext
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    CredentialAuthenticationInput,
    GrantContext,
    GrantTypeDefinition,
    MemoryServiceCredentialStore,
    RevokeContext,
    Service,
    ServiceOptions,
    StoredCredentialGrantTypeOptions,
    stored_api_key_grant_type,
)

from .test_platform import NOW, KeyStore
from .test_platform import options as platform_options

SERVICE_DID = "did:web:service.example"
AGENT_DID = "did:web:agent.example"
RESOURCE = "https://service.example/private"


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["aep-jwt", "api-key"])
async def test_protected_resource_helper_through_real_asgi_service(method: str) -> None:
    from agent_enrollment_protocol.adapters import AsgiReceive, AsgiScope, AsgiSend

    key = Ed25519PrivateKey.generate()
    issued = [0]
    received: list[tuple[str, dict[bytes, bytes]]] = []

    async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        issued[0] += 1
        return ApiKeyGrantResponse(
            api_key="secret",
            credential_id="one",
            header="X-Key",
            expires_at=(NOW + timedelta(hours=1)).isoformat(),
        )

    definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(issue=issue, store=MemoryServiceCredentialStore())
    )
    service = Service(
        ServiceOptions(
            service_did=SERVICE_DID,
            identity_methods=("did:web",),
            authentication_methods=(method,),
            verifier=Verifier(key),
            clock=lambda: NOW,
            grant_types=(definition,),
        )
    )

    async def private(scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
        headers = dict(scope.get("headers", []))
        path = scope.get("path", "")
        received.append((path, headers))
        if path == "/private":
            await send(
                {
                    "type": "http.response.start",
                    "status": 307,
                    "headers": [(b"location", b"/result")],
                }
            )
        else:
            await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"authenticated"})

    app = AepAsgiApplication(
        service,
        AepAuthenticationMiddleware(private, service, resource_origin="https://service.example"),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        transport = HttpxTransport(client)
        async with Agent(
            AgentOptions(
                identity_provider=LocalIdentityProvider(key),
                clock=lambda: NOW,
                command_transport=transport,
                inspect_transport=transport,
            )
        ) as agent:
            # Authentication can obtain a session credential, but enrollment is always explicit.
            configuration = FetchProtectedResourceOptions(
                agent=agent, request=HttpRequest(method="GET", url=RESOURCE), transport=transport
            )
            if method == "api-key":
                with pytest.raises(AgentCommandError, match="existing enrolled identity"):
                    await fetch_protected_resource(configuration)
            else:
                assert (await fetch_protected_resource(configuration)).status == 401
            assert await service._enrollment_store.find(AGENT_DID) is None
            assert received == [] and issued[0] == 0
            await agent.service("https://service.example").enroll()
            result = await fetch_protected_resource(
                FetchProtectedResourceOptions(
                    agent=agent,
                    request=HttpRequest(method="GET", url=RESOURCE),
                    carrier="AEP-Authorization",
                    transport=transport,
                    additional_authentication_headers={"Authorization": "Payment opaque"},
                )
            )
            assert result.status == 200 and result.body == b"authenticated"
            assert [path for path, _ in received] == ["/private", "/result"]
            assert all(headers[b"authorization"] == b"Payment opaque" for _, headers in received)
            if method == "aep-jwt":
                tokens = [
                    headers[b"aep-authorization"].decode().split()[1] for _, headers in received
                ]
                assert [decode_jwt_unverified(token)[1]["resource"] for token in tokens] == [
                    RESOURCE,
                    "https://service.example/result",
                ]
                assert tokens[0] != tokens[1] and issued[0] == 0
            else:
                assert all(headers[b"x-key"] == b"secret" for _, headers in received)
                assert issued[0] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "expected,target",
    [
        ("https://SERVICE.EXAMPLE:443/private", "https://service.example/private"),
        ("https://service.example", "https://service.example/"),
        ("https://SERVICE.EXAMPLE:443/private?a=1&b=2", "https://service.example/private?a=1&b=2"),
    ],
)
async def test_agent_and_service_share_resource_url_normalization(
    expected: str, target: str
) -> None:
    from agent_enrollment_protocol.adapters import AsgiReceive, AsgiScope, AsgiSend
    from agent_enrollment_protocol.service import ProtectedResourceRequest

    key = Ed25519PrivateKey.generate()
    service = Service(
        ServiceOptions(
            service_did=SERVICE_DID,
            identity_methods=("did:web",),
            verifier=Verifier(key),
            clock=lambda: NOW,
            authentication_methods=("aep-jwt",),
        )
    )

    async def private(scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"authenticated"})

    app = AepAsgiApplication(
        service,
        AepAuthenticationMiddleware(private, service, resource_origin="https://service.example"),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        transport = HttpxTransport(client)
        agent = Agent(
            AgentOptions(
                identity_provider=LocalIdentityProvider(key),
                clock=lambda: NOW,
                command_transport=transport,
                inspect_transport=transport,
            )
        )
        session = agent.service("https://service.example")
        await session.enroll()
        headers = await session.authentication_headers(AuthenticationOptions(resource=expected))
        assert (
            decode_jwt_unverified(headers["Authorization"].removeprefix("AEP "))[1]["resource"]
            == target
        )
        result = await client.get(expected, headers=headers)
        assert result.status_code == 200
        assert result.request.url.raw_path == httpx.URL(target).raw_path
        assert (await client.get(expected, headers=headers)).status_code == 401
        other = await session.authentication_headers(
            AuthenticationOptions(resource="https://service.example/other")
        )
        assert (await client.get(expected, headers=other)).status_code == 401
        raw = ClientAssertionClaims(
            iss=AGENT_DID,
            sub=AGENT_DID,
            aud=SERVICE_DID,
            iat=int(NOW.timestamp()),
            exp=int(NOW.timestamp()) + 60,
            jti="raw-case",
            op=AssertionOperation.AUTHENTICATE,
            resource=expected,
        )
        token = sign_client_assertion(raw, key=key, algorithm=SigningAlgorithm.EDDSA)
        assert (
            await client.get(target, headers={"Authorization": f"AEP {token}"})
        ).status_code == 200

    class SignatureVerifier(Verifier):
        async def verify(
            self, token: str, context: AssertionVerificationContext
        ) -> ClientAssertionClaims:
            return verify_client_assertion(
                token,
                key=self.key.public_key(),
                options=VerifyClientAssertionOptions(
                    algorithms=context.algorithms,
                    audience=context.service_did,
                    operation=context.operation,
                    current_time=int(context.current_time.timestamp()),
                ),
            )

    independent = Service(
        ServiceOptions(
            service_did=SERVICE_DID,
            identity_methods=("did:web",),
            verifier=SignatureVerifier(key),
            clock=lambda: NOW,
            authentication_methods=("aep-jwt",),
            enrollment_store=service._enrollment_store,
        )
    )
    assert (
        await independent.authenticate_protected_resource(
            ProtectedResourceRequest(
                headers={"Authorization": f"AEP {token}"}, method="GET", url=target
            )
        )
    ).authenticated


class LocalIdentityProvider:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
        return ServiceIdentity(AGENT_DID, "did:web", request.service_did, (SigningAlgorithm.EDDSA,))

    async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
        async def sign(
            claims: ClientAssertionClaims, algorithms: tuple[SigningAlgorithm, ...]
        ) -> str:
            assert claims.iss == identity.agent_did
            assert SigningAlgorithm.EDDSA in algorithms
            return sign_client_assertion(claims, key=self.key, algorithm=SigningAlgorithm.EDDSA)

        return sign


class Verifier:
    def __init__(self, key: Any) -> None:
        self.key = key

    async def verify(
        self, token: str, context: AssertionVerificationContext
    ) -> ClientAssertionClaims:
        return verify_client_assertion(
            token,
            key=self.key.public_key(),
            options=VerifyClientAssertionOptions(
                algorithms=context.algorithms,
                audience=context.service_did,
                operation=context.operation,
                resource=context.resource,
                current_time=int(context.current_time.timestamp()),
            ),
        )


@pytest_asyncio.fixture
async def enrolled() -> AsyncIterator[tuple[Agent, MemoryServiceCredentialStore]]:
    key = Ed25519PrivateKey.generate()
    issued = MemoryServiceCredentialStore()
    count = 0

    async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        nonlocal count
        count += 1
        return ApiKeyGrantResponse(
            api_key=f"secret-{count}",
            credential_id=f"key-{count}",
            expires_at=(NOW + timedelta(hours=1)).isoformat(),
            header="x-key",
        )

    definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(
            issue=issue,
            store=issued,
            config=GrantTypeConfig(supports_per_credential_revoke="true"),
        )
    )
    service = Service(
        ServiceOptions(
            service_did=SERVICE_DID,
            authentication_methods=("api-key",),
            identity_methods=("did:web",),
            verifier=Verifier(key),
            clock=lambda: NOW,
            grant_types=(definition,),
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=AepAsgiApplication(service))
    ) as client:
        transport = HttpxTransport(client)
        agent = Agent(
            AgentOptions(
                identity_provider=LocalIdentityProvider(key),
                clock=lambda: NOW,
                command_transport=transport,
                inspect_transport=transport,
            )
        )
        session = agent.service("https://service.example")
        await session.enroll()
        await session.grant()
        await session.grant()
        yield agent, issued


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["all_grant_types", "credential_id", "grant_type"])
async def test_revoke_extension_cannot_change_selector(
    enrolled: tuple[Agent, MemoryServiceCredentialStore], field: str
) -> None:
    agent, issued = enrolled
    session = agent.service("https://service.example")
    with pytest.raises(ValueError, match="selectors"):
        await session.revoke(RevokeOptions(grant_type="api-key", parameters={field: "key-1"}))
    for index in (1, 2):
        headers = await session.authentication_headers(
            AuthenticationOptions(resource=RESOURCE, credential_id=f"key-{index}")
        )
        assert (
            await issued.authenticate_credential(
                "api-key",
                CredentialAuthenticationInput(
                    headers={name: (value,) for name, value in headers.items()},
                    method="GET",
                    url=RESOURCE,
                    current_time=NOW,
                ),
            )
            is not None
        )


@pytest.mark.asyncio
async def test_targeted_revoke_preserves_other_local_and_service_credentials(
    enrolled: tuple[Agent, MemoryServiceCredentialStore],
) -> None:
    agent, issued = enrolled
    session = agent.service("https://service.example")
    await session.revoke(RevokeOptions(grant_type="api-key", credential_id="key-1"))
    with pytest.raises(ValueError, match="not found"):
        await session.authentication_headers(
            AuthenticationOptions(resource=RESOURCE, credential_id="key-1")
        )
    headers = await session.authentication_headers(
        AuthenticationOptions(resource=RESOURCE, credential_id="key-2")
    )
    assert (
        await issued.authenticate_credential(
            "api-key",
            CredentialAuthenticationInput(
                headers={name: (value,) for name, value in headers.items()},
                method="GET",
                url=RESOURCE,
                current_time=NOW,
            ),
        )
        is not None
    )
    assert (
        await issued.authenticate_credential(
            "api-key",
            CredentialAuthenticationInput(
                headers={"x-key": ("secret-1",)}, method="GET", url=RESOURCE, current_time=NOW
            ),
        )
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "selector",
    [
        AuthenticationOptions(resource=RESOURCE, credential_id=""),
        AuthenticationOptions(resource=RESOURCE, grant_type=""),
    ],
)
async def test_empty_selection_does_not_fall_back(
    enrolled: tuple[Agent, MemoryServiceCredentialStore], selector: AuthenticationOptions
) -> None:
    agent, _ = enrolled
    with pytest.raises(ValueError, match="must not be empty"):
        await agent.service("https://service.example").authentication_headers(selector)


@pytest.mark.asyncio
async def test_custom_store_cannot_substitute_a_different_credential(
    enrolled: tuple[Agent, MemoryServiceCredentialStore],
) -> None:
    original, _ = enrolled
    record = await original._credential_store.find_credential(SERVICE_DID, "key-2")
    assert record is not None

    class WrongStore(MemoryCredentialStore):
        async def find_credential(
            self, service_did: str, credential_id: str
        ) -> CredentialRecord | None:
            return record

    agent = Agent(
        AgentOptions(
            identity_provider=original._identity_provider,
            clock=lambda: NOW,
            command_transport=original._command_transport,
            inspect_transport=original._inspect_transport,
            credential_store=WrongStore(),
        )
    )
    with pytest.raises(ValueError, match="requested credential ID"):
        await agent.service("https://service.example").authentication_headers(
            AuthenticationOptions(resource=RESOURCE, credential_id="key-1")
        )


class ExtensionIssuer:
    async def grant(self, request: GrantRequest, context: GrantContext) -> bytes:
        return b'{"credential_id":"extension-key","opaque":"secret"}'

    async def revoke(self, request: RevokeRequest, context: RevokeContext) -> None:
        return None


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", [1, 65, 365])
async def test_real_platform_signing_and_read_only_identity_recovery(delay: int) -> None:
    clock = [NOW.replace(microsecond=123456)]
    keys = KeyStore()
    platform = Platform(platform_options(clock=lambda: clock[0], key_store=keys))
    paths: list[tuple[str, str]] = []

    async def dispatch(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        paths.append((request.method, path))
        context = RequestContext(
            principal="owner",
            idempotency_key=request.headers.get("idempotency-key"),
            current_time=clock[0],
        )
        result: Any
        if path == "/.well-known/aep-platform":
            result = platform.discovery()
        elif request.method == "GET":
            result = await platform.list(IdentityListQuery(service_did=SERVICE_DID), context)
        elif path.endswith("/sign"):
            clock[0] += timedelta(seconds=delay)
            result = await platform.sign(
                path.split("/")[-2],
                PlatformSignRequest.model_validate_json(request.content),
                replace(context, current_time=clock[0]),
            )
        else:
            result = await platform.provision(
                PlatformProvisionRequest.model_validate_json(request.content), context
            )
        body = result.problem or result.body
        return httpx.Response(
            result.status,
            headers={"Content-Type": result.content_type, **result.headers},
            json=body.to_wire(),
        )

    service = Service(
        ServiceOptions(
            service_did=SERVICE_DID,
            identity_methods=("did:web",),
            verifier=Verifier(keys.key),
            clock=lambda: clock[0],
            grant_types=(GrantTypeDefinition("future", ExtensionIssuer()),),
        )
    )
    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(dispatch)) as platform_client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=AepAsgiApplication(service))
        ) as service_client,
    ):
        provider = PlatformIdentityProvider(
            PlatformIdentityProviderOptions(
                platform_url="https://platform.example",
                transport=HttpxTransport(platform_client),
                clock=lambda: clock[0],
            )
        )

        def fresh_agent() -> Agent:
            transport = HttpxTransport(service_client)
            return Agent(
                AgentOptions(
                    identity_provider=provider,
                    clock=lambda: clock[0],
                    command_transport=transport,
                    inspect_transport=transport,
                )
            )

        await fresh_agent().service("https://service.example").enroll()
        paths.clear()
        recovered = fresh_agent()
        result = await recovered.service("https://service.example").grant(
            GrantOptions(grant_type="future")
        )
        assert json.loads(result.body.raw)["credential_id"] == "extension-key"
        assert await recovered._identity_store.find_identity(SERVICE_DID) is not None
        private_paths = [item for item in paths if item[1] != "/.well-known/aep-platform"]
        assert private_paths[0] == ("GET", "/v1/aep/agent-identities")
        assert all(method == "GET" or path.endswith("/sign") for method, path in paths)


@pytest.mark.asyncio
async def test_missing_platform_identity_does_not_provision_during_grant() -> None:
    from .test_agent import QueueTransport, response
    from .test_core_models import inspect_document

    class LookupProvider(LocalIdentityProvider):
        async def find_identity_by_service_did(self, service_did: str) -> ServiceIdentity | None:
            return None

        async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
            raise AssertionError("Grant must not provision")

    agent = Agent(
        AgentOptions(
            identity_provider=LookupProvider(Ed25519PrivateKey.generate()),
            clock=lambda: NOW,
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
            command_transport=QueueTransport(),
        )
    )
    with pytest.raises(AgentCommandError, match="existing enrolled identity"):
        await agent.service("https://api.example.com").grant()
