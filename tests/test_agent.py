from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from agent_enrollment_protocol.agent import (
    Agent,
    AgentCommandError,
    AgentOptions,
    AssertionSigner,
    AuthenticationOptions,
    ClaimRequirementsError,
    CredentialRecord,
    EnrollmentStateError,
    EnrollOptions,
    GrantOptions,
    HttpxTransport,
    MemoryCredentialStore,
    MemoryIdentityStore,
    MemoryInspectCache,
    RandomIdempotencyKeyProvider,
    RevokeOptions,
    ServiceIdentity,
    WaitOptions,
)
from agent_enrollment_protocol.agent.types import IdentityRequest, OperationKey
from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AgentStatus,
    ApiKeyGrantResponse,
    AuthorizationCarrier,
    ClaimValues,
    ClientAssertionClaims,
    HttpRequest,
    HttpResponse,
    InspectDocument,
    SigningAlgorithm,
)

from .test_core_models import inspect_document


class QueueTransport:
    def __init__(self, *responses: HttpResponse) -> None:
        self.requests: list[HttpRequest] = []
        self.responses = list(responses)

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)

    async def aclose(self) -> None:
        return None


class FakeIdentityProvider:
    def __init__(self) -> None:
        self.requests: list[IdentityRequest] = []
        self.claims: list[ClientAssertionClaims] = []

    async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
        self.requests.append(request)
        return ServiceIdentity(
            agent_did="did:web:agent.example.com",
            identity_method="did:web",
            service_did=request.service_did,
            signing_algorithms=(SigningAlgorithm.EDDSA,),
            metadata={"source": "test"},
        )

    async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
        async def sign(
            claims: ClientAssertionClaims, algorithms: tuple[SigningAlgorithm, ...]
        ) -> str:
            assert identity.agent_did == claims.iss
            assert algorithms == (SigningAlgorithm.EDDSA,)
            self.claims.append(claims)
            return "signed.assertion.value"

        return sign


class FixedKeys:
    def __init__(self, value: str = "operation-key") -> None:
        self.value = value
        self.operations: list[OperationKey] = []

    async def create_key(self, operation: OperationKey) -> str:
        self.operations.append(operation)
        return self.value


def response(
    body: object, *, status: int = 200, headers: dict[str, str] | None = None
) -> HttpResponse:
    values = {"Content-Type": AEP_MEDIA_TYPE, **(headers or {})}
    return HttpResponse(
        status=status,
        headers=values,
        body=json.dumps(body, separators=(",", ":")).encode(),
    )


def inspect_response(document: InspectDocument | None = None, **headers: str) -> HttpResponse:
    normalized = {name.replace("_", "-"): value for name, value in headers.items()}
    return response((document or inspect_document()).to_wire(), headers=normalized)


def configured_agent(
    inspect_transport: QueueTransport,
    command_transport: QueueTransport,
    *,
    provider: FakeIdentityProvider | None = None,
    credential_store: MemoryCredentialStore | None = None,
    keys: FixedKeys | None = None,
    clock: Callable[[], datetime] = lambda: datetime(2026, 1, 1, tzinfo=UTC),
) -> tuple[Agent, FakeIdentityProvider]:
    identity_provider = provider or FakeIdentityProvider()
    return (
        Agent(
            AgentOptions(
                identity_provider=identity_provider,
                clock=clock,
                command_transport=command_transport,
                credential_store=credential_store,
                idempotency_keys=keys,
                inspect_transport=inspect_transport,
            )
        ),
        identity_provider,
    )


@pytest.mark.asyncio
async def test_inspect_caches_and_revalidates() -> None:
    transport = QueueTransport(
        inspect_response(cache_control="max-age=0", etag="one"),
        HttpResponse(status=304, headers={"Cache-Control": "max-age=60"}),
    )
    agent, _ = configured_agent(transport, QueueTransport())
    service = agent.service("api.example.com/path")
    first = await service.inspect()
    second = await service.inspect()
    assert first.document.service.did == "did:web:api.example.com"
    assert second.final_url == "https://api.example.com/.well-known/aep"
    assert transport.requests[1].headers["If-None-Match"] == "one"


@pytest.mark.asyncio
async def test_inspect_follows_same_origin_redirect_and_rejects_bad_responses() -> None:
    redirect = HttpResponse(status=307, headers={"Location": "/metadata/aep"})
    agent, _ = configured_agent(QueueTransport(redirect, inspect_response()), QueueTransport())
    assert (await agent.service("https://api.example.com").inspect()).final_url.endswith(
        "/metadata/aep"
    )
    failures = (
        (HttpResponse(status=302), "omitted Location"),
        (
            HttpResponse(status=302, headers={"Location": "https://other.example/aep"}),
            "changed origin",
        ),
        (HttpResponse(status=304), "without a cached"),
        (HttpResponse(status=503), "HTTP 503"),
        (HttpResponse(status=200, headers={"Content-Type": "application/json"}), "media type"),
        (
            HttpResponse(
                status=200,
                headers={"Content-Type": AEP_MEDIA_TYPE},
                body=b"{}" * ((1 << 19) + 1),
            ),
            "configured limit",
        ),
    )
    for invalid, message in failures:
        candidate, _ = configured_agent(QueueTransport(invalid), QueueTransport())
        with pytest.raises((ValueError, AgentCommandError), match=message):
            await candidate.service("api.example.com").inspect()


@pytest.mark.asyncio
async def test_enroll_status_wait_and_claim_requirements() -> None:
    commands = QueueTransport(
        response({"status": "pending"}),
        response({"status": "pending"}),
        response({"status": "active"}),
        response(
            {
                "api_key": "secret",
                "credential_id": "after-enroll",
                "expires_at": "2026-01-01T01:00:00Z",
                "header": "X-API-Key",
            }
        ),
    )
    keys = FixedKeys()
    agent, provider = configured_agent(QueueTransport(inspect_response()), commands, keys=keys)
    service = agent.service("api.example.com")
    with pytest.raises(ClaimRequirementsError) as missing:
        await service.enroll()
    assert missing.value.missing == ("contact.email",)
    enrolled = await service.enroll(
        EnrollOptions(claims=ClaimValues.model_validate({"contact.email": "owner@example.com"}))
    )
    assert enrolled.status == 200
    assert (await service.wait_for_active(WaitOptions(0.001, 1))).body.status is AgentStatus.ACTIVE
    assert keys.operations[0].command == "enroll"
    assert provider.claims[0].op.value == "enroll"
    assert commands.requests[0].headers["Idempotency-Key"] == "operation-key"
    assert (await service.grant()).body.grant_type == "api-key"


@pytest.mark.asyncio
async def test_wait_rejects_terminal_state_and_supports_cancellation() -> None:
    rejected_agent, _ = configured_agent(
        QueueTransport(inspect_response()), QueueTransport(response({"status": "rejected"}))
    )
    with pytest.raises(EnrollmentStateError, match="rejected"):
        await rejected_agent.service("api.example.com").wait_for_active()
    pending = QueueTransport(*(response({"status": "pending"}) for _ in range(10)))
    waiting_agent, _ = configured_agent(QueueTransport(inspect_response()), pending)
    task = asyncio.create_task(
        waiting_agent.service("api.example.com").wait_for_active(WaitOptions(1, 10))
    )
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_grant_stores_and_revoke_forgets_api_key() -> None:
    expires = "2026-01-01T01:00:00Z"
    granted = {
        "api_key": "secret",
        "credential_id": "credential-one",
        "expires_at": expires,
        "header": "X-API-Key",
        "scopes": None,
    }
    store = MemoryCredentialStore(lambda: datetime(2026, 1, 1, tzinfo=UTC))
    agent, _ = configured_agent(
        QueueTransport(inspect_response()),
        QueueTransport(response({"status": "active"}), response(granted), response({})),
        credential_store=store,
    )
    service = agent.service("api.example.com")
    await service.identity()
    result = await service.grant(GrantOptions(grant_type="api-key"))
    assert isinstance(result.body.credential, ApiKeyGrantResponse)
    assert await service.authentication_headers(
        AuthenticationOptions(resource="https://api.example.com/products")
    ) == {"X-API-Key": "secret"}
    revoked = await service.revoke(
        RevokeOptions(grant_type="api-key", credential_id="credential-one")
    )
    assert revoked.status == 200
    assert await store.list_credentials("did:web:api.example.com") == ()


@pytest.mark.asyncio
async def test_authentication_uses_assertion_and_honors_selection() -> None:
    agent, provider = configured_agent(QueueTransport(inspect_response()), QueueTransport())
    service = agent.service("api.example.com")
    headers = await service.authentication_headers(
        AuthenticationOptions(
            resource="https://api.example.com/resource",
            carrier=AuthorizationCarrier.DEDICATED.value,
            client_assertion_only=True,
        )
    )
    assert headers == {"AEP-Authorization": "AEP signed.assertion.value"}
    assert provider.claims[-1].resource == "https://api.example.com/resource"
    with pytest.raises(ValueError, match="cannot accompany"):
        await service.authentication_headers(
            AuthenticationOptions(
                resource="https://api.example.com/resource",
                client_assertion_only=True,
                grant_type="api-key",
            )
        )
    with pytest.raises(ValueError, match="Service origin"):
        await service.authentication_headers(
            AuthenticationOptions(resource="https://other.example/resource")
        )


@pytest.mark.asyncio
async def test_memory_stores_expiration_and_forget() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryCredentialStore(lambda: now)
    expired = CredentialRecord(
        credential_id="old",
        expires_at=now - timedelta(seconds=1),
        grant_type="api-key",
        issued_at=now,
        payload=b"{}",
        service_did="did:web:api.example.com",
        service_url="https://api.example.com/",
    )
    with pytest.raises(ValueError, match="future"):
        await store.save_credential(expired)
    identity_store = MemoryIdentityStore()
    assert await identity_store.find_identity("missing") is None
    cache = MemoryInspectCache()
    assert await cache.find_inspect("missing") is None
    await cache.delete_inspect("missing")
    assert len(await RandomIdempotencyKeyProvider().create_key(OperationKey("x", "d", "u"))) == 32


def test_agent_option_and_service_reference_validation() -> None:
    provider = FakeIdentityProvider()
    for options, message in (
        (AgentOptions(provider, assertion_lifetime=timedelta(0)), "lifetime"),
        (AgentOptions(provider, maximum_response_bytes=0), "response bytes"),
        (AgentOptions(provider, request_timeout=0), "timeout"),
    ):
        with pytest.raises(ValueError, match=message):
            Agent(options)
    agent = Agent(AgentOptions(provider, allow_insecure_loopback=True))
    assert agent.service("http://localhost:8080/path")._service_url == "http://localhost:8080/"
    assert agent.service("did:web:api.example.com")._service_url == "https://api.example.com/"
    for reference in ("", "http://example.com", "https://user@example.com"):
        with pytest.raises(ValueError):
            agent.service(reference)


def test_httpx_transport_constructs() -> None:
    assert isinstance(HttpxTransport(), HttpxTransport)
