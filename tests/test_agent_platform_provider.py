from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import parse_qs, urlsplit

import pytest

from agent_enrollment_protocol.agent import (
    MemoryPlatformDiscoveryCache,
    PlatformAuthenticationHeaders,
    PlatformCommandError,
    PlatformContextProvider,
    PlatformDiscoveryCache,
    PlatformDiscoveryCacheEntry,
    PlatformIdempotencyKeyFactory,
    PlatformIdentityProvider,
    PlatformIdentityProviderOptions,
    PlatformPendingSign,
    PlatformPendingSignResolver,
    PlatformSignPendingError,
    ServiceIdentity,
)
from agent_enrollment_protocol.agent.platform_provider import (
    _cache_directive,
    _cache_fresh,
    _endpoint,
    _platform_url,
    _valid_url,
    _validate_cache_entry,
)
from agent_enrollment_protocol.agent.types import IdentityRequest
from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AEP_PROBLEM_MEDIA_TYPE,
    AssertionOperation,
    ClientAssertionClaims,
    HttpRequest,
    HttpResponse,
    InspectDocument,
    PlatformDiscoveryDocument,
    SigningAlgorithm,
)

from .test_core_models import inspect_document

NOW = datetime(2026, 9, 3, 12, tzinfo=UTC)
SERVICE_DID = "did:web:api.example.com"
AGENT_DID = "did:web:platform.example:agents:one"


class QueueTransport:
    def __init__(self, *responses: HttpResponse) -> None:
        self.closed = False
        self.requests: list[HttpRequest] = []
        self.responses = list(responses)

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)

    async def aclose(self) -> None:
        self.closed = True


class BlockingTransport:
    async def send(self, request: HttpRequest) -> HttpResponse:
        del request
        await asyncio.sleep(1)
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        return None


def json_response(
    body: object,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    return HttpResponse(
        status=status,
        headers={"Content-Type": AEP_MEDIA_TYPE, **(headers or {})},
        body=json.dumps(body, separators=(",", ":")).encode(),
    )


def discovery(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "aep_version": "1.0",
        "endpoints": {
            "hosted_verification": "/v1/aep/verifications",
            "lifecycle": "/v1/aep/agent-identities/{agent_identity_id}",
            "list": "/v1/aep/agent-identities",
            "provision": "/v1/aep/agent-identities",
            "sign": "/v1/aep/agent-identities/{agent_identity_id}/sign",
        },
        "http": {"endpoint_base": "/v1/aep"},
        "identity": {
            "did_methods": ["did:web"],
            "did_url_template": "https://platform.example/agents/{agent_did_id}/did.json",
        },
        "platform": {
            "did": "did:web:platform.example",
            "hosted_verification": True,
            "name": "Example Platform",
        },
        "signing": {"algorithms": ["ES256"], "default_lifetime_seconds": "300"},
    }
    value.update(changes)
    return value


def identity(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "agent_did": AGENT_DID,
        "agent_identity_id": "pai_one",
        "created_at": "2026-09-03T12:00:00Z",
        "did_document_url": "https://platform.example/agents/one/did.json",
        "key_id": AGENT_DID,
        "service_did": SERVICE_DID,
        "signing_algorithms": ["ES256"],
        "status": "active",
        "updated_at": "2026-09-03T12:00:00Z",
    }
    value.update(changes)
    return value


def listed(*values: dict[str, object]) -> dict[str, object]:
    return {"count": str(len(values)), "data": list(values), "total": str(len(values))}


def request(
    *,
    inspect: InspectDocument | None = None,
    service_did: str | None = None,
    service_url: str = "https://api.example.com/",
) -> IdentityRequest:
    document = inspect or inspect_document()
    return IdentityRequest(
        inspect=document,
        service_did=service_did or document.service.did,
        service_url=service_url,
    )


def service_identity(
    *,
    agent_did: str = AGENT_DID,
    identity_method: str = "did:web",
    metadata: Mapping[str, str] | None = None,
    service_did: str = SERVICE_DID,
    signing_algorithms: tuple[SigningAlgorithm, ...] = (SigningAlgorithm.ES256,),
) -> ServiceIdentity:
    return ServiceIdentity(
        agent_did=agent_did,
        identity_method=identity_method,
        service_did=service_did,
        signing_algorithms=signing_algorithms,
        metadata={
            "agent_identity_id": "pai_one",
            "created_at": "2026-09-03T12:00:00Z",
            "did_document_url": "https://platform.example/agents/one/did.json",
            "key_id": AGENT_DID,
            "platform_url": "https://platform.example/",
            "status": "active",
            "updated_at": "2026-09-03T12:00:00Z",
        }
        if metadata is None
        else metadata,
    )


def claims(**changes: object) -> ClientAssertionClaims:
    values: dict[str, object] = {
        "aud": SERVICE_DID,
        "exp": int((NOW + timedelta(minutes=2)).timestamp()),
        "iat": int(NOW.timestamp()),
        "iss": AGENT_DID,
        "jti": "assertion-one",
        "op": AssertionOperation.ENROLL,
        "sub": AGENT_DID,
    }
    values.update(changes)
    return ClientAssertionClaims.model_validate(values)


def completed(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "agent_did": AGENT_DID,
        "client_assertion": "header.payload.signature",
        "expires_at": "2026-09-03T12:02:00Z",
        "issued_at": "2026-09-03T12:00:00Z",
        "jti": "assertion-one",
        "service_did": SERVICE_DID,
        "status": "completed",
    }
    value.update(changes)
    return value


def provider(
    transport: QueueTransport,
    *,
    allow_insecure_loopback: bool = False,
    authentication_headers: PlatformAuthenticationHeaders | None = None,
    authorization: str | None = None,
    clock: Callable[[], datetime] = lambda: NOW,
    discovery_cache: PlatformDiscoveryCache | None = None,
    idempotency_key: PlatformIdempotencyKeyFactory | None = None,
    maximum_response_bytes: int = 1 << 20,
    pending_sign_resolver: PlatformPendingSignResolver | None = None,
    platform_context: PlatformContextProvider | None = None,
    platform_url: str = "https://platform.example",
    request_timeout: float = 30.0,
) -> PlatformIdentityProvider:
    return PlatformIdentityProvider(
        PlatformIdentityProviderOptions(
            allow_insecure_loopback=allow_insecure_loopback,
            authentication_headers=authentication_headers,
            authorization=authorization,
            clock=clock,
            discovery_cache=discovery_cache,
            idempotency_key=idempotency_key,
            maximum_response_bytes=maximum_response_bytes,
            pending_sign_resolver=pending_sign_resolver,
            platform_context=platform_context,
            platform_url=platform_url,
            request_timeout=request_timeout,
            transport=transport,
        )
    )


@pytest.mark.asyncio
async def test_recovers_existing_identity_with_authenticated_list() -> None:
    async def headers() -> dict[str, str]:
        return {
            "authorization": "Bearer dynamic",
            "Content-Type": "ignored",
            "Idempotency-Key": "ignored",
            "X-Platform-Tenant": "tenant",
        }

    transport = QueueTransport(
        json_response(discovery(), headers={"Cache-Control": "max-age=300"}),
        json_response(listed(identity())),
    )
    instance = provider(
        transport,
        authentication_headers=headers,
        authorization="Bearer static",
    )
    recovered = await instance.get_or_create_identity(request())
    assert recovered == service_identity()
    assert len(transport.requests) == 2
    listed_request = transport.requests[1]
    assert listed_request.method == "GET"
    assert parse_qs(urlsplit(listed_request.url).query) == {
        "descending": ["true"],
        "limit": ["100"],
        "service_did": [SERVICE_DID],
    }
    assert listed_request.headers["authorization"] == "Bearer dynamic"
    assert listed_request.headers["X-Platform-Tenant"] == "tenant"
    assert listed_request.headers["Accept"] == AEP_MEDIA_TYPE
    assert "Content-Type" not in listed_request.headers
    assert "Idempotency-Key" not in listed_request.headers
    await instance.aclose()
    assert not transport.closed


@pytest.mark.asyncio
async def test_loopback_platform_preserves_canonical_https_did_document_url() -> None:
    agent_did = "did:web:127.0.0.1%3A4310:agents:one"
    transport = QueueTransport(
        json_response(
            discovery(
                identity={
                    "did_methods": ["did:web"],
                    "did_url_template": "https://127.0.0.1:4310/agents/{agent_did_id}/did.json",
                }
            )
        ),
        json_response(
            listed(
                identity(
                    agent_did=agent_did,
                    did_document_url="https://127.0.0.1:4310/agents/one/did.json",
                    key_id=agent_did,
                )
            )
        ),
    )
    instance = provider(
        transport,
        allow_insecure_loopback=True,
        platform_url="http://127.0.0.1:4310",
    )

    recovered = await instance.find_identity_by_service_did(SERVICE_DID)

    assert recovered is not None
    assert recovered.metadata["did_document_url"] == "https://127.0.0.1:4310/agents/one/did.json"
    await instance.aclose()
    assert not transport.closed


@pytest.mark.asyncio
async def test_provisions_when_recovery_is_empty_and_serializes_concurrent_calls() -> None:
    keys = iter(("provision-one", "provision-two"))

    async def key() -> str:
        return next(keys)

    transport = QueueTransport(
        json_response(discovery(), headers={"Cache-Control": "max-age=300"}),
        json_response(listed()),
        json_response(identity()),
        json_response(listed(identity())),
    )
    instance = provider(transport, idempotency_key=key)
    first, second = await asyncio.gather(
        instance.get_or_create_identity(request()),
        instance.get_or_create_identity(request()),
    )
    assert first == second == service_identity()
    provision = transport.requests[2]
    assert provision.method == "POST"
    assert provision.headers["Idempotency-Key"] == "provision-one"
    assert json.loads(provision.body or b"") == {"service_did": SERVICE_DID}
    assert [item.method for item in transport.requests] == ["GET", "GET", "POST", "GET"]


@pytest.mark.asyncio
async def test_identity_request_and_platform_response_boundaries() -> None:
    instance = provider(QueueTransport())
    with pytest.raises(ValueError, match="does not match"):
        await instance.get_or_create_identity(request(service_did="did:web:other.example"))

    document_data = inspect_document().to_wire()
    cast(dict[str, object], document_data["identity"])["methods"] = []
    cast(dict[str, object], document_data["commands"])["supported"] = ["inspect"]
    document = InspectDocument.model_validate_json(json.dumps(document_data))
    with pytest.raises(ValueError, match="does not support"):
        await instance.get_or_create_identity(request(inspect=document))

    for changed, message in (
        ({"agent_did": "did:key:one", "key_id": "did:key:one"}, "invalid identity"),
        ({"key_id": "did:web:other.example"}, "invalid identity"),
        ({"did_document_url": "https://platform.example/wrong"}, "does not match"),
    ):
        broken = provider(
            QueueTransport(json_response(discovery()), json_response(listed(identity(**changed))))
        )
        with pytest.raises(ValueError, match=message):
            await broken.find_identity_by_service_did(SERVICE_DID)

    inactive = provider(
        QueueTransport(
            json_response(discovery()),
            json_response(listed(identity(status="suspended"))),
        )
    )
    assert await inactive.find_identity_by_service_did(SERVICE_DID) is None

    for changed in (
        {"service_did": "did:web:other.example"},
        {"status": "suspended"},
    ):
        broken = provider(
            QueueTransport(
                json_response(discovery()),
                json_response(listed()),
                json_response(identity(**changed)),
            )
        )
        with pytest.raises(ValueError, match="outside the requested Service scope"):
            await broken.get_or_create_identity(request())


@pytest.mark.asyncio
async def test_delegates_completed_signing_with_context() -> None:
    context: dict[str, object] = {"authorization_handle": {"value": "opaque"}}

    async def context_provider(
        selected: ServiceIdentity, assertion: ClientAssertionClaims
    ) -> dict[str, object]:
        assert selected.agent_did == assertion.iss
        return context

    transport = QueueTransport(json_response(discovery()), json_response(completed()))
    instance = provider(transport, platform_context=context_provider)
    signer = await instance.signer_for(service_identity())
    assert await signer(claims(), (SigningAlgorithm.ES256,)) == "header.payload.signature"
    outbound = transport.requests[1]
    assert outbound.url.endswith("/v1/aep/agent-identities/pai_one/sign")
    assert outbound.headers["Idempotency-Key"]
    body = json.loads(outbound.body or b"")
    assert body == {
        "jti": "assertion-one",
        "lifetime_seconds": "120",
        "op": "enroll",
        "platform_context": context,
        "service_did": SERVICE_DID,
    }
    context["authorization_handle"] = "changed"
    assert body["platform_context"] != context


@pytest.mark.asyncio
async def test_pending_signing_exposes_or_resolves_opaque_context() -> None:
    pending_response = {
        "platform_context": {"authorization_handle": {"value": "opaque"}},
        "retry_after_seconds": "5",
        "status": "pending",
    }
    without_resolver = provider(
        QueueTransport(json_response(discovery()), json_response(pending_response, status=202))
    )
    signer = await without_resolver.signer_for(service_identity())
    with pytest.raises(PlatformSignPendingError) as raised:
        await signer(claims(), (SigningAlgorithm.ES256,))
    assert raised.value.pending.retry_after_seconds == 5
    assert raised.value.pending.platform_context == pending_response["platform_context"]

    resolved: list[PlatformPendingSign] = []

    async def resolver(pending: PlatformPendingSign) -> dict[str, object]:
        resolved.append(pending)
        return {"authorization_handle": "approved"}

    keys = iter(("initial", "final"))

    async def key() -> str:
        return next(keys)

    transport = QueueTransport(
        json_response(discovery()),
        json_response(pending_response, status=202),
        json_response(completed(platform_context={"authorization_handle": "approved"})),
    )
    instance = provider(
        transport,
        idempotency_key=key,
        pending_sign_resolver=resolver,
    )
    signer = await instance.signer_for(service_identity())
    assert await signer(claims(), (SigningAlgorithm.ES256,)) == "header.payload.signature"
    assert len(resolved) == 1
    assert transport.requests[1].headers["Idempotency-Key"] == "initial"
    assert transport.requests[2].headers["Idempotency-Key"] == "final"
    assert json.loads(transport.requests[2].body or b"")["platform_context"] == {
        "authorization_handle": "approved"
    }


@pytest.mark.asyncio
async def test_signing_rejects_identity_claim_algorithm_and_stage_mismatches() -> None:
    instance = provider(QueueTransport())
    invalid_identities = (
        service_identity(metadata={}),
        service_identity(identity_method="did:key"),
        service_identity(agent_did="did:key:one"),
        service_identity(metadata={**service_identity().metadata, "key_id": "wrong"}),
        service_identity(signing_algorithms=()),
        service_identity(
            metadata={**service_identity().metadata, "did_document_url": "https://wrong.example"}
        ),
    )
    for value in invalid_identities:
        with pytest.raises(ValueError):
            await instance.signer_for(value)

    signer = await instance.signer_for(service_identity())
    with pytest.raises(ValueError, match="another identity"):
        await signer(claims(aud="did:web:other.example"), (SigningAlgorithm.ES256,))
    with pytest.raises(ValueError, match="no compatible"):
        await signer(claims(), (SigningAlgorithm.EDDSA,))

    async def duplicate() -> str:
        return "same"

    duplicate_provider = provider(
        QueueTransport(
            json_response(discovery()),
            json_response({"retry_after_seconds": "1", "status": "pending"}, status=202),
        ),
        idempotency_key=duplicate,
        pending_sign_resolver=_empty_context,
    )
    duplicate_signer = await duplicate_provider.signer_for(service_identity())
    with pytest.raises(ValueError, match="distinct idempotency"):
        await duplicate_signer(claims(), (SigningAlgorithm.ES256,))


async def _empty_context(pending: PlatformPendingSign) -> None:
    del pending


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sign_response,status,headers,message",
    [
        (completed(), 202, {}, "completed Sign"),
        (completed(jti="wrong"), 200, {}, "completed Sign"),
        ({"retry_after_seconds": "1", "status": "pending"}, 200, {}, "pending Sign"),
        (completed(), 200, {"Retry-After": "1"}, "included Retry-After"),
    ],
)
async def test_sign_response_contract_boundaries(
    sign_response: dict[str, object],
    status: int,
    headers: dict[str, str],
    message: str,
) -> None:
    instance = provider(
        QueueTransport(
            json_response(discovery()),
            json_response(sign_response, status=status, headers=headers),
        )
    )
    signer = await instance.signer_for(service_identity())
    with pytest.raises(ValueError, match=message):
        await signer(claims(), (SigningAlgorithm.ES256,))


@pytest.mark.asyncio
async def test_authenticate_signing_includes_resource() -> None:
    transport = QueueTransport(json_response(discovery()), json_response(completed()))
    instance = provider(transport)
    signer = await instance.signer_for(service_identity())
    authentication = claims(
        op=AssertionOperation.AUTHENTICATE,
        resource="https://api.example.com/orders",
    )
    await signer(authentication, (SigningAlgorithm.ES256,))
    assert json.loads(transport.requests[1].body or b"")["resource"] == (
        "https://api.example.com/orders"
    )


@pytest.mark.asyncio
async def test_discovery_cache_freshness_revalidation_and_no_store() -> None:
    cache = MemoryPlatformDiscoveryCache()
    transport = QueueTransport(
        json_response(discovery(), headers={"Cache-Control": "max-age=0", "ETag": '"one"'}),
        json_response(listed()),
        HttpResponse(status=304, headers={"Cache-Control": "max-age=300"}),
        json_response(listed()),
    )
    instance = provider(transport, discovery_cache=cache)
    assert await instance.find_identity_by_service_did(SERVICE_DID) is None
    assert await instance.find_identity_by_service_did(SERVICE_DID) is None
    assert transport.requests[2].headers["If-None-Match"] == '"one"'

    modified_transport = QueueTransport(
        json_response(
            discovery(),
            headers={"Cache-Control": "max-age=0", "Last-Modified": "latest"},
        ),
        json_response(listed()),
        HttpResponse(status=304),
        json_response(listed()),
    )
    modified = provider(modified_transport)
    await modified.find_identity_by_service_did(SERVICE_DID)
    await modified.find_identity_by_service_did(SERVICE_DID)
    assert modified_transport.requests[2].headers["If-Modified-Since"] == "latest"
    assert "If-None-Match" not in modified_transport.requests[2].headers

    no_store_transport = QueueTransport(
        json_response(discovery(), headers={"Cache-Control": "no-store"}),
        json_response(listed()),
        json_response(discovery(), headers={"Cache-Control": "no-store"}),
        json_response(listed()),
    )
    no_store = provider(no_store_transport)
    await no_store.find_identity_by_service_did(SERVICE_DID)
    await no_store.find_identity_by_service_did(SERVICE_DID)
    assert (
        sum(item.url.endswith("/.well-known/aep-platform") for item in no_store_transport.requests)
        == 2
    )


@pytest.mark.asyncio
async def test_discovery_redirect_and_failure_boundaries() -> None:
    redirected = provider(
        QueueTransport(
            HttpResponse(status=307, headers={"Location": "/metadata/platform"}),
            json_response(discovery()),
            json_response(listed()),
        )
    )
    await redirected.find_identity_by_service_did(SERVICE_DID)

    failures = (
        (QueueTransport(HttpResponse(status=307)), "omitted Location"),
        (
            QueueTransport(
                HttpResponse(status=307, headers={"Location": "https://other.example/platform"})
            ),
            "changed origin",
        ),
        (QueueTransport(json_response({}, status=500)), "HTTP 500"),
        (
            QueueTransport(json_response(discovery(), headers={"Content-Type": "text/plain"})),
            "media type",
        ),
        (QueueTransport(HttpResponse(status=304)), "without a cached"),
        (
            QueueTransport(
                json_response(
                    discovery(
                        identity={
                            "did_methods": ["did:key"],
                            "did_url_template": (
                                "https://platform.example/agents/{agent_did_id}/did.json"
                            ),
                        }
                    )
                )
            ),
            "does not advertise did:web",
        ),
    )
    for transport, message in failures:
        with pytest.raises((PlatformCommandError, ValueError), match=message):
            await provider(transport).find_identity_by_service_did(SERVICE_DID)

    redirects = [
        HttpResponse(status=307, headers={"Location": f"/redirect-{value}"}) for value in range(6)
    ]
    with pytest.raises(ValueError, match="five redirects"):
        await provider(QueueTransport(*redirects)).find_identity_by_service_did(SERVICE_DID)


@pytest.mark.asyncio
async def test_invalid_cached_discovery_is_evicted() -> None:
    cache = MemoryPlatformDiscoveryCache()
    document = PlatformDiscoveryDocument.model_validate_json(json.dumps(discovery()))
    unsupported = PlatformDiscoveryDocument.model_validate_json(
        json.dumps(
            discovery(
                identity={
                    "did_methods": ["did:key"],
                    "did_url_template": ("https://platform.example/agents/{agent_did_id}/did.json"),
                }
            )
        )
    )
    key = "https://platform.example/.well-known/aep-platform"
    for entry in (
        PlatformDiscoveryCacheEntry(datetime(2026, 9, 3), document, key),
        PlatformDiscoveryCacheEntry(NOW, document, "https://other.example/platform"),
        PlatformDiscoveryCacheEntry(NOW, unsupported, key),
    ):
        await cache.save(key, entry)
        transport = QueueTransport(json_response(discovery()), json_response(listed()))
        await provider(transport, discovery_cache=cache).find_identity_by_service_did(SERVICE_DID)
        assert transport.requests[0].url == key
    await cache.delete(key)
    assert await cache.find(key) is None


@pytest.mark.asyncio
async def test_platform_command_errors_media_bounds_and_timeout() -> None:
    problem = {
        "code": "not_recognized",
        "status": 401,
        "title": "Not recognized",
        "type": "urn:aep:error:not_recognized",
    }
    for body, content_type, expected_problem in (
        (problem, AEP_PROBLEM_MEDIA_TYPE, True),
        ({**problem, "status": 403}, AEP_PROBLEM_MEDIA_TYPE, False),
        ({"invalid": True}, AEP_PROBLEM_MEDIA_TYPE, False),
        (problem, "application/json", False),
    ):
        instance = provider(
            QueueTransport(
                json_response(discovery()),
                json_response(body, status=401, headers={"Content-Type": content_type}),
            )
        )
        with pytest.raises(PlatformCommandError) as raised:
            await instance.find_identity_by_service_did(SERVICE_DID)
        assert (raised.value.problem is not None) is expected_problem
        assert raised.value.status == 401

    invalid_media = provider(
        QueueTransport(
            json_response(discovery()),
            json_response(listed(), headers={"Content-Type": "application/json"}),
        )
    )
    with pytest.raises(ValueError, match="response media type"):
        await invalid_media.find_identity_by_service_did(SERVICE_DID)

    oversized = provider(QueueTransport(json_response(discovery())), maximum_response_bytes=10)
    with pytest.raises(ValueError, match="configured limit"):
        await oversized.find_identity_by_service_did(SERVICE_DID)

    timed_out = PlatformIdentityProvider(
        PlatformIdentityProviderOptions(
            platform_url="https://platform.example",
            request_timeout=0.001,
            transport=BlockingTransport(),
        )
    )
    with pytest.raises(TimeoutError):
        await timed_out.find_identity_by_service_did(SERVICE_DID)


def test_configuration_and_url_boundaries() -> None:
    for changes, message in (
        ({"maximum_response_bytes": 0}, "response bytes"),
        ({"request_timeout": 0}, "timeout"),
        ({"request_timeout": float("inf")}, "timeout"),
        ({"clock": lambda: datetime(2026, 9, 3)}, "offset-aware"),
    ):
        with pytest.raises(ValueError, match=message):
            provider(QueueTransport(), **changes)
    for value in ("", "http://platform.example", "https://user:secret@platform.example"):
        with pytest.raises(ValueError):
            provider(QueueTransport(), platform_url=value)
    loopback = provider(
        QueueTransport(),
        allow_insecure_loopback=True,
        platform_url="http://localhost:8080/path",
    )
    assert loopback._platform_url == "http://localhost:8080/"
    assert _platform_url("platform.example/path", False) == "https://platform.example/"
    assert _valid_url("https://platform.example", False)
    assert not _valid_url("https:///missing", False)

    for path in (
        "relative",
        "//other.example/path",
        "/path?query=true",
        "/path#fragment",
        "/path/{missing}",
    ):
        with pytest.raises(ValueError, match="invalid endpoint"):
            _endpoint("https://platform.example/", path)
    assert _endpoint(
        "https://platform.example/",
        "/identities/{agent_identity_id}",
        agent_identity_id="a/b",
    ).endswith("/identities/a%2Fb")


def test_cache_and_pending_value_boundaries() -> None:
    document = PlatformDiscoveryDocument.model_validate_json(json.dumps(discovery()))
    entry = PlatformDiscoveryCacheEntry(NOW, document, "https://platform.example/platform")
    assert _cache_fresh(entry, NOW + timedelta(seconds=299))
    assert not _cache_fresh(entry, NOW + timedelta(seconds=300))
    for control in ("no-cache", "no-store", "max-age=invalid", "max-age=-1"):
        assert not _cache_fresh(replace(entry, cache_control=control), NOW)
    assert _cache_fresh(replace(entry, cache_control="max-age=999999999999999999999"), NOW)
    assert not _cache_fresh(replace(entry, cached_at=NOW + timedelta(seconds=1)), NOW)
    assert _cache_directive('public, max-age="60"', "max-age") == '"60"'
    assert _cache_directive("public", "missing") is None
    with pytest.raises(ValueError, match="timestamp"):
        _validate_cache_entry(
            replace(entry, cached_at=datetime(2026, 9, 3)),
            "https://platform.example/.well-known/aep-platform",
            False,
        )
    with pytest.raises(ValueError, match="URL"):
        _validate_cache_entry(
            replace(entry, final_url="https://other.example/platform"),
            "https://platform.example/.well-known/aep-platform",
            False,
        )
    for seconds in (0, 301):
        with pytest.raises(ValueError, match="between 1 and 300"):
            PlatformPendingSign(service_identity(), {}, seconds)


@pytest.mark.asyncio
async def test_default_owned_transport_closes_and_empty_key_fails() -> None:
    instance = PlatformIdentityProvider(
        PlatformIdentityProviderOptions(platform_url="https://platform.example")
    )
    async with instance as entered:
        assert entered is instance

    async def empty_key() -> str:
        return " "

    invalid = provider(
        QueueTransport(json_response(discovery()), json_response(listed())),
        idempotency_key=empty_key,
    )
    with pytest.raises(ValueError, match="key generation"):
        await invalid.get_or_create_identity(request())
