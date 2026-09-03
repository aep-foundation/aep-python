from __future__ import annotations

import asyncio
import json
import math
import secrets
from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Protocol, TypeVar
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AEP_PLATFORM_WELL_KNOWN_PATH,
    AEP_PROBLEM_MEDIA_TYPE,
    AepValidationError,
    ClientAssertionClaims,
    HttpRequest,
    HttpResponse,
    ManagedAgentStatus,
    PlatformAgentIdentity,
    PlatformAgentIdentityListResponse,
    PlatformDiscoveryDocument,
    PlatformProvisionRequest,
    PlatformSignCompleted,
    PlatformSignPending,
    PlatformSignRequest,
    ProblemDetails,
    SigningAlgorithm,
    did_web_document_url,
    media_type_essence,
    parse_json_model,
    parse_platform_sign_response,
    same_origin,
)

from .transport import AsyncHttpTransport, HttpxTransport
from .types import AssertionSigner, IdentityRequest, ServiceIdentity

Clock = Callable[[], datetime]
PlatformAuthenticationHeaders = Callable[[], Awaitable[Mapping[str, str]]]
PlatformIdempotencyKeyFactory = Callable[[], Awaitable[str]]
PlatformContextProvider = Callable[
    [ServiceIdentity, ClientAssertionClaims], Awaitable[Mapping[str, object] | None]
]
ResponseT = TypeVar("ResponseT")


@dataclass(frozen=True, slots=True)
class PlatformDiscoveryCacheEntry:
    cached_at: datetime
    document: PlatformDiscoveryDocument
    final_url: str
    cache_control: str = ""
    etag: str = ""
    last_modified: str = ""


class PlatformDiscoveryCache(Protocol):
    async def delete(self, key: str) -> None: ...

    async def find(self, key: str) -> PlatformDiscoveryCacheEntry | None: ...

    async def save(self, key: str, entry: PlatformDiscoveryCacheEntry) -> None: ...


class MemoryPlatformDiscoveryCache:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[str, PlatformDiscoveryCacheEntry] = {}

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._records.pop(key, None)

    async def find(self, key: str) -> PlatformDiscoveryCacheEntry | None:
        async with self._lock:
            entry = self._records.get(key)
            return _copy_cache_entry(entry) if entry is not None else None

    async def save(self, key: str, entry: PlatformDiscoveryCacheEntry) -> None:
        async with self._lock:
            self._records[key] = _copy_cache_entry(entry)


@dataclass(frozen=True, slots=True)
class PlatformPendingSign:
    identity: ServiceIdentity
    platform_context: Mapping[str, object]
    retry_after_seconds: int

    def __post_init__(self) -> None:
        if self.retry_after_seconds < 1 or self.retry_after_seconds > 300:
            raise ValueError("retry_after_seconds must be between 1 and 300")
        object.__setattr__(self, "platform_context", _copy_context(self.platform_context))


PlatformPendingSignResolver = Callable[
    [PlatformPendingSign], Awaitable[Mapping[str, object] | None]
]


class PlatformSignPendingError(Exception):
    def __init__(self, pending: PlatformPendingSign) -> None:
        super().__init__("AEP Platform signing is pending")
        self.pending = pending


class PlatformCommandError(Exception):
    def __init__(self, status: int, problem: ProblemDetails | None = None) -> None:
        message = (
            f"AEP Platform command failed: {problem.title}"
            if problem is not None
            else f"AEP Platform command failed with HTTP {status}"
        )
        super().__init__(message)
        self.status = status
        self.problem = problem


@dataclass(frozen=True, slots=True)
class PlatformIdentityProviderOptions:
    platform_url: str
    allow_insecure_loopback: bool = False
    authentication_headers: PlatformAuthenticationHeaders | None = None
    authorization: str | None = field(default=None, repr=False)
    clock: Clock = lambda: datetime.now(UTC)
    discovery_cache: PlatformDiscoveryCache | None = None
    idempotency_key: PlatformIdempotencyKeyFactory | None = None
    maximum_response_bytes: int = 1 << 20
    pending_sign_resolver: PlatformPendingSignResolver | None = None
    platform_context: PlatformContextProvider | None = None
    request_timeout: float = 30.0
    transport: AsyncHttpTransport | None = None


class PlatformIdentityProvider:
    def __init__(self, options: PlatformIdentityProviderOptions) -> None:
        if options.maximum_response_bytes < 1:
            raise ValueError("AEP Platform maximum response bytes must be positive")
        if options.request_timeout <= 0 or not math.isfinite(options.request_timeout):
            raise ValueError("AEP Platform request timeout must be positive and finite")
        self._allow_insecure_loopback = options.allow_insecure_loopback
        self._authentication_headers = options.authentication_headers
        self._authorization = options.authorization
        self._clock = _validated_clock(options.clock)
        self._discovery_cache = options.discovery_cache or MemoryPlatformDiscoveryCache()
        self._idempotency_key = options.idempotency_key or _random_idempotency_key
        self._maximum_response_bytes = options.maximum_response_bytes
        self._pending_sign_resolver = options.pending_sign_resolver
        self._platform_context = options.platform_context
        self._platform_url = _platform_url(options.platform_url, options.allow_insecure_loopback)
        self._request_timeout = options.request_timeout
        self._transport = options.transport or HttpxTransport(
            maximum_response_bytes=options.maximum_response_bytes
        )
        self._owns_transport = options.transport is None
        self._discovery_lock = asyncio.Lock()
        self._identity_lock = asyncio.Lock()
        self._clock()

    async def __aenter__(self) -> PlatformIdentityProvider:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_transport:
            await self._transport.aclose()

    async def find_identity_by_service_did(self, service_did: str) -> ServiceIdentity | None:
        PlatformProvisionRequest(service_did=service_did)
        discovery = await self._discover()
        endpoint = _endpoint(self._platform_url, discovery.document.endpoints.list)
        query = urlencode(
            {
                "descending": "true",
                "limit": "100",
                "service_did": service_did,
            }
        )
        _, _, listed = await self._command(
            "GET",
            f"{endpoint}?{query}",
            None,
            None,
            lambda body: parse_json_model(
                body, PlatformAgentIdentityListResponse, "Platform identity list"
            ),
        )
        for candidate in listed.data:
            _validate_platform_identity(candidate, self._allow_insecure_loopback)
            if (
                candidate.service_did == service_did
                and candidate.status is ManagedAgentStatus.ACTIVE
            ):
                return self._service_identity(candidate)
        return None

    async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
        if request.service_did != request.inspect.service.did:
            raise ValueError("AEP identity request does not match the inspected Service")
        if "did:web" not in request.inspect.identity.methods:
            raise ValueError("AEP Service does not support Platform-hosted did:web identities")
        async with self._identity_lock:
            existing = await self.find_identity_by_service_did(request.service_did)
            if existing is not None:
                return existing
            discovery = await self._discover()
            endpoint = _endpoint(self._platform_url, discovery.document.endpoints.provision)
            key = await self._new_idempotency_key()
            provision = PlatformProvisionRequest(service_did=request.service_did)
            _, _, created = await self._command(
                "POST",
                endpoint,
                key,
                provision.to_wire(),
                lambda body: parse_json_model(
                    body, PlatformAgentIdentity, "Platform provision response"
                ),
            )
            _validate_platform_identity(created, self._allow_insecure_loopback)
            if (
                created.service_did != request.service_did
                or created.status is not ManagedAgentStatus.ACTIVE
            ):
                raise ValueError(
                    "AEP Platform provisioned an identity outside the requested Service scope"
                )
            identity = self._service_identity(created)
            return identity

    async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
        self._validate_owned_identity(identity)

        async def signer(
            claims: ClientAssertionClaims, algorithms: tuple[SigningAlgorithm, ...]
        ) -> str:
            if (
                claims.iss != identity.agent_did
                or claims.sub != identity.agent_did
                or claims.aud != identity.service_did
            ):
                raise ValueError("AEP Platform signer received claims for another identity")
            if not set(identity.signing_algorithms).intersection(algorithms):
                raise ValueError("AEP Platform and Service have no compatible signing algorithm")
            context: Mapping[str, object] | None = None
            if self._platform_context is not None:
                context = await self._platform_context(identity, claims)
            previous_key: str | None = None
            while True:
                key = await self._new_idempotency_key()
                if key == previous_key:
                    raise ValueError(
                        "AEP Platform pending Sign stages require distinct idempotency keys"
                    )
                response = await self._sign(identity, claims, context, key)
                if isinstance(response, PlatformSignCompleted):
                    return response.client_assertion
                pending = PlatformPendingSign(
                    identity=identity,
                    platform_context=response.platform_context or {},
                    retry_after_seconds=int(response.retry_after_seconds),
                )
                if self._pending_sign_resolver is None:
                    raise PlatformSignPendingError(pending)
                previous_key = key
                context = await self._pending_sign_resolver(pending)

        return signer

    async def _sign(
        self,
        identity: ServiceIdentity,
        claims: ClientAssertionClaims,
        platform_context: Mapping[str, object] | None,
        idempotency_key: str,
    ) -> PlatformSignCompleted | PlatformSignPending:
        discovery = await self._discover()
        agent_identity_id = identity.metadata.get("agent_identity_id", "")
        endpoint = _endpoint(
            self._platform_url,
            discovery.document.endpoints.sign,
            agent_identity_id=agent_identity_id,
        )
        request_data: dict[str, object] = {
            "jti": claims.jti,
            "lifetime_seconds": str(claims.exp - claims.iat),
            "op": claims.op,
            "service_did": claims.aud,
        }
        if platform_context is not None:
            request_data["platform_context"] = deepcopy(dict(platform_context))
        if claims.resource is not None:
            request_data["resource"] = claims.resource
        request = PlatformSignRequest.model_validate(request_data)
        status, headers, response = await self._command(
            "POST",
            endpoint,
            idempotency_key,
            request.to_wire(),
            parse_platform_sign_response,
        )
        if _header(headers, "retry-after") is not None:
            raise ValueError("AEP Platform Sign response included Retry-After")
        if isinstance(response, PlatformSignPending):
            if status != 202:
                raise ValueError("AEP Platform returned an invalid pending Sign status")
            return response
        if status != 200 or not _valid_completed_sign(response, identity, claims):
            raise ValueError("AEP Platform returned an invalid completed Sign response")
        return response

    async def _discover(self) -> PlatformDiscoveryCacheEntry:
        async with self._discovery_lock:
            discovery_url = urljoin(self._platform_url, AEP_PLATFORM_WELL_KNOWN_PATH)
            cached = await self._discovery_cache.find(discovery_url)
            now = self._clock()
            if cached is not None:
                try:
                    cached = _validate_cache_entry(
                        cached,
                        discovery_url,
                        self._allow_insecure_loopback,
                    )
                except ValueError:
                    await self._discovery_cache.delete(discovery_url)
                    cached = None
            if cached is not None and _cache_fresh(cached, now):
                return cached
            current = cached.final_url if cached is not None else discovery_url
            headers = {"Accept": AEP_MEDIA_TYPE}
            if cached is not None:
                if cached.etag:
                    headers["If-None-Match"] = cached.etag
                if cached.last_modified:
                    headers["If-Modified-Since"] = cached.last_modified
            redirects = 0
            while True:
                response = await self._send(HttpRequest(method="GET", url=current, headers=headers))
                if response.status in {301, 302, 303, 307, 308}:
                    location = _header(response.headers, "location")
                    if location is None:
                        raise ValueError("AEP Platform discovery redirect omitted Location")
                    if redirects >= 5:
                        raise ValueError("AEP Platform discovery exceeded five redirects")
                    target = urljoin(current, location)
                    if not _valid_url(target, self._allow_insecure_loopback) or not same_origin(
                        current, target
                    ):
                        raise ValueError("AEP Platform discovery redirect changed origin or scheme")
                    current = target
                    redirects += 1
                    continue
                entry = self._discovery_response(response, current, now, cached)
                if _cache_directive(entry.cache_control, "no-store") is not None:
                    await self._discovery_cache.delete(discovery_url)
                else:
                    await self._discovery_cache.save(discovery_url, entry)
                return entry

    def _discovery_response(
        self,
        response: HttpResponse,
        final_url: str,
        now: datetime,
        cached: PlatformDiscoveryCacheEntry | None,
    ) -> PlatformDiscoveryCacheEntry:
        if response.status == 304:
            if cached is None:
                raise ValueError("AEP Platform discovery returned 304 without a cached document")
            return PlatformDiscoveryCacheEntry(
                cached_at=now,
                document=cached.document,
                final_url=final_url,
                cache_control=_header(response.headers, "cache-control") or cached.cache_control,
                etag=_header(response.headers, "etag") or cached.etag,
                last_modified=_header(response.headers, "last-modified") or cached.last_modified,
            )
        if response.status < 200 or response.status >= 300:
            raise PlatformCommandError(response.status)
        if media_type_essence(_header(response.headers, "content-type") or "") != AEP_MEDIA_TYPE:
            raise ValueError("AEP Platform discovery response media type is invalid")
        _bounded(response.body, self._maximum_response_bytes)
        document = parse_json_model(
            response.body, PlatformDiscoveryDocument, "Platform discovery document"
        )
        if "did:web" not in document.identity.did_methods:
            raise ValueError("AEP Platform does not advertise did:web")
        return PlatformDiscoveryCacheEntry(
            cached_at=now,
            document=document,
            final_url=final_url,
            cache_control=_header(response.headers, "cache-control") or "",
            etag=_header(response.headers, "etag") or "",
            last_modified=_header(response.headers, "last-modified") or "",
        )

    async def _command(
        self,
        method: str,
        url: str,
        idempotency_key: str | None,
        body: Mapping[str, object] | None,
        parser: Callable[[bytes], ResponseT],
    ) -> tuple[int, Mapping[str, str], ResponseT]:
        headers = await self._headers()
        headers["Accept"] = AEP_MEDIA_TYPE
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = AEP_MEDIA_TYPE
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        response = await self._send(HttpRequest(method=method, url=url, headers=headers, body=data))
        _bounded(response.body, self._maximum_response_bytes)
        if response.status < 200 or response.status >= 300:
            problem = None
            if (
                media_type_essence(_header(response.headers, "content-type") or "")
                == AEP_PROBLEM_MEDIA_TYPE
            ):
                try:
                    candidate = parse_json_model(response.body, ProblemDetails, "Problem Details")
                    if candidate.status == response.status:
                        problem = candidate
                except AepValidationError:
                    pass
            raise PlatformCommandError(response.status, problem)
        if media_type_essence(_header(response.headers, "content-type") or "") != AEP_MEDIA_TYPE:
            raise ValueError("AEP Platform response media type is invalid")
        return response.status, response.headers, parser(response.body)

    async def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._authorization:
            headers["Authorization"] = self._authorization
        if self._authentication_headers is not None:
            supplied = await self._authentication_headers()
            for name, value in supplied.items():
                if name.lower() in {"accept", "content-type", "idempotency-key"}:
                    continue
                _set_header(headers, name, value)
        return headers

    async def _send(self, request: HttpRequest) -> HttpResponse:
        return await asyncio.wait_for(self._transport.send(request), timeout=self._request_timeout)

    async def _new_idempotency_key(self) -> str:
        key = await self._idempotency_key()
        if not key.strip():
            raise ValueError("AEP Platform idempotency key generation failed")
        return key

    def _service_identity(self, value: PlatformAgentIdentity) -> ServiceIdentity:
        return ServiceIdentity(
            agent_did=value.agent_did,
            identity_method="did:web",
            service_did=value.service_did,
            signing_algorithms=value.signing_algorithms,
            metadata={
                "agent_identity_id": value.agent_identity_id,
                "created_at": value.created_at,
                "did_document_url": value.did_document_url,
                "key_id": value.key_id,
                "platform_url": self._platform_url,
                "status": value.status.value,
                "updated_at": value.updated_at,
            },
        )

    def _validate_owned_identity(self, identity: ServiceIdentity) -> None:
        if (
            identity.metadata.get("platform_url") != self._platform_url
            or not identity.metadata.get("agent_identity_id")
            or identity.metadata.get("status") != ManagedAgentStatus.ACTIVE.value
            or identity.identity_method != "did:web"
            or not identity.agent_did.startswith("did:web:")
            or identity.metadata.get("key_id") != identity.agent_did
            or not identity.signing_algorithms
        ):
            raise ValueError("AEP identity is not an active identity from this Platform")
        expected = did_web_document_url(
            identity.agent_did,
            allow_insecure_loopback=self._allow_insecure_loopback,
        )
        if identity.metadata.get("did_document_url") != expected:
            raise ValueError("AEP Platform DID document URL does not match the Agent DID")


async def _random_idempotency_key() -> str:
    return secrets.token_hex(16)


def _platform_url(value: str, allow_insecure_loopback: bool) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("invalid AEP Platform URL")
    if "://" not in raw:
        raw = f"https://{raw}"
    if not _valid_url(raw, allow_insecure_loopback):
        raise ValueError("AEP Platform URLs require HTTPS")
    parsed = urlsplit(raw)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _valid_url(value: str, allow_insecure_loopback: bool) -> bool:
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        return False
    if parsed.scheme == "https":
        return True
    return (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )


def _endpoint(platform_url: str, path: str, *, agent_identity_id: str | None = None) -> str:
    if agent_identity_id is not None:
        path = path.replace("{agent_identity_id}", quote(agent_identity_id, safe=""))
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "{" in path
    ):
        raise ValueError("AEP Platform advertised an invalid endpoint")
    return urljoin(platform_url, path)


def _validate_platform_identity(
    value: PlatformAgentIdentity, allow_insecure_loopback: bool
) -> None:
    if (
        not value.agent_did.startswith("did:web:")
        or value.key_id != value.agent_did
        or not value.signing_algorithms
    ):
        raise ValueError("AEP Platform returned an invalid identity")
    expected = did_web_document_url(
        value.agent_did, allow_insecure_loopback=allow_insecure_loopback
    )
    if value.did_document_url != expected:
        raise ValueError("AEP Platform DID document URL does not match the Agent DID")


def _valid_completed_sign(
    response: PlatformSignCompleted,
    identity: ServiceIdentity,
    claims: ClientAssertionClaims,
) -> bool:
    issued_at = datetime.fromisoformat(response.issued_at.replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(response.expires_at.replace("Z", "+00:00"))
    return (
        response.agent_did == identity.agent_did
        and response.service_did == identity.service_did
        and response.jti == claims.jti
        and int((expires_at - issued_at).total_seconds()) == claims.exp - claims.iat
    )


def _copy_cache_entry(entry: PlatformDiscoveryCacheEntry) -> PlatformDiscoveryCacheEntry:
    return PlatformDiscoveryCacheEntry(
        cached_at=entry.cached_at,
        document=entry.document.model_copy(deep=True),
        final_url=entry.final_url,
        cache_control=entry.cache_control,
        etag=entry.etag,
        last_modified=entry.last_modified,
    )


def _copy_context(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(deepcopy(dict(value)))


def _validate_cache_entry(
    entry: PlatformDiscoveryCacheEntry,
    discovery_url: str,
    allow_insecure_loopback: bool,
) -> PlatformDiscoveryCacheEntry:
    if entry.cached_at.utcoffset() is None:
        raise ValueError("cached AEP Platform discovery timestamp has no UTC offset")
    if not _valid_url(entry.final_url, allow_insecure_loopback) or not same_origin(
        entry.final_url, discovery_url
    ):
        raise ValueError("cached AEP Platform discovery URL is invalid")
    document = parse_json_model(
        json.dumps(entry.document.to_wire()),
        PlatformDiscoveryDocument,
        "Platform discovery document",
    )
    if "did:web" not in document.identity.did_methods:
        raise ValueError("AEP Platform does not advertise did:web")
    return PlatformDiscoveryCacheEntry(
        cached_at=entry.cached_at,
        document=document,
        final_url=entry.final_url,
        cache_control=entry.cache_control,
        etag=entry.etag,
        last_modified=entry.last_modified,
    )


def _cache_fresh(entry: PlatformDiscoveryCacheEntry, now: datetime) -> bool:
    if any(
        _cache_directive(entry.cache_control, directive) is not None
        for directive in ("no-cache", "no-store")
    ):
        return False
    maximum_age = _cache_directive(entry.cache_control, "max-age")
    if maximum_age is None:
        seconds = 300
    else:
        try:
            seconds = int(maximum_age.strip('"'))
        except ValueError:
            return False
        if seconds < 0:
            return False
    elapsed = (now - entry.cached_at).total_seconds()
    return 0 <= elapsed < seconds


def _cache_directive(value: str, name: str) -> str | None:
    for item in value.split(","):
        key, separator, content = item.strip().partition("=")
        if key.lower() == name.lower():
            return content if separator else ""
    return None


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def _set_header(headers: dict[str, str], name: str, value: str) -> None:
    existing = next((key for key in headers if key.lower() == name.lower()), None)
    if existing is not None:
        del headers[existing]
    headers[name] = value


def _bounded(body: bytes, maximum: int) -> None:
    if len(body) > maximum:
        raise ValueError("AEP Platform response exceeds the configured limit")


def _validated_clock(clock: Clock) -> Clock:
    def current() -> datetime:
        value = clock()
        if value.utcoffset() is None:
            raise ValueError("AEP Platform clock must return an offset-aware datetime")
        return value

    return current
