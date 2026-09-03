from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Generic, Protocol, TypeVar

from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    ClientAssertionClaims,
    ManagedAgentStatus,
    PlatformAgentIdentity,
    PlatformAgentIdentityListResponse,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignRequest,
    PlatformSignResponse,
    PlatformVerificationRequest,
    ProblemDetails,
    SigningAlgorithm,
)

BodyT = TypeVar("BodyT")


@dataclass(frozen=True, slots=True)
class PlatformResult(Generic[BodyT]):
    status: int
    body: BodyT | None = None
    content_type: str = AEP_MEDIA_TYPE
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    problem: ProblemDetails | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True, slots=True)
class RequestContext:
    principal: str
    idempotency_key: str | None = None
    authorization: str | None = None
    request_id: str | None = None
    current_time: datetime | None = None


@dataclass(frozen=True, slots=True)
class IdentityRecord:
    agent_did: str
    agent_did_id: str
    agent_identity_id: str
    created_at: datetime
    did_document_url: str
    key_id: str
    principal: str
    service_did: str
    signing_algorithms: tuple[SigningAlgorithm, ...]
    status: ManagedAgentStatus
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class IdentityListQuery:
    descending: bool = False
    limit: int = 100
    offset: int = 0
    service_did: str | None = None
    status: ManagedAgentStatus | None = None


@dataclass(frozen=True, slots=True)
class IdentityListResult:
    identities: tuple[IdentityRecord, ...]
    total: int


IdentityFactory = Callable[[], Awaitable[IdentityRecord]]


class IdentityStore(Protocol):
    async def find_or_create(
        self, principal: str, service_did: str, factory: IdentityFactory
    ) -> tuple[IdentityRecord, bool]: ...

    async def find_by_agent_did(self, agent_did: str) -> IdentityRecord | None: ...

    async def find_by_agent_did_id(self, agent_did_id: str) -> IdentityRecord | None: ...

    async def get(self, agent_identity_id: str) -> IdentityRecord | None: ...

    async def list(self, principal: str, query: IdentityListQuery) -> IdentityListResult: ...

    async def update_status(
        self, agent_identity_id: str, status: ManagedAgentStatus, updated_at: datetime
    ) -> IdentityRecord | None: ...


@dataclass(frozen=True, slots=True)
class DidVerificationMethod:
    controller: str
    id: str
    public_key_jwk: Mapping[str, Any]
    type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "public_key_jwk", MappingProxyType(dict(self.public_key_jwk)))


class KeyStore(Protocol):
    async def create_key(self, identity: IdentityRecord) -> None: ...

    async def did_verification_method(self, identity: IdentityRecord) -> DidVerificationMethod: ...

    async def sign(self, identity: IdentityRecord, claims: ClientAssertionClaims) -> str: ...

    async def verification_key(self, identity: IdentityRecord) -> Any: ...


class ServiceDidResolver(Protocol):
    async def resolve(self, service_did: str) -> bool: ...


class AuthorizationOperation(StrEnum):
    GET_IDENTITY = "get-identity"
    LIST_IDENTITIES = "list-identities"
    PROVISION = "provision-identity"
    SIGN = "sign"
    UPDATE_IDENTITY = "update-identity"
    VERIFY = "verify"


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    operation: AuthorizationOperation
    identity: IdentityRecord | None = None
    lifecycle_request: PlatformLifecycleRequest | None = None
    list_query: IdentityListQuery | None = None
    provision_request: PlatformProvisionRequest | None = None
    sign_request: PlatformSignRequest | None = None
    verification_request: PlatformVerificationRequest | None = None


class Authorizer(Protocol):
    async def authorize(self, request: AuthorizationRequest, context: RequestContext) -> bool: ...


class LifecyclePolicy(Protocol):
    async def can_sign(self, identity: IdentityRecord, context: RequestContext) -> bool: ...

    async def can_transition(
        self,
        identity: IdentityRecord,
        status: ManagedAgentStatus,
        context: RequestContext,
    ) -> bool: ...

    async def can_verify(self, identity: IdentityRecord, context: RequestContext) -> bool: ...


class ReplayStore(Protocol):
    async def consume(self, key: str, expires_at: datetime, now: datetime) -> bool: ...


class IdempotentOperation(StrEnum):
    HOSTED_VERIFICATION = "hosted_verification"
    PROVISION = "provision"
    SIGN = "sign"


@dataclass(frozen=True, slots=True)
class StoredResponse:
    status: int
    content_type: str
    body: bytes
    created_at: datetime
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True, slots=True)
class PlatformIdempotencyInput:
    idempotency_key: str
    operation: IdempotentOperation
    principal: str
    request_hash: str


class PlatformIdempotencyState(StrEnum):
    CONFLICT = "conflict"
    CREATED = "created"
    REPLAYED = "replayed"


@dataclass(frozen=True, slots=True)
class PlatformIdempotencyResult:
    response: StoredResponse | None
    state: PlatformIdempotencyState


StoredOperation = Callable[[], Awaitable[StoredResponse]]


class PlatformIdempotencyStore(Protocol):
    async def execute(
        self, value: PlatformIdempotencyInput, operation: StoredOperation
    ) -> PlatformIdempotencyResult: ...


@dataclass(frozen=True, slots=True)
class SignHandlerInput:
    identity: IdentityRecord
    request: PlatformSignRequest


SignHandler = Callable[
    [SignHandlerInput, RequestContext],
    Awaitable[PlatformResult[PlatformSignResponse] | None],
]


@dataclass(frozen=True, slots=True)
class DiscoveryOptions:
    endpoint_base: str
    lifecycle_endpoint: str
    list_endpoint: str
    platform_name: str
    provision_endpoint: str
    sign_endpoint: str
    hosted_verification_endpoint: str | None = None
    platform_did: str | None = None


@dataclass(frozen=True, slots=True)
class PlatformOptions:
    authorizer: Authorizer
    did_host: str
    did_url_template: str
    discovery: DiscoveryOptions
    key_store: KeyStore
    service_did_resolver: ServiceDidResolver
    signing_algorithms: tuple[SigningAlgorithm, ...]
    agent_did_id_generator: Callable[[], str] | None = None
    clock: Callable[[], datetime] | None = None
    default_lifetime: timedelta = timedelta(seconds=300)
    did_path_prefix: str = "agents"
    hosted_verification: bool = False
    identifier: Callable[[], str] | None = None
    idempotency_store: PlatformIdempotencyStore | None = None
    identity_store: IdentityStore | None = None
    lifecycle_policy: LifecyclePolicy | None = None
    maximum_lifetime: timedelta = timedelta(seconds=300)
    replay_store: ReplayStore | None = None
    sign_handler: SignHandler | None = None


def identity_response(record: IdentityRecord) -> PlatformAgentIdentity:
    return PlatformAgentIdentity(
        agent_did=record.agent_did,
        agent_identity_id=record.agent_identity_id,
        created_at=_rfc3339(record.created_at),
        did_document_url=record.did_document_url,
        key_id=record.key_id,
        service_did=record.service_did,
        signing_algorithms=record.signing_algorithms,
        status=record.status,
        updated_at=_rfc3339(record.updated_at),
    )


def list_response(result: IdentityListResult) -> PlatformAgentIdentityListResponse:
    data = tuple(identity_response(record) for record in result.identities)
    return PlatformAgentIdentityListResponse(
        count=str(len(data)), data=data, total=str(result.total)
    )


def _rfc3339(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")
