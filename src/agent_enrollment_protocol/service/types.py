from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Generic, Protocol, TypeVar

from agent_enrollment_protocol.core import (
    AgentStatus,
    AssertionOperation,
    ClaimValues,
    ClientAssertionClaims,
    EnrollmentDecisionStatus,
    EnrollRequest,
    GrantRequest,
    GrantTypeConfig,
    InspectClaims,
    OpenApiReference,
    ProblemDetails,
    RevokeRequest,
    SigningAlgorithm,
)

BodyT = TypeVar("BodyT")
StoredOperation = Callable[[], Awaitable["StoredResponse"]]
EnrollmentFactory = Callable[[], Awaitable["EnrollmentRecord"]]
HeaderValue = str | Sequence[str]


@dataclass(frozen=True, slots=True)
class ServiceResult(Generic[BodyT]):
    status: int
    body: BodyT | None = None
    content_type: str = "application/aep+json"
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    problem: ProblemDetails | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True, slots=True)
class CommandOptions:
    client_assertion: str
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class AssertionVerificationContext:
    algorithms: tuple[SigningAlgorithm, ...]
    allow_insecure_loopback: bool
    clock_tolerance: timedelta
    current_time: datetime
    idempotency_key: str | None
    operation: AssertionOperation
    resource: str | None
    service_did: str


class AssertionVerifier(Protocol):
    async def verify(
        self, assertion: str, context: AssertionVerificationContext
    ) -> ClientAssertionClaims: ...


@dataclass(frozen=True, slots=True)
class ReplayRecord:
    expires_at: int
    jwt_id: str
    subject: str


class ReplayStore(Protocol):
    async def consume(self, record: ReplayRecord, now: int) -> bool: ...


@dataclass(frozen=True, slots=True)
class EnrollmentRecord:
    agent_did: str
    claims: ClaimValues | None
    created_at: datetime
    enrollment_id: str
    owner_action_required: bool
    requirements_pending: tuple[str, ...]
    since: datetime
    status: AgentStatus
    updated_at: datetime
    verification_pending: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.agent_did or not self.enrollment_id:
            raise ValueError("AEP enrollment record requires Agent and enrollment identifiers")
        if any(
            value.utcoffset() is None for value in (self.created_at, self.since, self.updated_at)
        ):
            raise ValueError("AEP enrollment timestamps must contain UTC offsets")


class EnrollmentStore(Protocol):
    async def find(self, agent_did: str) -> EnrollmentRecord | None: ...

    async def find_or_create(
        self, agent_did: str, factory: EnrollmentFactory
    ) -> tuple[EnrollmentRecord, bool]: ...

    async def save(self, record: EnrollmentRecord) -> EnrollmentRecord: ...


@dataclass(frozen=True, slots=True)
class EnrollmentDecision:
    status: EnrollmentDecisionStatus = EnrollmentDecisionStatus.ACTIVE
    owner_action_required: bool = False
    requirements_pending: tuple[str, ...] = ()
    verification_pending: tuple[str, ...] = ()


class EnrollmentPolicy(Protocol):
    async def decide(
        self, request: EnrollRequest, current_time: datetime
    ) -> EnrollmentDecision: ...


@dataclass(frozen=True, slots=True)
class IdempotencyInput:
    agent_did: str
    command: str
    idempotency_key: str
    request_hash: str


@dataclass(frozen=True, slots=True)
class StoredResponse:
    body: bytes
    content_type: str
    created_at: datetime
    headers: Mapping[str, str]
    status: int

    def __post_init__(self) -> None:
        if self.created_at.utcoffset() is None:
            raise ValueError("AEP stored response timestamp must contain a UTC offset")
        object.__setattr__(self, "body", bytes(self.body))
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True, slots=True)
class IdempotencyResult:
    response: StoredResponse | None
    state: IdempotencyState


class IdempotencyState(StrEnum):
    CONFLICT = "conflict"
    CREATED = "created"
    REPLAYED = "replayed"


class IdempotencyStore(Protocol):
    async def execute(
        self, value: IdempotencyInput, operation: StoredOperation
    ) -> IdempotencyResult: ...


@dataclass(frozen=True, slots=True)
class GrantContext:
    agent_did: str
    enrollment: EnrollmentRecord
    grant_type: str
    current_time: datetime


@dataclass(frozen=True, slots=True)
class RevokeContext:
    agent_did: str
    enrollment: EnrollmentRecord
    grant_type: str
    current_time: datetime


class GrantTypeHandler(Protocol):
    async def grant(self, request: GrantRequest, context: GrantContext) -> bytes: ...

    async def revoke(self, request: RevokeRequest, context: RevokeContext) -> None: ...


@dataclass(frozen=True, slots=True)
class CredentialAuthenticationInput:
    headers: Mapping[str, tuple[str, ...]]
    method: str
    current_time: datetime
    url: str


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    agent_did: str
    authentication_kind: AuthenticationKind
    authentication_method: str
    credential_id: str | None = None
    grant_type: str | None = None
    scopes: tuple[str, ...] = ()


class AuthenticationKind(StrEnum):
    AEP_JWT = "aep-jwt"
    SESSION_CREDENTIAL = "session-credential"


class CredentialAuthenticator(Protocol):
    async def authenticate(
        self, request: CredentialAuthenticationInput
    ) -> AuthenticatedPrincipal | None: ...

    async def has_presentation(self, request: CredentialAuthenticationInput) -> bool: ...


@dataclass(frozen=True, slots=True)
class GrantTypeDefinition:
    grant_type: str
    handler: GrantTypeHandler
    config: GrantTypeConfig = field(default_factory=GrantTypeConfig)
    authenticator: CredentialAuthenticator | None = None


@dataclass(frozen=True, slots=True)
class ProtectedResourceRequest:
    headers: Mapping[str, HeaderValue]
    method: str
    url: str


@dataclass(frozen=True, slots=True)
class ProtectedResourceResult:
    authenticated: bool
    principal: AuthenticatedPrincipal | None = None
    response: ServiceResult[object] | None = None


@dataclass(frozen=True, slots=True)
class ClaimValueLimits:
    maximum_encoded_bytes: int = 65_536
    maximum_member_count: int = 128
    maximum_object_depth: int = 8
    maximum_string_length: int = 4_096


@dataclass(frozen=True, slots=True)
class ServiceOptions:
    service_did: str
    identity_methods: tuple[str, ...]
    verifier: AssertionVerifier
    authentication_methods: tuple[str, ...] = ()
    allow_insecure_loopback: bool = False
    claim_value_limits: ClaimValueLimits = field(default_factory=ClaimValueLimits)
    claims: InspectClaims | None = None
    clock: Callable[[], datetime] | None = None
    clock_tolerance: timedelta = timedelta(seconds=30)
    endpoint_base: str = "/aep/"
    enrollment_policy: EnrollmentPolicy | None = None
    enrollment_store: EnrollmentStore | None = None
    extensions: tuple[str, ...] = ()
    grant_types: tuple[GrantTypeDefinition, ...] = ()
    idempotency_store: IdempotencyStore | None = None
    identifier: Callable[[], str] | None = None
    inspect_url: str | None = None
    maximum_assertion_lifetime: timedelta = timedelta(minutes=5)
    openapi: OpenApiReference | None = None
    replay_store: ReplayStore | None = None
    signing_algorithms: tuple[SigningAlgorithm, ...] = (
        SigningAlgorithm.EDDSA,
        SigningAlgorithm.ES256,
    )
