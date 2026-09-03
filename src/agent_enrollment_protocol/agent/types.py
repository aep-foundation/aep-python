from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Generic, Protocol, TypeVar

from agent_enrollment_protocol.core import (
    ApiKeyGrantResponse,
    BasicGrantResponse,
    ClaimValues,
    ClientAssertionClaims,
    InspectDocument,
    OAuthBearerGrantResponse,
    ProblemDetails,
    SigningAlgorithm,
)

AssertionSigner = Callable[[ClientAssertionClaims, tuple[SigningAlgorithm, ...]], Awaitable[str]]
BuiltInCredential = ApiKeyGrantResponse | BasicGrantResponse | OAuthBearerGrantResponse


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    agent_did: str
    identity_method: str
    service_did: str
    signing_algorithms: tuple[SigningAlgorithm, ...]
    metadata: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "signing_algorithms", tuple(self.signing_algorithms))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if any(not isinstance(value, SigningAlgorithm) for value in self.signing_algorithms):
            raise ValueError("signing_algorithms must contain SigningAlgorithm values")


@dataclass(frozen=True, slots=True)
class IdentityRequest:
    inspect: InspectDocument
    service_did: str
    service_url: str


class IdentityProvider(Protocol):
    async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity: ...

    async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner: ...


class IdentityStore(Protocol):
    async def find_identity(self, service_did: str) -> ServiceIdentity | None: ...

    async def save_identity(self, identity: ServiceIdentity) -> None: ...


@dataclass(frozen=True, slots=True)
class OperationKey:
    command: str
    service_did: str
    service_url: str
    credential_id: str | None = None
    grant_type: str | None = None


class IdempotencyKeyProvider(Protocol):
    async def create_key(self, operation: OperationKey) -> str: ...


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    credential_id: str
    expires_at: datetime
    grant_type: str
    issued_at: datetime
    payload: bytes = field(repr=False)
    service_did: str
    service_url: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", bytes(self.payload))
        if self.expires_at.utcoffset() is None or self.issued_at.utcoffset() is None:
            raise ValueError("credential timestamps must include a UTC offset")


class CredentialStore(Protocol):
    async def delete_credential(self, service_did: str, credential_id: str) -> None: ...

    async def find_credential(
        self, service_did: str, credential_id: str
    ) -> CredentialRecord | None: ...

    async def list_credentials(self, service_did: str) -> tuple[CredentialRecord, ...]: ...

    async def save_credential(self, credential: CredentialRecord) -> None: ...


@dataclass(frozen=True, slots=True)
class InspectCacheEntry:
    cached_at: datetime
    document: InspectDocument
    final_url: str
    cache_control: str = ""
    etag: str = ""
    last_modified: str = ""


class InspectCache(Protocol):
    async def delete_inspect(self, key: str) -> None: ...

    async def find_inspect(self, key: str) -> InspectCacheEntry | None: ...

    async def save_inspect(self, key: str, entry: InspectCacheEntry) -> None: ...


@dataclass(frozen=True, slots=True)
class Inspection:
    document: InspectDocument
    final_url: str
    inspect_url: str
    service_url: str
    cache_control: str = ""
    etag: str = ""
    last_modified: str = ""


ResultT = TypeVar("ResultT")


@dataclass(frozen=True, slots=True)
class CommandResult(Generic[ResultT]):
    body: ResultT
    status: int
    url: str


@dataclass(frozen=True, slots=True)
class EnrollOptions:
    claims: ClaimValues | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class GrantOptions:
    grant_type: str | None = None
    idempotency_key: str | None = None
    parameters: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))
    preferred_grant_types: tuple[str, ...] = ()
    requested_scopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "preferred_grant_types", tuple(self.preferred_grant_types))
        object.__setattr__(self, "parameters", _copy_parameters(self.parameters))
        object.__setattr__(self, "requested_scopes", tuple(self.requested_scopes))


@dataclass(frozen=True, slots=True)
class GrantResult:
    credential: BuiltInCredential | None = field(repr=False)
    grant_type: str
    raw: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class RevokeOptions:
    all_grant_types: bool = False
    credential_id: str | None = None
    grant_type: str | None = None
    idempotency_key: str | None = None
    parameters: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", _copy_parameters(self.parameters))


@dataclass(frozen=True, slots=True)
class WaitOptions:
    interval: float = 1.0
    timeout: float = 30.0


@dataclass(frozen=True, slots=True)
class AuthenticationOptions:
    resource: str
    carrier: str = "Authorization"
    client_assertion_only: bool = False
    credential_id: str | None = None
    grant_type: str | None = None


class AgentCommandError(Exception):
    def __init__(self, status: int, message: str, problem: ProblemDetails | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.problem = problem


class EnrollmentStateError(Exception):
    def __init__(self, status: str) -> None:
        super().__init__(f"AEP Agent identity did not become active: {status}")
        self.status = status


class ClaimRequirementsError(Exception):
    def __init__(self, missing: Sequence[str]) -> None:
        values = tuple(missing)
        super().__init__(
            "AEP Agent cannot satisfy the Service's required Claim Names: " + ", ".join(values)
        )
        self.missing = values


def _copy_parameters(parameters: Mapping[str, object]) -> Mapping[str, object]:
    if any(not isinstance(name, str) or not name for name in parameters):
        raise ValueError("AEP extension parameter names must be non-empty strings")
    return MappingProxyType(deepcopy(dict(parameters)))
