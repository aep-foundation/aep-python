from __future__ import annotations

import re
from copy import deepcopy
from datetime import date, datetime
from email.errors import HeaderParseError
from email.headerregistry import Address
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationInfo,
    model_validator,
)

from .constants import AEP_SIGNING_ALGORITHMS, AEP_VERSION

IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CLAIM_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
IDENTITY_METHOD_PATTERN = re.compile(r"^[a-z0-9]+(?::[a-z0-9]+)*(?:-[a-z0-9]+)*$")
VERSION_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
E164_PATTERN = re.compile(r"^\+[1-9][0-9]{1,14}$")
COUNTRY_PATTERN = re.compile(r"^[A-Z]{2}$")
BODY_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ERROR_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
HTTP_FIELD_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
NON_NEGATIVE_INTEGER_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)$")
POSITIVE_SECONDS_PATTERN = re.compile(r"^(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$")
RFC3339_DATETIME_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
URI_SCHEME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


StringTuple = Annotated[tuple[str, ...], BeforeValidator(_as_tuple)]


class Command(StrEnum):
    INSPECT = "inspect"
    ENROLL = "enroll"
    GRANT = "grant"
    REVOKE = "revoke"
    STATUS = "status"


class AssertionOperation(StrEnum):
    ENROLL = "enroll"
    GRANT = "grant"
    REVOKE = "revoke"
    STATUS = "status"
    AUTHENTICATE = "authenticate"


class AgentStatus(StrEnum):
    ACTIVE = "active"
    PENDING = "pending"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"
    UNAVAILABLE = "unavailable"


class EnrollmentDecisionStatus(StrEnum):
    ACTIVE = "active"
    PENDING = "pending"
    REJECTED = "rejected"


class ManagedAgentStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class SigningAlgorithm(StrEnum):
    EDDSA = "EdDSA"
    ES256 = "ES256"


class OpenApiTrailingSlash(StrEnum):
    STRICT = "strict"
    EQUIVALENT = "equivalent"


class AuthorizationCarrier(StrEnum):
    STANDARD = "Authorization"
    DEDICATED = "AEP-Authorization"


class AuthorizationScheme(StrEnum):
    AEP = "AEP"
    BEARER = "Bearer"
    BASIC = "Basic"


class AepModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        populate_by_name=True,
        strict=True,
        validate_default=True,
    )
    nullable_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_null(cls, value: Any) -> Any:
        if isinstance(value, dict):
            known_fields = {field.alias or name for name, field in cls.model_fields.items()}
            for field, member in value.items():
                if member is None and field in known_fields and field not in cls.nullable_fields:
                    raise ValueError(f"{field} must be omitted instead of null")
            return deepcopy(value)
        return value

    def to_wire(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_unset=True, mode="json")


class ClosedAepModel(AepModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
        validate_default=True,
    )


class Authentication(ClosedAepModel):
    methods: StringTuple = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def validate_methods(self) -> Self:
        _require_identifiers(self.methods, "methods", unique=True)
        return self


class Bindings(AepModel):
    supported: StringTuple = Field(min_length=1)

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        _require_identifiers(self.supported, "supported")
        if "http" not in self.supported:
            raise ValueError("supported must advertise http")
        return self


class InspectClaims(AepModel):
    required: StringTuple | None = None
    preferred: StringTuple | None = None
    optional: StringTuple | None = None

    @model_validator(mode="after")
    def validate_claim_names(self) -> Self:
        for values in (self.required, self.preferred, self.optional):
            if values is not None and any(
                CLAIM_NAME_PATTERN.fullmatch(value) is None for value in values
            ):
                raise ValueError("claim names use the registered claim-name syntax")
        return self


class GrantTypeConfig(AepModel):
    supports_per_credential_revoke: Literal["true", "false"] | None = None


class Commands(AepModel):
    supported: StringTuple = Field(min_length=1)
    grant_types: StringTuple | None = None
    grant_types_config: dict[str, GrantTypeConfig] | None = None

    @model_validator(mode="after")
    def validate_commands(self) -> Self:
        _require_identifiers(self.supported, "supported")
        if "inspect" not in self.supported:
            raise ValueError("supported must advertise inspect")
        if "authenticate" in self.supported:
            raise ValueError("authenticate is an assertion operation, not a command")
        grant_types = self.grant_types or ()
        _require_identifiers(grant_types, "grant_types")
        if ({"grant", "revoke"} & set(self.supported)) and not grant_types:
            raise ValueError("grant_types is required when grant or revoke is advertised")
        if self.grant_types_config is not None:
            for grant_type in self.grant_types_config:
                if (
                    IDENTIFIER_PATTERN.fullmatch(grant_type) is None
                    or grant_type not in grant_types
                ):
                    raise ValueError("grant_types_config keys must name advertised grant types")
        return self


class CoreConfiguration(AepModel):
    signing_algorithms: StringTuple = Field(min_length=1)

    @model_validator(mode="after")
    def validate_algorithms(self) -> Self:
        if not set(AEP_SIGNING_ALGORITHMS).issubset(self.signing_algorithms):
            raise ValueError("signing_algorithms must advertise EdDSA and ES256")
        return self


class Extensions(AepModel):
    supported: StringTuple | None = None

    @model_validator(mode="after")
    def validate_extensions(self) -> Self:
        if self.supported is not None and any(
            not _is_absolute_uri(value) for value in self.supported
        ):
            raise ValueError("supported extensions must be absolute URIs")
        return self


class OpenApiPathMatching(ClosedAepModel):
    trailing_slash: OpenApiTrailingSlash


class OpenApiReference(ClosedAepModel):
    url: str = Field(min_length=1)
    path_matching: OpenApiPathMatching

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if any(character.isspace() for character in self.url):
            raise ValueError("url must be a URI-reference")
        return self


class HttpConfiguration(AepModel):
    endpoint_base: str | None = None
    openapi: OpenApiReference | None = None

    @model_validator(mode="after")
    def validate_endpoint_base(self) -> Self:
        if self.endpoint_base is not None and (
            not self.endpoint_base.startswith("/") or self.endpoint_base.startswith("//")
        ):
            raise ValueError("endpoint_base must be an origin-relative absolute path")
        return self


class Identity(AepModel):
    methods: StringTuple

    @model_validator(mode="after")
    def validate_methods(self) -> Self:
        if any(IDENTITY_METHOD_PATTERN.fullmatch(value) is None for value in self.methods):
            raise ValueError("identity methods use the registered identifier syntax")
        return self


class ServiceIdentity(AepModel):
    did: str

    @model_validator(mode="after")
    def validate_did(self) -> Self:
        if not self.did.startswith("did:"):
            raise ValueError("did must be a DID")
        return self


class InspectDocument(AepModel):
    aep_version: str
    authentication: Authentication | None = None
    bindings: Bindings
    claims: InspectClaims | None = None
    commands: Commands
    core: CoreConfiguration
    extensions: Extensions | None = None
    http: HttpConfiguration
    identity: Identity
    service: ServiceIdentity

    @model_validator(mode="after")
    def validate_document(self) -> Self:
        if VERSION_PATTERN.fullmatch(self.aep_version) is None:
            raise ValueError("aep_version must use major.minor syntax")
        if self.aep_version.split(".", 1)[0] != AEP_VERSION.split(".", 1)[0]:
            raise ValueError(f"unsupported AEP major version: {self.aep_version}")
        authenticated = {"enroll", "grant", "revoke", "status"} & set(self.commands.supported)
        if authenticated and not self.identity.methods:
            raise ValueError("identity.methods is required for authenticated commands")
        return self


class ContactAddressPrimary(AepModel):
    city: str | None = None
    country: str
    first_name: str
    last_name: str
    line1: str
    line2: str | None = None
    line3: str | None = None
    postcode: str | None = None
    region: str | None = None

    @model_validator(mode="after")
    def validate_address(self) -> Self:
        for name in ("country", "first_name", "last_name", "line1"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        if self.city is not None and not self.city:
            raise ValueError("city must not be empty")
        if COUNTRY_PATTERN.fullmatch(self.country) is None:
            raise ValueError("country must contain two uppercase ASCII letters")
        if "postal_code" in (self.model_extra or {}):
            raise ValueError("use postcode instead of postal_code")
        return self


class ClaimValues(AepModel):
    contact_address_primary: ContactAddressPrimary | None = Field(
        default=None, alias="contact.address.primary"
    )
    contact_email: str | None = Field(default=None, alias="contact.email")
    contact_mobile: str | None = Field(default=None, alias="contact.mobile")
    person_birthdate: str | None = Field(default=None, alias="person.birthdate")
    person_first_name: str | None = Field(default=None, alias="person.first_name")
    person_last_name: str | None = Field(default=None, alias="person.last_name")
    person_username: str | None = Field(default=None, alias="person.username")

    @model_validator(mode="after")
    def validate_claims(self) -> Self:
        non_empty = (
            self.person_first_name,
            self.person_last_name,
            self.person_username,
        )
        if any(value == "" for value in non_empty if value is not None):
            raise ValueError("registered person claims must not be empty")
        if self.contact_email is not None and not _is_mailbox(self.contact_email):
            raise ValueError("contact.email must be an RFC 5321 Mailbox")
        if self.contact_mobile is not None and E164_PATTERN.fullmatch(self.contact_mobile) is None:
            raise ValueError("contact.mobile must use E.164 form")
        if self.person_birthdate is not None:
            try:
                parse_full_date(self.person_birthdate)
            except ValueError as error:
                raise ValueError("person.birthdate must be an RFC 3339 full-date") from error
        return self


class EnrollRequest(AepModel):
    agent_did: str = Field(min_length=1)
    claims: ClaimValues | None = None
    idempotency_key: str | None = Field(default=None, min_length=1)


class LifecycleResponse(AepModel):
    status: AgentStatus
    owner_action_required: Literal["true", "false"] | None = None
    verification_pending: StringTuple | None = None
    requirements_pending: StringTuple | None = None

    @model_validator(mode="after")
    def validate_pending_values(self) -> Self:
        for name in ("verification_pending", "requirements_pending"):
            values = getattr(self, name)
            if values is not None and (not values or any(not value for value in values)):
                raise ValueError(f"{name} must contain unique non-empty values")
            if values is not None and len(set(values)) != len(values):
                raise ValueError(f"{name} must contain unique non-empty values")
        return self

    def to_wire(self) -> dict[str, Any]:
        wire = super().to_wire()
        if wire.get("owner_action_required") == "false":
            wire.pop("owner_action_required")
        return wire


class EnrollResponse(LifecycleResponse):
    pass


class StatusResponse(LifecycleResponse):
    since: str | None = None

    @model_validator(mode="after")
    def validate_since(self) -> Self:
        if self.since is not None:
            _require_datetime(self.since, "since")
        return self


class GrantRequest(AepModel):
    grant_type: str = Field(min_length=1)
    requested_scopes: StringTuple | None = None


class RevokeRequest(AepModel):
    grant_type: str | None = Field(default=None, min_length=1)
    credential_id: str | None = Field(default=None, min_length=1)
    all_grant_types: Literal["true"] | None = None

    @model_validator(mode="after")
    def validate_selector(self) -> Self:
        valid = (
            self.grant_type is not None
            and self.all_grant_types is None
            and (self.credential_id is None or self.credential_id != "")
        ) or (
            self.all_grant_types == "true"
            and self.grant_type is None
            and self.credential_id is None
        )
        if not valid or (self.credential_id is not None and self.grant_type is None):
            raise ValueError(
                "expected grant_type, grant_type with credential_id, or all_grant_types"
            )
        return self


class RevokeResponse(ClosedAepModel):
    pass


class ClientAssertionClaims(AepModel):
    aud: str = Field(min_length=1)
    exp: int
    iat: int
    iss: str = Field(min_length=1)
    jti: str = Field(min_length=1)
    op: AssertionOperation
    resource: str | None = None
    sub: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_assertion(self, info: ValidationInfo) -> Self:
        if self.iss != self.sub:
            raise ValueError("sub must identify the Agent DID from iss")
        if self.exp <= self.iat or self.exp - self.iat > 300:
            raise ValueError("assertion lifetime must be between 1 and 300 seconds")
        if self.op is AssertionOperation.AUTHENTICATE:
            if self.resource is None:
                raise ValueError("authenticate requires resource")
        elif self.resource is not None:
            raise ValueError("resource is only valid for authenticate")
        if self.resource is not None:
            allow_insecure = bool(
                isinstance(info.context, dict)
                and info.context.get("allow_insecure_loopback") is True
            )
            _require_resource_uri(self.resource, "resource", allow_insecure_loopback=allow_insecure)
        return self


class ProblemDetails(AepModel):
    type: str = Field(min_length=1)
    title: str = Field(min_length=1)
    status: int
    code: str = Field(min_length=1)
    detail: str | None = None
    instance: str | None = None
    owner_action_required: Literal["true"] | None = None
    verification_pending: StringTuple | None = None
    requirements_pending: StringTuple | None = None

    @model_validator(mode="after")
    def validate_problem(self) -> Self:
        if ERROR_CODE_PATTERN.fullmatch(self.code) is None:
            raise ValueError("code must use the registered AEP error-code syntax")
        if self.type != f"urn:aep:error:{self.code}":
            raise ValueError("type must be the AEP error URN matching code")
        for name in ("verification_pending", "requirements_pending"):
            values = getattr(self, name)
            if values is not None and (
                not values or any(not value for value in values) or len(set(values)) != len(values)
            ):
                raise ValueError(f"{name} must contain unique non-empty values")
        if self.code == "not_recognized" and any(
            value is not None
            for value in (
                self.owner_action_required,
                self.verification_pending,
                self.requirements_pending,
            )
        ):
            raise ValueError("not_recognized must not disclose pending metadata")
        return self


class CredentialResponse(AepModel):
    nullable_fields: ClassVar[frozenset[str]] = frozenset({"scopes"})
    credential_id: str = Field(min_length=1)
    expires_at: str
    scopes: StringTuple | None = None

    @model_validator(mode="after")
    def normalize_scopes(self) -> Self:
        _require_datetime(self.expires_at, "expires_at")
        if self.scopes is None:
            object.__setattr__(self, "scopes", ())
        return self


class OAuthBearerGrantResponse(CredentialResponse):
    access_token: str = Field(min_length=1)
    token_format: Literal["opaque", "jwt"] | None = None
    token_type: Literal["Bearer"]


class ApiKeyGrantResponse(CredentialResponse):
    api_key: str = Field(min_length=1)
    header: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_api_key(self) -> Self:
        if any(
            ord(character) < 0x21 or ord(character) > 0x7E or character in {'"', ",", ";", "\\"}
            for character in self.api_key
        ):
            raise ValueError("api_key must be an unambiguous HTTP field value")
        if HTTP_FIELD_NAME_PATTERN.fullmatch(self.header) is None:
            raise ValueError("header must be an HTTP field name")
        return self


class BasicGrantResponse(CredentialResponse):
    password: str = Field(min_length=1)
    realm: str | None = Field(default=None, min_length=1)
    username: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_basic(self) -> Self:
        if ":" in self.username or _contains_control_character(self.username):
            raise ValueError("username must not contain a colon or control character")
        if _contains_control_character(self.password):
            raise ValueError("password must not contain control characters")
        return self


class ProtectedResourceAuthorization(ClosedAepModel):
    carrier: AuthorizationCarrier
    scheme: AuthorizationScheme
    credentials: str = Field(min_length=1)


class IdempotencyMetadata(AepModel):
    idempotency_key: str = Field(min_length=1)
    agent_did: str | None = Field(default=None, min_length=1)
    first_body_hash: str | None = None
    second_body_hash: str | None = None

    @model_validator(mode="after")
    def validate_hashes(self) -> Self:
        for value in (self.first_body_hash, self.second_body_hash):
            if value is not None and BODY_HASH_PATTERN.fullmatch(value) is None:
                raise ValueError("body hashes must use lowercase sha256 form")
        return self


class OpenApiAepSecurityScheme(AepModel):
    authentication_method: str = Field(alias="x-aep-authentication-method")

    @model_validator(mode="after")
    def validate_method(self) -> Self:
        if IDENTIFIER_PATTERN.fullmatch(self.authentication_method) is None:
            raise ValueError("authentication method uses the registered identifier syntax")
        return self


class PlatformEndpoints(AepModel):
    lifecycle: str
    provision: str
    sign: str
    list: str
    hosted_verification: str | None = None

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        for value in (
            self.lifecycle,
            self.provision,
            self.sign,
            self.list,
            self.hosted_verification,
        ):
            if value is not None and (not value.startswith("/") or value.startswith("//")):
                raise ValueError("Platform endpoint paths must be origin-relative absolute paths")
        if self.lifecycle.count("{agent_identity_id}") != 1:
            raise ValueError("lifecycle must contain one {agent_identity_id} placeholder")
        if self.sign.count("{agent_identity_id}") != 1:
            raise ValueError("sign must contain one {agent_identity_id} placeholder")
        if "{" in self.provision or "{" in self.list:
            raise ValueError("provision and list must not contain path placeholders")
        if self.hosted_verification is not None and "{" in self.hosted_verification:
            raise ValueError("hosted_verification must not contain path placeholders")
        return self


class PlatformHttp(AepModel):
    endpoint_base: str

    @model_validator(mode="after")
    def validate_endpoint_base(self) -> Self:
        if (
            not self.endpoint_base.startswith("/")
            or self.endpoint_base.startswith("//")
            or "{" in self.endpoint_base
        ):
            raise ValueError("endpoint_base must be an origin-relative absolute path")
        return self


class PlatformIdentityConfiguration(AepModel):
    did_methods: StringTuple = Field(min_length=1)
    did_url_template: str

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if any(not value for value in self.did_methods) or len(set(self.did_methods)) != len(
            self.did_methods
        ):
            raise ValueError("did_methods must contain unique non-empty values")
        if self.did_url_template.count("{agent_did_id}") != 1:
            raise ValueError("did_url_template must contain one {agent_did_id} placeholder")
        _require_https_uri(
            self.did_url_template.replace("{agent_did_id}", "validation"),
            "did_url_template",
        )
        return self


class PlatformMetadata(AepModel):
    hosted_verification: bool
    name: str = Field(min_length=1)
    did: str | None = None

    @model_validator(mode="after")
    def validate_did(self) -> Self:
        if self.did is not None:
            _require_did(self.did, "did")
        return self


class PlatformSigningConfiguration(AepModel):
    algorithms: Annotated[tuple[SigningAlgorithm, ...], BeforeValidator(_as_tuple)] = Field(
        min_length=1
    )
    default_lifetime_seconds: str

    @model_validator(mode="after")
    def validate_lifetime(self) -> Self:
        if POSITIVE_SECONDS_PATTERN.fullmatch(self.default_lifetime_seconds) is None:
            raise ValueError("default_lifetime_seconds must be between 1 and 300")
        return self


class PlatformDiscoveryDocument(AepModel):
    aep_version: str
    endpoints: PlatformEndpoints
    http: PlatformHttp
    identity: PlatformIdentityConfiguration
    platform: PlatformMetadata
    signing: PlatformSigningConfiguration

    @model_validator(mode="after")
    def validate_version(self) -> Self:
        supported_major = AEP_VERSION.split(".", 1)[0]
        if (
            VERSION_PATTERN.fullmatch(self.aep_version) is None
            or self.aep_version.split(".", 1)[0] != supported_major
        ):
            raise ValueError("aep_version must use a supported major.minor version")
        if self.platform.hosted_verification != (self.endpoints.hosted_verification is not None):
            raise ValueError("hosted_verification flag and endpoint must agree")
        return self


class PlatformAgentIdentity(AepModel):
    agent_did: str
    agent_identity_id: str = Field(min_length=1)
    created_at: str
    did_document_url: str
    key_id: str = Field(min_length=1)
    service_did: str
    signing_algorithms: Annotated[tuple[SigningAlgorithm, ...], BeforeValidator(_as_tuple)] = Field(
        min_length=1
    )
    status: ManagedAgentStatus
    updated_at: str

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        _require_did(self.agent_did, "agent_did")
        _require_did(self.service_did, "service_did")
        _require_https_uri(self.did_document_url, "did_document_url")
        _require_datetime(self.created_at, "created_at")
        _require_datetime(self.updated_at, "updated_at")
        return self


class PlatformAgentIdentityListResponse(AepModel):
    count: str
    data: Annotated[tuple[PlatformAgentIdentity, ...], BeforeValidator(_as_tuple)]
    total: str

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if NON_NEGATIVE_INTEGER_PATTERN.fullmatch(self.count) is None:
            raise ValueError("count must be a non-negative decimal integer")
        if NON_NEGATIVE_INTEGER_PATTERN.fullmatch(self.total) is None:
            raise ValueError("total must be a non-negative decimal integer")
        if int(self.count) != len(self.data):
            raise ValueError("count must equal the number of data entries")
        if int(self.total) < int(self.count):
            raise ValueError("total must not be less than count")
        return self


class PlatformProvisionRequest(ClosedAepModel):
    service_did: str

    @model_validator(mode="after")
    def validate_did(self) -> Self:
        _require_did(self.service_did, "service_did")
        return self


class PlatformLifecycleRequest(ClosedAepModel):
    status: ManagedAgentStatus


class PlatformSignRequest(ClosedAepModel):
    jti: str = Field(min_length=1)
    op: AssertionOperation
    service_did: str
    lifetime_seconds: str | None = None
    platform_context: dict[str, Any] | None = None
    resource: str | None = None

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        _require_did(self.service_did, "service_did")
        _validate_operation_resource(self.op, self.resource)
        if (
            self.lifetime_seconds is not None
            and POSITIVE_SECONDS_PATTERN.fullmatch(self.lifetime_seconds) is None
        ):
            raise ValueError("lifetime_seconds must be between 1 and 300")
        return self


class PlatformSignCompleted(AepModel):
    status: Literal["completed"]
    agent_did: str
    client_assertion: str = Field(min_length=1)
    expires_at: str
    issued_at: str
    jti: str = Field(min_length=1)
    service_did: str
    platform_context: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        _require_did(self.agent_did, "agent_did")
        _require_did(self.service_did, "service_did")
        _require_datetime(self.expires_at, "expires_at")
        _require_datetime(self.issued_at, "issued_at")
        return self


class PlatformSignPending(AepModel):
    status: Literal["pending"]
    retry_after_seconds: str
    platform_context: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_retry(self) -> Self:
        if POSITIVE_SECONDS_PATTERN.fullmatch(self.retry_after_seconds) is None:
            raise ValueError("retry_after_seconds must be between 1 and 300")
        return self


PlatformSignResponse = PlatformSignCompleted | PlatformSignPending
PlatformProvisionResponse = PlatformAgentIdentity
PlatformLifecycleResponse = PlatformAgentIdentity


class PlatformVerificationRequest(ClosedAepModel):
    client_assertion: str = Field(min_length=1)
    op: AssertionOperation
    service_did: str
    resource: str | None = None

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        _require_did(self.service_did, "service_did")
        _validate_operation_resource(self.op, self.resource)
        return self


class PlatformVerificationResponse(AepModel):
    reason: Literal["not_recognized", "verified"]
    service_did: str
    verified: bool
    agent_did: str | None = None
    agent_identity_id: str | None = Field(default=None, min_length=1)
    op: AssertionOperation | None = None
    status: ManagedAgentStatus | None = None

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        _require_did(self.service_did, "service_did")
        identity_details = (self.agent_did, self.agent_identity_id, self.op, self.status)
        if self.verified:
            if self.reason != "verified":
                raise ValueError("verified and reason must agree")
            agent_did = self.agent_did
            if agent_did is None or any(value is None for value in identity_details[1:]):
                raise ValueError("verified responses require Agent identity details")
            _require_did(agent_did, "agent_did")
        elif self.reason != "not_recognized":
            raise ValueError("verified and reason must agree")
        elif any(value is not None for value in identity_details):
            raise ValueError("not_recognized responses must not disclose identity details")
        return self


def parse_rfc3339(value: str) -> datetime:
    if RFC3339_DATETIME_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid RFC 3339 date-time")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_full_date(value: str) -> date:
    return date.fromisoformat(value)


def _require_identifiers(values: tuple[str, ...], name: str, *, unique: bool = False) -> None:
    if any(IDENTIFIER_PATTERN.fullmatch(value) is None for value in values):
        raise ValueError(f"{name} uses the registered identifier syntax")
    if unique and len(set(values)) != len(values):
        raise ValueError(f"{name} must contain unique values")


def _require_datetime(value: str, name: str) -> None:
    try:
        parse_rfc3339(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an RFC 3339 date-time") from error


def _require_did(value: str, name: str) -> None:
    if not value.startswith("did:"):
        raise ValueError(f"{name} must be a DID")


def _require_https_uri(value: str, name: str) -> None:
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
        raise ValueError(f"{name} must be an absolute HTTPS URI without a fragment")


def _require_resource_uri(value: str, name: str, *, allow_insecure_loopback: bool = False) -> None:
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    secure = parsed.scheme == "https"
    loopback = (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if (not secure and not loopback) or not parsed.hostname or parsed.fragment:
        raise ValueError(f"{name} must be an absolute HTTPS URI without a fragment")


def _validate_operation_resource(op: AssertionOperation, resource: str | None) -> None:
    if op is AssertionOperation.AUTHENTICATE:
        if resource is None:
            raise ValueError("authenticate requires resource")
        _require_https_uri(resource, "resource")
    elif resource is not None:
        raise ValueError("resource is only valid for authenticate")


def _is_mailbox(value: str) -> bool:
    if len(value.encode()) > 320 or "@" not in value:
        return False
    try:
        address = Address(addr_spec=value)
    except (HeaderParseError, IndexError, ValueError):
        return False
    local, separator, domain = address.addr_spec.rpartition("@")
    if not separator or len(local.encode()) > 64 or len(domain.encode()) > 255:
        return False
    if "." not in local and local.startswith('"'):
        return True
    labels = domain.split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def _is_absolute_uri(value: str) -> bool:
    if any(character.isspace() for character in value):
        return False
    scheme, separator, remainder = value.partition(":")
    return bool(separator and remainder and URI_SCHEME_PATTERN.fullmatch(scheme) is not None)


def _contains_control_character(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
