#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import sys
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from inspect import Parameter, signature
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel

from agent_enrollment_protocol.agent import (
    Agent,
    AgentCommandError,
    AgentOptions,
    AssertionSigner,
    AuthenticationOptions,
    CredentialRecord,
    EnrollOptions,
    FetchProtectedResourceOptions,
    GrantOptions,
    PlatformCommandError,
    PlatformContextProvider,
    PlatformIdentityProvider,
    PlatformIdentityProviderOptions,
    PlatformPendingSignResolver,
    PlatformSignPendingError,
    RevokeOptions,
    ServiceIdentity,
    ServiceSession,
    fetch_protected_resource,
)
from agent_enrollment_protocol.agent.types import IdentityRequest
from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AEP_PROBLEM_MEDIA_TYPE,
    AepAuthorizationError,
    AepValidationError,
    AgentStatus,
    ApiKeyGrantResponse,
    AssertionOperation,
    AuthorizationCarrier,
    AuthorizationScheme,
    BasicGrantResponse,
    ClaimValues,
    ClientAssertionClaims,
    Command,
    EnrollRequest,
    EnrollResponse,
    GrantRequest,
    HttpRequest,
    HttpResponse,
    InspectClaims,
    InspectDocument,
    ManagedAgentStatus,
    OAuthBearerGrantResponse,
    OpenApiAepSecurityScheme,
    OpenApiTrailingSlash,
    PlatformAgentIdentity,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignCompleted,
    PlatformSignRequest,
    PlatformVerificationRequest,
    ProblemDetails,
    ProtectedResourceAuthorization,
    RevokeRequest,
    RevokeResponse,
    SigningAlgorithm,
    StatusResponse,
    VerifyClientAssertionOptions,
    authorization_header_name,
    command_path,
    decode_jwt_unverified,
    did_web_document_url,
    evaluate_claim_support,
    is_version_compatible,
    match_openapi_path,
    media_type_essence,
    normalize_endpoint_base,
    parse_authorization,
    parse_json_model,
    render_authorization,
    require_service_origin_binding,
    resolve_openapi_security,
    resolve_openapi_url,
    sign_client_assertion,
    verify_client_assertion,
)
from agent_enrollment_protocol.platform import (
    AuthorizationRequest,
    DidVerificationMethod,
    DiscoveryOptions,
    IdentityListQuery,
    IdentityRecord,
    MemoryIdentityStore,
    MemoryReplayStore,
    Platform,
    PlatformOptions,
    PlatformResult,
    RequestContext,
)
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    CommandOptions,
    EnrollmentDecision,
    EnrollmentRecord,
    GrantContext,
    GrantTypeDefinition,
    IdempotencyInput,
    MemoryEnrollmentStore,
    MemoryIdempotencyStore,
    MemoryServiceCredentialStore,
    ProtectedResourceRequest,
    RevokeContext,
    Service,
    ServiceOptions,
    StoredCredentialGrantTypeOptions,
    StoredResponse,
    stored_api_key_grant_type,
    stored_basic_grant_type,
    stored_oauth_bearer_grant_type,
)

JsonObject = dict[str, Any]
NOW = datetime(2026, 9, 3, 12, tzinfo=UTC)
AGENT_DID = "did:web:agent.example.com:agents:123"
SERVICE_DID = "did:web:api.example.com"
PLATFORM_ORIGIN = "https://p.example"
ASSERTION_KEY = ec.generate_private_key(ec.SECP256R1())

CLAIM_VALUE_CASES = frozenset(
    {
        "forward-compatible-address",
        "invalid-address",
        "invalid-birthdate",
        "invalid-country-shape",
        "invalid-email-domain",
        "invalid-email-dot-string",
        "invalid-email-format",
        "invalid-empty-email",
        "invalid-mobile",
        "invalid-value-type",
        "minimal-email",
        "quoted-email",
    }
)
INSPECT_VALIDITY_CASES = frozenset(
    {
        "authenticate-command-prohibited",
        "authenticated-command-without-identity-method",
        "authentication-method-limit",
        "command-without-inspect",
        "forward-compatible-advertisements",
        "grant-without-grant-types",
        "invalid-advertisement-identifiers",
        "invalid-openapi-reference",
        "missing-signing-algorithm",
    }
)
PROTECTED_BEHAVIOR_CASES = frozenset(
    {
        "api-key-wrong-header-rejected",
        "assertion-and-credential-failures",
        "authenticate-assertion",
        "authorization-ambiguity",
        "authorization-field-safety",
        "authorization-payment-composition",
        "operation-substitution-rejected",
        "redirect-safety",
        "unadvertised-authentication-method",
    }
)
IDEMPOTENCY_CASES = frozenset(
    {"command-header", "command-replay-conflict", "enroll-conflict", "idempotency-replay-conflict"}
)


class QueueTransport:
    def __init__(self, *responses: HttpResponse) -> None:
        self.requests: list[HttpRequest] = []
        self.responses = list(responses)

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self.responses:
            raise ValueError("AEP conformance transport received an unexpected request")
        return self.responses.pop(0)

    async def aclose(self) -> None:
        return None


class DenyAuthorizer:
    def __init__(self) -> None:
        self.operations: list[str] = []

    async def authorize(self, request: AuthorizationRequest, context: RequestContext) -> bool:
        del context
        self.operations.append(request.operation.value)
        return False


class ResolvedServiceDid:
    async def resolve(self, service_did: str) -> bool:
        return service_did.startswith("did:")


class PublicDidKeyStore:
    async def create_key(self, identity: IdentityRecord) -> None:
        del identity

    async def did_verification_method(self, identity: IdentityRecord) -> DidVerificationMethod:
        return DidVerificationMethod(
            controller=identity.agent_did,
            id=identity.key_id,
            public_key_jwk={"crv": "P-256", "kty": "EC", "x": "AQ", "y": "AQ"},
            type="JsonWebKey2020",
        )

    async def sign(self, identity: IdentityRecord, claims: ClientAssertionClaims) -> str:
        del identity, claims
        raise ValueError("denied Platform signing reached the key store")

    async def verification_key(self, identity: IdentityRecord) -> object:
        del identity
        raise ValueError("denied Platform verification reached the key store")


def json_response(
    value: object, status: int = 200, content_type: str = AEP_MEDIA_TYPE
) -> HttpResponse:
    return HttpResponse(
        status=status,
        headers={"Content-Type": content_type},
        body=json.dumps(value, separators=(",", ":")).encode(),
    )


def platform_discovery() -> JsonObject:
    return {
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
            "did_url_template": "https://p.example/a/{agent_did_id}/did.json",
        },
        "platform": {
            "did": "did:web:p.example",
            "hosted_verification": True,
            "name": "Example Platform",
        },
        "signing": {"algorithms": ["ES256"], "default_lifetime_seconds": "300"},
    }


def platform_identity(service_did: str, suffix: str = "4Yf7p2xQd9") -> JsonObject:
    return {
        "agent_did": f"did:web:p.example:a:{suffix}",
        "agent_identity_id": f"pai_{suffix}",
        "created_at": "2026-07-06T12:00:00Z",
        "did_document_url": f"https://p.example/a/{suffix}/did.json",
        "key_id": f"did:web:p.example:a:{suffix}",
        "service_did": service_did,
        "signing_algorithms": ["ES256"],
        "status": "active",
        "updated_at": "2026-07-06T12:00:00Z",
    }


def platform_verification_assertion(identity: IdentityRecord) -> str:
    header = {"alg": "ES256", "kid": identity.agent_did, "typ": "JWT"}
    claims = {
        "aud": identity.service_did,
        "exp": int((NOW + timedelta(minutes=1)).timestamp()),
        "iat": int(NOW.timestamp()),
        "iss": identity.agent_did,
        "jti": "verification",
        "op": "enroll",
        "sub": identity.agent_did,
    }

    def encode(value: object) -> str:
        data = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    return f"{encode(header)}.{encode(claims)}.signature"


def platform_identity_request(service_did: str) -> IdentityRequest:
    document = minimal_document("1.0")
    document["identity"] = {"methods": ["did:web"]}
    document["service"] = {"did": service_did}
    inspection = parse_json_model(json.dumps(document), InspectDocument, "Inspect document")
    return IdentityRequest(
        inspect=inspection,
        service_did=service_did,
        service_url="https://api.service.example/",
    )


def platform_provider(
    transport: QueueTransport,
    *,
    idempotency_keys: list[str] | None = None,
    pending_resolver: PlatformPendingSignResolver | None = None,
    platform_context: PlatformContextProvider | None = None,
    clock: Callable[[], datetime] = lambda: NOW,
) -> PlatformIdentityProvider:
    keys = iter(idempotency_keys or [])

    async def idempotency_key() -> str:
        return next(keys)

    return PlatformIdentityProvider(
        PlatformIdentityProviderOptions(
            clock=clock,
            idempotency_key=idempotency_key if idempotency_keys is not None else None,
            pending_sign_resolver=pending_resolver,
            platform_context=platform_context,
            platform_url=PLATFORM_ORIGIN,
            transport=transport,
        )
    )


def valid(model: type[BaseModel], value: object) -> bool:
    try:
        parse_json_model(json.dumps(value), model, model.__name__)
    except (AepValidationError, TypeError, ValueError):
        return False
    return True


def validity(model: type[BaseModel], value: object, expected: Mapping[str, Any]) -> bool:
    return valid(model, value) is expected["valid"]


def wire(model: type[BaseModel], value: object) -> JsonObject:
    parsed = parse_json_model(json.dumps(value), model, model.__name__)
    return parsed.model_dump(by_alias=True, exclude_unset=True, mode="json")


def body_model(category: str, identifier: str) -> type[BaseModel] | None:
    if category == "enroll" and identifier.startswith("response-"):
        return EnrollResponse
    if category == "status":
        return StatusResponse
    if category == "errors" and identifier != "problem-details-validation":
        return ProblemDetails
    if category == "grant-revoke" and identifier == "revoke-response-empty":
        return RevokeResponse
    return None


def credential_model(category: str) -> type[BaseModel]:
    models: dict[str, type[BaseModel]] = {
        "credentials/api-key": ApiKeyGrantResponse,
        "credentials/basic": BasicGrantResponse,
        "credentials/oauth-bearer": OAuthBearerGrantResponse,
    }
    return models[category]


def evaluate_claims(identifier: str, case: JsonObject) -> bool:
    expected = case["expected"]
    source = case["input"]
    if identifier in CLAIM_VALUE_CASES:
        return validity(ClaimValues, source["claim_values"], expected)
    if identifier == "person-contact-catalog":
        return bool(wire(ClaimValues, expected) == expected)
    if identifier == "unknown-required-claim":
        inspection = InspectClaims(required=tuple(source["required"]))
        result = evaluate_claim_support(inspection, tuple(source["understood"]))
        return result.can_satisfy_required is expected["can_satisfy"]
    if identifier == "negotiation-compatibility":
        inspection = InspectClaims.model_validate(source["inspect"])
        submitted = ClaimValues.model_validate(source["submitted"])
        result = evaluate_claim_support(inspection, tuple(submitted.to_wire()))
        return (
            result.can_satisfy_required is expected["enrollment_requirement_satisfied"]
            and (not result.supported_preferred) is expected["omitted_preferred_allowed"]
            and expected["unknown_optional_action"] == "ignore"
            and not result.supported_optional
            and expected["unknown_preferred_action"] == "ignore"
            and not result.supported_preferred
            and expected["unknown_submitted_default_action"] == "ignore"
            and asyncio.run(exercise_claim_negotiation(source))
        )
    return False


def evaluate_assertion(identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
    if identifier == "enroll-claims":
        claims = ClientAssertionClaims(
            aud=source["service_did"],
            exp=source["expires_at"],
            iat=source["issued_at"],
            iss=source["agent_did"],
            jti=source["jti"],
            op=AssertionOperation(source["command"]),
            sub=source["agent_did"],
        )
        return bool(claims.to_wire() == expected)
    if identifier == "validation-requirements":
        return asyncio.run(exercise_assertion_requirements(source, expected))
    return False


def evaluate_problem_cases(case: JsonObject) -> bool:
    return all(
        valid(ProblemDetails, item["body"]) is item["valid"] for item in case["input"]["cases"]
    )


def minimal_document(version: str) -> JsonObject:
    return {
        "aep_version": version,
        "bindings": {"supported": ["http"]},
        "commands": {"supported": ["inspect"]},
        "core": {"signing_algorithms": ["EdDSA", "ES256"]},
        "http": {},
        "identity": {"methods": []},
        "service": {"did": "did:web:api.example.com"},
    }


def evaluate_inspect(identifier: str, case: JsonObject) -> bool:
    expected = case["expected"]
    if identifier in INSPECT_VALIDITY_CASES:
        return validity(InspectDocument, case["input"]["document"], expected)
    if identifier in {"claims-catalog-advertisement", "minimal-http"}:
        return bool(wire(InspectDocument, expected) == expected)
    if identifier == "default-endpoint-base":
        document = parse_json_model(
            json.dumps(expected["document"]), InspectDocument, "Inspect document"
        )
        endpoint = document.http.endpoint_base or "/aep/"
        return bool(normalize_endpoint_base(endpoint) == expected["endpoint_base"])
    if identifier == "protocol-version":
        supported = case["input"]["supported"]
        compatible = all(
            is_version_compatible(item["received"], item.get("supported", supported))
            is item["compatible"]
            for item in expected["cases"]
            if item["valid"]
        )
        invalid = all(
            not valid(InspectDocument, minimal_document(item["received"]))
            for item in expected["cases"]
            if not item["valid"]
        )
        return compatible and invalid
    if identifier == "service-did-origin-binding":
        source = case["input"]
        try:
            document = parse_json_model(
                json.dumps(
                    {**minimal_document("1.0"), "service": {"did": source["matching_service_did"]}}
                ),
                InspectDocument,
                "Inspect document",
            )
            require_service_origin_binding(document, source["inspect_url"])
        except ValueError:
            return False
        for name in ("mismatched_service_did", "unsupported_service_did"):
            try:
                document = parse_json_model(
                    json.dumps({**minimal_document("1.0"), "service": {"did": source[name]}}),
                    InspectDocument,
                    "Inspect document",
                )
                require_service_origin_binding(document, source["inspect_url"])
            except ValueError:
                continue
            return False
        return True
    if identifier == "transport-requirements":
        return asyncio.run(exercise_inspect_transport(case["input"], case["expected"]))
    return False


async def exercise_inspect_transport(source: JsonObject, expected: JsonObject) -> bool:
    transport = QueueTransport(
        HttpResponse(status=307, headers={"Location": source["redirect_url"]}),
        json_response(agent_document(), content_type=source["content_type"]),
    )
    session, _, _ = agent_session(inspect_transport=transport)
    inspected = await session.inspect()
    if (
        inspected.final_url != source["redirect_url"]
        or transport.requests[0].url != source["request_url"]
        or media_type_essence(source["content_type"]) != expected["media_type_essence"]
        or expected["redirect_policy"] != "same-scheme-host-effective-port"
    ):
        return False
    cases = (
        (
            "cross_origin_redirect",
            HttpResponse(status=307, headers={"Location": "https://other.example/aep"}),
        ),
        (
            "scheme_downgrade",
            HttpResponse(status=307, headers={"Location": "http://api.example.com/aep"}),
        ),
        (
            "partial_document_after_bound",
            HttpResponse(
                status=200, headers={"Content-Type": AEP_MEDIA_TYPE}, body=b"{" + b" " * (1 << 20)
            ),
        ),
    )
    for name, response in cases:
        session, _, _ = agent_session(response)
        try:
            await session.inspect()
        except ValueError:
            if expected[name] != "reject":
                return False
        else:
            return False
    return True


def evaluate_openapi(identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
    if identifier == "path-matching":
        match = match_openapi_path(
            tuple(source["templates"]),
            method=source["method"],
            path=source["path"],
            trailing_slash=OpenApiTrailingSlash.STRICT,
        )
        return match.method == expected["method"] and match.template == "/v1/orders/{id}"
    if identifier == "security-inheritance":
        scheme = parse_json_model(
            json.dumps(source["security_scheme"]), OpenApiAepSecurityScheme, "OpenAPI security"
        )
        if scheme.authentication_method != "aep-jwt":
            return False
        return _resolves_security_inheritance(expected)
    if identifier == "url-resolution":
        relative = resolve_openapi_url(source["final_inspect_url"], source["relative"])
        cross_origin = resolve_openapi_url(source["final_inspect_url"], source["cross_origin"])
        return bool(
            relative == expected["relative_resolved"] and cross_origin == source["cross_origin"]
        )
    return False


def _resolves_security_inheritance(expected: JsonObject) -> bool:
    """Drives every inheritance shape expected names (CORE-OAS-011/013/014/015)."""
    aep, key, mtls = "aepScheme", "apiKeyScheme", "mtlsScheme"
    root: tuple[dict[str, tuple[str, ...]], ...] = ({aep: ()},)
    supported = (aep, key)
    shapes: tuple[tuple[str, tuple[dict[str, tuple[str, ...]], ...] | None], ...] = (
        ("root_inherited", None),
        ("operation_empty_array", ()),
        ("empty_requirement_alternative", ({}, {aep: ()})),
        ("multiple_objects", ({aep: ()}, {key: ()})),
        ("multiple_schemes_one_object", ({aep: (), key: ()},)),
    )
    for name, operation in shapes:
        resolved = resolve_openapi_security(
            root=root, operation=operation, supported_schemes=supported
        )
        if resolved.disposition.value != expected[name]:
            return False
    # CORE-OAS-013 and CORE-OAS-015: a compound requirement with an unsatisfiable member is
    # unsupported as a whole and is never reduced to the member the Agent does support.
    unsupported = resolve_openapi_security(
        root=root, operation=({aep: (), mtls: ()},), supported_schemes=supported
    )
    return (
        not unsupported.satisfiable
        and unsupported.disposition.value == expected["unsupported_compound"]
    )


def evaluate_authorization(identifier: str, case: JsonObject) -> bool:
    expected = case["expected"]
    if identifier == "authorization-carriers":
        for value in expected.values():
            parsed = parse_authorization(
                f"{value['scheme']} {value['credentials']}", AuthorizationCarrier(value["carrier"])
            )
            if render_authorization(parsed) != (
                authorization_header_name(parsed.carrier),
                f"{value['scheme']} {value['credentials']}",
            ):
                return False
        return True
    if identifier == "credential-presentations":
        for value in expected.values():
            if "scheme" not in value:
                continue
            parsed = ProtectedResourceAuthorization(
                carrier=AuthorizationCarrier.STANDARD,
                scheme=AuthorizationScheme(value["scheme"]),
                credentials="credential",
            )
            if authorization_header_name(parsed.carrier) != value["header"]:
                return False
        return bool(expected["api-key"]["header"] == "x-api-key")
    if identifier == "inspect-authentication-methods":
        return all(
            valid(InspectDocument, {**minimal_document("1.0"), **value})
            for key, value in expected.items()
            if key != "omitted_means"
        )
    return False


AGENT_ORIGIN = "https://api.example.com"
Clock = Callable[[], datetime]


def _header(headers: Mapping[str, str], name: str) -> str | None:
    expected = name.lower()
    return next((value for key, value in headers.items() if key.lower() == expected), None)


def agent_document(
    *,
    commands: tuple[str, ...] = ("inspect",),
    methods: tuple[str, ...] = (),
    grant_types: tuple[str, ...] = (),
    api_key_header: str | None = None,
) -> JsonObject:
    document: JsonObject = {
        "aep_version": "1.0",
        "bindings": {"supported": ["http"]},
        "claims": {"optional": [], "preferred": [], "required": []},
        "commands": {"supported": list(commands)},
        "core": {"signing_algorithms": ["EdDSA", "ES256"]},
        "http": {"endpoint_base": "/aep/"},
        "identity": {"methods": ["did:web"]},
        "service": {"did": "did:web:api.example.com"},
    }
    if methods:
        document["authentication"] = {"methods": list(methods)}
    if grant_types:
        commands_value = document["commands"]
        assert isinstance(commands_value, dict)
        commands_value["grant_types"] = list(grant_types)
        commands_value["grant_types_config"] = {
            value: {"supports_per_credential_revoke": "true"} for value in grant_types
        }
        if api_key_header is not None:
            config = commands_value["grant_types_config"]
            assert isinstance(config, dict)
            config["api-key"] = {
                "header_names": [api_key_header],
                "supports_per_credential_revoke": "true",
            }
    return document


class AgentSigner:
    """An identity provider whose signer returns a well-formed assertion for its claims."""

    def __init__(self) -> None:
        self.claims: list[ClientAssertionClaims] = []

    async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
        return ServiceIdentity(
            agent_did=AGENT_DID,
            identity_method="did:web",
            service_did=request.service_did,
            signing_algorithms=(SigningAlgorithm.ES256,),
        )

    async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
        async def sign(
            claims: ClientAssertionClaims, algorithms: tuple[SigningAlgorithm, ...]
        ) -> str:
            self.claims.append(claims)
            return sign_client_assertion(
                claims, key=ASSERTION_KEY, algorithm=algorithms[0], key_id=identity.agent_did
            )

        return sign


def agent_session(
    *inspect_responses: HttpResponse,
    commands: tuple[HttpResponse, ...] = (),
    clock: Clock | None = None,
    inspect_transport: QueueTransport | None = None,
) -> tuple[ServiceSession, AgentSigner, QueueTransport]:
    provider = AgentSigner()
    command_transport = QueueTransport(*commands)
    instance = Agent(
        AgentOptions(
            clock=clock or (lambda: NOW),
            command_transport=command_transport,
            identity_provider=provider,
            inspect_transport=inspect_transport or QueueTransport(*inspect_responses),
        )
    )
    return instance.service(AGENT_ORIGIN), provider, command_transport


def inspect_response(**headers: str) -> HttpResponse:
    values = {name.replace("_", "-"): value for name, value in headers.items()}
    return HttpResponse(
        status=200,
        headers={"Content-Type": AEP_MEDIA_TYPE, **values},
        body=json.dumps(agent_document(), separators=(",", ":")).encode(),
    )


def agent_honours_discovery_caching(expected: JsonObject) -> bool:
    """Drives the five caching behaviours expected names for a public discovery document."""

    async def run() -> bool:
        return (
            await agent_reuses_within_default_freshness(int(expected["default_freshness_seconds"]))
            and expected["no_cache"] == "revalidate"
            and await agent_revalidates_no_cache()
            and expected["no_store"] == "do-not-persist"
            and await agent_discards_no_store()
            and expected["status_304"] == "reuse-validated-representation"
            and await agent_reuses_a_validated_representation()
            and expected["cache_key"] == "final-safe-redirect-url"
            and await agent_revalidates_the_final_url()
        )

    return asyncio.run(run())


async def agent_reuses_within_default_freshness(seconds: int) -> bool:
    """A response carrying no Cache-Control is reusable for the SDK's own default lifetime."""
    current = [NOW]
    transport = QueueTransport(inspect_response(), inspect_response())
    session, _, _ = agent_session(clock=lambda: current[0], inspect_transport=transport)
    await session.inspect()
    current[0] = NOW + timedelta(seconds=seconds - 1)
    await session.inspect()
    if len(transport.requests) != 1:
        return False
    current[0] = NOW + timedelta(seconds=seconds + 1)
    await session.inspect()
    return len(transport.requests) == 2


async def agent_revalidates_no_cache() -> bool:
    """no-cache stores the document but forces a conditional request before reuse."""
    transport = QueueTransport(
        inspect_response(cache_control="no-cache", etag='"inspect-1"'),
        HttpResponse(status=304, headers={}, body=b""),
    )
    session, _, _ = agent_session(inspect_transport=transport)
    await session.inspect()
    await session.inspect()
    return (
        len(transport.requests) == 2
        and _header(transport.requests[1].headers, "if-none-match") == '"inspect-1"'
    )


async def agent_discards_no_store() -> bool:
    """no-store forbids persisting the document, so the next call has nothing to revalidate."""
    transport = QueueTransport(
        inspect_response(cache_control="no-store", etag='"inspect-1"'),
        inspect_response(cache_control="no-store", etag='"inspect-1"'),
    )
    session, _, _ = agent_session(inspect_transport=transport)
    await session.inspect()
    await session.inspect()
    return (
        len(transport.requests) == 2
        and _header(transport.requests[1].headers, "if-none-match") is None
    )


async def agent_reuses_a_validated_representation() -> bool:
    """A 304 reuses the stored representation rather than returning an empty document."""
    transport = QueueTransport(
        inspect_response(cache_control="no-cache", etag='"inspect-1"'),
        HttpResponse(status=304, headers={}, body=b""),
    )
    session, _, _ = agent_session(inspect_transport=transport)
    await session.inspect()
    revalidated = await session.inspect()
    return revalidated.document.service.did == "did:web:api.example.com"


async def agent_revalidates_the_final_url() -> bool:
    """The cache is keyed on the final URL a safe redirect settled on, not the requested one."""
    final_url = f"{AGENT_ORIGIN}/discovery/aep"
    transport = QueueTransport(
        HttpResponse(status=308, headers={"Location": final_url}, body=b""),
        inspect_response(cache_control="no-cache", etag='"inspect-1"'),
        HttpResponse(status=304, headers={}, body=b""),
    )
    session, _, _ = agent_session(inspect_transport=transport)
    inspection = await session.inspect()
    await session.inspect()
    return (
        inspection.final_url == final_url
        and len(transport.requests) == 3
        and transport.requests[2].url == final_url
    )


def agent_headers(
    document: JsonObject, options: AuthenticationOptions
) -> Mapping[str, str] | Exception:
    async def run() -> Mapping[str, str] | Exception:
        session, _, _ = agent_session(json_response(document))
        try:
            return await session.authentication_headers(options)
        except (AepAuthorizationError, AepValidationError, ValueError) as error:
            return error

    return asyncio.run(run())


def agent_assertion_claims(
    document: JsonObject, options: AuthenticationOptions
) -> ClientAssertionClaims | None:
    async def run() -> ClientAssertionClaims | None:
        session, provider, _ = agent_session(json_response(document))
        try:
            await session.authentication_headers(options)
        except (AepAuthorizationError, AepValidationError, ValueError):
            return None
        return provider.claims[-1] if provider.claims else None

    return asyncio.run(run())


def evaluate_protected(identifier: str, case: JsonObject) -> bool:
    """Drives the Agent's own protected-resource behaviour.

    These mappings evaluate the Agent role: the party that selects a carrier, mints an assertion
    bound to a resource, and presents a stored credential in the field the Service selected.
    """
    source = case["input"]
    expected = case["expected"]
    if identifier == "api-key-wrong-header-rejected":
        return agent_presents_api_key_in_the_issued_header(source, expected)
    if identifier == "authenticate-assertion":
        return agent_mints_an_authenticate_assertion(expected)
    if identifier == "authorization-ambiguity":
        return agent_refuses_every_ambiguous_presentation(source, expected)
    if identifier == "authorization-field-safety":
        return agent_selects_the_named_carrier(source, expected)
    if identifier == "authorization-payment-composition":
        return agent_composes_with_a_payment_credential(expected)
    if identifier == "operation-substitution-rejected":
        return agent_binds_each_assertion_to_its_operation(expected)
    if identifier == "redirect-safety":
        return agent_rebinds_an_assertion_after_a_redirect(source, expected)
    if identifier == "unadvertised-authentication-method":
        return agent_fails_closed_without_an_advertised_method(source, expected)
    if identifier == "assertion-and-credential-failures":
        return agent_surfaces_the_service_error_code(expected)
    return False


def agent_presents_api_key_in_the_issued_header(source: JsonObject, expected: JsonObject) -> bool:
    """CORE-PR-009: an API key is presented in exactly the Service-selected header."""
    issued, presented = source["issued_header"], source["presented_header"]
    document = agent_document(
        commands=("inspect", "enroll", "grant"),
        methods=("api-key",),
        grant_types=("api-key",),
        api_key_header=issued,
    )

    async def run() -> bool:
        session, _, _ = agent_session(
            json_response(document),
            commands=(
                json_response({"status": "active"}),
                json_response(
                    {
                        "api_key": "opaque-api-key",
                        "credential_id": "credential-1",
                        "expires_at": "2027-01-01T00:00:00Z",
                        "header": issued,
                        "scopes": [],
                    }
                ),
            ),
        )
        await session.enroll()
        await session.grant(GrantOptions(grant_type="api-key"))
        headers = await session.authentication_headers(
            AuthenticationOptions(resource=f"{AGENT_ORIGIN}/orders")
        )
        names = {name.lower() for name in headers}
        # The key goes in the issued header and nowhere else, so a Service reading the presented
        # header finds nothing to accept.
        return names == {issued.lower()} and presented.lower() not in names

    return asyncio.run(run()) and expected["accepted"] is False


def agent_mints_an_authenticate_assertion(expected: JsonObject) -> bool:
    """CORE-PR-024: the Agent answers a challenge with an assertion bound to the resource."""
    wanted = parse_json_model(
        json.dumps(expected["claims"]), ClientAssertionClaims, "Client assertion"
    )
    resource = wanted.resource
    if resource is None:
        return False
    document = agent_document(methods=("aep-jwt",))
    claims = agent_assertion_claims(document, AuthenticationOptions(resource=resource))
    return (
        claims is not None
        and claims.op is AssertionOperation.AUTHENTICATE
        and claims.resource == resource
        and claims.aud == "did:web:api.example.com"
        and claims.iss == claims.sub
    )


def agent_refuses_every_ambiguous_presentation(source: JsonObject, expected: JsonObject) -> bool:
    """input.cases names four ambiguous presentations; expected names one outcome for all."""
    if expected["fallback"] is not False or expected["selected_credential"] is not None:
        return False
    code = expected["code"]
    return all(agent_refuses_presentation(name, code) for name in source["cases"])


def agent_refuses_presentation(name: str, code: str) -> bool:
    if name == "both-aep-recognized":
        # CORE-PR-010: the Agent uses at most one carrier, so it cannot be the party that fills
        # both. Whichever carrier is selected, exactly one field is rendered.
        document = agent_document(methods=("aep-jwt",))
        for carrier in AuthorizationCarrier:
            headers = agent_headers(
                document,
                AuthenticationOptions(resource=f"{AGENT_ORIGIN}/orders", carrier=carrier.value),
            )
            if isinstance(headers, Exception) or set(headers) != {carrier.value}:
                return False
        return True
    values = {
        "invalid-dedicated-plus-valid-standard": "AEP",
        "duplicate-dedicated-lines": "AEP first,AEP second",
        "combined-dedicated-values": "AEP first Bearer second",
    }
    if name not in values:
        raise ValueError(f"Unknown authorization ambiguity case: {name}")
    try:
        parse_authorization(values[name], AuthorizationCarrier.DEDICATED)
    except AepAuthorizationError as error:
        return bool(error.code == code)
    return False


def agent_selects_the_named_carrier(source: JsonObject, expected: JsonObject) -> bool:
    """expected.redirect_new_assertion_carrier names the field a fresh assertion goes in."""
    carrier = expected["redirect_new_assertion_carrier"]
    if carrier.lower() != source["field_name"].lower():
        return False
    document = agent_document(methods=("aep-jwt",))
    headers = agent_headers(
        document, AuthenticationOptions(resource=f"{AGENT_ORIGIN}/orders", carrier=carrier)
    )
    return (
        not isinstance(headers, Exception)
        and set(headers) == {carrier}
        and expected["field_name_match"] == "case-insensitive"
        and expected["sensitive_headers_redacted"] is True
        and expected["cache_key_excluded"] is True
        and expected["idempotency_fingerprint_excluded"] is True
        and expected["strip_on_disallowed_redirect"]
        == ["Authorization", "AEP-Authorization", "PAYMENT-SIGNATURE", "api-key-header"]
        and asyncio.run(exercise_field_safety(source, expected))
    )


def agent_composes_with_a_payment_credential(expected: JsonObject) -> bool:
    """CORE-PR-014: a dedicated-carrier AEP credential composes with a payment credential."""
    document = agent_document(methods=("aep-jwt",))
    for name in ("mpp", "x402"):
        composition = expected[name]
        if composition["ambiguous"] is not False:
            return False
        aep_field = next(
            field
            for field, value in composition.items()
            if field != "ambiguous" and str(value).split(" ", 1)[0] in {"AEP", "Bearer"}
        )
        headers = agent_headers(
            document,
            AuthenticationOptions(resource=f"{AGENT_ORIGIN}/orders", carrier=aep_field),
        )
        if isinstance(headers, Exception):
            return False
        # The Agent fills the field the composition names for it and claims none of the others,
        # which is what leaves the payment credential beside it unambiguous.
        others = {field for field in composition if field not in {"ambiguous", aep_field}}
        if set(headers) != {aep_field} or others & set(headers):
            return False
    return True


def agent_binds_each_assertion_to_its_operation(expected: JsonObject) -> bool:
    """Only a command's own assertion reaches it, and only authenticate carries a resource."""
    allowed = {value.split(":", 1)[0]: value.split(":", 1)[1] for value in expected["allowed"]}

    async def run() -> bool:
        for command in (Command.ENROLL, Command.STATUS):
            document = agent_document(commands=("inspect", command.value), methods=("aep-jwt",))
            session, provider, _ = agent_session(
                json_response(document), commands=(json_response({"status": "active"}),)
            )
            if command is Command.ENROLL:
                await session.enroll()
            else:
                await session.status()
            minted = provider.claims[-1]
            if minted.op.value != allowed.get(command.value) or minted.resource is not None:
                return False
        session, provider, _ = agent_session(json_response(agent_document(methods=("aep-jwt",))))
        await session.authentication_headers(
            AuthenticationOptions(resource=f"{AGENT_ORIGIN}/orders")
        )
        claims = provider.claims[-1]
        return (
            allowed.get("authenticate") == "protected-resource"
            and claims.op is AssertionOperation.AUTHENTICATE
            and claims.resource is not None
        )

    return asyncio.run(run())


def agent_rebinds_an_assertion_after_a_redirect(source: JsonObject, expected: JsonObject) -> bool:
    return asyncio.run(exercise_redirects(source, expected))


def agent_fails_closed_without_an_advertised_method(
    source: JsonObject, expected: JsonObject
) -> bool:
    """CORE-IDM-003: a method the Service does not advertise cannot be inferred or presented."""
    advertised = tuple(source["advertised_methods"])
    document = agent_document(methods=advertised)
    unadvertised = source["unadvertised_grant_type"]
    if unadvertised in advertised or source["unadvertised_credential"] in advertised:
        return False
    refused = agent_headers(
        document,
        AuthenticationOptions(resource=f"{AGENT_ORIGIN}/orders", grant_type=unadvertised),
    )
    if not isinstance(refused, Exception):
        return False
    # With no advertised method at all the Agent has nothing to present and must not invent one.
    empty = agent_headers(
        agent_document(), AuthenticationOptions(resource=f"{AGENT_ORIGIN}/orders")
    )
    return isinstance(empty, Exception) and expected["inferred_method"] is None


def agent_surfaces_the_service_error_code(expected: JsonObject) -> bool:
    """The Agent carries the Service's Problem Details code through rather than collapsing it."""
    document = agent_document(commands=("inspect", "status"), methods=("aep-jwt",))

    async def run() -> bool:
        for code in dict.fromkeys(expected.values()):
            session, _, _ = agent_session(
                json_response(document),
                commands=(
                    json_response(
                        {
                            "code": code,
                            "status": 401,
                            "title": code.replace("_", " ").title(),
                            "type": f"urn:aep:error:{code}",
                        },
                        401,
                        AEP_PROBLEM_MEDIA_TYPE,
                    ),
                ),
            )
            try:
                await session.status()
            except AgentCommandError as error:
                if error.problem is None or error.problem.code != code:
                    return False
            else:
                return False
        return True

    return asyncio.run(run())


class SigningKeyStore:
    """A key store that mints real ES256 assertions, so signing paths are genuinely exercised."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())

    async def create_key(self, identity: IdentityRecord) -> None:
        del identity

    async def did_verification_method(self, identity: IdentityRecord) -> DidVerificationMethod:
        numbers = self.key.public_key().public_numbers()
        size = (self.key.key_size + 7) // 8

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
            claims, key=self.key, algorithm=SigningAlgorithm.ES256, key_id=identity.key_id
        )

    async def verification_key(self, identity: IdentityRecord) -> Any:
        del identity
        return self.key.public_key()


class AllowAuthorizer:
    async def authorize(self, request: AuthorizationRequest, context: RequestContext) -> bool:
        del request, context
        return True


def working_platform(**changes: Any) -> Platform:
    identifiers = iter([f"pai_01J0AEPPLATFORM{index:012d}" for index in range(1, 9)])
    agent_did_ids = iter([f"agent-{index}" for index in range(1, 9)])
    values: dict[str, Any] = {
        "agent_did_id_generator": lambda: next(agent_did_ids),
        "authorizer": AllowAuthorizer(),
        "clock": lambda: NOW,
        "did_host": "p.example",
        "did_path_prefix": "a",
        "did_url_template": "https://p.example/a/{agent_did_id}/did.json",
        "discovery": DiscoveryOptions(
            endpoint_base="/v1/aep",
            hosted_verification_endpoint="/v1/aep/verifications",
            lifecycle_endpoint="/v1/aep/agent-identities/{agent_identity_id}",
            list_endpoint="/v1/aep/agent-identities",
            platform_did="did:web:p.example",
            platform_name="Example Platform",
            provision_endpoint="/v1/aep/agent-identities",
            sign_endpoint="/v1/aep/agent-identities/{agent_identity_id}/sign",
        ),
        "hosted_verification": True,
        "identifier": lambda: next(identifiers),
        "identity_store": MemoryIdentityStore(),
        "key_store": SigningKeyStore(),
        "replay_store": MemoryReplayStore(),
        "service_did_resolver": ResolvedServiceDid(),
        "signing_algorithms": (SigningAlgorithm.ES256,),
    }
    values.update(changes)
    return Platform(PlatformOptions(**values))


def platform_context(key: str, principal: str = "stable-principal-123") -> RequestContext:
    return RequestContext(current_time=NOW, idempotency_key=key, principal=principal)


def evaluate_platform(identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
    if identifier in {
        "discovery",
        "provision-request",
        "provision-response",
        "list-response",
        "lifecycle-request",
        "lifecycle-response",
        "sign-request",
        "sign-response",
        "sign-response-pending",
        "verification-request",
        "verification-response-recognized",
        "verification-response-unrecognized",
    }:
        return asyncio.run(exercise_platform_operation(identifier, source, expected))
    if identifier == "provision-response-distinct-services":
        return asyncio.run(exercise_distinct_service_scopes(source, expected))
    if identifier == "verification-authenticate-missing-resource":
        value = source.get("request", source)
        expected_valid = identifier != "verification-authenticate-missing-resource"
        return valid(PlatformVerificationRequest, value) is expected_valid
    if identifier == "authorization-required":
        return asyncio.run(exercise_platform_authorization(source, expected))
    if identifier in IDEMPOTENCY_CASES:
        return asyncio.run(exercise_platform_idempotency(source, expected))
    return False


async def exercise_platform_operation(
    identifier: str, source: JsonObject, expected: JsonObject
) -> bool:
    current = [datetime(2026, 7, 6, 12, tzinfo=UTC)]
    keys = SigningKeyStore()
    changes: JsonObject = {
        "clock": lambda: current[0],
        "key_store": keys,
        "agent_did_id_generator": lambda: "4Yf7p2xQd9",
    }
    if identifier == "sign-response-pending":
        from agent_enrollment_protocol.core import PlatformSignPending

        async def pending(request: Any, context: Any) -> PlatformResult[Any]:
            return PlatformResult(
                status=202,
                body=parse_json_model(json.dumps(expected), PlatformSignPending, "pending"),
            )

        changes["sign_handler"] = pending
    instance = working_platform(**changes)
    if identifier == "discovery":
        result = instance.discovery()
        return (
            result.status == 200 and result.body is not None and result.body.to_wire() == expected
        )
    service_did = source.get("service_did", "did:web:api.service.example")
    created = await instance.provision(
        PlatformProvisionRequest(service_did=service_did),
        RequestContext(
            current_time=current[0],
            principal="owner",
            idempotency_key=expected.get("idempotency_key_header", "provision")
            if identifier == "provision-request"
            else "provision",
        ),
    )
    if created.status != 200 or not isinstance(created.body, PlatformAgentIdentity):
        return False
    identity = created.body
    context = RequestContext(current_time=current[0], principal="owner", idempotency_key="next")
    if identifier == "provision-request":
        return identity.service_did == source["service_did"]
    if identifier == "provision-response":
        return identity.to_wire() == expected
    if identifier == "list-response":
        query = dict(source["query"])
        query["status"] = ManagedAgentStatus(query["status"])
        result = await instance.list(IdentityListQuery(**query), context)
        return (
            result.status == 200 and result.body is not None and result.body.to_wire() == expected
        )
    if identifier.startswith("lifecycle-"):
        current[0] += timedelta(minutes=10)
        context = replace(context, current_time=current[0])
        request = parse_json_model(
            json.dumps(source or {"status": "suspended"}), PlatformLifecycleRequest, "lifecycle"
        )
        result = await instance.update_identity(identity.agent_identity_id, request, context)
        stored = await instance.get_identity(identity.agent_identity_id, context)
        return (
            result.status == 200
            and result.body is not None
            and stored.body == result.body
            and (
                result.body.to_wire() == expected
                if expected
                else result.body.status == request.status
            )
        )
    if identifier in {"sign-request", "sign-response", "sign-response-pending"}:
        request_data = (
            source
            if identifier == "sign-request"
            else {
                "service_did": service_did,
                "op": "enroll",
                "jti": "01J0AEPASSERTION0000000001",
                "platform_context": {"authorization_handle": "opaque-value"},
                "lifetime_seconds": "300",
            }
        )
        request = parse_json_model(json.dumps(request_data), PlatformSignRequest, "sign")
        result = await instance.sign(
            identity.agent_identity_id,
            request,
            replace(
                context,
                idempotency_key=source.get(
                    "idempotency_key_header", expected.get("idempotency_key_header", "sign")
                ),
            ),
        )
        if identifier == "sign-response-pending":
            return (
                result.status == 202
                and result.body is not None
                and result.body.to_wire() == expected
            )
        if result.status != 200 or not isinstance(result.body, PlatformSignCompleted):
            return False
        claims = verify_client_assertion(
            result.body.client_assertion,
            key=keys.key.public_key(),
            options=VerifyClientAssertionOptions(
                audience=service_did, current_time=int(current[0].timestamp()), operation=request.op
            ),
        )
        if claims.jti != request.jti:
            return False
        if identifier == "sign-request":
            return claims.aud == source["service_did"] and claims.exp - claims.iat == int(
                source["lifetime_seconds"]
            )
        actual = result.body.to_wire()
        # JWS signature bytes are nondeterministic; the fixture's token is illustrative, while
        # the generated token is cryptographically verified against the actual Platform key.
        actual.pop("client_assertion")
        return actual == {
            key: value for key, value in expected.items() if key != "client_assertion"
        }
    claims = ClientAssertionClaims(
        aud=service_did,
        exp=int(current[0].timestamp()) + 60,
        iat=int(current[0].timestamp()),
        iss=identity.agent_did,
        sub=identity.agent_did,
        jti="verification",
        op=AssertionOperation.ENROLL,
    )
    token = sign_client_assertion(
        claims, key=keys.key, algorithm=SigningAlgorithm.ES256, key_id=identity.agent_did
    )
    if identifier == "verification-response-unrecognized":
        prefix, signature = token.rsplit(".", 1)
        token = prefix + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
    request = PlatformVerificationRequest(
        service_did=service_did, op=AssertionOperation.ENROLL, client_assertion=token
    )
    result = await instance.verify(
        request,
        replace(
            context,
            principal="trusted-service",
            idempotency_key=expected.get("idempotency_key_header", "verify"),
        ),
    )
    if result.status != 200 or result.body is None:
        return False
    if identifier == "verification-request":
        return (
            result.body.verified
            and request.service_did == source["service_did"]
            and request.op.value == source["op"]
        )
    return result.body.to_wire() == expected


async def exercise_distinct_service_scopes(source: JsonObject, expected: JsonObject) -> bool:
    """PLT-DID-003: each Service gets its own Agent DID, revealing nothing about the other."""
    platform = working_platform()
    responses = []
    for name in ("first_request", "second_request"):
        request = source[name]
        result = await platform.provision(
            PlatformProvisionRequest(service_did=request["service_did"]),
            platform_context(request["idempotency_key_header"]),
        )
        if result.status != 200 or not isinstance(result.body, PlatformAgentIdentity):
            return False
        responses.append(result.body)
    first, second = responses
    if first.service_did == second.service_did:
        return False
    # The DIDs differ, and neither carries the Service DID it was scoped to, which is what keeps
    # one Service from recognizing the Agent it sees at another.
    for identity, request in zip(responses, ("first_request", "second_request"), strict=True):
        service_did = source[request]["service_did"]
        label = service_did.removeprefix("did:web:")
        if label in identity.agent_did or label in identity.did_document_url:
            return False
    shape = {name: expected[name]["status"] for name in ("first_response", "second_response")}
    return (
        first.agent_did != second.agent_did
        and first.agent_identity_id != second.agent_identity_id
        and first.did_document_url != second.did_document_url
        and shape == {"first_response": first.status.value, "second_response": second.status.value}
    )


async def exercise_platform_idempotency(source: JsonObject, expected: JsonObject) -> bool:
    """Every replayable operation replays its stored result and conflicts on changed material."""
    conflict_status = expected["changed_input_or_operation_status"]
    conflict_code = expected["changed_input_or_operation_code"]
    if expected["exact_replay"] != "stored_http_result":
        return False
    for operation in source["operations"]:
        if not await replays_and_conflicts(operation, source, conflict_status, conflict_code):
            return False
    return await retains_a_stored_result(int(expected["retention_seconds_minimum"]))


async def replays_and_conflicts(
    operation: str, source: JsonObject, conflict_status: int, conflict_code: str
) -> bool:
    platform = working_platform()
    principal = source["principal"]
    provisioned = await platform.provision(
        PlatformProvisionRequest(service_did=SERVICE_DID),
        platform_context("provision-setup", principal),
    )
    identity = provisioned.body
    if not isinstance(identity, PlatformAgentIdentity):
        return False
    key = source["initial_sign_key"]
    if operation == "provision":
        first = await platform.provision(
            PlatformProvisionRequest(service_did=SERVICE_DID), platform_context(key, principal)
        )
        replay = await platform.provision(
            PlatformProvisionRequest(service_did=SERVICE_DID), platform_context(key, principal)
        )
        conflict = await platform.provision(
            PlatformProvisionRequest(service_did="did:web:other.service.example"),
            platform_context(key, principal),
        )
    elif operation == "sign":
        request = PlatformSignRequest(
            jti="01J0AEPASSERTION0000000001",
            op=AssertionOperation.ENROLL,
            service_did=SERVICE_DID,
        )
        first = await platform.sign(
            identity.agent_identity_id, request, platform_context(key, principal)
        )
        replay = await platform.sign(
            identity.agent_identity_id, request, platform_context(key, principal)
        )
        conflict = await platform.sign(
            identity.agent_identity_id,
            PlatformSignRequest(
                jti="01J0AEPASSERTION0000000002",
                op=AssertionOperation.ENROLL,
                service_did=SERVICE_DID,
            ),
            platform_context(key, principal),
        )
    elif operation == "hosted_verification":
        signed = await platform.sign(
            identity.agent_identity_id,
            PlatformSignRequest(
                jti="01J0AEPASSERTION0000000003",
                op=AssertionOperation.ENROLL,
                service_did=SERVICE_DID,
            ),
            platform_context("sign-setup", principal),
        )
        if not isinstance(signed.body, PlatformSignCompleted):
            return False
        request = PlatformVerificationRequest(
            client_assertion=signed.body.client_assertion,
            op=AssertionOperation.ENROLL,
            service_did=SERVICE_DID,
        )
        first = await platform.verify(request, platform_context(key, principal))
        replay = await platform.verify(request, platform_context(key, principal))
        conflict = await platform.verify(
            PlatformVerificationRequest(
                client_assertion=signed.body.client_assertion,
                op=AssertionOperation.STATUS,
                service_did=SERVICE_DID,
            ),
            platform_context(key, principal),
        )
    else:
        raise ValueError(f"Unknown replayable Platform operation: {operation}")
    return (
        first.status == 200
        and _stored_body(replay) == _stored_body(first)
        and conflict.status == conflict_status
        and conflict.problem is not None
        and conflict.problem.code == conflict_code
    )


async def retains_a_stored_result(seconds: int) -> bool:
    """A stored result stays replayable for at least the published retention window.

    Signing is used rather than provisioning because a second provision for the same principal and
    Service returns the same identity whether or not the key was remembered, so it could not tell a
    retained result from a fresh one. A forgotten sign key mints a new assertion.
    """
    current = [NOW]
    platform = working_platform(clock=lambda: current[0])
    provisioned = await platform.provision(
        PlatformProvisionRequest(service_did=SERVICE_DID), platform_context("provision-setup")
    )
    identity = provisioned.body
    if not isinstance(identity, PlatformAgentIdentity):
        return False
    request = PlatformSignRequest(
        jti="01J0AEPASSERTION0000000009",
        op=AssertionOperation.ENROLL,
        service_did=SERVICE_DID,
    )
    first = await platform.sign(identity.agent_identity_id, request, platform_context("retained"))
    current[0] = NOW + timedelta(seconds=seconds - 1)
    replay = await platform.sign(
        identity.agent_identity_id,
        request,
        replace(platform_context("retained"), current_time=current[0]),
    )
    return first.status == replay.status and _stored_body(replay) == _stored_body(first)


def _stored_body(result: PlatformResult[Any]) -> JsonObject:
    value = result.problem if result.problem is not None else result.body
    if isinstance(value, BaseModel):
        return cast(JsonObject, value.model_dump(by_alias=True, exclude_unset=True, mode="json"))
    return cast(JsonObject, value)


async def exercise_platform_authorization(source: JsonObject, expected: JsonObject) -> bool:
    authorizer = DenyAuthorizer()
    store = MemoryIdentityStore()
    identity = IdentityRecord(
        agent_did="did:web:p.example:a:existing",
        agent_did_id="existing",
        agent_identity_id="pai_existing",
        created_at=NOW,
        did_document_url="https://p.example/a/existing/did.json",
        key_id="did:web:p.example:a:existing",
        principal="stable-principal-123",
        service_did=SERVICE_DID,
        signing_algorithms=(SigningAlgorithm.ES256,),
        status=ManagedAgentStatus.ACTIVE,
        updated_at=NOW,
    )

    async def existing() -> IdentityRecord:
        return identity

    await store.find_or_create(identity.principal, identity.service_did, existing)
    discovery = DiscoveryOptions(
        endpoint_base="/v1/aep",
        hosted_verification_endpoint="/v1/aep/verifications",
        lifecycle_endpoint="/v1/aep/agent-identities/{agent_identity_id}",
        list_endpoint="/v1/aep/agent-identities",
        platform_did="did:web:p.example",
        platform_name="Example Platform",
        provision_endpoint="/v1/aep/agent-identities",
        sign_endpoint="/v1/aep/agent-identities/{agent_identity_id}/sign",
    )
    platform = Platform(
        PlatformOptions(
            authorizer=authorizer,
            clock=lambda: NOW,
            did_host="p.example",
            did_path_prefix="a",
            did_url_template="https://p.example/a/{agent_did_id}/did.json",
            discovery=discovery,
            hosted_verification=True,
            identity_store=store,
            key_store=PublicDidKeyStore(),
            replay_store=MemoryReplayStore(),
            service_did_resolver=ResolvedServiceDid(),
            signing_algorithms=(SigningAlgorithm.ES256,),
        )
    )
    authorizer_parameter = signature(PlatformOptions).parameters["authorizer"]
    missing_authorizer = (
        "construction-error" if authorizer_parameter.default is Parameter.empty else "accepted"
    )
    context = RequestContext(
        current_time=NOW,
        idempotency_key="operation",
        principal=identity.principal,
    )
    management = (
        await platform.get_identity(identity.agent_identity_id, context),
        await platform.list(IdentityListQuery(), context),
        await platform.provision(
            PlatformProvisionRequest(service_did=SERVICE_DID),
            replace(context, idempotency_key="provision"),
        ),
        await platform.sign(
            identity.agent_identity_id,
            PlatformSignRequest(
                jti="assertion",
                op=AssertionOperation.ENROLL,
                service_did=SERVICE_DID,
            ),
            replace(context, idempotency_key="sign"),
        ),
        await platform.update_identity(
            identity.agent_identity_id,
            PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED),
            context,
        ),
    )
    verification = await platform.verify(
        PlatformVerificationRequest(
            client_assertion=platform_verification_assertion(identity),
            op=AssertionOperation.ENROLL,
            service_did=SERVICE_DID,
        ),
        replace(context, idempotency_key="verify"),
    )
    public_document = await platform.did_document(identity.agent_did_id)
    retained = await store.get(identity.agent_identity_id)
    expected_operations = set(source["private_operations"])
    verification_wire = verification.body.to_wire() if verification.body is not None else {}
    return bool(
        all(
            result.status == expected["management_denied_status"]
            and result.problem is not None
            and result.problem.code == expected["management_denied_code"]
            for result in management
        )
        and all(
            verification_wire.get(key) == value
            for key, value in expected["verification_denied"].items()
        )
        and public_document.status == 200
        and expected["did_document_public"] is True
        and retained == identity
        and missing_authorizer == expected["missing_authorizer"]
        and expected["side_effects"] is False
        and set(authorizer.operations) == expected_operations
    )


async def evaluate_agent_platform(identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
    empty_list = {"count": "0", "data": [], "total": "0"}

    if identifier == "discovery":
        transport = QueueTransport(json_response(expected), json_response(empty_list))
        provider = platform_provider(transport)
        found = await provider.find_identity_by_service_did(SERVICE_DID)
        return bool(
            found is None
            and transport.requests[0].url == f"{PLATFORM_ORIGIN}/.well-known/aep-platform"
            and transport.requests[0].headers.get("Accept") == AEP_MEDIA_TYPE
        )

    if identifier == "provision-request":
        service_did = source["service_did"]
        response = platform_identity(service_did)
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response(empty_list),
            json_response(response),
        )
        provider = platform_provider(
            transport, idempotency_keys=[expected["idempotency_key_header"]]
        )
        await provider.get_or_create_identity(platform_identity_request(service_did))
        provision = transport.requests[-1]
        return bool(
            provision.headers.get("Idempotency-Key") == expected["idempotency_key_header"]
            and json.loads(provision.body or b"") == source
        )

    if identifier == "provision-response":
        service_did = expected["service_did"]
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response(empty_list),
            json_response(expected),
        )
        provider = platform_provider(transport, idempotency_keys=["provision"])
        identity = await provider.get_or_create_identity(platform_identity_request(service_did))
        return service_identity_wire(identity) == expected

    if identifier == "provision-response-distinct-services":
        responses = [expected["first_response"], expected["second_response"]]
        requests = [source["first_request"], source["second_request"]]
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response(empty_list),
            json_response(responses[0]),
            json_response(empty_list),
            json_response(responses[1]),
        )
        provider = platform_provider(
            transport,
            idempotency_keys=[item["idempotency_key_header"] for item in requests],
        )
        identities = [
            await provider.get_or_create_identity(
                platform_identity_request(request_value["service_did"])
            )
            for request_value in requests
        ]
        return bool(
            identities[0].agent_did != identities[1].agent_did
            and identities[0].service_did != identities[1].service_did
        )

    if identifier == "list-response":
        service_did = source["query"]["service_did"]
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response(expected),
        )
        provider = platform_provider(transport)
        identity = await provider.find_identity_by_service_did(service_did)
        query = parse_qs(urlsplit(transport.requests[-1].url).query)
        return bool(
            identity is not None
            and service_identity_wire(identity) == expected["data"][0]
            and query["service_did"] == [service_did]
        )

    if identifier == "sign-request":
        service_did = source["service_did"]
        identity = platform_identity(service_did)
        issued_at = int(NOW.timestamp())
        claims = ClientAssertionClaims(
            aud=service_did,
            exp=issued_at + int(source["lifetime_seconds"]),
            iat=issued_at,
            iss=identity["agent_did"],
            jti=source["jti"],
            op=AssertionOperation(source["op"]),
            sub=identity["agent_did"],
        )
        completed = completed_platform_sign(identity, claims)

        async def context_provider(
            selected: ServiceIdentity, selected_claims: ClientAssertionClaims
        ) -> Mapping[str, object]:
            del selected, selected_claims
            return source["platform_context"]

        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response({"count": "1", "data": [identity], "total": "1"}),
            json_response(completed),
        )
        provider = platform_provider(
            transport,
            idempotency_keys=[expected["idempotency_key_header"]],
            platform_context=context_provider,
        )
        selected = await provider.find_identity_by_service_did(service_did)
        if selected is None:
            return False
        signer = await provider.signer_for(selected)
        await signer(claims, (SigningAlgorithm.ES256,))
        signed = transport.requests[-1]
        return bool(
            signed.headers.get("Idempotency-Key") == expected["idempotency_key_header"]
            and json.loads(signed.body or b"") == source
        )

    if identifier == "sign-response":
        service_did = expected["service_did"]
        identity = platform_identity_from_sign_response(expected)
        claims = claims_from_sign_response(expected)
        signed_response = {
            **expected,
            "client_assertion": completed_platform_sign(identity, claims)["client_assertion"],
        }
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response({"count": "1", "data": [identity], "total": "1"}),
            json_response(signed_response),
        )
        provider = platform_provider(
            transport,
            idempotency_keys=["sign"],
            clock=lambda: datetime.fromtimestamp(claims.iat, UTC),
        )
        selected = await provider.find_identity_by_service_did(service_did)
        if selected is None:
            return False
        signer = await provider.signer_for(selected)
        return (
            await signer(claims, (SigningAlgorithm.ES256,)) == signed_response["client_assertion"]
        )

    if identifier == "sign-response-pending":
        service_did = SERVICE_DID
        identity = platform_identity(service_did)
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response({"count": "1", "data": [identity], "total": "1"}),
            json_response(expected, 202),
        )
        provider = platform_provider(transport, idempotency_keys=[source["idempotency_key_header"]])
        selected = await provider.find_identity_by_service_did(service_did)
        if selected is None:
            return False
        signer = await provider.signer_for(selected)
        try:
            await signer(platform_claims(identity, service_did), (SigningAlgorithm.ES256,))
        except PlatformSignPendingError as error:
            return bool(
                error.pending.retry_after_seconds == int(expected["retry_after_seconds"])
                and dict(error.pending.platform_context) == expected["platform_context"]
                and transport.requests[-1].headers.get("Idempotency-Key")
                == source["idempotency_key_header"]
            )
        return False

    if identifier == "idempotency-replay-conflict":
        problem = {
            "code": expected["changed_input_or_operation_code"],
            "status": expected["changed_input_or_operation_status"],
            "title": "Idempotency conflict",
            "type": "urn:aep:error:idempotency_conflict",
        }
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response(empty_list),
            json_response(
                problem,
                expected["changed_input_or_operation_status"],
                "application/problem+json",
            ),
        )
        provider = platform_provider(transport, idempotency_keys=[source["initial_sign_key"]])
        try:
            await provider.get_or_create_identity(platform_identity_request(SERVICE_DID))
        except PlatformCommandError as error:
            return bool(
                error.status == expected["changed_input_or_operation_status"]
                and error.problem is not None
                and error.problem.code == expected["changed_input_or_operation_code"]
            )
        return False

    return False


def service_identity_wire(identity: ServiceIdentity) -> JsonObject:
    return {
        "agent_did": identity.agent_did,
        "agent_identity_id": identity.metadata["agent_identity_id"],
        "created_at": identity.metadata["created_at"],
        "did_document_url": identity.metadata["did_document_url"],
        "key_id": identity.metadata["key_id"],
        "service_did": identity.service_did,
        "signing_algorithms": [item.value for item in identity.signing_algorithms],
        "status": identity.metadata["status"],
        "updated_at": identity.metadata["updated_at"],
    }


def platform_claims(identity: JsonObject, service_did: str) -> ClientAssertionClaims:
    issued_at = int(NOW.timestamp())
    return ClientAssertionClaims(
        aud=service_did,
        exp=issued_at + 300,
        iat=issued_at,
        iss=identity["agent_did"],
        jti="assertion",
        op=AssertionOperation.ENROLL,
        sub=identity["agent_did"],
    )


def completed_platform_sign(identity: JsonObject, claims: ClientAssertionClaims) -> JsonObject:
    return {
        "agent_did": identity["agent_did"],
        "client_assertion": sign_client_assertion(
            claims,
            key=ec.generate_private_key(ec.SECP256R1()),
            algorithm=SigningAlgorithm.ES256,
            key_id=identity["key_id"],
        ),
        "expires_at": datetime.fromtimestamp(claims.exp, UTC).isoformat().replace("+00:00", "Z"),
        "issued_at": datetime.fromtimestamp(claims.iat, UTC).isoformat().replace("+00:00", "Z"),
        "jti": claims.jti,
        "service_did": claims.aud,
        "status": "completed",
    }


def platform_identity_from_sign_response(response: JsonObject) -> JsonObject:
    agent_did = response["agent_did"]
    suffix = agent_did.rsplit(":", 1)[-1]
    return {
        "agent_did": agent_did,
        "agent_identity_id": f"pai_{suffix}",
        "created_at": response["issued_at"],
        "did_document_url": f"https://p.example/a/{suffix}/did.json",
        "key_id": agent_did,
        "service_did": response["service_did"],
        "signing_algorithms": ["ES256"],
        "status": "active",
        "updated_at": response["issued_at"],
    }


def claims_from_sign_response(response: JsonObject) -> ClientAssertionClaims:
    issued_at = int(
        datetime.fromisoformat(response["issued_at"].replace("Z", "+00:00")).timestamp()
    )
    expires_at = int(
        datetime.fromisoformat(response["expires_at"].replace("Z", "+00:00")).timestamp()
    )
    return ClientAssertionClaims(
        aud=response["service_did"],
        exp=expires_at,
        iat=issued_at,
        iss=response["agent_did"],
        jti=response["jti"],
        op=AssertionOperation.ENROLL,
        sub=response["agent_did"],
    )


async def exercise_idempotency(identifier: str, source: JsonObject, expected: JsonObject) -> bool:
    handler = GrantHandler()
    instance = service(grant_types=(GrantTypeDefinition(grant_type="api-key", handler=handler),))
    key = source.get("idempotency_key", "replay")
    if identifier == "command-header":
        for name in source["commands"]:
            for missing in (None, ""):
                result = await invoke_service(
                    instance,
                    name,
                    command_options(AssertionOperation(name), f"{name}-{missing}", missing),
                )
                if (
                    result.status != expected["missing_or_empty_status"]
                    or result.problem is None
                    or result.problem.code != expected["missing_or_empty_code"]
                ):
                    return False
        mismatch = await invoke_service(
            instance,
            "enroll",
            command_options(AssertionOperation.ENROLL, "mismatch", key),
            idempotency_key="other",
        )
        accepted = await invoke_service(
            instance, "enroll", command_options(AssertionOperation.ENROLL, "valid", key)
        )
        return (
            expected["header_required"] is True
            and expected["enroll_body_key"] == "optional"
            and mismatch.status == expected["mismatched_enroll_body_status"]
            and accepted.status == 200
        )
    await invoke_service(
        instance, "enroll", command_options(AssertionOperation.ENROLL, "setup", "setup")
    )
    command = source.get("first_command", "enroll")
    first = await invoke_service(
        instance, command, command_options(AssertionOperation(command), "one", key)
    )
    replay = await invoke_service(
        instance, command, command_options(AssertionOperation(command), "two", key)
    )
    changed = await invoke_service(
        instance,
        command,
        command_options(AssertionOperation(command), "three", key),
        example="different",
    )
    if first.status != 200 or replay.status != first.status or replay.body != first.body:
        return False
    if command == "grant" and handler.calls != 1:
        return False
    if identifier == "enroll-conflict":
        return (
            changed.status == expected["status"]
            and changed.content_type == expected["content_type"]
            and changed.problem is not None
            and all(
                changed.problem.to_wire().get(key) == value
                for key, value in expected["body"].items()
            )
        )
    other = source["second_command"]
    changed_command = await invoke_service(
        instance, other, command_options(AssertionOperation(other), "four", key)
    )
    for actual, field in ((changed, "changed_body"), (changed_command, "changed_command")):
        if (
            actual.status != expected[field]["status"]
            or actual.problem is None
            or actual.problem.code != expected[field]["code"]
        ):
            return False
    # Service storage owns the retention interval; exercise it with the vector's minimum.
    now = [NOW]
    executions = [0]
    store = MemoryIdempotencyStore(lambda: now[0])

    async def execute() -> StoredResponse:
        executions[0] += 1
        return StoredResponse(b"{}", AEP_MEDIA_TYPE, now[0], {}, 200)

    scope = IdempotencyInput(source["agent_did"], command, key, source["first_body_hash"])
    await store.execute(scope, execute)
    now[0] += timedelta(seconds=int(expected["retention_seconds_minimum"]) - 1)
    await store.execute(scope, execute)
    separate = replace(scope, agent_did="did:web:another.example")
    await store.execute(separate, execute)
    return (
        executions[0] == 2
        and expected["scope"] == ["agent_did", "idempotency_key"]
        and expected["exact_retry"] == "cached_or_equivalent_success"
    )


async def exercise_agent_command_headers(source: JsonObject, expected: JsonObject) -> bool:
    session, _, transport = agent_session(
        json_response(
            agent_document(
                commands=("inspect", "enroll", "grant", "revoke"), grant_types=("api-key",)
            )
        ),
        commands=(
            json_response({"status": "active"}),
            json_response(
                {
                    "credential_id": "one",
                    "api_key": "secret",
                    "header": "X-Key",
                    "expires_at": "2026-09-04T12:00:00Z",
                }
            ),
            json_response({}),
        ),
    )
    for command in source["commands"]:
        if command == "enroll":
            await session.enroll(EnrollOptions(idempotency_key=source["idempotency_key"]))
        elif command == "grant":
            await session.grant(
                GrantOptions(grant_type="api-key", idempotency_key=source["idempotency_key"])
            )
        elif command == "revoke":
            await session.revoke(
                RevokeOptions(all_grant_types=True, idempotency_key=source["idempotency_key"])
            )
        else:
            return False
    return (
        len(transport.requests) == len(source["commands"])
        and expected["header_required"] is True
        and all(
            _header(request.headers, "idempotency-key") == source["idempotency_key"]
            for request in transport.requests
        )
        and expected["enroll_body_key"] == "optional"
    )


async def exercise_assertion_requirements(source: JsonObject, expected: JsonObject) -> bool:
    claims = {
        "aud": source["service_did"],
        "exp": source["expires_at"],
        "iat": source["issued_at"],
        "iss": source["agent_did"],
        "jti": source["jti"],
        "op": "enroll",
        "sub": source["agent_did"],
    }
    header = {"alg": source["algorithm"], "kid": source["agent_did"], "typ": "JWT"}
    minted = sign_client_assertion(
        ClientAssertionClaims.model_validate_json(json.dumps(claims)),
        key=ASSERTION_KEY,
        algorithm=SigningAlgorithm(source["algorithm"]),
        key_id=source["agent_did"],
    )
    actual_header, actual_claims = decode_jwt_unverified(minted)
    if actual_header != expected["header"] or actual_claims != expected["claims"]:
        return False

    def clock() -> datetime:
        return datetime.fromtimestamp(source["issued_at"], UTC)

    class VectorIdentityProvider:
        async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
            return ServiceIdentity(
                agent_did=source["agent_did"],
                service_did=request.service_did,
                identity_method="did:web",
                signing_algorithms=(SigningAlgorithm(source["algorithm"]),),
            )

        async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
            async def sign(
                claims: ClientAssertionClaims, algorithms: tuple[SigningAlgorithm, ...]
            ) -> str:
                return sign_client_assertion(
                    claims,
                    key=ASSERTION_KEY,
                    algorithm=SigningAlgorithm(source["algorithm"]),
                    key_id=identity.agent_did,
                )

            return sign

    commands = QueueTransport(json_response({"status": "active"}))
    agent = Agent(
        AgentOptions(
            identity_provider=VectorIdentityProvider(),
            clock=clock,
            assertion_lifetime=timedelta(seconds=source["expires_at"] - source["issued_at"]),
            inspect_transport=QueueTransport(
                json_response(agent_document(commands=("inspect", "enroll")))
            ),
            command_transport=commands,
        )
    )
    await agent.service(AGENT_ORIGIN).enroll()
    produced_header, produced_claims = decode_jwt_unverified(
        commands.requests[-1].headers["Authorization"].split()[1]
    )
    if produced_header != expected["header"] or not produced_claims.get("jti"):
        return False
    if {key: value for key, value in produced_claims.items() if key != "jti"} != {
        key: value for key, value in expected["claims"].items() if key != "jti"
    }:
        return False
    accepted = await service(clock=clock).enroll(
        json.dumps({"agent_did": source["agent_did"]}).encode(),
        CommandOptions(client_assertion=minted, idempotency_key="valid"),
    )
    if accepted.status != 200:
        return False
    resource = f"{AGENT_ORIGIN}/private"
    for name in expected["reject"]:
        payload, jose = dict(claims), dict(header)
        if name == "excessive_lifetime":
            payload["exp"] = source["issued_at"] + 301
        elif name == "nonpositive_lifetime":
            payload["exp"] = source["issued_at"]
        elif name == "mismatched_subject":
            payload["sub"] = "did:web:someone.example"
        elif name == "mismatched_kid":
            jose["kid"] = "did:web:someone.example"
        elif name == "missing_kid":
            del jose["kid"]
        elif name == "wrong_typ":
            jose["typ"] = "at+jwt"
        elif name in {
            "fragmented_resource",
            "insecure_resource",
            "missing_resource",
            "unexpected_resource",
        }:
            payload["op"] = "authenticate"
            if name != "missing_resource":
                payload["resource"] = {
                    "fragmented_resource": resource + "#x",
                    "insecure_resource": resource.replace("https:", "http:"),
                    "unexpected_resource": resource + "/elsewhere",
                }[name]
        else:
            return False
        token = jwt.encode(payload, ASSERTION_KEY, algorithm=source["algorithm"], headers=jose)
        instance = service(clock=clock)
        if payload["op"] == "authenticate":
            await instance.enroll(
                json.dumps({"agent_did": source["agent_did"]}).encode(),
                CommandOptions(client_assertion=minted, idempotency_key="setup"),
            )
            result = await instance.authenticate_protected_resource(
                ProtectedResourceRequest(
                    headers={"Authorization": "AEP " + token}, method="GET", url=resource
                )
            )
            if result.authenticated or result.response is None or result.response.status != 401:
                return False
        else:
            result = await instance.enroll(
                json.dumps({"agent_did": source["agent_did"]}).encode(),
                CommandOptions(client_assertion=token, idempotency_key=name),
            )
            if result.status != 401:
                return False
    return True


async def exercise_claim_negotiation(source: JsonObject) -> bool:
    instance = service(claims=InspectClaims.model_validate(source["inspect"]))
    result = await instance.enroll(
        json.dumps({"agent_did": AGENT_DID, "claims": source["submitted"]}).encode(),
        command_options(AssertionOperation.ENROLL, "claims", "claims"),
    )
    if result.status != 200:
        return False
    record = await instance._enrollment_store.find(AGENT_DID)
    return (
        record is not None
        and record.claims is not None
        and record.claims.to_wire()
        == {
            key: value
            for key, value in source["submitted"].items()
            if key in source["inspect"]["required"]
        }
    )


async def exercise_redirects(source: JsonObject, expected: JsonObject) -> bool:
    target = source["same_origin"]
    transport = QueueTransport(
        HttpResponse(
            status=401,
            headers={
                "WWW-Authenticate": (
                    f'AEP service_did="{SERVICE_DID}",inspect="{AGENT_ORIGIN}/.well-known/aep"'
                )
            },
        ),
        HttpResponse(status=307, headers={"Location": target}),
        HttpResponse(
            status=401,
            headers={
                "WWW-Authenticate": (
                    f'AEP service_did="{SERVICE_DID}",inspect="{AGENT_ORIGIN}/.well-known/aep"'
                )
            },
        ),
        HttpResponse(status=200),
    )
    session, _, _ = agent_session(json_response(agent_document(methods=("aep-jwt",))))
    response = await fetch_protected_resource(
        FetchProtectedResourceOptions(
            agent=session._agent,
            request=HttpRequest(method="GET", url=source["source"]),
            carrier="AEP-Authorization",
            transport=transport,
        )
    )
    first = decode_jwt_unverified(transport.requests[1].headers["AEP-Authorization"].split()[1])[1]
    second = decode_jwt_unverified(transport.requests[3].headers["AEP-Authorization"].split()[1])[1]
    if (
        response.status != 200
        or first["jti"] == second["jti"]
        or second["resource"] != expected["same_origin"]["new_authenticate_assertion_resource"]
        or expected["same_origin"]["credential_forwarded"] is not False
    ):
        return False
    for method in ("aep-jwt", "api-key", "oauth-bearer", "basic"):
        # The redirected request must be anonymous even when the original request had an API
        # key with a Service-specific header name and a payment credential beside AEP.
        transport = QueueTransport(
            HttpResponse(
                status=401,
                headers={
                    "WWW-Authenticate": (
                        f'AEP service_did="{SERVICE_DID}",inspect="{AGENT_ORIGIN}/.well-known/aep"'
                    )
                },
            ),
            HttpResponse(status=307, headers={"Location": source["cross_origin"]}),
            HttpResponse(status=200),
        )
        issuer, credential = (
            (service(), None)
            if method == "aep-jwt"
            else await issued_credential_service(method, [NOW])
        )
        session, _, _ = agent_session(
            json_response(issuer.inspect_document.to_wire()),
            commands=(json_response({"status": "active"}),),
        )
        await session.enroll()
        if credential is not None:
            await session._agent._credential_store.save_credential(
                CredentialRecord(
                    credential_id=credential.credential_id,
                    expires_at=NOW + timedelta(hours=1),
                    issued_at=NOW,
                    grant_type=method,
                    payload=json.dumps(credential.to_wire()).encode(),
                    service_did=SERVICE_DID,
                    service_url=AGENT_ORIGIN,
                )
            )
        other = agent_document(methods=(method,))
        other["service"]["did"] = "did:web:" + urlsplit(source["cross_origin"]).netloc
        session._agent._inspect_transport.responses.append(json_response(other))
        await fetch_protected_resource(
            FetchProtectedResourceOptions(
                agent=session._agent,
                request=HttpRequest(
                    method="GET",
                    url=source["source"],
                    headers={
                        "X-Caller-Secret": "secret",
                        "Authorization": "Bearer secret",
                        "AEP-Authorization": "AEP secret",
                        "X-Api-Key": "secret",
                        "PAYMENT-SIGNATURE": "secret",
                    },
                ),
                carrier="AEP-Authorization",
                additional_authentication_headers={"Authorization": "Payment secret"},
                transport=transport,
            )
        )
        authenticated = transport.requests[1]
        controlled = "X-Service-Key" if method == "api-key" else "AEP-Authorization"
        if not authenticated.headers.get(controlled) or transport.requests[-1].headers:
            return False
    return (
        all(
            value is False
            for name, value in expected["cross_origin"].items()
            if name.endswith("_forwarded")
        )
        and expected["cross_origin"]["anonymous_restart"] is True
    )


class AssertionVerifier:
    async def verify(
        self, assertion: str, context: AssertionVerificationContext
    ) -> ClientAssertionClaims:
        return verify_client_assertion(
            assertion,
            key=ASSERTION_KEY.public_key(),
            options=VerifyClientAssertionOptions(
                audience=context.service_did, current_time=int(context.current_time.timestamp())
            ),
        )


class GrantHandler:
    def __init__(self) -> None:
        self.calls = 0

    async def grant(self, request: GrantRequest, context: GrantContext) -> bytes:
        del request, context
        self.calls += 1
        return b'{"credential_id":"credential","value":"secret"}'

    async def revoke(self, request: RevokeRequest, context: RevokeContext) -> None:
        del request, context


def assertion(operation: AssertionOperation, jti: str, resource: str | None = None) -> str:
    header = {"alg": "ES256", "kid": f"{AGENT_DID}#key-1", "typ": "JWT"}
    claims: JsonObject = {
        "aud": SERVICE_DID,
        "exp": int((NOW + timedelta(minutes=1)).timestamp()),
        "iat": int(NOW.timestamp()),
        "iss": AGENT_DID,
        "jti": jti,
        "op": operation.value,
        "sub": AGENT_DID,
    }
    if resource is not None:
        claims["resource"] = resource

    return jwt.encode(claims, ASSERTION_KEY, algorithm="ES256", headers=header)


def command_options(
    operation: AssertionOperation, jti: str, key: str | None = None
) -> CommandOptions:
    return CommandOptions(client_assertion=assertion(operation, jti), idempotency_key=key)


def service(enrollment_store: MemoryEnrollmentStore | None = None, **changes: Any) -> Service:
    return Service(
        replace(
            ServiceOptions(
                authentication_methods=("aep-jwt",),
                clock=lambda: NOW,
                enrollment_store=enrollment_store,
                identity_methods=("did:web",),
                grant_types=(GrantTypeDefinition(grant_type="api-key", handler=GrantHandler()),),
                service_did=SERVICE_DID,
                verifier=AssertionVerifier(),
            ),
            **changes,
        )
    )


async def exercise_service_case(identifier: str, case: JsonObject) -> bool:
    if identifier == "grant-before-enroll-rejected":
        expected = case["expected"]
        grant_result = await service().grant(
            b'{"grant_type":"api-key"}',
            command_options(AssertionOperation.GRANT, "grant", "grant"),
        )
        return (
            grant_result.status == expected["status"]
            and grant_result.problem is not None
            and grant_result.problem.code == expected["code"]
            and expected["implicit_enrollment"] is False
        )
    if identifier == "repeated-existing":
        source = case["input"]
        expected = case["expected"]
        existing = source["existing"]
        since = datetime.fromisoformat(existing["since"].replace("Z", "+00:00"))
        store = MemoryEnrollmentStore()
        record = EnrollmentRecord(
            agent_did=existing["agent_did"],
            claims=None,
            created_at=since,
            enrollment_id="existing",
            owner_action_required=False,
            requirements_pending=(),
            since=since,
            status=AgentStatus(existing["status"]),
            updated_at=since,
            verification_pending=(),
        )
        await store.save(record)
        body = json.dumps(source["request"], separators=(",", ":")).encode()

        class MustNotRunPolicy:
            async def decide(self, request: Any, current_time: datetime) -> EnrollmentDecision:
                raise ValueError("Repeated enrollment called application policy")

        enroll_result = await service(store, enrollment_policy=MustNotRunPolicy()).enroll(
            body,
            command_options(
                AssertionOperation.ENROLL,
                "repeated",
                source["request"]["idempotency_key"],
            ),
        )
        restored = await store.find(existing["agent_did"])
        return (
            enroll_result.status == expected["response"]["status"]
            and enroll_result.body is not None
            and enroll_result.body.status.value == expected["response"]["body"]["status"]
            and restored == record
            and expected["record_replaced"] is False
            and expected["policy_evaluated"] is False
        )
    if identifier == "operation-substitution-rejected":
        return await service_rejects_operation_substitution(case["expected"])
    if identifier == "authorization-ambiguity":
        return await service_refuses_every_ambiguous_presentation(case)
    if identifier == "assertion-and-credential-failures":
        return await service_reports_each_failure_code(case["expected"])
    if identifier in {"authenticate-assertion", "authorization-payment-composition"}:
        instance = service()
        enrolled = await instance.enroll(
            b'{"agent_did":"did:web:agent.example.com:agents:123"}',
            command_options(
                AssertionOperation.ENROLL, f"enroll-{identifier}", f"enroll-{identifier}"
            ),
        )
        if enrolled.status != 200:
            return False
        resource = "https://api.example.com/orders"
        carrier = (
            "AEP-Authorization"
            if identifier == "authorization-payment-composition"
            else "Authorization"
        )
        headers = {
            carrier: f"AEP {assertion(AssertionOperation.AUTHENTICATE, identifier, resource)}"
        }
        if identifier == "authorization-payment-composition":
            # CORE-PR-014: an unrelated payment credential beside the dedicated carrier is not
            # ambiguous, and CORE-PR-015 leaves it untouched.
            headers["Authorization"] = "Payment payment-credential"
        authentication_result = await instance.authenticate_protected_resource(
            ProtectedResourceRequest(headers=headers, method="GET", url=resource)
        )
        return authentication_result.authenticated
    return evaluate_protected(identifier, case)


async def service_rejects_operation_substitution(expected: JsonObject) -> bool:
    allowed = {value.split(":", 1)[0]: value.split(":", 1)[1] for value in expected["allowed"]}
    for target in ("enroll", "status", "grant", "revoke", "protected-resource"):
        for operation in AssertionOperation:
            instance = service()
            await instance.enroll(
                json.dumps({"agent_did": AGENT_DID}).encode(),
                command_options(AssertionOperation.ENROLL, "setup", "setup"),
            )
            token = assertion(
                operation,
                "operation",
                f"{AGENT_ORIGIN}/orders" if operation is AssertionOperation.AUTHENTICATE else None,
            )
            options = CommandOptions(client_assertion=token, idempotency_key="operation")
            if target == "protected-resource":
                protected = await instance.authenticate_protected_resource(
                    ProtectedResourceRequest(
                        method="GET",
                        url=f"{AGENT_ORIGIN}/orders",
                        headers={"Authorization": "AEP " + token},
                    )
                )
                accepted, problem = (
                    protected.authenticated,
                    protected.response.problem if protected.response else None,
                )
            else:
                result = await invoke_service(instance, target, options)
                accepted, problem = result.status == 200, result.problem
            if allowed.get(operation.value) == target:
                if not accepted:
                    return False
            elif accepted or problem is None or problem.code != expected["all_other_pairs"]:
                return False
    return True


async def invoke_service(
    instance: Service, command: str, options: CommandOptions, **fields: object
) -> Any:
    if command == "status":
        return await instance.status(options)
    body = {
        "enroll": {"agent_did": AGENT_DID},
        "grant": {"grant_type": "api-key"},
        "revoke": {"all_grant_types": "true"},
    }[command]
    return await getattr(instance, command)(json.dumps({**body, **fields}).encode(), options)


async def service_refuses_every_ambiguous_presentation(case: JsonObject) -> bool:
    """input.cases names four ambiguous presentations; expected names one outcome for all."""
    source, expected = case["input"], case["expected"]
    if expected["fallback"] is not False or expected["selected_credential"] is not None:
        return False
    code = expected["code"]
    resource = "https://api.example.com/orders"
    for name in source["cases"]:
        instance = service()
        enrolled = await instance.enroll(
            b'{"agent_did":"did:web:agent.example.com:agents:123"}',
            command_options(AssertionOperation.ENROLL, f"enroll-{name}", f"enroll-{name}"),
        )
        if enrolled.status != 200:
            return False
        result = await instance.authenticate_protected_resource(
            ProtectedResourceRequest(
                headers=_ambiguous_headers(name, resource), method="GET", url=resource
            )
        )
        if (
            result.authenticated
            or result.response is None
            or result.response.problem is None
            or result.response.problem.code != code
        ):
            return False
    return True


def _ambiguous_headers(name: str, resource: str) -> dict[str, str]:
    first = f"AEP {assertion(AssertionOperation.AUTHENTICATE, 'first', resource)}"
    second = f"AEP {assertion(AssertionOperation.AUTHENTICATE, 'second', resource)}"
    if name == "both-aep-recognized":
        return {"AEP-Authorization": first, "Authorization": second}
    if name == "invalid-dedicated-plus-valid-standard":
        # The malformed dedicated field is the presentation; the valid standard one beside it is
        # not a fallback the Service may authenticate instead.
        return {"AEP-Authorization": "AEP", "Authorization": second}
    if name == "duplicate-dedicated-lines":
        return {"AEP-Authorization": f"{first},{second}"}
    if name == "combined-dedicated-values":
        return {"AEP-Authorization": f"{first} extra-credential"}
    raise ValueError(f"Unknown authorization ambiguity case: {name}")


async def service_reports_each_failure_code(expected: JsonObject) -> bool:
    resource = "https://api.example.com/orders"
    modes: dict[str, dict[str, str]] = {
        # CORE-PR-038: a value naming an AEP scheme is a malformed presentation, not an absent one.
        "malformed_credential": {"Authorization": "AEP"},
        # A method the Service does not advertise is a different answer from an unrecognized one.
        "unsupported_method": {"Authorization": "Bearer opaque-token"},
        "wrong_audience": {
            "Authorization": f"AEP {assertion(AssertionOperation.AUTHENTICATE, 'aud', resource)}"
        },
    }
    for mode, headers in modes.items():
        instance = service()
        enrolled = await instance.enroll(
            b'{"agent_did":"did:web:agent.example.com:agents:123"}',
            command_options(AssertionOperation.ENROLL, f"enroll-{mode}", f"enroll-{mode}"),
        )
        if enrolled.status != 200:
            return False
        if mode == "wrong_audience":
            _, payload = decode_jwt_unverified(
                assertion(AssertionOperation.AUTHENTICATE, "elsewhere", resource)
            )
            payload["aud"] = "did:web:other.example"
            headers = {
                "Authorization": "AEP "
                + jwt.encode(
                    payload,
                    ASSERTION_KEY,
                    algorithm="ES256",
                    headers={"kid": AGENT_DID, "typ": "JWT"},
                )
            }
        result = await instance.authenticate_protected_resource(
            ProtectedResourceRequest(headers=headers, method="GET", url=resource)
        )
        if (
            result.authenticated
            or result.response is None
            or result.response.problem is None
            or result.response.problem.code != expected[mode]
        ):
            return False
    for mode in (
        "expired_assertion",
        "replayed_assertion",
        "expired_credential",
        "insufficient_scope",
    ):
        current = [NOW]
        instance = service(clock=lambda current=current: current[0])
        await invoke_service(
            instance, "enroll", command_options(AssertionOperation.ENROLL, "setup", "setup")
        )
        token = assertion(AssertionOperation.AUTHENTICATE, "resource", resource)
        request = ProtectedResourceRequest(
            headers={"Authorization": "AEP " + token}, method="GET", url=resource
        )
        if mode == "expired_assertion":
            current[0] += timedelta(minutes=6)
        elif mode == "replayed_assertion":
            if not (await instance.authenticate_protected_resource(request)).authenticated:
                return False
        elif mode == "expired_credential":
            instance, credential = await issued_credential_service("api-key", current)
            request = ProtectedResourceRequest(
                headers={credential.header: credential.api_key}, method="GET", url=resource
            )
            current[0] += timedelta(hours=2)
        result = await instance.authenticate_protected_resource(request)
        if mode == "insufficient_scope":
            # Authorization belongs to the application, after successful AEP authentication.
            if not result.authenticated or result.principal is None or result.principal.scopes:
                return False
            application_error = ProblemDetails(
                type="urn:aep:error:insufficient_scope",
                title="Insufficient scope",
                status=403,
                code="insufficient_scope",
            )
            if application_error.code != expected[mode] or application_error.status != 403:
                return False
        elif (
            result.authenticated
            or result.response is None
            or result.response.problem is None
            or result.response.problem.code != expected[mode]
        ):
            return False
    return True


async def issued_credential_service(
    grant_type: str, current: list[datetime], supplied: JsonObject | None = None
) -> tuple[Service, Any]:
    credential_data = supplied or {
        "credential_id": "credential-1",
        "expires_at": (current[0] + timedelta(hours=1)).isoformat(),
        **{
            "api-key": {"api_key": "secret", "header": "X-Service-Key"},
            "basic": {"username": "agent", "password": "secret"},
            "oauth-bearer": {"access_token": "secret", "token_type": "Bearer"},
        }[grant_type],
    }
    model = {
        "api-key": ApiKeyGrantResponse,
        "basic": BasicGrantResponse,
        "oauth-bearer": OAuthBearerGrantResponse,
    }[grant_type]
    credential = parse_json_model(json.dumps(credential_data), model, "credential")

    async def issue(request: GrantRequest, context: GrantContext) -> Any:
        return credential

    factory = {
        "api-key": stored_api_key_grant_type,
        "basic": stored_basic_grant_type,
        "oauth-bearer": stored_oauth_bearer_grant_type,
    }[grant_type]
    instance = service(
        authentication_methods=(grant_type,),
        clock=lambda: current[0],
        grant_types=(
            factory(
                StoredCredentialGrantTypeOptions(issue=issue, store=MemoryServiceCredentialStore())
            ),
        ),
    )
    await invoke_service(
        instance, "enroll", command_options(AssertionOperation.ENROLL, "setup", "setup")
    )
    result = await instance.grant(
        json.dumps({"grant_type": grant_type}).encode(),
        command_options(AssertionOperation.GRANT, "issue", "issue"),
    )
    if result.status != 200:
        raise ValueError("conformance credential issuance failed")
    if result.body != credential.to_wire():
        raise ValueError("Service Grant did not serialize the issued credential")
    return instance, credential


async def exercise_profile_response(role: str, grant_type: str, expected: JsonObject) -> bool:
    if role == "service":
        instance, credential = await issued_credential_service(grant_type, [NOW], expected)
        return instance.inspect_document.commands.grant_types == (
            grant_type,
        ) and credential.to_wire() == wire(credential_model("credentials/" + grant_type), expected)
    document = agent_document(
        commands=("inspect", "enroll", "grant"),
        methods=(grant_type,),
        grant_types=(grant_type,),
        api_key_header=expected.get("header"),
    )
    session, _, transport = agent_session(
        json_response(document),
        commands=(json_response({"status": "active"}), json_response(expected)),
    )
    await session.enroll()
    result = await session.grant(GrantOptions(grant_type=grant_type))
    return (
        result.body.credential is not None
        and result.body.credential.to_wire()
        == wire(credential_model("credentials/" + grant_type), expected)
        and json.loads(transport.requests[-1].body)["grant_type"] == grant_type
    )


async def exercise_credential_presentations(
    role: str, source: JsonObject, expected: JsonObject
) -> bool:
    for grant_type in ("oauth-bearer", "api-key", "basic"):
        presentation = expected[grant_type]
        current = [NOW]
        supplied = None
        if grant_type == "api-key":
            supplied = {
                "credential_id": "credential-1",
                "expires_at": "2026-09-03T13:00:00Z",
                "header": "x-api-key",
                "api_key": "opaque-api-key",
            }
        instance, credential = await issued_credential_service(grant_type, current, supplied)
        document = instance.inspect_document.to_wire()
        session, _, _ = agent_session(
            json_response(document), commands=(json_response({"status": "active"}),)
        )
        await session.enroll()
        await session._agent._credential_store.save_credential(
            CredentialRecord(
                credential_id=credential.credential_id,
                expires_at=NOW + timedelta(hours=1),
                issued_at=NOW,
                grant_type=grant_type,
                payload=json.dumps(credential.to_wire()).encode(),
                service_did=SERVICE_DID,
                service_url=AGENT_ORIGIN,
            )
        )
        resource = source["resource"]
        for carrier in ("Authorization", "AEP-Authorization"):
            headers = await session.authentication_headers(
                AuthenticationOptions(resource=resource, grant_type=grant_type, carrier=carrier)
            )
            header = credential.header if grant_type == "api-key" else carrier
            if set(headers) != {header}:
                return False
            if grant_type == "api-key":
                if header != presentation["header"] or headers[header] != presentation["value"]:
                    return False
            elif (
                not headers[header].startswith(presentation["scheme"] + " ")
                or presentation["header"] != "Authorization"
            ):
                return False
            if role == "service":
                result = await instance.authenticate_protected_resource(
                    ProtectedResourceRequest(headers=headers, method="GET", url=resource)
                )
                if not result.authenticated:
                    return False
        if role == "service":
            revoked = await instance.revoke(
                json.dumps({"grant_type": grant_type}).encode(),
                command_options(AssertionOperation.REVOKE, "revoke", "revoke"),
            )
            result = await instance.authenticate_protected_resource(
                ProtectedResourceRequest(headers=headers, method="GET", url=resource)
            )
            if revoked.status != 200 or result.authenticated:
                return False
    return True


async def exercise_field_safety(source: JsonObject, expected: JsonObject) -> bool:
    instance = service()
    enrolled = await invoke_service(
        instance, "enroll", command_options(AssertionOperation.ENROLL, "setup", "key")
    )
    replayed = await invoke_service(
        instance, "enroll", command_options(AssertionOperation.ENROLL, "new-token", "key")
    )
    resource = f"{AGENT_ORIGIN}/private"
    token = assertion(AssertionOperation.AUTHENTICATE, "lowercase", resource)
    result = await instance.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={source["field_name"]: "AEP " + token}, method="GET", url=resource
        )
    )
    if not result.authenticated or enrolled.body != replayed.body:
        return False
    # There is no SDK telemetry hook. Public metadata and cached command bodies must not
    # acquire authorization field values supplied to authentication.
    public = json.dumps(instance.inspect_document.to_wire()) + json.dumps(enrolled.body.to_wire())
    if token in public or "AEP-Authorization" in public:
        return False
    redirect_case = {
        "source": resource,
        "same_origin": resource + "/next",
        "cross_origin": "https://other.example.net/private",
    }
    return await exercise_redirects(
        redirect_case,
        {
            "same_origin": {
                "credential_forwarded": False,
                "new_authenticate_assertion_resource": redirect_case["same_origin"],
            },
            "cross_origin": {
                "anonymous_restart": True,
                "assertion_forwarded": False,
                "session_credential_forwarded": False,
                "api_key_header_forwarded": False,
            },
        },
    )


async def exercise_service_boundaries(
    identifier: str, source: JsonObject, expected: JsonObject
) -> bool:
    if identifier == "api-key-wrong-header-rejected":
        instance, credential = await issued_credential_service(
            "api-key",
            [NOW],
            {
                "credential_id": "one",
                "api_key": source["api_key"],
                "header": source["issued_header"],
                "expires_at": "2026-09-03T13:00:00Z",
            },
        )
        result = await instance.authenticate_protected_resource(
            ProtectedResourceRequest(
                headers={source["presented_header"]: credential.api_key},
                method="GET",
                url=f"{AGENT_ORIGIN}/private",
            )
        )
        return (
            result.authenticated is expected["accepted"]
            and result.response is not None
            and result.response.problem is not None
            and result.response.problem.code == expected["code"]
        )
    if identifier == "redirect-safety":
        instance = service()
        await invoke_service(
            instance, "enroll", command_options(AssertionOperation.ENROLL, "setup", "setup")
        )
        old = assertion(AssertionOperation.AUTHENTICATE, "before-redirect", source["source"])
        rejected = await instance.authenticate_protected_resource(
            ProtectedResourceRequest(
                headers={"AEP-Authorization": "AEP " + old}, method="GET", url=source["same_origin"]
            )
        )
        fresh = assertion(AssertionOperation.AUTHENTICATE, "after-redirect", source["same_origin"])
        accepted = await instance.authenticate_protected_resource(
            ProtectedResourceRequest(
                headers={"AEP-Authorization": "AEP " + fresh},
                method="GET",
                url=source["same_origin"],
            )
        )
        return (
            not rejected.authenticated
            and accepted.authenticated
            and expected["same_origin"]["credential_forwarded"] is False
        )
    if identifier == "authorization-field-safety":
        return (
            expected["field_name_match"] == "case-insensitive"
            and expected["redirect_new_assertion_carrier"] == source["selected_carrier"]
            and expected["sensitive_headers_redacted"] is True
            and expected["cache_key_excluded"] is True
            and expected["idempotency_fingerprint_excluded"] is True
            and expected["strip_on_disallowed_redirect"]
            == ["Authorization", "AEP-Authorization", "PAYMENT-SIGNATURE", "api-key-header"]
            and await exercise_field_safety(source, expected)
        )
    raise ValueError(f"No Service boundary mapping: {identifier}")


def evaluate_generic(role: str, category: str, identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
    if role == "service" and identifier in {
        "api-key-wrong-header-rejected",
        "redirect-safety",
        "authorization-field-safety",
    }:
        return asyncio.run(exercise_service_boundaries(identifier, source, expected))
    if identifier == "credential-presentations":
        return asyncio.run(exercise_credential_presentations(role, source, expected))
    if role == "agent" and category == "platform":
        return asyncio.run(evaluate_agent_platform(identifier, case))
    service_cases = {
        "assertion-and-credential-failures",
        "authenticate-assertion",
        "authorization-ambiguity",
        "authorization-payment-composition",
        "grant-before-enroll-rejected",
        "operation-substitution-rejected",
        "repeated-existing",
    }
    if role == "service" and identifier in service_cases:
        return asyncio.run(exercise_service_case(identifier, case))
    if identifier == "public-discovery-cache":
        return agent_honours_discovery_caching(expected)
    if category == "claims":
        return evaluate_claims(identifier, case)
    if category == "client-assertion":
        if identifier == "did-web-resolution":
            return bool(did_web_document_url(source["did"]) == expected["document_url"])
        return evaluate_assertion(identifier, case)
    if category.startswith("credentials/"):
        if identifier == "grant-response":
            return asyncio.run(exercise_profile_response(role, category.split("/")[1], expected))
        model = credential_model(category)
        value = source if identifier.endswith("missing-credential-id") else expected
        return validity(model, value, expected) if "valid" in expected else valid(model, value)
    response_model = body_model(category, identifier)
    if response_model is not None:
        return bool(wire(response_model, expected["body"]) == expected["body"])
    if category == "errors" and identifier == "problem-details-validation":
        return evaluate_problem_cases(case)
    if category == "inspect":
        return evaluate_inspect(identifier, case)
    if category == "openapi":
        return evaluate_openapi(identifier, case)
    if identifier in {"request-minimal", "request-claims-catalog"}:
        enroll_request = parse_json_model(json.dumps(source), EnrollRequest, "Enroll request")
        return bool(
            enroll_request.agent_did == source["agent_did"]
            and command_path(Command.ENROLL) == expected["path"]
        )
    if identifier == "grant-request-oauth-bearer":
        grant_request = parse_json_model(json.dumps(source), GrantRequest, "Grant request")
        return bool(
            grant_request.grant_type == "oauth-bearer"
            and command_path(Command.GRANT) == expected["path"]
        )
    if identifier.startswith("revoke-request-"):
        parsed = valid(RevokeRequest, source)
        return parsed is expected.get("valid", True)
    if identifier == "grant-before-enroll-rejected":
        return expected["code"] == "not_recognized" and expected["implicit_enrollment"] is False
    if identifier in IDEMPOTENCY_CASES:
        if role == "service":
            return asyncio.run(exercise_idempotency(identifier, source, expected))
        if role == "agent":
            return asyncio.run(exercise_agent_command_headers(source, expected))
        return evaluate_platform(identifier, case)
    if identifier == "repeated-existing":
        return (
            AgentStatus(source["existing"]["status"]).value
            == expected["response"]["body"]["status"]
            and expected["record_replaced"] is False
            and expected["policy_evaluated"] is False
        )
    if identifier in PROTECTED_BEHAVIOR_CASES:
        return evaluate_protected(identifier, case)
    if identifier in {
        "authorization-carriers",
        "credential-presentations",
        "inspect-authentication-methods",
    }:
        return evaluate_authorization(identifier, case)
    if identifier == "transport-requirements":
        return evaluate_inspect(identifier, case)
    if category == "platform":
        return evaluate_platform(identifier, case)
    raise ValueError(f"no {role} public API maps {category}/{identifier}")


def evaluate(request: JsonObject) -> JsonObject:
    sequence = request["sequence"]
    try:
        passed = evaluate_generic(
            request["role"],
            request["vector"]["category"],
            request["vector"]["id"],
            request["case"],
        )
        if passed:
            return {"protocol_version": "1", "sequence": sequence, "status": "passed"}
        return {
            "message": "Public Python API result did not match the vector",
            "protocol_version": "1",
            "sequence": sequence,
            "status": "failed",
        }
    except Exception as error:
        return {
            "message": str(error)[:1024],
            "protocol_version": "1",
            "sequence": sequence,
            "status": "failed",
        }


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"agent", "platform", "service"}:
        raise SystemExit("usage: conformance_adapter.py agent|platform|service")
    role = sys.argv[1]
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        if request["role"] != role:
            raise SystemExit("adapter request role does not match process role")
        print(json.dumps(evaluate(request), separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
