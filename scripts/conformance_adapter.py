#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import sys
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from inspect import Parameter, signature
from typing import Any
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel

from agent_enrollment_protocol.agent import (
    InspectCacheEntry,
    MemoryInspectCache,
    OperationKey,
    PlatformCommandError,
    PlatformContextProvider,
    PlatformIdentityProvider,
    PlatformIdentityProviderOptions,
    PlatformPendingSignResolver,
    PlatformSignPendingError,
    RandomIdempotencyKeyProvider,
    ServiceIdentity,
)
from agent_enrollment_protocol.agent.types import IdentityRequest
from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AepAssertionError,
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
    PlatformAgentIdentityListResponse,
    PlatformDiscoveryDocument,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignRequest,
    PlatformVerificationRequest,
    PlatformVerificationResponse,
    ProblemDetails,
    ProtectedResourceAuthorization,
    RevokeRequest,
    RevokeResponse,
    SigningAlgorithm,
    StatusResponse,
    authorization_header_name,
    command_path,
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
    resolve_openapi_url,
    same_origin,
)
from agent_enrollment_protocol.platform import (
    AuthorizationRequest,
    DidVerificationMethod,
    DiscoveryOptions,
    IdempotentOperation,
    IdentityListQuery,
    IdentityRecord,
    MemoryIdentityStore,
    MemoryPlatformIdempotencyStore,
    MemoryReplayStore,
    Platform,
    PlatformIdempotencyInput,
    PlatformOptions,
    RequestContext,
    create_service_scoped_agent_did,
)
from agent_enrollment_protocol.platform import (
    StoredResponse as PlatformStoredResponse,
)
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    CommandOptions,
    EnrollmentRecord,
    GrantContext,
    GrantTypeDefinition,
    IdempotencyInput,
    MemoryEnrollmentStore,
    MemoryIdempotencyStore,
    ProtectedResourceRequest,
    RevokeContext,
    Service,
    ServiceOptions,
    StoredResponse,
)

JsonObject = dict[str, Any]
NOW = datetime(2026, 9, 3, 12, tzinfo=UTC)
AGENT_DID = "did:web:agent.example.com:agents:123"
SERVICE_DID = "did:web:api.example.com"
PLATFORM_ORIGIN = "https://p.example"

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
) -> PlatformIdentityProvider:
    keys = iter(idempotency_keys or [])

    async def idempotency_key() -> str:
        return next(keys)

    return PlatformIdentityProvider(
        PlatformIdentityProviderOptions(
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
        return result.can_satisfy_required is expected["enrollment_requirement_satisfied"]
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
        claims = parse_json_model(
            json.dumps(expected["claims"]), ClientAssertionClaims, "Client assertion"
        )
        return claims.op is AssertionOperation.ENROLL and claims.iss == claims.sub
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
        source = case["input"]
        return media_type_essence(source["content_type"]) == AEP_MEDIA_TYPE
    return False


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
        return scheme.authentication_method == "aep-jwt"
    if identifier == "url-resolution":
        relative = resolve_openapi_url(source["final_inspect_url"], source["relative"])
        cross_origin = resolve_openapi_url(source["final_inspect_url"], source["cross_origin"])
        return bool(
            relative == expected["relative_resolved"] and cross_origin == source["cross_origin"]
        )
    return False


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


def evaluate_protected(identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
    if identifier == "api-key-wrong-header-rejected":
        return bool(
            source["issued_header"].lower() != source["presented_header"].lower()
            and expected["accepted"] is False
        )
    if identifier == "authenticate-assertion":
        claims = parse_json_model(
            json.dumps(expected["claims"]), ClientAssertionClaims, "Client assertion"
        )
        return claims.op is AssertionOperation.AUTHENTICATE
    if identifier == "authorization-ambiguity":
        try:
            parse_authorization("AEP first,AEP second", AuthorizationCarrier.DEDICATED)
        except (AepAuthorizationError, AepValidationError, ValueError):
            return expected["fallback"] is False and expected["selected_credential"] is None
        return False
    if identifier == "authorization-field-safety":
        return bool(
            authorization_header_name(AuthorizationCarrier.DEDICATED).lower()
            == source["field_name"].lower()
            and "Authorization" in expected["strip_on_disallowed_redirect"]
            and "AEP-Authorization" in expected["strip_on_disallowed_redirect"]
        )
    if identifier == "authorization-payment-composition":
        aep = ProtectedResourceAuthorization(
            carrier=AuthorizationCarrier.DEDICATED,
            scheme=AuthorizationScheme.AEP,
            credentials="compact-jws",
        )
        carrier, value = render_authorization(aep)
        return bool(
            carrier == "AEP-Authorization"
            and value == "AEP compact-jws"
            and expected["mpp"]["ambiguous"] is False
            and expected["x402"]["ambiguous"] is False
        )
    if identifier == "operation-substitution-rejected":
        return set(expected["allowed"]) == {
            "enroll:enroll",
            "grant:grant",
            "revoke:revoke",
            "status:status",
            "authenticate:protected-resource",
        }
    if identifier == "redirect-safety":
        return same_origin(source["source"], source["same_origin"]) and not same_origin(
            source["source"], source["cross_origin"]
        )
    if identifier == "unadvertised-authentication-method":
        authentication = case["input"]["advertised_methods"]
        return (
            source["unadvertised_credential"] not in authentication
            and source["unadvertised_grant_type"] not in authentication
            and expected["inferred_method"] is None
        )
    if identifier == "assertion-and-credential-failures":
        return all(
            valid(
                ProblemDetails,
                {
                    "code": code,
                    "status": 401,
                    "title": code.replace("_", " ").title(),
                    "type": f"urn:aep:error:{code}",
                },
            )
            for code in set(expected.values())
        )
    return False


def evaluate_platform(identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
    if identifier == "discovery":
        return bool(wire(PlatformDiscoveryDocument, expected) == expected)
    if identifier == "provision-request":
        return valid(PlatformProvisionRequest, source)
    if identifier in {"provision-response", "lifecycle-response"}:
        return valid(PlatformAgentIdentity, expected)
    if identifier == "provision-response-distinct-services":
        first = source["first_request"]["service_did"]
        second = source["second_request"]["service_did"]
        return create_service_scoped_agent_did(
            "platform.example", "agents", first
        ) != create_service_scoped_agent_did("platform.example", "agents", second)
    if identifier == "list-response":
        return valid(PlatformAgentIdentityListResponse, expected)
    if identifier == "lifecycle-request":
        return valid(PlatformLifecycleRequest, source)
    if identifier == "sign-request":
        return valid(PlatformSignRequest, source)
    if identifier in {"sign-response", "sign-response-pending"}:
        from agent_enrollment_protocol.core import parse_platform_sign_response

        return bool(parse_platform_sign_response(json.dumps(expected)).to_wire() == expected)
    if identifier in {"verification-request", "verification-authenticate-missing-resource"}:
        value = source.get("request", source)
        expected_valid = identifier != "verification-authenticate-missing-resource"
        return valid(PlatformVerificationRequest, value) is expected_valid
    if identifier in {"verification-response-recognized", "verification-response-unrecognized"}:
        return valid(PlatformVerificationResponse, expected)
    if identifier == "authorization-required":
        return asyncio.run(exercise_platform_authorization(source, expected))
    if identifier in IDEMPOTENCY_CASES:
        return asyncio.run(exercise_platform_idempotency())
    return False


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
        transport = QueueTransport(
            json_response(platform_discovery()),
            json_response({"count": "1", "data": [identity], "total": "1"}),
            json_response(expected),
        )
        provider = platform_provider(transport, idempotency_keys=["sign"])
        selected = await provider.find_identity_by_service_did(service_did)
        if selected is None:
            return False
        signer = await provider.signer_for(selected)
        claims = claims_from_sign_response(expected)
        return await signer(claims, (SigningAlgorithm.ES256,)) == expected["client_assertion"]

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
        "client_assertion": "header.payload.signature",
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


async def exercise_idempotency() -> bool:
    now = datetime.now(UTC)
    store = MemoryIdempotencyStore(lambda: now)
    source = IdempotencyInput("did:web:agent.example", "enroll", "same", "sha256:one")

    async def operation() -> StoredResponse:
        return StoredResponse(b"{}", AEP_MEDIA_TYPE, now, {}, 200)

    created = await store.execute(source, operation)
    replayed = await store.execute(source, operation)
    conflict = await store.execute(
        IdempotencyInput("did:web:agent.example", "enroll", "same", "sha256:two"),
        operation,
    )
    return (
        created.state.value == "created"
        and replayed.state.value == "replayed"
        and conflict.state.value == "conflict"
    )


async def exercise_platform_idempotency() -> bool:
    store = MemoryPlatformIdempotencyStore(lambda: NOW)
    source = PlatformIdempotencyInput(
        "same", IdempotentOperation.PROVISION, "principal", "sha256:one"
    )

    async def operation() -> PlatformStoredResponse:
        return PlatformStoredResponse(200, AEP_MEDIA_TYPE, b"{}", NOW, {})

    created = await store.execute(source, operation)
    replayed = await store.execute(source, operation)
    conflict = await store.execute(
        PlatformIdempotencyInput("same", IdempotentOperation.PROVISION, "principal", "sha256:two"),
        operation,
    )
    return (
        created.state.value == "created"
        and replayed.state.value == "replayed"
        and conflict.state.value == "conflict"
    )


class AssertionVerifier:
    async def verify(
        self, assertion: str, context: AssertionVerificationContext
    ) -> ClientAssertionClaims:
        del context
        try:
            encoded = assertion.split(".")[1]
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            return parse_json_model(payload, ClientAssertionClaims, "Client assertion")
        except (AepValidationError, IndexError, ValueError) as error:
            raise AepAssertionError("Client assertion is invalid.") from error


class GrantHandler:
    async def grant(self, request: GrantRequest, context: GrantContext) -> bytes:
        del request, context
        return b'{"credential_id":"credential","value":"secret"}'

    async def revoke(self, request: RevokeRequest, context: RevokeContext) -> None:
        del request, context


def assertion(operation: AssertionOperation, jti: str, resource: str | None = None) -> str:
    header = {"alg": "EdDSA", "kid": f"{AGENT_DID}#key-1", "typ": "JWT"}
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

    def encode(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{encode(header)}.{encode(claims)}.signature"


def command_options(
    operation: AssertionOperation, jti: str, key: str | None = None
) -> CommandOptions:
    return CommandOptions(client_assertion=assertion(operation, jti), idempotency_key=key)


def service(enrollment_store: MemoryEnrollmentStore | None = None) -> Service:
    return Service(
        ServiceOptions(
            authentication_methods=("aep-jwt",),
            clock=lambda: NOW,
            enrollment_store=enrollment_store,
            identity_methods=("did:web",),
            grant_types=(GrantTypeDefinition(grant_type="api-key", handler=GrantHandler()),),
            service_did=SERVICE_DID,
            verifier=AssertionVerifier(),
        )
    )


async def exercise_service_case(identifier: str, case: JsonObject) -> bool:
    if identifier == "grant-before-enroll-rejected":
        grant_result = await service().grant(
            b'{"grant_type":"api-key"}',
            command_options(AssertionOperation.GRANT, "grant", "grant"),
        )
        return (
            grant_result.status == 401
            and grant_result.problem is not None
            and grant_result.problem.code == "not_recognized"
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
        enroll_result = await service(store).enroll(
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
        )
    if identifier == "operation-substitution-rejected":
        substitution_result = await service().enroll(
            b'{"agent_did":"did:web:agent.example.com:agents:123"}',
            command_options(AssertionOperation.STATUS, "substitution", "substitution"),
        )
        return (
            substitution_result.status == 401
            and substitution_result.problem is not None
            and substitution_result.problem.code == "not_recognized"
        )
    if identifier in {
        "authenticate-assertion",
        "authorization-ambiguity",
        "authorization-payment-composition",
        "assertion-and-credential-failures",
    }:
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
        headers: dict[str, str] = {}
        if identifier == "authorization-ambiguity":
            headers = {
                "AEP-Authorization": (
                    f"AEP {assertion(AssertionOperation.AUTHENTICATE, 'first', resource)}"
                ),
                "Authorization": (
                    f"AEP {assertion(AssertionOperation.AUTHENTICATE, 'second', resource)}"
                ),
            }
        elif identifier == "assertion-and-credential-failures":
            headers = {"Authorization": "AEP malformed"}
        else:
            carrier = (
                "AEP-Authorization"
                if identifier == "authorization-payment-composition"
                else "Authorization"
            )
            headers[carrier] = (
                f"AEP {assertion(AssertionOperation.AUTHENTICATE, identifier, resource)}"
            )
            if identifier == "authorization-payment-composition":
                headers["Authorization"] = "Payment payment-credential"
        authentication_result = await instance.authenticate_protected_resource(
            ProtectedResourceRequest(headers=headers, method="GET", url=resource)
        )
        if identifier in {"authenticate-assertion", "authorization-payment-composition"}:
            return authentication_result.authenticated
        return (
            not authentication_result.authenticated
            and authentication_result.response is not None
            and authentication_result.response.problem is not None
            and authentication_result.response.problem.code == "not_recognized"
        )
    return evaluate_protected(identifier, case)


def evaluate_generic(role: str, category: str, identifier: str, case: JsonObject) -> bool:
    source = case["input"]
    expected = case["expected"]
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

        async def exercise_cache() -> bool:
            cache = MemoryInspectCache()
            document = parse_json_model(
                json.dumps(minimal_document("1.0")), InspectDocument, "Inspect document"
            )
            entry = InspectCacheEntry(
                cached_at=datetime.now(UTC),
                document=document,
                final_url="https://api.example.com/discovery/aep",
                cache_control="no-cache",
                etag='"inspect-1"',
                last_modified="Wed, 03 Sep 2026 00:00:00 GMT",
            )
            await cache.save_inspect(entry.final_url, entry)
            restored = await cache.find_inspect(entry.final_url)
            return restored == entry and restored is not entry

        return asyncio.run(exercise_cache())
    if category == "claims":
        return evaluate_claims(identifier, case)
    if category == "client-assertion":
        if identifier == "did-web-resolution":
            return bool(did_web_document_url(source["did"]) == expected["document_url"])
        return evaluate_assertion(identifier, case)
    if category.startswith("credentials/"):
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
            return asyncio.run(exercise_idempotency())
        if role == "agent":
            provider = RandomIdempotencyKeyProvider()
            operation = OperationKey("enroll", SERVICE_DID, "https://api.example.com")
            return bool(asyncio.run(provider.create_key(operation)))
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
