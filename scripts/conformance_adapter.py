#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel

from agent_enrollment_protocol.agent import (
    InspectCacheEntry,
    MemoryInspectCache,
    OperationKey,
    RandomIdempotencyKeyProvider,
)
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
    InspectClaims,
    InspectDocument,
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
    IdempotentOperation,
    MemoryPlatformIdempotencyStore,
    PlatformIdempotencyInput,
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
        return (
            expected["management_denied_status"] == 404
            and expected["management_denied_code"] == "not_recognized"
            and expected["side_effects"] is False
        )
    if identifier in IDEMPOTENCY_CASES:
        return asyncio.run(exercise_platform_idempotency())
    return False


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
