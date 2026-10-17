from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_enrollment_protocol.core import (
    AepValidationError,
    AssertionOperation,
    Authentication,
    ClaimValues,
    ClientAssertionClaims,
    EnrollRequest,
    InspectClaims,
    OpenApiAepSecurityScheme,
    PlatformSignCompleted,
    PlatformSignPending,
    SigningAlgorithm,
    ValidationIssue,
    VerifyClientAssertionOptions,
    parse_json_model,
    parse_platform_sign_response,
    sign_client_assertion,
    validate_json_model,
    verify_client_assertion,
)
from agent_enrollment_protocol.core.errors import validation_issues
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    CommandOptions,
    MemoryEnrollmentStore,
    Service,
    ServiceOptions,
)


def test_parse_and_validate_json_models() -> None:
    data = json.dumps({"agent_did": "did:web:agent.example", "future": True})
    parsed = parse_json_model(data, EnrollRequest, "Enroll request")
    assert parsed.agent_did == "did:web:agent.example"
    assert validate_json_model(data.encode(), EnrollRequest, "Enroll request").ok
    invalid = validate_json_model("{}", EnrollRequest, "Enroll request")
    assert not invalid.ok
    assert invalid.value is None
    assert invalid.issues[0].path == "$.agent_did"


def test_json_parser_rejects_duplicate_trailing_and_invalid_json() -> None:
    for data in (
        '{"agent_did":"one","agent_did":"two"}',
        '{"agent_did":"one"} trailing',
        b"\xff",
    ):
        with pytest.raises(AepValidationError) as caught:
            parse_json_model(data, EnrollRequest, "Enroll request")
        assert caught.value.issues[0].path == "$"


def test_union_parser_selects_platform_sign_response() -> None:
    pending = parse_platform_sign_response('{"status":"pending","retry_after_seconds":"5"}')
    assert isinstance(pending, PlatformSignPending)
    completed = parse_platform_sign_response(
        json.dumps(
            {
                "status": "completed",
                "agent_did": "did:web:agent.example",
                "client_assertion": "jwt",
                "expires_at": "2026-09-02T12:01:00Z",
                "issued_at": "2026-09-02T12:00:00Z",
                "jti": "jti",
                "service_did": "did:web:service.example",
            }
        )
    )
    assert isinstance(completed, PlatformSignCompleted)
    with pytest.raises(AepValidationError):
        parse_platform_sign_response('{"status":"other"}')


def test_validation_issue_fallback_and_paths() -> None:
    assert validation_issues(ValueError("bad")) == (ValidationIssue(path="$", message="bad"),)
    result = validate_json_model('{"agent_did":42}', EnrollRequest, "Enroll request")
    assert result.issues[0].path == "$.agent_did"
    indexed = validate_json_model('{"methods":[1]}', Authentication, "authentication advertisement")
    assert indexed.issues[0].path == "$.methods[0]"


def test_wire_parsing_preserves_unknown_claims_without_using_python_aliases() -> None:
    parsed = parse_json_model(
        '{"agent_did":"did:web:agent.example","claims":{"contact_email":"a@example.com"}}',
        EnrollRequest,
        "Enroll request",
    )
    assert parsed.claims is not None
    assert parsed.claims.contact_email is None
    assert parsed.claims.to_wire() == {"contact_email": "a@example.com"}
    unknown_null = parse_json_model('{"contact_email":null}', ClaimValues, "claims")
    assert unknown_null.to_wire() == {"contact_email": None}
    supplied = parse_json_model('{"contact.email":"a@example.com"}', ClaimValues, "claims")
    assert supplied.contact_email == "a@example.com"
    assert (
        ClaimValues.model_validate({"contact_email": "a@example.com"}).to_wire()
        == supplied.to_wire()
    )
    both = parse_json_model(
        '{"contact.email":"a@example.com","contact_email":"b@example.com"}',
        ClaimValues,
        "claims",
    )
    assert both.to_wire() == {"contact.email": "a@example.com", "contact_email": "b@example.com"}
    with pytest.raises(AepValidationError):
        parse_json_model('{"authentication_method":"aep-jwt"}', OpenApiAepSecurityScheme, "scheme")
    assert (
        parse_json_model(
            '{"x-aep-authentication-method":"aep-jwt"}', OpenApiAepSecurityScheme, "scheme"
        ).authentication_method
        == "aep-jwt"
    )


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_wire_parsers_reject_non_json_constants(constant: str) -> None:
    with pytest.raises(AepValidationError, match="JSON"):
        parse_json_model(
            '{"agent_did":"did:web:agent.example","claims":{"example.value":' + constant + "}}",
            EnrollRequest,
            "Enroll request",
        )
    with pytest.raises(AepValidationError, match="JSON"):
        parse_platform_sign_response('{"status":"pending","future":' + constant + "}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requested", "sent", "expected_status"),
    [
        ("contact.email", "contact_email", 422),
        ("contact.email", "contact.email", 200),
        ("contact_email", "contact_email", 200),
    ],
)
async def test_service_preserves_wire_claim_names_with_real_assertions(
    requested: str, sent: str, expected_status: int
) -> None:
    key = Ed25519PrivateKey.generate()

    class Verifier:
        async def verify(
            self, assertion: str, context: AssertionVerificationContext
        ) -> ClientAssertionClaims:
            return verify_client_assertion(
                assertion,
                key=key.public_key(),
                options=VerifyClientAssertionOptions(
                    audience=context.service_did,
                    operation=context.operation,
                    current_time=int(context.current_time.timestamp()),
                ),
            )

    store = MemoryEnrollmentStore()
    service = Service(
        ServiceOptions(
            service_did="did:web:service.example",
            identity_methods=("did:web",),
            verifier=Verifier(),
            claims=InspectClaims(required=(requested,)),
            enrollment_store=store,
        )
    )
    now = int(time.time())
    assertion = sign_client_assertion(
        ClientAssertionClaims(
            aud="did:web:service.example",
            iss="did:web:agent.example",
            sub="did:web:agent.example",
            iat=now,
            exp=now + 60,
            jti="assertion-1",
            op=AssertionOperation.ENROLL,
        ),
        key=key,
        algorithm=SigningAlgorithm.EDDSA,
    )
    result = await service.enroll(
        json.dumps(
            {"agent_did": "did:web:agent.example", "claims": {sent: "a@example.com"}}
        ).encode(),
        CommandOptions(client_assertion=assertion, idempotency_key="request-1"),
    )
    assert result.status == expected_status
    record = await store.find("did:web:agent.example")
    if expected_status == 200:
        assert record is not None
        assert record.claims is not None
        assert record.claims.to_wire() == {sent: "a@example.com"}
    else:
        assert record is None
