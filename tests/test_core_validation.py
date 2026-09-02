from __future__ import annotations

import json

import pytest

from agent_enrollment_protocol.core import (
    AepValidationError,
    Authentication,
    EnrollRequest,
    PlatformSignCompleted,
    PlatformSignPending,
    ValidationIssue,
    parse_json_model,
    parse_platform_sign_response,
    validate_json_model,
)
from agent_enrollment_protocol.core.errors import validation_issues


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
