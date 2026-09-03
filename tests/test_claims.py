from agent_enrollment_protocol.core import (
    ClaimValues,
    InspectClaims,
    evaluate_claim_support,
    missing_required_claim_names,
)


def test_evaluates_claim_support_without_mutating_inputs() -> None:
    requested = InspectClaims(
        required=("contact.email", "example.required"),
        preferred=("example.preferred", "person.first_name"),
        optional=("contact.mobile", "example.optional"),
    )
    supported = ["contact.email", "person.first_name", "contact.mobile"]
    result = evaluate_claim_support(requested, supported)
    assert not result.can_satisfy_required
    assert result.unsupported_required == ("example.required",)
    assert result.supported_preferred == ("person.first_name",)
    assert result.supported_optional == ("contact.mobile",)
    assert supported == ["contact.email", "person.first_name", "contact.mobile"]
    assert evaluate_claim_support(None).can_satisfy_required


def test_reports_missing_registered_and_extension_claims_in_request_order() -> None:
    values = ClaimValues.model_validate(
        {"contact.email": "agent@example.com", "example.extension": {"value": True}}
    )
    required = ("example.missing", "contact.email", "example.extension", "contact.mobile")
    assert missing_required_claim_names(required, values) == (
        "example.missing",
        "contact.mobile",
    )
    assert missing_required_claim_names(required, None) == required
