from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

REPOSITORY = Path(__file__).resolve().parent.parent
ADAPTER = REPOSITORY / "scripts" / "conformance_adapter.py"

JsonObject = dict[str, Any]
Corruption = tuple[str, str, str, str, Any]

# Each entry corrupts one member of a vector's published expectation. A mapping that reads its
# expectation flips from passed to failed; a mapping that compares two constants, or two fields of
# the vector to each other, stays passed and fails this test.
CORRUPTIONS: tuple[Corruption, ...] = (
    ("service", "service-documents", "wire-shapes", "cases", []),
    ("service", "service-documents", "structural-limits", "cases", []),
    ("service", "service-documents", "enrollment-lifecycle", "identity_preserved", False),
    ("service", "service-documents", "enrollment-lifecycle", "credential_ids", ["not-issued"]),
    ("service", "service-documents", "grant-guidance", "grant_status", 200),
    ("service", "service-documents", "grant-guidance", "credential_issued", True),
    (
        "service",
        "protected-resource",
        "assertion-and-credential-failures",
        "wrong_audience",
        "invalid_request",
    ),
    (
        "service",
        "protected-resource",
        "assertion-and-credential-failures",
        "expired_assertion",
        "invalid_request",
    ),
    (
        "service",
        "protected-resource",
        "assertion-and-credential-failures",
        "replayed_assertion",
        "invalid_request",
    ),
    (
        "service",
        "protected-resource",
        "assertion-and-credential-failures",
        "expired_credential",
        "invalid_request",
    ),
    (
        "service",
        "protected-resource",
        "assertion-and-credential-failures",
        "insufficient_scope",
        "invalid_request",
    ),
    ("service", "enroll", "repeated-existing", "policy_evaluated", False),
    (
        "service",
        "claims",
        "negotiation-compatibility",
        "unknown_submitted_default_action",
        "accept",
    ),
    ("agent", "claims", "negotiation-compatibility", "omitted_preferred_allowed", False),
    ("service", "idempotency", "command-header", "missing_or_empty_status", 200),
    ("service", "idempotency", "command-header", "mismatched_enroll_body_status", 200),
    (
        "service",
        "idempotency",
        "command-replay-conflict",
        "changed_command",
        {"status": 200, "code": "ok"},
    ),
    ("agent", "protected-resource", "api-key-wrong-header-rejected", "accepted", True),
    ("agent", "protected-resource", "authorization-ambiguity", "fallback", True),
    ("agent", "protected-resource", "authorization-ambiguity", "code", "invalid_request"),
    (
        "agent",
        "protected-resource",
        "authorization-field-safety",
        "redirect_new_assertion_carrier",
        "Authorization",
    ),
    ("agent", "protected-resource", "unadvertised-authentication-method", "inferred_method", "x"),
    ("agent", "openapi", "security-inheritance", "multiple_schemes_one_object", "required"),
    ("agent", "openapi", "security-inheritance", "unsupported_compound", "required"),
    ("agent", "openapi", "security-inheritance", "root_inherited", "public"),
    ("agent", "caching", "public-discovery-cache", "default_freshness_seconds", "30"),
    (
        "platform",
        "platform",
        "idempotency-replay-conflict",
        "changed_input_or_operation_status",
        400,
    ),
    (
        "platform",
        "platform",
        "idempotency-replay-conflict",
        "changed_input_or_operation_code",
        "invalid_request",
    ),
    ("platform", "platform", "idempotency-replay-conflict", "retention_seconds_minimum", "36000"),
    ("platform", "platform", "idempotency-replay-conflict", "exact_replay", "fresh_result"),
    (
        "platform",
        "platform",
        "provision-response-distinct-services",
        "first_response",
        {"status": "revoked"},
    ),
    ("service", "grant-revoke", "grant-before-enroll-rejected", "code", "invalid_request"),
    ("service", "grant-revoke", "grant-before-enroll-rejected", "status", 400),
    (
        "service",
        "protected-resource",
        "operation-substitution-rejected",
        "all_other_pairs",
        "authentication_required",
    ),
    ("service", "protected-resource", "authorization-ambiguity", "code", "authentication_required"),
    ("service", "protected-resource", "authorization-ambiguity", "fallback", True),
    (
        "service",
        "protected-resource",
        "assertion-and-credential-failures",
        "malformed_credential",
        "authentication_required",
    ),
    (
        "service",
        "protected-resource",
        "assertion-and-credential-failures",
        "unsupported_method",
        "not_recognized",
    ),
)


def _spec_vectors() -> Path | None:
    configured = os.environ.get("AEP_SPECS_DIR")
    candidates = [Path(configured)] if configured else []
    candidates += [REPOSITORY.parent / "aep-specs", REPOSITORY / ".conformance" / "aep-specs"]
    for candidate in candidates:
        vectors = candidate / "ietf" / "test-vectors"
        if vectors.is_dir():
            return vectors
    return None


def _request(sequence: int, role: str, vector: JsonObject, case: JsonObject) -> JsonObject:
    applicability = vector["applicability"][role]
    return {
        "sequence": sequence,
        "role": role,
        "profile": applicability.get("profile", ""),
        "expectation": applicability.get("expectation", ""),
        "vector": {"category": vector["category"], "id": vector["id"]},
        "case": case,
    }


def _evaluate(role: str, requests: list[JsonObject]) -> list[str]:
    completed = subprocess.run(
        [sys.executable, str(ADAPTER), role],
        input="\n".join(json.dumps(item) for item in requests),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"conformance adapter failed: {completed.stderr[-2000:]}")
    return [json.loads(line)["status"] for line in completed.stdout.splitlines() if line.strip()]


def test_conformance_mappings_read_the_expectation_they_publish() -> None:
    """A conformance mapping that cannot fail reports every implementation as conformant.

    Each case runs twice in one adapter process: once against the vector the specification
    publishes, and once against the same vector with one member of its expectation corrupted.
    """
    vectors = _spec_vectors()
    if vectors is None:
        pytest.skip(
            "aep-specs is not checked out; set AEP_SPECS_DIR to run the falsifiability check"
        )
    by_role: dict[str, tuple[list[JsonObject], list[str]]] = {}
    for role, category, identifier, member, replacement in CORRUPTIONS:
        vector = json.loads((vectors / category / f"{identifier}.json").read_text())
        published = {"input": vector.get("input", {}), "expected": vector.get("expected", {})}
        assert member in published["expected"], f"{identifier}: {member} is not a published member"
        corrupted = deepcopy(published)
        corrupted["expected"][member] = replacement
        requests, labels = by_role.setdefault(role, ([], []))
        requests.append(_request(len(requests) + 1, role, vector, published))
        labels.append(f"{role} {identifier}.{member}: published")
        requests.append(_request(len(requests) + 1, role, vector, corrupted))
        labels.append(f"{role} {identifier}.{member}: corrupted")

    for role, (requests, labels) in by_role.items():
        statuses = _evaluate(role, requests)
        assert len(statuses) == len(requests)
        for index, (label, status) in enumerate(zip(labels, statuses, strict=True)):
            if index % 2 == 0:
                assert status == "passed", f"{label}: the mapping rejects the published vector"
            else:
                assert status == "failed", (
                    f"{label}: the mapping accepted a corrupted expectation, "
                    "so nothing about the SDK can make it fail"
                )


@pytest.mark.parametrize(
    "role,category,identifier,owner,method",
    [
        ("service", "service-documents", "enrollment-lifecycle", "Service", "enroll"),
        ("service", "service-documents", "grant-guidance", "Service", "grant"),
        ("agent", "idempotency", "command-header", "Agent", "service"),
        (
            "agent",
            "protected-resource",
            "redirect-safety",
            "ServiceSession",
            "authentication_headers",
        ),
        ("service", "client-assertion", "validation-requirements", "Service", "enroll"),
        ("service", "idempotency", "command-replay-conflict", "Service", "grant"),
        ("service", "claims", "negotiation-compatibility", "Service", "enroll"),
        (
            "service",
            "protected-resource",
            "credential-presentations",
            "Service",
            "authenticate_protected_resource",
        ),
        ("service", "protected-resource", "operation-substitution-rejected", "Service", "status"),
        ("platform", "platform", "discovery", "Platform", "discovery"),
        ("platform", "platform", "provision-response", "Platform", "provision"),
        ("platform", "platform", "lifecycle-response", "Platform", "update_identity"),
        ("platform", "platform", "list-response", "Platform", "list"),
        ("platform", "platform", "sign-response", "Platform", "sign"),
        ("platform", "platform", "sign-response-pending", "Platform", "sign"),
        ("platform", "platform", "verification-response-recognized", "Platform", "verify"),
        ("platform", "platform", "verification-response-unrecognized", "Platform", "verify"),
    ],
)
def test_behavioral_mapping_fails_when_sdk_operation_is_disabled(
    role: str, category: str, identifier: str, owner: str, method: str
) -> None:
    vectors = _spec_vectors()
    if vectors is None:
        pytest.skip("Set AEP_SPECS_DIR to run conformance negative controls")
    vector = json.loads((vectors / category / f"{identifier}.json").read_text())
    request = _request(
        1, role, vector, {"input": vector.get("input", {}), "expected": vector.get("expected", {})}
    )
    assert _evaluate(role, [request]) == ["passed"]
    code = """
import json, runpy, sys
from unittest.mock import patch
adapter = runpy.run_path(sys.argv[1], run_name='conformance_test')
def disabled(*args, **kwargs):
    raise RuntimeError('SDK operation disabled by negative control')
with patch.object(adapter[sys.argv[2]], sys.argv[3], disabled):
    print(json.dumps(adapter['evaluate'](json.loads(sys.stdin.read()))))
"""
    completed = subprocess.run(
        [sys.executable, "-c", code, str(ADAPTER), owner, method],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert json.loads(completed.stdout)["status"] == "failed"
