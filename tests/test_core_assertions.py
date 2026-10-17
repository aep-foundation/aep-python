from __future__ import annotations

import json
from base64 import urlsafe_b64encode

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from agent_enrollment_protocol.core import (
    AepAssertionError,
    AssertionOperation,
    ClientAssertionClaims,
    SigningAlgorithm,
    VerifyClientAssertionOptions,
    decode_jwt_unverified,
    sign_client_assertion,
    verify_client_assertion,
)

NOW = 1_700_000_000


def claims(*, op: AssertionOperation = AssertionOperation.ENROLL) -> ClientAssertionClaims:
    values: dict[str, object] = {
        "aud": "did:web:service.example",
        "exp": NOW + 60,
        "iat": NOW,
        "iss": "did:web:agent.example:agents:one",
        "jti": "assertion-1",
        "op": op,
        "sub": "did:web:agent.example:agents:one",
    }
    if op is AssertionOperation.AUTHENTICATE:
        values["resource"] = "https://resource.example/items/1"
    return ClientAssertionClaims.model_validate(values)


@pytest.mark.parametrize(
    "asserted,target,accepted,loopback",
    [
        ("https://RESOURCE.EXAMPLE:443/items/1", "https://resource.example/items/1", True, False),
        ("https://resource.example", "https://resource.example/", True, False),
        ("https://[ABCD::1]:443/", "https://[abcd::1]/", True, False),
        ("http://LOCALHOST:80/private", "http://localhost/private", True, True),
        ("https://resource.example:8443/", "https://resource.example/", False, False),
        ("https://resource.example/private", "https://resource.example/Private", False, False),
        ("https://resource.example/private", "https://resource.example/private/", False, False),
        ("https://resource.example/a%2Fb", "https://resource.example/a/b", False, False),
        ("https://resource.example/?a=1&b=2", "https://resource.example/?b=2&a=1", False, False),
        ("https://resource.example/private?", "https://resource.example/private", False, False),
        ("https://resource.example/private?", "https://RESOURCE.EXAMPLE:443/private?", True, False),
        ("https://resource.example/private", "https://resource.example/private#", False, False),
        ("https://resource.example/private", "https://@resource.example/private", False, False),
        ("https://resource.example/private", "https://resource.example:bad/private", False, False),
    ],
)
def test_resource_comparison_preserves_target_identity(
    asserted: str,
    target: str,
    accepted: bool,
    loopback: bool,
) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    original = claims(op=AssertionOperation.AUTHENTICATE).model_copy(update={"resource": asserted})
    token = sign_client_assertion(
        original, key=key, algorithm=SigningAlgorithm.EDDSA, allow_insecure_loopback=loopback
    )
    options = VerifyClientAssertionOptions(
        resource=target, current_time=NOW, allow_insecure_loopback=loopback
    )
    if accepted:
        assert verify_client_assertion(token, key=key.public_key(), options=options) == original
    else:
        with pytest.raises(AepAssertionError, match="resource"):
            verify_client_assertion(token, key=key.public_key(), options=options)


def test_resource_expectation_cannot_accept_an_assertion_without_a_resource() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    token = sign_client_assertion(claims(), key=key, algorithm=SigningAlgorithm.EDDSA)
    with pytest.raises(AepAssertionError, match="resource"):
        verify_client_assertion(
            token,
            key=key.public_key(),
            options=VerifyClientAssertionOptions(
                resource="https://resource.example/private", current_time=NOW
            ),
        )


@pytest.mark.parametrize("algorithm", [SigningAlgorithm.EDDSA, SigningAlgorithm.ES256])
def test_sign_verify_and_decode_client_assertions(algorithm: SigningAlgorithm) -> None:
    private_key: object
    public_key: object
    if algorithm is SigningAlgorithm.EDDSA:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
    expected = claims()
    assertion = sign_client_assertion(expected, key=private_key, algorithm=algorithm)
    header, payload = decode_jwt_unverified(assertion)
    assert header == {
        "alg": algorithm.value,
        "kid": expected.iss,
        "typ": "JWT",
    }
    assert payload["jti"] == expected.jti
    actual = verify_client_assertion(
        assertion,
        key=public_key,
        options=VerifyClientAssertionOptions(
            algorithms=(algorithm,),
            audience=expected.aud,
            issuer=expected.iss,
            subject=expected.sub,
            operation=expected.op,
            current_time=NOW + 30,
        ),
    )
    assert actual == expected


def test_authenticate_assertion_binds_the_resource() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    expected = claims(op=AssertionOperation.AUTHENTICATE)
    assertion = sign_client_assertion(
        expected, key=key, algorithm=SigningAlgorithm.EDDSA, key_id=f"{expected.iss}#key-1"
    )
    actual = verify_client_assertion(
        assertion,
        key=key.public_key(),
        options=VerifyClientAssertionOptions(
            algorithms=(SigningAlgorithm.EDDSA,),
            resource=expected.resource,
            current_time=NOW,
        ),
    )
    assert actual.resource == expected.resource


def test_loopback_resource_requires_an_explicit_development_option() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    values = claims(op=AssertionOperation.AUTHENTICATE).to_wire()
    values["resource"] = "http://127.0.0.1:9900/items/1"
    expected = ClientAssertionClaims.model_validate_json(
        json.dumps(values), context={"allow_insecure_loopback": True}
    )
    assertion = sign_client_assertion(
        expected,
        key=key,
        algorithm=SigningAlgorithm.EDDSA,
        allow_insecure_loopback=True,
    )
    actual = verify_client_assertion(
        assertion,
        key=key.public_key(),
        options=VerifyClientAssertionOptions(
            allow_insecure_loopback=True,
            current_time=NOW,
        ),
    )
    assert actual.resource == "http://127.0.0.1:9900/items/1"
    with pytest.raises(ValueError):
        ClientAssertionClaims.model_validate_json(json.dumps(values))


def test_assertion_validation_rejects_headers_bindings_time_and_expectations() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    expected = claims()
    assertion = sign_client_assertion(expected, key=key, algorithm=SigningAlgorithm.EDDSA)
    bad_options = [
        VerifyClientAssertionOptions(algorithms=(), current_time=NOW),
        VerifyClientAssertionOptions(audience="other", current_time=NOW),
        VerifyClientAssertionOptions(issuer="other", current_time=NOW),
        VerifyClientAssertionOptions(subject="other", current_time=NOW),
        VerifyClientAssertionOptions(operation=AssertionOperation.STATUS, current_time=NOW),
        VerifyClientAssertionOptions(resource="https://other.example", current_time=NOW),
        VerifyClientAssertionOptions(current_time=NOW - 1),
        VerifyClientAssertionOptions(current_time=NOW + 61),
    ]
    for options in bad_options:
        with pytest.raises(AepAssertionError):
            verify_client_assertion(assertion, key=key.public_key(), options=options)
    tolerated = verify_client_assertion(
        assertion,
        key=key.public_key(),
        options=VerifyClientAssertionOptions(current_time=NOW - 1, clock_tolerance_seconds=1),
    )
    assert tolerated.jti == expected.jti
    with pytest.raises(ValueError, match="negative"):
        VerifyClientAssertionOptions(clock_tolerance_seconds=-1)


def test_assertion_validation_rejects_malformed_and_unsafe_tokens() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    expected = claims()
    with pytest.raises(AepAssertionError, match="kid"):
        sign_client_assertion(
            expected,
            key=key,
            algorithm=SigningAlgorithm.EDDSA,
            key_id="did:web:other.example#key",
        )
    tokens = [
        jwt.encode(expected.to_wire(), key, algorithm="EdDSA", headers={"typ": "JWT"}),
        jwt.encode(
            expected.to_wire(),
            key,
            algorithm="EdDSA",
            headers={"kid": expected.iss, "typ": "not-jwt"},
        ),
        jwt.encode(
            expected.to_wire(),
            key,
            algorithm="EdDSA",
            headers={"crit": ["future"], "kid": expected.iss, "typ": "JWT"},
        ),
    ]
    for token in tokens:
        with pytest.raises(AepAssertionError):
            verify_client_assertion(
                token,
                key=key.public_key(),
                options=VerifyClientAssertionOptions(current_time=NOW),
            )
    with pytest.raises(AepAssertionError):
        verify_client_assertion("not-a-jwt", key=key.public_key())
    with pytest.raises(AepAssertionError):
        verify_client_assertion(
            jwt.encode(expected.to_wire(), "a" * 32, algorithm="HS256"),
            key="a" * 32,
            options=VerifyClientAssertionOptions(current_time=NOW),
        )
    with pytest.raises(AepAssertionError):
        verify_client_assertion(
            jwt.encode(
                {**expected.to_wire(), "sub": "did:web:other.example"},
                key,
                algorithm="EdDSA",
                headers={"kid": expected.iss, "typ": "JWT"},
            ),
            key=key.public_key(),
            options=VerifyClientAssertionOptions(current_time=NOW),
        )


def test_unverified_decoder_rejects_non_jwt_and_non_object_parts() -> None:
    with pytest.raises(AepAssertionError):
        decode_jwt_unverified("one.two")
    array = urlsafe_b64encode(json.dumps([]).encode()).decode().rstrip("=")
    object_part = urlsafe_b64encode(json.dumps({}).encode()).decode().rstrip("=")
    with pytest.raises(AepAssertionError):
        decode_jwt_unverified(f"{array}.{object_part}.signature")
    with pytest.raises(AepAssertionError):
        decode_jwt_unverified("invalid.invalid.signature")
    with pytest.raises(AepAssertionError):
        decode_jwt_unverified(f"{object_part}!!!.{object_part}.signature")
    duplicate = urlsafe_b64encode(b'{"value":1,"value":2}').decode().rstrip("=")
    with pytest.raises(AepAssertionError):
        decode_jwt_unverified(f"{duplicate}.{object_part}.signature")


@pytest.mark.parametrize("not_before", [NOW + 10, NOW + 10.5])
def test_not_before_uses_the_configured_clock_and_tolerance(not_before: float) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    payload = {**claims().to_wire(), "nbf": not_before}
    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": payload["iss"]})
    options = VerifyClientAssertionOptions(current_time=NOW + 11)
    assert (
        verify_client_assertion(token, key=key.public_key(), options=options).jti == "assertion-1"
    )
    with pytest.raises(AepAssertionError, match="not yet valid"):
        verify_client_assertion(
            token, key=key.public_key(), options=VerifyClientAssertionOptions(current_time=NOW + 9)
        )
    assert (
        verify_client_assertion(
            token,
            key=key.public_key(),
            options=VerifyClientAssertionOptions(current_time=NOW + 9, clock_tolerance_seconds=2),
        ).jti
        == "assertion-1"
    )


@pytest.mark.parametrize("not_before", [None, True, "1700000000", [], {}])
def test_not_before_rejects_non_numeric_dates(not_before: object) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    payload = {**claims().to_wire(), "nbf": not_before}
    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": payload["iss"]})
    with pytest.raises(AepAssertionError, match="invalid nbf"):
        verify_client_assertion(
            token, key=key.public_key(), options=VerifyClientAssertionOptions(current_time=NOW)
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_jwt_boundaries_reject_non_json_constants(value: float) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    payload = {**claims().to_wire(), "example.future": {"value": value}}
    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"kid": payload["iss"]})
    with pytest.raises(AepAssertionError):
        decode_jwt_unverified(token)
    with pytest.raises(AepAssertionError):
        verify_client_assertion(
            token, key=key.public_key(), options=VerifyClientAssertionOptions(current_time=NOW)
        )
    header_token = jwt.encode(
        claims().to_wire(), key, algorithm="EdDSA", headers={"kid": payload["iss"], "future": value}
    )
    with pytest.raises(AepAssertionError):
        verify_client_assertion(header_token, key=key.public_key())
    with pytest.raises(ValueError):
        sign_client_assertion(
            ClientAssertionClaims.model_validate(payload), key=key, algorithm=SigningAlgorithm.EDDSA
        )
