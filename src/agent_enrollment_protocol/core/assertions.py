from __future__ import annotations

import json
import time
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from typing import Any

import jwt

from .errors import AepAssertionError
from .models import AssertionOperation, ClientAssertionClaims, SigningAlgorithm


@dataclass(frozen=True, slots=True)
class VerifyClientAssertionOptions:
    algorithms: tuple[SigningAlgorithm, ...] = (SigningAlgorithm.EDDSA, SigningAlgorithm.ES256)
    audience: str | None = None
    issuer: str | None = None
    subject: str | None = None
    operation: AssertionOperation | None = None
    resource: str | None = None
    current_time: int | None = None
    clock_tolerance_seconds: int = 0
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        if self.clock_tolerance_seconds < 0:
            raise ValueError("clock_tolerance_seconds must not be negative")


def sign_client_assertion(
    claims: ClientAssertionClaims,
    *,
    key: Any,
    algorithm: SigningAlgorithm,
    key_id: str | None = None,
    allow_insecure_loopback: bool = False,
) -> str:
    claims = ClientAssertionClaims.model_validate_json(
        json.dumps(claims.to_wire()),
        context={"allow_insecure_loopback": allow_insecure_loopback},
    )
    kid = key_id or claims.iss
    _require_key_binding(kid, claims)
    return jwt.encode(
        claims.to_wire(),
        key,
        algorithm=algorithm.value,
        headers={"kid": kid, "typ": "JWT"},
    )


def verify_client_assertion(
    assertion: str, *, key: Any, options: VerifyClientAssertionOptions | None = None
) -> ClientAssertionClaims:
    options = options or VerifyClientAssertionOptions()
    try:
        header = jwt.get_unverified_header(assertion)
    except jwt.PyJWTError as error:
        raise AepAssertionError("Invalid AEP client assertion.") from error
    if header.get("typ") != "JWT" or not isinstance(header.get("kid"), str):
        raise AepAssertionError("Invalid AEP client assertion JOSE header.")
    algorithm = header.get("alg")
    allowed = tuple(item.value for item in options.algorithms)
    if algorithm not in allowed:
        raise AepAssertionError("AEP client assertion signing algorithm is not allowed.")
    try:
        payload = jwt.decode(
            assertion,
            key,
            algorithms=list(allowed),
            options={
                "require": ["aud", "exp", "iat", "iss", "jti", "op", "sub"],
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
            },
        )
        claims = ClientAssertionClaims.model_validate_json(
            json.dumps(payload),
            context={"allow_insecure_loopback": options.allow_insecure_loopback},
        )
    except (jwt.PyJWTError, ValueError) as error:
        raise AepAssertionError("Invalid AEP client assertion.") from error
    _require_key_binding(header["kid"], claims)
    now = options.current_time if options.current_time is not None else int(time.time())
    tolerance = options.clock_tolerance_seconds
    if claims.iat > now + tolerance or claims.exp <= now - tolerance:
        raise AepAssertionError("AEP client assertion is outside its valid time window.")
    expected = (
        ("audience", options.audience, claims.aud),
        ("issuer", options.issuer, claims.iss),
        ("subject", options.subject, claims.sub),
        ("operation", options.operation, claims.op),
        ("resource", options.resource, claims.resource),
    )
    for name, wanted, actual in expected:
        if wanted is not None and wanted != actual:
            raise AepAssertionError(f"AEP client assertion {name} does not match.")
    return claims


def decode_jwt_unverified(assertion: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = assertion.split(".")
    if len(parts) != 3:
        raise AepAssertionError("Invalid JWT.")
    try:
        header = _decode_part(parts[0])
        payload = _decode_part(parts[1])
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise AepAssertionError("Invalid JWT.") from error
    return header, payload


def _require_key_binding(key_id: str, claims: ClientAssertionClaims) -> None:
    key_did = key_id.partition("#")[0]
    if key_did != claims.iss or claims.iss != claims.sub:
        raise AepAssertionError(
            "AEP client assertion kid, iss, and sub must identify one Agent DID."
        )


def _decode_part(value: str) -> dict[str, Any]:
    decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
    parsed = json.loads(decoded)
    if not isinstance(parsed, dict):
        raise ValueError("JWT part must be an object")
    return parsed
