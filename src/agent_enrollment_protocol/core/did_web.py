from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlsplit


def did_web_document_url(did: str, *, allow_insecure_loopback: bool = False) -> str:
    prefix = "did:web:"
    if not did.startswith(prefix):
        raise ValueError(f"Unsupported DID method: {did}")
    parts = did[len(prefix) :].split(":")
    if not parts[0]:
        raise ValueError(f"Invalid did:web identifier: {did}")
    host = unquote(parts[0])
    path = (
        "/.well-known/did.json"
        if len(parts) == 1
        else f"/{'/'.join(unquote(part) for part in parts[1:])}/did.json"
    )
    scheme = "http" if allow_insecure_loopback and _is_loopback(host) else "https"
    url = f"{scheme}://{host}{path}"
    parsed = urlsplit(url)
    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid did:web identifier: {did}") from error
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"Invalid did:web identifier: {did}")
    return url


def select_did_web_public_jwk(
    document: Mapping[str, Any], *, did: str, key_id: str
) -> dict[str, Any]:
    key_did = key_id.partition("#")[0]
    if key_did != did:
        raise ValueError("AEP did:web key ID does not identify the assertion issuer")
    methods = document.get("verificationMethod")
    if not isinstance(methods, list):
        raise ValueError(f"No public JWK found for {key_id}")
    for method in methods:
        if not isinstance(method, dict) or method.get("id") != key_id:
            continue
        jwk = method.get("publicKeyJwk")
        if isinstance(jwk, dict):
            return dict(jwk)
    raise ValueError(f"No public JWK found for {key_id}")


def _is_loopback(host: str) -> bool:
    hostname = urlsplit(f"//{host}").hostname
    return hostname in {"localhost", "127.0.0.1", "::1"}
