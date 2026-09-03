from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any
from urllib.parse import unquote, urlsplit

_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9A-Fa-f]{2})")


def did_web_document_url(did: str, *, allow_insecure_loopback: bool = False) -> str:
    host, path_parts = _did_web_parts(did)
    path = "/.well-known/did.json" if not path_parts else f"/{'/'.join(path_parts)}/did.json"
    scheme = "http" if allow_insecure_loopback and _is_loopback(host) else "https"
    return f"{scheme}://{host}{path}"


def select_did_web_public_jwk(
    document: Mapping[str, Any], *, did: str, key_id: str
) -> dict[str, Any]:
    if document.get("id") != did:
        raise ValueError("AEP did:web document ID does not identify the assertion issuer")
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
            return deepcopy(jwk)
    raise ValueError(f"No public JWK found for {key_id}")


def _is_loopback(host: str) -> bool:
    hostname = urlsplit(f"//{host}").hostname
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _did_web_parts(did: str) -> tuple[str, tuple[str, ...]]:
    prefix = "did:web:"
    if not did.startswith(prefix):
        raise ValueError(f"Unsupported DID method: {did}")
    encoded_parts = did[len(prefix) :].split(":")
    if (
        not did.isascii()
        or not encoded_parts[0]
        or any(_INVALID_PERCENT_ENCODING.search(part) for part in encoded_parts)
    ):
        raise ValueError(f"Invalid did:web identifier: {did}")
    host = unquote(encoded_parts[0])
    if not host.isascii():
        raise ValueError(f"Invalid did:web identifier: {did}")
    parsed = urlsplit(f"//{host}")
    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid did:web identifier: {did}") from error
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"Invalid did:web identifier: {did}")
    path_parts = tuple(encoded_parts[1:])
    for part in path_parts:
        decoded = unquote(part)
        if not part or decoded in {".", ".."} or any(value in decoded for value in "/\\?#"):
            raise ValueError(f"Invalid did:web identifier: {did}")
    return host, path_parts
