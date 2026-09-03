from __future__ import annotations

from urllib.parse import SplitResult, unquote, urlsplit

from .constants import AEP_VERSION
from .models import VERSION_PATTERN, InspectDocument


def is_version_compatible(received: str, supported: str = AEP_VERSION) -> bool:
    if VERSION_PATTERN.fullmatch(received) is None or VERSION_PATTERN.fullmatch(supported) is None:
        return False
    return received.partition(".")[0] == supported.partition(".")[0]


def require_service_origin_binding(
    document: InspectDocument,
    final_inspect_url: str,
    *,
    allow_insecure_loopback: bool = False,
) -> None:
    origin = _inspect_origin(final_inspect_url, allow_insecure_loopback)
    did_origin = did_web_origin(
        document.service.did,
        allow_insecure_loopback=allow_insecure_loopback,
    )
    if origin != did_origin:
        raise ValueError("AEP Service DID does not match the final Inspect response origin")


def did_web_origin(did: str, *, allow_insecure_loopback: bool = False) -> str:
    prefix = "did:web:"
    if not did.startswith(prefix):
        raise ValueError("AEP Service identity must use did:web")
    encoded_host = did[len(prefix) :].partition(":")[0]
    if not encoded_host:
        raise ValueError("Invalid did:web Service identity")
    host = unquote(encoded_host)
    scheme = "http" if allow_insecure_loopback and _loopback_host(host) else "https"
    parsed = urlsplit(f"{scheme}://{host}")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid did:web Service identity")
    return _origin(parsed)


def same_origin(first: str, second: str) -> bool:
    return _origin(urlsplit(first)) == _origin(urlsplit(second))


def _inspect_origin(value: str, allow_insecure_loopback: bool) -> str:
    parsed = urlsplit(value)
    insecure_loopback = (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if (
        (parsed.scheme != "https" and not insecure_loopback)
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("AEP Inspect URL must be an absolute HTTPS URL")
    return _origin(parsed)


def _loopback_host(value: str) -> bool:
    return urlsplit(f"//{value}").hostname in {"localhost", "127.0.0.1", "::1"}


def _origin(parsed: SplitResult) -> str:
    if not parsed.hostname:
        raise ValueError("URL must contain a host")
    port = parsed.port
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{effective_port}"
