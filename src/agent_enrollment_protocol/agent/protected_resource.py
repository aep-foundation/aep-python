from __future__ import annotations

import asyncio
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast
from urllib.parse import urljoin, urlsplit

import httpx

from agent_enrollment_protocol.core import (
    AuthorizationCarrier,
    HttpRequest,
    HttpResponse,
    OpenApiSecurityDisposition,
    match_openapi_path,
    media_type_essence,
    resolve_openapi_security,
    resolve_openapi_url,
    same_origin,
)
from agent_enrollment_protocol.core.validation import _reject_duplicate_members

from .client import Agent
from .transport import AsyncHttpTransport, HttpxTransport
from .types import (
    AgentCommandError,
    AuthenticationOptions,
    CredentialUnavailableError,
    GrantOptions,
    Inspection,
)

_REDIRECTS = {301, 302, 303, 307, 308}
_SECRET_HEADERS = {
    "authorization",
    "aep-authorization",
    "proxy-authorization",
    "cookie",
    "payment",
    "payment-signature",
    "x-payment",
    "x-api-key",
    "api-key",
}
_PARAMETER = re.compile(r'([a-z_]+)[\t ]*=[\t ]*"([^"\\]*)"', re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class FetchProtectedResourceOptions:
    agent: Agent
    request: HttpRequest
    carrier: str = "Authorization"
    credential_id: str | None = None
    grant_type: str | None = None
    additional_authentication_headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    transport: AsyncHttpTransport | None = None
    max_redirects: int = 5
    timeout: float = 30.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "additional_authentication_headers",
            MappingProxyType(dict(self.additional_authentication_headers)),
        )
        AuthorizationCarrier(self.carrier)
        if (
            isinstance(self.max_redirects, bool)
            or not isinstance(self.max_redirects, int)
            or self.max_redirects < 0
        ):
            raise ValueError("max_redirects must be a non-negative integer")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        if self.request.body is not None and not isinstance(self.request.body, bytes):
            raise ValueError("AEP authentication requires a replayable bytes request body")


async def fetch_protected_resource(options: FetchProtectedResourceOptions) -> HttpResponse:
    """Authenticate a replayable request without automatically enrolling with a Service.

    Put payment credentials and custom API keys in additional_authentication_headers: they are
    sent only after AEP authentication and only to the original origin. The transport must return
    redirects without following them; HttpxTransport enforces this for its HTTPX client.
    """
    transport = options.transport or HttpxTransport(
        maximum_response_bytes=options.agent._maximum_response_bytes
    )
    try:
        async with asyncio.timeout(options.timeout):
            return await _fetch(options, transport)
    finally:
        if options.transport is None:
            await transport.aclose()


async def _fetch(
    options: FetchProtectedResourceOptions, transport: AsyncHttpTransport
) -> HttpResponse:
    agent = options.agent
    request = options.request
    target = request.url
    _validate_url(target, agent._allow_insecure_loopback)
    initial = target
    redirects = 0
    require_challenge = False
    use_openapi = True
    while redirects <= options.max_redirects:
        session = agent.service(target)
        inspection: Inspection | None = None
        methods: tuple[str, ...] | None = None
        try:
            inspection = await session.inspect()
            if use_openapi:
                methods = await _openapi_methods(inspection, request.method, target, agent)
        except (ValueError, OSError, httpx.HTTPError, TimeoutError, AgentCommandError):
            # OpenAPI is advisory. A live challenge remains authoritative when discovery fails.
            methods = None
        anonymous: HttpResponse | None = None
        policy_used = methods is not None
        if methods is None or require_challenge:
            anonymous = await _send(
                transport,
                agent._maximum_response_bytes,
                HttpRequest(
                    method=request.method,
                    url=target,
                    body=request.body,
                    headers=_anonymous_headers(request.headers)
                    if same_origin(initial, target)
                    else {},
                ),
            )
            if anonymous.status not in _REDIRECTS:
                challenge = _challenge(anonymous)
                if challenge is None:
                    return anonymous
                service_did, inspect_url = challenge
                _validate_url(inspect_url, agent._allow_insecure_loopback)
                if not same_origin(target, inspect_url):
                    raise ValueError("AEP challenge Inspect URI changed origin")
                inspection = await session.inspect()
                if inspection.document.service.did != service_did:
                    raise ValueError("AEP challenge Service DID did not match Inspect")
                if methods is None:
                    methods = (
                        inspection.document.authentication.methods
                        if inspection.document.authentication
                        else ()
                    )
                if not methods:
                    return anonymous
            else:
                target, crossed = _redirect(anonymous, target, agent._allow_insecure_loopback)
                require_challenge |= crossed
                use_openapi = True
                redirects += 1
                continue
        authentication = AuthenticationOptions(
            resource=target,
            carrier=options.carrier,
            credential_id=options.credential_id,
            grant_type=options.grant_type,
            allowed_methods=methods,
        )
        if options.grant_type is not None and options.grant_type not in methods:
            raise ValueError(
                "Requested grant type is not permitted by resource authentication policy"
            )
        try:
            headers = await session.authentication_headers(authentication)
        except CredentialUnavailableError:
            if options.credential_id is not None:
                raise
            grant_type = options.grant_type or next((m for m in methods if m != "aep-jwt"), None)
            if grant_type is None:
                raise
            await session.grant(GrantOptions(grant_type=grant_type))
            headers = await session.authentication_headers(authentication)
        response = await _send(
            transport,
            agent._maximum_response_bytes,
            HttpRequest(
                method=request.method,
                url=target,
                body=request.body,
                headers=_authenticated_headers(options, headers, same_origin(initial, target)),
            ),
        )
        if policy_used and _challenge(response) is not None:
            use_openapi = False
            continue
        if response.status not in _REDIRECTS:
            return response
        target, crossed = _redirect(response, target, agent._allow_insecure_loopback)
        require_challenge |= crossed
        use_openapi = True
        redirects += 1
    raise ValueError(f"AEP protected resource exceeded {redirects} redirects")


async def _send(transport: AsyncHttpTransport, maximum: int, request: HttpRequest) -> HttpResponse:
    response = await transport.send(request)
    if len(response.body) > maximum:
        raise ValueError("AEP response exceeds the configured byte limit")
    return response


def _validate_url(value: str, allow_loopback: bool) -> None:
    parsed = urlsplit(value)
    _ = parsed.port
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "#" in value
        or any(c.isspace() or ord(c) < 32 for c in value)
        or not (
            parsed.scheme == "https"
            or (
                allow_loopback
                and parsed.scheme == "http"
                and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            )
        )
    ):
        raise ValueError("AEP resource requires an HTTPS URL without user information or fragments")


def _redirect(response: HttpResponse, target: str, allow_loopback: bool) -> tuple[str, bool]:
    location = _header(response.headers, "location")
    if not location:
        raise ValueError("AEP redirect has no Location")
    if "#" in location:
        raise ValueError("AEP redirect contains a fragment")
    next_url = urljoin(target, location)
    _validate_url(next_url, allow_loopback)
    if urlsplit(target).scheme == "https" and urlsplit(next_url).scheme != "https":
        raise ValueError("AEP redirect weakens HTTPS")
    return next_url, not same_origin(target, next_url)


def _header(headers: Mapping[str, str], name: str) -> str:
    values = [value for key, value in headers.items() if key.lower() == name]
    if len(values) > 1:
        raise ValueError(f"Ambiguous {name} header")
    return values[0] if values else ""


def _challenge(response: HttpResponse) -> tuple[str, str] | None:
    value = _header(response.headers, "www-authenticate")
    if response.status != 401 or not re.match(r"^AEP[\t ]+", value, re.IGNORECASE):
        return None
    parameters: dict[str, str] = {}
    remainder = value[3:].strip()
    while remainder:
        matched = _PARAMETER.match(remainder)
        if matched is None or matched[1].lower() in parameters:
            return None
        parameters[matched[1].lower()] = matched[2]
        remainder = remainder[matched.end() :].strip()
        if remainder:
            if not remainder.startswith(","):
                return None
            remainder = remainder[1:].strip()
            if not remainder:
                return None
    did, inspect = parameters.get("service_did"), parameters.get("inspect")
    return (did, inspect) if did and inspect else None


def _anonymous_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() not in _SECRET_HEADERS}


def _authenticated_headers(
    options: FetchProtectedResourceOptions, controlled: Mapping[str, str], original: bool
) -> dict[str, str]:
    headers = _anonymous_headers(options.request.headers) if original else {}
    controlled_names = {name.lower() for name in controlled}
    additional = options.additional_authentication_headers if original else {}
    for name, value in additional.items():
        if name.lower() in controlled_names or name.lower() == "aep-authorization":
            raise ValueError("Additional authentication header conflicts with AEP presentation")
        headers = {
            key: existing for key, existing in headers.items() if key.lower() != name.lower()
        }
        headers[name] = value
    headers = {key: value for key, value in headers.items() if key.lower() not in controlled_names}
    headers.update(controlled)
    return headers


async def _openapi_methods(
    inspection: Inspection, method: str, target: str, agent: Agent
) -> tuple[str, ...] | None:
    import json

    advertisement = inspection.document.http.openapi
    if advertisement is None:
        return None
    url = resolve_openapi_url(
        inspection.final_url,
        advertisement.url,
        allow_insecure_loopback=agent._allow_insecure_loopback,
    )
    _validate_url(url, agent._allow_insecure_loopback)
    response: HttpResponse | None = None
    for _ in range(6):
        response = await agent._inspect_transport.send(
            HttpRequest(
                method="GET",
                url=url,
                headers={
                    "Accept": "application/vnd.oai.openapi+json;version=3.1, application/json"
                },
            )
        )
        if response.status not in _REDIRECTS:
            break
        url, _ = _redirect(response, url, agent._allow_insecure_loopback)
    else:
        return None
    content_type = _header(response.headers, "content-type")
    if (
        response.status != 200
        or len(response.body) > agent._maximum_response_bytes
        or media_type_essence(content_type)
        not in {"application/json", "application/vnd.oai.openapi+json"}
        or (
            media_type_essence(content_type) == "application/vnd.oai.openapi+json"
            and re.search(r';\s*version\s*=\s*"?3\.1"?(?:\s*;|\s*$)', content_type, re.IGNORECASE)
            is None
        )
    ):
        return None
    _reject_duplicate_members(response.body, "OpenAPI document")
    document = json.loads(response.body)
    if not isinstance(document, dict) or not re.fullmatch(
        r"3\.1\.\d+", str(document.get("openapi", ""))
    ):
        return None
    paths = document.get("paths")
    if not isinstance(paths, dict) or any(not isinstance(key, str) for key in paths):
        return None
    matched = match_openapi_path(
        tuple(paths),
        method=method,
        path=urlsplit(target).path or "/",
        trailing_slash=advertisement.path_matching.trailing_slash,
    )
    item = paths[matched.template]
    if not isinstance(item, dict) or "$ref" in item:
        return None
    operation = item.get(method.lower())
    if not isinstance(operation, dict):
        return None
    components = document.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    if not isinstance(schemes, dict):
        return None
    advertised = (
        inspection.document.authentication.methods if inspection.document.authentication else ()
    )
    supported = {
        name: scheme.get("x-aep-authentication-method")
        for name, scheme in schemes.items()
        if isinstance(scheme, dict)
        and "$ref" not in scheme
        and scheme.get("x-aep-authentication-method") in advertised
    }
    root, selected = document.get("security"), operation.get("security")
    if ("security" in document and root is None) or ("security" in operation and selected is None):
        return None
    if not _security_shape(root) or not _security_shape(selected):
        return None
    resolution = resolve_openapi_security(
        root=root, operation=selected, supported_schemes=supported
    )
    if resolution.disposition not in {
        OpenApiSecurityDisposition.REQUIRED,
        OpenApiSecurityDisposition.ALTERNATIVES,
    }:
        return None
    alternatives = [
        requirement[0] for requirement in resolution.satisfiable if len(requirement) == 1
    ]
    return tuple(cast(str, supported[name]) for name in alternatives) or None


def _security_shape(value: object) -> bool:
    return value is None or (
        isinstance(value, list)
        and all(
            isinstance(item, dict)
            and all(
                isinstance(key, str)
                and isinstance(scopes, list)
                and all(isinstance(scope, str) for scope in scopes)
                for key, scopes in item.items()
            )
            for item in value
        )
    )
