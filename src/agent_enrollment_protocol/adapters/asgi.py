from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Awaitable, Callable, Iterable, Mapping, MutableMapping, Sequence
from typing import Any, Protocol
from urllib.parse import quote, quote_from_bytes, urlsplit, urlunsplit

from pydantic import BaseModel

from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AEP_PROBLEM_MEDIA_TYPE,
    AEP_WELL_KNOWN_PATH,
    AuthorizationCarrier,
    AuthorizationScheme,
    Command,
    command_path_from_inspect,
    media_type_essence,
    parse_authorization,
)
from agent_enrollment_protocol.core.errors import AepAuthorizationError
from agent_enrollment_protocol.service import (
    AuthenticatedPrincipal,
    CommandOptions,
    ProtectedResourceRequest,
    Service,
    ServiceResult,
)

AsgiScope = MutableMapping[str, Any]
AsgiMessage = MutableMapping[str, Any]
AsgiReceive = Callable[[], Awaitable[AsgiMessage]]
AsgiSend = Callable[[AsgiMessage], Awaitable[None]]

DEFAULT_INSPECT_CACHE_CONTROL = "public, max-age=300"
DEFAULT_MAXIMUM_REQUEST_BODY_BYTES = 1 << 20
AEP_PRINCIPAL_SCOPE_KEY = "aep.principal"
_HTTP_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


class _RequestDisconnected(Exception):
    pass


class AsgiApplication(Protocol):
    async def __call__(self, scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None: ...


class AepAsgiApplication:
    def __init__(
        self,
        service: Service,
        application: AsgiApplication | None = None,
        *,
        inspect_cache_control: str = DEFAULT_INSPECT_CACHE_CONTROL,
        maximum_request_body_bytes: int = DEFAULT_MAXIMUM_REQUEST_BODY_BYTES,
    ) -> None:
        if not isinstance(service, Service):
            raise TypeError("AEP ASGI application requires a Service")
        if (
            not isinstance(maximum_request_body_bytes, int)
            or isinstance(maximum_request_body_bytes, bool)
            or maximum_request_body_bytes < 1
        ):
            raise ValueError("AEP ASGI request body limit must be positive")
        try:
            encoded_cache_control = inspect_cache_control.encode("latin-1")
        except (AttributeError, UnicodeEncodeError) as error:
            raise ValueError(
                "AEP Inspect Cache-Control must be a valid HTTP field value"
            ) from error
        if (
            not inspect_cache_control.strip()
            or b"\r" in encoded_cache_control
            or b"\n" in encoded_cache_control
        ):
            raise ValueError("AEP Inspect Cache-Control must be a valid HTTP field value")

        document = service.inspect_document
        inspect_body = _json_bytes(document.to_wire())
        self._application = application if application is not None else _default_application
        self._command_paths = {
            command_path_from_inspect(document, command): command
            for command in Command
            if command is not Command.INSPECT and command.value in document.commands.supported
        }
        self._inspect_body = inspect_body
        self._inspect_cache_control = inspect_cache_control
        self._inspect_etag = f'"sha256:{hashlib.sha256(inspect_body).hexdigest()}"'
        self._maximum_request_body_bytes = maximum_request_body_bytes
        self._service = service

    async def __call__(self, scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
        if scope.get("type") != "http":
            await self._application(scope, receive, send)
            return

        path = scope.get("path")
        if path == AEP_WELL_KNOWN_PATH:
            await self._serve_inspect(scope, send)
            return

        command = self._command_paths.get(path) if isinstance(path, str) else None
        if command is None:
            await self._application(scope, receive, send)
            return
        await self._serve_command(scope, receive, send, command)

    async def _serve_inspect(self, scope: AsgiScope, send: AsgiSend) -> None:
        if scope.get("method") != "GET":
            await _send_problem(
                send,
                400,
                "Invalid request",
                code="invalid_request",
                headers={"Allow": "GET"},
            )
            return

        headers = _request_headers(scope)
        if _etag_matches(headers.get("if-none-match"), self._inspect_etag):
            await _send_response(
                send,
                304,
                b"",
                {
                    "Cache-Control": self._inspect_cache_control,
                    "ETag": self._inspect_etag,
                },
            )
            return
        await _send_response(
            send,
            200,
            self._inspect_body,
            {
                "Cache-Control": self._inspect_cache_control,
                "Content-Type": AEP_MEDIA_TYPE,
                "ETag": self._inspect_etag,
            },
        )

    async def _serve_command(
        self,
        scope: AsgiScope,
        receive: AsgiReceive,
        send: AsgiSend,
        command: Command,
    ) -> None:
        expected_method = "GET" if command is Command.STATUS else "POST"
        if scope.get("method") != expected_method:
            await _send_problem(
                send,
                400,
                "Invalid request",
                code="invalid_request",
                headers={"Allow": expected_method},
            )
            return

        headers = _request_headers(scope)
        assertion = _command_assertion(headers.get("authorization"))
        if command is Command.STATUS:
            status_result = await self._service.status(CommandOptions(client_assertion=assertion))
            await _send_service_result(send, status_result)
            return

        if not _single_media_type(headers.get("content-type"), AEP_MEDIA_TYPE):
            await _send_problem(send, 400, "Invalid request", code="invalid_request")
            return
        try:
            body = await _read_body(receive, self._maximum_request_body_bytes)
        except _RequestDisconnected:
            return
        if body is None:
            await _send_problem(send, 400, "Invalid request", code="invalid_request")
            return
        options = CommandOptions(
            client_assertion=assertion,
            idempotency_key=_single_header(headers.get("idempotency-key")) or "",
        )
        result: ServiceResult[Any]
        if command is Command.ENROLL:
            result = await self._service.enroll(body, options)
        elif command is Command.GRANT:
            result = await self._service.grant(body, options)
        else:
            result = await self._service.revoke(body, options)
        await _send_service_result(send, result)


class AepAuthenticationMiddleware:
    def __init__(
        self,
        application: AsgiApplication,
        service: Service,
        *,
        resource_origin: str,
        allow_insecure_loopback: bool = False,
    ) -> None:
        if not callable(application):
            raise TypeError("AEP authentication middleware requires an ASGI application")
        if not isinstance(service, Service):
            raise TypeError("AEP authentication middleware requires a Service")
        self._application = application
        self._resource_origin = _resource_origin(resource_origin, allow_insecure_loopback)
        self._service = service

    async def __call__(self, scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
        if scope.get("type") != "http":
            await self._application(scope, receive, send)
            return

        result = await self._service.authenticate_protected_resource(
            ProtectedResourceRequest(
                headers=_request_headers(scope),
                method=_scope_text(scope, "method"),
                url=_resource_url(self._resource_origin, scope),
            )
        )
        if not result.authenticated:
            if result.response is None:
                raise RuntimeError("AEP Service returned an incomplete authentication result")
            await _send_service_result(send, result.response)
            return
        if result.principal is None:
            raise RuntimeError("AEP Service returned an authenticated result without a principal")
        authenticated_scope = dict(scope)
        authenticated_scope[AEP_PRINCIPAL_SCOPE_KEY] = result.principal
        await self._application(authenticated_scope, receive, send)


def principal_from_scope(scope: Mapping[str, Any]) -> AuthenticatedPrincipal | None:
    principal = scope.get(AEP_PRINCIPAL_SCOPE_KEY)
    return principal if isinstance(principal, AuthenticatedPrincipal) else None


async def _default_application(scope: AsgiScope, receive: AsgiReceive, send: AsgiSend) -> None:
    scope_type = scope.get("type")
    if scope_type == "http":
        await _send_problem(send, 404, "Not Found")
        return
    if scope_type != "lifespan":
        raise RuntimeError("AEP ASGI application received an unsupported scope")
    while True:
        message_type = (await receive()).get("type")
        if message_type == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message_type == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return
        else:
            raise RuntimeError("AEP ASGI application received an invalid lifespan message")


async def _read_body(receive: AsgiReceive, maximum: int) -> bytes | None:
    body = bytearray()
    while True:
        message = await receive()
        message_type = message.get("type")
        if message_type == "http.disconnect":
            raise _RequestDisconnected
        if message_type != "http.request":
            raise RuntimeError("AEP ASGI application received an invalid request message")
        chunk = message.get("body", b"")
        if not isinstance(chunk, bytes):
            raise RuntimeError("AEP ASGI request body chunks must be bytes")
        if len(body) + len(chunk) > maximum:
            return None
        body.extend(chunk)
        if not message.get("more_body", False):
            return bytes(body)


async def _send_service_result(send: AsgiSend, result: ServiceResult[Any]) -> None:
    value: object = result.problem if result.problem is not None else result.body
    if isinstance(value, BaseModel):
        value = value.model_dump(by_alias=True, exclude_none=True, mode="json")
    body = _json_bytes(value)
    headers = dict(result.headers)
    headers["Cache-Control"] = "no-store"
    headers["Content-Type"] = result.content_type
    await _send_response(send, result.status, body, headers)


async def _send_problem(
    send: AsgiSend,
    status: int,
    title: str,
    *,
    code: str | None = None,
    headers: Mapping[str, str] | None = None,
) -> None:
    response_headers = dict(headers or {})
    response_headers["Cache-Control"] = "no-store"
    response_headers["Content-Type"] = AEP_PROBLEM_MEDIA_TYPE
    problem = {
        "status": status,
        "title": title,
        "type": f"urn:aep:error:{code}" if code is not None else "about:blank",
    }
    if code is not None:
        problem["code"] = code
    await _send_response(send, status, _json_bytes(problem), response_headers)


async def _send_response(
    send: AsgiSend,
    status: int,
    body: bytes,
    headers: Mapping[str, str],
) -> None:
    values = {
        name.lower(): value for name, value in headers.items() if name.lower() != "content-length"
    }
    if status != 304:
        values["content-length"] = str(len(body))
    encoded: list[tuple[bytes, bytes]] = []
    for name, value in values.items():
        if (
            not name
            or any(character not in _HTTP_TOKEN_CHARACTERS for character in name)
            or "\r" in value
            or "\n" in value
            or any(ord(character) > 255 for character in value)
        ):
            raise ValueError("AEP ASGI response contains an invalid HTTP field")
        encoded.append((name.encode("ascii"), value.encode("latin-1")))
    await send({"type": "http.response.start", "status": status, "headers": encoded})
    await send({"type": "http.response.body", "body": body})


def _request_headers(scope: Mapping[str, Any]) -> Mapping[str, str | Sequence[str]]:
    grouped: dict[str, list[str]] = {}
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, Iterable):
        raise RuntimeError("AEP ASGI request headers must be iterable")
    for item in raw_headers:
        if not isinstance(item, Iterable):
            raise RuntimeError("AEP ASGI request header entries must be pairs")
        try:
            raw_name, raw_value = item
        except (TypeError, ValueError) as error:
            raise RuntimeError("AEP ASGI request header entries must be pairs") from error
        if not isinstance(raw_name, bytes) or not isinstance(raw_value, bytes):
            raise RuntimeError("AEP ASGI request headers must contain bytes")
        name = raw_name.decode("latin-1").lower()
        grouped.setdefault(name, []).append(raw_value.decode("latin-1"))
    return {
        name: values[0] if len(values) == 1 else tuple(values) for name, values in grouped.items()
    }


def _single_header(value: str | Sequence[str] | None) -> str | None:
    return value if isinstance(value, str) else None


def _single_media_type(value: str | Sequence[str] | None, expected: str) -> bool:
    return isinstance(value, str) and media_type_essence(value) == expected


def _command_assertion(value: str | Sequence[str] | None) -> str:
    if not isinstance(value, str):
        return ""
    try:
        presentation = parse_authorization(value, AuthorizationCarrier.STANDARD)
    except AepAuthorizationError:
        return ""
    return presentation.credentials if presentation.scheme is AuthorizationScheme.AEP else ""


def _etag_matches(value: str | Sequence[str] | None, expected: str) -> bool:
    values = (value,) if isinstance(value, str) else value or ()
    for field_value in values:
        for candidate in field_value.split(","):
            candidate = candidate.strip()
            if (
                candidate == "*"
                or candidate == expected
                or candidate.removeprefix("W/") == expected
            ):
                return True
    return False


def _resource_origin(value: str, allow_insecure_loopback: bool) -> tuple[str, str]:
    parsed = urlsplit(value)
    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("AEP protected-resource origin is invalid") from error
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
    ):
        raise ValueError(
            "AEP protected-resource origin must not contain credentials, path, query, or fragment"
        )
    secure = parsed.scheme == "https"
    loopback = parsed.scheme == "http" and allow_insecure_loopback and _is_loopback(parsed.hostname)
    if not secure and not loopback:
        raise ValueError("AEP protected-resource origin must use HTTPS")
    return parsed.scheme, parsed.netloc


def _is_loopback(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _resource_url(origin: tuple[str, str], scope: Mapping[str, Any]) -> str:
    raw_path = scope.get("raw_path")
    if isinstance(raw_path, bytes):
        path = quote_from_bytes(raw_path, safe="/%:@!$&'()*+,;=-._~")
    else:
        path = quote(_scope_text(scope, "path"), safe="/:@!$&'()*+,;=-._~")
    raw_query = scope.get("query_string", b"")
    if not isinstance(raw_query, bytes):
        raise RuntimeError("AEP ASGI query string must be bytes")
    return urlunsplit((origin[0], origin[1], path, raw_query.decode("ascii"), ""))


def _scope_text(scope: Mapping[str, Any], name: str) -> str:
    value = scope.get(name)
    if not isinstance(value, str):
        raise RuntimeError(f'AEP ASGI scope field "{name}" must be text')
    return value


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
