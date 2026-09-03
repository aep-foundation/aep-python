from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .constants import AEP_AUTHORIZATION_HEADER, DEFAULT_HTTP_ENDPOINT_BASE
from .errors import AepAuthorizationError
from .models import (
    AuthorizationCarrier,
    AuthorizationScheme,
    Command,
    InspectDocument,
    ProtectedResourceAuthorization,
)

_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_QUOTED_STRING = r'"(?:[\t !#-\[\]-~\x80-\xff]|\\[\t !-~\x80-\xff])*"'
_MEDIA_TYPE_PATTERN = re.compile(
    rf"\A[ \t]*(?P<type>{_TOKEN})/(?P<subtype>{_TOKEN})[ \t]*"
    rf"(?:;[ \t]*{_TOKEN}[ \t]*=[ \t]*(?:{_TOKEN}|{_QUOTED_STRING})[ \t]*)*\Z"
)


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    body: bytes | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    body: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


def media_type_essence(value: str) -> str:
    match = _MEDIA_TYPE_PATTERN.fullmatch(value)
    if match is None:
        return ""
    return f"{match.group('type')}/{match.group('subtype')}".lower()


def normalize_endpoint_base(endpoint_base: str = DEFAULT_HTTP_ENDPOINT_BASE) -> str:
    if not endpoint_base.startswith("/") or endpoint_base.startswith("//"):
        raise ValueError("AEP endpoint_base must be an origin-relative absolute path")
    return endpoint_base if endpoint_base.endswith("/") else f"{endpoint_base}/"


def command_path(command: Command, endpoint_base: str = DEFAULT_HTTP_ENDPOINT_BASE) -> str:
    if command is Command.INSPECT:
        raise ValueError("Inspect does not have a command endpoint path")
    return f"{normalize_endpoint_base(endpoint_base)}{command.value}"


def command_path_from_inspect(document: InspectDocument, command: Command) -> str:
    return command_path(command, document.http.endpoint_base or DEFAULT_HTTP_ENDPOINT_BASE)


def render_authorization(value: ProtectedResourceAuthorization) -> tuple[str, str]:
    if not value.credentials:
        raise AepAuthorizationError(
            "Authorization credentials must not be empty.", "invalid_request"
        )
    return value.carrier.value, f"{value.scheme.value} {value.credentials}"


def parse_authorization(
    value: str, carrier: AuthorizationCarrier = AuthorizationCarrier.STANDARD
) -> ProtectedResourceAuthorization:
    if carrier is AuthorizationCarrier.DEDICATED and "," in value:
        raise AepAuthorizationError(
            "The dedicated authorization field is ambiguous.", "not_recognized"
        )
    scheme_text, separator, credentials = value.partition(" ")
    schemes = {item.value.lower(): item for item in AuthorizationScheme}
    scheme = schemes.get(scheme_text.lower())
    if not separator or scheme is None or not credentials or credentials[0].isspace():
        raise AepAuthorizationError(
            "The authorization presentation was not recognized.", "not_recognized"
        )
    return ProtectedResourceAuthorization(
        carrier=carrier,
        credentials=credentials,
        scheme=scheme,
    )


def authorization_header_name(carrier: AuthorizationCarrier) -> str:
    if carrier is AuthorizationCarrier.DEDICATED:
        return AEP_AUTHORIZATION_HEADER
    return "Authorization"
