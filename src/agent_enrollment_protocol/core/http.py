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

_CREDENTIALS_PATTERN = re.compile(r"\A[\x21-\x7e]+\Z")
# CORE-AUTH-001 spells the presentation as `"AEP" 1*SP compact-jws`, so repeated separators belong
# to the grammar, a field value may carry trailing optional whitespace, and the credential itself is
# visible US-ASCII with no space. Requiring a single separator rejected a conforming presentation,
# and allowing a space inside the credential let one field value carry two of them.
_AUTHORIZATION_PATTERN = re.compile(
    r"\A(AEP|Bearer|Basic)[ \t]+([\x21-\x7e]+)[ \t]*\Z", re.IGNORECASE
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
    if not is_endpoint_path(endpoint_base):
        raise ValueError("AEP endpoint_base must be an origin-relative absolute path")
    return endpoint_base if endpoint_base.endswith("/") else f"{endpoint_base}/"


def is_endpoint_path(value: str) -> bool:
    """Reports whether a value can carry a command path appended to it.

    CORE-HTTP-004 builds a command URL by appending the relative path with exactly one `/`
    separator. A base carrying a query, a fragment, or a dot segment cannot satisfy that: the
    command name would land in the query string or walk out of the advertised base.
    """
    if not value.startswith("/") or value.startswith("//"):
        return False
    if "?" in value or "#" in value:
        return False
    return not any(segment in {".", ".."} for segment in value.split("/"))


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
    # Visible US-ASCII excluding space keeps CR, LF, NUL, and other control characters out of a
    # rendered field value, and keeps one field value from carrying two credentials.
    if _CREDENTIALS_PATTERN.fullmatch(value.credentials) is None:
        raise AepAuthorizationError(
            "Authorization credentials must not contain whitespace or control characters.",
            "invalid_request",
        )
    return value.carrier.value, f"{value.scheme.value} {value.credentials}"


def parse_authorization(
    value: str, carrier: AuthorizationCarrier = AuthorizationCarrier.STANDARD
) -> ProtectedResourceAuthorization:
    if carrier is AuthorizationCarrier.DEDICATED and "," in value:
        raise AepAuthorizationError(
            "The dedicated authorization field is ambiguous.", "not_recognized"
        )
    match = _AUTHORIZATION_PATTERN.fullmatch(value)
    if match is None:
        raise AepAuthorizationError(
            "The authorization presentation was not recognized.", "not_recognized"
        )
    schemes = {item.value.lower(): item for item in AuthorizationScheme}
    return ProtectedResourceAuthorization(
        carrier=carrier,
        credentials=match.group(2),
        scheme=schemes[match.group(1).lower()],
    )


def authorization_header_name(carrier: AuthorizationCarrier) -> str:
    if carrier is AuthorizationCarrier.DEDICATED:
        return AEP_AUTHORIZATION_HEADER
    return "Authorization"
