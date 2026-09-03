from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .models import OpenApiTrailingSlash

_PATH_EXPRESSION = re.compile(r"\{[^{}]+\}")


@dataclass(frozen=True, slots=True)
class OpenApiPathMatch:
    method: str
    template: str


def match_openapi_path(
    templates: tuple[str, ...],
    *,
    method: str,
    path: str,
    trailing_slash: OpenApiTrailingSlash,
) -> OpenApiPathMatch:
    if not method or not path or "?" in path or "#" in path:
        raise ValueError("Invalid OpenAPI operation target")
    request_segments = _segments(path, trailing_slash)
    matches: list[tuple[tuple[int, ...], str]] = []
    for template in templates:
        template_segments = _segments(template, trailing_slash)
        if len(template_segments) != len(request_segments):
            continue
        score: list[int] = []
        for expected, actual in zip(template_segments, request_segments, strict=True):
            matched, templated = _match_segment(expected, actual)
            if not matched:
                break
            score.append(0 if templated else 1)
        else:
            matches.append((tuple(score), template))
    if not matches:
        raise ValueError("OpenAPI operation is not documented")
    matches.sort(reverse=True)
    if len(matches) > 1 and matches[0][0] == matches[1][0]:
        raise ValueError("Ambiguous OpenAPI path templates")
    return OpenApiPathMatch(method=method.upper(), template=matches[0][1])


def resolve_openapi_url(
    final_inspect_url: str, reference: str, *, allow_insecure_loopback: bool = False
) -> str:
    inspect = urlsplit(final_inspect_url)
    inspect_allowed = inspect.scheme == "https" or (
        allow_insecure_loopback
        and inspect.scheme == "http"
        and inspect.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if (
        not inspect_allowed
        or not inspect.hostname
        or inspect.username
        or inspect.password
        or inspect.fragment
    ):
        raise ValueError("Invalid final AEP Inspect URL")
    resolved = urlsplit(urljoin(final_inspect_url, reference))
    if inspect.scheme == "https" and resolved.scheme != "https":
        raise ValueError("Invalid AEP OpenAPI URL")
    allowed = resolved.scheme == "https" or (
        allow_insecure_loopback
        and resolved.scheme == "http"
        and resolved.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if (
        not allowed
        or not resolved.hostname
        or resolved.username
        or resolved.password
        or resolved.fragment
    ):
        raise ValueError("Invalid AEP OpenAPI URL")
    return resolved.geturl()


def _segments(path: str, mode: OpenApiTrailingSlash) -> tuple[str, ...]:
    normalized = (
        path[:-1]
        if mode == OpenApiTrailingSlash.EQUIVALENT and path != "/" and path.endswith("/")
        else path
    )
    return tuple(normalized.removeprefix("/").split("/"))


def _match_segment(template: str, value: str) -> tuple[bool, bool]:
    remainder = _PATH_EXPRESSION.sub("", template)
    if "{" in remainder or "}" in remainder:
        return False, False
    expressions = tuple(_PATH_EXPRESSION.finditer(template))
    if not expressions:
        return template == value, False
    position = 0
    pattern: list[str] = []
    for expression in expressions:
        pattern.append(re.escape(template[position : expression.start()]))
        pattern.append(r"[^/?#]+")
        position = expression.end()
    pattern.append(re.escape(template[position:]))
    return re.fullmatch("".join(pattern), value) is not None, True
