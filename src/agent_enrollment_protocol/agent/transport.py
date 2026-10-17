from __future__ import annotations

import ssl
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Protocol

import httpx

from agent_enrollment_protocol.core import HttpRequest, HttpResponse


class AsyncHttpTransport(Protocol):
    async def send(self, request: HttpRequest) -> HttpResponse: ...

    async def aclose(self) -> None: ...


class HttpxTransport:
    def __init__(
        self, client: httpx.AsyncClient | None = None, *, maximum_response_bytes: int = 1 << 20
    ) -> None:
        if maximum_response_bytes < 1:
            raise ValueError("maximum_response_bytes must be positive")
        if client is None:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            client = httpx.AsyncClient(follow_redirects=False, verify=context)
        self._client = client
        self._maximum_response_bytes = maximum_response_bytes

    async def send(self, request: HttpRequest) -> HttpResponse:
        return await self._send(self._client, request)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _send(self, client: httpx.AsyncClient, request: HttpRequest) -> HttpResponse:
        outbound = httpx.Request(
            request.method,
            request.url,
            headers=dict(request.headers),
            content=request.body,
        )
        response = await client.send(outbound, auth=None, follow_redirects=False, stream=True)
        try:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > self._maximum_response_bytes:
                    raise ValueError("AEP response exceeds the configured limit")
                body.extend(chunk)
            return HttpResponse(
                status=response.status_code,
                headers=dict(response.headers),
                body=bytes(body),
            )
        finally:
            await response.aclose()


def _fresh_cache(
    *,
    cache_control: str,
    cached_at: datetime,
    now: datetime,
    age: str,
    date: str,
    expires: str,
) -> bool:
    directives = {}
    for item in cache_control.split(","):
        key, _, value = item.strip().partition("=")
        directives[key.lower()] = value.strip('"')
    if "no-cache" in directives or "no-store" in directives:
        return False
    try:
        response_date = _http_date(date) if date else cached_at
        lifetime = 300.0
        if "max-age" in directives:
            raw_lifetime = directives["max-age"]
            if not raw_lifetime.isascii() or not raw_lifetime.isdecimal():
                return False
            lifetime = float(raw_lifetime)
        elif expires:
            lifetime = (_http_date(expires) - response_date).total_seconds()
        if age and (not age.isascii() or not age.isdecimal()):
            return False
        initial_age = max((cached_at - response_date).total_seconds(), float(age or "0"))
        # cached_at is the request start, so elapsed time includes the response delay.
        resident_time = (now - cached_at).total_seconds()
        return resident_time >= 0 and initial_age + resident_time < lifetime
    except (ValueError, OverflowError, TypeError):
        return False


def _http_date(value: str) -> datetime:
    result = parsedate_to_datetime(value)
    return result.replace(tzinfo=UTC) if result.tzinfo is None else result
