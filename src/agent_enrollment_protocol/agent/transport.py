from __future__ import annotations

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
        self._client = client or httpx.AsyncClient(follow_redirects=False)
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
