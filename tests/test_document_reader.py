from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

import pytest

from agent_enrollment_protocol.agent import read_service_document
from agent_enrollment_protocol.core import MAX_SERVICE_DOCUMENT_BYTES, ServiceDocument

from .test_service_documents import descriptor, portable


@asynccontextmanager
async def document_server(
    body: bytes,
    *,
    status: int = 200,
    headers: bytes = b"Content-Type: application/json\r\n",
    stall: bool = False,
    truncate: bool = False,
) -> AsyncIterator[tuple[str, list[bytes], asyncio.Event]]:
    requests: list[bytes] = []
    received = asyncio.Event()
    finished = asyncio.Event()

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            received.set()
            if stall:
                await reader.read()
            else:
                length = len(body) + (10 if truncate else 0)
                writer.write(
                    f"HTTP/1.1 {status} Response\r\n".encode()
                    + headers
                    + f"Content-Length: {length}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionResetError, BrokenPipeError):
                await writer.wait_closed()
            finished.set()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    try:
        yield (
            f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/terms.json",
            requests,
            received,
        )
    finally:
        server.close()
        await server.wait_closed()
        if requests:
            await asyncio.wait_for(finished.wait(), timeout=3)


def with_portable(url: str) -> ServiceDocument:
    data = descriptor().to_wire()
    data["representations"].append({"media_type": "application/json", "url": url})
    return ServiceDocument.model_validate(data)


@pytest.mark.asyncio
async def test_reader_downloads_anonymously_and_preserves_service_content() -> None:
    async with document_server(json.dumps(portable()).encode()) as (url, requests, _):
        result = await read_service_document(with_portable(url))
    assert result.reason is None
    assert result.document and result.document.to_wire() == portable()
    assert result.web_url == "https://example.com/terms"
    assert len(requests) == 1
    request = requests[0].lower()
    assert request.startswith(b"get /terms.json http/1.1\r\n")
    assert b"accept: application/json\r\n" in request
    assert b"accept-encoding: identity\r\n" in request
    for name in (b"authorization:", b"aep-authorization:", b"cookie:", b"user-agent:"):
        assert name not in request


@pytest.mark.asyncio
async def test_reader_offers_html_without_fetching_when_portable_is_absent() -> None:
    result = await read_service_document(descriptor())
    assert result.reason == "not_advertised" and result.document is None
    assert result.web_url == "https://example.com/terms"


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
async def test_reader_requires_bounded_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="positive and finite"):
        await read_service_document(descriptor(), timeout=timeout)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,headers,body,truncate",
    [
        (403, b"Content-Type: application/json\r\n", b"{}", False),
        (302, b"Location: /redirect-target\r\n", b"", False),
        (200, b"Content-Type: text/html\r\n", b"{}", False),
        (200, b"Content-Type: application/json; charset=latin-1\r\n", b"{}", False),
        (200, b"Content-Type: application/json\r\nContent-Encoding: gzip\r\n", b"{}", False),
        (200, b"Content-Type: application/json\r\n", b"{", False),
        (200, b"Content-Type: application/json\r\n", b"\xff", False),
        (
            200,
            b"Content-Type: application/json\r\n",
            b" " * (MAX_SERVICE_DOCUMENT_BYTES + 1),
            False,
        ),
        (200, b"Content-Type: application/json\r\n", b"{}", True),
        (
            200,
            b"Content-Type: application/json\r\n",
            json.dumps(portable() | {"id": "other"}).encode(),
            False,
        ),
        (
            200,
            b"Content-Type: application/json\r\n",
            json.dumps(portable() | {"content": [{"type": "future"}]}).encode(),
            False,
        ),
    ],
)
async def test_reader_falls_back_without_following_redirects_or_returning_partial_content(
    status: int, headers: bytes, body: bytes, truncate: bool
) -> None:
    async with document_server(body, status=status, headers=headers, truncate=truncate) as (
        url,
        requests,
        _,
    ):
        result = await read_service_document(with_portable(url))
    assert result.reason == "unavailable_or_unsupported"
    assert result.document is None and result.web_url == "https://example.com/terms"
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_reader_applies_total_timeout_and_propagates_cancellation() -> None:
    async with document_server(b"", stall=True) as (url, requests, _):
        result = await read_service_document(with_portable(url), timeout=0.2)
    assert result.reason == "unavailable_or_unsupported" and len(requests) == 1
    async with document_server(b"", stall=True) as (url, requests, received):
        task = asyncio.create_task(read_service_document(with_portable(url)))
        await asyncio.wait_for(received.wait(), timeout=3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_reader_handles_connection_failure() -> None:
    async with document_server(b"") as (url, _, _):
        selected = with_portable(url)
    result = await read_service_document(selected)
    assert result.reason == "unavailable_or_unsupported"


@pytest.mark.asyncio
async def test_reader_offers_html_when_http_client_cannot_parse_an_advertised_uri() -> None:
    result = await read_service_document(with_portable("https://[v1.test]/terms"))
    assert result.reason == "unavailable_or_unsupported"
    assert result.web_url == "https://example.com/terms" and result.document is None


@pytest.mark.asyncio
async def test_reader_accepts_content_type_parameters() -> None:
    async with document_server(
        json.dumps(portable()).encode(),
        headers=b"Content-Type: application/json; charset=UTF-8; profile=example\r\n",
    ) as (url, _, _):
        result = await read_service_document(with_portable(url))
    assert result.document and result.reason is None
