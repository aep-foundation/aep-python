from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from typing import Literal

import httpx

from agent_enrollment_protocol.core import (
    MAX_SERVICE_DOCUMENT_BYTES,
    AepValidationError,
    PortableServiceDocument,
    ServiceDocument,
    media_type_essence,
    parse_portable_service_document,
)


@dataclass(frozen=True, slots=True)
class DocumentReadResult:
    descriptor: ServiceDocument
    web_url: str
    document: PortableServiceDocument | None = None
    reason: Literal["not_advertised", "unavailable_or_unsupported"] | None = None


async def read_service_document(
    descriptor: ServiceDocument, *, timeout: float = 10
) -> DocumentReadResult:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("document timeout must be positive and finite")
    descriptor = ServiceDocument.model_validate(descriptor.to_wire())
    web_url = next(
        item.url for item in descriptor.representations if item.media_type == "text/html"
    )
    portable_url = next(
        (item.url for item in descriptor.representations if item.media_type == "application/json"),
        None,
    )
    if portable_url is None:
        return DocumentReadResult(descriptor, web_url, reason="not_advertised")
    try:
        async with asyncio.timeout(timeout), httpx.AsyncClient(follow_redirects=False) as client:
            request = httpx.Request(
                "GET",
                portable_url,
                headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            )
            response = await client.send(request, auth=None, follow_redirects=False, stream=True)
            try:
                if (
                    not response.is_success
                    or media_type_essence(response.headers.get("content-type", ""))
                    != "application/json"
                    or response.charset_encoding not in (None, "utf-8", "UTF-8")
                    or response.headers.get("content-encoding", "identity").lower() != "identity"
                ):
                    raise ValueError("unsupported document response")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > MAX_SERVICE_DOCUMENT_BYTES:
                        raise ValueError("document exceeds one mebibyte")
                    body.extend(chunk)
                document = parse_portable_service_document(bytes(body), descriptor.id)
                return DocumentReadResult(descriptor, web_url, document=document)
            finally:
                await response.aclose()
    except (TimeoutError, httpx.HTTPError, httpx.InvalidURL, ValueError, AepValidationError):
        return DocumentReadResult(descriptor, web_url, reason="unavailable_or_unsupported")
