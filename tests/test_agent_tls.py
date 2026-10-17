from __future__ import annotations

import asyncio
import ssl
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agent_enrollment_protocol.agent import HttpxTransport
from agent_enrollment_protocol.core import HttpRequest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tls,custom_client,accepted",
    [
        (ssl.TLSVersion.TLSv1_2, False, False),
        (ssl.TLSVersion.TLSv1_3, False, True),
        (ssl.TLSVersion.TLSv1_2, True, True),
    ],
)
async def test_actual_tls_negotiation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls: ssl.TLSVersion,
    custom_client: bool,
    accepted: bool,
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "certificate.pem"
    key_path = tmp_path / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate_path))
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = tls
    server_context.maximum_version = tls
    server_context.load_cert_chain(certificate_path, key_path)
    negotiated: list[str] = []
    completed = asyncio.Event()

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            negotiated.append(writer.get_extra_info("ssl_object").version())
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            await writer.drain()
        finally:
            writer.close()
            with suppress(TimeoutError, ConnectionResetError):
                await writer.wait_closed()
            completed.set()

    server = await asyncio.start_server(
        serve, "127.0.0.1", 0, ssl=server_context, ssl_shutdown_timeout=0.1
    )
    context = ssl.create_default_context()
    context.minimum_version = tls
    context.maximum_version = tls
    client = httpx.AsyncClient(verify=context) if custom_client else None
    transport = HttpxTransport(client)
    try:
        port = server.sockets[0].getsockname()[1]
        request = HttpRequest("GET", f"https://localhost:{port}/")
        if accepted:
            assert (await transport.send(request)).status == 200
            await asyncio.wait_for(completed.wait(), timeout=3)
            assert negotiated == ["TLSv1.2" if tls == ssl.TLSVersion.TLSv1_2 else "TLSv1.3"]
        else:
            with pytest.raises(httpx.ConnectError):
                await transport.send(request)
            assert negotiated == []
    finally:
        await transport.aclose()
        server.close()
        await server.wait_closed()
