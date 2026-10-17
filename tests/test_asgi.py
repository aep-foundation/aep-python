from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import count
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_enrollment_protocol.adapters import (
    AEP_PRINCIPAL_SCOPE_KEY,
    AepAsgiApplication,
    AepAuthenticationMiddleware,
    AsgiApplication,
    AsgiMessage,
    AsgiScope,
    principal_from_scope,
)
from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AssertionOperation,
    ClientAssertionClaims,
    GrantTypeConfig,
    SigningAlgorithm,
    VerifyClientAssertionOptions,
    sign_client_assertion,
    verify_client_assertion,
)
from agent_enrollment_protocol.service import (
    AssertionVerificationContext,
    AuthenticatedPrincipal,
    AuthenticationKind,
    CommandOptions,
    CredentialAuthenticationInput,
    GrantTypeDefinition,
    ProtectedResourceResult,
    Service,
    ServiceOptions,
    ServiceResult,
)

from .test_service import (
    AGENT_DID,
    NOW,
    SERVICE_DID,
    Authenticator,
    GrantHandler,
    _assertion,
    _service,
)


def signed_service(
    endpoint_base: str = "/aep/",
) -> tuple[Service, Callable[[AssertionOperation, str | None], str]]:
    key = Ed25519PrivateKey.generate()
    identifiers = count()

    class Verifier:
        async def verify(
            self, assertion: str, context: AssertionVerificationContext
        ) -> ClientAssertionClaims:
            return verify_client_assertion(
                assertion,
                key=key.public_key(),
                options=VerifyClientAssertionOptions(
                    algorithms=context.algorithms,
                    audience=context.service_did,
                    operation=context.operation,
                    resource=context.resource,
                    current_time=int(context.current_time.timestamp()),
                ),
            )

    def sign(operation: AssertionOperation, resource: str | None) -> str:
        values: dict[str, object] = {
            "aud": SERVICE_DID,
            "iss": AGENT_DID,
            "sub": AGENT_DID,
            "iat": int(NOW.timestamp()),
            "exp": int(NOW.timestamp()) + 60,
            "jti": f"assertion-{next(identifiers)}",
            "op": operation,
        }
        if resource is not None:
            values["resource"] = resource
        return sign_client_assertion(
            ClientAssertionClaims.model_validate(values), key=key, algorithm=SigningAlgorithm.EDDSA
        )

    return Service(
        ServiceOptions(
            service_did=SERVICE_DID,
            identity_methods=("did:web",),
            verifier=Verifier(),
            endpoint_base=endpoint_base,
            authentication_methods=("aep-jwt",),
            clock=lambda: NOW,
            grant_types=(
                GrantTypeDefinition(
                    "api-key",
                    GrantHandler(),
                    config=GrantTypeConfig(supports_per_credential_revoke="true"),
                ),
            ),
        )
    ), sign


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base",
    [
        "/aep/",
        "/custom/aep/",
        "/caf%C3%A9/aep/",
        "/caf%65/aep/",
        "/café/aep/",
        "/literal%252F/aep/",
        "/reserved%3F%23/aep/",
    ],
)
async def test_asgi_routes_commands_at_the_advertised_encoded_base(base: str) -> None:
    service, sign = signed_service(base)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=AepAsgiApplication(service)),
        base_url="https://service.example",
    ) as client:
        inspect = (await client.get("/.well-known/aep")).json()
        assert inspect["http"]["endpoint_base"] == base
        for operation, body in (
            (AssertionOperation.ENROLL, {"agent_did": AGENT_DID}),
            (AssertionOperation.STATUS, None),
            (AssertionOperation.GRANT, {"grant_type": "api-key"}),
            (AssertionOperation.REVOKE, {"grant_type": "api-key", "credential_id": "credential-1"}),
        ):
            response = await client.request(
                "GET" if operation is AssertionOperation.STATUS else "POST",
                base + operation.value,
                headers={
                    "Authorization": "AEP " + sign(operation, None),
                    "Idempotency-Key": "request-" + operation.value,
                    "Content-Type": AEP_MEDIA_TYPE,
                },
                content=json.dumps(body).encode() if body is not None else None,
            )
            assert response.status_code == 200, response.text
            assert response.headers["cache-control"] == "no-store"
        if base == "/literal%252F/aep/":
            wrong_path = await client.get("/literal%2F/aep/status")
            assert wrong_path.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("iterator", [False, True])
async def test_authentication_preserves_raw_headers_and_streamed_body(iterator: bool) -> None:
    service, sign = signed_service()
    enrolled = await service.enroll(
        json.dumps({"agent_did": AGENT_DID}).encode(),
        CommandOptions(
            client_assertion=sign(AssertionOperation.ENROLL, None), idempotency_key="enroll"
        ),
    )
    assert enrolled.status == 200
    resource = "https://service.example/caf%C3%A9?view=full"
    headers = [
        (b"AEP-Authorization", ("AEP " + sign(AssertionOperation.AUTHENTICATE, resource)).encode()),
        (b"Authorization", b"Payment opaque-proof"),
        (b"payment-signature", b"opaque-signature"),
        (b"content-type", b"application/json"),
        (b"x-repeat", b"first"),
        (b"X-Repeat", b"second"),
    ]
    observed: list[tuple[bytes, bytes]] = []
    bodies: list[bytes] = []

    async def downstream(scope: AsgiScope, receive: Any, send: Any) -> None:
        observed.extend(scope["headers"])
        principal = principal_from_scope(scope)
        assert principal is not None and principal.agent_did == AGENT_DID
        while True:
            message = await receive()
            bodies.append(message["body"])
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    raw_headers = iter(iter(pair) for pair in headers) if iterator else headers
    response = await invoke(
        AepAuthenticationMiddleware(downstream, service, resource_origin="https://service.example"),
        headers=raw_headers,
        method="POST",
        path="/café",
        raw_path=b"/caf%C3%A9",
        query_string=b"view=full",
        messages=[
            {"type": "http.request", "body": b'{"quantity":', "more_body": True},
            {"type": "http.request", "body": b"2}"},
        ],
    )
    assert response.status == 200
    assert observed == headers
    assert b"".join(bodies) == b'{"quantity":2}'
    assert headers[1] == (b"Authorization", b"Payment opaque-proof")


@pytest.mark.asyncio
@pytest.mark.parametrize("presentation", ["missing", "invalid", "duplicate", "wrong-resource"])
async def test_single_use_headers_do_not_bypass_authentication(presentation: str) -> None:
    service, sign = signed_service()
    await service.enroll(
        json.dumps({"agent_did": AGENT_DID}).encode(),
        CommandOptions(
            client_assertion=sign(AssertionOperation.ENROLL, None), idempotency_key="enroll"
        ),
    )
    resource = (
        "https://service.example/other"
        if presentation == "wrong-resource"
        else "https://service.example/private"
    )
    credential = ("AEP " + sign(AssertionOperation.AUTHENTICATE, resource)).encode()
    headers = [(b"aep-authorization", credential)]
    if presentation == "missing":
        headers = []
    elif presentation == "invalid":
        headers = [(b"aep-authorization", b"malformed"), (b"authorization", credential)]
    elif presentation == "duplicate":
        headers *= 2

    async def downstream(scope: AsgiScope, receive: Any, send: Any) -> None:
        raise AssertionError("An unauthenticated request reached the application")

    response = await invoke(
        AepAuthenticationMiddleware(downstream, service, resource_origin="https://service.example"),
        headers=iter(iter(pair) for pair in headers),
        path="/private",
    )
    assert response.status == 401
    expected = "authentication_required" if presentation == "missing" else "not_recognized"
    assert json.loads(response.body)["code"] == expected
    assert response.headers["cache-control"] == "no-store"


@dataclass(frozen=True)
class AsgiResponse:
    body: bytes
    headers: dict[str, str]
    status: int


async def invoke(
    application: AsgiApplication,
    *,
    body: bytes = b"",
    headers: Iterable[tuple[bytes, bytes]] | object = (),
    messages: list[AsgiMessage] | None = None,
    method: str | None = "GET",
    path: str = "/",
    query_string: bytes = b"",
    raw_path: bytes | None = None,
    scope_type: str = "http",
) -> AsgiResponse:
    pending = list(messages or [{"type": "http.request", "body": body}])
    sent: list[AsgiMessage] = []
    scope: AsgiScope = {
        "headers": headers,
        "path": path,
        "query_string": query_string,
        "type": scope_type,
    }
    if method is not None:
        scope["method"] = method
    if raw_path is not None:
        scope["raw_path"] = raw_path

    async def receive() -> AsgiMessage:
        return pending.pop(0)

    async def send(message: AsgiMessage) -> None:
        sent.append(message)

    await application(scope, receive, send)
    if not sent or sent[0].get("type") != "http.response.start":
        return AsgiResponse(body=b"", headers={}, status=0)
    start = sent[0]
    response_headers = {
        name.decode("ascii"): value.decode("latin-1") for name, value in start["headers"]
    }
    response_body = b"".join(message.get("body", b"") for message in sent[1:])
    return AsgiResponse(
        body=response_body,
        headers=response_headers,
        status=cast(int, start["status"]),
    )


def authorization(
    operation: AssertionOperation, identifier: str, **values: Any
) -> tuple[bytes, bytes]:
    return b"authorization", f"AEP {_assertion(operation, jti=identifier, **values)}".encode()


def test_asgi_application_validates_configuration() -> None:
    service, _ = _service()
    with pytest.raises(TypeError, match="requires a Service"):
        AepAsgiApplication(cast(Any, None))
    for maximum in (0, True, cast(Any, None)):
        with pytest.raises(ValueError, match="body limit"):
            AepAsgiApplication(service, maximum_request_body_bytes=maximum)
    for cache_control in (
        "",
        " \t",
        "public\rmax-age=1",
        "public\nmax-age=1",
        "public, title=☃",
        cast(Any, None),
    ):
        with pytest.raises(ValueError, match="Cache-Control"):
            AepAsgiApplication(service, inspect_cache_control=cache_control)


@pytest.mark.asyncio
async def test_asgi_application_serves_and_revalidates_inspect() -> None:
    service, _ = _service()
    application = AepAsgiApplication(service)

    response = await invoke(application, path="/.well-known/aep")
    assert response.status == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    assert response.headers["content-type"] == AEP_MEDIA_TYPE
    assert response.headers["content-length"] == str(len(response.body))
    assert response.headers["etag"].startswith('"sha256:')
    assert json.loads(response.body)["service"]["did"] == "did:web:service.example"

    revalidated = await invoke(
        application,
        path="/.well-known/aep",
        headers=[
            (b"if-none-match", b'"unrelated"'),
            (b"if-none-match", f"W/{response.headers['etag']}".encode()),
        ],
    )
    assert revalidated.status == 304
    assert revalidated.body == b""
    assert revalidated.headers["etag"] == response.headers["etag"]
    assert "content-length" not in revalidated.headers

    wildcard = await invoke(
        application,
        path="/.well-known/aep",
        headers=[(b"if-none-match", b'"other", *')],
    )
    assert wildcard.status == 304

    # RFC 9110 section 15.5.5 answers an unsupported method with 405, and section 15.5.6 requires
    # the Allow field to name the ones the resource does support.
    rejected = await invoke(application, method="POST", path="/.well-known/aep")
    assert rejected.status == 405
    assert rejected.headers["allow"] == "GET, HEAD"
    assert rejected.headers["content-type"] == "application/problem+json"
    assert json.loads(rejected.body) == {
        "code": "invalid_request",
        "status": 405,
        "title": "Method not allowed",
        "type": "urn:aep:error:invalid_request",
    }

    # RFC 9110 section 9.1 requires HEAD wherever GET is supported, and section 9.3.2 keeps its
    # header fields identical to the GET it stands in for, content aside.
    served = await invoke(application, method="GET", path="/.well-known/aep")
    head = await invoke(application, method="HEAD", path="/.well-known/aep")
    assert head.status == served.status == 200
    assert head.headers == served.headers
    assert head.headers["content-length"] == str(len(served.body))
    assert head.body == b""

    conditional_head = await invoke(
        application,
        method="HEAD",
        path="/.well-known/aep",
        headers=[(b"if-none-match", served.headers["etag"].encode())],
    )
    assert conditional_head.status == 304
    assert conditional_head.body == b""


@pytest.mark.asyncio
async def test_asgi_application_delegates_or_returns_not_found() -> None:
    service, _ = _service()
    scopes: list[AsgiScope] = []

    async def downstream(scope: AsgiScope, receive: Any, send: Any) -> None:
        del receive, send
        scopes.append(scope)

    application = AepAsgiApplication(service, downstream)
    response = await invoke(application, path="/application")
    assert response.status == 0
    assert scopes[0]["path"] == "/application"

    await invoke(application, scope_type="lifespan")
    assert scopes[1]["type"] == "lifespan"

    missing = await invoke(AepAsgiApplication(service), path="/missing")
    assert missing.status == 404

    lifespan = await invoke(
        AepAsgiApplication(service),
        messages=[
            {"type": "lifespan.startup"},
            {"type": "lifespan.shutdown"},
        ],
        scope_type="lifespan",
    )
    assert lifespan.status == 0

    with pytest.raises(RuntimeError, match="unsupported scope"):
        await invoke(AepAsgiApplication(service), scope_type="websocket")
    with pytest.raises(RuntimeError, match="invalid lifespan"):
        await invoke(
            AepAsgiApplication(service),
            messages=[{"type": "invalid"}],
            scope_type="lifespan",
        )


@pytest.mark.asyncio
async def test_asgi_application_runs_all_advertised_commands() -> None:
    handler = GrantHandler()
    service, _ = _service(
        grant_types=(
            GrantTypeDefinition(
                "api-key",
                handler,
                config=GrantTypeConfig(supports_per_credential_revoke="true"),
            ),
        )
    )
    application = AepAsgiApplication(service)
    enroll_body = b'{"agent_did":"did:web:agent.example"}'
    enrolled = await invoke(
        application,
        body=enroll_body,
        headers=[
            authorization(AssertionOperation.ENROLL, "enroll"),
            (b"content-type", b"application/aep+json; charset=utf-8"),
            (b"idempotency-key", b"enroll-key"),
        ],
        method="POST",
        path="/aep/enroll",
    )
    assert enrolled.status == 200
    assert json.loads(enrolled.body)["status"] == "active"
    assert enrolled.headers["cache-control"] == "no-store"

    status = await invoke(
        application,
        headers=[authorization(AssertionOperation.STATUS, "status")],
        path="/aep/status",
    )
    assert status.status == 200
    assert json.loads(status.body)["status"] == "active"

    granted = await invoke(
        application,
        body=b'{"grant_type":"api-key"}',
        headers=[
            authorization(AssertionOperation.GRANT, "grant"),
            (b"content-type", b"application/aep+json"),
            (b"idempotency-key", b"grant-key"),
        ],
        method="POST",
        path="/aep/grant",
    )
    assert granted.status == 200
    assert json.loads(granted.body)["credential_id"] == "credential-1"

    revoked = await invoke(
        application,
        body=b'{"grant_type":"api-key","credential_id":"credential-1"}',
        headers=[
            authorization(AssertionOperation.REVOKE, "revoke"),
            (b"content-type", b"application/aep+json"),
            (b"idempotency-key", b"revoke-key"),
        ],
        method="POST",
        path="/aep/revoke",
    )
    assert revoked.status == 200
    assert json.loads(revoked.body) == {}
    assert len(handler.revocations) == 1


@pytest.mark.asyncio
async def test_asgi_application_rejects_invalid_command_requests() -> None:
    service, _ = _service()
    application = AepAsgiApplication(service, maximum_request_body_bytes=4)

    wrong_method = await invoke(application, method="GET", path="/aep/enroll")
    assert wrong_method.status == 405
    assert wrong_method.headers["allow"] == "POST"

    # Status is safe, so it answers HEAD as well as GET and names both in Allow.
    status_head = await invoke(application, method="HEAD", path="/aep/status")
    status_get = await invoke(application, method="GET", path="/aep/status")
    assert status_head.status == status_get.status
    assert status_head.headers == status_get.headers
    assert status_head.body == b""
    status_method = await invoke(application, method="POST", path="/aep/status")
    assert status_method.status == 405
    assert status_method.headers["allow"] == "GET, HEAD"

    for headers in (
        [],
        [(b"content-type", b"application/json")],
        [(b"content-type", b"application/aep+json"), (b"content-type", b"application/aep+json")],
    ):
        media = await invoke(
            application,
            headers=headers,
            method="POST",
            path="/aep/enroll",
        )
        assert media.status == 400
        assert json.loads(media.body)["code"] == "invalid_request"

    large = await invoke(
        application,
        headers=[(b"content-type", b"application/aep+json")],
        messages=[
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"45"},
        ],
        method="POST",
        path="/aep/enroll",
    )
    # RFC 9110 section 15.5.14: a body over the configured limit is 413, which tells the caller not
    # to retry it unchanged, rather than 400 claiming the request itself was malformed.
    assert large.status == 413
    assert json.loads(large.body)["code"] == "invalid_request"
    assert json.loads(large.body)["title"] == "Content too large"

    disconnected = await invoke(
        application,
        headers=[(b"content-type", b"application/aep+json")],
        messages=[{"type": "http.disconnect"}],
        method="POST",
        path="/aep/enroll",
    )
    assert disconnected.status == 0

    no_assertion = await invoke(
        application,
        body=b"{}",
        headers=[
            (b"authorization", b"Basic credentials"),
            (b"content-type", b"application/aep+json"),
            (b"idempotency-key", b"one"),
        ],
        method="POST",
        path="/aep/enroll",
    )
    assert no_assertion.status == 401

    malformed_assertion = await invoke(
        application,
        body=b"{}",
        headers=[
            (b"authorization", b"malformed"),
            (b"content-type", b"application/aep+json"),
            (b"idempotency-key", b"one"),
        ],
        method="POST",
        path="/aep/enroll",
    )
    assert malformed_assertion.status == 401

    duplicate_assertion = await invoke(
        application,
        body=b"{}",
        headers=[
            authorization(AssertionOperation.ENROLL, "duplicate"),
            authorization(AssertionOperation.ENROLL, "duplicate"),
            (b"content-type", b"application/aep+json"),
            (b"idempotency-key", b"one"),
        ],
        method="POST",
        path="/aep/enroll",
    )
    assert duplicate_assertion.status == 401


def test_authentication_middleware_validates_configuration() -> None:
    service, _ = _service()

    async def application(scope: AsgiScope, receive: Any, send: Any) -> None:
        del scope, receive, send

    with pytest.raises(TypeError, match="ASGI application"):
        AepAuthenticationMiddleware(cast(Any, None), service, resource_origin="https://x.example")
    with pytest.raises(TypeError, match="requires a Service"):
        AepAuthenticationMiddleware(
            application, cast(Any, None), resource_origin="https://x.example"
        )
    for origin in (
        "",
        "https://user@service.example",
        "https://service.example/path",
        "https://service.example?",
        "https://service.example#",
        "https://service.example:invalid",
        "http://service.example",
    ):
        with pytest.raises(ValueError, match=r"origin|HTTPS"):
            AepAuthenticationMiddleware(application, service, resource_origin=origin)

    AepAuthenticationMiddleware(
        application,
        service,
        resource_origin="http://localhost:8000/",
        allow_insecure_loopback=True,
    )
    AepAuthenticationMiddleware(
        application,
        service,
        resource_origin="http://127.0.0.1",
        allow_insecure_loopback=True,
    )
    with pytest.raises(ValueError, match="HTTPS"):
        AepAuthenticationMiddleware(
            application,
            service,
            resource_origin="http://example.test",
            allow_insecure_loopback=True,
        )


@pytest.mark.asyncio
async def test_authentication_middleware_authenticates_and_exposes_principal() -> None:
    service, _ = _service(authentication_methods=("aep-jwt",))
    await service.enroll(
        b'{"agent_did":"did:web:agent.example"}',
        CommandOptions(
            client_assertion=_assertion(AssertionOperation.ENROLL, jti="enroll"),
            idempotency_key="enroll-key",
        ),
    )
    scopes: list[AsgiScope] = []

    async def application(scope: AsgiScope, receive: Any, send: Any) -> None:
        del receive
        scopes.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AepAuthenticationMiddleware(
        application,
        service,
        resource_origin="https://service.example",
    )
    resource = "https://service.example/private%20resource?view=full"
    accepted = await invoke(
        middleware,
        headers=[
            authorization(
                AssertionOperation.AUTHENTICATE,
                "authentication",
                resource=resource,
            )
        ],
        path="/private resource",
        raw_path=b"/private%20resource",
        query_string=b"view=full",
    )
    assert accepted.status == 204
    principal = principal_from_scope(scopes[0])
    assert principal is not None and principal.agent_did == AGENT_DID
    assert AEP_PRINCIPAL_SCOPE_KEY in scopes[0]

    rejected = await invoke(middleware, path="/private")
    assert rejected.status == 401
    assert "service_did" in rejected.headers["www-authenticate"]

    await invoke(middleware, scope_type="lifespan")
    assert scopes[-1]["type"] == "lifespan"
    assert principal_from_scope({AEP_PRINCIPAL_SCOPE_KEY: "invalid"}) is None


@pytest.mark.asyncio
async def test_authentication_middleware_handles_service_contract_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ = _service()

    async def application(scope: AsgiScope, receive: Any, send: Any) -> None:
        del scope, receive, send

    middleware = AepAuthenticationMiddleware(
        application, service, resource_origin="https://service.example"
    )

    async def missing_response(service: Service, request: Any) -> ProtectedResourceResult:
        del service, request
        return ProtectedResourceResult(authenticated=False)

    monkeypatch.setattr(Service, "authenticate_protected_resource", missing_response)
    with pytest.raises(RuntimeError, match="incomplete"):
        await invoke(middleware, path="/private")

    async def missing_principal(service: Service, request: Any) -> ProtectedResourceResult:
        del service, request
        return ProtectedResourceResult(authenticated=True)

    monkeypatch.setattr(Service, "authenticate_protected_resource", missing_principal)
    with pytest.raises(RuntimeError, match="without a principal"):
        await invoke(middleware, path="/private")


@pytest.mark.asyncio
async def test_asgi_rejects_malformed_server_messages_and_response_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ = _service()
    application = AepAsgiApplication(service)

    for headers in (
        object(),
        cast(Any, "invalid"),
        cast(Any, [1]),
        cast(Any, [(b"name",)]),
        cast(Any, [("name", b"value")]),
    ):
        with pytest.raises(RuntimeError, match="header"):
            await invoke(application, headers=headers, path="/.well-known/aep")

    iterable_headers = await invoke(
        application,
        headers=iter(((b"if-none-match", b'"unrelated"'),)),
        path="/.well-known/aep",
    )
    assert iterable_headers.status == 200

    with pytest.raises(RuntimeError, match="invalid request message"):
        await invoke(
            application,
            headers=[(b"content-type", b"application/aep+json")],
            messages=[{"type": "invalid"}],
            method="POST",
            path="/aep/enroll",
        )
    with pytest.raises(RuntimeError, match="chunks must be bytes"):
        await invoke(
            application,
            headers=[(b"content-type", b"application/aep+json")],
            messages=[{"type": "http.request", "body": "invalid"}],
            method="POST",
            path="/aep/enroll",
        )

    async def invalid_header(service: Service, options: Any) -> ServiceResult[Any]:
        del service, options
        return ServiceResult(status=200, body={}, headers={"Invalid Header": "value"})

    monkeypatch.setattr(Service, "status", invalid_header)
    with pytest.raises(ValueError, match="invalid HTTP field"):
        await invoke(
            application,
            headers=[authorization(AssertionOperation.STATUS, "status")],
            path="/aep/status",
        )

    async def invalid_value(service: Service, options: Any) -> ServiceResult[Any]:
        del service, options
        return ServiceResult(status=200, body={}, headers={"X-Value": "bad\nvalue"})

    monkeypatch.setattr(Service, "status", invalid_value)
    with pytest.raises(ValueError, match="invalid HTTP field"):
        await invoke(
            application,
            headers=[authorization(AssertionOperation.STATUS, "other")],
            path="/aep/status",
        )

    async def invalid_encoding(service: Service, options: Any) -> ServiceResult[Any]:
        del service, options
        return ServiceResult(status=200, body={}, headers={"X-Value": "☃"})

    monkeypatch.setattr(Service, "status", invalid_encoding)
    with pytest.raises(ValueError, match="invalid HTTP field"):
        await invoke(
            application,
            headers=[authorization(AssertionOperation.STATUS, "encoding")],
            path="/aep/status",
        )


@pytest.mark.asyncio
async def test_authentication_middleware_builds_encoded_resource_url() -> None:
    class RecordingAuthenticator(Authenticator):
        def __init__(self) -> None:
            super().__init__()
            self.requests: list[CredentialAuthenticationInput] = []

        async def authenticate(
            self, request: CredentialAuthenticationInput
        ) -> AuthenticatedPrincipal | None:
            self.requests.append(request)
            return await super().authenticate(request)

    authenticator = RecordingAuthenticator()
    authenticator.presented = True
    authenticator.principal = AuthenticatedPrincipal(
        agent_did=AGENT_DID,
        authentication_kind=AuthenticationKind.SESSION_CREDENTIAL,
        authentication_method="api-key",
        credential_id="credential-1",
        grant_type="api-key",
    )
    service, _ = _service(
        authentication_methods=("api-key",),
        grant_types=(GrantTypeDefinition("api-key", GrantHandler(), authenticator=authenticator),),
    )
    await service.enroll(
        b'{"agent_did":"did:web:agent.example"}',
        CommandOptions(
            client_assertion=_assertion(AssertionOperation.ENROLL, jti="enroll"),
            idempotency_key="enroll-key",
        ),
    )

    async def application(scope: AsgiScope, receive: Any, send: Any) -> None:
        del scope, receive
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AepAuthenticationMiddleware(
        application, service, resource_origin="https://service.example"
    )
    response = await invoke(
        middleware,
        headers=[(b"x-key", b"secret")],
        path="/café",
        raw_path=b"/caf\xc3\xa9",
    )
    assert response.status == 204
    assert authenticator.requests[0].url == "https://service.example/caf%C3%A9"

    encoded_percent = await invoke(
        middleware,
        headers=[(b"x-key", b"secret")],
        path="/100% ready",
    )
    assert encoded_percent.status == 204
    assert authenticator.requests[1].url == "https://service.example/100%25%20ready"

    with pytest.raises(RuntimeError, match="query string"):
        await invoke(
            middleware,
            path="/private",
            query_string=cast(Any, "invalid"),
        )
    with pytest.raises(RuntimeError, match='field "method"'):
        await invoke(middleware, method=None, path="/private")
