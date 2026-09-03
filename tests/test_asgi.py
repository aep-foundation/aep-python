from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

import pytest

from agent_enrollment_protocol.adapters import (
    AEP_PRINCIPAL_SCOPE_KEY,
    AepAsgiApplication,
    AepAuthenticationMiddleware,
    AsgiApplication,
    AsgiMessage,
    AsgiScope,
    principal_from_scope,
)
from agent_enrollment_protocol.core import AEP_MEDIA_TYPE, AssertionOperation, GrantTypeConfig
from agent_enrollment_protocol.service import (
    AuthenticatedPrincipal,
    AuthenticationKind,
    CommandOptions,
    CredentialAuthenticationInput,
    GrantTypeDefinition,
    ProtectedResourceResult,
    Service,
    ServiceResult,
)

from .test_service import AGENT_DID, Authenticator, GrantHandler, _assertion, _service


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
        "headers": list(headers) if isinstance(headers, Iterable) else headers,
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

    rejected = await invoke(application, method="POST", path="/.well-known/aep")
    assert rejected.status == 405
    assert rejected.headers["allow"] == "GET"
    assert rejected.headers["content-type"] == "application/problem+json"


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
        assert media.status == 415

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
    assert large.status == 413

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
        cast(Any, [(b"name",)]),
        cast(Any, [("name", b"value")]),
    ):
        with pytest.raises(RuntimeError, match="header"):
            await invoke(application, headers=headers, path="/.well-known/aep")

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
    )
    assert response.status == 204
    assert authenticator.requests[0].url == "https://service.example/caf%C3%A9"

    with pytest.raises(RuntimeError, match="query string"):
        await invoke(
            middleware,
            path="/private",
            query_string=cast(Any, "invalid"),
        )
    with pytest.raises(RuntimeError, match='field "method"'):
        await invoke(middleware, method=None, path="/private")
