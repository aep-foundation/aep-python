from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from typing import Any

import pytest

from agent_enrollment_protocol.agent import (
    FetchProtectedResourceOptions,
    fetch_protected_resource,
)
from agent_enrollment_protocol.core import (
    AepValidationError,
    HttpRequest,
    HttpResponse,
    InspectDocument,
)

from .test_agent import QueueTransport, configured_agent, inspect_response
from .test_core_models import inspect_document

URL = "https://api.example.com/private"


def challenge(
    *,
    did: str = "did:web:api.example.com",
    inspect: str = "https://api.example.com/.well-known/aep",
) -> HttpResponse:
    return HttpResponse(
        status=401, headers={"WWW-Authenticate": f'AEP service_did="{did}", inspect="{inspect}"'}
    )


def options(
    *responses: HttpResponse, document: InspectDocument | None = None, **changes: Any
) -> FetchProtectedResourceOptions:
    if document is None:
        data = inspect_document().to_wire()
        data["http"] = {}
        document = InspectDocument.model_validate_json(json.dumps(data))
    agent, _ = configured_agent(
        QueueTransport(inspect_response(document, cache_control="max-age=600")), QueueTransport()
    )
    return FetchProtectedResourceOptions(
        agent=agent,
        request=HttpRequest(method="GET", url=URL),
        transport=QueueTransport(*responses),
        **changes,
    )


@pytest.mark.asyncio
async def test_authentication_and_same_origin_redirect_sign_each_target() -> None:
    configuration = options(
        challenge(),
        HttpResponse(status=307, headers={"Location": "/second"}),
        challenge(),
        HttpResponse(status=200, body=b"ok"),
        carrier="AEP-Authorization",
    )
    result = await fetch_protected_resource(configuration)
    assert result.body == b"ok"
    transport = configuration.transport
    assert isinstance(transport, QueueTransport)
    assert len(transport.requests) == 4
    tokens = [
        request.headers["AEP-Authorization"].split()[1] for request in transport.requests[1::2]
    ]
    from agent_enrollment_protocol.core import decode_jwt_unverified

    claims = [decode_jwt_unverified(token)[1] for token in tokens]
    assert [claim["resource"] for claim in claims] == [URL, "https://api.example.com/second"]
    assert claims[0]["jti"] != claims[1]["jti"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 401, 403, 500])
async def test_unrelated_response_does_not_authenticate(status: int) -> None:
    configuration = options(
        HttpResponse(status=status, headers={"WWW-Authenticate": "Bearer realm=other"})
    )
    assert (await fetch_protected_resource(configuration)).status == status
    transport = configuration.transport
    assert isinstance(transport, QueueTransport)
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_cross_origin_redirect_drops_all_caller_headers_and_requires_challenge() -> None:
    configuration = options(
        challenge(),
        HttpResponse(status=307, headers={"Location": "https://other.example/private"}),
        HttpResponse(status=200, body=b"anonymous"),
        carrier="AEP-Authorization",
        additional_authentication_headers={"Authorization": "Payment secret", "X-Custom": "secret"},
    )
    configuration = replace(
        configuration,
        request=HttpRequest(
            method="POST",
            url=URL,
            headers={"X-Caller": "private", "Authorization": "Bearer secret", "Cookie": "secret"},
            body=b"payload",
        ),
    )
    # The second origin has its own binding and its own Inspect response.
    inspection = configuration.agent._inspect_transport
    assert isinstance(inspection, QueueTransport)
    other = inspect_document().to_wire()
    other["service"] = {"did": "did:web:other.example"}
    other["http"] = {}
    inspection.responses.append(
        inspect_response(
            InspectDocument.model_validate_json(json.dumps(other)), cache_control="max-age=600"
        )
    )
    assert (await fetch_protected_resource(configuration)).body == b"anonymous"
    transport = configuration.transport
    assert isinstance(transport, QueueTransport)
    assert dict(transport.requests[0].headers) == {"X-Caller": "private"}
    assert transport.requests[1].headers["Authorization"] == "Payment secret"
    assert dict(transport.requests[2].headers) == {}
    assert all(request.body == b"payload" for request in transport.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "AEP",
        'AEP service_did="x", service_did="y", inspect="https://api.example.com"',
        'AEP service_did="x", inspect="https://api.example.com",',
        'AEP service_did="x" inspect="https://api.example.com"',
        'AEP reason="missing"',
    ],
)
async def test_malformed_challenge_does_not_authenticate(value: str) -> None:
    configuration = options(HttpResponse(status=401, headers={"WWW-Authenticate": value}))
    assert (await fetch_protected_resource(configuration)).status == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [challenge(did="did:web:other.example"), challenge(inspect="https://other.example/aep")],
)
async def test_challenge_binding_is_required(response: HttpResponse) -> None:
    with pytest.raises(ValueError, match=r"match|origin"):
        await fetch_protected_resource(options(response))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    [
        "http://api.example.com/private",
        "https://@api.example.com/private",
        "https://api.example.com/private#",
        "ftp://api.example.com/private",
    ],
)
async def test_invalid_redirects_are_never_followed(location: str) -> None:
    with pytest.raises(ValueError):
        await fetch_protected_resource(
            options(HttpResponse(status=307, headers={"Location": location}))
        )


@pytest.mark.asyncio
async def test_missing_location_and_redirect_limit() -> None:
    with pytest.raises(ValueError, match="Location"):
        await fetch_protected_resource(options(HttpResponse(status=302)))
    with pytest.raises(ValueError, match="redirects"):
        await fetch_protected_resource(
            options(HttpResponse(status=308, headers={"Location": "/again"}), max_redirects=0)
        )


@pytest.mark.asyncio
async def test_explicit_missing_credential_does_not_grant() -> None:
    with pytest.raises(ValueError, match="not found"):
        await fetch_protected_resource(options(challenge(), credential_id="missing"))


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [{"Authorization": "secret"}, {"aEp-AuThOrIzAtIoN": "secret"}])
async def test_additional_headers_cannot_replace_selected_aep(headers: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="conflicts"):
        await fetch_protected_resource(
            options(challenge(), additional_authentication_headers=headers)
        )


def openapi_configuration(
    document: object, *, content_type: str = "application/json"
) -> FetchProtectedResourceOptions:
    inspection = inspect_document().to_wire()
    inspection["http"] = {
        "openapi": {"url": "/openapi.json", "path_matching": {"trailing_slash": "strict"}}
    }
    configuration = options(
        HttpResponse(status=200),
        document=InspectDocument.model_validate_json(json.dumps(inspection)),
    )
    transport = configuration.agent._inspect_transport
    assert isinstance(transport, QueueTransport)
    transport.responses.append(
        HttpResponse(
            status=200, headers={"Content-Type": content_type}, body=json.dumps(document).encode()
        )
    )
    return configuration


def api_document(**changes: object) -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "paths": {"/private": {"get": {}}},
        "components": {
            "securitySchemes": {
                "agent": {"type": "http", "scheme": "AEP", "x-aep-authentication-method": "aep-jwt"}
            }
        },
        "security": [{"agent": []}],
        **changes,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome", ["updated", "unchanged", "failed", "cancelled", "wrong-did", "unrelated", "denied"]
)
async def test_public_openapi_contradiction_revalidates_once(outcome: str) -> None:
    configuration = openapi_configuration(api_document(security=[]))
    initial = configuration.agent._inspect_transport
    assert isinstance(initial, QueueTransport)

    class RefreshTransport(QueueTransport):
        async def send(self, request: HttpRequest) -> HttpResponse:
            if request.url.endswith("/openapi.json") and not self.responses:
                self.requests.append(request)
                if outcome == "cancelled":
                    raise asyncio.CancelledError
                if outcome == "failed":
                    raise OSError("offline")
                return HttpResponse(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps(
                        api_document() if outcome == "updated" else api_document(security=[])
                    ).encode(),
                )
            return await super().send(request)

    metadata = RefreshTransport(*initial.responses)
    configuration.agent._inspect_transport = metadata
    transport = QueueTransport(
        challenge(did="did:web:wrong.example")
        if outcome == "wrong-did"
        else HttpResponse(status=401)
        if outcome == "unrelated"
        else challenge(),
        challenge() if outcome == "denied" else HttpResponse(status=200),
    )
    configuration = replace(
        configuration,
        transport=transport,
        request=HttpRequest(
            method="GET",
            url=URL,
            headers={"Authorization": "Bearer secret", "Cookie": "secret", "X-Caller": "private"},
        ),
    )
    if outcome == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await fetch_protected_resource(configuration)
    elif outcome == "wrong-did":
        with pytest.raises(ValueError, match="did not match"):
            await fetch_protected_resource(configuration)
    else:
        assert (await fetch_protected_resource(configuration)).status == (
            401 if outcome in {"unrelated", "denied"} else 200
        )
    documents = [request for request in metadata.requests if request.url.endswith("/openapi.json")]
    assert len(documents) == (1 if outcome in {"wrong-did", "unrelated"} else 2)
    assert all(
        dict(request.headers)
        == {"Accept": "application/vnd.oai.openapi+json;version=3.1, application/json"}
        for request in documents
    )
    assert len(transport.requests) == (
        1 if outcome in {"cancelled", "wrong-did", "unrelated"} else 2
    )
    assert "Authorization" not in transport.requests[0].headers
    assert "Cookie" not in transport.requests[0].headers
    if len(transport.requests) == 2:
        assert transport.requests[1].headers["Authorization"].startswith("AEP ")


@pytest.mark.asyncio
async def test_definitive_openapi_security_can_authenticate_without_probe() -> None:
    configuration = openapi_configuration(api_document())
    assert (await fetch_protected_resource(configuration)).status == 200
    transport = configuration.transport
    assert isinstance(transport, QueueTransport)
    assert len(transport.requests) == 1
    assert transport.requests[0].headers["Authorization"].startswith("AEP ")
    inspection = configuration.agent._inspect_transport
    assert isinstance(inspection, QueueTransport)
    assert dict(inspection.requests[-1].headers) == {
        "Accept": "application/vnd.oai.openapi+json;version=3.1, application/json"
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"openapi": "3.0.0"},
        {"paths": None},
        {"paths": {"/private": {"get": None}}},
        {"paths": {"/private": {"$ref": "elsewhere"}}},
        {"components": {"securitySchemes": None}},
        {"security": None},
        {"security": "invalid"},
        {"security": [{"agent": [], "unknown": []}]},
        {"security": [{}]},
        {"security": []},
        {"components": None},
    ],
)
async def test_inconclusive_openapi_falls_back_to_live_response(changes: dict[str, object]) -> None:
    configuration = openapi_configuration(api_document(**changes))
    assert (await fetch_protected_resource(configuration)).status == 200
    transport = configuration.transport
    assert isinstance(transport, QueueTransport)
    assert dict(transport.requests[0].headers) == {}


@pytest.mark.parametrize(
    "changes",
    [
        {"timeout": 0},
        {"timeout": float("inf")},
        {"max_redirects": -1},
        {"max_redirects": True},
        {"carrier": "Other"},
    ],
)
def test_options_reject_invalid_limits_and_carrier(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        options(**changes)


@pytest.mark.asyncio
async def test_overall_timeout_and_task_cancellation() -> None:
    class WaitingTransport(QueueTransport):
        async def send(self, request: HttpRequest) -> HttpResponse:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    configuration = replace(options(), transport=WaitingTransport(), timeout=0.01)
    with pytest.raises(TimeoutError):
        await fetch_protected_resource(configuration)
    task = asyncio.create_task(fetch_protected_resource(replace(configuration, timeout=30)))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_default_transport_is_closed_and_custom_transport_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    class Transport(QueueTransport):
        async def aclose(self) -> None:
            closed.append(True)

    transport = Transport(HttpResponse(status=200), HttpResponse(status=200))
    monkeypatch.setattr(
        "agent_enrollment_protocol.agent.protected_resource.HttpxTransport",
        lambda **kwargs: transport,
    )
    await fetch_protected_resource(replace(options(), transport=None))
    assert closed == [True]
    await fetch_protected_resource(replace(options(), transport=transport))
    assert closed == [True]


@pytest.mark.asyncio
async def test_bad_inspect_and_no_advertised_authentication_fall_back_anonymously() -> None:
    configuration = options(HttpResponse(status=200))
    configuration.agent._inspect_transport = QueueTransport(HttpResponse(status=500))
    assert (await fetch_protected_resource(configuration)).status == 200
    document = inspect_document().to_wire()
    document.pop("authentication")
    document["http"] = {}
    configuration = options(
        challenge(), document=InspectDocument.model_validate_json(json.dumps(document))
    )
    assert (await fetch_protected_resource(configuration)).status == 401


@pytest.mark.asyncio
async def test_requested_grant_must_be_permitted() -> None:
    with pytest.raises(ValueError, match="not permitted"):
        await fetch_protected_resource(options(challenge(), grant_type="basic"))


@pytest.mark.asyncio
async def test_custom_session_without_usable_method_does_not_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_enrollment_protocol.agent import CredentialUnavailableError, ServiceSession

    document = inspect_document().to_wire()
    document["authentication"] = {"methods": ["aep-jwt"]}
    document["http"] = {}
    configuration = options(
        challenge(), document=InspectDocument.model_validate_json(json.dumps(document))
    )

    async def unavailable(*args: object) -> dict[str, str]:
        raise CredentialUnavailableError("no signing method")

    monkeypatch.setattr(ServiceSession, "authentication_headers", unavailable)
    with pytest.raises(CredentialUnavailableError, match="no signing method"):
        await fetch_protected_resource(configuration)


@pytest.mark.asyncio
async def test_signer_failure_is_not_converted_into_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    configuration = options(challenge())

    async def failed(*args: object) -> None:
        raise RuntimeError("signer unavailable")

    monkeypatch.setattr(configuration.agent._identity_provider, "signer_for", failed)
    with pytest.raises(RuntimeError, match="signer unavailable"):
        await fetch_protected_resource(configuration)
    commands = configuration.agent._command_transport
    assert isinstance(commands, QueueTransport)
    assert commands.requests == []


@pytest.mark.asyncio
async def test_corrupt_credential_is_not_replaced_with_a_grant() -> None:
    from datetime import UTC, datetime

    from agent_enrollment_protocol.agent import CredentialRecord

    configuration = options(challenge(), grant_type="api-key")
    await configuration.agent._credential_store.save_credential(
        CredentialRecord(
            credential_id="one",
            expires_at=datetime(2027, 1, 1, tzinfo=UTC),
            issued_at=datetime(2026, 1, 1, tzinfo=UTC),
            grant_type="api-key",
            payload=b'{"bad":true}',
            service_did="did:web:api.example.com",
            service_url="https://api.example.com",
        )
    )
    with pytest.raises(AepValidationError):
        await fetch_protected_resource(configuration)
    commands = configuration.agent._command_transport
    assert isinstance(commands, QueueTransport)
    assert commands.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type",
    [
        "text/html",
        "application/vnd.oai.openapi+json",
        "application/vnd.oai.openapi+json;version=3.0",
    ],
)
async def test_openapi_requires_a_supported_complete_json_media_type(content_type: str) -> None:
    configuration = openapi_configuration(api_document(), content_type=content_type)
    assert (await fetch_protected_resource(configuration)).status == 200
    transport = configuration.transport
    assert isinstance(transport, QueueTransport)
    assert not transport.requests[0].headers


@pytest.mark.asyncio
async def test_openapi_follows_only_safe_anonymous_redirects_and_has_a_bound() -> None:
    configuration = openapi_configuration(api_document())
    transport = configuration.agent._inspect_transport
    assert isinstance(transport, QueueTransport)
    document = transport.responses[-1]
    transport.responses[1:] = [
        HttpResponse(status=307, headers={"Location": "https://metadata.example/openapi.json"}),
        document,
    ]
    assert (await fetch_protected_resource(configuration)).status == 200
    assert transport.requests[-1].url == "https://metadata.example/openapi.json"
    configuration = openapi_configuration(api_document())
    transport = configuration.agent._inspect_transport
    assert isinstance(transport, QueueTransport)
    transport.responses[1:] = [HttpResponse(status=307, headers={"Location": "/again"})] * 6
    assert (await fetch_protected_resource(configuration)).status == 200


@pytest.mark.asyncio
async def test_duplicate_challenge_header_is_ambiguous() -> None:
    with pytest.raises(ValueError, match="Ambiguous"):
        await fetch_protected_resource(
            options(
                HttpResponse(
                    status=401, headers={"WWW-Authenticate": "AEP", "www-authenticate": "AEP"}
                )
            )
        )


@pytest.mark.asyncio
async def test_resource_response_limit_also_applies_to_custom_transport() -> None:
    configuration = options(HttpResponse(status=200, body=b"ab"))
    configuration.agent._maximum_response_bytes = 1
    with pytest.raises(ValueError, match="byte limit"):
        await fetch_protected_resource(configuration)


def test_request_body_must_be_bytes_before_discovery() -> None:
    from typing import cast

    with pytest.raises(ValueError, match="replayable"):
        replace(
            options(),
            request=HttpRequest(method="POST", url=URL, body=cast(bytes, iter([b"data"]))),
        )


@pytest.mark.asyncio
async def test_cross_origin_requires_challenge_even_with_definitive_openapi() -> None:
    configuration = options(
        HttpResponse(status=307, headers={"Location": "https://other.example/private"}),
        challenge(did="did:web:other.example", inspect="https://other.example/.well-known/aep"),
        HttpResponse(status=200),
    )
    other = inspect_document().to_wire()
    other["service"] = {"did": "did:web:other.example"}
    transport = configuration.agent._inspect_transport
    assert isinstance(transport, QueueTransport)
    transport.responses += [
        inspect_response(
            InspectDocument.model_validate_json(json.dumps(other)), cache_control="max-age=600"
        ),
        HttpResponse(
            status=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(api_document()).encode(),
        ),
    ]
    assert (await fetch_protected_resource(configuration)).status == 200
    resource = configuration.transport
    assert isinstance(resource, QueueTransport)
    assert not resource.requests[1].headers
    assert resource.requests[2].headers["Authorization"].startswith("AEP ")


@pytest.mark.asyncio
async def test_https_to_loopback_http_downgrade_is_rejected_with_development_enabled() -> None:
    configuration = options(
        HttpResponse(status=307, headers={"Location": "http://localhost/private"})
    )
    configuration.agent._allow_insecure_loopback = True
    with pytest.raises(ValueError, match="weakens HTTPS"):
        await fetch_protected_resource(configuration)


@pytest.mark.asyncio
async def test_live_challenge_overrides_openapi_without_infinite_retries() -> None:
    configuration = replace(
        openapi_configuration(api_document()),
        max_redirects=0,
        transport=QueueTransport(challenge(), challenge(), challenge()),
    )
    assert (await fetch_protected_resource(configuration)).status == 401
    transport = configuration.transport
    assert isinstance(transport, QueueTransport)
    assert len(transport.requests) == 3
    assert transport.requests[0].headers and not transport.requests[1].headers
    assert transport.requests[2].headers != transport.requests[0].headers
