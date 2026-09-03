from __future__ import annotations

from types import MappingProxyType
from typing import Any, cast
from urllib.parse import urlsplit

import pytest

from agent_enrollment_protocol.core import (
    AEP_AUTHORIZATION_HEADER,
    AepAuthorizationError,
    AgentStatus,
    AuthorizationCarrier,
    AuthorizationScheme,
    Command,
    EnrollResponse,
    HttpRequest,
    HttpResponse,
    OpenApiTrailingSlash,
    ProtectedResourceAuthorization,
    authorization_header_name,
    command_path,
    command_path_from_inspect,
    did_web_document_url,
    did_web_origin,
    is_version_compatible,
    match_openapi_path,
    media_type_essence,
    normalize_endpoint_base,
    parse_authorization,
    render_authorization,
    require_service_origin_binding,
    resolve_openapi_url,
    same_origin,
    select_did_web_public_jwk,
)
from agent_enrollment_protocol.core.inspect import _origin

from .test_core_models import inspect_document


def test_http_values_paths_and_transport_models() -> None:
    assert media_type_essence("Application/AEP+JSON; charset=utf-8") == "application/aep+json"
    assert media_type_essence('application/aep+json; profile="one;two"') == ("application/aep+json")
    for malformed in (
        "application/aep+json;",
        "application/aep+json; garbage",
        "application/aep+json; charset=",
        "application/aep+json\r\n",
    ):
        assert media_type_essence(malformed) == ""
    assert normalize_endpoint_base() == "/aep/"
    assert normalize_endpoint_base("/custom") == "/custom/"
    assert normalize_endpoint_base("/custom/") == "/custom/"
    assert command_path(Command.ENROLL, "/custom") == "/custom/enroll"
    assert command_path_from_inspect(inspect_document(), Command.STATUS) == "/custom/status"
    request = HttpRequest(method="GET", url="https://example.com", headers={"Accept": "x"})
    response = HttpResponse(status=200)
    assert request.headers["Accept"] == "x"
    assert response.headers == MappingProxyType({})
    assert response.body == b""
    source_headers = {"Accept": "one"}
    copied = HttpRequest(method="GET", url="https://example.com", headers=source_headers)
    source_headers["Accept"] = "two"
    assert copied.headers["Accept"] == "one"
    with pytest.raises(ValueError, match="origin-relative"):
        normalize_endpoint_base("https://example.com/aep")
    with pytest.raises(ValueError, match="Inspect"):
        command_path(Command.INSPECT)


@pytest.mark.parametrize(
    ("text", "scheme"),
    [
        ("AEP assertion", AuthorizationScheme.AEP),
        ("bearer token", AuthorizationScheme.BEARER),
        ("Basic value", AuthorizationScheme.BASIC),
    ],
)
def test_authorization_round_trip(text: str, scheme: AuthorizationScheme) -> None:
    parsed = parse_authorization(text)
    assert parsed.scheme is scheme
    header, value = render_authorization(parsed)
    assert header == "Authorization"
    assert value == f"{scheme.value} {parsed.credentials}"
    assert authorization_header_name(AuthorizationCarrier.DEDICATED) == AEP_AUTHORIZATION_HEADER
    assert authorization_header_name(AuthorizationCarrier.STANDARD) == "Authorization"


def test_authorization_rejects_ambiguous_or_invalid_values() -> None:
    with pytest.raises(AepAuthorizationError) as ambiguous:
        parse_authorization("AEP one, AEP two", AuthorizationCarrier.DEDICATED)
    assert ambiguous.value.code == "not_recognized"
    for value in ("", "Digest value", "AEP", "AEP  value"):
        with pytest.raises(AepAuthorizationError):
            parse_authorization(value)
    with pytest.raises(AepAuthorizationError) as empty:
        render_authorization(
            ProtectedResourceAuthorization.model_construct(
                carrier=AuthorizationCarrier.DEDICATED,
                scheme=AuthorizationScheme.AEP,
                credentials="",
            )
        )
    assert empty.value.code == "invalid_request"


def test_inspect_version_origin_and_did_web_helpers() -> None:
    assert is_version_compatible("1.7")
    assert is_version_compatible("1.0", "1.7")
    assert not is_version_compatible("2.0")
    assert not is_version_compatible("1")
    assert not is_version_compatible("1.0", "bad")
    document = inspect_document()
    require_service_origin_binding(document, "https://api.example.com/discovery/aep")
    assert did_web_origin("did:web:api.example.com:service:one") == "https://api.example.com:443"
    assert same_origin("https://EXAMPLE.com/a", "https://example.com:443/b")
    assert not same_origin("https://example.com", "https://other.example.com")
    with pytest.raises(ValueError, match="does not match"):
        require_service_origin_binding(document, "https://other.example.com/.well-known/aep")
    for did in ("did:key:one", "did:web:", "did:web:%2Fbad"):
        with pytest.raises(ValueError):
            did_web_origin(did)
    with pytest.raises(ValueError, match="HTTPS"):
        require_service_origin_binding(document, "http://api.example.com/.well-known/aep")
    loopback = inspect_document()
    loopback = loopback.model_copy(
        update={"service": loopback.service.model_copy(update={"did": "did:web:localhost%3A8080"})}
    )
    require_service_origin_binding(
        loopback,
        "http://localhost:8080/.well-known/aep",
        allow_insecure_loopback=True,
    )
    default_loopback = loopback.model_copy(
        update={"service": loopback.service.model_copy(update={"did": "did:web:localhost"})}
    )
    require_service_origin_binding(
        default_loopback,
        "http://localhost/.well-known/aep",
        allow_insecure_loopback=True,
    )
    with pytest.raises(ValueError, match="does not match"):
        require_service_origin_binding(
            loopback,
            "http://localhost:8081/.well-known/aep",
            allow_insecure_loopback=True,
        )
    with pytest.raises(ValueError, match="host"):
        _origin(urlsplit("relative"))


def test_did_web_document_and_public_key_selection() -> None:
    did = "did:web:agent.example.com:agents:123"
    key_id = f"{did}#key-1"
    assert did_web_document_url(did) == "https://agent.example.com/agents/123/did.json"
    assert did_web_document_url("did:web:localhost", allow_insecure_loopback=True) == (
        "http://localhost/.well-known/did.json"
    )
    assert (
        did_web_document_url("did:web:%5B%3A%3A1%5D", allow_insecure_loopback=True)
        == "http://[::1]/.well-known/did.json"
    )
    assert did_web_document_url("did:web:example.com") == "https://example.com/.well-known/did.json"
    document = {
        "id": did,
        "verificationMethod": [
            {"id": "other", "publicKeyJwk": {}},
            {
                "id": key_id,
                "publicKeyJwk": {"key_ops": ["verify"], "kty": "OKP", "x": "key"},
            },
        ],
    }
    key = select_did_web_public_jwk(document, did=did, key_id=key_id)
    assert key == {"key_ops": ["verify"], "kty": "OKP", "x": "key"}
    key["x"] = "changed"
    cast(list[str], key["key_ops"]).append("sign")
    methods = cast(list[dict[str, Any]], document["verificationMethod"])
    assert methods[1]["publicKeyJwk"]["x"] == "key"
    assert methods[1]["publicKeyJwk"]["key_ops"] == ["verify"]
    for invalid_did in (
        "did:key:one",
        "did:web:",
        "did:web:user@example.com",
        "did:web:example.com%3Fquery",
        "did:web:example.com%3Ainvalid",
        "did:web:example.com:%2Fadmin",
        "did:web:example.com:%2E%2E:secret",
        "did:web:example.com:",
        "did:web:examplé.com",
        "did:web:%C3%A9xample.com",
    ):
        with pytest.raises(ValueError):
            did_web_document_url(invalid_did)
    with pytest.raises(ValueError, match="issuer"):
        select_did_web_public_jwk(document, did=did, key_id="did:web:other#key")
    with pytest.raises(ValueError, match="No public JWK"):
        select_did_web_public_jwk({"id": did}, did=did, key_id=key_id)
    with pytest.raises(ValueError, match="document ID"):
        select_did_web_public_jwk(
            {**document, "id": "did:web:other.example"}, did=did, key_id=key_id
        )
    with pytest.raises(ValueError, match="No public JWK"):
        select_did_web_public_jwk(
            {
                "id": did,
                "verificationMethod": [{"id": key_id, "publicKeyMultibase": "z123"}],
            },
            did=did,
            key_id=key_id,
        )


def test_openapi_url_and_path_helpers() -> None:
    assert (
        resolve_openapi_url("https://service.example/.well-known/aep", "/openapi.json")
        == "https://service.example/openapi.json"
    )
    with pytest.raises(ValueError):
        resolve_openapi_url(
            "https://127.0.0.1/.well-known/aep",
            "http://127.0.0.1/openapi.json",
            allow_insecure_loopback=True,
        )
    assert (
        resolve_openapi_url(
            "http://127.0.0.1/.well-known/aep",
            "/openapi.json",
            allow_insecure_loopback=True,
        )
        == "http://127.0.0.1/openapi.json"
    )
    match = match_openapi_path(
        ("/items/{id}", "/items/current"),
        method="get",
        path="/items/current",
        trailing_slash=OpenApiTrailingSlash.STRICT,
    )
    assert match.method == "GET"
    assert match.template == "/items/current"
    equivalent = match_openapi_path(
        ("/items/{id}",),
        method="post",
        path="/items/one/",
        trailing_slash=OpenApiTrailingSlash.EQUIVALENT,
    )
    assert equivalent.template == "/items/{id}"
    partial = match_openapi_path(
        ("/items/{id}.json",),
        method="get",
        path="/items/one.json",
        trailing_slash=OpenApiTrailingSlash.STRICT,
    )
    assert partial.template == "/items/{id}.json"
    for inspect_url, reference in (
        ("http://service.example/.well-known/aep", "/openapi.json"),
        ("https://user@service.example/.well-known/aep", "/openapi.json"),
        ("https://service.example/.well-known/aep", "http://service.example/openapi.json"),
        ("https://service.example/.well-known/aep", "https://user@service.example/openapi.json"),
        ("https://service.example/.well-known/aep", "https://service.example/openapi.json#part"),
    ):
        with pytest.raises(ValueError):
            resolve_openapi_url(inspect_url, reference)
    with pytest.raises(ValueError, match="target"):
        match_openapi_path(
            ("/items/{id}",),
            method="",
            path="/items/one",
            trailing_slash=OpenApiTrailingSlash.STRICT,
        )
    with pytest.raises(ValueError, match="not documented"):
        match_openapi_path(
            ("/items/{id}",),
            method="GET",
            path="/other/one",
            trailing_slash=OpenApiTrailingSlash.STRICT,
        )
    with pytest.raises(ValueError, match="not documented"):
        match_openapi_path(
            ("/one",),
            method="GET",
            path="/one/two",
            trailing_slash=OpenApiTrailingSlash.STRICT,
        )
    with pytest.raises(ValueError, match="not documented"):
        match_openapi_path(
            ("/items/{id",),
            method="GET",
            path="/items/one",
            trailing_slash=OpenApiTrailingSlash.STRICT,
        )
    with pytest.raises(ValueError, match="Ambiguous"):
        match_openapi_path(
            ("/items/{id}", "/items/{name}"),
            method="GET",
            path="/items/one",
            trailing_slash=OpenApiTrailingSlash.STRICT,
        )


def test_imported_status_is_used() -> None:
    assert EnrollResponse(status=AgentStatus.ACTIVE).status is AgentStatus.ACTIVE
