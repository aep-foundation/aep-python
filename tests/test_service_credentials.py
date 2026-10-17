from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import threading
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, cast

import pytest

from agent_enrollment_protocol.core import (
    ApiKeyGrantResponse,
    AssertionOperation,
    BasicGrantResponse,
    GrantRequest,
    GrantTypeConfig,
    OAuthBearerGrantResponse,
)
from agent_enrollment_protocol.service import (
    CredentialAuthenticationInput,
    CredentialMatch,
    GrantContext,
    MemoryEnrollmentStore,
    MemoryServiceCredentialStore,
    ProtectedResourceRequest,
    ServiceCredentialRecord,
    StoredCredentialGrantTypeOptions,
    stored_api_key_grant_type,
    stored_basic_grant_type,
    stored_oauth_bearer_grant_type,
)

from .test_service import AGENT_DID, NOW, _options, _record, _service

EXPIRES = "2026-09-02T13:00:00Z"
RESOURCE = "https://service.example/private"


async def _active_store() -> MemoryEnrollmentStore:
    store = MemoryEnrollmentStore()
    await store.save(_record())
    return store


@pytest.mark.asyncio
async def test_public_grant_configuration_cannot_mutate_private_issuance() -> None:
    store = MemoryServiceCredentialStore()
    header = ["X-Key"]

    async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        return ApiKeyGrantResponse(
            api_key="secret", credential_id="one", expires_at=EXPIRES, header=header[0]
        )

    definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(
            issue=issue,
            store=store,
            config=GrantTypeConfig.model_validate({"header_names": ["x-key"]}),
        )
    )
    service, _ = _service(grant_types=(definition,), enrollment_store=await _active_store())
    assert definition.config.model_extra is not None
    definition.config.model_extra["header_names"].append("x-other")
    header[0] = "X-Other"
    with pytest.raises(ValueError, match="not advertised"):
        await service.grant(
            b'{"grant_type":"api-key"}',
            _options(AssertionOperation.GRANT, "bad-config", key="bad-config"),
        )
    assert store._records == {}
    configs = service.inspect_document.commands.grant_types_config
    assert configs is not None
    assert configs["api-key"].to_wire()["header_names"] == ["x-key"]
    header[0] = "X-Key"
    assert (
        await service.grant(
            b'{"grant_type":"api-key"}',
            _options(AssertionOperation.GRANT, "good-config", key="good-config"),
        )
    ).status == 200


@pytest.mark.asyncio
async def test_stored_credential_expiry_uses_core_rfc3339_rules() -> None:
    store = MemoryServiceCredentialStore()

    async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        return ApiKeyGrantResponse(
            api_key="secret", credential_id="lowercase", expires_at=EXPIRES.lower(), header="X-Key"
        )

    definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(issue=issue, store=store)
    )
    service, _ = _service(
        grant_types=(definition,),
        authentication_methods=("api-key",),
        enrollment_store=await _active_store(),
    )
    result = await service.grant(
        b'{"grant_type":"api-key"}',
        _options(AssertionOperation.GRANT, "lowercase", key="lowercase"),
    )
    assert result.status == 200
    assert (
        await service.authenticate_protected_resource(
            ProtectedResourceRequest(headers={"X-Key": "secret"}, method="GET", url=RESOURCE)
        )
    ).authenticated


@pytest.mark.asyncio
async def test_memory_password_verifier_has_unique_salt_and_preserves_store_contract() -> None:
    credential = BasicGrantResponse(
        username="agent", password="password-secret", credential_id="basic-one", expires_at=EXPIRES
    )
    record = ServiceCredentialRecord(
        AGENT_DID, NOW, credential, credential.credential_id, NOW + timedelta(hours=1), "basic"
    )
    first, second = MemoryServiceCredentialStore(), MemoryServiceCredentialStore()
    await first.save_credential(record)
    await second.save_credential(record)
    stored = first._records[record.credential_id]
    other = second._records[record.credential_id]
    presented = base64.b64encode(b"agent:password-secret").decode()
    assert len(stored.salt) == 16 and stored.salt != other.salt
    assert stored.verifier != other.verifier
    assert stored.verifier != hashlib.sha256(presented.encode()).digest()
    assert hmac.compare_digest(
        stored.verifier,
        hashlib.scrypt(presented.encode(), salt=stored.salt, n=16384, r=8, p=1, dklen=32),
    )
    assert credential.password not in repr(stored)
    with pytest.raises(ValueError, match="secret has already"):
        await first.save_credential(
            replace(
                record,
                credential_id="duplicate",
                credential=credential.model_copy(update={"credential_id": "duplicate"}),
            )
        )
    for token in (
        "a",
        "/w==",
        base64.b64encode(b"wrong:password-secret").decode(),
        base64.b64encode(b"agent:wrong").decode(),
    ):
        assert (
            await first.authenticate_credential(
                "basic",
                CredentialAuthenticationInput(
                    headers={"authorization": (f"Basic {token}",)},
                    method="GET",
                    current_time=NOW,
                    url=RESOURCE,
                ),
            )
            is None
        )
    assert (
        await first.authenticate_credential(
            "basic",
            CredentialAuthenticationInput(
                headers={"aep-authorization": (f"Basic {presented}",)},
                method="GET",
                current_time=NOW,
                url=RESOURCE,
            ),
        )
        is not None
    )


@pytest.mark.asyncio
async def test_stored_credential_profiles_issue_authenticate_and_revoke() -> None:
    store = MemoryServiceCredentialStore()

    async def issue_api_key(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        assert request.requested_scopes == ("catalog:read",)
        del context
        return ApiKeyGrantResponse(
            api_key="api-secret",
            credential_id="api-1",
            expires_at=EXPIRES,
            header="X-Service-Key",
            scopes=("catalog:read",),
        )

    async def issue_basic(request: GrantRequest, context: GrantContext) -> BasicGrantResponse:
        del request, context
        return BasicGrantResponse(
            credential_id="basic-1",
            expires_at=EXPIRES,
            password="password-secret",
            username="agent",
        )

    async def issue_oauth(request: GrantRequest, context: GrantContext) -> OAuthBearerGrantResponse:
        del request, context
        return OAuthBearerGrantResponse(
            access_token="oauth-secret",
            credential_id="oauth-1",
            expires_at=EXPIRES,
            token_type="Bearer",
        )

    definitions = (
        stored_api_key_grant_type(
            StoredCredentialGrantTypeOptions(
                config=GrantTypeConfig.model_validate({"header_names": ["x-service-key"]}),
                issue=issue_api_key,
                store=store,
            )
        ),
        stored_basic_grant_type(StoredCredentialGrantTypeOptions(issue=issue_basic, store=store)),
        stored_oauth_bearer_grant_type(
            StoredCredentialGrantTypeOptions(issue=issue_oauth, store=store)
        ),
    )
    service, _ = _service(
        authentication_methods=("api-key", "basic", "oauth-bearer", "aep-jwt"),
        enrollment_store=await _active_store(),
        grant_types=definitions,
    )
    for index, (_grant_type, body) in enumerate(
        (
            ("api-key", b'{"grant_type":"api-key","requested_scopes":["catalog:read"]}'),
            ("basic", b'{"grant_type":"basic"}'),
            ("oauth-bearer", b'{"grant_type":"oauth-bearer"}'),
        )
    ):
        grant_result = await service.grant(
            body,
            _options(AssertionOperation.GRANT, f"grant-{index}", key=f"grant-{index}"),
        )
        assert grant_result.status == 200
        assert grant_result.body is not None and grant_result.body["credential_id"].endswith("-1")

    presentations = (
        ({"X-Service-Key": "api-secret"}, "api-key", "api-1"),
        (
            {"Authorization": "Basic " + base64.b64encode(b"agent:password-secret").decode()},
            "basic",
            "basic-1",
        ),
        ({"AEP-Authorization": "Bearer oauth-secret"}, "oauth-bearer", "oauth-1"),
    )
    for headers, method, credential_id in presentations:
        authentication_result = await service.authenticate_protected_resource(
            ProtectedResourceRequest(headers=headers, method="GET", url=RESOURCE)
        )
        assert authentication_result.authenticated
        assert authentication_result.principal is not None
        assert authentication_result.principal.authentication_method == method
        assert authentication_result.principal.credential_id == credential_id

    assert (
        await store.authenticate_credential(
            "oauth-bearer",
            CredentialAuthenticationInput(
                headers={"authorization": ("malformed",)},
                method="GET",
                current_time=NOW,
                url=RESOURCE,
            ),
        )
        is None
    )

    await service.revoke(
        b'{"grant_type":"api-key","credential_id":"api-1"}',
        _options(AssertionOperation.REVOKE, "revoke-api", key="revoke-api"),
    )
    revoked = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={"X-Service-Key": "api-secret"}, method="GET", url=RESOURCE
        )
    )
    assert revoked.response is not None
    assert revoked.response.problem is not None
    assert revoked.response.problem.code == "not_recognized"

    await service.revoke(
        b'{"grant_type":"basic"}',
        _options(AssertionOperation.REVOKE, "revoke-basic", key="revoke-basic"),
    )
    revoked_basic = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers=presentations[1][0], method="GET", url=RESOURCE)
    )
    assert revoked_basic.response is not None


@pytest.mark.asyncio
async def test_api_key_missing_and_invalid_presentations_have_distinct_results() -> None:
    store = MemoryServiceCredentialStore()

    async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        del request, context
        return ApiKeyGrantResponse(
            api_key="secret",
            credential_id="key-1",
            expires_at=EXPIRES,
            header="X-Key",
        )

    definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(issue=issue, store=store)
    )
    service, _ = _service(
        authentication_methods=("api-key",),
        enrollment_store=await _active_store(),
        grant_types=(definition,),
    )
    await service.grant(
        b'{"grant_type":"api-key"}',
        _options(AssertionOperation.GRANT, "grant", key="grant"),
    )
    missing = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers={}, method="GET", url=RESOURCE)
    )
    invalid = await service.authenticate_protected_resource(
        ProtectedResourceRequest(headers={"x-key": "wrong"}, method="GET", url=RESOURCE)
    )
    duplicate = await service.authenticate_protected_resource(
        ProtectedResourceRequest(
            headers={"X-Key": ("secret", "secret")}, method="GET", url=RESOURCE
        )
    )
    assert missing.response is not None and missing.response.problem is not None
    assert missing.response.problem.code == "authentication_required"
    for result in (invalid, duplicate):
        assert result.response is not None and result.response.problem is not None
        assert result.response.problem.code == "not_recognized"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("username", "password"),
    [("agent", "pa\u00dfwort"), ("\u00e9agent", "secret"), ("agent", "s\u00e9cret")],
)
async def test_issued_basic_credentials_must_survive_rfc_7617_encoding(
    username: str, password: str
) -> None:
    # BSC-RSP-003: RFC 7617 leaves the user-pass charset undefined without a charset parameter, so a
    # client encoding a non-ASCII value as ISO-8859-1 and a Service storing it as UTF-8 derive
    # different bytes from the same credential and authentication silently fails.
    async def issue(request: GrantRequest, context: GrantContext) -> BasicGrantResponse:
        del request, context
        return BasicGrantResponse(
            credential_id="basic-1",
            expires_at=EXPIRES,
            password=password,
            username=username,
        )

    definition = stored_basic_grant_type(
        StoredCredentialGrantTypeOptions(issue=issue, store=MemoryServiceCredentialStore())
    )
    with pytest.raises(ValueError, match="US-ASCII"):
        await definition.handler.grant(GrantRequest(grant_type="basic"), _grant_context("basic"))


@pytest.mark.asyncio
async def test_stored_credential_profiles_reject_invalid_issuance_and_storage() -> None:
    store = MemoryServiceCredentialStore()

    async def wrong_type(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        del request, context
        return cast(
            ApiKeyGrantResponse,
            OAuthBearerGrantResponse(
                access_token="secret",
                credential_id="wrong",
                expires_at=EXPIRES,
                token_type="Bearer",
            ),
        )

    wrong = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(issue=wrong_type, store=store)
    )
    with pytest.raises(ValueError, match="wrong built-in"):
        await wrong.handler.grant(
            GrantRequest(grant_type="api-key"),
            _grant_context("api-key"),
        )

    async def expired(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        del request, context
        return ApiKeyGrantResponse(
            api_key="secret",
            credential_id="expired",
            expires_at="2026-09-02T12:00:00Z",
            header="X-Key",
        )

    expired_definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(issue=expired, store=store)
    )
    with pytest.raises(ValueError, match="expire after"):
        await expired_definition.handler.grant(
            GrantRequest(grant_type="api-key"), _grant_context("api-key")
        )

    async def unadvertised(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        del request, context
        return ApiKeyGrantResponse(
            api_key="other",
            credential_id="other",
            expires_at=EXPIRES,
            header="X-Other",
        )

    constrained = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(
            config=GrantTypeConfig.model_validate({"header_names": ["x-key"]}),
            issue=unadvertised,
            store=store,
        )
    )
    with pytest.raises(ValueError, match="not advertised"):
        await constrained.handler.grant(
            GrantRequest(grant_type="api-key"), _grant_context("api-key")
        )

    for config, message in (
        ({"header_names": "x-key"}, "configuration is invalid"),
        ({"header_names": ["bad header"]}, "invalid HTTP field"),
        ({"header_names": ["X-Key", "x-key"]}, "duplicate field"),
    ):
        with pytest.raises(ValueError, match=message):
            stored_api_key_grant_type(
                StoredCredentialGrantTypeOptions(
                    config=GrantTypeConfig.model_validate(config),
                    issue=unadvertised,
                    store=store,
                )
            )


def _grant_context(grant_type: str) -> GrantContext:
    return GrantContext(
        agent_did=AGENT_DID,
        enrollment=_record(),
        grant_type=grant_type,
        current_time=NOW,
    )


@pytest.mark.asyncio
async def test_memory_store_rejects_reuse_and_invalid_custom_matches() -> None:
    store = MemoryServiceCredentialStore()
    credential = ApiKeyGrantResponse(
        api_key="secret", credential_id="one", expires_at=EXPIRES, header="X-Key"
    )
    record = ServiceCredentialRecord(
        agent_did=AGENT_DID,
        created_at=NOW,
        credential=credential,
        credential_id="one",
        expires_at=NOW + timedelta(hours=1),
        grant_type="api-key",
    )
    await store.save_credential(record)
    with pytest.raises(ValueError, match="identifier"):
        await store.save_credential(record)
    with pytest.raises(ValueError, match="secret"):
        await store.save_credential(
            replace(
                record,
                credential=credential.model_copy(update={"credential_id": "two"}),
                credential_id="two",
            )
        )
    for invalid, message in (
        (replace(record, agent_did=""), "invalid record"),
        (replace(record, expires_at=NOW), "invalid record"),
        (replace(record, credential_id="different"), "does not match"),
    ):
        with pytest.raises(ValueError, match=message):
            await MemoryServiceCredentialStore().save_credential(invalid)
    with pytest.raises(ValueError, match="UTC offsets"):
        replace(record, created_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="UTC offset"):
        CredentialMatch("agent", "credential", NOW.replace(tzinfo=None), "api-key")
    with pytest.raises(ValueError, match="revocation time"):
        await store.revoke_credential(AGENT_DID, "api-key", "one", NOW.replace(tzinfo=None))
    await store.revoke_credential("did:web:other.example", "api-key", "one", NOW)
    await store.revoke_credential(AGENT_DID, "basic", "one", NOW)
    await store.revoke_credential(AGENT_DID, "api-key", "missing", NOW)
    await store.revoke_grant_type("did:web:other.example", "api-key", NOW)

    class InvalidStore:
        malformed = False

        async def save_credential(self, record: ServiceCredentialRecord) -> None:
            del record

        async def authenticate_credential(
            self, grant_type: str, request: CredentialAuthenticationInput
        ) -> CredentialMatch | None:
            del request
            if self.malformed:
                return cast(CredentialMatch, object())
            return CredentialMatch("", "", NOW, grant_type)

        async def has_credential_presentation(
            self, grant_type: str, request: CredentialAuthenticationInput
        ) -> bool:
            del grant_type, request
            return True

        async def revoke_credential(
            self, agent_did: str, grant_type: str, credential_id: str, revoked_at: datetime
        ) -> None:
            del agent_did, grant_type, credential_id, revoked_at

        async def revoke_grant_type(
            self, agent_did: str, grant_type: str, revoked_at: datetime
        ) -> None:
            del agent_did, grant_type, revoked_at

    async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        del request, context
        return credential

    invalid_store = InvalidStore()
    definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(issue=issue, store=invalid_store)
    )
    assert definition.authenticator is not None
    with pytest.raises(ValueError, match="invalid match"):
        await definition.authenticator.authenticate(
            CredentialAuthenticationInput(
                headers={"x-key": ("secret",)}, method="GET", current_time=NOW, url=RESOURCE
            )
        )
    invalid_store.malformed = True
    with pytest.raises(ValueError, match="invalid match"):
        await definition.authenticator.authenticate(
            CredentialAuthenticationInput(
                headers={"x-key": ("secret",)}, method="GET", current_time=NOW, url=RESOURCE
            )
        )
    assert await definition.authenticator.has_presentation(
        CredentialAuthenticationInput(
            headers={"x-key": ("secret",)}, method="GET", current_time=NOW, url=RESOURCE
        )
    )


@pytest.mark.asyncio
async def test_stored_profile_constructor_and_presentation_boundaries() -> None:
    with pytest.raises(ValueError, match="issuer and store"):
        stored_api_key_grant_type(
            StoredCredentialGrantTypeOptions(issue=cast(Any, None), store=cast(Any, None))
        )

    async def issue(request: GrantRequest, context: GrantContext) -> ApiKeyGrantResponse:
        del request, context
        return ApiKeyGrantResponse(
            api_key="secret", credential_id="one", expires_at=EXPIRES, header="X-Key"
        )

    definition = stored_api_key_grant_type(
        StoredCredentialGrantTypeOptions(issue=issue, store=MemoryServiceCredentialStore())
    )
    with pytest.raises(ValueError, match="issuance time"):
        await definition.handler.grant(
            GrantRequest(grant_type="api-key"),
            replace(_grant_context("api-key"), current_time=NOW.replace(tzinfo=None)),
        )


@pytest.mark.asyncio
async def test_password_hashing_runs_outside_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = hashlib.scrypt
    threads: list[int] = []

    def measured(*args: Any, **kwargs: Any) -> bytes:
        threads.append(threading.get_ident())
        return original(*args, **kwargs)

    monkeypatch.setattr(hashlib, "scrypt", measured)
    credential = BasicGrantResponse(
        username="agent", password="secret", credential_id="one", expires_at=EXPIRES
    )
    record = ServiceCredentialRecord(
        AGENT_DID, NOW, credential, "one", NOW + timedelta(hours=1), "basic"
    )
    store = MemoryServiceCredentialStore()
    await store.save_credential(record)
    token = base64.b64encode(b"agent:secret").decode()
    assert (
        await store.authenticate_credential(
            "basic",
            CredentialAuthenticationInput(
                headers={"authorization": (f"Basic {token}",)},
                method="GET",
                current_time=NOW,
                url=RESOURCE,
            ),
        )
        is not None
    )
    assert len(threads) == 2 and all(identity != threading.get_ident() for identity in threads)


@pytest.mark.asyncio
async def test_concurrent_duplicate_passwords_cannot_both_be_saved() -> None:
    credential = BasicGrantResponse(
        username="agent", password="secret", credential_id="one", expires_at=EXPIRES
    )
    record = ServiceCredentialRecord(
        AGENT_DID, NOW, credential, "one", NOW + timedelta(hours=1), "basic"
    )
    store = MemoryServiceCredentialStore()
    outcomes = await asyncio.gather(
        store.save_credential(record),
        store.save_credential(
            replace(
                record,
                credential_id="two",
                credential=credential.model_copy(update={"credential_id": "two"}),
            )
        ),
        return_exceptions=True,
    )
    assert outcomes.count(None) == 1
    assert sum(isinstance(value, ValueError) for value in outcomes) == 1
    assert len(store._records) == 1


@pytest.mark.asyncio
async def test_direct_memory_store_preserves_utf8_basic_credentials() -> None:
    credential = BasicGrantResponse(
        username="\u00e9agent", password="s\u00e9cret", credential_id="utf8", expires_at=EXPIRES
    )
    record = ServiceCredentialRecord(
        AGENT_DID, NOW, credential, "utf8", NOW + timedelta(hours=1), "basic"
    )
    store = MemoryServiceCredentialStore()
    await store.save_credential(record)
    token = base64.b64encode(f"{credential.username}:{credential.password}".encode()).decode()
    assert (
        await store.authenticate_credential(
            "basic",
            CredentialAuthenticationInput(
                headers={"authorization": (f"Basic {token}",)},
                method="GET",
                current_time=NOW,
                url=RESOURCE,
            ),
        )
        is not None
    )
