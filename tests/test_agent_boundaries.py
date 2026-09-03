from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import cast

import httpx
import pytest

from agent_enrollment_protocol.agent import (
    Agent,
    AgentCommandError,
    AgentOptions,
    AssertionSigner,
    AuthenticationOptions,
    CredentialRecord,
    EnrollOptions,
    GrantOptions,
    HttpxTransport,
    InspectCacheEntry,
    MemoryCredentialStore,
    MemoryInspectCache,
    RevokeOptions,
    ServiceIdentity,
    WaitOptions,
)
from agent_enrollment_protocol.agent.client import (
    _cache_directive,
    _cache_fresh,
    _credential_headers,
    _parse_credential,
    _select_grant_type,
    _validate_credential_record,
)
from agent_enrollment_protocol.agent.types import IdentityRequest
from agent_enrollment_protocol.core import (
    AuthorizationCarrier,
    ClaimValues,
    ClientAssertionClaims,
    HttpRequest,
    HttpResponse,
    InspectDocument,
    SigningAlgorithm,
)

from .test_agent import FakeIdentityProvider, FixedKeys, QueueTransport, configured_agent, response
from .test_core_models import inspect_document


def document_with(**changes: object) -> InspectDocument:
    data = inspect_document().to_wire()
    for name, value in changes.items():
        if value is None:
            data.pop(name, None)
        else:
            data[name] = value
    return InspectDocument.model_validate_json(json.dumps(data))


@pytest.mark.asyncio
async def test_inspect_cache_boundaries() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    cache = MemoryInspectCache()
    key = "https://api.example.com/.well-known/aep"
    malicious = InspectCacheEntry(
        cached_at=now,
        document=inspect_document(),
        final_url="https://other.example/.well-known/aep",
    )
    await cache.save_inspect(key, malicious)
    transport = QueueTransport(
        response(inspect_document().to_wire(), headers={"Cache-Control": "no-store"})
    )
    agent = Agent(
        AgentOptions(
            identity_provider=FakeIdentityProvider(),
            clock=lambda: now,
            inspect_cache=cache,
            inspect_transport=transport,
        )
    )
    await agent.service("api.example.com").inspect()
    assert await cache.find_inspect(key) is None
    await cache.save_inspect(
        key,
        InspectCacheEntry(
            cached_at=datetime(2026, 1, 1),
            document=inspect_document(),
            final_url=key,
        ),
    )
    naive_transport = QueueTransport(response(inspect_document().to_wire()))
    uncached = Agent(
        AgentOptions(
            identity_provider=FakeIdentityProvider(),
            clock=lambda: now,
            inspect_cache=cache,
            inspect_transport=naive_transport,
        )
    )
    await uncached.service("api.example.com").inspect()
    assert len(naive_transport.requests) == 1
    redirects = QueueTransport(
        *(
            HttpResponse(status=307, headers={"Location": f"/redirect/{index}"})
            for index in range(6)
        )
    )
    looping = Agent(
        AgentOptions(identity_provider=FakeIdentityProvider(), inspect_transport=redirects)
    )
    with pytest.raises(ValueError, match="five redirects"):
        await looping.service("api.example.com").inspect()

    conditional_cache = MemoryInspectCache()
    await conditional_cache.save_inspect(
        key,
        InspectCacheEntry(
            cached_at=now,
            document=inspect_document(),
            final_url=key,
            cache_control="max-age=0",
            last_modified="Thu, 01 Jan 2026 00:00:00 GMT",
        ),
    )
    conditional_transport = QueueTransport(HttpResponse(status=304, headers={"ETag": "new"}))
    conditional = Agent(
        AgentOptions(
            identity_provider=FakeIdentityProvider(),
            clock=lambda: now,
            inspect_cache=conditional_cache,
            inspect_transport=conditional_transport,
        )
    )
    await conditional.service("api.example.com").inspect()
    assert conditional_transport.requests[0].headers["If-Modified-Since"].startswith("Thu")

    wrong_document = document_with(service={"did": "did:web:other.example"})
    await conditional_cache.save_inspect(
        key,
        InspectCacheEntry(
            cached_at=now,
            document=wrong_document,
            final_url=key,
            cache_control="max-age=60",
        ),
    )
    replacement_transport = QueueTransport(response(inspect_document().to_wire()))
    replacement = Agent(
        AgentOptions(
            identity_provider=FakeIdentityProvider(),
            clock=lambda: now,
            inspect_cache=conditional_cache,
            inspect_transport=replacement_transport,
        )
    )
    assert (
        await replacement.service("api.example.com").inspect()
    ).document.service.did == "did:web:api.example.com"

    await conditional_cache.save_inspect(
        key,
        InspectCacheEntry(
            cached_at=now,
            document=inspect_document(),
            final_url=key,
            cache_control="max-age=0",
            etag="old",
        ),
    )
    no_store = Agent(
        AgentOptions(
            identity_provider=FakeIdentityProvider(),
            clock=lambda: now,
            inspect_cache=conditional_cache,
            inspect_transport=QueueTransport(
                HttpResponse(status=304, headers={"Cache-Control": "no-store"})
            ),
        )
    )
    await no_store.service("api.example.com").inspect()
    assert await conditional_cache.find_inspect(key) is None


def test_cache_directive_and_freshness_boundaries() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    entry = InspectCacheEntry(now, inspect_document(), "https://api.example.com/a")
    assert _cache_fresh(entry, now)
    assert not _cache_fresh(
        InspectCacheEntry(now, inspect_document(), entry.final_url, cache_control="no-cache"), now
    )
    for value in ("max-age=bad", "max-age=-1"):
        assert not _cache_fresh(
            InspectCacheEntry(now, inspect_document(), entry.final_url, cache_control=value), now
        )
    assert _cache_directive('public, max-age="60"', "max-age") == "60"
    assert _cache_directive("public", "missing") is None


@pytest.mark.asyncio
async def test_command_failure_media_and_problem_boundaries() -> None:
    problem = {
        "code": "requirements_unmet",
        "status": 422,
        "title": "Requirements unmet",
        "type": "urn:aep:error:requirements_unmet",
    }
    agent, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())),
        QueueTransport(
            response(problem, status=422, headers={"Content-Type": "application/problem+json"})
        ),
    )
    with pytest.raises(AgentCommandError) as error:
        await agent.service("api.example.com").status()
    assert error.value.problem is not None
    invalid_problem, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())),
        QueueTransport(
            HttpResponse(
                status=401,
                headers={"Content-Type": "application/problem+json"},
                body=b"{}",
            )
        ),
    )
    with pytest.raises(AgentCommandError) as generic:
        await invalid_problem.service("api.example.com").status()
    assert generic.value.problem is None
    plain_error, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())),
        QueueTransport(HttpResponse(status=500, headers={"Content-Type": "application/json"})),
    )
    with pytest.raises(AgentCommandError) as plain:
        await plain_error.service("api.example.com").status()
    assert plain.value.problem is None
    bad_media, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())),
        QueueTransport(HttpResponse(status=200, headers={"Content-Type": "application/json"})),
    )
    with pytest.raises(ValueError, match="media type"):
        await bad_media.service("api.example.com").status()


@pytest.mark.asyncio
async def test_command_and_identity_fail_closed_boundaries() -> None:
    unsupported = document_with(commands={"supported": ["inspect"], "grant_types": ["api-key"]})
    agent, _ = configured_agent(QueueTransport(response(unsupported.to_wire())), QueueTransport())
    with pytest.raises(ValueError, match="does not advertise status"):
        await agent.service("api.example.com").status()
    no_identity, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())), QueueTransport(response({}))
    )
    with pytest.raises(AgentCommandError, match="existing enrolled identity"):
        await no_identity.service("api.example.com").grant()

    class InvalidProvider(FakeIdentityProvider):
        async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
            return ServiceIdentity("did:key:one", "did:web", request.service_did, ())

    invalid = Agent(
        AgentOptions(
            identity_provider=InvalidProvider(),
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
        )
    )
    with pytest.raises(ValueError, match="invalid Service-scoped"):
        await invalid.service("api.example.com").identity()

    class WrongDidProvider(FakeIdentityProvider):
        async def get_or_create_identity(self, request: IdentityRequest) -> ServiceIdentity:
            return ServiceIdentity(
                "did:key:one",
                "did:web",
                request.service_did,
                (SigningAlgorithm.EDDSA,),
            )

    wrong_did = Agent(
        AgentOptions(
            identity_provider=WrongDidProvider(),
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
        )
    )
    with pytest.raises(ValueError, match="does not match"):
        await wrong_did.service("api.example.com").identity()


@pytest.mark.asyncio
async def test_idempotency_poll_and_grant_failures() -> None:
    empty_keys = FixedKeys("")
    agent, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())), QueueTransport(), keys=empty_keys
    )
    with pytest.raises(ValueError, match="empty key"):
        await agent.service("api.example.com").enroll(
            EnrollOptions(claims=ClaimValues.model_validate({"contact.email": "x@example.com"}))
        )
    with pytest.raises(ValueError, match="must not be empty"):
        await agent.service("api.example.com").enroll(
            EnrollOptions(
                claims=ClaimValues.model_validate({"contact.email": "x@example.com"}),
                idempotency_key="",
            )
        )
    for options in (WaitOptions(0, 1), WaitOptions(float("nan"), 1)):
        with pytest.raises(ValueError, match="interval"):
            await agent.service("api.example.com").wait_for_active(options)

    no_claims = document_with(claims=None)
    without_claims, _ = configured_agent(
        QueueTransport(response(no_claims.to_wire())),
        QueueTransport(response({"status": "active"})),
    )
    assert (await without_claims.service("api.example.com").enroll()).status == 200


@pytest.mark.asyncio
async def test_grant_selection_custom_and_inactive_boundaries() -> None:
    document = inspect_document()
    assert _select_grant_type(document, None, ("future", "api-key")) == "api-key"
    for selected in ("missing", None):
        with pytest.raises(ValueError, match="grant type"):
            _select_grant_type(document, selected, ("missing",))
    inactive, _ = configured_agent(
        QueueTransport(response(document.to_wire())),
        QueueTransport(response({"status": "pending"})),
    )
    await inactive.service("api.example.com").identity()
    with pytest.raises(AgentCommandError, match="active enrollment"):
        await inactive.service("api.example.com").grant()
    custom_document = document_with(
        authentication={"methods": ["future"]},
        commands={
            "supported": ["inspect", "grant", "status"],
            "grant_types": ["future"],
        },
    )
    custom, _ = configured_agent(
        QueueTransport(response(custom_document.to_wire())),
        QueueTransport(response({"status": "active"}), response({"custom": "value"})),
    )
    await custom.service("api.example.com").identity()
    result = await custom.service("api.example.com").grant()
    assert result.body.credential is None
    with pytest.raises(ValueError, match="JSON object"):
        _parse_credential("future", b"[]")

    no_status = document_with(
        authentication={"methods": ["future"]},
        commands={"supported": ["grant", "inspect"], "grant_types": ["future"]},
    )
    missing_status, _ = configured_agent(
        QueueTransport(response(no_status.to_wire())), QueueTransport(response({"custom": True}))
    )
    await missing_status.service("api.example.com").identity()
    assert (await missing_status.service("api.example.com").grant()).status == 200

    scoped, _ = configured_agent(
        QueueTransport(response(document.to_wire())),
        QueueTransport(
            response({"status": "active"}),
            response(
                {
                    "api_key": "key",
                    "credential_id": "scoped",
                    "expires_at": "2026-01-01T01:00:00Z",
                    "header": "X-Key",
                }
            ),
        ),
    )
    await scoped.service("api.example.com").identity()
    result = await scoped.service("api.example.com").grant(GrantOptions(requested_scopes=("read",)))
    assert result.body.grant_type == "api-key"


@pytest.mark.asyncio
async def test_revoke_and_forget_boundaries() -> None:
    agent, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())), QueueTransport(response({}))
    )
    service = agent.service("api.example.com")
    with pytest.raises(ValueError, match="credential ID"):
        await service.forget_credential("")
    with pytest.raises(ValueError, match="expected grant_type"):
        await service.revoke(RevokeOptions())
    unsupported = document_with(
        commands={
            "supported": ["inspect", "revoke"],
            "grant_types": ["api-key"],
            "grant_types_config": {"api-key": {"supports_per_credential_revoke": "false"}},
        }
    )
    unsupported_agent, _ = configured_agent(
        QueueTransport(response(unsupported.to_wire())), QueueTransport()
    )
    with pytest.raises(ValueError, match="per-credential"):
        await unsupported_agent.service("api.example.com").revoke(
            RevokeOptions(grant_type="api-key", credential_id="one")
        )
    all_agent, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())), QueueTransport(response({}))
    )
    assert (
        await all_agent.service("api.example.com").revoke(
            RevokeOptions(all_grant_types=True, idempotency_key="key")
        )
    ).status == 200
    invalid_grant, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())), QueueTransport()
    )
    with pytest.raises(ValueError, match="selected grant type"):
        await invalid_grant.service("api.example.com").revoke(RevokeOptions(grant_type="future"))

    forgotten, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())), QueueTransport()
    )
    await forgotten.service("api.example.com").forget_credential("missing")

    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryCredentialStore(lambda: now)
    await store.save_credential(
        CredentialRecord(
            "other",
            now + timedelta(hours=1),
            "future",
            now,
            b"{}",
            "did:web:api.example.com",
            "url",
        )
    )
    unmatched, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())),
        QueueTransport(response({})),
        credential_store=store,
    )
    await unmatched.service("api.example.com").revoke(RevokeOptions(grant_type="api-key"))
    assert await store.find_credential("did:web:api.example.com", "other") is not None


@pytest.mark.asyncio
async def test_credential_presentations_and_metadata_validation() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    expires = "2026-01-01T01:00:00Z"
    payloads = {
        "oauth-bearer": {
            "access_token": "token",
            "credential_id": "bearer",
            "expires_at": expires,
            "token_type": "Bearer",
        },
        "basic": {
            "credential_id": "basic",
            "expires_at": expires,
            "password": "pass",
            "username": "user",
        },
    }
    for grant_type, payload in payloads.items():
        raw = json.dumps(payload).encode()
        record = CredentialRecord(
            payload["credential_id"],
            now + timedelta(hours=1),
            grant_type,
            now,
            raw,
            "did:web:api.example.com",
            "https://api.example.com/",
        )
        _validate_credential_record(record, record.service_did, now)
        headers = _credential_headers(record, AuthorizationCarrier.DEDICATED)
        assert "AEP-Authorization" in headers
    invalid = CredentialRecord(
        "wrong",
        now + timedelta(hours=1),
        "basic",
        now,
        json.dumps(payloads["basic"]).encode(),
        "did:web:api.example.com",
        "https://api.example.com/",
    )
    with pytest.raises(ValueError, match="does not match"):
        _validate_credential_record(invalid, invalid.service_did, now)
    with pytest.raises(ValueError, match="metadata is invalid"):
        _validate_credential_record(invalid, "did:web:other", now)
    with pytest.raises(ValueError, match="does not match"):
        _credential_headers(invalid, AuthorizationCarrier.STANDARD)


@pytest.mark.asyncio
async def test_authentication_selection_boundaries() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    expires = now + timedelta(hours=1)
    payload = json.dumps(
        {
            "api_key": "secret",
            "credential_id": "one",
            "expires_at": "2026-01-01T01:00:00Z",
            "header": "X-Key",
        }
    ).encode()
    store = MemoryCredentialStore(lambda: now)
    await store.save_credential(
        CredentialRecord("one", expires, "api-key", now, payload, "did:web:api.example.com", "url")
    )
    agent, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())),
        QueueTransport(),
        credential_store=store,
    )
    service = agent.service("api.example.com")
    assert await service.authentication_headers(
        AuthenticationOptions(
            "https://api.example.com/resource", credential_id="one", grant_type="api-key"
        )
    ) == {"X-Key": "secret"}
    for options, message in (
        (
            AuthenticationOptions("https://api.example.com/resource", credential_id="missing"),
            "not found",
        ),
        (
            AuthenticationOptions("https://api.example.com/resource", grant_type="future"),
            "compatible",
        ),
    ):
        with pytest.raises(ValueError, match=message):
            await service.authentication_headers(options)
    with pytest.raises(ValueError, match="invalid"):
        await service.authentication_headers(
            AuthenticationOptions("https://api.example.com/resource#fragment")
        )
    fallback, provider = configured_agent(
        QueueTransport(response(inspect_document().to_wire())), QueueTransport()
    )
    fallback_headers = await fallback.service("api.example.com").authentication_headers(
        AuthenticationOptions("https://api.example.com/resource")
    )
    assert fallback_headers["Authorization"].startswith("AEP ")
    assert provider.claims[-1].op.value == "authenticate"

    jwt_only = document_with(authentication={"methods": ["api-key"]})
    without_jwt, _ = configured_agent(
        QueueTransport(response(jwt_only.to_wire())), QueueTransport()
    )
    with pytest.raises(ValueError, match="compatible"):
        await without_jwt.service("api.example.com").authentication_headers(
            AuthenticationOptions("https://api.example.com/resource", client_assertion_only=True)
        )

    class MixedStore:
        async def delete_credential(self, service_did: str, credential_id: str) -> None:
            pass

        async def find_credential(
            self, service_did: str, credential_id: str
        ) -> CredentialRecord | None:
            return None

        async def list_credentials(self, service_did: str) -> tuple[CredentialRecord, ...]:
            invalid = CredentialRecord(
                "unrelated",
                expires,
                "future",
                now,
                b"{}",
                "did:web:other.example",
                "https://other.example/",
            )
            valid = CredentialRecord(
                "one",
                expires,
                "api-key",
                now,
                payload,
                service_did,
                "https://api.example.com/",
            )
            return invalid, valid

        async def save_credential(self, credential: CredentialRecord) -> None:
            pass

    api_key_document = document_with(authentication={"methods": ["api-key"]})
    mixed = Agent(
        AgentOptions(
            identity_provider=FakeIdentityProvider(),
            clock=lambda: now,
            credential_store=MixedStore(),
            inspect_transport=QueueTransport(response(api_key_document.to_wire())),
        )
    )
    assert await mixed.service("api.example.com").authentication_headers(
        AuthenticationOptions("https://api.example.com/resource")
    ) == {"X-Key": "secret"}


@pytest.mark.asyncio
async def test_custom_store_and_signer_fail_closed() -> None:
    class ForeignStore:
        async def delete_credential(self, service_did: str, credential_id: str) -> None:
            pass

        async def find_credential(
            self, service_did: str, credential_id: str
        ) -> CredentialRecord | None:
            return CredentialRecord(
                credential_id,
                datetime(2026, 1, 1, 1, tzinfo=UTC),
                "api-key",
                datetime(2026, 1, 1, tzinfo=UTC),
                b"{}",
                "did:web:foreign.example",
                "url",
            )

        async def list_credentials(self, service_did: str) -> tuple[CredentialRecord, ...]:
            return ()

        async def save_credential(self, credential: CredentialRecord) -> None:
            pass

    foreign, _ = configured_agent(
        QueueTransport(response(inspect_document().to_wire())),
        QueueTransport(),
        credential_store=cast(MemoryCredentialStore, ForeignStore()),
    )
    with pytest.raises(ValueError, match="metadata is invalid"):
        await foreign.service("api.example.com").authentication_headers(
            AuthenticationOptions("https://api.example.com/resource", credential_id="one")
        )

    class EmptySignerProvider(FakeIdentityProvider):
        async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
            async def sign(
                claims: ClientAssertionClaims, algorithms: tuple[SigningAlgorithm, ...]
            ) -> str:
                return ""

            return sign

    empty = Agent(
        AgentOptions(
            identity_provider=EmptySignerProvider(),
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
            command_transport=QueueTransport(),
        )
    )
    with pytest.raises(ValueError, match="empty assertion"):
        await empty.service("api.example.com").status()

    class NoSignerProvider(FakeIdentityProvider):
        async def signer_for(self, identity: ServiceIdentity) -> AssertionSigner:
            return cast(AssertionSigner, None)

    missing = Agent(
        AgentOptions(
            identity_provider=NoSignerProvider(),
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
        )
    )
    with pytest.raises(ValueError, match="no assertion signer"):
        await missing.service("api.example.com").status()
    authentication_missing = Agent(
        AgentOptions(
            identity_provider=NoSignerProvider(),
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
        )
    )
    with pytest.raises(ValueError, match="no assertion signer"):
        await authentication_missing.service("api.example.com").authentication_headers(
            AuthenticationOptions("https://api.example.com/resource", client_assertion_only=True)
        )

    unsupported = document_with(
        commands={"supported": ["inspect", "status"], "grant_types": ["api-key"]}
    )
    unsupported_grant, _ = configured_agent(
        QueueTransport(response(unsupported.to_wire())), QueueTransport()
    )
    with pytest.raises(ValueError, match="does not advertise grant"):
        await unsupported_grant.service("api.example.com").grant()

    grant_missing_signer = Agent(
        AgentOptions(
            identity_provider=NoSignerProvider(),
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
        )
    )
    await grant_missing_signer.service("api.example.com").identity()
    with pytest.raises(ValueError, match="no assertion signer"):
        await grant_missing_signer.service("api.example.com").grant()


def test_identity_rejects_untyped_signing_algorithms() -> None:
    with pytest.raises(ValueError, match="SigningAlgorithm"):
        ServiceIdentity(
            "did:web:agent.example.com",
            "did:web",
            "did:web:api.example.com",
            cast(tuple[SigningAlgorithm, ...], ("future",)),
        )
    with pytest.raises(ValueError, match="UTC offset"):
        CredentialRecord(
            "credential",
            datetime(2026, 1, 1),
            "api-key",
            datetime(2026, 1, 1, tzinfo=UTC),
            b"{}",
            "did:web:api.example.com",
            "https://api.example.com/",
        )


@pytest.mark.asyncio
async def test_explicit_credential_selection_mismatches() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    payload = json.dumps(
        {
            "api_key": "secret",
            "credential_id": "one",
            "expires_at": "2026-01-01T01:00:00Z",
            "header": "X-Key",
        }
    ).encode()
    store = MemoryCredentialStore(lambda: now)
    await store.save_credential(
        CredentialRecord(
            "one",
            now + timedelta(hours=1),
            "api-key",
            now,
            payload,
            "did:web:api.example.com",
            "url",
        )
    )
    both_methods = document_with(authentication={"methods": ["aep-jwt", "api-key", "oauth-bearer"]})
    agent, _ = configured_agent(
        QueueTransport(response(both_methods.to_wire())),
        QueueTransport(),
        credential_store=store,
    )
    with pytest.raises(ValueError, match="does not match requested"):
        await agent.service("api.example.com").authentication_headers(
            AuthenticationOptions(
                "https://api.example.com/resource",
                credential_id="one",
                grant_type="oauth-bearer",
            )
        )

    class UnadvertisedStore:
        async def delete_credential(self, service_did: str, credential_id: str) -> None:
            pass

        async def find_credential(
            self, service_did: str, credential_id: str
        ) -> CredentialRecord | None:
            return CredentialRecord(
                "basic",
                now + timedelta(hours=1),
                "basic",
                now,
                json.dumps(
                    {
                        "credential_id": "basic",
                        "expires_at": "2026-01-01T01:00:00Z",
                        "password": "pass",
                        "username": "user",
                    }
                ).encode(),
                service_did,
                "url",
            )

        async def list_credentials(self, service_did: str) -> tuple[CredentialRecord, ...]:
            return ()

        async def save_credential(self, credential: CredentialRecord) -> None:
            pass

    unadvertised = Agent(
        AgentOptions(
            identity_provider=FakeIdentityProvider(),
            clock=lambda: now,
            credential_store=UnadvertisedStore(),
            inspect_transport=QueueTransport(response(inspect_document().to_wire())),
        )
    )
    with pytest.raises(ValueError, match="compatible authentication"):
        await unadvertised.service("api.example.com").authentication_headers(
            AuthenticationOptions("https://api.example.com/resource", credential_id="basic")
        )


@pytest.mark.asyncio
async def test_memory_credential_expiration_and_ordering() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryCredentialStore(lambda: now)
    values = [
        CredentialRecord("b", now + timedelta(hours=1), "x", now, b"{}", "service", "url"),
        CredentialRecord("a", now + timedelta(hours=1), "x", now, b"{}", "service", "url"),
    ]
    for value in values:
        await store.save_credential(value)
    assert [value.credential_id for value in await store.list_credentials("service")] == ["a", "b"]
    found = await store.find_credential("service", "a")
    assert found is not None and found.credential_id == "a"
    expiring = MemoryCredentialStore(lambda: now + timedelta(hours=2))
    expiring._records[("service", "a")] = values[0]
    assert await expiring.find_credential("service", "a") is None
    expiring._records[("service", "b")] = values[1]
    assert await expiring.list_credentials("service") == ()


@pytest.mark.asyncio
async def test_httpx_transport_does_not_inherit_client_credentials() -> None:
    observed: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, headers={"X-Test": "yes"}, content=b"ok")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        auth=("inherited-user", "inherited-password"),
        headers={"Authorization": "Bearer inherited"},
        cookies={"session": "inherited"},
    ) as client:
        transport = HttpxTransport(client)
        result = await transport.send(HttpRequest("GET", "https://example.com"))
    assert result.body == b"ok"
    assert "authorization" not in observed[0].headers
    assert "cookie" not in observed[0].headers
    assert result.headers["x-test"] == "yes"


@pytest.mark.asyncio
async def test_httpx_transport_owned_client(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeClient:
        closed = False

        async def send(
            self,
            request: httpx.Request,
            *,
            auth: object,
            follow_redirects: bool,
            stream: bool,
        ) -> httpx.Response:
            assert auth is None
            assert not follow_redirects
            assert stream
            return httpx.Response(200, content=b"owned", request=request)

        async def aclose(self) -> None:
            self.closed = True

    client = FakeClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)
    transport = HttpxTransport()
    assert (await transport.send(HttpRequest("GET", "https://example.com"))).body == b"owned"
    await transport.aclose()
    assert client.closed
    with pytest.raises(ValueError, match="positive"):
        HttpxTransport(maximum_response_bytes=0)


@pytest.mark.asyncio
async def test_httpx_transport_rejects_stream_over_limit() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"large", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="configured limit"):
            await HttpxTransport(client, maximum_response_bytes=4).send(
                HttpRequest("GET", "https://example.com")
            )


@pytest.mark.asyncio
async def test_agent_owned_transport_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    class ClosingTransport:
        closed = False

        async def send(self, request: HttpRequest) -> HttpResponse:
            raise AssertionError("not called")

        async def aclose(self) -> None:
            self.closed = True

    created = ClosingTransport()
    monkeypatch.setattr(
        "agent_enrollment_protocol.agent.client.HttpxTransport", lambda **options: created
    )
    async with Agent(AgentOptions(identity_provider=FakeIdentityProvider())):
        pass
    assert created.closed

    custom = ClosingTransport()
    inspect = ClosingTransport()
    monkeypatch.setattr(
        "agent_enrollment_protocol.agent.client.HttpxTransport", lambda **options: inspect
    )
    async with Agent(
        AgentOptions(identity_provider=FakeIdentityProvider(), command_transport=custom)
    ):
        pass
    assert inspect.closed
    assert not custom.closed
