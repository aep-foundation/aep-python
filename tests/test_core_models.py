from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_enrollment_protocol.core import (
    AEP_ASSERTION_OPERATIONS,
    AEP_AUTHENTICATED_COMMANDS,
    AEP_AUTHENTICATION_METHOD_JWT,
    AEP_BINDINGS,
    AEP_BUILT_IN_GRANT_TYPES,
    AEP_CLAIM_NAMES,
    AEP_COMMANDS,
    AEP_IDENTITY_METHOD_DID_WEB,
    AEP_SIGNING_ALGORITHMS,
    AgentStatus,
    ApiKeyGrantResponse,
    AssertionOperation,
    Authentication,
    BasicGrantResponse,
    Bindings,
    ClaimValues,
    ClientAssertionClaims,
    Commands,
    ContactAddressPrimary,
    CoreConfiguration,
    EnrollRequest,
    EnrollResponse,
    Extensions,
    GrantRequest,
    GrantTypeConfig,
    HttpConfiguration,
    IdempotencyMetadata,
    Identity,
    InspectClaims,
    InspectDocument,
    ManagedAgentStatus,
    OAuthBearerGrantResponse,
    OpenApiAepSecurityScheme,
    OpenApiPathMatching,
    OpenApiReference,
    OpenApiTrailingSlash,
    PlatformAgentIdentity,
    PlatformAgentIdentityListResponse,
    PlatformDiscoveryDocument,
    PlatformEndpoints,
    PlatformHttp,
    PlatformIdentityConfiguration,
    PlatformLifecycleRequest,
    PlatformMetadata,
    PlatformProvisionRequest,
    PlatformSignCompleted,
    PlatformSigningConfiguration,
    PlatformSignPending,
    PlatformSignRequest,
    PlatformVerificationRequest,
    PlatformVerificationResponse,
    ProblemDetails,
    RevokeRequest,
    RevokeResponse,
    ServiceIdentity,
    SigningAlgorithm,
    StatusResponse,
)
from agent_enrollment_protocol.core.models import AepModel, _is_mailbox


def test_registered_protocol_constants() -> None:
    assert AEP_COMMANDS == ("inspect", "enroll", "grant", "revoke", "status")
    assert AEP_COMMANDS[1:] == AEP_AUTHENTICATED_COMMANDS
    assert (*AEP_AUTHENTICATED_COMMANDS, "authenticate") == AEP_ASSERTION_OPERATIONS
    assert AEP_AUTHENTICATION_METHOD_JWT == "aep-jwt"
    assert AEP_BINDINGS == ("http",)
    assert AEP_SIGNING_ALGORITHMS == ("EdDSA", "ES256")
    assert AEP_IDENTITY_METHOD_DID_WEB == "did:web"
    assert AEP_CLAIM_NAMES == (
        "contact.address.primary",
        "contact.email",
        "contact.mobile",
        "person.birthdate",
        "person.first_name",
        "person.last_name",
        "person.username",
    )
    assert AEP_BUILT_IN_GRANT_TYPES == ("oauth-bearer", "api-key", "basic")


def inspect_document() -> InspectDocument:
    return InspectDocument.model_validate(
        {
            "aep_version": "1.7",
            "authentication": Authentication(methods=("aep-jwt", "api-key")),
            "bindings": Bindings.model_validate(
                {"supported": ("http", "future-binding"), "future": True}
            ),
            "claims": InspectClaims(
                required=("contact.email",),
                preferred=("person.first_name",),
                optional=("example.future",),
            ),
            "commands": Commands(
                supported=("inspect", "enroll", "grant", "revoke", "status"),
                grant_types=("api-key",),
                grant_types_config={
                    "api-key": GrantTypeConfig(supports_per_credential_revoke="true")
                },
            ),
            "core": CoreConfiguration(signing_algorithms=("EdDSA", "ES256", "future")),
            "extensions": Extensions(supported=("https://example.com/aep/extension",)),
            "http": HttpConfiguration(
                endpoint_base="/custom",
                openapi=OpenApiReference(
                    url="/openapi.json",
                    path_matching=OpenApiPathMatching(trailing_slash=OpenApiTrailingSlash.STRICT),
                ),
            ),
            "identity": Identity(methods=("did:web",)),
            "service": ServiceIdentity(did="did:web:api.example.com"),
            "future_section": {"enabled": True},
        }
    )


def test_inspect_and_command_models_are_immutable_and_forward_compatible() -> None:
    document = inspect_document()
    assert document.bindings.supported == ("http", "future-binding")
    assert document.model_extra == {"future_section": {"enabled": True}}
    assert document.to_wire()["http"]["openapi"]["url"] == "/openapi.json"
    with pytest.raises(ValidationError):
        document.aep_version = "2.0"
    with pytest.raises(ValidationError):
        Authentication.model_validate({"methods": ("aep-jwt",), "future": True})
    model = AepModel()
    assert AepModel.model_validate(model) is model
    with pytest.raises(ValidationError):
        AepModel.model_validate("value")
    with pytest.raises(ValidationError, match="omitted"):
        EnrollRequest.model_validate_json('{"agent_did":"did:web:agent","claims":null}')
    additive_null = Bindings.model_validate_json('{"supported":["http"],"future":null}')
    assert additive_null.to_wire()["future"] is None
    caller_owned = {"nested": {"enabled": True}}
    copied = Bindings.model_validate({"supported": ("http",), "future": caller_owned})
    caller_owned["nested"]["enabled"] = False
    assert copied.to_wire()["future"]["nested"]["enabled"] is True


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (lambda: Authentication(methods=("aep-jwt", "aep-jwt")), "unique"),
        (lambda: Authentication(methods=("AEP",)), "identifier"),
        (lambda: Bindings(supported=("future",)), "http"),
        (lambda: Bindings(supported=("bad_name", "http")), "identifier"),
        (lambda: InspectClaims(required=("Contact.Email",)), "claim"),
        (lambda: Commands(supported=("enroll",)), "inspect"),
        (lambda: Commands(supported=("inspect", "authenticate")), "assertion"),
        (lambda: Commands(supported=("inspect", "grant")), "grant_types"),
        (
            lambda: Commands(
                supported=("inspect",),
                grant_types=("bad_type",),
            ),
            "identifier",
        ),
        (
            lambda: Commands(
                supported=("inspect",),
                grant_types=("api-key",),
                grant_types_config={"basic": GrantTypeConfig()},
            ),
            "advertised",
        ),
        (lambda: CoreConfiguration(signing_algorithms=("ES256",)), "EdDSA"),
        (lambda: Extensions(supported=("relative",)), "absolute"),
        (lambda: Extensions(supported=("https://bad example.com",)), "absolute"),
        (
            lambda: OpenApiReference(
                url="not a URI",
                path_matching=OpenApiPathMatching(trailing_slash=OpenApiTrailingSlash.STRICT),
            ),
            "URI-reference",
        ),
        (lambda: HttpConfiguration(endpoint_base="https://example.com"), "origin-relative"),
        (lambda: Identity(methods=("DID:web",)), "identifier"),
        (lambda: ServiceIdentity(did="https://example.com"), "DID"),
        (
            lambda: InspectDocument(
                aep_version="1",
                bindings=Bindings(supported=("http",)),
                commands=Commands(supported=("inspect",)),
                core=CoreConfiguration(signing_algorithms=("EdDSA", "ES256")),
                http=HttpConfiguration(),
                identity=Identity(methods=()),
                service=ServiceIdentity(did="did:web:example.com"),
            ),
            "major.minor",
        ),
        (
            lambda: InspectDocument(
                aep_version="2.0",
                bindings=Bindings(supported=("http",)),
                commands=Commands(supported=("inspect",)),
                core=CoreConfiguration(signing_algorithms=("EdDSA", "ES256")),
                http=HttpConfiguration(),
                identity=Identity(methods=()),
                service=ServiceIdentity(did="did:web:example.com"),
            ),
            "unsupported",
        ),
        (
            lambda: InspectDocument(
                aep_version="1.0",
                bindings=Bindings(supported=("http",)),
                commands=Commands(supported=("inspect", "status")),
                core=CoreConfiguration(signing_algorithms=("EdDSA", "ES256")),
                http=HttpConfiguration(),
                identity=Identity(methods=()),
                service=ServiceIdentity(did="did:web:example.com"),
            ),
            "identity.methods",
        ),
    ],
)
def test_invalid_inspect_models(factory: object, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        assert callable(factory)
        factory()


def test_claim_models_accept_registered_and_additive_values() -> None:
    values = ClaimValues.model_validate_json(
        json.dumps(
            {
                "contact.address.primary": {
                    "city": "San Francisco",
                    "country": "US",
                    "delivery_instructions": "Reception",
                    "first_name": "Grace",
                    "last_name": "Hopper",
                    "line1": "123 Market Street",
                    "line2": "",
                    "line3": "Receiving",
                    "postcode": "94105",
                    "region": "CA",
                },
                "contact.email": '"quoted local"@example.com',
                "contact.mobile": "+14155550100",
                "person.birthdate": "1990-04-12",
                "person.first_name": "Ada",
                "person.last_name": "Lovelace",
                "person.username": "ada",
                "example.future": {"value": True},
            }
        )
    )
    assert values.contact_address_primary is not None
    assert values.contact_address_primary.line2 == ""
    assert values.to_wire()["contact.email"] == '"quoted local"@example.com'


@pytest.mark.parametrize(
    "value",
    [
        {"contact.address.primary": {"country": "US", "first_name": "A", "last_name": "B"}},
        {
            "contact.address.primary": {
                "country": "us",
                "first_name": "A",
                "last_name": "B",
                "line1": "1 Main",
            }
        },
        {
            "contact.address.primary": {
                "country": "US",
                "first_name": "A",
                "last_name": "B",
                "line1": "1 Main",
                "postal_code": "1",
            }
        },
        {"contact.email": "owner..name@example.com"},
        {"contact.email": "owner@-example.com"},
        {"contact.email": "owner.example.com"},
        {"contact.mobile": "(415) 555-0100"},
        {"person.birthdate": "2025-02-30"},
        {"person.birthdate": "20250101"},
        {"person.birthdate": "2025-W01-1"},
        {"person.first_name": ""},
    ],
)
def test_invalid_claim_values(value: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ClaimValues.model_validate(value)


def test_claim_validation_boundaries() -> None:
    assert ClaimValues().to_wire() == {}
    assert _is_mailbox("a@b")
    assert not _is_mailbox("a" * 65 + "@b")
    assert not _is_mailbox("a@" + "b" * 256)
    assert not _is_mailbox("a@")
    with pytest.raises(ValidationError, match="country"):
        ContactAddressPrimary(
            country="",
            first_name="A",
            last_name="B",
            line1="1 Main",
        )
    with pytest.raises(ValidationError, match="city"):
        ContactAddressPrimary(
            city="",
            country="US",
            first_name="A",
            last_name="B",
            line1="1 Main",
        )


def test_lifecycle_and_command_wire_models() -> None:
    request = EnrollRequest(agent_did="did:web:agent.example", idempotency_key="request-1")
    assert request.to_wire() == {
        "agent_did": "did:web:agent.example",
        "idempotency_key": "request-1",
    }
    assert EnrollResponse(status=AgentStatus.SUSPENDED).status is AgentStatus.SUSPENDED
    pending = StatusResponse(
        status=AgentStatus.PENDING,
        owner_action_required="false",
        requirements_pending=("profile",),
        since="2026-09-02T12:00:00Z",
    )
    assert "owner_action_required" not in pending.to_wire()
    assert EnrollResponse(status=AgentStatus.ACTIVE).to_wire() == {"status": "active"}
    assert (
        EnrollResponse(status=AgentStatus.PENDING, owner_action_required="true").to_wire()[
            "owner_action_required"
        ]
        == "true"
    )
    assert StatusResponse(status=AgentStatus.ACTIVE).since is None
    assert GrantRequest(grant_type="future-grant", requested_scopes=()).requested_scopes == ()
    assert RevokeRequest(grant_type="api-key").grant_type == "api-key"
    assert RevokeRequest(grant_type="api-key", credential_id="credential-1").credential_id
    assert RevokeRequest(all_grant_types="true").all_grant_types == "true"
    assert RevokeResponse().to_wire() == {}


@pytest.mark.parametrize(
    "factory",
    [
        lambda: EnrollResponse(status=AgentStatus.PENDING, verification_pending=()),
        lambda: EnrollResponse(
            status=AgentStatus.PENDING,
            verification_pending=("one", "one"),
        ),
        lambda: StatusResponse(status=AgentStatus.ACTIVE, since="yesterday"),
        lambda: StatusResponse(status=AgentStatus.ACTIVE, since="2026-09-02 12:00:00Z"),
        lambda: RevokeRequest(),
        lambda: RevokeRequest(credential_id="one"),
        lambda: RevokeRequest(grant_type="api-key", all_grant_types="true"),
    ],
)
def test_invalid_lifecycle_and_revoke_models(factory: object) -> None:
    with pytest.raises(ValidationError):
        assert callable(factory)
        factory()


def test_assertion_problem_credential_and_metadata_models() -> None:
    claims = ClientAssertionClaims(
        aud="did:web:service.example",
        exp=1_700_000_060,
        iat=1_700_000_000,
        iss="did:web:agent.example",
        jti="assertion-1",
        op=AssertionOperation.ENROLL,
        sub="did:web:agent.example",
    )
    assert claims.op is AssertionOperation.ENROLL
    problem = ProblemDetails(
        type="urn:aep:error:invalid_request",
        title="Invalid request",
        status=400,
        code="invalid_request",
    )
    assert problem.status == 400
    expires = "2026-09-02T12:00:00Z"
    assert (
        OAuthBearerGrantResponse(
            access_token="token",
            credential_id="credential-1",
            expires_at=expires,
            scopes=None,
            token_format="opaque",
            token_type="Bearer",
        ).scopes
        == ()
    )
    assert (
        ApiKeyGrantResponse(
            api_key="secret",
            credential_id="credential-2",
            expires_at=expires,
            header="X-API-Key",
            scopes=("read",),
        ).header
        == "X-API-Key"
    )
    assert (
        BasicGrantResponse(
            credential_id="credential-3",
            expires_at=expires,
            password="password",
            realm="example",
            username="user",
        ).realm
        == "example"
    )
    assert "access-secret-value" not in repr(
        OAuthBearerGrantResponse(
            access_token="access-secret-value",
            credential_id="credential-1",
            expires_at=expires,
            token_type="Bearer",
        )
    )
    assert "api-secret-value" not in repr(
        ApiKeyGrantResponse(
            api_key="api-secret-value",
            credential_id="credential-2",
            expires_at=expires,
            header="X-API-Key",
        )
    )
    assert "basic-secret-value" not in repr(
        BasicGrantResponse(
            credential_id="credential-3",
            expires_at=expires,
            password="basic-secret-value",
            username="user",
        )
    )
    assert IdempotencyMetadata(
        idempotency_key="request-1",
        first_body_hash=f"sha256:{'0' * 64}",
    ).first_body_hash
    assert (
        OpenApiAepSecurityScheme(**{"x-aep-authentication-method": "api-key"}).authentication_method
        == "api-key"
    )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ClientAssertionClaims(
            aud="service",
            exp=2,
            iat=1,
            iss="agent-1",
            jti="jti",
            op=AssertionOperation.ENROLL,
            resource="https://resource.example",
            sub="agent-1",
        ),
        lambda: ClientAssertionClaims(
            aud="service",
            exp=2,
            iat=1,
            iss="agent-1",
            jti="jti",
            op=AssertionOperation.ENROLL,
            sub="agent-2",
        ),
        lambda: ClientAssertionClaims(
            aud="service",
            exp=301,
            iat=0,
            iss="agent",
            jti="jti",
            op=AssertionOperation.ENROLL,
            sub="agent",
        ),
        lambda: ClientAssertionClaims(
            aud="service",
            exp=2,
            iat=1,
            iss="agent",
            jti="jti",
            op=AssertionOperation.AUTHENTICATE,
            sub="agent",
        ),
        lambda: ClientAssertionClaims(
            aud="service",
            exp=2,
            iat=1,
            iss="agent",
            jti="jti",
            op=AssertionOperation.AUTHENTICATE,
            resource="https://resource.example/#fragment",
            sub="agent",
        ),
        lambda: ProblemDetails(
            type="urn:aep:error:other",
            title="Invalid",
            status=400,
            code="invalid_request",
        ),
        lambda: ProblemDetails(
            type="urn:aep:error:not_recognized",
            title="Not recognized",
            status=401,
            code="not_recognized",
            verification_pending=("proof",),
        ),
        lambda: ProblemDetails(
            type="urn:aep:error:INVALID",
            title="Invalid",
            status=400,
            code="INVALID",
        ),
        lambda: ProblemDetails(
            type="urn:aep:error:requirements_unmet",
            title="Requirements unmet",
            status=400,
            code="requirements_unmet",
            requirements_pending=("claim", "claim"),
        ),
        lambda: OAuthBearerGrantResponse(
            access_token="token",
            credential_id="credential",
            expires_at="tomorrow",
            token_type="Bearer",
        ),
        lambda: IdempotencyMetadata(idempotency_key="one", first_body_hash="SHA256:bad"),
        lambda: OpenApiAepSecurityScheme(**{"x-aep-authentication-method": "API_KEY"}),
        lambda: ApiKeyGrantResponse(
            api_key="bad value",
            credential_id="credential",
            expires_at="2026-09-02T12:00:00Z",
            header="X-API-Key",
        ),
        lambda: ApiKeyGrantResponse(
            api_key="secret",
            credential_id="credential",
            expires_at="2026-09-02T12:00:00Z",
            header="bad header",
        ),
        lambda: BasicGrantResponse(
            credential_id="credential",
            expires_at="2026-09-02T12:00:00Z",
            password="secret",
            username="user:name",
        ),
        lambda: BasicGrantResponse(
            credential_id="credential",
            expires_at="2026-09-02T12:00:00Z",
            password="bad\nsecret",
            username="user",
        ),
    ],
)
def test_invalid_assertion_problem_credential_and_metadata_models(factory: object) -> None:
    with pytest.raises(ValidationError):
        assert callable(factory)
        factory()


def platform_identity() -> PlatformAgentIdentity:
    return PlatformAgentIdentity(
        agent_did="did:web:platform.example:agents:one",
        agent_identity_id="identity-1",
        created_at="2026-09-02T12:00:00Z",
        did_document_url="https://platform.example/agents/one/did.json",
        key_id="did:web:platform.example:agents:one#key-1",
        service_did="did:web:service.example",
        signing_algorithms=(SigningAlgorithm.EDDSA, SigningAlgorithm.ES256),
        status=ManagedAgentStatus.ACTIVE,
        updated_at="2026-09-02T12:00:01Z",
    )


def test_platform_wire_contracts() -> None:
    discovery = PlatformDiscoveryDocument(
        aep_version="1.0",
        endpoints=PlatformEndpoints(
            lifecycle="/identities/{agent_identity_id}",
            provision="/identities",
            sign="/identities/{agent_identity_id}/sign",
            list="/identities",
            hosted_verification="/verify",
        ),
        http=PlatformHttp(endpoint_base="/platform/aep/"),
        identity=PlatformIdentityConfiguration(
            did_methods=("did:web",),
            did_url_template="https://platform.example/agents/{agent_did_id}/did.json",
        ),
        platform=PlatformMetadata(hosted_verification=True, name="Example Platform"),
        signing=PlatformSigningConfiguration(
            algorithms=(SigningAlgorithm.EDDSA, SigningAlgorithm.ES256),
            default_lifetime_seconds="300",
        ),
    )
    assert discovery.platform.name == "Example Platform"
    identity = platform_identity()
    assert PlatformAgentIdentityListResponse(count="1", data=(identity,), total="1").data == (
        identity,
    )
    assert PlatformProvisionRequest(service_did="did:web:service.example").service_did
    assert PlatformLifecycleRequest(status=ManagedAgentStatus.SUSPENDED).status
    assert (
        PlatformSignRequest(
            jti="jti",
            op=AssertionOperation.ENROLL,
            service_did="did:web:service.example",
            lifetime_seconds="60",
        ).jti
        == "jti"
    )
    assert (
        PlatformSignCompleted(
            status="completed",
            agent_did=identity.agent_did,
            client_assertion="jwt",
            expires_at="2026-09-02T12:01:00Z",
            issued_at="2026-09-02T12:00:00Z",
            jti="jti",
            service_did=identity.service_did,
        ).status
        == "completed"
    )
    assert PlatformSignPending(status="pending", retry_after_seconds="5").status == "pending"
    assert PlatformVerificationRequest(
        client_assertion="jwt",
        op=AssertionOperation.AUTHENTICATE,
        resource="https://resource.example/items/1",
        service_did=identity.service_did,
    ).resource
    assert PlatformVerificationResponse(
        reason="verified",
        service_did=identity.service_did,
        verified=True,
        agent_did=identity.agent_did,
        agent_identity_id=identity.agent_identity_id,
        op=AssertionOperation.ENROLL,
        status=ManagedAgentStatus.ACTIVE,
    ).verified


@pytest.mark.parametrize(
    "factory",
    [
        lambda: PlatformEndpoints(
            lifecycle="relative", provision="/one", sign="/two", list="/three"
        ),
        lambda: PlatformEndpoints(
            lifecycle="/identities/{agent_identity_id}",
            provision="/identities",
            sign="/sign",
            list="/identities",
        ),
        lambda: PlatformEndpoints(
            lifecycle="/identities/{agent_identity_id}",
            provision="/identities/{id}",
            sign="/identities/{agent_identity_id}/sign",
            list="/identities",
        ),
        lambda: PlatformEndpoints(
            lifecycle="/identities/{agent_identity_id}",
            provision="/identities",
            sign="/identities/{agent_identity_id}/sign",
            list="/identities",
            hosted_verification="/verify/{id}",
        ),
        lambda: PlatformHttp(endpoint_base="https://example.com"),
        lambda: PlatformHttp(endpoint_base="/{id}"),
        lambda: PlatformIdentityConfiguration(
            did_methods=("did:web", "did:web"),
            did_url_template="https://example.com/{agent_did_id}",
        ),
        lambda: PlatformIdentityConfiguration(
            did_methods=("did:web",), did_url_template="http://example.com/{id}"
        ),
        lambda: PlatformIdentityConfiguration(
            did_methods=("did:web",),
            did_url_template="https://example.com/{agent_did_id}#key",
        ),
        lambda: PlatformMetadata(
            did="https://platform.example", hosted_verification=False, name="Platform"
        ),
        lambda: PlatformSigningConfiguration(
            algorithms=(SigningAlgorithm.EDDSA,), default_lifetime_seconds="301"
        ),
        lambda: PlatformDiscoveryDocument(
            aep_version="version",
            endpoints=PlatformEndpoints(
                lifecycle="/one", provision="/two", sign="/three", list="/four"
            ),
            http=PlatformHttp(endpoint_base="/"),
            identity=PlatformIdentityConfiguration(
                did_methods=("did:web",), did_url_template="https://example.com/{id}"
            ),
            platform=PlatformMetadata(hosted_verification=False, name="Platform"),
            signing=PlatformSigningConfiguration(
                algorithms=(SigningAlgorithm.EDDSA,), default_lifetime_seconds="1"
            ),
        ),
        lambda: PlatformDiscoveryDocument(
            aep_version="1.0",
            endpoints=PlatformEndpoints(
                lifecycle="/identities/{agent_identity_id}",
                provision="/identities",
                sign="/identities/{agent_identity_id}/sign",
                list="/identities",
                hosted_verification="/verify",
            ),
            http=PlatformHttp(endpoint_base="/"),
            identity=PlatformIdentityConfiguration(
                did_methods=("did:web",),
                did_url_template="https://example.com/{agent_did_id}",
            ),
            platform=PlatformMetadata(hosted_verification=False, name="Platform"),
            signing=PlatformSigningConfiguration(
                algorithms=(SigningAlgorithm.EDDSA,), default_lifetime_seconds="1"
            ),
        ),
        lambda: PlatformDiscoveryDocument(
            aep_version="2.0",
            endpoints=PlatformEndpoints(
                lifecycle="/identities/{agent_identity_id}",
                provision="/identities",
                sign="/identities/{agent_identity_id}/sign",
                list="/identities",
            ),
            http=PlatformHttp(endpoint_base="/"),
            identity=PlatformIdentityConfiguration(
                did_methods=("did:web",),
                did_url_template="https://example.com/{agent_did_id}",
            ),
            platform=PlatformMetadata(hosted_verification=False, name="Platform"),
            signing=PlatformSigningConfiguration(
                algorithms=(SigningAlgorithm.EDDSA,), default_lifetime_seconds="1"
            ),
        ),
        lambda: PlatformAgentIdentityListResponse(count="01", data=(), total="0"),
        lambda: PlatformAgentIdentityListResponse(count="0", data=(), total="-1"),
        lambda: PlatformAgentIdentityListResponse(
            count="0", data=(platform_identity(),), total="1"
        ),
        lambda: PlatformAgentIdentityListResponse(
            count="1", data=(platform_identity(),), total="0"
        ),
        lambda: PlatformProvisionRequest(service_did="not-a-did"),
        lambda: PlatformSignRequest(
            jti="jti",
            op=AssertionOperation.AUTHENTICATE,
            service_did="did:web:service.example",
        ),
        lambda: PlatformSignRequest(
            jti="jti",
            op=AssertionOperation.ENROLL,
            resource="https://resource.example",
            service_did="did:web:service.example",
        ),
        lambda: PlatformSignPending(status="pending", retry_after_seconds="0"),
        lambda: PlatformSignRequest(
            jti="jti",
            op=AssertionOperation.ENROLL,
            service_did="did:web:service.example",
            lifetime_seconds="0",
        ),
        lambda: PlatformVerificationResponse(
            reason="not_recognized", service_did="did:web:service.example", verified=True
        ),
        lambda: PlatformVerificationResponse(
            reason="not_recognized",
            service_did="did:web:service.example",
            verified=False,
            agent_did="did:web:agent.example",
        ),
        lambda: PlatformVerificationResponse(
            reason="verified", service_did="did:web:service.example", verified=True
        ),
        lambda: PlatformVerificationResponse(
            reason="verified",
            service_did="did:web:service.example",
            verified=True,
            agent_did="not-a-did",
            agent_identity_id="identity",
            op=AssertionOperation.ENROLL,
            status=ManagedAgentStatus.ACTIVE,
        ),
        lambda: PlatformVerificationResponse(
            reason="verified", service_did="did:web:service.example", verified=False
        ),
    ],
)
def test_invalid_platform_contracts(factory: object) -> None:
    with pytest.raises(ValidationError):
        assert callable(factory)
        factory()


def test_additional_platform_validation_boundaries() -> None:
    with pytest.raises(ValidationError, match="date-time"):
        PlatformAgentIdentity(
            agent_did="did:web:agent.example",
            agent_identity_id="identity",
            created_at="2026-09-02T12:00:00",
            did_document_url="https://agent.example/did.json",
            key_id="did:web:agent.example#key",
            service_did="did:web:service.example",
            signing_algorithms=(SigningAlgorithm.EDDSA,),
            status=ManagedAgentStatus.ACTIVE,
            updated_at="2026-09-02T12:00:00Z",
        )
    assert not PlatformVerificationResponse(
        reason="not_recognized",
        service_did="did:web:service.example",
        verified=False,
    ).verified
