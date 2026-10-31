from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from agent_enrollment_protocol.adapters import AepAsgiApplication
from agent_enrollment_protocol.agent import (
    Agent,
    AgentCommandError,
    AgentOptions,
    EnrollOptions,
    GrantOptions,
    HttpxTransport,
)
from agent_enrollment_protocol.core import (
    AEP_PROBLEM_MEDIA_TYPE,
    AEP_SERVICE_DOCUMENTS_EXTENSION,
    MAX_SERVICE_DOCUMENT_BYTES,
    SERVICE_DOCUMENT_TYPES,
    AepValidationError,
    AgentStatus,
    AssertionOperation,
    ClaimValues,
    EnrollmentDecisionStatus,
    EnrollRequest,
    EnrollResponse,
    InspectClaims,
    InspectDocument,
    PortableDocumentBlock,
    PortableServiceDocument,
    ProblemDetails,
    ServiceDocument,
    parse_portable_service_document,
)
from agent_enrollment_protocol.service import (
    EnrollmentDecision,
    GrantTypeDefinition,
    MemoryEnrollmentStore,
    Service,
    ServiceOptions,
    StaticEnrollmentPolicy,
)

from .test_agent import QueueTransport, configured_agent, inspect_response, response
from .test_agent_integration import LocalIdentityProvider, Verifier
from .test_core_models import inspect_document
from .test_platform import NOW
from .test_service import AGENT_DID, GrantHandler, _options, _service


def descriptor(
    identifier: str = "terms", url: str = "https://example.com/terms"
) -> ServiceDocument:
    return ServiceDocument.model_validate(
        {
            "id": identifier,
            "type": "custom_terms",
            "title": "Terms",
            "enrollment": "required",
            "representations": [{"media_type": "text/html", "url": url}],
        }
    )


def portable() -> dict[str, Any]:
    return {
        "format": "aep-service-document",
        "version": "1.0",
        "id": "terms",
        "summary": [{"type": "paragraph", "text": "A service summary."}],
        "content": [
            {
                "type": "section",
                "title": "Use",
                "blocks": [
                    {"type": "paragraph", "text": "Full café terms."},
                    {"type": "numbered_list", "items": ["First", "Second"]},
                    {"type": "bulleted_list", "items": ["Third"]},
                ],
            }
        ],
    }


def advertised() -> InspectDocument:
    data = inspect_document().to_wire()
    data.update(
        extensions={"supported": [AEP_SERVICE_DOCUMENTS_EXTENSION]},
        service_documents=[descriptor().to_wire()],
    )
    return InspectDocument.model_validate_json(json.dumps(data))


def test_document_models_preserve_content_and_additive_fields() -> None:
    assert tuple(sorted(SERVICE_DOCUMENT_TYPES)) == SERVICE_DOCUMENT_TYPES
    assert len(SERVICE_DOCUMENT_TYPES) == 13
    assert advertised().service_documents == (descriptor(),)
    raw = portable() | {"future": {"value": None}}
    parsed = parse_portable_service_document(json.dumps(raw).encode(), "terms")
    assert parsed.to_wire() == raw
    assert isinstance(parsed.content, tuple)
    assert parsed.content[0].blocks is not None
    with pytest.raises(ValidationError):
        parsed.id = "other"
    assert (
        PortableServiceDocument.model_validate(
            {k: v for k, v in portable().items() if k != "summary"}
        ).summary
        is None
    )
    for ids in ((), ("Terms", "terms", "a" * 32), tuple(f"id-{n}" for n in range(7))):
        request = EnrollRequest(agent_did=AGENT_DID, acknowledged_document_ids=ids)
        assert request.to_wire()["acknowledged_document_ids"] == list(ids)
    assert "acknowledged_document_ids" not in EnrollRequest(agent_did=AGENT_DID).to_wire()


def test_portable_block_ignores_members_not_defined_for_its_type() -> None:
    for block in (
        {"type": "paragraph", "text": "Terms"},
        {"type": "section", "title": "Use", "blocks": [{"type": "paragraph", "text": "Terms"}]},
        {"type": "bulleted_list", "items": ["One"]},
        {"type": "numbered_list", "items": ["One"]},
    ):
        extras = {key: None for key in ("text", "title", "blocks", "items") if key not in block}
        assert PortableDocumentBlock.model_validate(block | extras).to_wire() == block
    with pytest.raises(ValidationError):
        PortableDocumentBlock.model_validate("not an object")
    with pytest.raises(ValidationError, match="string_unicode"):
        ServiceDocument.model_validate(descriptor().to_wire() | {"title": "\ud800"})


@pytest.mark.parametrize(
    "ids",
    [
        None,
        [""],
        ["a" * 33],
        ["é"],
        ["id\n"],
        ["id", "id"],
        [str(i) for i in range(8)],
        "terms",
        [1],
    ],
)
def test_rejects_invalid_declarations(ids: Any) -> None:
    for model, base in (
        (EnrollRequest, {"agent_did": AGENT_DID}),
        (EnrollResponse, {"status": "active"}),
    ):
        with pytest.raises(ValidationError):
            model.model_validate_json(json.dumps(base | {"acknowledged_document_ids": ids}))


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/terms",
        "http://127.0.0.1:8080/terms",
        "http://[::1]/terms",
        "https://10.0.0.1/terms",
        "https://example.com/terms?x=1",
    ],
)
def test_document_url_policy_accepts_standard_networking(url: str) -> None:
    assert descriptor(url=url).representations[0].url == url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/terms",
        "http://localhost.example/terms",
        "http://192.168.1.1/terms",
        "https://user@example.com/",
        "https://user:pass@example.com/",
        "https:///x",
        "https://[broken/",
        "https://example.com/é",
        "https://example.com/a b",
        "https://example.com/\\x",
        "https://example.com/\x7f",
        "https://example.com/" + "a" * 2048,
    ],
)
def test_document_url_policy_rejects_malformed_or_nonlocal_http(url: str) -> None:
    with pytest.raises(ValidationError):
        descriptor(url=url)


@pytest.mark.parametrize(
    "change",
    [
        {"id": "x\n"},
        {"type": "bad-type"},
        {"enrollment": "future"},
        {"title": ""},
        {"title": "x" * 257},
        {"title": "\ud800"},
        {"representations": []},
        {"representations": [{"media_type": "application/json", "url": "https://example.com/x"}]},
        {"representations": [descriptor().representations[0].to_wire()] * 2},
        {"representations": [{"media_type": "text/html; x=y", "url": "https://example.com/x"}]},
    ],
)
def test_descriptor_rejects_invalid_known_fields(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ServiceDocument.model_validate(descriptor().to_wire() | change)


@pytest.mark.parametrize("enrollment", ["required", "not-required"])
def test_enrollment_requirement_wire_values(enrollment: str) -> None:
    document = ServiceDocument.model_validate(descriptor().to_wire() | {"enrollment": enrollment})
    assert document.to_wire()["enrollment"] == enrollment


def test_catalog_requires_unique_ids_bounds_and_extension() -> None:
    for docs in (
        [],
        [descriptor().to_wire()] * 2,
        [descriptor(str(i)).to_wire() for i in range(8)],
    ):
        with pytest.raises(ValidationError):
            InspectDocument.model_validate_json(
                json.dumps(advertised().to_wire() | {"service_documents": docs})
            )
    data = advertised().to_wire()
    del data["extensions"]
    with pytest.raises(ValidationError):
        InspectDocument.model_validate_json(json.dumps(data))
    data["extensions"] = {"supported": []}
    with pytest.raises(ValidationError):
        InspectDocument.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "block",
    [
        {"type": "paragraph"},
        {"type": "paragraph", "text": ""},
        {"type": "paragraph", "text": "x" * 16385},
        {"type": "paragraph", "text": "\ud800"},
        {"type": "section", "title": "Title"},
        {"type": "section", "blocks": []},
        {"type": "bulleted_list"},
        {"type": "numbered_list", "items": []},
        {"type": "bulleted_list", "items": ["x"] * 129},
        {"type": "future"},
    ],
)
def test_rejects_bad_portable_blocks(block: dict[str, Any]) -> None:
    with pytest.raises(AepValidationError):
        parse_portable_service_document(
            json.dumps(portable() | {"content": [block]}).encode(), "terms"
        )


def test_portable_depth_count_byte_and_identity_bounds() -> None:
    block: dict[str, Any] = {"type": "paragraph", "text": "Terms"}
    for _ in range(8):
        block = {"type": "section", "title": "Title", "blocks": [block]}
    assert PortableServiceDocument.model_validate(portable() | {"content": [block]})
    with pytest.raises(ValidationError):
        PortableServiceDocument.model_validate(
            portable() | {"content": [{"type": "section", "title": "Title", "blocks": [block]}]}
        )
    text = {"type": "paragraph", "text": "Terms"}
    assert PortableServiceDocument.model_validate(portable() | {"content": [text] * 1023})
    with pytest.raises(ValidationError):
        PortableServiceDocument.model_validate(portable() | {"content": [text] * 1024})
    for body, expected in (
        (b"\xc3(", "terms"),
        (b"{", "terms"),
        (json.dumps(portable()).encode(), "other"),
        (b" " * (MAX_SERVICE_DOCUMENT_BYTES + 1), "terms"),
        (b"[" * 1200, "terms"),
    ):
        with pytest.raises(AepValidationError):
            parse_portable_service_document(body, expected)


def test_document_problem_requires_complete_guidance() -> None:
    problem = {
        "type": "urn:aep:error:requirements_unmet",
        "title": "Requirements unmet",
        "code": "requirements_unmet",
        "status": 422,
        "requirements_pending": ["contact.email", "service_documents"],
        "required_document_ids": ["terms"],
    }
    assert ProblemDetails.model_validate(problem).required_document_ids == ("terms",)
    changes: tuple[dict[str, Any], ...] = (
        {"required_document_ids": []},
        {"required_document_ids": None},
        {"requirements_pending": ["contact.email"]},
        {"status": 400},
        {"code": "invalid_request"},
    )
    for change in changes:
        with pytest.raises(ValidationError):
            ProblemDetails.model_validate(problem | change)
    del problem["required_document_ids"]
    with pytest.raises(ValidationError):
        ProblemDetails.model_validate(problem)


@pytest.mark.asyncio
async def test_document_lifecycle_and_grant_requirements() -> None:
    store = MemoryEnrollmentStore()
    handler = GrantHandler()
    service, _ = _service(
        extensions=(AEP_SERVICE_DOCUMENTS_EXTENSION,),
        service_documents=(descriptor(), descriptor("privacy")),
        enrollment_store=store,
        grant_types=(GrantTypeDefinition("api-key", handler),),
        claims=InspectClaims(required=("contact.email",)),
    )
    counter = 0

    async def enroll(fields: dict[str, Any], key: str | None = None) -> Any:
        nonlocal counter
        counter += 1
        return await service.enroll(
            json.dumps({"agent_did": AGENT_DID} | fields).encode(),
            _options(AssertionOperation.ENROLL, f"e-{counter}", key=key or f"key-{counter}"),
        )

    async def grant() -> Any:
        nonlocal counter
        counter += 1
        return await service.grant(
            b'{"grant_type":"api-key"}',
            _options(AssertionOperation.GRANT, f"g-{counter}", key=f"gk-{counter}"),
        )

    unseen = await grant()
    assert unseen.status == 401 and unseen.problem.required_document_ids is None
    missing = await enroll({})
    assert missing.problem.required_document_ids == ("terms", "privacy")
    assert missing.problem.requirements_pending == ("contact.email", "service_documents")
    claims = {"contact.email": "owner@example.com"}
    first = await enroll(
        {"claims": claims, "acknowledged_document_ids": ["terms", "retired"]}, "first"
    )
    assert first.body.acknowledged_document_ids == ("terms", "retired")
    original = await store.find(AGENT_DID)
    assert original and original.acknowledged_document_ids == ("terms",)
    assert (
        await enroll({"claims": claims, "acknowledged_document_ids": ["terms", "retired"]}, "first")
    ).body == first.body
    assert (
        await enroll({"claims": claims, "acknowledged_document_ids": ["privacy"]}, "first")
    ).status == 409
    blocked = await grant()
    assert blocked.problem.required_document_ids == ("privacy",) and not handler.grants
    assert (await enroll({})).status == 422
    empty = await enroll({"acknowledged_document_ids": []})
    assert empty.body.acknowledged_document_ids == ()
    assert (await grant()).status == 422
    updated = await enroll({"acknowledged_document_ids": ["privacy"]})
    assert updated.body.acknowledged_document_ids == ("privacy",)
    record = await store.find(AGENT_DID)
    assert record and record.enrollment_id == original.enrollment_id
    assert record.created_at == original.created_at and record.since == original.since
    assert record.claims == original.claims
    assert set(record.acknowledged_document_ids) == {"terms", "privacy"}
    assert (await enroll({})).body.acknowledged_document_ids is None
    assert (await grant()).status == 200 and len(handler.grants) == 1
    await store.save(replace(record, required_document_ids=("terms",)))
    assert (await grant()).problem.required_document_ids == ("terms",)
    await enroll({"acknowledged_document_ids": ["terms"]})
    assert (await grant()).status == 200
    record = await store.find(AGENT_DID)
    assert record and not record.required_document_ids
    await store.save(replace(record, claims=ClaimValues()))
    assert (await grant()).problem.requirements_pending == ("contact.email",)


@pytest.mark.asyncio
async def test_service_honors_unchanged_rejection_and_nonadvertised_documents() -> None:
    store = MemoryEnrollmentStore()
    service, _ = _service(enrollment_store=store)
    body = json.dumps({"agent_did": AGENT_DID, "acknowledged_document_ids": ["terms"]}).encode()
    response_ = await service.enroll(
        body, _options(AssertionOperation.ENROLL, "initial", key="initial")
    )
    assert response_.body and response_.body.acknowledged_document_ids is None
    original = await store.find(AGENT_DID)
    assert original
    for decision in (
        EnrollmentDecision(update_existing=False),
        EnrollmentDecision(status=EnrollmentDecisionStatus.REJECTED),
    ):
        service, _ = _service(
            enrollment_store=store,
            enrollment_policy=StaticEnrollmentPolicy(decision),
            extensions=(AEP_SERVICE_DOCUMENTS_EXTENSION,),
            service_documents=(descriptor(),),
        )
        result = await service.enroll(
            body, _options(AssertionOperation.ENROLL, "repeat", key="repeat")
        )
        assert result.status == (
            403 if decision.status is EnrollmentDecisionStatus.REJECTED else 200
        )
        assert await store.find(AGENT_DID) == original
    rejected, _ = _service(
        extensions=(AEP_SERVICE_DOCUMENTS_EXTENSION,),
        service_documents=(descriptor(),),
        enrollment_policy=StaticEnrollmentPolicy(
            EnrollmentDecision(status=EnrollmentDecisionStatus.REJECTED)
        ),
    )
    result = await rejected.enroll(
        body, _options(AssertionOperation.ENROLL, "reject", key="reject")
    )
    assert result.body and result.body.acknowledged_document_ids is None


@pytest.mark.asyncio
async def test_agent_enrolls_without_local_claim_gate_and_checks_exact_echo() -> None:
    for echo, accepted in ((["terms"], True), (["other"], False), (None, False)):
        body: dict[str, Any] = {"status": "active"}
        if echo is not None:
            body["acknowledged_document_ids"] = echo
        commands = QueueTransport(response(body))
        agent, _ = configured_agent(QueueTransport(inspect_response(advertised())), commands)
        session = agent.service("api.example.com")
        if accepted:
            result = await session.enroll(EnrollOptions(acknowledged_document_ids=("terms",)))
            assert result.body.acknowledged_document_ids == ("terms",)
        else:
            with pytest.raises(AgentCommandError, match="acknowledgement"):
                await session.enroll(EnrollOptions(acknowledged_document_ids=("terms",)))
        assert len(commands.requests) == 1
        assert json.loads(commands.requests[0].body or b"{}")["acknowledged_document_ids"] == [
            "terms"
        ]
    commands = QueueTransport(response({"status": "active"}))
    agent, _ = configured_agent(QueueTransport(inspect_response()), commands)
    session = agent.service("api.example.com")
    with pytest.raises(ValueError, match="advertise"):
        await session.enroll(EnrollOptions(acknowledged_document_ids=()))
    assert not commands.requests
    assert (await session.enroll()).body.status is AgentStatus.ACTIVE


@pytest.mark.asyncio
async def test_agent_preserves_requirements_without_automatic_enroll_or_grant_retry() -> None:
    problem = {
        "type": "urn:aep:error:requirements_unmet",
        "code": "requirements_unmet",
        "title": "Accept terms",
        "status": 422,
        "requirements_pending": ["contact.email", "service_documents"],
        "required_document_ids": ["terms"],
    }
    commands = QueueTransport(
        response({"status": "active", "acknowledged_document_ids": ["terms"]}),
        response(problem, status=422, headers={"Content-Type": AEP_PROBLEM_MEDIA_TYPE}),
    )
    agent, _ = configured_agent(QueueTransport(inspect_response(advertised())), commands)
    session = agent.service("api.example.com")
    await session.enroll(EnrollOptions(acknowledged_document_ids=("terms",)))
    with pytest.raises(AgentCommandError) as error:
        await session.grant(GrantOptions(grant_type="api-key"))
    assert error.value.problem and error.value.problem.required_document_ids == ("terms",)
    assert len(commands.requests) == 2


@pytest.mark.asyncio
async def test_agent_and_service_document_reenrollment_through_asgi() -> None:
    key = Ed25519PrivateKey.generate()
    store = MemoryEnrollmentStore()
    handler = GrantHandler()
    handler.response = json.dumps(
        {
            "credential_id": "document-credential",
            "api_key": "secret",
            "header": "X-Key",
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        }
    ).encode()
    service = Service(
        ServiceOptions(
            service_did="did:web:service.example",
            identity_methods=("did:web",),
            clock=lambda: NOW,
            verifier=Verifier(key),
            enrollment_store=store,
            extensions=(AEP_SERVICE_DOCUMENTS_EXTENSION,),
            service_documents=(descriptor(), descriptor("privacy")),
            claims=InspectClaims(required=("contact.email",)),
            grant_types=(GrantTypeDefinition(grant_type="api-key", handler=handler),),
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=AepAsgiApplication(service))
    ) as client:
        transport = HttpxTransport(client)
        async with Agent(
            AgentOptions(
                identity_provider=LocalIdentityProvider(key),
                clock=lambda: NOW,
                command_transport=transport,
                inspect_transport=transport,
            )
        ) as agent:
            session = agent.service("https://service.example")
            inspection = await session.inspect()
            assert inspection.document.service_documents == (descriptor(), descriptor("privacy"))
            with pytest.raises(AgentCommandError) as unmet:
                await session.enroll()
            assert unmet.value.problem and unmet.value.problem.required_document_ids == (
                "terms",
                "privacy",
            )
            accepted = await session.enroll(
                EnrollOptions(
                    claims=ClaimValues.model_validate({"contact.email": "owner@example.com"}),
                    acknowledged_document_ids=("terms",),
                )
            )
            assert accepted.body.acknowledged_document_ids == ("terms",)
            original = await store.find(AGENT_DID)
            assert original
            with pytest.raises(AgentCommandError) as missing:
                await session.grant(GrantOptions(grant_type="api-key"))
            assert missing.value.problem and missing.value.problem.required_document_ids == (
                "privacy",
            )
            assert handler.grants == []
            accepted = await session.enroll(EnrollOptions(acknowledged_document_ids=("privacy",)))
            assert accepted.body.acknowledged_document_ids == ("privacy",)
            record = await store.find(AGENT_DID)
            assert record and record.enrollment_id == original.enrollment_id
            assert record.claims == original.claims
            assert record.acknowledged_document_ids == ("terms", "privacy")
            assert (await session.grant(GrantOptions(grant_type="api-key"))).status == 200
            assert len(handler.grants) == 1
