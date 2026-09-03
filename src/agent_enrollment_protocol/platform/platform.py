from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar, cast

from pydantic import BaseModel

from agent_enrollment_protocol.core import (
    AEP_MEDIA_TYPE,
    AEP_PROBLEM_MEDIA_TYPE,
    MAX_ASSERTION_LIFETIME_SECONDS,
    ClientAssertionClaims,
    ManagedAgentStatus,
    PlatformAgentIdentity,
    PlatformAgentIdentityListResponse,
    PlatformDiscoveryDocument,
    PlatformLifecycleRequest,
    PlatformProvisionRequest,
    PlatformSignCompleted,
    PlatformSignPending,
    PlatformSignRequest,
    PlatformSignResponse,
    PlatformVerificationRequest,
    PlatformVerificationResponse,
    ProblemDetails,
    SigningAlgorithm,
    VerifyClientAssertionOptions,
    decode_jwt_unverified,
    verify_client_assertion,
)
from agent_enrollment_protocol.core.errors import AepAssertionError

from .document import (
    DID_MEDIA_TYPE,
    create_did_document,
    create_discovery_document,
    create_service_scoped_agent_did,
    render_did_url,
)
from .stores import (
    DefaultLifecyclePolicy,
    MemoryIdentityStore,
    MemoryPlatformIdempotencyStore,
    validate_identity_record,
)
from .types import (
    AuthorizationOperation,
    AuthorizationRequest,
    IdempotentOperation,
    IdentityListQuery,
    IdentityRecord,
    KeyStore,
    PlatformIdempotencyInput,
    PlatformIdempotencyState,
    PlatformOptions,
    PlatformResult,
    ReplayStore,
    RequestContext,
    SignHandlerInput,
    StoredResponse,
    identity_response,
    list_response,
)

BodyT = TypeVar("BodyT")
ModelT = TypeVar("ModelT", bound=BaseModel)


class Platform:
    def __init__(self, options: PlatformOptions) -> None:
        if (
            options.authorizer is None
            or options.key_store is None
            or options.service_did_resolver is None
        ):
            raise ValueError(
                "AEP Platform authorizer, key store, and Service DID resolver are required"
            )
        if not options.signing_algorithms or len(set(options.signing_algorithms)) != len(
            options.signing_algorithms
        ):
            raise ValueError("AEP Platform requires unique signing algorithms")
        if any(
            algorithm not in (SigningAlgorithm.EDDSA, SigningAlgorithm.ES256)
            for algorithm in options.signing_algorithms
        ):
            raise ValueError("AEP Platform signing algorithm is not supported")
        maximum = _seconds(options.maximum_lifetime, "maximum assertion lifetime")
        default = _seconds(options.default_lifetime, "default assertion lifetime")
        if maximum > MAX_ASSERTION_LIFETIME_SECONDS or default > maximum:
            raise ValueError("AEP Platform assertion lifetime exceeds the configured maximum")
        if options.hosted_verification and options.replay_store is None:
            raise ValueError("AEP Platform hosted verification requires a replay store")
        create_service_scoped_agent_did(options.did_host, options.did_path_prefix, "validation")
        self._discovery = create_discovery_document(
            options.discovery,
            did_url_template=options.did_url_template,
            hosted_verification=options.hosted_verification,
            signing_algorithms=options.signing_algorithms,
            default_lifetime_seconds=default,
        )
        self._agent_did_id_generator = options.agent_did_id_generator or _identifier
        self._authorizer = options.authorizer
        self._clock = options.clock or (lambda: datetime.now(UTC))
        self._default_lifetime = default
        self._did_host = options.did_host
        self._did_path_prefix = options.did_path_prefix
        self._did_url_template = options.did_url_template
        self._hosted_verification = options.hosted_verification
        self._identifier = options.identifier or _identifier
        self._identity_store = options.identity_store or MemoryIdentityStore()
        self._idempotency_store = options.idempotency_store or MemoryPlatformIdempotencyStore(
            self._clock
        )
        self._key_store = options.key_store
        self._lifecycle_policy = options.lifecycle_policy or DefaultLifecyclePolicy()
        self._maximum_lifetime = maximum
        self._replay_store = options.replay_store
        self._service_did_resolver = options.service_did_resolver
        self._sign_handler = options.sign_handler
        self._signing_algorithms = options.signing_algorithms

    def discovery(self) -> PlatformResult[PlatformDiscoveryDocument]:
        return _success(200, self._discovery, {"Cache-Control": "max-age=300"})

    async def did_document(self, agent_did_id: str) -> PlatformResult[dict[str, Any]]:
        identity = await self._identity_store.find_by_agent_did_id(agent_did_id)
        if identity is None or identity.status is not ManagedAgentStatus.ACTIVE:
            return _problem(404, "not_recognized", "Identity not recognized")
        validate_identity_record(identity)
        if identity.agent_did_id != agent_did_id:
            raise ValueError("AEP Platform identity store returned a mismatched record")
        method = await self._key_store.did_verification_method(identity)
        return PlatformResult(
            status=200,
            body=create_did_document(identity, method),
            content_type=DID_MEDIA_TYPE,
            headers={"Cache-Control": "max-age=300"},
        )

    async def get_identity(
        self, agent_identity_id: str, context: RequestContext
    ) -> PlatformResult[PlatformAgentIdentity]:
        identity = await self._authorized_identity(
            agent_identity_id,
            AuthorizationRequest(operation=AuthorizationOperation.GET_IDENTITY),
            context,
        )
        if identity is None:
            return _problem(404, "not_recognized", "Identity not recognized")
        return _success(200, identity_response(identity))

    async def list(
        self, query: IdentityListQuery, context: RequestContext
    ) -> PlatformResult[PlatformAgentIdentityListResponse]:
        if (
            query.limit < 0
            or query.limit > 100
            or query.offset < 0
            or (query.service_did is not None and not _is_did(query.service_did))
        ):
            return _problem(400, "invalid_request", "Identity list query is invalid")
        effective = query if query.limit else replace(query, limit=100)
        authorized = await self._authorizer.authorize(
            AuthorizationRequest(
                operation=AuthorizationOperation.LIST_IDENTITIES, list_query=effective
            ),
            context,
        )
        if not authorized or not context.principal:
            return _problem(404, "not_recognized", "Identity not recognized")
        listed = await self._identity_store.list(context.principal, effective)
        if any(
            not _valid_listed_identity(identity, context.principal, effective)
            for identity in listed.identities
        ):
            raise ValueError("AEP Platform identity store returned an unauthorized record")
        identifiers = [identity.agent_identity_id for identity in listed.identities]
        if listed.total < len(identifiers) or len(set(identifiers)) != len(identifiers):
            raise ValueError("AEP Platform identity store returned an invalid list result")
        return _success(200, list_response(listed))

    async def provision(
        self, request: PlatformProvisionRequest, context: RequestContext
    ) -> PlatformResult[PlatformAgentIdentity]:
        return await self._idempotent(
            IdempotentOperation.PROVISION,
            request,
            context,
            PlatformAgentIdentity,
            lambda: self._provision(request, context),
        )

    async def _provision(
        self, request: PlatformProvisionRequest, context: RequestContext
    ) -> PlatformResult[PlatformAgentIdentity]:
        authorized = await self._authorizer.authorize(
            AuthorizationRequest(
                operation=AuthorizationOperation.PROVISION, provision_request=request
            ),
            context,
        )
        if not authorized:
            return _problem(404, "not_recognized", "Identity not recognized")
        if not await self._service_did_resolver.resolve(request.service_did):
            return _problem(400, "invalid_request", "Service DID could not be resolved")
        identity, _ = await self._identity_store.find_or_create(
            context.principal,
            request.service_did,
            lambda: self._create_identity(context.principal, request.service_did),
        )
        validate_identity_record(identity)
        if identity.principal != context.principal or identity.service_did != request.service_did:
            raise ValueError("AEP Platform identity store returned a mismatched record")
        return _success(200, identity_response(identity))

    async def sign(
        self,
        agent_identity_id: str,
        request: PlatformSignRequest,
        context: RequestContext,
    ) -> PlatformResult[PlatformSignResponse]:
        lifetime = self._sign_lifetime(request)
        material = {"agent_identity_id": agent_identity_id, "request": request.to_wire()}
        return await self._idempotent(
            IdempotentOperation.SIGN,
            material,
            context,
            PlatformSignCompleted | PlatformSignPending,
            lambda: self._sign(agent_identity_id, request, context, lifetime),
        )

    async def _sign(
        self,
        agent_identity_id: str,
        request: PlatformSignRequest,
        context: RequestContext,
        lifetime: int,
    ) -> PlatformResult[PlatformSignResponse]:
        identity = await self._authorized_identity(
            agent_identity_id,
            AuthorizationRequest(
                operation=AuthorizationOperation.SIGN,
                sign_request=_clone_model(request),
            ),
            context,
        )
        if identity is None or identity.service_did != request.service_did:
            return _problem(404, "not_recognized", "Identity not recognized")
        if (
            identity.status is not ManagedAgentStatus.ACTIVE
            or not await self._lifecycle_policy.can_sign(identity, context)
        ):
            return _problem(403, _lifecycle_error(identity.status), "Identity cannot sign")
        if self._sign_handler is not None:
            handled = await self._sign_handler(
                SignHandlerInput(identity, _clone_model(request)), context
            )
            if handled is not None:
                await _validate_sign_result(handled, identity, request, lifetime, self._key_store)
                return handled
        now = _aware(self._request_time(context))
        claim_data: dict[str, Any] = {
            "aud": request.service_did,
            "exp": int(now.timestamp()) + lifetime,
            "iat": int(now.timestamp()),
            "iss": identity.agent_did,
            "jti": request.jti,
            "op": request.op,
            "sub": identity.agent_did,
        }
        if request.resource is not None:
            claim_data["resource"] = request.resource
        claims = ClientAssertionClaims.model_validate(claim_data)
        assertion = await self._key_store.sign(identity, claims)
        response_data: dict[str, Any] = {
            "agent_did": identity.agent_did,
            "client_assertion": assertion,
            "expires_at": _rfc3339(now + timedelta(seconds=lifetime)),
            "issued_at": _rfc3339(now),
            "jti": request.jti,
            "service_did": request.service_did,
            "status": "completed",
        }
        if request.platform_context is not None:
            response_data["platform_context"] = request.platform_context
        body = PlatformSignCompleted.model_validate(response_data)
        await _validate_sign_result(
            _success(200, body), identity, request, lifetime, self._key_store
        )
        return _success(200, body)

    async def update_identity(
        self,
        agent_identity_id: str,
        request: PlatformLifecycleRequest,
        context: RequestContext,
    ) -> PlatformResult[PlatformAgentIdentity]:
        identity = await self._authorized_identity(
            agent_identity_id,
            AuthorizationRequest(
                operation=AuthorizationOperation.UPDATE_IDENTITY,
                lifecycle_request=request,
            ),
            context,
        )
        if identity is None:
            return _problem(404, "not_recognized", "Identity not recognized")
        if not await self._lifecycle_policy.can_transition(identity, request.status, context):
            return _problem(403, _lifecycle_error(identity.status), "Lifecycle transition rejected")
        updated = await self._identity_store.update_status(
            agent_identity_id, request.status, _aware(self._clock())
        )
        if updated is None:
            return _problem(404, "not_recognized", "Identity not recognized")
        validate_identity_record(updated)
        if not _is_lifecycle_update(identity, updated, request.status):
            raise ValueError("AEP Platform identity store returned a mismatched record")
        return _success(200, identity_response(updated))

    async def verify(
        self, request: PlatformVerificationRequest, context: RequestContext
    ) -> PlatformResult[PlatformVerificationResponse]:
        if not self._hosted_verification:
            return _problem(404, "not_recognized", "Hosted verification is not available")
        return await self._idempotent(
            IdempotentOperation.HOSTED_VERIFICATION,
            request,
            context,
            PlatformVerificationResponse,
            lambda: self._verify(request, context),
        )

    async def _verify(
        self, request: PlatformVerificationRequest, context: RequestContext
    ) -> PlatformResult[PlatformVerificationResponse]:
        unrecognized = _success(
            200,
            PlatformVerificationResponse(
                reason="not_recognized", service_did=request.service_did, verified=False
            ),
        )
        try:
            header, payload = decode_jwt_unverified(request.client_assertion)
        except AepAssertionError:
            return unrecognized
        agent_did = payload.get("iss")
        if (
            not isinstance(agent_did, str)
            or payload.get("sub") != agent_did
            or header.get("kid") != agent_did
        ):
            return unrecognized
        identity = await self._identity_store.find_by_agent_did(agent_did)
        if identity is not None:
            validate_identity_record(identity)
            if identity.agent_did != agent_did:
                raise ValueError("AEP Platform identity store returned a mismatched record")
        if (
            identity is None
            or identity.service_did != request.service_did
            or identity.principal != context.principal
        ):
            return unrecognized
        authorized = await self._authorizer.authorize(
            AuthorizationRequest(
                operation=AuthorizationOperation.VERIFY,
                identity=identity,
                verification_request=request,
            ),
            context,
        )
        if (
            not authorized
            or identity.status is not ManagedAgentStatus.ACTIVE
            or not await self._lifecycle_policy.can_verify(identity, context)
        ):
            return unrecognized
        try:
            claims = verify_client_assertion(
                request.client_assertion,
                key=await self._key_store.verification_key(identity),
                options=VerifyClientAssertionOptions(
                    algorithms=identity.signing_algorithms,
                    audience=request.service_did,
                    current_time=int(_aware(self._request_time(context)).timestamp()),
                    issuer=identity.agent_did,
                    operation=request.op,
                    resource=request.resource,
                    subject=identity.agent_did,
                ),
            )
        except AepAssertionError:
            return unrecognized
        replay_store = cast(ReplayStore, self._replay_store)
        replay_key = "\0".join(
            (request.service_did, request.op.value, identity.agent_did, claims.jti)
        )
        if not await replay_store.consume(
            replay_key,
            datetime.fromtimestamp(claims.exp, UTC),
            _aware(self._request_time(context)),
        ):
            return unrecognized
        return _success(
            200,
            PlatformVerificationResponse(
                agent_did=identity.agent_did,
                agent_identity_id=identity.agent_identity_id,
                op=request.op,
                reason="verified",
                service_did=request.service_did,
                status=identity.status,
                verified=True,
            ),
        )

    async def _create_identity(self, principal: str, service_did: str) -> IdentityRecord:
        agent_identity_id = self._identifier()
        agent_did_id = self._agent_did_id_generator()
        if not agent_identity_id or not agent_did_id:
            raise ValueError("AEP Platform identity generator returned an empty identifier")
        if not agent_identity_id.startswith("pai_"):
            agent_identity_id = f"pai_{agent_identity_id}"
        now = _aware(self._clock())
        agent_did = create_service_scoped_agent_did(
            self._did_host, self._did_path_prefix, agent_did_id
        )
        identity = IdentityRecord(
            agent_did=agent_did,
            agent_did_id=agent_did_id,
            agent_identity_id=agent_identity_id,
            created_at=now,
            did_document_url=render_did_url(self._did_url_template, agent_did_id),
            key_id=agent_did,
            principal=principal,
            service_did=service_did,
            signing_algorithms=self._signing_algorithms,
            status=ManagedAgentStatus.ACTIVE,
            updated_at=now,
        )
        await self._key_store.create_key(identity)
        return identity

    async def _authorized_identity(
        self,
        agent_identity_id: str,
        request: AuthorizationRequest,
        context: RequestContext,
    ) -> IdentityRecord | None:
        identity = await self._identity_store.get(agent_identity_id)
        if identity is None:
            return None
        validate_identity_record(identity)
        if identity.agent_identity_id != agent_identity_id:
            raise ValueError("AEP Platform identity store returned a mismatched record")
        request = replace(request, identity=identity)
        if (
            not context.principal
            or identity.principal != context.principal
            or not await self._authorizer.authorize(request, context)
        ):
            return None
        return identity

    def _sign_lifetime(self, request: PlatformSignRequest) -> int:
        lifetime = (
            self._default_lifetime
            if request.lifetime_seconds is None
            else int(request.lifetime_seconds)
        )
        if lifetime > self._maximum_lifetime:
            raise ValueError("lifetime_seconds exceeds the configured maximum")
        return lifetime

    def _request_time(self, context: RequestContext) -> datetime:
        return context.current_time or self._clock()

    async def _idempotent(
        self,
        operation: IdempotentOperation,
        material: BaseModel | dict[str, Any],
        context: RequestContext,
        model: Any,
        execute: Callable[[], Awaitable[PlatformResult[BodyT]]],
    ) -> PlatformResult[BodyT]:
        if not context.principal or not context.idempotency_key:
            return _problem(
                400,
                "invalid_request",
                "Idempotency-Key and authenticated principal are required",
            )
        wire = (
            material.model_dump(by_alias=True, exclude_unset=True, mode="json")
            if isinstance(material, BaseModel)
            else material
        )
        encoded = json.dumps(wire, sort_keys=True, separators=(",", ":")).encode()
        result = await self._idempotency_store.execute(
            PlatformIdempotencyInput(
                idempotency_key=context.idempotency_key,
                operation=operation,
                principal=context.principal,
                request_hash=hashlib.sha256(encoded).hexdigest(),
            ),
            lambda: _store_result(execute, self._clock),
        )
        if result.state is PlatformIdempotencyState.CONFLICT:
            return _problem(409, "idempotency_conflict", "Idempotency conflict")
        if result.response is None:
            raise ValueError("AEP Platform idempotency store returned no response")
        return _restore_result(result.response, model)


async def _store_result(
    execute: Callable[[], Awaitable[PlatformResult[Any]]], clock: Callable[[], datetime]
) -> StoredResponse:
    result = await execute()
    value: Any = result.problem if result.problem is not None else result.body
    body = (
        value.model_dump(by_alias=True, exclude_unset=True, mode="json")
        if isinstance(value, BaseModel)
        else value
    )
    return StoredResponse(
        status=result.status,
        content_type=result.content_type,
        body=json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
        created_at=_aware(clock()),
        headers=result.headers,
    )


def _restore_result(stored: StoredResponse, model: Any) -> PlatformResult[BodyT]:
    if stored.content_type == AEP_PROBLEM_MEDIA_TYPE:
        body: BodyT | None = None
        problem = ProblemDetails.model_validate_json(stored.body)
    else:
        from pydantic import TypeAdapter

        # TypeAdapter validates the dynamic union or model before this generic boundary.
        body = cast(BodyT, TypeAdapter(model).validate_json(stored.body))
        problem = None
    return PlatformResult(
        stored.status,
        body,
        stored.content_type,
        stored.headers,
        problem,
    )


def _success(
    status: int, body: BodyT, headers: dict[str, str] | None = None
) -> PlatformResult[BodyT]:
    return PlatformResult(status, body, AEP_MEDIA_TYPE, headers or {})


def _problem(status: int, code: str, title: str) -> PlatformResult[BodyT]:
    return PlatformResult(
        status=status,
        content_type=AEP_PROBLEM_MEDIA_TYPE,
        problem=ProblemDetails(type=f"urn:aep:error:{code}", title=title, status=status, code=code),
    )


async def _validate_sign_result(
    result: PlatformResult[PlatformSignResponse],
    identity: IdentityRecord,
    request: PlatformSignRequest,
    requested_lifetime: int,
    key_store: KeyStore,
) -> None:
    body = result.body
    if isinstance(body, PlatformSignPending):
        if result.status != 202:
            raise ValueError("AEP Platform pending signing response must use 202")
        return
    if not isinstance(body, PlatformSignCompleted) or result.status != 200:
        raise ValueError("AEP Platform signing handler returned an invalid response")
    issued = datetime.fromisoformat(body.issued_at.replace("Z", "+00:00"))
    expires = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
    if (
        body.agent_did != identity.agent_did
        or body.service_did != request.service_did
        or body.jti != request.jti
        or expires - issued != timedelta(seconds=requested_lifetime)
    ):
        raise ValueError("AEP Platform signing handler response does not match the request")
    try:
        header, _ = decode_jwt_unverified(body.client_assertion)
        claims = verify_client_assertion(
            body.client_assertion,
            key=await key_store.verification_key(identity),
            options=VerifyClientAssertionOptions(
                algorithms=identity.signing_algorithms,
                audience=request.service_did,
                current_time=int(issued.timestamp()),
                issuer=identity.agent_did,
                operation=request.op,
                resource=request.resource,
                subject=identity.agent_did,
            ),
        )
    except AepAssertionError as error:
        raise ValueError("AEP Platform signer returned an invalid client assertion") from error
    if (
        header.get("kid") != identity.key_id
        or claims.iat != int(issued.timestamp())
        or claims.exp != int(expires.timestamp())
        or claims.jti != request.jti
    ):
        raise ValueError("AEP Platform signer returned mismatched assertion claims")


def _valid_listed_identity(
    identity: IdentityRecord, principal: str, query: IdentityListQuery
) -> bool:
    try:
        validate_identity_record(identity)
    except ValueError:
        return False
    return (
        identity.principal == principal
        and (query.service_did is None or identity.service_did == query.service_did)
        and (query.status is None or identity.status is query.status)
    )


def _is_lifecycle_update(
    before: IdentityRecord, after: IdentityRecord, status: ManagedAgentStatus
) -> bool:
    return after == replace(before, status=status, updated_at=after.updated_at)


def _seconds(value: timedelta, name: str) -> int:
    seconds = value.total_seconds()
    if seconds <= 0 or not seconds.is_integer():
        raise ValueError(f"AEP Platform {name} must be a positive whole number of seconds")
    return int(seconds)


def _aware(value: datetime) -> datetime:
    if value.utcoffset() is None:
        raise ValueError("AEP Platform clock must return an offset-aware datetime")
    return value


def _identifier() -> str:
    return secrets.token_hex(16)


def _is_did(value: str) -> bool:
    prefix, separator, identifier = value.partition(":")
    return prefix == "did" and bool(
        separator and identifier and not any(c.isspace() for c in value)
    )


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _lifecycle_error(status: ManagedAgentStatus) -> str:
    return f"identity_{status.value}"


def _clone_model(value: ModelT) -> ModelT:
    return type(value).model_validate_json(value.model_dump_json(by_alias=True, exclude_unset=True))
