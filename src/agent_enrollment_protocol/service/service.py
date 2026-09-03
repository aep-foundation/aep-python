from __future__ import annotations

import hashlib
import json
import math
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, TypeGuard, TypeVar, cast
from urllib.parse import urlsplit

from pydantic import BaseModel

from agent_enrollment_protocol.core import (
    AEP_AUTHENTICATION_METHOD_JWT,
    AEP_PROBLEM_MEDIA_TYPE,
    AEP_VERSION,
    AgentStatus,
    AssertionOperation,
    AuthorizationCarrier,
    AuthorizationScheme,
    Bindings,
    ClientAssertionClaims,
    Command,
    Commands,
    CoreConfiguration,
    EnrollRequest,
    EnrollResponse,
    Extensions,
    GrantRequest,
    HttpConfiguration,
    Identity,
    InspectDocument,
    ProblemDetails,
    ProtectedResourceAuthorization,
    RevokeRequest,
    RevokeResponse,
    ServiceIdentity,
    SigningAlgorithm,
    StatusResponse,
    decode_jwt_unverified,
    normalize_endpoint_base,
    parse_authorization,
    parse_json_model,
    require_service_origin_binding,
)
from agent_enrollment_protocol.core.errors import (
    AepAssertionError,
    AepAuthorizationError,
    AepValidationError,
)

from .stores import (
    MemoryEnrollmentStore,
    MemoryIdempotencyStore,
    MemoryReplayStore,
    StaticEnrollmentPolicy,
)
from .types import (
    AssertionVerificationContext,
    AuthenticatedPrincipal,
    AuthenticationKind,
    ClaimValueLimits,
    CommandOptions,
    CredentialAuthenticationInput,
    CredentialAuthenticator,
    EnrollmentDecision,
    EnrollmentRecord,
    GrantContext,
    GrantTypeDefinition,
    IdempotencyInput,
    IdempotencyState,
    ProtectedResourceRequest,
    ProtectedResourceResult,
    ReplayRecord,
    RevokeContext,
    ServiceOptions,
    ServiceResult,
    StoredResponse,
)

ResponseT = TypeVar("ResponseT")


class Service:
    def __init__(self, options: ServiceOptions) -> None:
        if not options.service_did:
            raise ValueError("AEP Service DID is required")
        if not options.identity_methods or len(set(options.identity_methods)) != len(
            options.identity_methods
        ):
            raise ValueError("AEP Service requires at least one unique identity method")
        if len(set(options.signing_algorithms)) != len(options.signing_algorithms) or {
            "EdDSA",
            "ES256",
        } - {item.value for item in options.signing_algorithms}:
            raise ValueError("AEP Service signing algorithms must uniquely include EdDSA and ES256")
        self._clock = options.clock or (lambda: datetime.now(UTC))
        self._allow_insecure_loopback = options.allow_insecure_loopback
        self._clock_tolerance = _whole_seconds(options.clock_tolerance, 0, 30, "clock tolerance")
        self._maximum_assertion_lifetime = _whole_seconds(
            options.maximum_assertion_lifetime, 1, 300, "assertion lifetime"
        )
        self._claim_limits = options.claim_value_limits
        _validate_claim_limits(self._claim_limits)
        endpoint_base = normalize_endpoint_base(options.endpoint_base)
        self._inspect_url = (
            _absolute_url(options.inspect_url, options.allow_insecure_loopback)
            if options.inspect_url is not None
            else None
        )
        definitions = _grant_definitions(options.grant_types)
        self._grant_types = definitions
        self._authentication_methods = tuple(options.authentication_methods)
        if len(self._authentication_methods) > 16 or len(set(self._authentication_methods)) != len(
            self._authentication_methods
        ):
            raise ValueError(
                "AEP Service authentication methods must be unique and within the limit"
            )
        for method in self._authentication_methods:
            if method == AEP_AUTHENTICATION_METHOD_JWT:
                continue
            definition = definitions.get(method)
            if definition is None or definition.authenticator is None:
                raise ValueError(
                    f'AEP authentication method "{method}" requires a matching authenticator'
                )
        commands = [Command.ENROLL.value, Command.INSPECT.value, Command.STATUS.value]
        if definitions:
            commands[1:1] = [Command.GRANT.value]
            commands.insert(3, Command.REVOKE.value)
        grant_configs = {
            name: definition.config
            for name, definition in definitions.items()
            if definition.config.to_wire()
        }
        command_data: dict[str, Any] = {"supported": tuple(commands)}
        if definitions:
            command_data["grant_types"] = tuple(definitions)
        if grant_configs:
            command_data["grant_types_config"] = grant_configs
        http_data: dict[str, Any] = {"endpoint_base": endpoint_base}
        if options.openapi is not None:
            http_data["openapi"] = options.openapi
        document_data: dict[str, Any] = {
            "aep_version": AEP_VERSION,
            "bindings": Bindings(supported=("http",)),
            "commands": Commands.model_validate(command_data),
            "core": CoreConfiguration(
                signing_algorithms=tuple(item.value for item in options.signing_algorithms)
            ),
            "http": HttpConfiguration.model_validate(http_data),
            "identity": Identity(methods=options.identity_methods),
            "service": ServiceIdentity(did=options.service_did),
        }
        if options.claims is not None:
            document_data["claims"] = options.claims
        if options.extensions:
            document_data["extensions"] = Extensions(supported=options.extensions)
        if self._authentication_methods:
            document_data["authentication"] = {"methods": self._authentication_methods}
        self._document = InspectDocument.model_validate(document_data)
        if self._inspect_url is not None:
            require_service_origin_binding(
                self._document,
                self._inspect_url,
                allow_insecure_loopback=self._allow_insecure_loopback,
            )
        self._enrollment_policy = options.enrollment_policy or StaticEnrollmentPolicy()
        self._enrollment_store = options.enrollment_store or MemoryEnrollmentStore()
        self._idempotency_store = options.idempotency_store or MemoryIdempotencyStore(self._now)
        self._identifier = options.identifier or (lambda: secrets.token_hex(16))
        self._replay_store = options.replay_store or MemoryReplayStore()
        self._verifier = options.verifier

    @property
    def inspect_document(self) -> InspectDocument:
        return InspectDocument.model_validate_json(json.dumps(self._document.to_wire()))

    async def enroll(self, body: bytes, options: CommandOptions) -> ServiceResult[EnrollResponse]:
        claims = await self._authenticate_assertion(
            options, AssertionOperation.ENROLL, resource=None
        )
        if claims is None:
            return _problem("not_recognized", "Not recognized", 401)
        request = _parse(body, EnrollRequest)
        idempotency_key = options.idempotency_key
        if (
            request is None
            or request.agent_did != claims.sub
            or not _claims_within_limits(request.claims, self._claim_limits)
            or not _valid_idempotency_key(idempotency_key)
            or (request.idempotency_key is not None and request.idempotency_key != idempotency_key)
        ):
            return _problem("invalid_request", "Invalid request", 400)

        async def execute() -> ServiceResult[EnrollResponse]:
            required = self._document.claims.required if self._document.claims else ()
            missing = _missing_claims(required or (), request)
            if missing:
                return _problem(
                    "requirements_unmet",
                    "Requirements unmet",
                    422,
                    requirements_pending=missing,
                )

            async def create() -> EnrollmentRecord:
                now = self._now()
                decision = await self._enrollment_policy.decide(request, now)
                _validate_enrollment_decision(decision)
                identifier = self._identifier()
                if not identifier:
                    raise ValueError(
                        "AEP enrollment identifier provider returned an empty identifier"
                    )
                return EnrollmentRecord(
                    agent_did=claims.sub,
                    claims=request.claims,
                    created_at=now,
                    enrollment_id=identifier,
                    owner_action_required=decision.owner_action_required,
                    requirements_pending=tuple(decision.requirements_pending),
                    since=now,
                    status=AgentStatus(decision.status.value),
                    updated_at=now,
                    verification_pending=tuple(decision.verification_pending),
                )

            record, _ = await self._enrollment_store.find_or_create(claims.sub, create)
            return _enrollment_result(record)

        return await self._idempotent(
            claims.sub,
            Command.ENROLL.value,
            idempotency_key,
            request,
            _model_parser(EnrollResponse),
            execute,
        )

    async def status(self, options: CommandOptions) -> ServiceResult[StatusResponse]:
        claims = await self._authenticate_assertion(
            options, AssertionOperation.STATUS, resource=None
        )
        if claims is None:
            return _problem("not_recognized", "Not recognized", 401)
        record = await self._enrollment_store.find(claims.sub)
        if record is None:
            return _problem("not_recognized", "Not recognized", 401)
        _validate_enrollment_record(record)
        return ServiceResult(
            status=200,
            body=StatusResponse.model_validate(
                _lifecycle_data(record) | {"since": _rfc3339(record.since)}
            ),
        )

    async def grant(self, body: bytes, options: CommandOptions) -> ServiceResult[dict[str, Any]]:
        claims = await self._authenticate_assertion(
            options, AssertionOperation.GRANT, resource=None
        )
        if claims is None:
            return _problem("not_recognized", "Not recognized", 401)
        request = _parse(body, GrantRequest)
        idempotency_key = options.idempotency_key
        if request is None or not _valid_idempotency_key(idempotency_key):
            return _problem("invalid_request", "Invalid request", 400)

        async def execute() -> ServiceResult[dict[str, Any]]:
            record = await self._enrollment_store.find(claims.sub)
            if record is None:
                return _problem("not_recognized", "Not recognized", 401)
            _validate_enrollment_record(record)
            definition = self._grant_types.get(request.grant_type)
            if definition is None:
                return _problem("unsupported_grant_type", "Unsupported grant type", 400)
            if record.status is not AgentStatus.ACTIVE:
                return _grant_lifecycle_problem(record)
            raw = await definition.handler.grant(
                request,
                GrantContext(
                    agent_did=claims.sub,
                    current_time=self._now(),
                    enrollment=record,
                    grant_type=request.grant_type,
                ),
            )
            credential = _credential_object(raw)
            return ServiceResult(status=200, body=credential)

        return await self._idempotent(
            claims.sub,
            Command.GRANT.value,
            idempotency_key,
            request,
            _parse_object,
            execute,
        )

    async def revoke(self, body: bytes, options: CommandOptions) -> ServiceResult[RevokeResponse]:
        claims = await self._authenticate_assertion(
            options, AssertionOperation.REVOKE, resource=None
        )
        if claims is None:
            return _problem("not_recognized", "Not recognized", 401)
        request = _parse(body, RevokeRequest)
        idempotency_key = options.idempotency_key
        if request is None or not _valid_idempotency_key(idempotency_key):
            return _problem("invalid_request", "Invalid request", 400)

        async def execute() -> ServiceResult[RevokeResponse]:
            record = await self._enrollment_store.find(claims.sub)
            if record is None:
                return _problem("not_recognized", "Not recognized", 401)
            _validate_enrollment_record(record)
            if request.grant_type is not None:
                definition = self._grant_types.get(request.grant_type)
                if definition is None:
                    return _problem("unsupported_grant_type", "Unsupported grant type", 400)
                if (
                    request.credential_id is not None
                    and definition.config.supports_per_credential_revoke != "true"
                ):
                    return _problem("invalid_request", "Invalid request", 400)
            if request.all_grant_types == "true":
                grant_types = sorted(self._grant_types)
            else:
                grant_types = [request.grant_type] if request.grant_type is not None else []
            for grant_type in grant_types:
                definition = self._grant_types[grant_type]
                await definition.handler.revoke(
                    request,
                    RevokeContext(
                        agent_did=claims.sub,
                        current_time=self._now(),
                        enrollment=record,
                        grant_type=grant_type,
                    ),
                )
            return ServiceResult(status=200, body=RevokeResponse())

        return await self._idempotent(
            claims.sub,
            Command.REVOKE.value,
            idempotency_key,
            request,
            _model_parser(RevokeResponse),
            execute,
        )

    async def authenticate_protected_resource(
        self, request: ProtectedResourceRequest
    ) -> ProtectedResourceResult:
        resource = _absolute_url(request.url, self._allow_insecure_loopback)
        headers = _normalize_headers(request.headers)
        presentation, unambiguous = _select_presentation(headers)
        if not unambiguous:
            return self._protected_problem("not_recognized", resource)
        if presentation is not None and presentation.scheme is AuthorizationScheme.AEP:
            if AEP_AUTHENTICATION_METHOD_JWT not in self._authentication_methods:
                return self._protected_problem("unsupported_authentication_method", resource)
            claims = await self._authenticate_assertion(
                CommandOptions(client_assertion=presentation.credentials),
                AssertionOperation.AUTHENTICATE,
                resource=resource,
            )
            if claims is None or not await self._active(claims.sub):
                return self._protected_problem("not_recognized", resource)
            return ProtectedResourceResult(
                authenticated=True,
                principal=AuthenticatedPrincipal(
                    agent_did=claims.sub,
                    authentication_kind=AuthenticationKind.AEP_JWT,
                    authentication_method=AEP_AUTHENTICATION_METHOD_JWT,
                ),
            )
        authentication_input = CredentialAuthenticationInput(
            current_time=self._now(),
            headers=headers,
            method=request.method,
            url=resource,
        )
        presented = presentation is not None
        for method in self._authentication_methods:
            if method == AEP_AUTHENTICATION_METHOD_JWT:
                continue
            authenticator = cast(CredentialAuthenticator, self._grant_types[method].authenticator)
            presented = presented or await authenticator.has_presentation(authentication_input)
            principal = await authenticator.authenticate(authentication_input)
            if principal is None:
                continue
            if (
                principal.agent_did == ""
                or principal.authentication_kind is not AuthenticationKind.SESSION_CREDENTIAL
                or principal.authentication_method != method
                or principal.grant_type != method
            ):
                raise ValueError("AEP credential authenticator returned an invalid principal")
            if not await self._active(principal.agent_did):
                return self._protected_problem("not_recognized", resource)
            return ProtectedResourceResult(authenticated=True, principal=principal)
        return self._protected_problem(
            "not_recognized" if presented else "authentication_required", resource
        )

    async def _active(self, agent_did: str) -> bool:
        record = await self._enrollment_store.find(agent_did)
        if record is None:
            return False
        _validate_enrollment_record(record)
        return record.status is AgentStatus.ACTIVE

    async def _authenticate_assertion(
        self,
        options: CommandOptions,
        operation: AssertionOperation,
        resource: str | None,
    ) -> ClientAssertionClaims | None:
        if not options.client_assertion:
            return None
        now = self._now()
        context = AssertionVerificationContext(
            algorithms=tuple(
                SigningAlgorithm(value) for value in self._document.core.signing_algorithms
            ),
            allow_insecure_loopback=self._allow_insecure_loopback,
            clock_tolerance=timedelta(seconds=self._clock_tolerance),
            current_time=now,
            idempotency_key=options.idempotency_key,
            operation=operation,
            resource=resource,
            service_did=self._document.service.did,
        )
        try:
            claims = await self._verifier.verify(options.client_assertion, context)
            header, _ = decode_jwt_unverified(options.client_assertion)
        except (AepAssertionError, ValueError):
            return None
        if not self._valid_assertion(header, claims, operation, resource, now):
            return None
        consumed = await self._replay_store.consume(
            ReplayRecord(
                expires_at=claims.exp + self._clock_tolerance,
                jwt_id=claims.jti,
                subject=claims.sub,
            ),
            int(now.timestamp()),
        )
        return claims if consumed else None

    def _valid_assertion(
        self,
        header: Mapping[str, Any],
        claims: ClientAssertionClaims,
        operation: AssertionOperation,
        resource: str | None,
        now: datetime,
    ) -> bool:
        try:
            claims = ClientAssertionClaims.model_validate_json(
                json.dumps(claims.to_wire()),
                context={"allow_insecure_loopback": self._allow_insecure_loopback},
            )
        except ValueError:
            return False
        key_id = header.get("kid")
        algorithm = header.get("alg")
        if (
            header.get("typ") != "JWT"
            or not isinstance(key_id, str)
            or key_id.partition("#")[0] != claims.sub
            or algorithm not in self._document.core.signing_algorithms
            or claims.aud != self._document.service.did
            or claims.iss != claims.sub
            or claims.op is not operation
            or claims.resource != resource
            or _identity_method(claims.sub) not in self._document.identity.methods
        ):
            return False
        current = int(now.timestamp())
        return (
            claims.exp - claims.iat <= self._maximum_assertion_lifetime
            and claims.iat <= current + self._clock_tolerance
            and claims.exp > current - self._clock_tolerance
        )

    async def _idempotent(
        self,
        agent_did: str,
        command: str,
        key: str,
        request: object,
        response_parser: Callable[[bytes], ResponseT],
        operation: Callable[[], Awaitable[ServiceResult[ResponseT]]],
    ) -> ServiceResult[ResponseT]:
        canonical = json.dumps(
            request.to_wire() if hasattr(request, "to_wire") else request,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

        async def store() -> StoredResponse:
            result = await operation()
            value: object = result.problem.to_wire() if result.problem is not None else result.body
            if isinstance(value, BaseModel):
                value = value.model_dump(by_alias=True, exclude_none=True, mode="json")
            return StoredResponse(
                body=json.dumps(value, separators=(",", ":")).encode(),
                content_type=result.content_type,
                created_at=self._now(),
                headers=result.headers,
                status=result.status,
            )

        result = await self._idempotency_store.execute(
            IdempotencyInput(
                agent_did=agent_did,
                command=command,
                idempotency_key=key,
                request_hash=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
            ),
            store,
        )
        if result.state is IdempotencyState.CONFLICT:
            return _problem("idempotency_conflict", "Idempotency conflict", 409)
        if result.response is None:
            raise ValueError("AEP idempotency store omitted its stored response")
        stored = result.response
        if stored.content_type == AEP_PROBLEM_MEDIA_TYPE:
            problem = parse_json_model(stored.body, ProblemDetails, "Problem response")
            return ServiceResult(
                status=stored.status,
                content_type=stored.content_type,
                headers=stored.headers,
                problem=problem,
            )
        body = response_parser(stored.body)
        return ServiceResult(
            status=stored.status,
            body=body,
            content_type=stored.content_type,
            headers=stored.headers,
        )

    def _protected_problem(self, code: str, resource: str) -> ProtectedResourceResult:
        inspect = self._inspect_url or _origin(resource) + "/.well-known/aep"
        result: ServiceResult[object] = _problem(code, _title(code), 401)
        return ProtectedResourceResult(
            authenticated=False,
            response=replace(
                result,
                headers={
                    "WWW-Authenticate": (
                        f'AEP service_did="{self._document.service.did}",'
                        f'inspect="{inspect}",reason="{code}"'
                    )
                },
            ),
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.utcoffset() is None:
            raise ValueError("AEP Service clock must return an offset-aware datetime")
        return value


ModelT = TypeVar("ModelT", bound=BaseModel)


def _parse(body: bytes, model: type[ModelT]) -> ModelT | None:
    try:
        return parse_json_model(body, model, "AEP request")
    except AepValidationError:
        return None


def _model_parser(model: type[ModelT]) -> Callable[[bytes], ModelT]:
    return lambda body: parse_json_model(body, model, "response")


def _parse_object(body: bytes) -> dict[str, Any]:
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("AEP Grant response must be a JSON object")
    return cast(dict[str, Any], value)


def _problem(
    code: str,
    title: str,
    status: int,
    *,
    requirements_pending: Sequence[str] = (),
    verification_pending: Sequence[str] = (),
    owner_action_required: bool = False,
) -> ServiceResult[Any]:
    data: dict[str, Any] = {
        "type": f"urn:aep:error:{code}",
        "title": title,
        "status": status,
        "code": code,
    }
    if requirements_pending:
        data["requirements_pending"] = tuple(requirements_pending)
    if verification_pending:
        data["verification_pending"] = tuple(verification_pending)
    if owner_action_required:
        data["owner_action_required"] = "true"
    problem = ProblemDetails.model_validate(data)
    headers = {"WWW-Authenticate": f'AEP reason="{code}"'} if status == 401 else {}
    return ServiceResult(
        status=status,
        content_type=AEP_PROBLEM_MEDIA_TYPE,
        headers=headers,
        problem=problem,
    )


def _enrollment_result(record: EnrollmentRecord) -> ServiceResult[EnrollResponse]:
    _validate_enrollment_record(record)
    if record.status in {AgentStatus.ACTIVE, AgentStatus.PENDING, AgentStatus.REJECTED}:
        return ServiceResult(
            status=200,
            body=EnrollResponse.model_validate(_lifecycle_data(record)),
        )
    code = {
        AgentStatus.SUSPENDED: "identity_suspended",
        AgentStatus.TERMINATED: "identity_terminated",
        AgentStatus.UNAVAILABLE: "identity_unavailable",
    }.get(record.status, "enrollment_failed")
    return _problem(
        code,
        _title(code),
        403 if code.startswith("identity_") else 400,
        owner_action_required=record.owner_action_required,
        requirements_pending=record.requirements_pending,
        verification_pending=record.verification_pending,
    )


def _grant_lifecycle_problem(record: EnrollmentRecord) -> ServiceResult[Any]:
    code = {
        AgentStatus.PENDING: "verification_pending",
        AgentStatus.SUSPENDED: "identity_suspended",
        AgentStatus.TERMINATED: "identity_terminated",
        AgentStatus.UNAVAILABLE: "identity_unavailable",
    }.get(record.status, "enrollment_failed")
    return _problem(
        code,
        _title(code),
        403 if code != "enrollment_failed" else 400,
        owner_action_required=record.owner_action_required,
        requirements_pending=record.requirements_pending,
        verification_pending=record.verification_pending,
    )


def _grant_definitions(
    definitions: Sequence[GrantTypeDefinition],
) -> dict[str, GrantTypeDefinition]:
    result: dict[str, GrantTypeDefinition] = {}
    for definition in definitions:
        if not definition.grant_type or definition.grant_type in result:
            raise ValueError("AEP Grant Type definitions require a unique identifier")
        result[definition.grant_type] = definition
    return result


def _valid_idempotency_key(value: str | None) -> TypeGuard[str]:
    return value is not None and bool(value.strip())


def _missing_claims(required: Sequence[str], request: EnrollRequest) -> tuple[str, ...]:
    claims = request.claims.to_wire() if request.claims is not None else {}
    return tuple(name for name in required if name not in claims)


def _claims_within_limits(claims: object, limits: ClaimValueLimits) -> bool:
    if claims is None:
        return True
    value = claims.to_wire() if hasattr(claims, "to_wire") else claims
    encoded = json.dumps(value, separators=(",", ":")).encode()
    return len(encoded) <= limits.maximum_encoded_bytes and _within_structure(
        value, limits, depth=1, members=[0]
    )


def _within_structure(
    value: object, limits: ClaimValueLimits, depth: int, members: list[int]
) -> bool:
    if isinstance(value, str):
        return len(value) <= limits.maximum_string_length
    if isinstance(value, Mapping):
        if depth > limits.maximum_object_depth:
            return False
        for key, member in value.items():
            members[0] += 1
            if (
                members[0] > limits.maximum_member_count
                or not isinstance(key, str)
                or len(key) > limits.maximum_string_length
                or not _within_structure(member, limits, depth + 1, members)
            ):
                return False
        return True
    if isinstance(value, (list, tuple)):
        return depth <= limits.maximum_object_depth and all(
            _within_structure(member, limits, depth + 1, members) for member in value
        )
    return value is None or isinstance(value, (bool, int, float))


def _credential_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("AEP Grant response must be a JSON object") from error
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("credential_id"), str)
        or not value["credential_id"]
    ):
        raise ValueError("AEP Grant response requires a stable credential_id")
    return value


def _normalize_headers(source: Mapping[str, str | Sequence[str]]) -> Mapping[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for name, raw in source.items():
        values = (raw,) if isinstance(raw, str) else tuple(raw)
        key = name.lower()
        result[key] = result.get(key, ()) + values
    return MappingProxyType(result)


def _select_presentation(
    headers: Mapping[str, tuple[str, ...]],
) -> tuple[ProtectedResourceAuthorization | None, bool]:
    dedicated = headers.get("aep-authorization", ())
    standard = headers.get("authorization", ())
    if dedicated:
        if len(dedicated) != 1:
            return None, False
        try:
            selected = parse_authorization(dedicated[0], AuthorizationCarrier.DEDICATED)
        except AepAuthorizationError:
            return None, False
        if any(_recognized(value) for value in standard):
            return None, False
        return selected, True
    recognized = [value for value in standard if _recognized(value)]
    if len(recognized) > 1 or (recognized and len(standard) > 1):
        return None, False
    if not recognized:
        return None, True
    return parse_authorization(recognized[0]), True


def _recognized(value: str) -> bool:
    try:
        parse_authorization(value)
        return True
    except AepAuthorizationError:
        return False


def _absolute_url(value: str | None, allow_insecure_loopback: bool) -> str:
    if value is None:
        raise ValueError("AEP URL is required")
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (
            parsed.scheme != "https"
            and not (allow_insecure_loopback and loopback and parsed.scheme == "http")
        )
    ):
        raise ValueError("AEP URL must be absolute HTTPS without credentials or a fragment")
    return value


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    hostname = (
        f"[{parsed.hostname}]" if parsed.hostname and ":" in parsed.hostname else parsed.hostname
    )
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{hostname}{port}"


def _identity_method(value: str) -> str:
    parts = value.split(":", 2)
    return f"did:{parts[1]}" if len(parts) == 3 and parts[0] == "did" and parts[1] else ""


def _whole_seconds(value: timedelta, minimum: int, maximum: int, name: str) -> int:
    seconds = value.total_seconds()
    if not math.isfinite(seconds) or not seconds.is_integer() or not minimum <= seconds <= maximum:
        raise ValueError(
            f"AEP Service {name} must be whole seconds from {minimum} through {maximum}"
        )
    return int(seconds)


def _validate_claim_limits(limits: ClaimValueLimits) -> None:
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 1
        for value in (
            limits.maximum_encoded_bytes,
            limits.maximum_member_count,
            limits.maximum_object_depth,
            limits.maximum_string_length,
        )
    ):
        raise ValueError("AEP Service claim limits must be positive integers")


def _validate_enrollment_decision(decision: EnrollmentDecision) -> None:
    data: dict[str, Any] = {"status": AgentStatus(decision.status.value)}
    if decision.owner_action_required:
        data["owner_action_required"] = "true"
    if decision.requirements_pending:
        data["requirements_pending"] = decision.requirements_pending
    if decision.verification_pending:
        data["verification_pending"] = decision.verification_pending
    EnrollResponse.model_validate(data)


def _lifecycle_data(record: EnrollmentRecord) -> dict[str, Any]:
    data: dict[str, Any] = {"status": record.status}
    if record.owner_action_required:
        data["owner_action_required"] = "true"
    if record.requirements_pending:
        data["requirements_pending"] = record.requirements_pending
    if record.verification_pending:
        data["verification_pending"] = record.verification_pending
    return data


def _validate_enrollment_record(record: EnrollmentRecord) -> None:
    replace(record)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _title(code: str) -> str:
    return code.replace("_", " ").capitalize()
