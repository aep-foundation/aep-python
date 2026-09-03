from __future__ import annotations

import asyncio
import json
import math
import secrets
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TypeVar
from urllib.parse import urljoin, urlsplit, urlunsplit

from agent_enrollment_protocol.core import (
    AEP_AUTHENTICATION_METHOD_JWT,
    AEP_MEDIA_TYPE,
    AEP_PROBLEM_MEDIA_TYPE,
    AEP_WELL_KNOWN_PATH,
    AepValidationError,
    AgentStatus,
    ApiKeyGrantResponse,
    AssertionOperation,
    AuthorizationCarrier,
    AuthorizationScheme,
    BasicGrantResponse,
    ClientAssertionClaims,
    Command,
    EnrollRequest,
    EnrollResponse,
    GrantRequest,
    HttpRequest,
    InspectDocument,
    OAuthBearerGrantResponse,
    ProblemDetails,
    ProtectedResourceAuthorization,
    RevokeRequest,
    RevokeResponse,
    SigningAlgorithm,
    StatusResponse,
    command_path_from_inspect,
    did_web_document_url,
    media_type_essence,
    parse_json_model,
    render_authorization,
    require_service_origin_binding,
    same_origin,
)

from .stores import (
    MemoryCredentialStore,
    MemoryIdentityStore,
    MemoryInspectCache,
    RandomIdempotencyKeyProvider,
)
from .transport import AsyncHttpTransport, HttpxTransport
from .types import (
    AgentCommandError,
    AssertionSigner,
    AuthenticationOptions,
    BuiltInCredential,
    ClaimRequirementsError,
    CommandResult,
    CredentialRecord,
    CredentialStore,
    EnrollmentStateError,
    EnrollOptions,
    GrantOptions,
    GrantResult,
    IdempotencyKeyProvider,
    IdentityProvider,
    IdentityRequest,
    IdentityStore,
    InspectCache,
    InspectCacheEntry,
    Inspection,
    OperationKey,
    RevokeOptions,
    ServiceIdentity,
    WaitOptions,
)

ResponseT = TypeVar("ResponseT")
Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class AgentOptions:
    identity_provider: IdentityProvider
    allow_insecure_loopback: bool = False
    assertion_lifetime: timedelta = timedelta(minutes=5)
    clock: Clock = lambda: datetime.now(UTC)
    command_transport: AsyncHttpTransport | None = None
    credential_store: CredentialStore | None = None
    identity_store: IdentityStore | None = None
    idempotency_keys: IdempotencyKeyProvider | None = None
    inspect_cache: InspectCache | None = None
    inspect_transport: AsyncHttpTransport | None = None
    maximum_response_bytes: int = 1 << 20
    request_timeout: float = 30.0


class Agent:
    def __init__(self, options: AgentOptions) -> None:
        lifetime = options.assertion_lifetime.total_seconds()
        if lifetime < 1 or lifetime > 300 or not lifetime.is_integer():
            raise ValueError(
                "AEP Agent assertion lifetime must be whole seconds from 1 through 300"
            )
        if options.maximum_response_bytes < 1:
            raise ValueError("AEP Agent maximum response bytes must be positive")
        if options.request_timeout <= 0 or not math.isfinite(options.request_timeout):
            raise ValueError("AEP Agent request timeout must be positive and finite")
        self._allow_insecure_loopback = options.allow_insecure_loopback
        self._assertion_lifetime = int(lifetime)
        self._clock = options.clock
        owned_transports: list[AsyncHttpTransport] = []
        command_transport: AsyncHttpTransport
        if options.command_transport is None:
            command_transport = HttpxTransport(
                maximum_response_bytes=options.maximum_response_bytes
            )
            owned_transports.append(command_transport)
        else:
            command_transport = options.command_transport
        self._command_transport = command_transport
        self._credential_store = options.credential_store or MemoryCredentialStore(options.clock)
        self._identity_provider = options.identity_provider
        self._identity_store = options.identity_store or MemoryIdentityStore()
        self._idempotency_keys = options.idempotency_keys or RandomIdempotencyKeyProvider()
        self._inspect_cache = options.inspect_cache or MemoryInspectCache()
        inspect_transport: AsyncHttpTransport
        if options.inspect_transport is None and options.command_transport is None:
            inspect_transport = command_transport
        elif options.inspect_transport is None:
            inspect_transport = HttpxTransport(
                maximum_response_bytes=options.maximum_response_bytes
            )
            owned_transports.append(inspect_transport)
        else:
            inspect_transport = options.inspect_transport
        self._inspect_transport = inspect_transport
        self._maximum_response_bytes = options.maximum_response_bytes
        self._request_timeout = options.request_timeout
        self._identity_lock = asyncio.Lock()
        self._owned_transports = tuple(owned_transports)

    async def __aenter__(self) -> Agent:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        for transport in self._owned_transports:
            await transport.aclose()

    def service(self, reference: str) -> ServiceSession:
        return ServiceSession(self, _service_url(reference, self._allow_insecure_loopback))


class ServiceSession:
    def __init__(self, agent: Agent, service_url: str) -> None:
        self._agent = agent
        self._service_url = service_url
        self._inspection_lock = asyncio.Lock()
        self._identity_lock = asyncio.Lock()
        self._identity: ServiceIdentity | None = None
        self._authoritative_active_enrollment = False

    async def inspect(self) -> Inspection:
        async with self._inspection_lock:
            return await asyncio.wait_for(self._inspect(), timeout=self._agent._request_timeout)

    async def _inspect(self) -> Inspection:
        inspect_url = urljoin(self._service_url, AEP_WELL_KNOWN_PATH)
        cached = await self._agent._inspect_cache.find_inspect(inspect_url)
        now = self._agent._clock()
        if cached is not None:
            try:
                if cached.cached_at.utcoffset() is None:
                    raise ValueError("cached AEP Inspect timestamp has no UTC offset")
                if not _valid_https_url(
                    cached.final_url, self._agent._allow_insecure_loopback
                ) or not same_origin(cached.final_url, inspect_url):
                    raise ValueError("cached AEP Inspect URL is invalid")
                document = parse_json_model(
                    json.dumps(cached.document.to_wire()),
                    InspectDocument,
                    "Inspect document",
                )
                require_service_origin_binding(document, cached.final_url)
                cached = replace(cached, document=document)
            except (AepValidationError, ValueError):
                await self._agent._inspect_cache.delete_inspect(inspect_url)
                cached = None
        if cached is not None and _cache_fresh(cached, now):
            return _inspection_from_cache(cached, inspect_url, self._service_url)
        current = cached.final_url if cached is not None else inspect_url
        headers = {"Accept": AEP_MEDIA_TYPE}
        if cached is not None:
            if cached.etag:
                headers["If-None-Match"] = cached.etag
            if cached.last_modified:
                headers["If-Modified-Since"] = cached.last_modified
        redirects = 0
        while True:
            response = await self._agent._inspect_transport.send(
                HttpRequest(method="GET", url=current, headers=headers)
            )
            if response.status in {301, 302, 303, 307, 308}:
                if redirects >= 5:
                    raise ValueError("AEP Inspect exceeded five redirects")
                location = _header(response.headers, "location")
                if location is None:
                    raise ValueError("AEP Inspect redirect omitted Location")
                target = urljoin(current, location)
                if not _valid_https_url(
                    target, self._agent._allow_insecure_loopback
                ) or not same_origin(current, target):
                    raise ValueError("AEP Inspect redirect changed origin or scheme")
                current = target
                redirects += 1
                continue
            if response.status == 304:
                if cached is None:
                    raise ValueError("AEP Inspect returned 304 without a cached document")
                entry = InspectCacheEntry(
                    cached_at=now,
                    document=cached.document,
                    final_url=current,
                    cache_control=_header(response.headers, "cache-control")
                    or cached.cache_control,
                    etag=_header(response.headers, "etag") or cached.etag,
                    last_modified=_header(response.headers, "last-modified")
                    or cached.last_modified,
                )
                if _cache_directive(entry.cache_control, "no-store") is not None:
                    await self._agent._inspect_cache.delete_inspect(inspect_url)
                else:
                    await self._agent._inspect_cache.save_inspect(inspect_url, entry)
                return _inspection_from_cache(entry, inspect_url, self._service_url)
            if response.status < 200 or response.status >= 300:
                raise AgentCommandError(
                    response.status, f"AEP Inspect failed with HTTP {response.status}"
                )
            if (
                media_type_essence(_header(response.headers, "content-type") or "")
                != AEP_MEDIA_TYPE
            ):
                raise ValueError("AEP Inspect response media type is invalid")
            _bounded(response.body, self._agent._maximum_response_bytes)
            document = parse_json_model(response.body, InspectDocument, "Inspect document")
            require_service_origin_binding(document, current)
            entry = InspectCacheEntry(
                cached_at=now,
                document=document,
                final_url=current,
                cache_control=_header(response.headers, "cache-control") or "",
                etag=_header(response.headers, "etag") or "",
                last_modified=_header(response.headers, "last-modified") or "",
            )
            if _cache_directive(entry.cache_control, "no-store") is not None:
                await self._agent._inspect_cache.delete_inspect(inspect_url)
            else:
                await self._agent._inspect_cache.save_inspect(inspect_url, entry)
            return _inspection_from_cache(entry, inspect_url, self._service_url)

    async def identity(self) -> ServiceIdentity:
        inspection = await self.inspect()
        return await self._resolve_identity(inspection)

    async def enroll(self, options: EnrollOptions | None = None) -> CommandResult[EnrollResponse]:
        options = options or EnrollOptions()
        inspection, identity, signer = await self._command_context(Command.ENROLL)
        required = (
            inspection.document.claims.required
            if inspection.document.claims and inspection.document.claims.required
            else ()
        )
        supplied = set(options.claims.to_wire()) if options.claims else set()
        missing = tuple(value for value in required if value not in supplied)
        if missing:
            raise ClaimRequirementsError(missing)
        key = await self._idempotency_key(inspection, Command.ENROLL.value, options.idempotency_key)
        request_data: dict[str, object] = {
            "agent_did": identity.agent_did,
            "idempotency_key": key,
        }
        if options.claims is not None:
            request_data["claims"] = options.claims
        request = EnrollRequest.model_validate(request_data)
        result = await self._execute(
            inspection,
            identity,
            signer,
            Command.ENROLL,
            "POST",
            request.to_wire(),
            key,
            _parse_enroll_response,
        )
        self._authoritative_active_enrollment = result.body.status is AgentStatus.ACTIVE
        return result

    async def status(self) -> CommandResult[StatusResponse]:
        inspection, identity, signer = await self._command_context(Command.STATUS)
        result = await self._execute(
            inspection,
            identity,
            signer,
            Command.STATUS,
            "GET",
            None,
            None,
            _parse_status_response,
        )
        self._authoritative_active_enrollment = result.body.status is AgentStatus.ACTIVE
        return result

    async def wait_for_active(
        self, options: WaitOptions | None = None
    ) -> CommandResult[StatusResponse]:
        options = options or WaitOptions()
        if (
            options.interval <= 0
            or options.timeout <= 0
            or not math.isfinite(options.interval)
            or not math.isfinite(options.timeout)
        ):
            raise ValueError("AEP Status polling interval and timeout must be positive and finite")

        async def poll() -> CommandResult[StatusResponse]:
            while True:
                result = await self.status()
                response = result.body
                if response.status is AgentStatus.ACTIVE:
                    return result
                if response.status in {
                    AgentStatus.REJECTED,
                    AgentStatus.SUSPENDED,
                    AgentStatus.TERMINATED,
                }:
                    raise EnrollmentStateError(response.status.value)
                await asyncio.sleep(options.interval)

        return await asyncio.wait_for(poll(), timeout=options.timeout)

    async def grant(self, options: GrantOptions | None = None) -> CommandResult[GrantResult]:
        options = options or GrantOptions()
        inspection, identity, signer = await self._existing_command_context(Command.GRANT)
        grant_type = _select_grant_type(
            inspection.document, options.grant_type, options.preferred_grant_types
        )
        if (
            not self._authoritative_active_enrollment
            and Command.STATUS.value in inspection.document.commands.supported
        ):
            current = await self._execute(
                inspection,
                identity,
                signer,
                Command.STATUS,
                "GET",
                None,
                None,
                _parse_status_response,
            )
            self._authoritative_active_enrollment = current.body.status is AgentStatus.ACTIVE
            if not self._authoritative_active_enrollment:
                raise AgentCommandError(401, "AEP Grant requires active enrollment")
        key = await self._idempotency_key(
            inspection, Command.GRANT.value, options.idempotency_key, grant_type=grant_type
        )
        request_data: dict[str, object] = {"grant_type": grant_type}
        if options.requested_scopes:
            request_data["requested_scopes"] = options.requested_scopes
        request = GrantRequest.model_validate(request_data)
        result = await self._execute(
            inspection,
            identity,
            signer,
            Command.GRANT,
            "POST",
            request.to_wire(),
            key,
            _copy_bytes,
        )
        raw = result.body
        credential = _parse_credential(grant_type, raw)
        grant_result = GrantResult(credential=credential, grant_type=grant_type, raw=raw)
        if credential is not None:
            record = CredentialRecord(
                credential_id=credential.credential_id,
                expires_at=datetime.fromisoformat(credential.expires_at.replace("Z", "+00:00")),
                grant_type=grant_type,
                issued_at=self._agent._clock(),
                payload=bytes(raw),
                service_did=inspection.document.service.did,
                service_url=self._service_url,
            )
            await self._agent._credential_store.save_credential(record)
        return CommandResult(body=grant_result, status=result.status, url=result.url)

    async def revoke(self, options: RevokeOptions) -> CommandResult[RevokeResponse]:
        if options.all_grant_types:
            request_data: dict[str, object] = {"all_grant_types": "true"}
        else:
            request_data = {}
            if options.grant_type is not None:
                request_data["grant_type"] = options.grant_type
            if options.credential_id is not None:
                request_data["credential_id"] = options.credential_id
        request = RevokeRequest.model_validate(request_data)
        inspection, identity, signer = await self._command_context(Command.REVOKE)
        if request.grant_type is not None and request.grant_type not in (
            inspection.document.commands.grant_types or ()
        ):
            raise ValueError("AEP Service does not advertise the selected grant type")
        if request.credential_id is not None:
            config = (inspection.document.commands.grant_types_config or {}).get(
                request.grant_type or ""
            )
            if config is None or config.supports_per_credential_revoke != "true":
                raise ValueError("AEP Service does not advertise per-credential Revoke")
        key = await self._idempotency_key(
            inspection,
            Command.REVOKE.value,
            options.idempotency_key,
            credential_id=request.credential_id,
            grant_type=request.grant_type,
        )
        result = await self._execute(
            inspection,
            identity,
            signer,
            Command.REVOKE,
            "POST",
            request.to_wire(),
            key,
            _parse_revoke_response,
        )
        for record in await self._agent._credential_store.list_credentials(
            inspection.document.service.did
        ):
            matches = (
                options.all_grant_types
                or record.credential_id == options.credential_id
                or (options.credential_id is None and record.grant_type == options.grant_type)
            )
            if matches:
                await self._agent._credential_store.delete_credential(
                    record.service_did, record.credential_id
                )
        return result

    async def authentication_headers(self, options: AuthenticationOptions) -> Mapping[str, str]:
        if options.client_assertion_only and (options.credential_id or options.grant_type):
            raise ValueError("AEP credential selection cannot accompany client-assertion-only mode")
        inspection = await self.inspect()
        _require_resource(options.resource, self._service_url, self._agent._allow_insecure_loopback)
        carrier = AuthorizationCarrier(options.carrier)
        methods = (
            inspection.document.authentication.methods if inspection.document.authentication else ()
        )
        if not options.client_assertion_only:
            record = await self._find_credential(inspection.document.service.did, methods, options)
            if record is not None:
                return _credential_headers(record, carrier)
            if options.credential_id or options.grant_type:
                raise ValueError("requested AEP credential was not found")
        if AEP_AUTHENTICATION_METHOD_JWT not in methods:
            raise ValueError("AEP Service does not advertise a compatible authentication method")
        identity = await self._resolve_identity(inspection)
        signer = await self._agent._identity_provider.signer_for(identity)
        if not callable(signer):
            raise ValueError("AEP identity provider returned no assertion signer")
        assertion = await self._sign_assertion(
            inspection, identity, signer, AssertionOperation.AUTHENTICATE, options.resource
        )
        name, value = render_authorization(
            ProtectedResourceAuthorization(
                carrier=carrier, scheme=AuthorizationScheme.AEP, credentials=assertion
            )
        )
        return {name: value}

    async def forget_credential(self, credential_id: str) -> None:
        if not credential_id:
            raise ValueError("AEP credential ID is required")
        inspection = await self.inspect()
        await self._agent._credential_store.delete_credential(
            inspection.document.service.did, credential_id
        )

    async def _command_context(
        self, command: Command
    ) -> tuple[Inspection, ServiceIdentity, AssertionSigner]:
        inspection = await self.inspect()
        if command.value not in inspection.document.commands.supported:
            raise ValueError(f"AEP Service does not advertise {command.value}")
        identity = await self._resolve_identity(inspection)
        signer = await self._agent._identity_provider.signer_for(identity)
        if not callable(signer):
            raise ValueError("AEP identity provider returned no assertion signer")
        return inspection, identity, signer

    async def _existing_command_context(
        self, command: Command
    ) -> tuple[Inspection, ServiceIdentity, AssertionSigner]:
        inspection = await self.inspect()
        if command.value not in inspection.document.commands.supported:
            raise ValueError(f"AEP Service does not advertise {command.value}")
        identity = await self._agent._identity_store.find_identity(inspection.document.service.did)
        if identity is None:
            raise AgentCommandError(401, "AEP Grant requires an existing enrolled identity")
        _validate_identity(identity, inspection)
        signer = await self._agent._identity_provider.signer_for(identity)
        if not callable(signer):
            raise ValueError("AEP identity provider returned no assertion signer")
        return inspection, identity, signer

    async def _resolve_identity(self, inspection: Inspection) -> ServiceIdentity:
        async with self._identity_lock:
            if self._identity is not None:
                _validate_identity(self._identity, inspection)
                return self._identity
            async with self._agent._identity_lock:
                identity = await self._agent._identity_store.find_identity(
                    inspection.document.service.did
                )
                if identity is None:
                    identity = await self._agent._identity_provider.get_or_create_identity(
                        IdentityRequest(
                            inspect=inspection.document,
                            service_did=inspection.document.service.did,
                            service_url=self._service_url,
                        )
                    )
                    _validate_identity(identity, inspection)
                    await self._agent._identity_store.save_identity(identity)
                else:
                    _validate_identity(identity, inspection)
                self._identity = identity
                return identity

    async def _idempotency_key(
        self,
        inspection: Inspection,
        command: str,
        provided: str | None,
        *,
        credential_id: str | None = None,
        grant_type: str | None = None,
    ) -> str:
        if provided is not None:
            if not provided:
                raise ValueError("AEP idempotency key must not be empty")
            return provided
        key = await self._agent._idempotency_keys.create_key(
            OperationKey(
                command=command,
                credential_id=credential_id,
                grant_type=grant_type,
                service_did=inspection.document.service.did,
                service_url=self._service_url,
            )
        )
        if not key:
            raise ValueError("AEP idempotency key provider returned an empty key")
        return key

    async def _execute(
        self,
        inspection: Inspection,
        identity: ServiceIdentity,
        signer: AssertionSigner,
        command: Command,
        method: str,
        body: Mapping[str, object] | None,
        idempotency_key: str | None,
        parser: Callable[[bytes], ResponseT],
    ) -> CommandResult[ResponseT]:
        url = urljoin(self._service_url, command_path_from_inspect(inspection.document, command))
        assertion = await self._sign_assertion(
            inspection, identity, signer, AssertionOperation(command.value), None
        )
        headers = {"Accept": AEP_MEDIA_TYPE, "Authorization": f"AEP {assertion}"}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = AEP_MEDIA_TYPE
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        response = await asyncio.wait_for(
            self._agent._command_transport.send(
                HttpRequest(method=method, url=url, headers=headers, body=data)
            ),
            timeout=self._agent._request_timeout,
        )
        _bounded(response.body, self._agent._maximum_response_bytes)
        if response.status < 200 or response.status >= 300:
            problem = None
            if (
                media_type_essence(_header(response.headers, "content-type") or "")
                == AEP_PROBLEM_MEDIA_TYPE
            ):
                with suppress(AepValidationError):
                    problem = parse_json_model(response.body, ProblemDetails, "Problem Details")
            code = f": {problem.code}" if problem is not None else ""
            raise AgentCommandError(
                response.status, f"AEP command failed with HTTP {response.status}{code}", problem
            )
        if media_type_essence(_header(response.headers, "content-type") or "") != AEP_MEDIA_TYPE:
            raise ValueError("AEP command response media type is invalid")
        parsed = parser(response.body)
        return CommandResult(body=parsed, status=response.status, url=url)

    async def _sign_assertion(
        self,
        inspection: Inspection,
        identity: ServiceIdentity,
        signer: AssertionSigner,
        operation: AssertionOperation,
        resource: str | None,
    ) -> str:
        _validate_identity(identity, inspection)
        now = int(self._agent._clock().timestamp())
        claim_data: dict[str, object] = {
            "aud": inspection.document.service.did,
            "exp": now + self._agent._assertion_lifetime,
            "iat": now,
            "iss": identity.agent_did,
            "jti": secrets.token_hex(16),
            "op": operation,
            "sub": identity.agent_did,
        }
        if resource is not None:
            claim_data["resource"] = resource
        claims = ClientAssertionClaims.model_validate(
            claim_data,
            context={"allow_insecure_loopback": self._agent._allow_insecure_loopback},
        )
        algorithms = tuple(
            value
            for value in inspection.document.core.signing_algorithms
            if value in {item.value for item in identity.signing_algorithms}
        )
        assertion = await signer(claims, tuple(SigningAlgorithm(value) for value in algorithms))
        if not assertion:
            raise ValueError("AEP assertion signer returned an empty assertion")
        return assertion

    async def _find_credential(
        self,
        service_did: str,
        methods: Sequence[str],
        options: AuthenticationOptions,
    ) -> CredentialRecord | None:
        if options.grant_type and options.grant_type not in methods:
            raise ValueError("AEP Service does not advertise a compatible authentication method")
        if options.credential_id:
            record = await self._agent._credential_store.find_credential(
                service_did, options.credential_id
            )
            if record is None:
                return None
            _validate_credential_record(record, service_did, self._agent._clock())
            if options.grant_type and record.grant_type != options.grant_type:
                raise ValueError("stored AEP credential does not match requested grant type")
            if record.grant_type not in methods:
                raise ValueError(
                    "AEP Service does not advertise a compatible authentication method"
                )
            return record
        records = await self._agent._credential_store.list_credentials(service_did)
        for method in methods:
            for record in records:
                if record.grant_type != method or (
                    options.grant_type is not None and record.grant_type != options.grant_type
                ):
                    continue
                _validate_credential_record(record, service_did, self._agent._clock())
                return record
        return None


def _service_url(reference: str, allow_insecure_loopback: bool) -> str:
    value = reference.strip()
    if not value:
        raise ValueError("invalid AEP Service reference")
    if value.startswith("did:web:"):
        document_url = did_web_document_url(value, allow_insecure_loopback=allow_insecure_loopback)
        parsed_document = urlsplit(document_url)
        value = urlunsplit((parsed_document.scheme, parsed_document.netloc, "/", "", ""))
    elif "://" not in value:
        value = f"https://{value}"
    if not _valid_https_url(value, allow_insecure_loopback):
        raise ValueError("AEP Service references require HTTPS")
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _valid_https_url(value: str, allow_insecure_loopback: bool) -> bool:
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        return False
    if parsed.scheme == "https":
        return True
    return (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )


def _require_resource(resource: str, service_url: str, allow_insecure_loopback: bool) -> None:
    if not _valid_https_url(resource, allow_insecure_loopback) or urlsplit(resource).fragment:
        raise ValueError("AEP protected resource URL is invalid")
    if not same_origin(resource, service_url):
        raise ValueError("AEP protected resource must use the Service origin")


def _validate_identity(identity: ServiceIdentity, inspection: Inspection) -> None:
    if (
        not identity.agent_did.startswith("did:")
        or identity.service_did != inspection.document.service.did
        or identity.identity_method not in inspection.document.identity.methods
        or not identity.signing_algorithms
    ):
        raise ValueError("AEP identity provider returned an invalid Service-scoped identity")
    if identity.identity_method == "did:web" and not identity.agent_did.startswith("did:web:"):
        raise ValueError("AEP Agent DID does not match its identity method")


def _select_grant_type(
    document: InspectDocument, selected: str | None, preferred: Sequence[str]
) -> str:
    advertised = document.commands.grant_types or ()
    if selected is not None:
        if selected in advertised:
            return selected
        raise ValueError("AEP Service does not advertise the selected grant type")
    for value in preferred or advertised:
        if value in advertised:
            return value
    raise ValueError("AEP Service does not advertise a compatible grant type")


def _parse_credential(grant_type: str, data: bytes) -> BuiltInCredential | None:
    if grant_type == "api-key":
        return parse_json_model(data, ApiKeyGrantResponse, "Grant response")
    elif grant_type == "basic":
        return parse_json_model(data, BasicGrantResponse, "Grant response")
    elif grant_type == "oauth-bearer":
        return parse_json_model(data, OAuthBearerGrantResponse, "Grant response")
    else:
        parsed = json.loads(data)
        if not isinstance(parsed, dict):
            raise ValueError("AEP Grant response must be a JSON object")
        return None


def _parse_enroll_response(data: bytes) -> EnrollResponse:
    return parse_json_model(data, EnrollResponse, "Enroll response")


def _parse_status_response(data: bytes) -> StatusResponse:
    return parse_json_model(data, StatusResponse, "Status response")


def _parse_revoke_response(data: bytes) -> RevokeResponse:
    return parse_json_model(data, RevokeResponse, "Revoke response")


def _copy_bytes(data: bytes) -> bytes:
    return bytes(data)


def _credential_headers(
    record: CredentialRecord, carrier: AuthorizationCarrier
) -> Mapping[str, str]:
    credential = _parse_credential(record.grant_type, record.payload)
    if credential is None or credential.credential_id != record.credential_id:
        raise ValueError("stored AEP credential metadata does not match its payload")
    if isinstance(credential, ApiKeyGrantResponse):
        return {credential.header: credential.api_key}
    if isinstance(credential, OAuthBearerGrantResponse):
        authorization = ProtectedResourceAuthorization(
            carrier=carrier,
            scheme=AuthorizationScheme.BEARER,
            credentials=credential.access_token,
        )
    else:
        import base64

        encoded = base64.b64encode(f"{credential.username}:{credential.password}".encode()).decode()
        authorization = ProtectedResourceAuthorization(
            carrier=carrier, scheme=AuthorizationScheme.BASIC, credentials=encoded
        )
    name, value = render_authorization(authorization)
    return {name: value}


def _validate_credential_record(record: CredentialRecord, service_did: str, now: datetime) -> None:
    if (
        not record.credential_id
        or record.service_did != service_did
        or not record.grant_type
        or record.expires_at <= now
    ):
        raise ValueError("stored AEP credential metadata is invalid")
    credential = _parse_credential(record.grant_type, record.payload)
    if (
        credential is None
        or credential.credential_id != record.credential_id
        or datetime.fromisoformat(credential.expires_at.replace("Z", "+00:00")) != record.expires_at
    ):
        raise ValueError("stored AEP credential metadata does not match its payload")


def _inspection_from_cache(
    entry: InspectCacheEntry, inspect_url: str, service_url: str
) -> Inspection:
    return Inspection(
        cache_control=entry.cache_control,
        document=entry.document,
        etag=entry.etag,
        final_url=entry.final_url,
        inspect_url=inspect_url,
        last_modified=entry.last_modified,
        service_url=service_url,
    )


def _cache_fresh(entry: InspectCacheEntry, now: datetime) -> bool:
    if (
        _cache_directive(entry.cache_control, "no-cache") is not None
        or _cache_directive(entry.cache_control, "no-store") is not None
    ):
        return False
    value = _cache_directive(entry.cache_control, "max-age")
    seconds = 300
    if value is not None:
        try:
            seconds = int(value)
        except ValueError:
            return False
        if seconds < 0:
            return False
    return entry.cached_at + timedelta(seconds=seconds) > now


def _cache_directive(value: str, name: str) -> str | None:
    for directive in value.split(","):
        key, separator, item = directive.strip().partition("=")
        if key.lower() == name:
            return item.strip('"') if separator else ""
    return None


def _header(headers: Mapping[str, str], name: str) -> str | None:
    expected = name.lower()
    return next((value for key, value in headers.items() if key.lower() == expected), None)


def _bounded(data: bytes, maximum: int) -> None:
    if len(data) > maximum:
        raise ValueError("AEP response exceeds the configured limit")
