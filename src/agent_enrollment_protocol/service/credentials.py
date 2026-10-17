from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Generic

from agent_enrollment_protocol.core import (
    AEP_GRANT_TYPE_API_KEY,
    AEP_GRANT_TYPE_BASIC,
    AEP_GRANT_TYPE_OAUTH_BEARER,
    ApiKeyGrantResponse,
    AuthorizationCarrier,
    AuthorizationScheme,
    BasicGrantResponse,
    GrantRequest,
    GrantTypeConfig,
    OAuthBearerGrantResponse,
    RevokeRequest,
    parse_authorization,
)
from agent_enrollment_protocol.core.errors import AepAuthorizationError
from agent_enrollment_protocol.core.models import parse_rfc3339

from .types import (
    AuthenticatedPrincipal,
    AuthenticationKind,
    BuiltInCredential,
    CredentialAuthenticationInput,
    CredentialMatch,
    CredentialT,
    GrantContext,
    GrantTypeDefinition,
    RevokeContext,
    ServiceCredentialRecord,
    StoredCredentialGrantTypeOptions,
)

HTTP_FIELD_NAME_PATTERN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def stored_oauth_bearer_grant_type(
    options: StoredCredentialGrantTypeOptions[OAuthBearerGrantResponse],
) -> GrantTypeDefinition:
    return _stored_credential_grant_type(AEP_GRANT_TYPE_OAUTH_BEARER, options)


def stored_api_key_grant_type(
    options: StoredCredentialGrantTypeOptions[ApiKeyGrantResponse],
) -> GrantTypeDefinition:
    return _stored_credential_grant_type(AEP_GRANT_TYPE_API_KEY, options)


def stored_basic_grant_type(
    options: StoredCredentialGrantTypeOptions[BasicGrantResponse],
) -> GrantTypeDefinition:
    return _stored_credential_grant_type(AEP_GRANT_TYPE_BASIC, options)


def _stored_credential_grant_type(
    grant_type: str, options: StoredCredentialGrantTypeOptions[CredentialT]
) -> GrantTypeDefinition:
    if not callable(options.issue) or options.store is None:
        raise ValueError("AEP stored credential Grant Type requires an issuer and store")
    config = GrantTypeConfig.model_validate(
        {**options.config.to_wire(), "supports_per_credential_revoke": "true"}
    )
    if grant_type == AEP_GRANT_TYPE_API_KEY:
        _configured_api_key_headers(config)
    handler = _StoredCredentialHandler(grant_type, config, options)
    return GrantTypeDefinition(
        grant_type=grant_type,
        handler=handler,
        config=config,
        authenticator=handler,
    )


class _StoredCredentialHandler(Generic[CredentialT]):
    def __init__(
        self,
        grant_type: str,
        config: GrantTypeConfig,
        options: StoredCredentialGrantTypeOptions[CredentialT],
    ) -> None:
        self._config = config.model_copy(deep=True)
        self._grant_type = grant_type
        self._issue = options.issue
        self._store = options.store

    async def grant(self, request: GrantRequest, context: GrantContext) -> bytes:
        _require_aware_time(context.current_time, "issuance")
        credential = await self._issue(request, context)
        parsed = _validate_built_in_credential(self._grant_type, credential)
        _validate_issued_credential_config(parsed, self._config)
        _require_encodable_basic(parsed)
        expires_at = _parse_expiry(parsed.expires_at)
        if expires_at <= context.current_time:
            raise ValueError("AEP issued credential must expire after issuance")
        await self._store.save_credential(
            ServiceCredentialRecord(
                agent_did=context.agent_did,
                created_at=context.current_time,
                credential=parsed,
                credential_id=parsed.credential_id,
                expires_at=expires_at,
                grant_type=self._grant_type,
            )
        )
        return json.dumps(parsed.to_wire(), separators=(",", ":")).encode()

    async def revoke(self, request: RevokeRequest, context: RevokeContext) -> None:
        credential_id = request.credential_id
        if credential_id is not None:
            await self._store.revoke_credential(
                context.agent_did,
                self._grant_type,
                credential_id,
                context.current_time,
            )
            return
        await self._store.revoke_grant_type(
            context.agent_did, self._grant_type, context.current_time
        )

    async def authenticate(
        self, request: CredentialAuthenticationInput
    ) -> AuthenticatedPrincipal | None:
        match = await self._store.authenticate_credential(self._grant_type, request)
        if match is None:
            return None
        if (
            not isinstance(match, CredentialMatch)
            or not match.agent_did
            or not match.credential_id
            or match.expires_at <= request.current_time
            or match.grant_type != self._grant_type
        ):
            raise ValueError("AEP credential store returned an invalid match")
        return AuthenticatedPrincipal(
            agent_did=match.agent_did,
            authentication_kind=AuthenticationKind.SESSION_CREDENTIAL,
            authentication_method=self._grant_type,
            credential_id=match.credential_id,
            grant_type=self._grant_type,
            scopes=tuple(match.scopes),
        )

    async def has_presentation(self, request: CredentialAuthenticationInput) -> bool:
        return await self._store.has_credential_presentation(self._grant_type, request)


@dataclass(frozen=True, slots=True)
class _MemoryCredentialRecord:
    agent_did: str
    credential_id: str
    expires_at: datetime
    grant_type: str
    header: str
    scopes: tuple[str, ...]
    salt: bytes
    username: str
    verifier: bytes
    revoked_at: datetime | None = None


class MemoryServiceCredentialStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[str, _MemoryCredentialRecord] = {}

    async def save_credential(self, record: ServiceCredentialRecord) -> None:
        stored = await _memory_credential_record(record)
        async with self._lock:
            if record.credential_id in self._records:
                raise ValueError("AEP credential identifier has already been issued")
            for existing in self._records.values():
                if (
                    existing.grant_type == stored.grant_type
                    and existing.header == stored.header
                    and existing.username == stored.username
                    and hmac.compare_digest(
                        existing.verifier,
                        await _credential_digest(
                            _credential_secret(record.credential),
                            existing.salt,
                            stored.grant_type == AEP_GRANT_TYPE_BASIC,
                        ),
                    )
                ):
                    raise ValueError("AEP credential secret has already been issued")
            self._records[record.credential_id] = stored

    async def authenticate_credential(
        self, grant_type: str, request: CredentialAuthenticationInput
    ) -> CredentialMatch | None:
        async with self._lock:
            records = tuple(self._records.values())
        presentations = _credential_presentations(grant_type, request.headers, records)
        if len(presentations) != 1:
            return None
        header, value = presentations[0]
        username = ""
        if grant_type == AEP_GRANT_TYPE_BASIC:
            try:
                username = base64.b64decode(value, validate=True).decode("utf-8").partition(":")[0]
            except (ValueError, UnicodeDecodeError):
                return None
        for record in records:
            if (
                record.grant_type == grant_type
                and record.header == header
                and record.username == username
                and record.revoked_at is None
                and record.expires_at > request.current_time
                and hmac.compare_digest(
                    record.verifier,
                    await _credential_digest(
                        value,
                        record.salt,
                        grant_type == AEP_GRANT_TYPE_BASIC,
                    ),
                )
            ):
                return CredentialMatch(
                    agent_did=record.agent_did,
                    credential_id=record.credential_id,
                    expires_at=record.expires_at,
                    grant_type=record.grant_type,
                    scopes=tuple(record.scopes),
                )
        return None

    async def has_credential_presentation(
        self, grant_type: str, request: CredentialAuthenticationInput
    ) -> bool:
        async with self._lock:
            records = tuple(self._records.values())
        return bool(_credential_presentations(grant_type, request.headers, records))

    async def revoke_credential(
        self, agent_did: str, grant_type: str, credential_id: str, revoked_at: datetime
    ) -> None:
        _require_aware_time(revoked_at, "revocation")
        async with self._lock:
            record = self._records.get(credential_id)
            if record is None:
                return
            if record.agent_did != agent_did or record.grant_type != grant_type:
                return
            self._records[credential_id] = replace(record, revoked_at=revoked_at)

    async def revoke_grant_type(
        self, agent_did: str, grant_type: str, revoked_at: datetime
    ) -> None:
        _require_aware_time(revoked_at, "revocation")
        async with self._lock:
            for credential_id, record in tuple(self._records.items()):
                if record.agent_did == agent_did and record.grant_type == grant_type:
                    self._records[credential_id] = replace(record, revoked_at=revoked_at)


async def _memory_credential_record(record: ServiceCredentialRecord) -> _MemoryCredentialRecord:
    _require_aware_time(record.created_at, "issuance")
    _require_aware_time(record.expires_at, "expiration")
    if (
        not record.agent_did
        or not record.credential_id
        or record.expires_at <= record.created_at
        or not record.grant_type
    ):
        raise ValueError("AEP credential store received an invalid record")
    credential = _validate_built_in_credential(record.grant_type, record.credential)
    if (
        credential.credential_id != record.credential_id
        or _parse_expiry(credential.expires_at) != record.expires_at
    ):
        raise ValueError("AEP credential record metadata does not match its credential")
    salt = secrets.token_bytes(16)
    return _MemoryCredentialRecord(
        agent_did=record.agent_did,
        credential_id=record.credential_id,
        expires_at=record.expires_at,
        grant_type=record.grant_type,
        header=credential.header.lower()
        if isinstance(credential, ApiKeyGrantResponse)
        else "authorization",
        scopes=tuple(credential.scopes or ()),
        salt=salt,
        username=credential.username if isinstance(credential, BasicGrantResponse) else "",
        verifier=await _credential_digest(
            _credential_secret(credential), salt, isinstance(credential, BasicGrantResponse)
        ),
    )


def _credential_secret(credential: BuiltInCredential) -> str:
    if isinstance(credential, ApiKeyGrantResponse):
        return credential.api_key
    if isinstance(credential, OAuthBearerGrantResponse):
        return credential.access_token
    return base64.b64encode(f"{credential.username}:{credential.password}".encode()).decode()


async def _credential_digest(value: str, salt: bytes, password: bool) -> bytes:
    if password:
        return await asyncio.to_thread(
            hashlib.scrypt, value.encode(), salt=salt, n=16384, r=8, p=1, dklen=32
        )
    return hashlib.sha256(salt + value.encode()).digest()


def _credential_presentations(
    grant_type: str,
    headers: Mapping[str, tuple[str, ...]],
    records: Sequence[_MemoryCredentialRecord],
) -> tuple[tuple[str, str], ...]:
    if grant_type == AEP_GRANT_TYPE_API_KEY:
        names = {record.header for record in records if record.grant_type == grant_type}
        return tuple((name, value) for name in names for value in headers.get(name, ()))
    expected = (
        AuthorizationScheme.BASIC
        if grant_type == AEP_GRANT_TYPE_BASIC
        else AuthorizationScheme.BEARER
    )
    presentations: list[tuple[str, str]] = []
    for name, carrier in (
        ("authorization", AuthorizationCarrier.STANDARD),
        ("aep-authorization", AuthorizationCarrier.DEDICATED),
    ):
        for value in headers.get(name, ()):
            try:
                parsed = parse_authorization(value, carrier)
            except AepAuthorizationError:
                continue
            if parsed.scheme is expected:
                presentations.append(("authorization", parsed.credentials))
    return tuple(presentations)


def _validate_built_in_credential(grant_type: str, credential: object) -> BuiltInCredential:
    model = {
        AEP_GRANT_TYPE_API_KEY: ApiKeyGrantResponse,
        AEP_GRANT_TYPE_BASIC: BasicGrantResponse,
        AEP_GRANT_TYPE_OAUTH_BEARER: OAuthBearerGrantResponse,
    }.get(grant_type)
    if model is None or not isinstance(credential, model):
        raise ValueError("AEP credential issuer returned the wrong built-in credential type")
    return model.model_validate(credential.to_wire())


def _validate_issued_credential_config(
    credential: BuiltInCredential, config: GrantTypeConfig
) -> None:
    if not isinstance(credential, ApiKeyGrantResponse):
        return
    header_names = _configured_api_key_headers(config)
    if header_names is not None and credential.header.lower() not in header_names:
        raise ValueError("AEP issued API-key header is not advertised by the Service")


def _require_encodable_basic(credential: BuiltInCredential) -> None:
    """BSC-RSP-003: issued Basic credentials must survive RFC 7617 encoding unchanged.

    RFC 7617 leaves the user-pass charset undefined without a `charset` parameter, so a client
    encoding a non-ASCII value as ISO-8859-1 and a Service storing it as UTF-8 derive different
    bytes from the same credential and authentication fails.
    """
    if not isinstance(credential, BasicGrantResponse):
        return
    if not credential.username.isascii() or not credential.password.isascii():
        raise ValueError("AEP issued Basic credentials must be encodable as US-ASCII")


def _configured_api_key_headers(config: GrantTypeConfig) -> frozenset[str] | None:
    value = config.to_wire().get("header_names")
    if value is None:
        return None
    if not isinstance(value, (list, tuple)):
        raise ValueError("AEP API-key header_names configuration is invalid")
    names: set[str] = set()
    for item in value:
        if not isinstance(item, str) or HTTP_FIELD_NAME_PATTERN.fullmatch(item) is None:
            raise ValueError(
                "AEP API-key header_names configuration contains an invalid HTTP field name"
            )
        name = item.lower()
        if name in names:
            raise ValueError(
                "AEP API-key header_names configuration contains a duplicate field name"
            )
        names.add(name)
    return frozenset(names)


def _parse_expiry(value: str) -> datetime:
    return parse_rfc3339(value)


def _require_aware_time(value: datetime, label: str) -> None:
    if value.utcoffset() is None:
        raise ValueError(f"AEP credential {label} time must contain a UTC offset")
