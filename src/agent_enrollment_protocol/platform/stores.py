from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from agent_enrollment_protocol.core import ManagedAgentStatus

from .types import (
    IdentityFactory,
    IdentityListQuery,
    IdentityListResult,
    IdentityRecord,
    PlatformIdempotencyInput,
    PlatformIdempotencyResult,
    PlatformIdempotencyState,
    RequestContext,
    StoredOperation,
    StoredResponse,
)


class MemoryIdentityStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._pending: dict[tuple[str, str], asyncio.Event] = {}
        self._records: dict[str, IdentityRecord] = {}
        self._by_agent_did: dict[str, str] = {}
        self._by_agent_did_id: dict[str, str] = {}
        self._by_scope: dict[tuple[str, str], str] = {}

    async def find_or_create(
        self, principal: str, service_did: str, factory: IdentityFactory
    ) -> tuple[IdentityRecord, bool]:
        if not principal or not service_did:
            raise ValueError("AEP Platform identity scope must not be empty")
        scope = (principal, service_did)
        while True:
            async with self._lock:
                identity_id = self._by_scope.get(scope)
                if identity_id is not None:
                    return self._records[identity_id], False
                pending = self._pending.get(scope)
                if pending is None:
                    pending = asyncio.Event()
                    self._pending[scope] = pending
                    break
            await pending.wait()
        try:
            record = await factory()
            validate_identity_record(record)
            if record.principal != principal or record.service_did != service_did:
                raise ValueError("AEP Platform identity does not match its requested scope")
            async with self._lock:
                if (
                    record.agent_identity_id in self._records
                    or record.agent_did in self._by_agent_did
                    or record.agent_did_id in self._by_agent_did_id
                ):
                    raise ValueError("AEP Platform identity material must be unique")
                self._records[record.agent_identity_id] = record
                self._by_agent_did[record.agent_did] = record.agent_identity_id
                self._by_agent_did_id[record.agent_did_id] = record.agent_identity_id
                self._by_scope[scope] = record.agent_identity_id
            return record, True
        finally:
            async with self._lock:
                self._pending.pop(scope).set()

    async def find_by_agent_did(self, agent_did: str) -> IdentityRecord | None:
        async with self._lock:
            identity_id = self._by_agent_did.get(agent_did)
            return self._records.get(identity_id) if identity_id is not None else None

    async def find_by_agent_did_id(self, agent_did_id: str) -> IdentityRecord | None:
        async with self._lock:
            identity_id = self._by_agent_did_id.get(agent_did_id)
            return self._records.get(identity_id) if identity_id is not None else None

    async def get(self, agent_identity_id: str) -> IdentityRecord | None:
        async with self._lock:
            return self._records.get(agent_identity_id)

    async def list(self, principal: str, query: IdentityListQuery) -> IdentityListResult:
        if not principal or query.limit < 0 or query.offset < 0:
            raise ValueError("AEP Platform identity list query is invalid")
        async with self._lock:
            records = [
                record
                for record in self._records.values()
                if record.principal == principal
                and (query.service_did is None or record.service_did == query.service_did)
                and (query.status is None or record.status is query.status)
            ]
        records.sort(
            key=lambda record: (record.created_at, record.agent_identity_id),
            reverse=query.descending,
        )
        total = len(records)
        records = records[query.offset : query.offset + query.limit]
        return IdentityListResult(tuple(records), total)

    async def update_status(
        self,
        agent_identity_id: str,
        status: ManagedAgentStatus,
        updated_at: datetime,
    ) -> IdentityRecord | None:
        if updated_at.utcoffset() is None:
            raise ValueError("AEP Platform identity update is invalid")
        async with self._lock:
            current = self._records.get(agent_identity_id)
            if current is None:
                return None
            updated = replace(current, status=status, updated_at=updated_at)
            self._records[agent_identity_id] = updated
            return updated


class MemoryPlatformIdempotencyStore:
    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()
        self._pending: dict[tuple[str, str], asyncio.Event] = {}
        self._records: dict[tuple[str, str], tuple[PlatformIdempotencyInput, StoredResponse]] = {}

    async def execute(
        self, value: PlatformIdempotencyInput, operation: StoredOperation
    ) -> PlatformIdempotencyResult:
        if not all((value.principal, value.idempotency_key, value.operation, value.request_hash)):
            raise ValueError("AEP Platform idempotency input is invalid")
        key = (value.principal, value.idempotency_key)
        while True:
            async with self._lock:
                now = self._clock()
                if now.utcoffset() is None:
                    raise ValueError("AEP Platform idempotency clock must be offset-aware")
                cutoff = now - timedelta(hours=1)
                self._records = {
                    record_key: record
                    for record_key, record in self._records.items()
                    if record[1].created_at >= cutoff
                }
                existing = self._records.get(key)
                if existing is not None:
                    previous, response = existing
                    if (
                        previous.operation is not value.operation
                        or previous.request_hash != value.request_hash
                    ):
                        return PlatformIdempotencyResult(None, PlatformIdempotencyState.CONFLICT)
                    return PlatformIdempotencyResult(response, PlatformIdempotencyState.REPLAYED)
                pending = self._pending.get(key)
                if pending is None:
                    pending = asyncio.Event()
                    self._pending[key] = pending
                    break
            await pending.wait()
        try:
            response = await operation()
            async with self._lock:
                self._records[key] = (value, response)
            return PlatformIdempotencyResult(response, PlatformIdempotencyState.CREATED)
        finally:
            async with self._lock:
                self._pending.pop(key).set()


class MemoryReplayStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[str, datetime] = {}

    async def consume(self, key: str, expires_at: datetime, now: datetime) -> bool:
        if not key or expires_at.utcoffset() is None or now.utcoffset() is None:
            raise ValueError("AEP Platform replay input is invalid")
        async with self._lock:
            self._records = {item: expiry for item, expiry in self._records.items() if expiry > now}
            if expires_at <= now or key in self._records:
                return False
            self._records[key] = expires_at
            return True


class DefaultLifecyclePolicy:
    async def can_sign(self, identity: IdentityRecord, context: RequestContext) -> bool:
        del context
        return identity.status is ManagedAgentStatus.ACTIVE

    async def can_transition(
        self, identity: IdentityRecord, status: ManagedAgentStatus, context: RequestContext
    ) -> bool:
        del identity, status, context
        return True

    async def can_verify(self, identity: IdentityRecord, context: RequestContext) -> bool:
        del context
        return identity.status is ManagedAgentStatus.ACTIVE


def validate_identity_record(record: IdentityRecord) -> None:
    values = (
        record.agent_did,
        record.agent_did_id,
        record.agent_identity_id,
        record.did_document_url,
        record.key_id,
        record.principal,
        record.service_did,
    )
    if (
        not all(values)
        or not record.signing_algorithms
        or record.key_id != record.agent_did
        or record.created_at.utcoffset() is None
        or record.updated_at.utcoffset() is None
    ):
        raise ValueError("AEP Platform identity store received an invalid record")
