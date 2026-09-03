from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from agent_enrollment_protocol.core import EnrollRequest

from .types import (
    EnrollmentDecision,
    EnrollmentFactory,
    EnrollmentRecord,
    IdempotencyInput,
    IdempotencyResult,
    IdempotencyState,
    ReplayRecord,
    StoredOperation,
    StoredResponse,
)


class MemoryReplayStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[tuple[str, str], int] = {}

    async def consume(self, record: ReplayRecord, now: int) -> bool:
        key = (record.subject, record.jwt_id)
        async with self._lock:
            self._records = {key: expiry for key, expiry in self._records.items() if expiry > now}
            if record.expires_at <= now or not record.subject or not record.jwt_id:
                raise ValueError("AEP replay store received an invalid record")
            if key in self._records:
                return False
            self._records[key] = record.expires_at
            return True


class MemoryEnrollmentStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._pending: dict[str, asyncio.Event] = {}
        self._records: dict[str, EnrollmentRecord] = {}

    async def find(self, agent_did: str) -> EnrollmentRecord | None:
        async with self._lock:
            return self._records.get(agent_did)

    async def find_or_create(
        self, agent_did: str, factory: EnrollmentFactory
    ) -> tuple[EnrollmentRecord, bool]:
        while True:
            async with self._lock:
                existing = self._records.get(agent_did)
                if existing is not None:
                    return existing, False
                pending = self._pending.get(agent_did)
                if pending is None:
                    pending = asyncio.Event()
                    self._pending[agent_did] = pending
                    break
            await pending.wait()
        try:
            created = await factory()
            if created.agent_did != agent_did:
                raise ValueError("enrollment factory returned a mismatched Agent DID")
            async with self._lock:
                self._records[agent_did] = created
            return created, True
        finally:
            async with self._lock:
                self._pending.pop(agent_did).set()

    async def save(self, record: EnrollmentRecord) -> EnrollmentRecord:
        async with self._lock:
            self._records[record.agent_did] = record
            return record


class MemoryIdempotencyStore:
    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()
        self._pending: dict[tuple[str, str], asyncio.Event] = {}
        self._records: dict[tuple[str, str], tuple[IdempotencyInput, StoredResponse]] = {}

    async def execute(
        self, value: IdempotencyInput, operation: StoredOperation
    ) -> IdempotencyResult:
        if not all((value.agent_did, value.command, value.idempotency_key, value.request_hash)):
            raise ValueError("AEP idempotency store received invalid input")
        key = (value.agent_did, value.idempotency_key)
        while True:
            async with self._lock:
                now = self._clock()
                if now.utcoffset() is None:
                    raise ValueError("AEP idempotency clock must return an offset-aware datetime")
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
                        previous.command != value.command
                        or previous.request_hash != value.request_hash
                    ):
                        return IdempotencyResult(None, IdempotencyState.CONFLICT)
                    return IdempotencyResult(response, IdempotencyState.REPLAYED)
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
            return IdempotencyResult(response, IdempotencyState.CREATED)
        finally:
            async with self._lock:
                self._pending.pop(key).set()


class StaticEnrollmentPolicy:
    def __init__(self, decision: EnrollmentDecision | None = None) -> None:
        self._decision = decision or EnrollmentDecision()

    async def decide(self, request: EnrollRequest, current_time: datetime) -> EnrollmentDecision:
        del request, current_time
        return self._decision
