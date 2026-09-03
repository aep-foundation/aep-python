from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from datetime import UTC, datetime

from .types import CredentialRecord, InspectCacheEntry, OperationKey, ServiceIdentity


class MemoryIdentityStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[str, ServiceIdentity] = {}

    async def find_identity(self, service_did: str) -> ServiceIdentity | None:
        async with self._lock:
            return self._records.get(service_did)

    async def save_identity(self, identity: ServiceIdentity) -> None:
        async with self._lock:
            self._records[identity.service_did] = identity


class MemoryCredentialStore:
    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()
        self._records: dict[tuple[str, str], CredentialRecord] = {}

    async def delete_credential(self, service_did: str, credential_id: str) -> None:
        async with self._lock:
            self._records.pop((service_did, credential_id), None)

    async def find_credential(
        self, service_did: str, credential_id: str
    ) -> CredentialRecord | None:
        async with self._lock:
            key = (service_did, credential_id)
            record = self._records.get(key)
            if record is not None and record.expires_at <= self._clock():
                del self._records[key]
                return None
            return record

    async def list_credentials(self, service_did: str) -> tuple[CredentialRecord, ...]:
        async with self._lock:
            now = self._clock()
            expired = [key for key, value in self._records.items() if value.expires_at <= now]
            for key in expired:
                del self._records[key]
            records = [
                value for value in self._records.values() if value.service_did == service_did
            ]
            return tuple(
                sorted(
                    records, key=lambda value: (-value.issued_at.timestamp(), value.credential_id)
                )
            )

    async def save_credential(self, credential: CredentialRecord) -> None:
        if credential.expires_at <= self._clock():
            raise ValueError("AEP credential expiration must be in the future")
        async with self._lock:
            self._records[(credential.service_did, credential.credential_id)] = credential


class MemoryInspectCache:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[str, InspectCacheEntry] = {}

    async def delete_inspect(self, key: str) -> None:
        async with self._lock:
            self._records.pop(key, None)

    async def find_inspect(self, key: str) -> InspectCacheEntry | None:
        async with self._lock:
            entry = self._records.get(key)
            return _copy_cache_entry(entry) if entry is not None else None

    async def save_inspect(self, key: str, entry: InspectCacheEntry) -> None:
        async with self._lock:
            self._records[key] = _copy_cache_entry(entry)


class RandomIdempotencyKeyProvider:
    async def create_key(self, operation: OperationKey) -> str:
        del operation
        return secrets.token_hex(16)


def _copy_cache_entry(entry: InspectCacheEntry) -> InspectCacheEntry:
    return InspectCacheEntry(
        cached_at=entry.cached_at,
        document=entry.document.model_copy(deep=True),
        final_url=entry.final_url,
        cache_control=entry.cache_control,
        etag=entry.etag,
        last_modified=entry.last_modified,
    )
