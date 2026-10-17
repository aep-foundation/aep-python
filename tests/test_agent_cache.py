from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_enrollment_protocol.agent import (
    Agent,
    AgentOptions,
    InspectCacheEntry,
    PlatformDiscoveryCacheEntry,
)
from agent_enrollment_protocol.agent.transport import _fresh_cache

from .test_agent import FakeIdentityProvider, response
from .test_agent_platform_provider import QueueTransport, discovery, json_response, listed, provider
from .test_core_models import inspect_document

NOW = datetime(2026, 9, 3, 12, tzinfo=UTC)
DATE = "Thu, 03 Sep 2026 12:00:00 GMT"


@pytest.mark.parametrize("hosted", [False, True])
@pytest.mark.parametrize(
    "headers",
    [
        {"Cache-Control": "max-age=60", "Age": "120"},
        {"Date": DATE, "Expires": "Thu, 03 Sep 2026 11:59:59 GMT"},
        {"Cache-Control": "max-age=60", "Date": "Thu, 03 Sep 2026 11:58:00 GMT"},
        {"Expires": "invalid"},
        {"Cache-Control": "max-age=300", "Age": "invalid"},
    ],
)
@pytest.mark.asyncio
async def test_public_discovery_revalidates_expired_http_metadata(
    hosted: bool, headers: dict[str, str]
) -> None:
    if hosted:
        wire = QueueTransport(
            json_response(discovery(), headers={**headers, "ETag": '"one"'}),
            json_response(listed()),
            json_response({}, status=304),
            json_response(listed()),
        )
        identities = provider(wire, clock=lambda: NOW)
        await identities.find_identity_by_service_did("did:web:api.example.com")
        await identities.find_identity_by_service_did("did:web:api.example.com")
        requests = [
            item for item in wire.requests if item.url.endswith("/.well-known/aep-platform")
        ]
    else:
        wire = QueueTransport(
            response(inspect_document().to_wire(), headers={**headers, "ETag": '"one"'}),
            response({}, status=304),
        )
        agent = Agent(
            AgentOptions(
                identity_provider=FakeIdentityProvider(),
                clock=lambda: NOW,
                inspect_transport=wire,
                command_transport=wire,
            )
        )
        await agent.service("https://api.example.com").inspect()
        await agent.service("https://api.example.com").inspect()
        requests = wire.requests
    assert len(requests) == 2
    assert requests[1].headers["If-None-Match"] == '"one"'


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True])
async def test_conditional_revalidation_merges_expiry_and_resets_response_age(hosted: bool) -> None:
    entry: InspectCacheEntry | PlatformDiscoveryCacheEntry | None
    clock = [NOW]
    headers = {
        "Date": DATE,
        "Expires": "Thu, 03 Sep 2026 12:02:00 GMT",
        "Age": "119",
        "ETag": '"one"',
    }
    if hosted:
        wire = QueueTransport(
            json_response(discovery(), headers=headers),
            json_response(listed()),
            json_response({}, status=304, headers={"Date": "Thu, 03 Sep 2026 12:00:02 GMT"}),
            json_response(listed()),
            json_response(listed()),
        )
        identities = provider(wire, clock=lambda: clock[0])
        await identities.find_identity_by_service_did("did:web:api.example.com")
        clock[0] += timedelta(seconds=2)
        await identities.find_identity_by_service_did("did:web:api.example.com")
        await identities.find_identity_by_service_did("did:web:api.example.com")
        requests = [
            item for item in wire.requests if item.url.endswith("/.well-known/aep-platform")
        ]
        entry = await identities._discovery_cache.find(
            "https://platform.example/.well-known/aep-platform"
        )
    else:
        wire = QueueTransport(
            response(inspect_document().to_wire(), headers=headers),
            response({}, status=304, headers={"Date": "Thu, 03 Sep 2026 12:00:02 GMT"}),
        )
        agent = Agent(
            AgentOptions(
                identity_provider=FakeIdentityProvider(),
                clock=lambda: clock[0],
                inspect_transport=wire,
                command_transport=wire,
            )
        )
        await agent.service("api.example.com").inspect()
        clock[0] += timedelta(seconds=2)
        await agent.service("api.example.com").inspect()
        await agent.service("api.example.com").inspect()
        requests = wire.requests
        entry = await agent._inspect_cache.find_inspect("https://api.example.com/.well-known/aep")
    assert len(requests) == 2
    assert entry is not None
    assert entry.age == ""
    assert entry.expires == headers["Expires"]
    assert entry.etag == '"one"'


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True])
async def test_response_delay_counts_toward_freshness(hosted: bool) -> None:
    from agent_enrollment_protocol.core import HttpRequest, HttpResponse

    clock = [NOW]

    class SlowResponse(QueueTransport):
        async def send(self, request: HttpRequest) -> HttpResponse:
            if len(self.requests) == 0:
                clock[0] += timedelta(seconds=65)
            return await super().send(request)

    headers = {"Cache-Control": "max-age=60", "Age": "0"}
    if hosted:
        wire = SlowResponse(
            json_response(discovery(), headers=headers),
            json_response(listed()),
            json_response(discovery()),
            json_response(listed()),
        )
        identities = provider(wire, clock=lambda: clock[0])
        await identities.find_identity_by_service_did("did:web:api.example.com")
        await identities.find_identity_by_service_did("did:web:api.example.com")
        assert len(wire.requests) == 4
    else:
        wire = SlowResponse(
            response(inspect_document().to_wire(), headers=headers),
            response(inspect_document().to_wire()),
        )
        agent = Agent(
            AgentOptions(
                identity_provider=FakeIdentityProvider(),
                clock=lambda: clock[0],
                command_transport=wire,
                inspect_transport=wire,
            )
        )
        await agent.service("api.example.com").inspect()
        await agent.service("api.example.com").inspect()
        assert len(wire.requests) == 2


@pytest.mark.parametrize(
    "changes, fresh",
    [
        ({}, True),
        ({"now": NOW + timedelta(seconds=300)}, False),
        ({"now": NOW - timedelta(seconds=1)}, False),
        ({"cache_control": "max-age=60", "age": "59"}, True),
        ({"cache_control": "max-age=60", "age": "60"}, False),
        ({"cache_control": "max-age=60", "age": "-1"}, False),
        ({"cache_control": "max-age=60", "age": "\u0661"}, False),
        ({"cache_control": "max-age=-1"}, False),
        ({"cache_control": "max-age=\u0661"}, False),
        ({"cache_control": 'max-age="60"', "expires": "invalid"}, True),
        ({"date": "invalid"}, False),
        ({"expires": "Thu, 03 Sep 2026 12:00:01 GMT"}, True),
        ({"expires": "Thu, 03 Sep 2026 12:00:01"}, True),
    ],
)
def test_http_freshness_rules(changes: dict[str, object], fresh: bool) -> None:
    from typing import Any

    arguments: dict[str, Any] = dict(
        cache_control="", cached_at=NOW, now=NOW, age="", date="", expires=""
    )
    arguments.update(changes)
    assert _fresh_cache(**arguments) is fresh
