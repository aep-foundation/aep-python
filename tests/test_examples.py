from __future__ import annotations

import importlib.util
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from agent_enrollment_protocol.agent import ServiceSession
from agent_enrollment_protocol.core import AepAssertionError, AgentStatus, ManagedAgentStatus
from agent_enrollment_protocol.platform import Platform


def example(name: str) -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "examples" / f"{name}.py"
    specification = importlib.util.spec_from_file_location(f"aep_example_{name}", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["enroll", "status"])
async def test_agent_example_fails_when_agent_is_not_active(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    module = example("agent_service")
    original = getattr(ServiceSession, method)

    async def inactive(self: ServiceSession, *args: Any, **kwargs: Any) -> Any:
        result = await original(self, *args, **kwargs)
        return replace(
            result, body=result.body.model_copy(update={"status": AgentStatus.SUSPENDED})
        )

    monkeypatch.setattr(ServiceSession, method, inactive)
    with pytest.raises(RuntimeError, match=r"active Agent|become active"):
        await module.main()


@pytest.mark.asyncio
async def test_platform_example_fails_when_discovery_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    module = example("hosted_platform")
    original = Platform.discovery

    def unavailable(self: Platform) -> Any:
        return replace(original(self), status=503, body=None)

    monkeypatch.setattr(Platform, "discovery", unavailable)
    with pytest.raises(RuntimeError, match="discovery metadata"):
        await module.main()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["list", "update_identity", "sign"])
async def test_platform_example_rejects_incorrect_success_results(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    module = example("hosted_platform")
    original = getattr(Platform, method)

    async def incorrect(self: Platform, *args: Any, **kwargs: Any) -> Any:
        result = await original(self, *args, **kwargs)
        changes: dict[str, object]
        if method == "list":
            changes = {"count": "0", "data": ()}
        elif method == "update_identity":
            changes = {"status": ManagedAgentStatus.ACTIVE}
        else:
            changes = {"client_assertion": "invalid.signature.value"}
        return replace(result, body=result.body.model_copy(update=changes))

    monkeypatch.setattr(Platform, method, incorrect)
    error = AepAssertionError if method == "sign" else RuntimeError
    with pytest.raises(error):
        await module.main()


@pytest.mark.asyncio
async def test_platform_example_detects_signing_after_suspension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = example("hosted_platform")
    original = Platform.sign
    completed: list[Any] = []

    async def ignores_suspension(self: Platform, *args: Any, **kwargs: Any) -> Any:
        if completed:
            return completed[0]
        result = await original(self, *args, **kwargs)
        completed.append(result)
        return result

    monkeypatch.setattr(Platform, "sign", ignores_suspension)
    with pytest.raises(RuntimeError, match="suspended identity"):
        await module.main()
