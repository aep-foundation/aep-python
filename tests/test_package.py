from importlib.metadata import version

from agent_enrollment_protocol import __version__, adapters, agent, core, platform, service
from agent_enrollment_protocol.adapters import AepAsgiApplication, AepAuthenticationMiddleware
from agent_enrollment_protocol.agent import Agent, AgentOptions, HttpxTransport, ServiceIdentity
from agent_enrollment_protocol.core import ClaimSupportEvaluation, evaluate_claim_support
from agent_enrollment_protocol.service import (
    MemoryServiceCredentialStore,
    Service,
    ServiceOptions,
    stored_api_key_grant_type,
    stored_basic_grant_type,
    stored_oauth_bearer_grant_type,
)


def test_public_package_modules() -> None:
    assert __version__ == version("agent-enrollment-protocol")
    assert adapters.__name__ == "agent_enrollment_protocol.adapters"
    assert agent.__name__ == "agent_enrollment_protocol.agent"
    assert core.__name__ == "agent_enrollment_protocol.core"
    assert platform.__name__ == "agent_enrollment_protocol.platform"
    assert service.__name__ == "agent_enrollment_protocol.service"
    assert Agent.__module__ == "agent_enrollment_protocol.agent.client"
    assert AgentOptions.__module__ == "agent_enrollment_protocol.agent.client"
    assert HttpxTransport.__module__ == "agent_enrollment_protocol.agent.transport"
    assert ServiceIdentity.__module__ == "agent_enrollment_protocol.agent.types"
    assert Service.__module__ == "agent_enrollment_protocol.service.service"
    assert ServiceOptions.__module__ == "agent_enrollment_protocol.service.types"
    assert AepAsgiApplication.__module__ == "agent_enrollment_protocol.adapters.asgi"
    assert AepAuthenticationMiddleware.__module__ == "agent_enrollment_protocol.adapters.asgi"
    assert ClaimSupportEvaluation.__module__ == "agent_enrollment_protocol.core.claims"
    assert evaluate_claim_support.__module__ == "agent_enrollment_protocol.core.claims"
    assert (
        MemoryServiceCredentialStore.__module__ == "agent_enrollment_protocol.service.credentials"
    )
    for factory in (
        stored_api_key_grant_type,
        stored_basic_grant_type,
        stored_oauth_bearer_grant_type,
    ):
        assert factory.__module__ == "agent_enrollment_protocol.service.credentials"
