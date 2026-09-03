from importlib.metadata import version

from agent_enrollment_protocol import __version__, adapters, agent, core, platform, service
from agent_enrollment_protocol.agent import Agent, AgentOptions, HttpxTransport, ServiceIdentity
from agent_enrollment_protocol.service import Service, ServiceOptions


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
