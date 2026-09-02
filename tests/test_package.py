from importlib.metadata import version

from agent_enrollment_protocol import __version__, adapters, agent, core, platform, service


def test_public_package_modules() -> None:
    assert __version__ == version("agent-enrollment-protocol")
    assert adapters.__name__ == "agent_enrollment_protocol.adapters"
    assert agent.__name__ == "agent_enrollment_protocol.agent"
    assert core.__name__ == "agent_enrollment_protocol.core"
    assert platform.__name__ == "agent_enrollment_protocol.platform"
    assert service.__name__ == "agent_enrollment_protocol.service"
