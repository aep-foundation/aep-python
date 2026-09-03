#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
consumer=$(mktemp -d)
trap 'rm -rf "$consumer"' EXIT

python=${AEP_PYTHON:-"$repository/.venv/bin/python"}
"$python" -m venv "$consumer/.venv"
requirement=("$repository"/dist/agent_enrollment_protocol-*.whl)
"$consumer/.venv/bin/python" -m pip install --disable-pip-version-check "${requirement[@]}"
"$consumer/.venv/bin/python" - <<'PY'
from agent_enrollment_protocol import __version__
from importlib.metadata import version

from agent_enrollment_protocol import adapters, agent, core, platform, service
from agent_enrollment_protocol.agent import Agent, AgentOptions, HttpxTransport, ServiceIdentity

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
PY
