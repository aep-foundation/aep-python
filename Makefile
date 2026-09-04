.PHONY: build conformance consumer-smoke examples format format-check interoperability lint sync test typecheck verify

sync:
	uv sync --all-groups --locked

format:
	uv run ruff format .
	uv run ruff check --fix .

format-check:
	uv run ruff format --check .
	uv run ruff check .

lint: format-check

typecheck:
	uv run mypy

test:
	uv run pytest

build:
	rm -rf dist
	uv build
	uv run twine check dist/*

consumer-smoke: build
	./scripts/verify-consumer.sh

examples:
	uv run python examples/agent_service.py
	uv run python examples/hosted_platform.py

conformance:
	./scripts/run-conformance.sh

interoperability:
	uv run mypy scripts/node_interoperability.py
	./scripts/run-node-interoperability.sh

verify: lint typecheck test examples consumer-smoke
