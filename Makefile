.PHONY: build consumer-smoke format format-check lint sync test typecheck verify

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

verify: lint typecheck test consumer-smoke
