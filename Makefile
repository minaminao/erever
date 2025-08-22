all:
	uv run ruff check --fix
	uv run ruff format
	uv run mypy .
	uv run mypy . --strict"