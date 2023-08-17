all: fmt lint type-check-strict test

fmt:
	isort erever/*.py
	black --line-length 120 .

lint:
	ruff check .

lint-fix:
	ruff check . --fix

type-check:
	mypy .

type-check-strict:
	mypy . --strict

test:
	pytest
