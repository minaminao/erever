all: fmt lint type-check

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
