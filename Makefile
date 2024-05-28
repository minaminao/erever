all: fmt lint type-check-strict test docker-test

fmt:
	isort erever/*.py
	isort tests/*.py
	ruff format .

lint:
	ruff check .

lint-fix:
	ruff check . --fix

type-check:
	mypy . --ignore-missing-imports

type-check-strict:
	mypy . --strict --ignore-missing-imports

test:
	pytest

docker-test:
	docker build . -t erever
