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
	mypy .

type-check-strict:
	mypy . --strict

test:
	pytest

docker-test:
	docker build . -t erever
