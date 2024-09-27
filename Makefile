fmt:
	isort erever/*.py
	isort tests/*.py
	ruff format .

docker-test:
	docker build . -t erever
