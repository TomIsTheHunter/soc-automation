install:
	uv sync --extra dev

test:
	python -m pytest

lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy app tests

run:
	uvicorn app.main:app --reload
