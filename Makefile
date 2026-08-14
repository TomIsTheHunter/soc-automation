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

audit:
	uv export --extra dev --no-hashes -o requirements-audit.txt
	pip-audit -r requirements-audit.txt --progress-spinner off
	rm -f requirements-audit.txt

screenshots:
	uv sync --extra screenshots
	playwright install chromium
	python scripts/capture_screenshots.py
