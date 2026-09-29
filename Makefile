PYTHON ?= python

.PHONY: generate check test integration

generate:
	$(PYTHON) scripts/unasync.py

check:
	$(PYTHON) scripts/unasync.py --check
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy src tests scripts

test:
	$(PYTHON) -m pytest

integration:
	$(PYTHON) -m pytest -m integration
