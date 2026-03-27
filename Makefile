VENV ?= venv
PYTEST := $(VENV)/bin/pytest

.PHONY: test test-backend

test: test-backend

test-backend:
	$(PYTEST) tests
