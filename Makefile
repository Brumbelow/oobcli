SHELL := /bin/bash

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

.PHONY: setup test lint run help release install

help:
	@echo "Targets: setup, test, lint, run"

setup:
	@echo "==> Setup"
	@if [ -f package.json ]; then \
		echo "Using Node: npm ci"; \
		npm ci; \
	elif [ -f pyproject.toml ]; then \
		if command -v uv >/dev/null 2>&1; then \
			echo "Using Python (uv): uv sync"; \
			uv sync; \
		else \
			echo "Using Python (venv+pip)"; \
			python -m venv .venv && . .venv/bin/activate && pip install -U pip; \
			if [ -f requirements.txt ]; then pip install -r requirements.txt; else pip install -e .; fi; \
		fi; \
	elif [ -f requirements.txt ]; then \
		echo "Using Python (venv+pip)"; \
		python -m venv .venv && . .venv/bin/activate && pip install -U pip && pip install -r requirements.txt; \
	elif [ -f go.mod ]; then \
		echo "Using Go (no setup needed)"; \
	else \
		echo "No known dependency manifest found (package.json/pyproject.toml/requirements.txt)."; \
	fi

test:
	@echo "==> Test"
	@if [ -f package.json ]; then \
		echo "Running: npm test"; \
		npm test; \
	elif [ -d tests ] || [ -f pyproject.toml ] || [ -f requirements.txt ]; then \
		[ -d .venv ] && . .venv/bin/activate || true; \
		if command -v pytest >/dev/null 2>&1; then pytest -q; else echo "pytest not installed"; exit 1; fi; \
	elif [ -f go.mod ]; then \
		echo "Running: go test ./..."; \
		go test ./...; \
	else \
		echo "No test configuration found."; \
	fi

lint:
	@echo "==> Lint/Format"
	@if [ -f package.json ]; then \
		npx eslint . --fix || true; \
		npx prettier -w . || true; \
	fi; \
	[ -d .venv ] && . .venv/bin/activate || true; \
	if command -v ruff >/dev/null 2>&1; then ruff check --fix .; else echo "ruff not installed (skip)"; fi; \
	if command -v black >/dev/null 2>&1; then black -q .; else echo "black not installed (skip)"; fi; \
	if [ -f go.mod ]; then \
		echo "Formatting Go with gofmt"; \
		gofmt -s -w .; \
		if command -v go >/dev/null 2>&1; then go vet ./... || true; fi; \
	fi

run:
	@echo "==> Run"
	@if [ -f package.json ]; then \
		npm start || npm run dev; \
	elif [ -d src ]; then \
		[ -d .venv ] && . .venv/bin/activate || true; \
		python -m src || python app.py || (echo "Define an entrypoint (python -m src or app.py)." && exit 1); \
	elif [ -f go.mod ]; then \
		go run ./cmd/oobcli --help; \
	else \
		echo "Nothing to run yet."; \
	fi

.PHONY: release
release:
	@echo "==> Release build"
	bash scripts/release.sh

install:
	@echo "==> Install to $(BINDIR)"
	@mkdir -p .bin
	GOCACHE=$(PWD)/.gocache go build -trimpath -ldflags "-s -w" -o .bin/oobcli ./cmd/oobcli
	install -m 0755 .bin/oobcli $(BINDIR)/oobcli
	@echo "Installed to $(BINDIR)/oobcli"
