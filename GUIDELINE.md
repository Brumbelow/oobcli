# Repository Guidelines

Minimal, practical rules for contributing to this repository.

## Project Structure & Module Organization
- `src/`: app/library code by feature (e.g., `src/users/`).
- `tests/`: mirrors `src/` (e.g., `tests/users/test_service.py`).
- `scripts/`: helper scripts; keep cross‑platform.
- `docs/`: short notes and diagrams only.

## Build, Test, and Development Commands
- `make setup`: install dependencies.
- `make test`: run unit tests.
- `make lint`: format + lint.
- `make run`: start the app locally.
No Makefile yet? Examples: Python `pip install -r requirements.txt && pytest -q`; Node `npm ci && npm test`.

## Coding Style & Naming Conventions
- Indent 2 spaces; no tabs. Auto‑format on save.
- Python: `black` + `ruff`; JS/TS: `prettier` + `eslint`.
- Names: Classes `PascalCase`; functions/vars `snake_case`; constants `UPPER_SNAKE_CASE`.
- Files: Python `snake_case.py`; JS/TS `kebab-case.ts`.

## Testing Guidelines
- Put tests in `tests/`, mirroring `src/`.
- Test names: `test_*.py`, `*.spec.ts`, or `*.test.ts`.
- Prefer small, deterministic tests; use `tests/fixtures/` when needed.
- Run via `make test`.

## Commit & Pull Request Guidelines
- Conventional Commits (e.g., `feat: add user service`, `fix: handle edge case`).
- PRs: clear description, linked issues, small and focused, include a test plan.
- All checks pass: format, lint, tests.
