# 0001. Python 3.12 managed by uv for the MVP

Date: 2026-11-13 · Status: accepted

## Context

The MVP needs the Python NLP ecosystem (Presidio, spaCy, Ollama clients in phase 2). The host
ships Python 3.15, which is newer than what the NLP libraries publish binary wheels for. Every
dependency, every tool and the interpreter itself must be pinned and reproducible on a laptop and
in CI.

## Decision

- Python **3.12.16**, pinned in `.python-version` and `requires-python = ">=3.12.16,<3.13"`.
- **uv** manages the interpreter, the virtualenv and the lockfile (`uv.lock`, with hashes).
- Exact pins (`==`) in `pyproject.toml`; CI runs `uv sync --locked` and fails if the lock is stale.
- Python tooling in pre-commit runs through `uv run`, so there is one source of versions.

## Alternatives rejected

- **System Python 3.15**: too new for spaCy/Presidio wheels; would force source builds.
- **pip + venv + pip-tools**: works, but three tools for what uv does in one, and no interpreter
  management.
- **Poetry**: slower, own lockfile format, no interpreter management.
- **Go from day one**: better for a high-throughput proxy, but the NER/LLM ecosystem is Python.
  A Go rewrite of the proxy stays open if phase 3 measurements justify it.

## Consequences

- New contributors need uv (`brew install uv`); everything else is bootstrapped by `uv sync`.
- Upgrading Python is a deliberate change (new ADR if it crosses a minor version).
