# CLAUDE.md

Guidance for AI coding assistants working in this repository. Humans: see README.md.

## What this is

cloakops: local, reversible pseudonymization of infrastructure data (Terraform, Kubernetes,
logs, configs) before it is sent to a public LLM, and re-injection of the real values in the
answer. Read `docs/threat-model.md` and `docs/architecture.md` before changing behavior.

## Commands

```bash
uv sync                                  # Python 3.12.16 + pinned deps
uv run pytest                            # tests (Hypothesis property tests included)
uv run ruff check && uv run ruff format --check
uv run mypy                              # strict, src + tests + bench
uv run pre-commit run --all-files        # also gitleaks and detect-private-key
uv run python bench/run.py               # benchmark + recall ratchet (CI gate)
uv run python bench/run.py --update-thresholds   # only after a real improvement
uv run cloakops --help                   # CLI (run from the repo root)
```

## Non-negotiable rules

- **Fail closed.** Any failure in detection, pseudonymization or re-scan raises a
  `FailClosedError` subclass and produces no output. Never degrade to "send as is".
  `--redact` (redact residues) and `--paranoid` (re-run detectors) are explicit options; the
  default blocks (ADR 0014).
- **No values in errors, logs, reports or repr.** Spans hold offsets, never values. Messages
  carry types, counts and positions only. The CLI hides tracebacks unless `CLOAKOPS_DEBUG=1`.
- **Recall first.** A missed value is a leak; over-masking only costs quality. Ambiguous
  candidates are emitted at low confidence, not dropped (ADR 0008).
- **Pseudonyms keep structure and stay coherent** (same entity, same pseudonym across values and
  the session; prefix-preserving IPs; JSON/YAML stay valid) (ADR 0003, 0010).
- Say **pseudonymization**, never anonymization.

## Conventions

- Code, comments, commits, docs: English. Conventional commits (`feat:`, `fix:`, `chore:`),
  one topic per commit.
- **Pin every version** (`==` in pyproject, `uv.lock`, actions by SHA, models by tag/digest).
  Prefer releases at least two weeks old. Runtime dependencies: currently none; adding one is a
  decision (proposal + ADR).
- **Every structural decision gets an ADR**: `docs/adr/NNNN-title.md` (context, decision,
  alternatives rejected, consequences). Amend with a new ADR and mark the old one.
- **Tests never contain realistic secrets as literals**: build them at runtime
  (`tests/_fakes.py`), split PEM markers. Only `bench/corpus/` is allowlisted for secret
  scanners.
- Python's `re` has no timeout and inputs can be hostile: avoid nested quantifiers; new pattern
  shapes get a case in `tests/test_rules_robustness.py` (ReDoS budget).
- Prefer property-based tests (Hypothesis) for invariants: coverage never lost by overlap
  resolution, `unmask(mask(x)) == x`, structural validity of JSON/YAML.
- `x if x is not None else Default()`, never `x or Default()` for objects (a `Session` with
  `__len__` is falsy when empty; this bug silently replaced keys once).

## Benchmark discipline (ADR 0004, 0013)

- Corpora: `synthetic` (templates, regression signal only), `dev` (hand-written, already used
  for fixes), `holdout` (hand-written, never used for tuning).
- A holdout sample that drives a fix moves to `dev`; record its score first in
  `docs/benchmark.md` (results history).
- Each detection layer must prove its contribution (with / without, per model size).
- Report what still leaks, honestly, in `docs/benchmark.md`.

## Environment

- macOS arm64. Local LLMs (Ollama / llama.cpp) run natively for Metal, never in Docker.
- Check free disk space before downloading any model; ask before downloading.
- Local state lives in `$CLOAKOPS_HOME` (default `~/.local/state/cloakops`), never in the repo.
