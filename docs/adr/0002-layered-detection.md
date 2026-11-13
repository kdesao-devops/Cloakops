# 0002. Layered detection behind a single detector interface

Date: 2026-11-13 · Status: accepted

## Context

Sensitive data in infrastructure content comes in very different shapes:

- **Formatted** values with a recognizable syntax: AWS access keys (`AKIA...`), JWTs, PEM keys,
  IPs, ARNs, account IDs. Deterministic rules catch them reliably and cheaply.
- **Named entities** in prose or comments: people, organizations, places. Need statistical NER.
- **Contextual** values with no fixed shape: a customer name in a Terraform tag, an internal
  project codename. Need a model that reads the context.

No single technique covers all three with good recall, and each extra layer costs latency,
memory and complexity.

## Decision

Three layers, each a `Detector` returning character spans `(start, end, type, confidence,
detector)` over the original text:

1. **Rules** (phase 1): regexes inspired by gitleaks/trufflehog, plus key/value heuristics
   (`password: X`, `"token": "X"`, `secret = "X"`) and an entropy check for unknown secret formats.
2. **NER** (phase 2): Presidio + spaCy for people, organizations and locations.
3. **Local LLM** (phase 2): Ollama running natively on macOS, for contextual entities.

The pipeline unions all spans, then resolves overlaps (longest composite span wins, see ADR 0003).
**A layer is kept only if the benchmark shows it adds recall** for an acceptable precision and
latency cost, including the choice of model size (e.g. 8B vs 14-32B quantized).

## Alternatives rejected

- **LLM only**: slow, non-deterministic, and a local model can still miss an `AKIA...` key that a
  regex never misses. Hard to audit.
- **Rules only**: no way to catch names or contextual entities.
- **Presidio as the framework for everything**: its recognizers target generic PII. Infrastructure
  entities would need custom recognizers anyway, and we want the pipeline to run without spaCy in
  phase 1.

## Consequences

- Phase 1 delivers value with no model and no heavy dependency.
- Every layer is benchmarked against the same corpus, so its contribution is measurable.
- Spans must refer to the original text, which rules out transforming the input between layers.
