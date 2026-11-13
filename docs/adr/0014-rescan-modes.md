# 0014. Re-scan modes: redact by default, fail closed in strict mode

Date: 2026-11-14 · Status: accepted · Amends ADR 0012 · Decided by the project owner

## Context

ADR 0012 made every re-scan finding fatal (`LeakDetectedError`) and always re-ran all detectors
on the output. In interactive use, a single residue then blocks the whole document, and the user
is left with nothing to send; the second full detection doubles the cost of every request,
which matters for the proxy (phase 3) and once NER and a local LLM join the detectors.

## Decision

Three modes:

| Mode | Fast check (originals still in clear) | Full re-detection of the output | On a finding |
|---|---|---|---|
| default | yes | no | redact as `[REDACTED]`, warning on the `cloakops` logger (stderr in the CLI) |
| `--paranoid` | yes | yes | redact + warning |
| `--strict` | yes | yes | `LeakDetectedError` (fail closed), for CI/CD and automation |

- The fast check is a string search for each replaced original value: negligible cost, always on.
- Warnings and errors carry counts and types, never values.
- A finding that overlaps a pseudonym cannot be redacted without corrupting it; it means the
  pipeline itself is wrong, so it fails closed in every mode.
- Detection and pseudonymization failures (`DetectionError`, `PseudonymizationError`) stay fatal
  in every mode: without a detection result there is nothing to redact against.
- `MaskResult.redactions` lists what was redacted, for the audit receipt; replacement offsets
  are shifted to the redacted text.

## Alternatives rejected

- **Fail closed by default** (ADR 0012): safest on paper, but a tool that refuses whole documents
  gets bypassed (copy-paste into the chat directly), which is worse.
- **Redact silently**: hides detection gaps; the warning keeps them visible and the benchmark
  counts them.
- **Always run the full re-detection**: doubles latency for a check that, with deterministic
  rules, mostly finds nothing new; it matters once detectors are context-dependent (NER, LLM),
  which is when `--paranoid` / `--strict` are worth their cost.

## Consequences

- In default and paranoid modes, a residue costs answer quality (`[REDACTED]` carries no
  structure, cannot be restored) instead of availability.
- `[REDACTED]` written unquoted in YAML parses as a list (`key: [REDACTED]`): the output can
  change shape where a residue is redacted. Acceptable for a residue (an anomaly by definition);
  the marker is configurable.
- Benchmark: documents with redactions and leaks remaining in the final output are reported
  separately from detection leaks.
