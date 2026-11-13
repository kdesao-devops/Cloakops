# 0014. Re-scan modes: fail closed by default, `--redact` and `--paranoid` on demand

Date: 2026-11-14 · Status: accepted · Amends ADR 0012 · Decided by the project owner

Revision (same day): a first version redacted residues by default and reserved fail-closed for a
`--strict` option. The owner reverted it: redaction must be an explicit command-line choice, not
a default. `--strict` disappeared since the default already fails closed.

## Context

ADR 0012 made every re-scan finding fatal and always re-ran all detectors on the output. Two
needs came up: an interactive user may prefer an answer with `[REDACTED]` holes over no answer
at all, and the second full detection doubles the cost of every request (the proxy in phase 3,
NER and a local LLM in phase 2).

## Decision

| | Fast check (replaced originals still in clear) | Full re-detection of the output | On a finding |
|---|---|---|---|
| default | yes | no | `LeakDetectedError`: fail closed, nothing is sent |
| `--redact` | yes | no | replaced by `[REDACTED]`, warning on the `cloakops` logger (stderr) |
| `--paranoid` | yes | yes | fail closed (or redacted if combined with `--redact`) |

- The fast check is a string search per replaced original value: negligible cost, always on.
- Errors and warnings carry counts and types, never values.
- A finding that overlaps a pseudonym cannot be redacted without corrupting it: it means the
  pipeline itself is wrong, so it fails closed even with `--redact`.
- Detection and pseudonymization failures are fatal in every mode.
- `MaskResult.redactions` lists what was redacted, for the audit receipt; replacement offsets are
  shifted to the redacted text.

## Alternatives rejected

- **Redact by default** (first version of this ADR): makes the tool more convenient, but turns a
  detection gap into a silent-looking degradation; the owner wants that trade-off to be chosen
  explicitly, per invocation.
- **Warn and send the residue in clear**: contradicts the fail-closed principle of the threat
  model.
- **Always run the full re-detection**: doubles latency for a check that, with deterministic
  rules, rarely finds anything new; it is worth its cost once detectors are context-dependent.

## Consequences

- Benchmark (synthetic, propagation off): the default blocks 62 documents (none leaks among
  them); `--redact` lets them through with holes, and 80 documents still leak values that were
  never detected anywhere, which no re-scan can catch.
- `[REDACTED]` written unquoted in YAML parses as a list (`key: [REDACTED]`): with `--redact`,
  the output can change shape where a residue is redacted. The marker is configurable.
