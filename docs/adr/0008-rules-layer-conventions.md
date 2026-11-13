# 0008. Rules layer conventions: confidence, ReDoS budget, runtime-built test secrets

Date: 2026-11-13 · Status: accepted

## Context

The rules layer (ADR 0002, layer 1) is a set of independent rules over raw text (ADR 0005). Three
questions come up for every rule: how sure is it, can it be abused, and how do we test it
without committing secrets.

## Decision

**Confidence levels.** Every span carries a confidence used by the resolver (ADR 0006) and, later,
by the policy (risk level):

| Confidence | Meaning | Examples |
|---|---|---|
| 1.0 | Unambiguous format or explicit context | `AKIA...`, `ghp_...`, PEM block, ARN, `"AccountId": "123456789012"` |
| 0.8-0.9 | Sensitive field name, value of unknown shape | `password: x`, `client: Acme`, `bucket = "x"` |
| 0.7 | Field that references a secret | `password_secret_arn`, `secretName` |
| 0.6 | Ambiguous format, recall first | any bare 12-digit number as an AWS account ID |
| 0.5 | Statistical guess | high-entropy strings |

Ambiguous candidates are emitted at low confidence rather than dropped: dropping is a potential
leak, a low-confidence span is a decision left to the policy.

**ReDoS budget.** Inputs may be attacker-controlled (logs), and Python's `re` has no timeout.
Rules avoid nested quantifiers over overlapping classes, and parsing that would rescan the rest
of a line per match is guarded (keys inside an already-emitted value are skipped). A test runs
the full rule set on ~100 KB pathological inputs under a 2 s budget. It caught a quadratic case
(`password: password: ...`, 8 s) during development.

**Test secrets are built at runtime** (`tests/_fakes.py`: prefix + seeded random characters, PEM
markers split across string literals). Secret scanners keep running on the whole test tree with
no allowlist; only the benchmark corpus is allowlisted (ADR 0004).

## Alternatives rejected

- **Drop ambiguous candidates** (precision first): contradicts the recall-first goal.
- **`regex` module with timeouts** instead of `re`: extra dependency, and a timeout that fires
  means fail-closed, i.e. an unusable tool on that input. Better to keep patterns linear.
- **Allowlist `tests/` in gitleaks**: a real secret pasted in a test would go unnoticed.
- **`# gitleaks:allow` on every test line**: noisy, and easy to copy onto a real secret.

## Consequences

- Confidence values are hand-set; the benchmark will tell whether they are well calibrated.
- New rules need a pathological-input check in the robustness test when they add a new pattern
  shape.
