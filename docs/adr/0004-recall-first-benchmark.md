# 0004. Recall-first benchmark with a held-out corpus

Date: 2026-11-13 · Status: accepted

## Context

The value of the project is a claim: "it catches what matters in infrastructure data". That claim
must be measurable from day one, per entity type, and the measurement must not be fooled by the
author writing both the detectors and the test data.

## Decision

- **Ground truth by construction**: a seeded generator (`bench/generate.py`, stdlib `random`)
  plants known values into realistic templates (Terraform plans, tfstate, Kubernetes manifests,
  CloudTrail JSON, application/nginx logs, `.env` files) and records each value's exact character
  span. No manual labeling.
- **Held-out set**: hand-written samples in `bench/corpus/holdout/`, in formats the generator does
  not produce, annotated by hand, and never used to tune rules. Headline numbers come from this
  set.
- **Metrics, per entity type**:
  - Recall = TP / (TP + FN). A false negative is a leak.
  - Precision = TP / (TP + FP). A false positive is over-masking: it hurts answer quality only.
  - **Per-document leak rate**: a document fails if a single value leaks.
- **Matching rule**: a planted value counts as caught if every one of its characters is covered by
  some detected span (quotes or a wider span are fine). A detection counts as a false positive if
  it covers no planted value.
- **CI gate**: the benchmark runs in CI and fails if recall for any entity type drops below its
  threshold.

## Alternatives rejected

- **Exact span match**: penalizes harmless boundary differences (a key detected with its quotes)
  and does not reflect the security question "did it leave in clear?".
- **F1 score as the headline**: weighs precision and recall equally, while one leak costs far more
  than one over-mask. If a single score is needed, use F2 (recall weighted ×2), but publish recall
  separately.
- **Public PII datasets**: generic personal data, no infrastructure entities.
- **Only synthetic data**: the rules would end up matching the templates rather than reality.

## Consequences

- The held-out set needs discipline: once a sample has been used to fix a rule, it moves to the
  synthetic/dev set and a new held-out sample is written.
- The corpus contains realistic fake secrets, so it is allowlisted for gitleaks and
  `detect-private-key` (`.gitleaks.toml`, `.pre-commit-config.yaml`).
