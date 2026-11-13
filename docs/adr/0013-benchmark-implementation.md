# 0013. Benchmark implementation: three corpora, design-aware recall, recall ratchet

Date: 2026-11-14 · Status: accepted · Implements ADR 0004

## Context

ADR 0004 set the method (planted values, held-out set, recall first). Implementing it raised
three questions: what to do with holdout samples once they have revealed a bug, how to count a
planted value that the pseudonymizer deliberately leaves partly in clear, and how to gate CI.

## Decision

- **Three corpora**: synthetic (seeded templates), dev (hand-written, already used for fixes),
  holdout (hand-written, never used for tuning). A holdout sample that drives a fix moves to dev;
  the holdout score is recorded before the fix (`docs/benchmark.md`, results history).
- **Ground truth** by construction (synthetic: spans recorded while rendering) or by inline
  markers (`⟦type|value⟧`, characters absent from infrastructure text).
- **Design-aware recall**: a planted value is caught when every character that must be masked is
  covered; characters of generic words the pseudonymizer keeps by design (ADR 0010) are exempt,
  unless the value is made only of generic words.
- **Precision on what is actually masked**: kept values (special IPs, booleans) are neither right
  nor wrong.
- **Each corpus is evaluated with and without propagation**, to measure what it adds; documents
  refused by the re-scan are counted (safe, but unusable).
- **Ratchet gate in CI**: `bench/thresholds.json` stores per-type recall for synthetic and dev;
  CI fails on any drop; `--update-thresholds` raises it after an improvement. Thresholds only go
  up.
- Reports (JSON and Markdown) contain document names, types and positions, never values.

## Alternatives rejected

- **Fixed absolute thresholds** (e.g. 95% recall): arbitrary today, and they would either fail
  CI permanently (prose names before phase 2) or be set so low they catch nothing.
- **Keeping holdout samples after fixing rules on them**: the score would measure the fixes,
  not the tool.
- **Strict character coverage including generic words**: would count as leaks the words the
  design keeps on purpose, and push towards masking everything.

## Consequences

- The keep-list becomes part of what the benchmark evaluates; adding a word to it can raise
  recall, so changes to it deserve review.
- A credible holdout needs samples written by someone other than the author of the rules.
