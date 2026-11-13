# 0012. Exact-value propagation, output re-scan and one fail-closed pipeline

Date: 2026-11-14 · Status: accepted · Extends ADR 0007 · Amended by ADR 0014 (re-scan modes)

## Context

ADR 0007 planned session propagation of name words (`client: Jacquil` → every `Jacquil`) and a
seed dictionary. Two gaps remained:

- a **secret** detected once (`password: S3cr3t`) may appear elsewhere where no rule fires
  (`echo S3cr3t | docker login`);
- nothing verified the **output** independently of the code that produced it. Detection and
  pseudonymization can have bugs; the threat model makes a leak the main risk (T4).

## Decision

**Pipeline** (`cloakops.pipeline.Pipeline`), per session:

```
detect -> resolve -> learn + propagate -> resolve -> pseudonymize -> re-scan
```

`mask` returns text that is safe to send or raises a `FailClosedError` (detection failure, no
acceptable pseudonym, leak found by the re-scan). No partial result exists.

**Propagation**, terms kept for the whole session:

- *exact values* of every detected type, case-sensitive, alphanumeric boundaries;
- *name words* (organization, person, project, bucket, cluster) from sources with confidence
  >= 0.8, any case, `_` and `-` as separators (`JACQUIL_API_KEY`, `jacquil-prod-eks`);
- the *seed dictionary*: one term per line, optional `person:` / `project:` prefix; refused if
  readable by group or others (it lists real sensitive names, like an SSH key lists access).

**Output re-scan**, two independent checks on the output text:

1. no replaced original value appears in it (alphanumeric boundaries);
2. the detectors, run again, find nothing that is neither a session pseudonym nor inside a
   replaced region (catches context-dependent misses and pipeline bugs).

Findings carry positions and types, never values.

**One definition of "distinctive"** (`propagate.is_distinctive`): at least 4 characters, some
letter or digit, not made only of generic words, not a common word. Propagation searches only
distinctive values, and the re-scan checks only distinctive values. They must agree: a value
deliberately not propagated (`client: error`) would otherwise be reported as a leak wherever
"error" is used as an ordinary word, blocking every document.

## Alternatives rejected

- **Re-scan only with the detectors**: deterministic rules on unchanged regions find the same
  things twice; the value-based check is what catches a pseudonymizer bug.
- **Re-scan that masks what it finds instead of failing**: a finding means the pipeline is
  wrong; silently patching the output hides the bug. Better fail closed and fix.
- **Propagate every detected value, distinctive or not**: `pin: 42` would mask every "42";
  `client: the` would mask every "the" (poisoning by attacker-controlled logs).

## Consequences

- Residual risk, accepted and documented: non-distinctive values (short secrets like a 3-digit
  PIN, a password equal to a common word) are masked where detected but neither propagated nor
  leak-checked.
- Session memory holds raw values (like the mapping table): it must get the same protection in
  phase 3 (encrypted vault, TTL).
- Booleans and nulls (`true`, `off`, `null`) are kept as is: no pseudonym can keep their YAML type
  while differing from them, and they carry no information.
