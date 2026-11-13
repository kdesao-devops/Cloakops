# Design review: pseudonymization (phase 1, step 1.3)

Date: 2026-11-13 · Reviewer: project owner · Outcome: approved

Decisions reviewed on the output of a sample Terraform state (bucket, ARNs, account, CIDR, node
names, ECR image, emails) and approved as is. Details and rejected alternatives are in the linked
ADRs; this page records what was explicitly validated and why.

| Decision | Why it was approved | Reference |
|---|---|---|
| Prefix-preserving IP permutation | Hosts stay in their subnets, private stays private, special addresses untouched: the model can still reason about the network | ADR 0003, ADR 0010 |
| Coherence across composite values (bucket, account, cluster, IP, organization word) | The model can follow one resource across plan, ARN, endpoint and logs | ADR 0010 |
| Fail-closed engine: after 32 rejected candidates, `PseudonymizationError`, nothing produced, error messages never carry the value (tested) | A pseudonymization failure must never turn into sending clear text or logging it | ADR 0010, `src/cloakops/pseudo/engine.py` |
| Passwords do not keep their shape (fixed 16 alphanumeric characters) | Length and character-class pattern help an attacker and give the model nothing | ADR 0010 |
| Generic words kept in names (`prod`, `logs`, `Industries`, `eu-west-1`); a value made only of generic words is still masked | Keeps what the model needs, hides what identifies; no leak through the keep-list | ADR 0010 |
| No separate "format repair" pass: generators emit a valid value directly | The type is known at generation time; a repair pass would have to rediscover it | ADR 0010 |

Follow-ups noted during the review:

- `--preamble` CLI option telling the model that values are consistent pseudonyms to reuse
  verbatim (step 1.7); system message in the proxy (phase 3).
- Secrets embedded in composite secrets (hostname inside a connection string) are masked as a
  whole and lose coherence with the standalone value.
