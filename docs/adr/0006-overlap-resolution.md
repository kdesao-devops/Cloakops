# 0006. Overlap resolution: relabel or fuse, never uncover

Date: 2026-11-13 · Status: accepted

## Context

Detectors run independently and their spans overlap in three ways:

- **Nested**: an ARN contains an account ID; a connection-string secret contains a hostname.
- **Identical range, different types**: a key/value heuristic (`GENERIC_SECRET`) and an access-key
  rule (`AWS_ACCESS_KEY_ID`) on the same value.
- **Partial**: two detections that cross without one containing the other (typically boundary
  disagreements between a regex and a model).

Replacement needs disjoint spans. Any resolution that drops part of a detection would put
detected characters back in clear.

## Decision

Group overlapping spans into clusters (transitively), then resolve each cluster:

1. If one or more detections cover the **whole cluster**, keep the highest-priority one. The
   outer span wins even when an inner span is more sensitive: masking the outer span masks the
   inner one too, and its pseudonymizer handles the parts (the ARN generator pseudonymizes its
   account ID with the account-ID generator, which keeps both consistent).
2. Otherwise, **fuse** the cluster into one span over the union, typed after the
   highest-priority member and flagged `merged=True`. The fused text has no known format, so
   pseudonymizers use an opaque placeholder of that type.

Priority: category (credential > personal > infrastructure), then specific over generic types,
then confidence; names break the remaining ties so the result is deterministic.

**Invariant, property-tested with Hypothesis:** the resolved spans cover exactly the characters
covered by the input spans. Also tested: output sorted and disjoint, idempotent, independent of
input order.

Spans store offsets, never values, so they can appear in errors, logs and audit receipts safely.

## Alternatives rejected

- **Keep the highest-priority span, drop the others** (classic NER post-processing): on partial
  overlaps it leaves the non-shared characters in clear. A leak by construction.
- **Truncate the losing span to its non-overlapping part**: masks everything but produces
  meaningless fragments with misleading types.
- **Keep the most sensitive span even when nested** (inner secret wins over outer hostname): would
  require splitting the outer span and pseudonymizing pieces of it independently, which breaks
  its structure for no confidentiality gain.

## Consequences

- Partial overlaps lose structure preservation for that value (opaque placeholder). The benchmark
  counts merged spans; a high count points at a detector with bad boundaries.
- Generators of composite types (ARN, URL, connection strings) must handle their inner entities.
