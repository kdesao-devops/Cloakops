# 0003. Keyed, consistent, structure-preserving pseudonymization

Date: 2026-11-13 · Status: accepted · Amended by ADR 0010 (hostnames, coherence)

## Context

Replacing every value with `[REDACTED]` protects data but ruins the answer: the model can no
longer tell that two log lines involve the same host, that an IP belongs to a CIDR, or that a
string is an ARN for an IAM role. We need pseudonyms that keep the information the model reasons
with, while revealing nothing about the real values.

## Decision

- **Per-session random key** (256 bits). A pseudonym is derived with `HMAC-SHA256(key, type ||
  value)`, then rendered in the entity's format. The output is deterministic within a session
  (same entity → same pseudonym, everywhere in the document and across requests of the session)
  and unlinkable across sessions.
- A **mapping table** (pseudonym → real value) is kept for re-injection and collision handling.
  Phase 1: in memory or a local `0600` file. Phase 3: encrypted at rest with a TTL.
- **Format-preserving generators per entity type**:
  - IPv4/IPv6 and CIDR: **prefix-preserving** permutation in the spirit of Crypto-PAn. Two
    addresses that share an n-bit prefix share an n-bit pseudonymized prefix, so subnets keep
    containing their hosts. Private stays private (RFC 1918 → RFC 1918). Special addresses
    (`0.0.0.0/0`, loopback, `169.254.169.254`, ...) are left untouched: they carry meaning and
    reveal nothing.
  - ARN: partition, service, region and resource type are kept. Account ID and resource name are
    pseudonymized with the same generators used elsewhere, so the account inside an ARN matches
    the same account seen alone.
  - AWS account ID: 12 digits → 12 digits.
  - Secrets: same known prefix and same length (`AKIA` + 16 chars, `ghp_` + 36, ...), and
    unusable: invalid by construction when the vendor format carries a checksum (GitHub tokens),
    otherwise a random value of 100+ bits that matches a real credential only with negligible
    probability. (Corrected 2026-11-14: the first version said "guaranteed invalid".)
  - Hostnames: same label count, internal suffix replaced by a reserved domain (`*.example`).
- Overlapping detections: the longest composite span wins and its generator handles the parts.

## Alternatives rejected

- **Opaque placeholders** (`<IP_1>`, `<SECRET_2>`): simple and robust to re-injection, but the
  model loses all structure (subnet membership, ARN anatomy).
- **Unkeyed hashing**: a 12-digit account ID or an IPv4 address has a tiny input space; an
  attacker can hash every candidate and reverse the pseudonym.
- **Random values + table only**: consistent, but non-deterministic across runs, which makes tests
  and the benchmark harder to reproduce. The keyed derivation gives both.
- **Format-preserving encryption (FF1/FF3-1)**: elegant, but more complex, and some formats
  (ARN, hostnames) are not simple alphabets. Can be revisited for specific types.

## Consequences

- Structure preservation leaks shape (resource types, regions, subnet sizes): accepted and
  documented in the threat model.
- A pseudonym can collide with a real value elsewhere in the text; the generator checks the
  document and retries with a counter.
- The model may alter a pseudonym (drift), which breaks re-injection for that value: measured in
  phase 3.
