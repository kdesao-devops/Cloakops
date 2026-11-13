# 0005. Detect on raw text, not on parsed YAML/JSON/HCL (phase 1)

Date: 2026-11-13 · Status: accepted

## Context

Inputs are often structured (YAML manifests, JSON tfstate, HCL). Parsing them would let detection
use the key a value belongs to. But cloakops must replace values **in place** in the original text,
and real inputs are frequently partial, truncated, mixed (a log line embedding JSON), or not valid
at all.

## Decision

Phase 1 works on raw text only. Structure is exploited through **key/value heuristics expressed as
regexes** that work across formats: `key: value`, `"key": "value"`, `key = "value"`, `KEY=value`.
A sensitive key name (`password`, `secret`, `token`, `private_key`, `client_secret`, ...) marks its
value as a secret whatever its shape.

## Alternatives rejected

- **Format-specific parsers** (PyYAML, `python-hcl2`, json): lose character offsets (or require
  position-tracking parsers), fail on invalid or truncated input, and need one code path per
  format.

## Consequences

- One code path for every format, robust to broken input, exact offsets.
- Multi-line values (PEM blocks, YAML block scalars) need dedicated rules.
- If the benchmark shows a gap that only parsing can close, add a parser as an optional
  detector that maps its findings back to offsets (new ADR).
