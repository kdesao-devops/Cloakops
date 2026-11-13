# Architecture

Status: phase 0. Describes the target for phase 1; later phases extend it.

## Pipeline

```
input text
   │
   ▼
[detectors] ──► spans over the ORIGINAL text (start, end, type, confidence, detector)
   │             rules (phase 1) · NER (phase 2) · local LLM (phase 2)
   ▼
[resolve overlaps] ── outer span wins; partial overlaps are fused (ADR 0006)
   ▼
[propagate] ── values found in a strong context (`client: Acme`) or in the seed dictionary
   │           are searched everywhere, variants included (`ACME`, `acme-prod-eks`),
   │           and across the session (ADR 0007)
   ▼
[pseudonymize] ── per-session HMAC key + per-type format-preserving generators
   │              mapping table: pseudonym → real value
   ▼
[re-scan output] ── original value left? → [REDACTED] + warning; --strict: fail closed;
   │                 --paranoid/--strict: also re-run every detector (ADR 0012, 0014)
   ▼
pseudonymized text ──► LLM ──► answer ──► [re-inject] ──► answer with real values
```

## Package layout (phase 1 target)

```
src/cloakops/
├── cli.py            mask / unmask / scan / bench
├── model.py          Span, EntityType, Category (spans hold offsets, never values)
├── resolve.py        overlap resolution (ADR 0006)
├── errors.py         FailClosedError: the one error type that means "send nothing"
├── pipeline.py       detect → resolve → propagate → pseudonymize → re-scan (ADR 0012)
├── policy.py         enabled entity types, risk level (YAML)
├── propagate.py      exact values, name words, learned domains and prefixes, seed (0007, 0012, 0015)
├── rescan.py         output re-scan and redaction (ADR 0012, 0014)
├── detect/
│   ├── base.py       Detector protocol, fail-closed runner (NER/LLM layers plug in here)
│   └── rules/        deterministic layer (ADR 0008)
│       ├── base.py         Rule, RegexRule, RulesDetector
│       ├── aws.py          ARNs, account/resource IDs, access keys, buckets, endpoints
│       ├── network.py      IPv4/IPv6, CIDRs, internal hostnames, organization domains
│       ├── secrets.py      vendor tokens, JWTs, bearer tokens, URL passwords
│       ├── crypto_keys.py  PEM/OpenSSH/PGP private keys (complete or truncated)
│       ├── identity.py     emails, ssh_config users
│       ├── organization.py tool URLs, AWS portals, cert subjects, legal entities, copyright (ADR 0015)
│       ├── k8s.py          values of Kubernetes Secret data/stringData
│       ├── keyvalue.py     sensitive field names across YAML/JSON/HCL/env/CLI flags
│       └── entropy.py      high-entropy unknown secrets
├── pseudo/           (ADR 0003, 0010)
│   ├── keyed.py      HMAC derivation, unbiased choice
│   ├── session.py    mapping table (pseudonym <-> original), kept values
│   ├── text.py       class-preserving and word-level primitives, kept generic words
│   ├── network.py    prefix-preserving IP permutation
│   ├── generators.py one generator per entity type; composites call the engine per component
│   └── engine.py     Pseudonymizer: caching, collision checks, fail-closed, text replacement
└── reinject.py       pseudonym → real value: longest first, exact, bounded (ADR 0011)

bench/
├── run.py            runs all corpora, writes reports, enforces the recall ratchet (ADR 0013)
├── thresholds.json   per-type recall floor (only goes up)
├── corpus/dev/       hand-written, already used to improve the rules
├── corpus/holdout/   hand-written, never used for tuning
└── reports/          latest.json / latest.md (no values)

src/cloakops/benchmark/
├── fakes.py          seeded realistic fake values
├── templates.py      synthetic document templates ({{factory}} placeholders)
├── corpus.py         rendering with recorded spans, ⟦type|value⟧ holdout parser
├── metrics.py        recall / precision / F2 / leak rate, design-aware coverage
└── report.py         JSON and Markdown rendering
```

## Decisions

See [docs/adr](adr/). Key ones: layered detection (0002), keyed structure-preserving
pseudonymization (0003), recall-first benchmark (0004), text-level detection (0005), overlap
resolution (0006), sensitive-values dictionary (0007), rules
layer conventions (0008), masking of non-secret identifiers (0009),
coherent and syntax-safe pseudonyms (0010), re-injection (0011), propagation and output re-scan (0012),
benchmark implementation (0013), re-scan modes (0014), organization signals (0015).
