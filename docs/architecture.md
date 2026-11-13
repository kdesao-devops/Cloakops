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
[re-scan output] ── any original value or new detection left? → fail, write nothing
   ▼
pseudonymized text ──► LLM ──► answer ──► [re-inject] ──► answer with real values
```

## Package layout (phase 1 target)

```
src/cloakops/
├── cli.py            mask / unmask / scan / bench
├── model.py          Span, EntityType, Category (spans hold offsets, never values)
├── resolve.py        overlap resolution (ADR 0006)
├── pipeline.py       detect → resolve → propagate → pseudonymize → re-scan
├── policy.py         enabled entity types, risk level (YAML)
├── propagate.py      session propagation + seed dictionary (ADR 0007)
├── detect/
│   ├── base.py       Detector protocol (NER/LLM layers plug in here)
│   ├── rules/        aws, network, secrets, crypto_keys, k8s, identity
│   ├── keyvalue.py   sensitive-key heuristics across YAML/JSON/HCL/env
│   └── entropy.py    high-entropy unknown secrets
├── pseudo/
│   ├── session.py    mapping table
│   ├── keyed.py      HMAC derivation
│   └── generators/   ip, arn, account_id, hostname, secret, ...
└── reinject.py       pseudonym → real value

bench/
├── generate.py       seeded synthetic corpus with recorded spans
├── run.py            per-entity recall / precision, per-document leak rate
├── corpus/synthetic/ generated, used for development
├── corpus/holdout/   hand-written, never used for tuning
└── reports/          versioned results
```

## Decisions

See [docs/adr](adr/). Key ones: layered detection (0002), keyed structure-preserving
pseudonymization (0003), recall-first benchmark (0004), text-level detection (0005), overlap
resolution (0006), sensitive-values dictionary (0007).
