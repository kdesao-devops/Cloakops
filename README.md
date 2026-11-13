# cloakops

> Send your Terraform plans, Kubernetes manifests and logs to a public LLM without sending your
> secrets and infrastructure identifiers with them.

**Status: early development (end of phase 1).** Rule-based detection, pseudonymization,
re-injection, CLI and benchmark work; NER and local-LLM layers come in phase 2.
See the [benchmark](docs/benchmark.md) for measured recall, including its limits.

cloakops is a local pseudonymization gateway specialized for infrastructure and DevOps data.
It detects secrets and sensitive identifiers (IPs/CIDRs, ARNs, AWS account IDs, internal
hostnames, bucket and cluster names, API keys, tokens, JWTs, private keys, emails, people and
customer names), replaces them with **consistent, structure-preserving** pseudonyms, sends only
the pseudonymized content to the model, and restores the real values in the answer.

Generic PII tools (Presidio and friends) target names, emails and card numbers; they understand
`arn:aws:iam::123456789012:role/deploy` or `10.42.0.0/16` poorly. cloakops is built for those.

```
prompt + confidential content
        │
        ▼
 ┌──────────────── local ─────────────────┐
 │ detect: rules → NER → local LLM        │
 │ pseudonymize (keyed, consistent,       │
 │   structure-preserving)                │──► public LLM (pseudonymized text only)
 │ re-inject real values into the answer  │◄──
 └────────────────────────────────────────┘
```

Note on wording: this is **pseudonymization**, not anonymization. The mapping is reversible by
design, and under GDPR pseudonymized personal data is still personal data.

## Usage

```bash
uv sync
# Mask a Terraform state, paste the result in any chat, keep the session name.
uv run cloakops mask terraform.tfstate --session incident-42 --preamble > masked.txt
# Restore the real values in the model's answer.
uv run cloakops unmask answer.txt --session incident-42
# Pipes work too (macOS clipboard):
pbpaste | uv run cloakops mask --session incident-42 | pbcopy
# What would be masked (types and positions, never values):
uv run cloakops scan app.log
# Names to always mask, and the organization's domains:
uv run cloakops dict add "Acme Industries"
uv run cloakops mask notes.md --session s --org-domain acme.io
```

Safety defaults: if detection fails or a value is found in clear after masking, nothing is
written (exit code 3). `--redact` replaces such residues with `[REDACTED]` instead;
`--paranoid` re-runs every detector on the output. Sessions live in
`~/.local/state/cloakops` (owner-only files, 24 h TTL, not encrypted yet: phase 3).

## Roadmap

| Phase | Scope |
|---|---|
| 0 | Framing, [threat model](docs/threat-model.md), repository, ADRs |
| 1 | CLI, rule-based detection of infrastructure entities, pseudonymization, re-injection, benchmark |
| 2 | NER (Presidio/spaCy) and local LLM (Ollama) layers, measured contribution of each |
| 3 | OpenAI/Anthropic-compatible proxy, streaming re-injection, encrypted mapping vault with TTL, fail-closed, audit receipts |
| 4 | Deployment on Kubernetes (Helm, ArgoCD, Sealed Secrets, Kyverno, NetworkPolicies), then EKS with GPU nodes |
| 5 | Published benchmark, demo, user feedback |

## Documentation

- [Threat model](docs/threat-model.md)
- [Architecture](docs/architecture.md)
- [Architecture Decision Records](docs/adr/)
- [Benchmark](docs/benchmark.md)

## Development

Requires [uv](https://docs.astral.sh/uv/) (`brew install uv`).

```bash
uv sync                      # installs the pinned Python 3.12 and all dependencies
uv run pre-commit install    # lint, type check and secret scan on every commit
uv run pytest
```

## License

[MIT](LICENSE)
