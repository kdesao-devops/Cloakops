# Threat model

Status: draft, Phase 0. Revisit at the end of every phase.

## 1. What cloakops is for

An engineer wants a public LLM (Claude, GPT, ...) to help with a Terraform plan, a Kubernetes
manifest, an application log or a CloudTrail event. That content holds **secrets** (keys, tokens,
private keys) and **sensitive identifiers** (IPs and CIDRs, AWS account IDs, ARNs, internal
hostnames, bucket/cluster names, people and customer names). cloakops replaces them locally with
consistent, structure-preserving pseudonyms, sends only the pseudonymized text, and restores the
real values in the answer.

We say **pseudonymization**, not anonymization: the mapping exists and the transformation is
reversible by design. Under GDPR (Art. 4(5), Recital 26), pseudonymized personal data is still
personal data.

## 2. Assets

| Asset | Why it matters |
|---|---|
| A1. Credentials (API keys, tokens, JWTs, private keys, passwords) | Direct compromise if leaked |
| A2. Infrastructure identifiers (IPs/CIDRs, account IDs, ARNs, resource IDs, hostnames, resource names) | Reconnaissance, targeting, inference of topology |
| A3. Personal and business data (people, emails, customer and project names) | Privacy (GDPR) and confidentiality obligations |
| A4. The mapping table (pseudonym → real value) | Holds every real value: as sensitive as all of the above combined |
| A5. Audit receipts | Must prove what was masked without becoming a leak themselves |

## 3. Trust boundaries

```
 trusted                                    │  untrusted
 ───────────────────────────────────────────┼──────────────────────────────
 user workstation / internal cluster        │  public LLM provider
   cloakops process, local LLM (phase 2+),  │    API, logs, storage,
   mapping table, audit receipts            │    training pipelines,
                                            │    staff, subprocessors
```

Only pseudonymized text crosses the boundary.

## 4. Adversaries and what we defend against

| # | Adversary / event | In scope? | Mitigation |
|---|---|---|---|
| T1 | Provider **retains** prompts (logs, abuse monitoring, debugging) | Yes | Secrets and identifiers never leave in clear |
| T2 | Provider **trains** on prompts | Yes | Same |
| T3 | Provider **breach** or insider reading stored prompts | Yes | Same |
| T4 | **Detection miss**: a secret is not recognized and leaves in clear | Yes, the main risk | Layered detection, recall-first benchmark, post-masking re-scan, fail-closed |
| T5 | Detection error or timeout lets raw text through | Yes | Fail-closed: no detection result, no request (phase 1 CLI, phase 3 proxy) |
| T6 | Mapping table stolen from disk | Partially | Phase 1: file mode 0600, never committed. Phase 3: encrypted at rest, TTL |
| T7 | Audit receipts leak values | Yes | Receipts store type, position, detector, salted hash; never raw values |
| T8 | Pseudonym is **reversible without the key** (e.g. guessable hash of a short value) | Yes | Keyed (HMAC) derivation with a per-session random key |
| T9 | **Prompt injection** in the processed content tries to make the model reveal or misuse values | Limited | The model never sees real values, so it cannot leak them. Re-injection only restores known pseudonyms |
| T10 | **Linkability**: stable unique identifiers (resource IDs, tenant IDs) tie prompts to the organization when the same ID appears elsewhere | Yes | Identifiers are masked even when not secret, with structure-preserving pseudonyms (ADR 0009) |

## 5. Explicitly out of scope

- **Re-identification through context.** "Our payment service in Frankfurt that went down on
  Black Friday" identifies a company without containing a single masked entity. Structure
  preservation (an ARN stays an ARN) deliberately leaks *shape*: resource types, regions, AWS
  services, subnet sizes, topology. That is the price of a useful answer.
- **A compromised workstation or cluster.** If the attacker controls the machine running cloakops,
  they can read the input and the mapping directly.
- **Content the user chooses not to route through cloakops**, or pastes elsewhere.
- **Correctness of the LLM's answer.** cloakops does not make the model's advice safe to apply.
- **Supply-chain attacks on dependencies.** Reduced (pinned versions, lockfile with hashes,
  minimal dependencies), not eliminated.
- **Side channels on the provider side** (prompt length, timing).

## 6. Residual risks we accept and measure

- **False negatives (leaks).** No detector reaches 100% recall on unseen data. The benchmark
  reports per-entity recall and the per-document leak rate on a held-out corpus, and those numbers
  are published, not hidden.
- **False positives (over-masking).** They harm answer quality, not confidentiality. Measured as
  precision. When in doubt, mask.
- **Pseudonym drift.** The model may rewrite a pseudonym (reformat an ARN, derive a new IP from a
  masked CIDR). The real value can then not be restored automatically. Measured in phase 3.

## 7. Security invariants (tested)

1. No original value detected in the input appears in the output (post-masking re-scan).
2. `unmask(mask(x)) == x` for every input (property-based tests).
3. Same entity, same session → same pseudonym; different sessions → unlinkable pseudonyms.
4. Any detector error → non-zero exit, nothing written to the output.
