# 0007. Sensitive-values dictionary: session propagation, seeded list, then a learned hashed store

Date: 2026-11-13 · Status: accepted

## Context

Some of the most sensitive values have no recognizable format: customer names, project codenames,
internal product names. A detector may catch one in a strong context (`client: Acme`) and miss
every other mention (`# Acme migration on Monday`, `acme-prod-eks`, `ACME_API_KEY`). A value
caught once and leaked elsewhere is still a leak.

Remembering such values makes detection deterministic, instant and free, but a list of an
organization's sensitive values is itself a highly sensitive asset, and an automatically
growing list can be poisoned by the content it processes.

## Decision

Three mechanisms, delivered in two phases.

**Phase 1**

1. **Session propagation.** After overlap resolution, every value found in a strong context is
   searched across the whole text and the rest of the session: case-insensitively, as a whole
   word, and as a sub-token of identifiers (split on `-`, `_`, `.`, `/`, camelCase). Guards: a
   minimum length, a stop-list of common infrastructure words (`test`, `prod`, `default`, `main`,
   ...), and a policy switch.
2. **Seed dictionary.** A user-maintained list (`cloakops dict add Acme`) of values to always
   mask. Plain file with mode `0600`, outside the repository; the user chooses what goes in.

**Phase 3** (with the encrypted vault, because both need the same key management)

3. **Learned dictionary.** Values are added across runs:
   - automatically when the evidence is strong (explicit sensitive key such as `client`,
     `customer`, `project`, `owner`; minimum length; not in the stop-list);
   - as pending entries otherwise (e.g. medium-confidence local-LLM findings), approved with
     `cloakops dict review`;
   - expired after N days without being seen.

   The store holds **keyed hashes**, never raw values: `HMAC-SHA256(key, normalize(value))`,
   with normalization = lowercase + Unicode NFKD without accents. At run time each word and
   identifier sub-token of the input is normalized, hashed and looked up. The key lives in the OS
   keychain (macOS Keychain) locally and in a Kubernetes secret in phase 4.

The benchmark reports recall without the dictionary, with session propagation, and with a seed
dictionary, so the contribution of each mechanism is measured.

## Alternatives rejected

- **Plain-text persistent list**: simplest, enables fuzzy matching, but a stolen file is a
  ready-made list of everything confidential.
- **Encrypted list decrypted at run time**: protects the file at rest, but puts every value in
  memory on every run, and still needs key management. Kept as a possible later option to enable
  fuzzy matching.
- **Unkeyed hashes**: reversible by hashing a wordlist (dictionary attack), as in ADR 0003.
- **Automatic addition of everything detected**: maximal recall, but trivially poisoned by input
  content (`client: the`), destroying answer quality across all later runs.
- **Learned dictionary in phase 1**: would need key storage now and again in phase 3.

## Consequences

- Hashed lookup matches the exact normalized form only (`ACME`, `acme-prod` yes; typo `Acmee`
  no). Accepted; fuzzy matching would require raw values.
- Multi-word values (`Acme Corp`) need hashing of word n-grams, bounded to a small n.
- Stored names of people are personal data: the store needs a retention period (TTL) and a way
  to delete an entry (`cloakops dict remove`).
- Poisoning resistance relies on the evidence threshold, the stop-list and the review step; the
  benchmark should include adversarial inputs (`client: the`).
