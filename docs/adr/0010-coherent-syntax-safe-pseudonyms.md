# 0010. Pseudonyms that stay coherent across values and never break the file's syntax

Date: 2026-11-13 · Status: accepted · Amends ADR 0003

## Context

ADR 0003 makes each pseudonym format-preserving. That is not enough for infrastructure content,
where values are derived from each other: a bucket appears in `bucket`, in its ARN and in its
endpoint; a node name `ip-10-42-3-17...` encodes an IP; an ECR URL embeds the account ID. A model
reasoning on a Terraform state relies on those links. And a replacement that breaks the file
(an invalid JSON escape, a string turned into a YAML boolean) makes a tfstate or a manifest much
less useful, which defeats the purpose.

## Decision

**Generate in the right format directly; no separate "repair" pass.** At pseudonymization time
the entity type is known, so the generator emits a valid value immediately.

**Coherence through components.** Composite values are split, and each component goes through
the engine with its own type, which caches and registers it:

- ARN: partition, service, region and resource type kept; account → account generator; S3
  bucket → bucket generator; EKS cluster → cluster generator; `i-...`, `sg-...` → resource-ID
  generator.
- Hostname: TLD, regions, AWS service labels and generic words kept; a 12-digit label → account;
  `ip-a-b-c-d` / `ec2-a-b-c-d` → the IP generator, re-encoded.
- Email: local part word by word; domain → hostname generator (public mail providers kept).
- Names (organizations, people, buckets, clusters, resources, hostname labels) share **one
  word-level derivation**: each alphanumeric run is pseudonymized on its lowercase form and the
  case re-applied; generic words (`prod`, `logs`, `eu`, `Industries`) are kept. `acme` therefore
  becomes the same word in `acme-logs`, `acme.io`, `Acme` and `ACME_API`.
- IPs: prefix-preserving permutation (Crypto-PAn style). The permutation is a bijection, so it is
  exempt from collision retries (a retry would break prefix preservation; an output equal to its
  input is a coincidence, not a leak, since the output is independent of the input without the
  key).

This amends ADR 0003, which planned to replace internal domains with a reserved `*.example`
domain: keeping the TLD and pseudonymizing labels word by word preserves coherence with the
organization's name everywhere else.

**Syntax safety invariants**, enforced by the generators and checked by the engine:

- character-class preservation never introduces quotes, backslashes or separators; escape
  sequences (`\n`, `\"`, `é`) are kept intact;
- base64 stays base64 (same alphabet, padding kept), hex stays hex;
- a candidate is rejected if it changes how YAML/JSON would type the scalar (string → boolean or
  null, number → number with a leading zero);
- numeric passwords stay numeric;
- values without any letter or digit carry no information and are kept.

**Tested**: tfstate JSON and multi-document Kubernetes YAML keep the same parsed shape; a
Hypothesis property generates arbitrary JSON documents with sensitive values and checks the
output still parses to the same shape.

**Shape is not preserved for passwords**: a fixed 16-character alphanumeric pseudonym, since
length and character-class pattern would help an attacker and help the model with nothing.

**Preamble.** The CLI gets a `--preamble` option (step 1.7) that prepends an instruction telling
the model that values are consistent pseudonyms and must be reused verbatim; the proxy will send
it as a system message (phase 3). Pseudonyms are not marked inline (`«...»`): markers would break
JSON/YAML.

## Alternatives rejected

- **Opaque placeholders + "repair" pass**: the repair would have to rediscover the type the
  detector already knew.
- **Random values with a mapping table**: consistent within a run, but not reproducible, and
  coherence across composite values would need explicit links.
- **Independent pseudonyms per entity type**: `acme` as an organization and inside `acme-logs`
  would get unrelated pseudonyms; the model loses the link.
- **Inline markers around pseudonyms**: easier for the model to spot, but break file syntax.

## Consequences

- Word-level pseudonyms leak word structure (`acme-prod-logs` → `icia-prod-logs`): the generic
  words are exactly what the model needs; the specific ones are hidden.
- Kept generic words are a list to maintain; a single-word value made only of kept words is
  still masked (character-level fallback).
- Values pseudonymized in an earlier document are not checked against literals of later
  documents; re-injection must handle that (phase 3).
- Secrets embedded in composite secrets (a hostname inside a connection string) are masked as a
  whole, not component by component, so they lose coherence with the standalone hostname.
