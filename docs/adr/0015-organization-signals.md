# 0015. High-confidence signals of the organization's own names

Date: 2026-11-14 · Status: accepted · Validated by the project owner

## Context

Name words are propagated from confident sources (ADR 0012), but an explicit `client: Acme` is
rare. The organization's name is nevertheless present, in precise formats, in most
infrastructure content. The first holdout run (docs/benchmark.md) missed it in a container
registry path and in a public hostname of the organization.

## Decision

Seven signals, all feeding the propagation layer so that one occurrence masks every other
mention for the whole session:

| # | Signal | Example | Where |
|---|---|---|---|
| 1 | Corporate email domain (not a public webmail) | `oncall@korvane.com` → domain `korvane.com` and word `korvane` | propagation (learned) |
| 2 | First word shared by >= 3 distinct resource names (buckets, clusters, resources, ARN resources) | `orbita-deployer`, `orbita-billing`, `orbita-events` | propagation (learned) |
| 3 | Organization in tool URLs: Terraform Cloud, Git SSH remotes, ghcr.io / GitLab / Quay / Azure registries | `git@github.com:korvane/infra.git` | rules |
| 4 | AWS sign-in alias and IAM Identity Center portal | `korvane-prod.signin.aws.amazon.com`, `korvane.awsapps.com` | rules |
| 5 | Certificate subject O= and CN= (issuer skipped) | `Subject: O=Korvane SAS, CN=*.korvane.com` | rules; CN domain learned |
| 6 | Capitalized words followed by a legal form | `Brindel Logistics SAS`, `Acme GmbH` | rules (confidence 0.8) |
| 7 | Copyright holder | `Copyright (c) 2026 Korvane Technologies` | rules |

Learned **domains** mask every hostname under them (`pay.korvane.com`), not only the word.

Guards:

- public organizations (GitHub Actions, HashiCorp, Bitnami, Kubernetes...) and public copyright
  holders are excluded: they are dependencies, not the user's organization;
- public webmail domains are never learned;
- legal forms are limited to unambiguous ones (`SAS`, `GmbH`, `Inc`, `LLC`, `Ltd`...); `Group`,
  `SA`, `AG`, `AB` are excluded (Resource Group, Security Group, service account);
- the shared-prefix signal needs 3 distinct names; 2 are not enough.

## Alternatives rejected

- **Ask the user to configure every name upfront** (seed dictionary, organization domains): kept
  as an option, but most users will not, and it misses names they did not think of.
- **Mask every capitalized phrase**: far too many false positives; prose is the job of NER and
  the local LLM (phase 2).
- **Count `Group` as a legal form**: catches `Acme Group` but also every Azure Resource Group and
  AWS Security Group.

## Consequences

- Measured on the synthetic corpus (biased, see ADR 0013): with propagation, the new templates
  have no misses; without propagation, 42.9% of documents leak. The signals are only as good as
  the propagation that spreads them.
- A capitalized word that starts a sentence is swallowed by the legal-entity rule
  (`Invoice Brindel Logistics SAS`): over-masking, not a leak.
- Learning happens per session; a domain learned in one document protects the next ones, not
  earlier ones.
