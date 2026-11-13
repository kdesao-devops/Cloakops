# 0009. Mask non-secret identifiers when structure-preserving pseudonymization makes it free

Date: 2026-11-13 · Status: accepted

## Context

AWS resource IDs (`vpc-0a1b2c3d4e5f67890`, `sg-12345678`, `i-...`), Azure tenant and
subscription IDs, KMS key IDs and similar values are not secrets: they grant nothing without
credentials. But they are globally unique and stable, so they:

- **link** a prompt to an organization when the same ID appears elsewhere (support ticket,
  screenshot, public repository), which is the re-identification the tool aims to make harder;
- give an attacker with partial access exact **targets** (reconnaissance).

With opaque placeholders (`[REDACTED]`), masking them would cost the model real information.
With structure-preserving pseudonyms (ADR 0003) the cost is close to zero.

## Decision

**When a pseudonym preserves everything the model reasons with, the bar for masking drops from
"is it secret?" to "does it identify something of ours?".**

- New entity type `AWS_RESOURCE_ID` (infrastructure): a known EC2/VPC-family prefix followed by 8
  or 17 lowercase hex characters, confidence 1.0, enabled by default and switchable off in the
  policy. Its pseudonym keeps the prefix and the length (`sg-0a1b...` → `sg-7c41...`) and is
  consistent across the session, so a security group can still be followed from the plan to
  the ingress rule to the error message.
- Identifiers without a distinctive format (UUIDs and the like) are masked **only in an explicit
  context**: the value of `tenant_id`, `subscription_id`, `kms_key_id`, `client_id`,
  `external_id`, ... (key/value rule, `RESOURCE_NAME`, confidence 0.8). A bare UUID is not
  masked: it is just as likely a request ID that identifies nothing.

## Alternatives rejected

- **Leave resource IDs in clear** (they are not secrets): accepts a linkability risk that costs
  almost nothing to remove.
- **Mask every UUID**: many are request or trace IDs; masking them adds noise without reducing
  linkability.
- **Distinguish public AMIs from private ones**: impossible offline. All AMI IDs are masked; the
  image name usually appears next to the ID when the model needs it.

## Consequences

- Terraform plans and state get many more masked values; consistency of pseudonyms becomes even
  more important (one ID → one pseudonym across the whole session).
- A "minimal" policy level can turn `AWS_RESOURCE_ID` off for users who accept the linkability
  risk.
