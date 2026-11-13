# 0011. Re-injection: exact, longest-first, alphanumeric boundaries

Date: 2026-11-13 · Status: accepted

## Context

The model answers in terms of pseudonyms. The real values must be put back before the user reads
the answer, without restoring text that was never a pseudonym, and without missing pseudonyms
the model reused next to punctuation, inside a derived name (`icia-logs-archive`) or glued to
another value.

## Decision

- **One pass, one regex**: an alternation of every pseudonym of the session (kept values
  excluded), **longest first**, so a bucket `icia-logs` wins over the organization `icia` at the
  same position and a full ARN wins over the account ID inside it.
- **Exact match only, case-sensitive.** A pseudonym the model altered (truncated, reformatted,
  re-cased) is not restored: that is *drift*. The preamble (ADR 0010) asks the model to avoid it;
  phase 3 measures it.
- **Boundaries: no letter or digit glued on the side of a pseudonym that starts or ends with a
  letter or digit.** `10.14.229.11` is not restored inside `10.14.229.111`, an account ID not
  inside a longer number; punctuation next to a pseudonym is fine.
- **Components are restorable on their own.** Named parts of composite values (role name in an
  ARN, hostname label, email local part) are registered as pseudonyms when generated, so the
  model can quote `icia-ergtqcsf` without its ARN and still get `acme-deployer` back. Found by a
  demo: the model extracted the role name from the ARN, which was not restorable.
- **Category filter** (`Reinjector(categories=...)`): the policy can choose not to restore, for
  example, credentials into answers. Default: restore everything.
- Restorations are reported (position, entity type) for the audit receipt, without values.
- The compiled pattern is rebuilt when the session grows (sessions only grow).

**Invariant, property-tested:** `reinject(mask(x)) == x` for texts built from sensitive values
glued with arbitrary separators, and for the realistic tfstate and Kubernetes documents.

## Alternatives rejected

- **Boundaries copied from the detection rules** (no `.`, `-`, `_` next to a pseudonym): tried
  first; the round-trip property found counterexamples (a token glued to an IP, a CIDR glued to a
  PEM block) and they also refused correct restorations such as `icia-logs-archive`.
- **Word-level reverse mapping** (restore each pseudo-word independently): would also restore new
  names the model invents, but short words make false restorations likely. Can be reconsidered
  with a minimum word length if drift measurements show the need.
- **Case-insensitive matching**: pseudonyms are case-preserving by design; folding case would
  restore unrelated text more often than it would fix drift.
- **Streaming now**: the proxy (phase 3) needs chunked re-injection with a hold-back buffer for
  pseudonyms split across chunks; the same `Reinjector` table will feed it.

## Consequences

- A literal in the model's answer that happens to equal a pseudonym is restored. Pseudonyms are
  long and random for secrets and IDs; the risk concentrates on short names.
- Restoring credentials puts real secrets in the local answer; that is the point when the user
  asks for a corrected config, and the category filter exists for when it is not.
