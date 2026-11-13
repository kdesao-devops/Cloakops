# 0016. CLI on the standard library, local session store with owner-only files and a TTL

Date: 2026-11-14 · Status: accepted

## Context

Phase 1 ends with a usable command line: mask a file or stdin, paste the result into any chat,
and restore the real values in the answer, in two separate invocations. Between them, the
session (key, mapping table, learned terms) must survive on disk. The project plan suggested
`typer` for the CLI.

## Decision

**CLI** (`cloakops`, `src/cloakops/cli.py`), on `argparse`:

- `mask [FILE] --session NAME [--preamble] [--redact] [--paranoid] [--org-domain D] [--seed F]`
- `unmask [FILE] --session NAME`
- `scan [FILE]`: what would be masked, as `line:column type length detector`, no values
- `session list | delete NAME | purge`, `dict list | add TERM | remove TERM`

Stdin/stdout by default, so it composes with pipes and the clipboard (`pbpaste | cloakops mask
--session s | pbcopy`). Diagnostics on stderr, never with values. Exit codes: 0 ok, 2 usage,
3 fail-closed. Outputs are written last, so any failure leaves stdout empty. Unexpected
exceptions are fail-closed as well and print only the exception type: a traceback or an
exception message can carry input values (`CLOAKOPS_DEBUG=1` shows it).

**Local store** (`$CLOAKOPS_HOME`, default `~/.local/state/cloakops`):

- `sessions/<name>.json`: key, mappings, learned propagation terms; directory 0700, files 0600,
  written atomically (temporary file + rename); refused if group or others can access them;
- TTL (default 24 h): an expired session is deleted when touched; `session purge`;
- session names restricted to `[A-Za-z0-9._-]{1,64}`, so a name cannot escape the directory;
- `seed.txt` (ADR 0007) and an optional `config.toml` (`organization_domains`,
  `internal_suffixes`), read with the standard `tomllib`.

## Alternatives rejected

- **typer** (planned): nicer help output, but it pulls `click` and `rich` into a tool whose job is
  handling secrets; the standard library covers this CLI. Fewer dependencies, smaller supply
  chain.
- **Session in memory only**: mask and unmask would have to happen in one process; useless for
  the copy-paste workflow.
- **Encrypting the session file now**: the right end state, but key management (OS keychain)
  is the same work as the phase 3 vault; doing it twice is waste. Accepted debt, below.

## Consequences

- **Known debt (threat model T6):** session files hold real values in clear, protected only by
  file permissions and the TTL. Phase 3 replaces them with the encrypted vault.
- Sessions are local to one machine and one user; sharing a session means sharing its file.
