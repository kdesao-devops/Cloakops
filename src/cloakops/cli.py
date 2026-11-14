"""Command-line interface (ADR 0016).

    cloakops mask   [FILE] --session NAME [--preamble] [--redact] [--paranoid]
    cloakops unmask [FILE] --session NAME
    cloakops scan   [FILE]                      what would be masked (types and positions only)
    cloakops session list | delete NAME | purge
    cloakops dict    list | add TERM | remove TERM

Input is FILE or stdin; results go to stdout; diagnostics to stderr, never with values.
Exit codes: 0 ok, 2 usage error, 3 fail-closed (nothing was written to stdout). Unexpected errors
are fail-closed too and show only the exception type (CLOAKOPS_DEBUG=1 for the traceback, which
may contain input values).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from cloakops import __version__
from cloakops.detect.rules import DEFAULT_INTERNAL_SUFFIXES, default_rules_detector
from cloakops.errors import FailClosedError
from cloakops.pipeline import Pipeline
from cloakops.preamble import PREAMBLE
from cloakops.propagate import load_seed_dictionary
from cloakops.store import DEFAULT_TTL, LoadedSession, Store

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FAIL_CLOSED = 3

log = logging.getLogger("cloakops")


def _read_input(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _store(args: argparse.Namespace) -> Store:
    home = Path(args.home) if args.home else None
    return Store(home, timedelta(hours=args.ttl_hours))


def _pipeline(
    args: argparse.Namespace, store: Store, session_name: str | None
) -> tuple[Pipeline, LoadedSession | None]:
    config = store.config()
    domains = (*config.organization_domains, *(getattr(args, "org_domain", None) or ()))
    detector = default_rules_detector(
        internal_suffixes=(
            config.internal_suffixes
            if config.internal_suffixes is not None
            else DEFAULT_INTERNAL_SUFFIXES
        ),
        organization_domains=domains,
    )
    loaded = store.load(session_name) if session_name else None
    seed_path = Path(args.seed) if getattr(args, "seed", None) else store.seed_path
    if seed_path.exists() and loaded is not None:
        loaded.propagator.add_seed(load_seed_dictionary(seed_path))
    pipeline = Pipeline(
        [detector],
        session=loaded.session if loaded else None,
        propagator=loaded.propagator if loaded else None,
        redact=getattr(args, "redact", False),
        paranoid=getattr(args, "paranoid", False),
    )
    return pipeline, loaded


def cmd_mask(args: argparse.Namespace) -> int:
    store = _store(args)
    text = _read_input(args.file)
    with store.lock(args.session):  # load -> mask -> save is one critical section
        pipeline, loaded = _pipeline(args, store, args.session)
        result = pipeline.mask(text)  # raises FailClosedError: nothing is written
        if loaded is None:  # unreachable: the parser requires --session
            return EXIT_USAGE
        store.save(loaded)
    types = Counter(
        r.span.entity_type.value for r in result.replacements if r.pseudonym != r.span.text_of(text)
    )
    summary = ", ".join(f"{n} {t}" for t, n in sorted(types.items())) or "nothing"
    log.info("masked %s (session %s)", summary, args.session)
    sys.stdout.write((PREAMBLE + "\n" if args.preamble else "") + result.text)
    return EXIT_OK


def cmd_unmask(args: argparse.Namespace) -> int:
    store = _store(args)
    if not store.exists(args.session):
        log.error("no session named %r (expired, or never used with mask)", args.session)
        return EXIT_USAGE
    pipeline, loaded = _pipeline(args, store, args.session)
    if loaded is not None and loaded.expired:
        # Restoring nothing would print pseudonyms with exit 0, as if it had worked.
        log.error(
            "session %r has expired: its mappings are gone, nothing can be restored", args.session
        )
        return EXIT_USAGE
    result = pipeline.unmask(_read_input(args.file))
    log.info("restored %d value(s) (session %s)", len(result.restorations), args.session)
    sys.stdout.write(result.text)
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    store = _store(args)
    pipeline, _ = _pipeline(args, store, None)
    text = _read_input(args.file)
    spans, _ = pipeline.detect(text)
    for span in spans:
        line = text.count("\n", 0, span.start) + 1
        column = span.start - (text.rfind("\n", 0, span.start) + 1) + 1
        sys.stdout.write(
            f"{line}:{column}\t{span.entity_type.value}\t{span.end - span.start} chars\t{span.detector}\n"
        )
    log.info("%d value(s) would be masked", len(spans))
    return EXIT_OK


def cmd_session(args: argparse.Namespace) -> int:
    store = _store(args)
    if args.action == "list":
        for name, created_at, expired in store.sessions():
            state = "expired" if expired else "active"
            sys.stdout.write(f"{name}\t{created_at.isoformat(timespec='seconds')}\t{state}\n")
    elif args.action == "delete":
        if not args.name:
            log.error("session delete needs a NAME")
            return EXIT_USAGE
        if not store.delete(args.name):
            log.error("no session named %r", args.name)
            return EXIT_USAGE
    elif args.action == "purge":
        log.info("removed %d expired session(s)", store.purge_expired())
    return EXIT_OK


def cmd_dict(args: argparse.Namespace) -> int:
    store = _store(args)
    lines = store.read_seed_lines()
    if args.action == "list":
        for line in lines:
            sys.stdout.write(f"{line}\n")
        return EXIT_OK
    if not args.term:
        log.error("dict %s needs a TERM", args.action)
        return EXIT_USAGE
    term = " ".join(args.term)
    if args.action == "add":
        if term not in lines:
            store.write_seed([*lines, term])
    else:
        store.write_seed([line for line in lines if line != term])
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloakops",
        description="Local, reversible pseudonymization of infrastructure data for LLMs.",
    )
    parser.add_argument("--version", action="version", version=f"cloakops {__version__}")
    parser.add_argument(
        "--home", help="state directory (default: $CLOAKOPS_HOME or ~/.local/state/cloakops)"
    )
    parser.add_argument(
        "--ttl-hours",
        type=float,
        default=DEFAULT_TTL.total_seconds() / 3600,
        help="sessions older than this are discarded (default: 24)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="only errors on stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    def detection_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("file", nargs="?", help="input file (default: stdin)")
        p.add_argument(
            "--org-domain",
            action="append",
            metavar="DOMAIN",
            help="the organization's own domain (repeatable), e.g. acme.io",
        )
        p.add_argument("--seed", metavar="FILE", help="seed dictionary (default: <home>/seed.txt)")

    mask = sub.add_parser("mask", help="pseudonymize FILE or stdin")
    detection_options(mask)
    mask.add_argument("--session", required=True, help="session name (shared with unmask)")
    mask.add_argument("--preamble", action="store_true", help="prepend instructions for the model")
    mask.add_argument(
        "--redact",
        action="store_true",
        help="redact re-scan residues as [REDACTED] instead of failing closed",
    )
    mask.add_argument(
        "--paranoid", action="store_true", help="also re-run every detector on the output (slower)"
    )
    mask.set_defaults(handler=cmd_mask)

    unmask = sub.add_parser("unmask", help="restore real values in FILE or stdin")
    unmask.add_argument("file", nargs="?", help="input file (default: stdin)")
    unmask.add_argument("--session", required=True)
    unmask.set_defaults(handler=cmd_unmask)

    scan = sub.add_parser("scan", help="list what would be masked (no values)")
    detection_options(scan)
    scan.set_defaults(handler=cmd_scan)

    session = sub.add_parser("session", help="manage stored sessions")
    session.add_argument("action", choices=["list", "delete", "purge"])
    session.add_argument("name", nargs="?")
    session.set_defaults(handler=cmd_session)

    seed = sub.add_parser("dict", help="manage the seed dictionary (names to always mask)")
    seed.add_argument("action", choices=["list", "add", "remove"])
    seed.add_argument("term", nargs="*", help="e.g. Acme, 'person: Jane Doe', 'project: Orion'")
    seed.set_defaults(handler=cmd_dict)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("cloakops: %(levelname)s: %(message)s"))
    log.handlers[:] = [handler]
    log.setLevel(logging.ERROR if args.quiet else logging.INFO)
    log.propagate = False
    try:
        code: int = args.handler(args)
    except FailClosedError as exc:
        log.error("%s. Nothing was written. (%s)", exc, type(exc).__name__)
        return EXIT_FAIL_CLOSED
    except (OSError, UnicodeDecodeError) as exc:
        log.error("cannot read input: %s", type(exc).__name__)
        return EXIT_USAGE
    except Exception as exc:
        # A traceback or an exception message can carry input values: by default only the type
        # is shown, and nothing was written to stdout (outputs are written last).
        if os.environ.get("CLOAKOPS_DEBUG"):
            raise
        log.error(
            "internal error (%s). Nothing was written. Set CLOAKOPS_DEBUG=1 for details.",
            type(exc).__name__,
        )
        return EXIT_FAIL_CLOSED
    return code


if __name__ == "__main__":
    sys.exit(main())
