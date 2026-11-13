"""Format-preserving text primitives shared by all generators.

- `class_preserving`: replace each character by a pseudo-random one of the same class
  (upper -> upper, lower -> lower, digit -> digit, hex stays hex), keep every other character.
  Separators, quotes, `=` padding and backslash escapes stay where they were, so the result is
  as valid as the input in JSON, YAML, base64 or a URL.
- `pseudo_words`: word-level pseudonymization for names. Each alphanumeric run is replaced
  independently and consistently (lowercased before derivation, case re-applied after), and
  generic words (`prod`, `logs`, `eu`, `west`, `Industries`) are kept. "acme" therefore becomes
  the same pseudo-word in `acme-logs`, `acme.io`, `Acme` and `ACME_API`: coherence across values
  without any explicit link between them.
"""

from __future__ import annotations

import re
import string

from cloakops.pseudo.keyed import KeyedDerivation, pick

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
HEX_LOWER = "0123456789abcdef"
HEX_UPPER = "0123456789ABCDEF"
ALNUM = UPPER + LOWER + DIGITS

_HEX_CHARS = frozenset(string.hexdigits)
_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")


def _is_hex_value(value: str) -> bool:
    alnum = [c for c in value if c.isascii() and c.isalnum()]
    return (
        len(alnum) >= 8
        and all(c in _HEX_CHARS for c in alnum)
        and any(c.isdigit() for c in alnum)
        and any(c.isalpha() for c in alnum)
    )


_ESCAPES = re.compile(r"\\u[0-9a-fA-F]{4}|\\.")


def has_content(value: str) -> bool:
    """True if the value has a letter or digit outside escape sequences: something to hide."""
    return any(c.isalnum() for c in _ESCAPES.sub("", value))


def class_preserving(value: str, derivation: KeyedDerivation, domain: str, counter: int = 0) -> str:
    stream = derivation.stream(f"chars:{domain}", value, counter)
    hex_mode = _is_hex_value(value)
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            # Escape sequence (\n, \", \\, \u00e9): keep it intact, or JSON breaks.
            width = 6 if _UNICODE_ESCAPE.match(value, i) else 2
            out.append(value[i : i + width])
            i += width
            continue
        if c.isdigit():
            alphabet = DIGITS
        elif hex_mode and c in _HEX_CHARS:
            alphabet = "ABCDEF" if c.isupper() else "abcdef"  # letters stay hex letters
        elif c.isalpha():
            # Non-ASCII letters are mapped to ASCII too: keeping them would leak "é" positions.
            alphabet = UPPER if c.isupper() else LOWER
        else:
            out.append(c)
            i += 1
            continue
        out.append(pick(stream, alphabet))
        i += 1
    return "".join(out)


_ENVIRONMENTS = """
    prod production prd staging stage stg dev development test testing qa uat preprod sandbox
    demo int integration local default
"""
_INFRASTRUCTURE = """
    app apps api web www db database cache redis postgres postgresql mysql mongo kafka queue
    worker workers service services svc frontend backend gateway proxy ingress egress internal
    external public private logs log logging metrics monitoring backup backups data assets static
    media artifacts state tfstate terraform cluster node nodes pool master primary replica read
    write admin main core shared common platform infra network vpc subnet sg lb alb nlb elb eks
    ecs ecr rds s3 iam role roles policy policies user users group groups lambda function
    functions bucket kms key keys secret secrets config configs kube system namespace deployment
    pod pods job jobs cron
"""
_AWS_AND_REGIONS = """
    us eu ap sa ca me af il mx cn gov iso east west north south central northeast southeast
    northwest southwest aws amazon amazonaws com net org io
"""
_COMPANY_SUFFIXES = """
    inc ltd llc plc sas sarl gmbh ag bv nv corp corporation company co group holding holdings
    industries bank labs technologies tech solutions
"""
_FILE_EXTENSIONS = """
    json yaml yml txt csv gz zip tar tgz py sh tf tfvars md pdf png jpg html xml conf ini env
    pem crt
"""

KEEP_WORDS: frozenset[str] = frozenset(
    " ".join(
        (_ENVIRONMENTS, _INFRASTRUCTURE, _AWS_AND_REGIONS, _COMPANY_SUFFIXES, _FILE_EXTENSIONS)
    ).split()
)

# Escape sequences first (kept as separators), then alphanumeric runs.
_RUN = re.compile(r"\\u[0-9a-fA-F]{4}|\\.|[^\W_]+")


def _pseudo_run(run: str, derivation: KeyedDerivation) -> str:
    if run.startswith("\\"):
        return run
    lower = run.lower()
    if lower in KEEP_WORDS:
        return run
    if run.isdigit():
        # Short numbers (prod-01, eu-west-1) identify nothing; longer ones may be IDs.
        return run if len(run) <= 2 else class_preserving(run, derivation, "word")
    if run.isalpha():
        base = class_preserving(lower, derivation, "word")
        return "".join(b.upper() if o.isupper() else b for b, o in zip(base, run, strict=True))
    return class_preserving(run, derivation, "word-mixed")


def pseudo_words(value: str, derivation: KeyedDerivation) -> str:
    return _RUN.sub(lambda m: _pseudo_run(m.group(), derivation), value)
