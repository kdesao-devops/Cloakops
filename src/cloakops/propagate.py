"""Propagation: a value found once is masked everywhere (ADR 0007, ADR 0012).

Two kinds of terms, learned from resolved detections and kept for the whole session:

- **Exact values** (every type): a secret, ID or name detected in one place is also masked where
  no rule fired (`password: S3cr3t` detected, `echo S3cr3t` in a script not). Case-sensitive.
- **Name words** (organizations, people, projects, buckets, clusters, from a confident source
  such as `client: Jacquil`): each specific word is masked in any case and inside identifiers,
  so `JACQUIL_API_KEY`, `jacquil-prod-eks` and `# Jacquil migration` are caught too.

Plus a **seed dictionary** the user maintains (`client: Acme`-style knowledge given upfront).

Guards against over-masking and poisoning (`client: the` must not mask every "the"): a minimum
length, a stop-list (generic infrastructure words and common English words), a minimum source
confidence.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterable, Mapping
from pathlib import Path

from cloakops.errors import FailClosedError
from cloakops.model import EntityType, Span
from cloakops.pseudo.generators import PUBLIC_MAIL_DOMAINS
from cloakops.pseudo.text import KEEP_WORDS, has_content, is_generic

PROPAGATION_DETECTOR = "propagation"
SHARED_PREFIX_MIN_VALUES = 3  # distinct resource names sharing a first word (ADR 0015)
_SECOND_LEVEL_SUFFIXES = frozenset(
    {"co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.nz", "co.za", "com.cn", "co.in", "com.mx"}
)
MIN_TERM_LENGTH = 4
MIN_SOURCE_CONFIDENCE = 0.8
TERM_CONFIDENCE = 0.9

NAME_TYPES = frozenset(
    {
        EntityType.ORGANIZATION,
        EntityType.PERSON,
        EntityType.RESOURCE_NAME,
        EntityType.BUCKET_NAME,
        EntityType.CLUSTER_NAME,
    }
)

_COMMON_WORDS = """
    the and for with from this that these those into onto over under about after before then
    than when where which while what who whom your yours ours their there here have has had
    been being were was are not but all any each every some such only also just more most less
    none null true false yes value values error errors warn warning info debug trace fatal
    name names type types text string number list item items example sample unknown other new
    old test tests user root admin guest owner default enabled disabled true false none
""".split()  # noqa: SIM905 (a word list reads better as text)
STOP_WORDS: frozenset[str] = KEEP_WORDS | frozenset(_COMMON_WORDS)

_WORD = re.compile(r"[^\W_]+")
_PREFIX_SOURCES = frozenset(
    {EntityType.BUCKET_NAME, EntityType.CLUSTER_NAME, EntityType.RESOURCE_NAME, EntityType.ARN}
)


def registered_domain(host: str) -> str:
    """korvane.com for pay.eu.korvane.com; acme.co.uk for www.acme.co.uk (common cases only)."""
    labels = host.lower().strip(".").removeprefix("*.").split(".")
    keep = 3 if ".".join(labels[-2:]) in _SECOND_LEVEL_SUFFIXES else 2
    return ".".join(labels[-keep:])


def _resource_name(entity_type: EntityType, value: str) -> str:
    if entity_type is EntityType.ARN:
        return re.split(r"[/:]", value)[-1]
    return value


def is_distinctive(value: str, min_length: int = MIN_TERM_LENGTH) -> bool:
    """Can this value be told apart from ordinary text? Shared by propagation (what to search
    for) and the re-scan (what to check for): if they disagreed, a value deliberately not
    propagated (`error`) would be reported as a leak wherever it appears as a normal word."""
    return (
        len(value) >= min_length
        and has_content(value)
        and not is_generic(value)
        and value.lower() not in STOP_WORDS
    )


class SeedDictionaryError(FailClosedError):
    """The seed dictionary cannot be trusted (permissions) or read."""


def load_seed_dictionary(path: Path) -> list[tuple[str, EntityType]]:
    """One term per line; `#` starts a comment; `person: Jane Doe` sets the type (default:
    organization). The file holds real sensitive names, so like an SSH key it must not be
    readable by group or others."""
    mode = path.stat().st_mode
    if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SeedDictionaryError(f"{path} must not be accessible by group or others (chmod 600)")
    prefixes = {
        "org": EntityType.ORGANIZATION,
        "person": EntityType.PERSON,
        "project": EntityType.RESOURCE_NAME,
    }
    terms: list[tuple[str, EntityType]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        prefix, sep, rest = line.partition(":")
        if sep and prefix.strip().lower() in prefixes:
            terms.append((rest.strip(), prefixes[prefix.strip().lower()]))
        else:
            terms.append((line, EntityType.ORGANIZATION))
    return terms


def _bounded(term: str) -> str:
    before = r"(?<![A-Za-z0-9])" if term[0].isalnum() else ""
    after = r"(?![A-Za-z0-9])" if term[-1].isalnum() else ""
    return f"{before}{re.escape(term)}{after}"


class Propagator:
    def __init__(
        self, seed: Iterable[tuple[str, EntityType]] = (), min_length: int = MIN_TERM_LENGTH
    ) -> None:
        self._min_length = min_length
        self._words: dict[str, EntityType] = {}  # lowercase word -> type
        self._values: dict[str, EntityType] = {}  # exact value -> type
        self._domains: set[str] = set()  # organization domains learned (korvane.com)
        self._prefixes: dict[str, set[str]] = {}  # first word -> distinct resource names
        self._compiled: tuple[int, re.Pattern[str] | None, re.Pattern[str] | None] | None = None
        self.add_seed(seed)

    def add_seed(self, seed: Iterable[tuple[str, EntityType]]) -> None:
        for term, entity_type in seed:
            self._add_value(term, entity_type)
            self._add_words(term, entity_type)

    def export_state(self) -> dict[str, object]:
        """Learned terms, to resume propagation in another process (holds real values)."""
        return {
            "words": {w: t.value for w, t in self._words.items()},
            "values": {v: t.value for v, t in self._values.items()},
            "domains": sorted(self._domains),
            "prefixes": {p: sorted(names) for p, names in self._prefixes.items()},
        }

    def import_state(self, state: Mapping[str, object]) -> None:
        words, values = state.get("words", {}), state.get("values", {})
        domains, prefixes = state.get("domains", []), state.get("prefixes", {})
        if not (
            isinstance(words, dict)
            and isinstance(values, dict)
            and isinstance(domains, list)
            and isinstance(prefixes, dict)
        ):
            raise ValueError("invalid propagation state")
        self._words.update({str(w): EntityType(t) for w, t in words.items()})
        self._values.update({str(v): EntityType(t) for v, t in values.items()})
        self._domains.update(str(d) for d in domains)
        for prefix, names in prefixes.items():
            self._prefixes.setdefault(str(prefix), set()).update(str(n) for n in names)

    def __len__(self) -> int:
        return len(self._words) + len(self._values) + len(self._domains)

    def _eligible(self, value: str) -> bool:
        return is_distinctive(value, self._min_length)

    def _add_value(self, value: str, entity_type: EntityType) -> None:
        if self._eligible(value):
            self._values.setdefault(value, entity_type)

    def _add_words(self, value: str, entity_type: EntityType) -> None:
        for word in _WORD.findall(value):
            lower = word.lower()
            if len(lower) >= self._min_length and lower not in STOP_WORDS and not word.isdigit():
                self._words.setdefault(lower, entity_type)

    def _add_domain(self, host: str) -> None:
        domain = registered_domain(host)
        if domain in PUBLIC_MAIL_DOMAINS or "." not in domain or is_generic(domain.split(".")[0]):
            return
        self._domains.add(domain)
        self._add_words(domain.split(".")[0], EntityType.ORGANIZATION)

    def _count_prefix(self, entity_type: EntityType, value: str) -> None:
        name = _resource_name(entity_type, value)
        first = re.split(r"[-_./:]", name, maxsplit=1)[0].lower()
        if len(first) < self._min_length or first in STOP_WORDS or first.isdigit():
            return
        names = self._prefixes.setdefault(first, set())
        names.add(name.lower())
        if len(names) >= SHARED_PREFIX_MIN_VALUES:
            self._words.setdefault(first, EntityType.ORGANIZATION)

    def learn(self, text: str, spans: Iterable[Span]) -> None:
        for span in spans:
            if span.merged:
                continue
            value = span.text_of(text)
            self._add_value(value, span.entity_type)
            if span.entity_type in NAME_TYPES and span.confidence >= MIN_SOURCE_CONFIDENCE:
                self._add_words(value, span.entity_type)
            # Signal 1: a corporate email domain (or a certificate CN) is the organization's.
            if span.entity_type is EntityType.EMAIL and "@" in value:
                self._add_domain(value.rsplit("@", 1)[1])
            if span.detector.startswith("rules:cert-subject-cn"):
                self._add_domain(value)
            # Signal 2: a first word shared by several resource names (korvane-logs,
            # korvane-prod-eks, korvane-etl) is the organization's or the project's name.
            if span.entity_type in _PREFIX_SOURCES:
                self._count_prefix(span.entity_type, value)

    def _domain_pattern(self) -> re.Pattern[str] | None:
        if not self._domains:
            return None
        alternation = "|".join(re.escape(d) for d in sorted(self._domains, key=len, reverse=True))
        return re.compile(
            rf"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*(?:{alternation})(?![\w-]|\.[a-z0-9])",
            re.IGNORECASE,
        )

    def _patterns(self) -> tuple[re.Pattern[str] | None, re.Pattern[str] | None]:
        version = len(self)
        if self._compiled is None or self._compiled[0] != version:
            values = sorted(self._values, key=len, reverse=True)
            words = sorted(self._words, key=len, reverse=True)
            value_pattern = re.compile("|".join(map(_bounded, values))) if values else None
            # Words: any case, and "_" counts as a separator (JACQUIL_API_KEY).
            word_pattern = (
                re.compile("|".join(map(_bounded, words)), re.IGNORECASE) if words else None
            )
            self._compiled = (version, value_pattern, word_pattern)
        return self._compiled[1], self._compiled[2]

    def expand(self, text: str) -> list[Span]:
        """Spans for every occurrence of a learned term (overlaps are resolved by the caller)."""
        value_pattern, word_pattern = self._patterns()
        spans: list[Span] = []
        if value_pattern is not None:
            for m in value_pattern.finditer(text):
                entity_type = self._values[m.group()]
                spans.append(
                    Span(m.start(), m.end(), entity_type, PROPAGATION_DETECTOR, TERM_CONFIDENCE)
                )
        domain_pattern = self._domain_pattern()
        if domain_pattern is not None:
            for m in domain_pattern.finditer(text):
                spans.append(
                    Span(
                        m.start(),
                        m.end(),
                        EntityType.HOSTNAME,
                        PROPAGATION_DETECTOR,
                        TERM_CONFIDENCE,
                    )
                )
        if word_pattern is not None:
            for m in word_pattern.finditer(text):
                entity_type = self._words[m.group().lower()]
                spans.append(
                    Span(m.start(), m.end(), entity_type, PROPAGATION_DETECTOR, TERM_CONFIDENCE)
                )
        return spans
