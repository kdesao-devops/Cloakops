"""Re-injection: put the real values back into the model's answer (ADR 0011).

The answer is scanned once with an alternation of every pseudonym of the session:
- longest first, so `icia-logs` (a bucket) wins over `icia` (an organization) at the same
  position, and a full ARN wins over the account ID inside it;
- never as the piece of a longer word or number, so the pseudonym `10.14.229.11` is not
  "restored" inside `10.14.229.111`.

Only exact pseudonyms are restored. A pseudonym the model altered (truncated, reformatted) stays
as is: that is drift, measured in phase 3, and the preamble asks the model to avoid it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from cloakops.model import Category, EntityType
from cloakops.pseudo.session import Session

# A pseudonym must not be the piece of a longer word or number (`10.14.229.11` inside
# `10.14.229.111`). Punctuation next to it is fine: `icia-logs-archive`, `host.icia.io`, a key
# glued to a dash. Stricter boundaries were tried and broke round-trips (see ADR 0011).
_BEFORE = r"(?<![A-Za-z0-9])"
_AFTER = r"(?![A-Za-z0-9])"


def _bounded(pseudonym: str) -> str:
    """Boundaries only where they mean something: a pseudonym starting with "-----BEGIN" can sit
    right after a digit; one starting with a digit must not be the tail of a longer number."""
    before = _BEFORE if pseudonym[0].isalnum() else ""
    after = _AFTER if pseudonym[-1].isalnum() else ""
    return f"{before}{re.escape(pseudonym)}{after}"


def entity_type_of(namespace: str) -> EntityType:
    return EntityType(namespace.removeprefix("merged:"))


@dataclass(frozen=True, slots=True)
class Restoration:
    start: int  # position of the pseudonym in the answer
    end: int
    namespace: str


@dataclass(frozen=True, slots=True)
class ReinjectedText:
    text: str
    restorations: tuple[Restoration, ...]


class Reinjector:
    def __init__(self, session: Session, categories: Iterable[Category] | None = None) -> None:
        """`categories` limits what is restored (e.g. everything but credentials); default all."""
        self._session = session
        self._categories = frozenset(categories) if categories is not None else None
        self._compiled_for = -1
        self._pattern: re.Pattern[str] | None = None
        self._table: dict[str, tuple[str, str]] = {}

    def _refresh(self) -> None:
        # The session only grows: recompile when its size changed.
        if self._compiled_for == len(self._session):
            return
        table: dict[str, tuple[str, str]] = {}
        for entry in self._session.entries():
            if entry.pseudonym == entry.original:
                continue  # kept value: nothing to restore
            if (
                self._categories is not None
                and entity_type_of(entry.namespace).category not in self._categories
            ):
                continue
            table[entry.pseudonym] = (entry.original, entry.namespace)
        self._table = table
        if table:
            alternation = "|".join(_bounded(p) for p in sorted(table, key=len, reverse=True))
            self._pattern = re.compile(alternation)
        else:
            self._pattern = None
        self._compiled_for = len(self._session)

    def reinject(self, text: str) -> ReinjectedText:
        self._refresh()
        if self._pattern is None:
            return ReinjectedText(text, ())
        restorations: list[Restoration] = []

        def restore(match: re.Match[str]) -> str:
            original, namespace = self._table[match.group()]
            restorations.append(Restoration(match.start(), match.end(), namespace))
            return original

        return ReinjectedText(self._pattern.sub(restore, text), tuple(restorations))
