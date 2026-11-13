"""Pseudonymizer: turns resolved spans into a pseudonymized text, consistently for a session.

Bijective generators (IP permutation) are exempt: see `generators.BIJECTIVE`. Otherwise a
candidate pseudonym is rejected (and the generator asked again with counter + 1) when it:
- equals the original (would leak it);
- already stands for another original (re-injection would be ambiguous);
- equals another real sensitive value of the session, or a token present in the document
  (re-injection would replace text that was never a pseudonym);
- changes how YAML would type the scalar (`acme` -> `true` turns a string into a boolean).
After `max_attempts` rejections, `PseudonymizationError`: fail closed, nothing is produced.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from cloakops.model import EntityType, Span
from cloakops.pseudo.generators import BIJECTIVE, GENERATORS, KEEP_IF, Generator, opaque
from cloakops.pseudo.keyed import KeyedDerivation
from cloakops.pseudo.session import Session
from cloakops.pseudo.text import has_content

DEFAULT_MAX_ATTEMPTS = 32

# Tokens of the input, used to avoid pseudonyms that already appear as literal text.
_DOC_TOKEN = re.compile(r"[^\s\"'`,;=<>(){}\[\]]+")

_YAML_SPECIAL = frozenset({"true", "false", "yes", "no", "on", "off", "y", "n", "null", "~"})
_YAML_NUMBER = re.compile(
    r"[-+]?(?:0x[0-9a-f_]+|0o[0-7_]+|0b[01_]+|(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9]+)"
    r"(?:e[-+]?[0-9]+)?|\.inf|\.nan)",
    re.I,
)


def _scalar_kind(value: str) -> str:
    if value.lower() in _YAML_SPECIAL:
        return f"special:{value.lower()}"
    if _YAML_NUMBER.fullmatch(value):
        # 0123 is not a valid JSON number (and an octal in YAML 1.1): a distinct kind.
        return "number:leading-zero" if re.match(r"[-+]?0[0-9]", value) else "number"
    return "string"


class PseudonymizationError(RuntimeError):
    """No acceptable pseudonym could be produced. The input must not leave the machine."""


@dataclass(frozen=True, slots=True)
class Replacement:
    span: Span
    pseudonym: str


@dataclass(frozen=True, slots=True)
class PseudonymizedText:
    text: str
    replacements: tuple[Replacement, ...]


class Pseudonymizer:
    def __init__(
        self,
        session: Session | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        generators: Mapping[EntityType, Generator] | None = None,
    ) -> None:
        self.session = session or Session()
        self._max_attempts = max_attempts
        self._generators = dict(GENERATORS) | dict(generators or {})
        self._doc_tokens: frozenset[str] = frozenset()

    @property
    def derivation(self) -> KeyedDerivation:
        return self.session.derivation

    def pseudonym(self, entity_type: EntityType, value: str) -> str:
        keep_if = KEEP_IF.get(entity_type)
        # A value without any letter or digit carries no information (and cannot be changed
        # while keeping its format).
        if not has_content(value) or (keep_if is not None and keep_if(value)):
            key = (entity_type.value, value)
            if self.session.lookup(key) is None:
                self.session.register(key, value, kept=True)
            return value
        generator = self._generators[entity_type]
        return self._pseudonym(entity_type.value, value, generator, entity_type in BIJECTIVE)

    def _pseudonym(
        self, namespace: str, value: str, generator: Generator, bijective: bool = False
    ) -> str:
        key = (namespace, value)
        cached = self.session.lookup(key)
        if cached is not None:
            return cached
        if bijective:
            candidate = generator(value, self, 0)
            self.session.register(key, candidate, kept=candidate == value)
            return candidate
        for counter in range(self._max_attempts):
            candidate = generator(value, self, counter)
            if self._acceptable(candidate, value):
                self.session.register(key, candidate)
                return candidate
        raise PseudonymizationError(
            f"no acceptable pseudonym for a {namespace} value after {self._max_attempts} attempts"
        )

    def _acceptable(self, candidate: str, original: str) -> bool:
        if candidate == original:
            return False
        if self.session.original_of(candidate) not in (None, original):
            return False
        if self.session.is_original(candidate) or candidate in self._doc_tokens:
            return False
        return _scalar_kind(candidate) == _scalar_kind(original)

    def pseudonym_for_span(self, span: Span, text: str) -> str:
        value = span.text_of(text)
        if span.merged:
            return self._pseudonym(f"merged:{span.entity_type.value}", value, opaque)
        return self.pseudonym(span.entity_type, value)

    def pseudonymize_text(self, text: str, spans: Iterable[Span]) -> PseudonymizedText:
        """Replace resolved (sorted, disjoint) spans. Raises on overlapping input: resolution
        must happen first (ADR 0006)."""
        ordered = list(spans)
        for left, right in itertools.pairwise(ordered):
            if left.end > right.start:
                raise PseudonymizationError("spans must be sorted and disjoint")
        if ordered and ordered[-1].end > len(text):
            raise PseudonymizationError("span outside the text")

        self._doc_tokens = frozenset(_DOC_TOKEN.findall(text))
        try:
            parts: list[str] = []
            replacements: list[Replacement] = []
            cursor = 0
            for span in ordered:
                pseudonym = self.pseudonym_for_span(span, text)
                parts.append(text[cursor : span.start])
                parts.append(pseudonym)
                replacements.append(Replacement(span, pseudonym))
                cursor = span.end
            parts.append(text[cursor:])
        finally:
            self._doc_tokens = frozenset()
        return PseudonymizedText("".join(parts), tuple(replacements))
