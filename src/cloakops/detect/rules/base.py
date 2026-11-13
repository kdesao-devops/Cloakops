"""Building blocks of the deterministic rules layer.

A `Rule` finds spans of one kind. Most rules are a single regular expression (`RegexRule`);
the few that need more logic (IPv6 validation, Kubernetes Secret blocks, key/value parsing)
implement `find` themselves. `RulesDetector` runs a list of rules and is the `Detector` the
pipeline sees.

ReDoS note: inputs (logs!) may be attacker-controlled, and Python's `re` has no timeout. Every
pattern here avoids nested quantifiers over overlapping character classes, and a test feeds the
whole rule set pathological inputs under a time budget.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Protocol

from cloakops.model import EntityType, Span

RULES_DETECTOR_NAME = "rules"


class Rule(Protocol):
    @property
    def name(self) -> str: ...

    def find(self, text: str) -> Iterator[Span]: ...


def span_for(rule_name: str, start: int, end: int, entity_type: EntityType, conf: float) -> Span:
    return Span(start, end, entity_type, f"{RULES_DETECTOR_NAME}:{rule_name}", conf)


@dataclass(frozen=True)
class RegexRule:
    """One regex, one entity type. `group` selects the part of the match that is sensitive."""

    name: str
    entity_type: EntityType
    pattern: re.Pattern[str]
    group: int | str = 0
    confidence: float = 1.0
    validate: Callable[[str], bool] | None = None

    def find(self, text: str) -> Iterator[Span]:
        for match in self.pattern.finditer(text):
            start, end = match.span(self.group)
            if start < 0 or start == end:  # optional group that did not participate
                continue
            if self.validate is not None and not self.validate(text[start:end]):
                continue
            yield span_for(self.name, start, end, self.entity_type, self.confidence)


class RulesDetector:
    """The rules layer as a single `Detector`."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: tuple[Rule, ...] = tuple(rules)
        names = [rule.name for rule in self._rules]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate rule names: {sorted(duplicates)}")

    @property
    def name(self) -> str:
        return RULES_DETECTOR_NAME

    @property
    def rules(self) -> Sequence[Rule]:
        return self._rules

    def detect(self, text: str) -> list[Span]:
        return [span for rule in self._rules for span in rule.find(text)]
