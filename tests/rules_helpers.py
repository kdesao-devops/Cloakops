from __future__ import annotations

from cloakops.detect.rules import Rule, RulesDetector, default_rules_detector
from cloakops.model import EntityType
from cloakops.resolve import resolve_overlaps


def raw(text: str, *rules: Rule) -> list[tuple[EntityType, str]]:
    """Every detection of the given rules, before overlap resolution."""
    spans = RulesDetector(rules).detect(text)
    return sorted((s.entity_type, s.text_of(text)) for s in spans)


def resolved(text: str, organization_domains: tuple[str, ...] = ()) -> list[tuple[EntityType, str]]:
    """What the full default rule set ends up masking, after overlap resolution."""
    detector = default_rules_detector(organization_domains=organization_domains)
    return [(s.entity_type, s.text_of(text)) for s in resolve_overlaps(detector.detect(text))]


def values(text: str, *rules: Rule) -> list[str]:
    return sorted(value for _, value in raw(text, *rules))
