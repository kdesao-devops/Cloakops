from __future__ import annotations

from cloakops.detect.rules import default_rules_detector
from cloakops.model import EntityType
from cloakops.pseudo import KeyedDerivation, Pseudonymizer, Session
from cloakops.resolve import resolve_overlaps

KEY = b"k" * 32
OTHER_KEY = b"o" * 32
DETECTOR = default_rules_detector(organization_domains=("acme.io",))


def engine(key: bytes = KEY) -> Pseudonymizer:
    return Pseudonymizer(Session(KeyedDerivation(key)))


def pseudo(entity_type: EntityType, value: str, key: bytes = KEY) -> str:
    return engine(key).pseudonym(entity_type, value)


def mask(text: str, pseudonymizer: Pseudonymizer | None = None) -> str:
    """Full pipeline: detect, resolve, pseudonymize."""
    spans = resolve_overlaps(DETECTOR.detect(text))
    return (pseudonymizer or engine()).pseudonymize_text(text, spans).text
