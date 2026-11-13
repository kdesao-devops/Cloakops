"""Session state: the key and the mapping table (pseudonym <-> real value).

Phase 1 keeps it in memory. Phase 3 persists it encrypted with a TTL (ADR 0003).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from cloakops.pseudo.keyed import KeyedDerivation

MappingKey = tuple[str, str]  # (namespace, original value); namespace = entity type or merged:*


class Session:
    def __init__(self, derivation: KeyedDerivation | None = None) -> None:
        self.derivation = derivation or KeyedDerivation.random()
        self._forward: dict[MappingKey, str] = {}
        self._reverse: dict[str, str] = {}
        self._originals: set[str] = set()
        self._kept: set[str] = set()

    def __repr__(self) -> str:
        return f"Session(<{len(self._forward)} mappings>)"

    def lookup(self, key: MappingKey) -> str | None:
        return self._forward.get(key)

    def original_of(self, pseudonym: str) -> str | None:
        return self._reverse.get(pseudonym)

    def is_original(self, value: str) -> bool:
        return value in self._originals

    def register(self, key: MappingKey, pseudonym: str, kept: bool = False) -> None:
        original = key[1]
        existing = self._reverse.get(pseudonym)
        if existing is not None and existing != original:
            raise ValueError("pseudonym already maps to another value")
        self._forward[key] = pseudonym
        self._reverse[pseudonym] = original
        self._originals.add(original)
        if kept:
            self._kept.add(original)

    @property
    def reverse(self) -> Mapping[str, str]:
        """pseudonym -> original, for re-injection."""
        return MappingProxyType(self._reverse)

    @property
    def kept(self) -> frozenset[str]:
        """Detected values intentionally left unchanged (special IPs, well-known names)."""
        return frozenset(self._kept)
