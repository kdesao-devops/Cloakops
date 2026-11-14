"""Session state: the key and the mapping table (pseudonym <-> real value).

Phase 1 keeps it in memory. Phase 3 persists it encrypted with a TTL (ADR 0003).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from cloakops.pseudo.keyed import KeyedDerivation

MappingKey = tuple[str, str]  # (namespace, original value); namespace = entity type or merged:*


@dataclass(frozen=True, slots=True)
class MappingEntry:
    namespace: str
    original: str
    pseudonym: str


class Session:
    def __init__(self, derivation: KeyedDerivation | None = None) -> None:
        self.derivation = derivation if derivation is not None else KeyedDerivation.random()
        self._forward: dict[MappingKey, str] = {}
        self._reverse: dict[str, str] = {}
        self._originals: set[str] = set()
        self._kept: set[str] = set()

    def __repr__(self) -> str:
        return f"Session(<{len(self._forward)} mappings>)"

    def __len__(self) -> int:
        return len(self._forward)

    def entries(self) -> Iterator[MappingEntry]:
        """Every mapping, kept values included (pseudonym == original)."""
        for (namespace, original), pseudonym in self._forward.items():
            yield MappingEntry(namespace, original, pseudonym)

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

    def rollback(self, length: int) -> None:
        """Forget the mappings added after the session had `length` of them (sessions only
        grow, in insertion order). Used when a mask fails: a refused document leaves no trace."""
        for key in list(self._forward)[length:]:
            self._forward.pop(key)
        self._reverse = {pseudonym: original for (_, original), pseudonym in self._forward.items()}
        self._originals = {original for (_, original) in self._forward}
        self._kept &= self._originals

    def export_state(self) -> dict[str, object]:
        """Everything needed to resume the session in another process (holds real values)."""
        return {
            "key": self.derivation.export_key().hex(),
            "mappings": [
                [namespace, original, pseudonym, original in self._kept and pseudonym == original]
                for (namespace, original), pseudonym in self._forward.items()
            ],
        }

    @classmethod
    def from_state(cls, state: Mapping[str, object]) -> Session:
        key = state["key"]
        mappings = state["mappings"]
        if not isinstance(key, str) or not isinstance(mappings, list):
            raise ValueError("invalid session state")
        session = cls(KeyedDerivation(bytes.fromhex(key)))
        for namespace, original, pseudonym, kept in mappings:
            session.register((str(namespace), str(original)), str(pseudonym), kept=bool(kept))
        return session

    @property
    def reverse(self) -> Mapping[str, str]:
        """pseudonym -> original, for re-injection."""
        return MappingProxyType(self._reverse)

    @property
    def kept(self) -> frozenset[str]:
        """Detected values intentionally left unchanged (special IPs, well-known names)."""
        return frozenset(self._kept)
