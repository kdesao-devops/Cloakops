"""Keyed derivation: every pseudonym is a deterministic function of (session key, value).

HMAC-SHA256 is a pseudo-random function (PRF): without the key its output is indistinguishable
from random, and it cannot be inverted by trying candidate inputs (unlike an unkeyed hash of a
12-digit account ID, which can be brute-forced). Domain separation (a `domain` string per use)
makes the outputs for different purposes independent even for the same value.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterator

KEY_BYTES = 32


class KeyedDerivation:
    def __init__(self, key: bytes) -> None:
        if len(key) < KEY_BYTES:
            raise ValueError(f"key must be at least {KEY_BYTES} bytes")
        self._key = key
        self._bit_cache: dict[tuple[str, str], int] = {}

    @classmethod
    def random(cls) -> KeyedDerivation:
        return cls(secrets.token_bytes(KEY_BYTES))

    def __repr__(self) -> str:
        return "KeyedDerivation(<key hidden>)"

    def digest(self, domain: str, value: str, counter: int = 0, block: int = 0) -> bytes:
        message = b"\x00".join(
            (
                domain.encode(),
                value.encode("utf-8", "surrogatepass"),
                str(counter).encode(),
                str(block).encode(),
            )
        )
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def stream(self, domain: str, value: str, counter: int = 0) -> Iterator[int]:
        """Unbounded pseudo-random byte stream (HMAC in counter mode)."""
        block = 0
        while True:
            yield from self.digest(domain, value, counter, block)
            block += 1

    def choice(self, alphabet: str, length: int, domain: str, value: str, counter: int = 0) -> str:
        stream = self.stream(domain, value, counter)
        return "".join(pick(stream, alphabet) for _ in range(length))

    def bit(self, domain: str, value: str) -> int:
        """One pseudo-random bit, cached (prefix-preserving IP permutation asks for many)."""
        key = (domain, value)
        cached = self._bit_cache.get(key)
        if cached is None:
            cached = self.digest(domain, value)[0] & 1
            self._bit_cache[key] = cached
        return cached


def pick(stream: Iterator[int], alphabet: str) -> str:
    """Uniform choice from `alphabet` using rejection sampling.

    `byte % n` alone is biased when 256 is not a multiple of n (some characters would come out
    more often); bytes above the largest multiple of n are discarded instead.
    """
    n = len(alphabet)
    limit = 256 - (256 % n)
    for byte in stream:
        if byte < limit:
            return alphabet[byte % n]
    raise AssertionError("unreachable: the stream is unbounded")
