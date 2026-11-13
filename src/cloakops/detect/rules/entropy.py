"""Unknown secret formats, caught by how random they look.

Shannon entropy H = -sum(p_i * log2 p_i) over the character frequencies of a string measures,
in bits per character, how unpredictable it is. A random base64 string approaches 6 bits/char,
English words sit around 3-4. Raw entropy grows with length (a 20-char string cannot use more
than 20 distinct characters), so we normalize by the maximum reachable entropy,
log2(min(length, alphabet size)), and compare that ratio to a threshold.

This is the last-resort rule: low confidence, more false positives than the others.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator

from cloakops.detect.rules.base import Rule, span_for
from cloakops.model import EntityType, Span

_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_.-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_.-])")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
_WORD_RUN = re.compile(r"[a-z]{9,}")
_DIGEST_PREFIX = re.compile(r"(?:sha1|sha256|sha384|sha512|md5):$", re.I)

MIN_LENGTH = 20
BASE64_THRESHOLD = 0.85
HEX_THRESHOLD = 0.80
CONFIDENCE = 0.5


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def normalized_entropy(value: str, alphabet_size: int) -> float:
    if len(value) < 2:
        return 0.0
    return shannon_entropy(value) / math.log2(min(len(value), alphabet_size))


def looks_random(token: str) -> bool:
    core = token.rstrip("=")
    if len(core) < MIN_LENGTH:
        return False
    if _HEX.fullmatch(core):
        has_digit = any(c.isdigit() for c in core)
        has_alpha = any(c.isalpha() for c in core)
        return has_digit and has_alpha and normalized_entropy(core.lower(), 16) >= HEX_THRESHOLD
    # Mixed case + digits: excludes identifiers, paths and words that are long but readable.
    if not (
        any(c.isupper() for c in core)
        and any(c.islower() for c in core)
        and any(c.isdigit() for c in core)
    ):
        return False
    # Words inside: in random base64 a lowercase letter has probability ~0.4, so a run of 9 has
    # 0.4^9 ~ 2.6e-4 per position: 0.59% of random 40-char secrets measured (the recall cost). Names
    # made of words (sha256WithRSAEncryption) usually contain one. A run of 7 was tried first:
    # it would have dropped ~5% of real 40-char secrets.
    if _WORD_RUN.search(core):
        return False
    return normalized_entropy(core, 64) >= BASE64_THRESHOLD


class EntropyRule:
    name = "high-entropy"

    def find(self, text: str) -> Iterator[Span]:
        for match in _CANDIDATE.finditer(text):
            if _DIGEST_PREFIX.search(text, max(0, match.start() - 8), match.start()):
                continue  # content digests (image@sha256:...) identify, they do not authenticate
            if looks_random(match.group()):
                yield span_for(
                    self.name, match.start(), match.end(), EntityType.GENERIC_SECRET, CONFIDENCE
                )


def entropy_rules() -> list[Rule]:
    return [EntropyRule()]
