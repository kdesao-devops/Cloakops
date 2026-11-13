"""The rules layer must never crash and never hang, whatever the input."""

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cloakops.detect.base import run_detectors
from cloakops.detect.rules import default_rules_detector

DETECTOR = default_rules_detector(organization_domains=("acme.io",))

# Characters that drive the regexes: separators, quotes, digits, hex, dots, dashes, newlines.
_ALPHABET = st.sampled_from(list("aAzZ09fF.:-_/=+@\"' \t\n{}[]#|>$AKIAeyJ"))


@given(st.text(_ALPHABET, max_size=400))
@settings(max_examples=300, deadline=None)
def test_never_crashes_and_spans_fit_the_text(text: str) -> None:
    for span in run_detectors(text, [DETECTOR]):
        assert 0 <= span.start < span.end <= len(text)


@pytest.mark.parametrize(
    "pathological",
    [
        "a." * 50_000,  # dotted labels without a suffix (hostname rules)
        "1." * 50_000,  # dotted numbers (IPv4)
        "a:" * 50_000,  # colons (IPv6, key/value)
        "-" * 100_000,
        "=" * 100_000,
        "A1b2" * 25_000,  # one huge high-entropy candidate
        "password: " * 10_000,
        "-----BEGIN " + "PRIVATE KEY-----" + " " * 100_000,
        '"' * 100_000,
        "x" * 100_000 + "@" + "y." * 10_000,  # email-like
    ],
    ids=lambda s: repr(s[:12]),
)
def test_no_catastrophic_backtracking(pathological: str) -> None:
    # ReDoS guard: ~100 KB of adversarial input must be scanned in well under a second.
    start = time.perf_counter()
    DETECTOR.detect(pathological)
    assert time.perf_counter() - start < 2.0
