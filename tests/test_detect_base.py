from collections.abc import Sequence

import pytest

from cloakops.detect.base import DetectionError, run_detectors
from cloakops.model import EntityType, Span


class FixedDetector:
    def __init__(self, name: str, spans: Sequence[Span]) -> None:
        self._name = name
        self._spans = spans

    @property
    def name(self) -> str:
        return self._name

    def detect(self, text: str) -> Sequence[Span]:
        return self._spans


class BrokenDetector:
    name = "broken"

    def detect(self, text: str) -> Sequence[Span]:
        raise RuntimeError("model timed out")


def span(start: int, end: int) -> Span:
    return Span(start, end, EntityType.HOSTNAME, "fixed")


def test_spans_from_all_detectors_are_collected() -> None:
    detectors = [FixedDetector("a", [span(0, 2)]), FixedDetector("b", [span(1, 3)])]
    assert run_detectors("abcdef", detectors) == [span(0, 2), span(1, 3)]


def test_failing_detector_fails_closed() -> None:
    with pytest.raises(DetectionError, match="broken"):
        run_detectors("text", [FixedDetector("ok", []), BrokenDetector()])


def test_span_outside_the_text_fails_closed() -> None:
    with pytest.raises(DetectionError, match="outside"):
        run_detectors("abc", [FixedDetector("buggy", [span(1, 10)])])
