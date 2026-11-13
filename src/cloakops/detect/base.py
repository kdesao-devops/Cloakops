"""Detector interface and the fail-closed runner.

Every detection layer (rules, NER, local LLM) implements `Detector`. The pipeline never calls a
detector directly: it goes through `run_detectors`, which turns any failure (exception, or a
span that does not fit the text) into a `DetectionError`. Callers must treat that error as
"nothing may be sent", never as "no entities found".
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol

from cloakops.errors import FailClosedError
from cloakops.model import Span


class DetectionError(FailClosedError):
    """A detector failed or misbehaved. The input must not leave the machine."""


class Detector(Protocol):
    @property
    def name(self) -> str: ...

    def detect(self, text: str) -> Sequence[Span]: ...


def run_detectors(text: str, detectors: Iterable[Detector]) -> list[Span]:
    """Run every detector on `text` and return all spans, unresolved (overlaps included)."""
    spans: list[Span] = []
    for detector in detectors:
        try:
            found = list(detector.detect(text))
        except Exception as exc:
            raise DetectionError(f"detector {detector.name!r} failed") from exc
        for span in found:
            if span.end > len(text):
                raise DetectionError(
                    f"detector {detector.name!r} returned span [{span.start}, {span.end}) "
                    f"outside a text of length {len(text)}"
                )
        spans.extend(found)
    return spans
