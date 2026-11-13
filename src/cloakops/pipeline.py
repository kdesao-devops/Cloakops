"""The full local pipeline for one session:

    detect -> resolve -> learn + propagate -> resolve -> pseudonymize -> re-scan

`mask` either returns text that is safe to send, or raises a `FailClosedError` (detection
failure, no acceptable pseudonym, leak found by the re-scan). There is no partial result.
`unmask` restores real values in the model's answer.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from cloakops.detect.base import Detector, run_detectors
from cloakops.model import Category, Span
from cloakops.propagate import Propagator
from cloakops.pseudo.engine import Pseudonymizer, Replacement
from cloakops.pseudo.session import Session
from cloakops.reinject import ReinjectedText, Reinjector
from cloakops.rescan import LeakDetectedError, rescan
from cloakops.resolve import resolve_overlaps


@dataclass(frozen=True, slots=True)
class MaskResult:
    text: str
    replacements: tuple[Replacement, ...]
    propagated: int  # spans added by propagation (for the audit receipt)


class Pipeline:
    def __init__(
        self,
        detectors: Sequence[Detector],
        session: Session | None = None,
        propagator: Propagator | None = None,
        restore_categories: Iterable[Category] | None = None,
        propagate: bool = True,
    ) -> None:
        self.detectors = tuple(detectors)
        self.session = session if session is not None else Session()
        self.propagator = propagator if propagator is not None else Propagator()
        self._pseudonymizer = Pseudonymizer(self.session)
        self._reinjector = Reinjector(self.session, restore_categories)
        self._propagate = propagate  # off only to measure what propagation adds (benchmark)

    def detect(self, text: str) -> tuple[list[Span], int]:
        spans = resolve_overlaps(run_detectors(text, self.detectors))
        if not self._propagate:
            return spans, 0
        self.propagator.learn(text, spans)
        extra = self.propagator.expand(text)
        if not extra:
            return spans, 0
        merged = resolve_overlaps([*spans, *extra])
        return merged, len(merged) - len(spans)

    def mask(self, text: str) -> MaskResult:
        spans, propagated = self.detect(text)
        masked = self._pseudonymizer.pseudonymize_text(text, spans)
        findings = rescan(text, masked, self.session, self.detectors)
        if findings:
            raise LeakDetectedError(findings)
        return MaskResult(masked.text, masked.replacements, max(propagated, 0))

    def unmask(self, text: str) -> ReinjectedText:
        return self._reinjector.reinject(text)
