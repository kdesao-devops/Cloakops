"""The full local pipeline for one session:

    detect -> resolve -> learn + propagate -> resolve -> pseudonymize -> re-scan

`mask` either returns text that is safe to send, or raises a `FailClosedError` (detection
failure, no acceptable pseudonym, residue found by the re-scan). With `redact=True`
(CLI `--redact`), residues are replaced by `[REDACTED]` with a warning instead. The full
re-detection of the output runs only with `paranoid=True` (CLI `--paranoid`) (ADR 0014).
`unmask` restores real values in the model's answer.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cloakops.detect.base import Detector, run_detectors
from cloakops.model import Category, Span
from cloakops.propagate import Propagator
from cloakops.pseudo.engine import Pseudonymizer, Replacement
from cloakops.pseudo.session import Session
from cloakops.reinject import ReinjectedText, Reinjector
from cloakops.rescan import REDACTED, Finding, LeakDetectedError, redact, rescan
from cloakops.resolve import resolve_overlaps


@dataclass(frozen=True, slots=True)
class MaskResult:
    text: str
    replacements: tuple[Replacement, ...]
    propagated: int  # spans added by propagation (for the audit receipt)
    redactions: tuple[Finding, ...] = field(default=())  # residues redacted by the re-scan


logger = logging.getLogger("cloakops")


class Pipeline:
    def __init__(
        self,
        detectors: Sequence[Detector],
        session: Session | None = None,
        propagator: Propagator | None = None,
        restore_categories: Iterable[Category] | None = None,
        propagate: bool = True,
        redact: bool = False,
        paranoid: bool = False,
        redaction_marker: str = REDACTED,
    ) -> None:
        """redact: re-scan residues are redacted with a warning instead of failing closed.
        paranoid: the output is also re-scanned with every detector (costs a second detection)."""
        self.detectors = tuple(detectors)
        self.session = session if session is not None else Session()
        self.propagator = propagator if propagator is not None else Propagator()
        self._pseudonymizer = Pseudonymizer(self.session)
        self._reinjector = Reinjector(self.session, restore_categories)
        self._propagate = propagate  # off only to measure what propagation adds (benchmark)
        self._redact = redact
        self._redetect = paranoid
        self._marker = redaction_marker

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
        """All or nothing: if masking fails, the session and the learned terms are restored, so a
        refused (possibly attacker-controlled) document leaves no trace in the session."""
        session_length, learned = len(self.session), self.propagator.snapshot()
        try:
            return self._mask(text)
        except BaseException:
            self.session.rollback(session_length)
            self.propagator.restore(learned)
            raise

    def _mask(self, text: str) -> MaskResult:
        spans, propagated = self.detect(text)
        masked = self._pseudonymizer.pseudonymize_text(text, spans)
        findings = rescan(text, masked, self.session, self.detectors if self._redetect else None)
        if not findings:
            return MaskResult(masked.text, masked.replacements, max(propagated, 0))
        if not self._redact:
            raise LeakDetectedError(findings)
        redacted = redact(masked, findings, self._marker)
        kinds = sorted({f"{f.entity_type.value} ({f.reason})" for f in findings})
        logger.warning(
            "re-scan redacted %d residue(s) the masking missed: %s", len(findings), ", ".join(kinds)
        )
        return MaskResult(redacted.text, redacted.replacements, max(propagated, 0), tuple(findings))

    def unmask(self, text: str) -> ReinjectedText:
        return self._reinjector.reinject(text)
