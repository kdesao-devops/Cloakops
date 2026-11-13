"""Output re-scan: the last check before anything leaves the machine (ADR 0012, ADR 0014).

1. **Always** (fast, string search): does any original value that was replaced still appear in
   the output?
2. **Opt-in** (paranoid / strict, runs every detector again): do the detectors find something
   that is neither a known pseudonym nor part of one?

What happens to findings is the pipeline's decision: by default they are redacted
(`[REDACTED]`) with a warning; in strict mode they raise `LeakDetectedError` (fail closed).
Findings carry positions and types, never values. Values that are not distinctive (short,
generic, common words: see `propagate.is_distinctive`) are not checked by (1): they cannot be
told apart from ordinary text (documented residual risk).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace

from cloakops.detect.base import Detector, run_detectors
from cloakops.errors import FailClosedError
from cloakops.model import EntityType
from cloakops.propagate import is_distinctive
from cloakops.pseudo.engine import PseudonymizedText, Replacement
from cloakops.pseudo.session import Session
from cloakops.resolve import resolve_overlaps


@dataclass(frozen=True, slots=True)
class Finding:
    start: int  # position in the output
    end: int
    entity_type: EntityType
    reason: str  # "original-value" | "redetected"


class LeakDetectedError(FailClosedError):
    def __init__(self, findings: Iterable[Finding]) -> None:
        self.findings = tuple(findings)
        kinds = sorted({f"{f.entity_type.value} ({f.reason})" for f in self.findings})
        super().__init__(
            f"output re-scan found {len(self.findings)} unmasked value(s): {', '.join(kinds)}"
        )


def _bounded(value: str) -> re.Pattern[str]:
    before = r"(?<![A-Za-z0-9])" if value[0].isalnum() else ""
    after = r"(?![A-Za-z0-9])" if value[-1].isalnum() else ""
    return re.compile(f"{before}{re.escape(value)}{after}")


def rescan(
    original: str,
    masked: PseudonymizedText,
    session: Session,
    detectors: Iterable[Detector] | None = None,
) -> list[Finding]:
    """`detectors=None` runs only the fast check (1)."""
    output = masked.text
    findings: list[Finding] = []

    # 1. Original values still present.
    checked: set[str] = set()
    for replacement in masked.replacements:
        value = replacement.span.text_of(original)
        if value in checked or value in session.kept or not is_distinctive(value):
            continue
        checked.add(value)
        for m in _bounded(value).finditer(output):
            findings.append(
                Finding(m.start(), m.end(), replacement.span.entity_type, "original-value")
            )

    # 2. Detections in the output that are not pseudonyms (opt-in: it costs a second detection).
    if detectors is None:
        return findings
    replaced = [(r.output_start, r.output_end) for r in masked.replacements]

    def outside_replacements(start: int, end: int) -> bool:
        for i in range(start, end):
            if output[i].isalnum() and not any(a <= i < b for a, b in replaced):
                return True
        return False

    for span in resolve_overlaps(run_detectors(output, detectors)):
        text = span.text_of(output)
        if session.original_of(text) is not None:
            continue  # a pseudonym (or a kept value) of this session
        if outside_replacements(span.start, span.end):
            findings.append(Finding(span.start, span.end, span.entity_type, "redetected"))
    return findings


REDACTED = "[REDACTED]"


@dataclass(frozen=True, slots=True)
class Redacted:
    text: str
    replacements: tuple[Replacement, ...]  # output offsets shifted to the redacted text


def redact(
    masked: PseudonymizedText, findings: Iterable[Finding], marker: str = REDACTED
) -> Redacted:
    """Replace each finding (merged when overlapping) with `marker`, and shift the output offsets
    of the replacements accordingly. A finding overlapping a pseudonym cannot be redacted without
    corrupting it: that is a pipeline bug, so it fails closed."""
    regions: list[list[int]] = []
    for f in sorted(findings, key=lambda f: (f.start, f.end)):
        if regions and f.start < regions[-1][1]:
            regions[-1][1] = max(regions[-1][1], f.end)
        else:
            regions.append([f.start, f.end])
    for start, end in regions:
        if any(r.output_start < end and start < r.output_end for r in masked.replacements):
            raise LeakDetectedError(findings)

    parts: list[str] = []
    cursor = 0
    shifts: list[tuple[int, int]] = []  # (position in old output, cumulative delta after it)
    delta = 0
    for start, end in regions:
        parts += [masked.text[cursor:start], marker]
        delta += len(marker) - (end - start)
        shifts.append((end, delta))
        cursor = end
    parts.append(masked.text[cursor:])

    def shift(position: int) -> int:
        applied = 0
        for boundary, cumulative in shifts:
            if boundary <= position:
                applied = cumulative
        return position + applied

    replacements = tuple(
        replace(r, output_start=shift(r.output_start), output_end=shift(r.output_end))
        for r in masked.replacements
    )
    return Redacted("".join(parts), replacements)
