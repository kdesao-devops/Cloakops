"""Output re-scan: the last check before anything leaves the machine (ADR 0012).

Independent of how masking was done, two questions are asked about the OUTPUT text:

1. Does any original value that was replaced still appear in it? (value-based)
2. Do the detectors find something that is neither a known pseudonym nor part of one?
   (detection-based)

Either finding raises `LeakDetectedError`: fail closed. Findings carry positions and types,
never values. Values that are not distinctive (short, generic, common words: see
`propagate.is_distinctive`) are not checked by (1): they cannot be told apart from ordinary
text (documented residual risk).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from cloakops.detect.base import Detector, run_detectors
from cloakops.errors import FailClosedError
from cloakops.model import EntityType
from cloakops.propagate import is_distinctive
from cloakops.pseudo.engine import PseudonymizedText
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
    detectors: Iterable[Detector],
) -> list[Finding]:
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

    # 2. Detections in the output that are not pseudonyms.
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
