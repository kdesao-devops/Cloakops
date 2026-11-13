"""Benchmark metrics (ADR 0004).

- Recall per planted type: a planted value counts as caught if every one of its characters is
  covered by a detected span. A miss is a leak.
- Precision per detected type: a masked span (pseudonym differs from the original) is correct if
  it overlaps a planted value; otherwise it is a false positive (over-masking).
- Per-document leak rate: a document fails if a single planted value is missed.
- F2 = 5PR / (4P + R): one score that weighs recall twice as much as precision.

Reports never contain values, only document names, types and positions.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from cloakops.benchmark.corpus import Document, Planted
from cloakops.errors import FailClosedError
from cloakops.model import EntityType, Span
from cloakops.pipeline import Pipeline
from cloakops.pseudo.text import KEEP_WORDS

_RUN = re.compile(r"[^\W_]+")


@dataclass(frozen=True, slots=True)
class Miss:
    document: str
    entity_type: EntityType
    start: int
    end: int


@dataclass
class Report:
    documents: int = 0
    leaked_documents: int = 0
    blocked_documents: int = 0  # refused by the fail-closed pipeline (safe, but unusable)
    merged_spans: int = 0
    planted: Counter[EntityType] = field(default_factory=Counter)
    caught: Counter[EntityType] = field(default_factory=Counter)
    masked: Counter[EntityType] = field(default_factory=Counter)
    masked_correct: Counter[EntityType] = field(default_factory=Counter)
    caught_by: Counter[str] = field(default_factory=Counter)
    misses: list[Miss] = field(default_factory=list)
    false_positives: list[Miss] = field(default_factory=list)

    def recall(self, entity_type: EntityType | None = None) -> float:
        planted = self.planted[entity_type] if entity_type else sum(self.planted.values())
        caught = self.caught[entity_type] if entity_type else sum(self.caught.values())
        return caught / planted if planted else 1.0

    def precision(self, entity_type: EntityType | None = None) -> float:
        masked = self.masked[entity_type] if entity_type else sum(self.masked.values())
        good = (
            self.masked_correct[entity_type] if entity_type else sum(self.masked_correct.values())
        )
        return good / masked if masked else 1.0

    def f2(self) -> float:
        p, r = self.precision(), self.recall()
        return 5 * p * r / (4 * p + r) if p + r else 0.0

    def leak_rate(self) -> float:
        return self.leaked_documents / self.documents if self.documents else 0.0


def required_positions(text: str, planted: Planted) -> list[int]:
    """Positions that must be masked: the whole value, minus generic words the pseudonymizer
    keeps by design (ADR 0010): `deployer` in `acme-payroll-deployer` may stay in clear."""
    value = text[planted.start : planted.end]
    keep: set[int] = set()
    for run in _RUN.finditer(value):
        if run.group().lower() in KEEP_WORDS:
            keep.update(range(run.start(), run.end()))
    if len(keep) == len(value.replace("-", "").replace("_", "").replace(".", "")):
        keep = set()  # a value made only of generic words must still be masked
    return [planted.start + i for i in range(len(value)) if i not in keep]


def _covered(spans: Iterable[Span]) -> set[int]:
    return {i for s in spans for i in range(s.start, s.end)}


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def evaluate(documents: Iterable[Document], make_pipeline: Callable[[], Pipeline]) -> Report:
    """Each document gets a fresh pipeline (fresh session): documents are independent."""
    report = Report()
    for doc in documents:
        pipeline = make_pipeline()
        report.documents += 1
        spans, _ = pipeline.detect(doc.text)
        covered = _covered(spans)
        report.merged_spans += sum(1 for s in spans if s.merged)

        leaked = False
        for planted in doc.planted:
            report.planted[planted.entity_type] += 1
            if all(i in covered for i in required_positions(doc.text, planted)):
                report.caught[planted.entity_type] += 1
                for s in spans:
                    if _overlaps(s.start, s.end, planted.start, planted.end):
                        report.caught_by[s.detector.split(":")[0]] += 1
                        break
            else:
                leaked = True
                report.misses.append(
                    Miss(doc.name, planted.entity_type, planted.start, planted.end)
                )
        report.leaked_documents += leaked

        try:
            result = pipeline.mask(doc.text)
        except FailClosedError:
            report.blocked_documents += 1
            continue
        for r in result.replacements:
            if r.pseudonym == r.span.text_of(doc.text):
                continue  # kept value: not masked, so neither right nor wrong
            report.masked[r.span.entity_type] += 1
            if any(_overlaps(r.span.start, r.span.end, p.start, p.end) for p in doc.planted):
                report.masked_correct[r.span.entity_type] += 1
            else:
                report.false_positives.append(
                    Miss(doc.name, r.span.entity_type, r.span.start, r.span.end)
                )
    return report
