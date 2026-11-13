"""Benchmark documents with ground truth: the exact span of every planted sensitive value.

Two sources:
- synthetic: templates filled by seeded fakes, spans recorded while rendering (no labeling);
- holdout: hand-written files where sensitive values are marked inline as `⟦type|value⟧`. The
  loader strips the markers and records the spans. The markers use characters that do not occur
  in infrastructure text, so they cannot collide with the content.
"""

from __future__ import annotations

import json
import random
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from cloakops.benchmark.fakes import Fakes
from cloakops.benchmark.templates import TEMPLATES, Template
from cloakops.model import EntityType

_PLACEHOLDER = re.compile(r"\{\{([a-z0-9_#]+)\}\}")
_HOLDOUT_MARK = re.compile(r"⟦([a-z_]+)\|(.*?)⟧", re.S)


@dataclass(frozen=True, slots=True)
class Planted:
    start: int
    end: int
    entity_type: EntityType


@dataclass(frozen=True, slots=True)
class Document:
    name: str
    source: str  # "synthetic" | "holdout"
    text: str
    planted: tuple[Planted, ...]

    def value(self, planted: Planted) -> str:
        return self.text[planted.start : planted.end]


def _escape(value: str, mode: str) -> str:
    return json.dumps(value)[1:-1] if mode == "json" else value


def render(template: Template, fakes: Fakes, name: str) -> Document:
    parts: list[str] = []
    planted: list[Planted] = []
    cursor = 0
    length = 0
    for match in _PLACEHOLDER.finditer(template.text):
        before = template.text[cursor : match.start()]
        entity_type, value = fakes.get(match.group(1))
        written = _escape(value, template.escape)
        parts += [before, written]
        start = length + len(before)
        length = start + len(written)
        planted.append(Planted(start, length, entity_type))
        cursor = match.end()
    parts.append(template.text[cursor:])
    return Document(name, "synthetic", "".join(parts), tuple(planted))


def synthetic_corpus(documents_per_template: int = 20, seed: int = 0) -> Iterator[Document]:
    rng = random.Random(seed)  # noqa: S311 (reproducible test data, not cryptography)
    for template in TEMPLATES:
        for i in range(documents_per_template):
            yield render(template, Fakes(rng), f"{template.name}-{i:03d}")


def parse_holdout(text: str, name: str) -> Document:
    parts: list[str] = []
    planted: list[Planted] = []
    cursor = 0
    length = 0
    for match in _HOLDOUT_MARK.finditer(text):
        before = text[cursor : match.start()]
        value = match.group(2)
        parts += [before, value]
        start = length + len(before)
        length = start + len(value)
        planted.append(Planted(start, length, EntityType(match.group(1))))
        cursor = match.end()
    parts.append(text[cursor:])
    return Document(name, "holdout", "".join(parts), tuple(planted))


def holdout_corpus(directory: Path) -> Iterator[Document]:
    for path in sorted(directory.glob("*.txt")):
        yield parse_holdout(path.read_text(encoding="utf-8"), path.stem)
