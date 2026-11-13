"""Kubernetes Secret objects: every value under `data` / `stringData` is secret, whatever its
key is called (`config.json`, `tls.crt`, `DB_URL`...). Keys stay visible: they tell the model
what the Secret is for.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator

from cloakops.detect.rules.base import Rule, span_for
from cloakops.model import EntityType, Span

_YAML_DOC_SEPARATOR = re.compile(r"^---[ \t]*$", re.M)
_YAML_KIND_SECRET = re.compile(r"^[ \t-]*kind:[ \t]*[\"']?Secret[\"']?[ \t]*$", re.M)
_YAML_DATA_KEY = re.compile(r"^(?P<indent>[ \t]*)(?:data|stringData):[ \t]*$", re.M)
_YAML_CHILD = re.compile(
    r"(?P<key>[^\s:#][^:\n]*?|\"[^\"\n]+\"|'[^'\n]+'):(?:[ \t]+(?P<value>.*))?$"
)

_JSON_KIND_SECRET = re.compile(r"\"kind\"[ \t]*:[ \t]*\"Secret\"")
_JSON_DATA_OBJECT = re.compile(r"\"(?:data|stringData)\"\s*:\s*\{(?P<body>[^{}]*)\}")
_JSON_PAIR = re.compile(r"\"(?:[^\"\\]|\\.)*\"\s*:\s*\"(?P<value>(?:[^\"\\]|\\.)*)\"")

_ENTITY = EntityType.GENERIC_SECRET


class KubernetesSecretRule:
    name = "k8s-secret-data"

    def find(self, text: str) -> Iterator[Span]:
        yield from self._find_yaml(text)
        yield from self._find_json(text)

    def _find_yaml(self, text: str) -> Iterator[Span]:
        bounds = [0, *(m.end() for m in _YAML_DOC_SEPARATOR.finditer(text)), len(text)]
        for doc_start, doc_end in itertools.pairwise(bounds):
            doc = text[doc_start:doc_end]
            if not _YAML_KIND_SECRET.search(doc):
                continue
            for data in _YAML_DATA_KEY.finditer(doc):
                yield from self._yaml_block(text, doc_start + data.end(), len(data["indent"]))

    def _yaml_block(self, text: str, pos: int, parent_indent: int) -> Iterator[Span]:
        child_indent: int | None = None
        pos = text.find("\n", pos)
        while pos >= 0 and pos < len(text):
            line_start = pos + 1
            line_end = text.find("\n", line_start)
            line_end = len(text) if line_end < 0 else line_end
            line = text[line_start:line_end].rstrip("\r")
            pos = line_end if line_end < len(text) else -1
            content = line.lstrip(" \t")
            if not content or content.startswith("#"):
                continue
            indent = len(line) - len(content)
            if indent <= parent_indent:
                return
            if child_indent is None:
                child_indent = indent
            content_start = line_start + indent
            if indent == child_indent:
                child = _YAML_CHILD.match(content)
                if child and child.group("value"):
                    value = child.group("value").strip()
                    if value and not re.fullmatch(r"[|>][+-]?[0-9]?", value):
                        start = content_start + child.start("value")
                        yield span_for(self.name, start, start + len(value), _ENTITY, 1.0)
                continue
            # Deeper line: continuation of a block scalar (certificate, JSON blob...).
            yield span_for(self.name, content_start, line_start + len(line.rstrip()), _ENTITY, 1.0)

    def _find_json(self, text: str) -> Iterator[Span]:
        if not _JSON_KIND_SECRET.search(text):
            return
        for data in _JSON_DATA_OBJECT.finditer(text):
            offset = data.start("body")
            for pair in _JSON_PAIR.finditer(data.group("body")):
                if pair.group("value"):
                    start, end = pair.span("value")
                    yield span_for(self.name, offset + start, offset + end, _ENTITY, 1.0)


def k8s_rules() -> list[Rule]:
    return [KubernetesSecretRule()]
