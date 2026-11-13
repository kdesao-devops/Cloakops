"""Benchmark report rendering (JSON for the CI gate, Markdown for humans). No values."""

from __future__ import annotations

from typing import Any

from cloakops.benchmark.metrics import Report
from cloakops.model import EntityType


def to_dict(report: Report) -> dict[str, Any]:
    types = sorted(set(report.planted) | set(report.masked), key=lambda t: t.value)
    return {
        "documents": report.documents,
        "leaked_documents": report.leaked_documents,
        "blocked_documents": report.blocked_documents,
        "merged_spans": report.merged_spans,
        "recall": round(report.recall(), 4),
        "precision": round(report.precision(), 4),
        "f2": round(report.f2(), 4),
        "per_type": {
            t.value: {
                "planted": report.planted[t],
                "caught": report.caught[t],
                "recall": round(report.recall(t), 4),
                "masked": report.masked[t],
                "precision": round(report.precision(t), 4),
            }
            for t in types
        },
        "caught_by_layer": dict(sorted(report.caught_by.items())),
        "misses": [
            {"document": m.document, "type": m.entity_type.value, "start": m.start, "end": m.end}
            for m in report.misses
        ],
        "false_positives": [
            {"document": m.document, "type": m.entity_type.value, "start": m.start, "end": m.end}
            for m in report.false_positives
        ],
    }


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def to_markdown(reports: dict[str, Report]) -> str:
    lines = ["# Benchmark results", ""]
    lines += ["| Corpus | Docs | Recall | Precision | F2 | Docs with a leak | Blocked |"]
    lines += ["|---|---|---|---|---|---|---|"]
    for name, r in reports.items():
        if not r.documents:
            lines.append(f"| {name} | 0 | n/a | n/a | n/a | n/a | n/a |")
            continue
        lines.append(
            f"| {name} | {r.documents} | {_pct(r.recall())} | {_pct(r.precision())} | "
            f"{r.f2():.3f} | {r.leaked_documents} ({_pct(r.leak_rate())}) | {r.blocked_documents} |"
        )
    for name, r in reports.items():
        if not r.documents:
            continue
        lines += ["", f"## {name}", ""]
        lines += [
            "| Entity type | Planted | Recall | Masked | Precision |",
            "|---|---|---|---|---|",
        ]
        types = sorted(set(r.planted) | set(r.masked), key=lambda t: t.value)
        for t in types:
            recall = _pct(r.recall(t)) if r.planted[t] else "-"
            precision = _pct(r.precision(t)) if r.masked[t] else "-"
            lines.append(f"| {t.value} | {r.planted[t]} | {recall} | {r.masked[t]} | {precision} |")
        if r.misses:
            lines += ["", "Missed (leaks):", ""]
            by_type: dict[EntityType, list[str]] = {}
            for m in r.misses:
                by_type.setdefault(m.entity_type, []).append(m.document)
            for t, docs in sorted(by_type.items(), key=lambda kv: kv[0].value):
                lines.append(f"- {t.value}: {len(docs)} in {', '.join(sorted(set(docs))[:6])}")
    return "\n".join(lines) + "\n"
