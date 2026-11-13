"""Run the detection benchmark and enforce the recall ratchet.

    uv run python bench/run.py                       # evaluate, write reports, check gates
    uv run python bench/run.py --update-thresholds   # after an improvement: raise the ratchet

Corpora:
- synthetic: seeded templates (what the rules were written against: a regression signal);
- dev: hand-written samples already used to improve the rules (bench/corpus/dev);
- holdout: hand-written samples never used to tune anything (bench/corpus/holdout). Once a
  holdout sample has driven a fix, it moves to dev (ADR 0004).
Each corpus is evaluated with and without propagation, to measure what propagation adds.
The gate fails if any per-type recall drops below bench/thresholds.json (a ratchet: thresholds
only go up, so a regression cannot slip in unnoticed).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cloakops.benchmark.corpus import holdout_corpus, synthetic_corpus
from cloakops.benchmark.metrics import Report, evaluate
from cloakops.benchmark.report import to_dict, to_markdown
from cloakops.detect.rules import default_rules_detector
from cloakops.pipeline import Pipeline
from cloakops.pseudo import KeyedDerivation, Session

BENCH = Path(__file__).resolve().parent
THRESHOLDS = BENCH / "thresholds.json"
REPORTS = BENCH / "reports"
KEY = b"benchmark-fixed-key-not-a-secret"  # reproducible pseudonyms; never used for real data


def make_pipeline(propagate: bool, redact: bool = False) -> Pipeline:
    detector = default_rules_detector()
    return Pipeline([detector], Session(KeyedDerivation(KEY)), propagate=propagate, redact=redact)


def run() -> dict[str, Report]:
    corpora = {
        "synthetic": list(synthetic_corpus(documents_per_template=20, seed=0)),
        "dev": list(holdout_corpus(BENCH / "corpus" / "dev")),
        "holdout": list(holdout_corpus(BENCH / "corpus" / "holdout")),
    }
    reports: dict[str, Report] = {}
    for name, documents in corpora.items():
        reports[name] = evaluate(documents, lambda: make_pipeline(propagate=True))
        reports[f"{name} (no propagation)"] = evaluate(
            documents, lambda: make_pipeline(propagate=False)
        )
        reports[f"{name} (no propagation, --redact)"] = evaluate(
            documents, lambda: make_pipeline(propagate=False, redact=True)
        )
    return reports


def gate(reports: dict[str, Report], thresholds: dict[str, dict[str, float]]) -> list[str]:
    failures = []
    for corpus, per_type in thresholds.items():
        report = reports[corpus]
        for type_name, minimum in per_type.items():
            actual = round(
                report.recall()
                if type_name == "_overall"
                else report.recall(next(t for t in report.planted if t.value == type_name)),
                4,
            )
            if actual < minimum:
                failures.append(f"{corpus}/{type_name}: recall {actual} < {minimum}")
    return failures


def current_thresholds(reports: dict[str, Report]) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for corpus in ("synthetic", "dev", "holdout"):
        r = reports[corpus]
        if not r.documents:
            continue
        out[corpus] = {"_overall": round(r.recall(), 4)}
        out[corpus] |= {
            t.value: round(r.recall(t), 4) for t in sorted(r.planted, key=lambda t: t.value)
        }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--update-thresholds", action="store_true")
    args = parser.parse_args()

    reports = run()
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "latest.json").write_text(
        json.dumps({k: to_dict(v) for k, v in reports.items()}, indent=2) + "\n"
    )
    (REPORTS / "latest.md").write_text(to_markdown(reports))
    print(to_markdown({k: v for k, v in reports.items()}).split("\n## ")[0])

    if args.update_thresholds:
        THRESHOLDS.write_text(json.dumps(current_thresholds(reports), indent=2) + "\n")
        print(f"thresholds updated: {THRESHOLDS}")
        return 0
    thresholds = json.loads(THRESHOLDS.read_text()) if THRESHOLDS.exists() else {}
    failures = gate(reports, thresholds)
    for failure in failures:
        print(f"RECALL REGRESSION {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
