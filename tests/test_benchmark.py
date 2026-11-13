from cloakops.benchmark.corpus import Planted, parse_holdout, synthetic_corpus
from cloakops.benchmark.fakes import FACTORIES
from cloakops.benchmark.metrics import evaluate, required_positions
from cloakops.benchmark.templates import TEMPLATES
from cloakops.detect.rules import default_rules_detector
from cloakops.model import EntityType as E
from cloakops.pipeline import Pipeline


def test_synthetic_spans_point_at_the_planted_values() -> None:
    docs = list(synthetic_corpus(documents_per_template=2, seed=1))
    assert len(docs) == 2 * len(TEMPLATES)
    for doc in docs:
        assert doc.planted
        for planted in doc.planted:
            value = doc.value(planted)
            assert value and "{{" not in value


def test_synthetic_corpus_is_reproducible() -> None:
    first = [d.text for d in synthetic_corpus(2, seed=7)]
    assert first == [d.text for d in synthetic_corpus(2, seed=7)]
    assert first != [d.text for d in synthetic_corpus(2, seed=8)]


def test_every_template_placeholder_has_a_factory() -> None:
    import re

    for template in TEMPLATES:
        for key in re.findall(r"\{\{([a-z0-9_#]+)\}\}", template.text):
            assert key.split("#")[0] in FACTORIES, (template.name, key)


def test_holdout_markers_are_parsed_and_stripped() -> None:
    doc = parse_holdout("host ⟦hostname|db.acme.lan⟧ at ⟦ip_address|10.0.0.1⟧\n", "x")
    assert doc.text == "host db.acme.lan at 10.0.0.1\n"
    assert [(doc.value(p), p.entity_type) for p in doc.planted] == [
        ("db.acme.lan", E.HOSTNAME),
        ("10.0.0.1", E.IP_ADDRESS),
    ]


def test_generic_words_inside_a_planted_value_need_not_be_covered() -> None:
    text = "acme-payroll-deployer"
    required = required_positions(text, Planted(0, len(text), E.RESOURCE_NAME))
    assert [text[i] for i in required] == list("acme-payroll-")
    only_generic = "prod-logs"
    assert len(required_positions(only_generic, Planted(0, 9, E.RESOURCE_NAME))) == 9


def test_evaluate_counts_misses_and_false_positives() -> None:
    doc = parse_holdout("ip ⟦ip_address|10.0.0.1⟧ person ⟦person|Jane Martin⟧ v 10.9.9.9\n", "d")
    report = evaluate([doc], lambda: Pipeline([default_rules_detector()]))
    assert report.planted[E.IP_ADDRESS] == 1 and report.caught[E.IP_ADDRESS] == 1
    assert report.caught[E.PERSON] == 0 and report.leaked_documents == 1  # prose name: phase 2
    assert report.masked[E.IP_ADDRESS] == 2 and report.masked_correct[E.IP_ADDRESS] == 1
