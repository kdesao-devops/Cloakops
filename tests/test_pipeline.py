from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

import pytest

from cloakops.detect.base import DetectionError
from cloakops.detect.rules import default_rules_detector
from cloakops.errors import FailClosedError
from cloakops.model import EntityType as E
from cloakops.model import Span
from cloakops.pipeline import Pipeline
from cloakops.propagate import Propagator, SeedDictionaryError, load_seed_dictionary
from cloakops.pseudo import KeyedDerivation, Session
from cloakops.pseudo.generators import Context
from cloakops.rescan import LeakDetectedError
from pseudo_helpers import KEY
from test_pseudo_structure import K8S, TFSTATE

RULES = default_rules_detector(organization_domains=("acme.io",))


def pipeline(propagator: Propagator | None = None) -> Pipeline:
    return Pipeline([RULES], Session(KeyedDerivation(KEY)), propagator)


# --- Propagation -----------------------------------------------------------------------------

DOC = """\
tags:
  client: Jacquil
# TODO: migrate Jacquil to the new VPC
resource "aws_eks_cluster" "jacquil-prod-eks" {}
env JACQUIL_API_KEY is owned by the jacquil team
"""


def test_name_found_once_is_masked_everywhere_in_any_case() -> None:
    out = pipeline().mask(DOC).text
    assert "jacquil" not in out.lower()
    pseudo = out.splitlines()[1].split(": ")[1]
    assert f"migrate {pseudo} " in out
    assert f'"{pseudo.lower()}-prod-eks"' in out
    assert f"{pseudo.upper()}_API_KEY" in out


def test_terms_are_remembered_for_the_whole_session() -> None:
    p = pipeline()
    first = p.mask(DOC).text
    pseudo = first.splitlines()[1].split(": ")[1]
    assert p.mask("Jacquil billing is late").text == f"{pseudo} billing is late"


def test_exact_value_is_masked_where_no_rule_fires() -> None:
    text = "password: S3cr3tV4lue\nrun: echo S3cr3tV4lue | docker login --password-stdin\n"
    out = pipeline().mask(text).text
    assert "S3cr3tV4lue" not in out


@pytest.mark.parametrize("value", ["the", "error", "prod", "eu-west-1", "abc", "default"])
def test_poisoning_does_not_propagate_common_words(value: str) -> None:
    # Content controlled by an attacker (a log line) must not make us mask ordinary words.
    text = f"client: {value}\nthe error happened in prod eu-west-1 abc default\n"
    out = pipeline().mask(text).text
    assert out.splitlines()[1] == "the error happened in prod eu-west-1 abc default"


def test_low_confidence_names_do_not_seed_word_propagation() -> None:
    propagator = Propagator()
    text = "something Jacquil"
    propagator.learn(text, [Span(10, 17, E.ORGANIZATION, "llm", confidence=0.5)])
    # The exact value is still propagated; the word-level, any-case variant is not.
    assert [
        s.text_of("JACQUIL jacquil Jacquil") for s in propagator.expand("JACQUIL jacquil Jacquil")
    ] == ["Jacquil"]


def test_seed_dictionary(tmp_path: Path) -> None:
    seed = tmp_path / "seed.txt"
    seed.write_text("# customers\nJacquil Industries\nperson: Jane Martin  # CTO\nproject: Orion\n")
    seed.chmod(0o600)
    terms = load_seed_dictionary(seed)
    assert terms == [
        ("Jacquil Industries", E.ORGANIZATION),
        ("Jane Martin", E.PERSON),
        ("Orion", E.RESOURCE_NAME),
    ]
    out = pipeline(Propagator(terms)).mask("Orion ships for jacquil, ask martin").text
    assert all(word not in out.lower() for word in ("orion", "jacquil", "martin"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_seed_dictionary_readable_by_others_is_refused(tmp_path: Path) -> None:
    seed = tmp_path / "seed.txt"
    seed.write_text("Jacquil\n")
    seed.chmod(0o644)
    with pytest.raises(SeedDictionaryError):
        load_seed_dictionary(seed)


# --- Re-scan and fail-closed -----------------------------------------------------------------


def test_realistic_documents_pass_the_rescan_and_round_trip() -> None:
    for document in (TFSTATE, K8S, DOC):
        p = pipeline()
        masked = p.mask(document)
        assert p.unmask(masked.text).text == document


def test_rescan_blocks_a_buggy_pseudonymizer_without_printing_values() -> None:
    def leaky(value: str, ctx: Context, counter: int) -> str:
        return f"{value} copy"  # a bug that keeps the original

    p = pipeline()
    p._pseudonymizer._generators[E.ORGANIZATION] = leaky
    with pytest.raises(LeakDetectedError) as error:
        p.mask("client: Jacquil Industries\n")
    assert error.value.findings
    assert "jacquil" not in str(error.value).lower()
    assert isinstance(error.value, FailClosedError)


def test_rescan_blocks_a_value_the_detectors_find_in_the_output() -> None:
    class ContextDependent:
        """Misses "Codename Orion" in the input because of its context, finds it in the output.
        The re-scan must catch what the first pass missed."""

        name = "context-dependent"

        def detect(self, text: str) -> Sequence[Span]:
            if "client: Jacquil" in text:
                return []
            start = text.find("Orion")
            return [Span(start, start + 5, E.RESOURCE_NAME, self.name)] if start >= 0 else []

    p = Pipeline([ContextDependent(), RULES], Session(KeyedDerivation(KEY)))
    with pytest.raises(LeakDetectedError) as error:
        p.mask("client: Jacquil\nCodename Orion\n")
    [finding] = error.value.findings
    assert (finding.reason, finding.entity_type) == ("redetected", E.RESOURCE_NAME)


def test_detector_failure_fails_closed() -> None:
    class Broken:
        name = "broken"

        def detect(self, text: str) -> Sequence[Span]:
            raise TimeoutError("local model timed out")

    with pytest.raises(DetectionError):
        Pipeline([Broken()]).mask("anything")
