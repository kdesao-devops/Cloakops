from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from cloakops.model import Category
from cloakops.model import EntityType as E
from cloakops.reinject import Reinjector
from pseudo_helpers import engine, mask
from test_pseudo_structure import K8S, SENSITIVE, TFSTATE


def test_answer_referring_to_pseudonyms_is_restored() -> None:
    p = engine()
    masked = mask(TFSTATE, p)
    bucket_arn = p.pseudonym(
        E.ARN, "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abcdef1234567890"
    )
    instance = p.pseudonym(E.AWS_RESOURCE_ID, "i-0abcdef1234567890")
    address = p.pseudonym(E.IP_ADDRESS, "10.42.3.17")
    assert instance in masked
    answer = (
        f"Instance {instance} ({address}) is the one in {bucket_arn}.\n"
        f"Its security group {p.pseudonym(E.AWS_RESOURCE_ID, 'sg-0a1b2c3d4e5f67890')} "
        "allows 0.0.0.0/0 on port 22, which you should restrict."
    )
    restored = Reinjector(p.session).reinject(answer).text
    assert restored == (
        "Instance i-0abcdef1234567890 (10.42.3.17) is the one in "
        "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abcdef1234567890.\n"
        "Its security group sg-0a1b2c3d4e5f67890 allows 0.0.0.0/0 on port 22, which you should "
        "restrict."
    )


def test_longest_pseudonym_wins() -> None:
    p = engine()
    org = p.pseudonym(E.ORGANIZATION, "acme")
    bucket = p.pseudonym(E.BUCKET_NAME, "acme-logs")
    assert bucket.startswith(org)
    out = Reinjector(p.session).reinject(f"{bucket} belongs to {org}").text
    assert out == "acme-logs belongs to acme"


def test_pseudonyms_are_not_restored_inside_longer_tokens() -> None:
    p = engine()
    address = p.pseudonym(E.IP_ADDRESS, "10.42.3.17")
    account = p.pseudonym(E.AWS_ACCOUNT_ID, "123456789012")
    text = f"{address}5 x{account} {account}0 v{address}"
    assert Reinjector(p.session).reinject(text).text == text


def test_end_of_sentence_punctuation_is_fine() -> None:
    p = engine()
    address = p.pseudonym(E.IP_ADDRESS, "10.42.3.17")
    assert Reinjector(p.session).reinject(f"Ping {address}.").text == "Ping 10.42.3.17."


def test_kept_values_and_unknown_text_are_untouched() -> None:
    p = engine()
    p.pseudonym(E.IP_ADDRESS, "169.254.169.254")
    text = "metadata at 169.254.169.254, nothing else to restore"
    result = Reinjector(p.session).reinject(text)
    assert result.text == text and result.restorations == ()


def test_categories_limit_what_is_restored() -> None:
    p = engine()
    password = p.pseudonym(E.PASSWORD, "hunter2-prod")
    address = p.pseudonym(E.IP_ADDRESS, "10.42.3.17")
    reinjector = Reinjector(p.session, categories={Category.INFRASTRUCTURE})
    out = reinjector.reinject(f"connect to {address} with {password}").text
    assert out == f"connect to 10.42.3.17 with {password}"


def test_reinjector_sees_mappings_added_after_creation() -> None:
    p = engine()
    reinjector = Reinjector(p.session)
    assert reinjector.reinject("nothing").restorations == ()
    bucket = p.pseudonym(E.BUCKET_NAME, "acme-logs")
    assert reinjector.reinject(bucket).text == "acme-logs"


def test_restorations_report_positions_and_types() -> None:
    p = engine()
    bucket = p.pseudonym(E.BUCKET_NAME, "acme-logs")
    [restoration] = Reinjector(p.session).reinject(f"see {bucket}").restorations
    assert (restoration.start, restoration.namespace) == (4, "bucket_name")


def test_round_trip_on_realistic_documents() -> None:
    for document in (TFSTATE, K8S):
        p = engine()
        masked = mask(document, p)
        assert masked != document
        assert Reinjector(p.session).reinject(masked).text == document


FILLER = st.sampled_from(["", " ", "\n", ", ", " -> ", "host=", '"', ": ", "\t", "/", "("])


@given(st.lists(st.tuples(FILLER, SENSITIVE), min_size=1, max_size=8))
@settings(max_examples=200, deadline=None)
def test_round_trip_property(pieces: list[tuple[str, str]]) -> None:
    # unmask(mask(x)) == x for any text built from sensitive values and separators.
    text = "".join(f + v for f, v in pieces)
    p = engine()
    masked = mask(text, p)
    assert Reinjector(p.session).reinject(masked).text == text


def test_drift_is_not_restored() -> None:
    # A pseudonym the model truncated cannot be mapped back: it stays as is (measured in phase 3).
    p = engine()
    arn = p.pseudonym(E.ARN, "arn:aws:iam::123456789012:role/deploy")
    truncated = re.sub(r"/.*$", "/…", arn)
    assert Reinjector(p.session).reinject(truncated).text.startswith("arn:aws:iam::")


def test_names_the_model_derived_from_a_pseudonym_are_restored() -> None:
    # Word-level coherence (ADR 0010) makes these restorations correct, not accidental.
    p = engine()
    bucket = p.pseudonym(E.BUCKET_NAME, "acme-logs")
    org = p.pseudonym(E.RESOURCE_NAME, "acme")
    out = Reinjector(p.session).reinject(f"create {bucket}-archive and grafana.{org}.io").text
    assert out == "create acme-logs-archive and grafana.acme.io"


def test_component_quoted_without_its_composite_is_restored() -> None:
    # The model often names the role without its ARN, or the host label alone.
    p = engine()
    arn = p.pseudonym(E.ARN, "arn:aws:iam::123456789012:role/acme-deployer")
    role = arn.rpartition("/")[2]
    host = p.pseudonym(E.HOSTNAME, "grafana.ops.acme.io")
    label = host.split(".")[0]
    out = Reinjector(p.session).reinject(f"give {role} access to {label}").text
    assert out == "give acme-deployer access to grafana"
