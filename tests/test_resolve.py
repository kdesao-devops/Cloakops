import itertools

from hypothesis import given
from hypothesis import strategies as st

from cloakops.model import EntityType, Span
from cloakops.resolve import resolve_overlaps

E = EntityType


def span(
    start: int, end: int, entity_type: EntityType, detector: str = "d", confidence: float = 1.0
) -> Span:
    return Span(start, end, entity_type, detector, confidence)


def covered(spans: list[Span]) -> set[int]:
    return {i for s in spans for i in range(s.start, s.end)}


# --- Examples --------------------------------------------------------------------------------


def test_disjoint_and_touching_spans_are_kept() -> None:
    spans = [span(10, 12, E.HOSTNAME), span(0, 5, E.IP_ADDRESS), span(5, 8, E.EMAIL)]
    assert resolve_overlaps(spans) == sorted(spans, key=lambda s: s.start)


def test_arn_wins_over_the_account_id_it_contains() -> None:
    # "arn:aws:iam::123456789012:role/deploy": account at [13, 25)
    arn = span(0, 37, E.ARN, "aws")
    account = span(13, 25, E.AWS_ACCOUNT_ID, "aws")
    assert resolve_overlaps([account, arn]) == [arn]


def test_outer_span_wins_even_if_inner_is_more_sensitive() -> None:
    # A connection-string secret containing a hostname: masking the outer span masks both.
    secret = span(0, 40, E.PASSWORD, "keyvalue")
    host = span(20, 31, E.HOSTNAME, "network")
    assert resolve_overlaps([secret, host]) == [secret]


def test_same_range_specific_type_beats_generic() -> None:
    generic = span(0, 20, E.GENERIC_SECRET, "keyvalue")
    specific = span(0, 20, E.AWS_ACCESS_KEY_ID, "aws")
    assert resolve_overlaps([generic, specific]) == [specific]


def test_same_range_credential_beats_infrastructure() -> None:
    host = span(0, 10, E.HOSTNAME, "network", confidence=1.0)
    token = span(0, 10, E.API_TOKEN, "entropy", confidence=0.6)
    assert resolve_overlaps([host, token]) == [token]


def test_partial_overlap_is_fused_into_a_merged_span() -> None:
    a = span(0, 10, E.HOSTNAME, "network")
    b = span(6, 15, E.PASSWORD, "keyvalue")
    [merged] = resolve_overlaps([a, b])
    assert (merged.start, merged.end) == (0, 15)
    assert merged.entity_type is E.PASSWORD
    assert merged.merged
    assert merged.detector == "keyvalue+network"


def test_overlap_chains_form_one_cluster() -> None:
    spans = [span(0, 5, E.HOSTNAME), span(4, 9, E.HOSTNAME), span(8, 12, E.HOSTNAME)]
    [merged] = resolve_overlaps(spans)
    assert (merged.start, merged.end) == (0, 12)


def test_empty_input() -> None:
    assert resolve_overlaps([]) == []


# --- Properties ------------------------------------------------------------------------------

spans_strategy = st.lists(
    st.builds(
        lambda start, length, entity_type, detector, confidence: Span(
            start, start + length, entity_type, detector, confidence
        ),
        start=st.integers(min_value=0, max_value=60),
        length=st.integers(min_value=1, max_value=20),
        entity_type=st.sampled_from(list(EntityType)),
        detector=st.sampled_from(["rules", "keyvalue", "ner", "llm"]),
        confidence=st.floats(min_value=0.0, max_value=1.0),
    ),
    max_size=25,
)


@given(spans_strategy)
def test_resolution_never_uncovers_a_character(spans: list[Span]) -> None:
    # The security invariant: every detected character is still masked after resolution.
    assert covered(resolve_overlaps(spans)) == covered(spans)


@given(spans_strategy)
def test_resolved_spans_are_sorted_and_disjoint(spans: list[Span]) -> None:
    resolved = resolve_overlaps(spans)
    for left, right in itertools.pairwise(resolved):
        assert left.end <= right.start


@given(spans_strategy)
def test_resolution_is_idempotent(spans: list[Span]) -> None:
    once = resolve_overlaps(spans)
    assert resolve_overlaps(once) == once


@given(spans_strategy)
def test_unmerged_output_is_one_of_the_inputs(spans: list[Span]) -> None:
    for resolved in resolve_overlaps(spans):
        assert resolved.merged or resolved in spans


@given(spans_strategy)
def test_resolution_does_not_depend_on_input_order(spans: list[Span]) -> None:
    assert resolve_overlaps(spans) == resolve_overlaps(list(reversed(spans)))
