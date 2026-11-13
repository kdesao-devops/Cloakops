import pytest

from cloakops.model import Category, EntityType, Span


def make(start: int, end: int, entity_type: EntityType = EntityType.HOSTNAME) -> Span:
    return Span(start=start, end=end, entity_type=entity_type, detector="test")


def test_every_entity_type_has_a_category() -> None:
    for entity_type in EntityType:
        assert isinstance(entity_type.category, Category)


@pytest.mark.parametrize(
    ("start", "end", "confidence", "detector"),
    [(-1, 3, 1.0, "d"), (3, 3, 1.0, "d"), (5, 2, 1.0, "d"), (0, 1, 1.5, "d"), (0, 1, 1.0, "")],
)
def test_invalid_spans_are_rejected(start: int, end: int, confidence: float, detector: str) -> None:
    with pytest.raises(ValueError):
        Span(start, end, EntityType.HOSTNAME, detector, confidence)


def test_touching_spans_do_not_overlap() -> None:
    assert not make(0, 5).overlaps(make(5, 9))
    assert make(0, 5).overlaps(make(4, 9))


def test_contains_and_text_of() -> None:
    text = "role arn:aws:iam::123456789012:role/deploy"
    arn = make(5, len(text), EntityType.ARN)
    account = make(18, 30, EntityType.AWS_ACCOUNT_ID)
    assert arn.contains(account)
    assert account.text_of(text) == "123456789012"


def test_repr_never_contains_the_value() -> None:
    # Spans do not store values, so printing one in a log or error cannot leak.
    span = make(0, 12, EntityType.AWS_ACCOUNT_ID)
    assert "123456789012" not in repr(span)


def test_rank_prefers_credentials_then_specific_types() -> None:
    assert EntityType.PASSWORD.rank > EntityType.EMAIL.rank > EntityType.ARN.rank
    assert EntityType.AWS_ACCESS_KEY_ID.rank > EntityType.GENERIC_SECRET.rank
