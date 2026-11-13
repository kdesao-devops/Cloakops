import base64
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cloakops.pseudo.keyed import KeyedDerivation
from cloakops.pseudo.text import class_preserving, pseudo_words

D = KeyedDerivation(b"k" * 32)


def test_derivation_is_deterministic_and_keyed() -> None:
    other = KeyedDerivation(b"o" * 32)
    assert D.digest("d", "v") == KeyedDerivation(b"k" * 32).digest("d", "v")
    assert D.digest("d", "v") != other.digest("d", "v")
    assert D.digest("d", "v") != D.digest("e", "v")  # domain separation
    assert D.digest("d", "v", counter=1) != D.digest("d", "v")


def test_short_keys_are_rejected_and_key_is_never_printed() -> None:
    with pytest.raises(ValueError):
        KeyedDerivation(b"short")
    assert "kkkk" not in repr(D)


def test_choice_uses_only_the_alphabet() -> None:
    out = D.choice("ab", 200, "d", "v")
    assert len(out) == 200 and set(out) == {"a", "b"}


@given(st.text(max_size=60))
def test_class_preserving_keeps_length_classes_and_separators(value: str) -> None:
    out = class_preserving(value, D, "test")
    assert len(out) == len(value)
    for i, (o, c) in enumerate(zip(out, value, strict=True)):
        if value[max(0, i - 1)] == "\\":
            continue  # characters after a backslash are part of a kept escape sequence
        if c.isdigit():
            assert o.isdigit()
        elif c.isalpha():
            assert o.isalpha() and o.isupper() == c.isupper()
        else:
            assert o == c


def test_class_preserving_keeps_escape_sequences() -> None:
    # JSON-escaped content must stay valid JSON: "\n" must not become "\x".
    assert class_preserving('ab\\ncd\\"e', D, "t")[2:4] == "\\n"


def test_hex_stays_hex_and_base64_stays_decodable() -> None:
    assert set(class_preserving("9f86d081884c7d659a2feaa0c55ad015", D, "t")) <= set(
        string.hexdigits
    )
    encoded = base64.b64encode(b"postgres://app:secret@db:5432/app").decode()
    base64.b64decode(class_preserving(encoded, D, "t"))  # raises if invalid


def test_words_are_consistent_case_preserving_and_keep_generic_words() -> None:
    acme = pseudo_words("acme", D)
    assert acme != "acme"
    assert pseudo_words("acme-prod-logs", D) == f"{acme}-prod-logs"
    assert pseudo_words("Acme Industries", D) == f"{acme.capitalize()} Industries"
    assert pseudo_words("ACME_API", D) == f"{acme.upper()}_API"
    assert pseudo_words("eu-west-1", D) == "eu-west-1"
