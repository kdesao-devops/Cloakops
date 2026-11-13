import re

import pytest

from _fakes import ALNUM, UPPER_DIGITS, fake, pem_private_key
from cloakops.model import EntityType as E
from cloakops.pseudo import PseudonymizationError, Pseudonymizer
from cloakops.pseudo.generators import Context
from pseudo_helpers import engine, pseudo


def test_account_and_resource_ids_keep_their_format() -> None:
    account = pseudo(E.AWS_ACCOUNT_ID, "123456789012")
    assert re.fullmatch(r"[0-9]{12}", account) and account != "123456789012"
    for value in ("vpc-0a1b2c3d4e5f67890", "sg-12345678", "tgw-attach-0123456789abcdef0"):
        out = pseudo(E.AWS_RESOURCE_ID, value)
        prefix = value.rpartition("-")[0]
        assert out != value and out.startswith(prefix + "-") and len(out) == len(value)
        assert re.fullmatch(r"[0-9a-f]+", out.rpartition("-")[2])


def test_access_key_keeps_its_prefix() -> None:
    key = fake("AKIA", UPPER_DIGITS, 16)
    out = pseudo(E.AWS_ACCESS_KEY_ID, key)
    assert out.startswith("AKIA") and len(out) == 20 and out != key


def test_tokens_keep_vendor_prefix_and_shape() -> None:
    token = fake("ghp_", ALNUM, 36)
    out = pseudo(E.API_TOKEN, token)
    assert out.startswith("ghp_") and len(out) == len(token) and out != token


def test_passwords_do_not_keep_their_shape() -> None:
    out = pseudo(E.PASSWORD, "Summer2024!")
    assert len(out) == 16 and out.isalnum()


def test_jwt_keeps_its_three_parts() -> None:
    out = pseudo(E.JWT, "eyJhbGc.eyJzdWIi.c2ln")
    assert re.fullmatch(r"eyJ\w+\.eyJ\w+\.\w+", out)


def test_private_key_keeps_its_markers() -> None:
    key = pem_private_key("RSA ")
    out = pseudo(E.PRIVATE_KEY, key)
    assert out != key
    assert out.splitlines()[0] == key.splitlines()[0]
    assert out.splitlines()[-1] == key.splitlines()[-1]


def test_names_keep_generic_words_and_case() -> None:
    out = pseudo(E.ORGANIZATION, "Jacquil Industries")
    first, second = out.split(" ")
    assert second == "Industries" and first[0].isupper() and first != "Jacquil"


def test_name_made_only_of_generic_words_is_still_masked() -> None:
    # "core" is a kept word inside names, but a value equal to its pseudonym would leak.
    assert pseudo(E.CLUSTER_NAME, "core") != "core"


def test_well_known_hostnames_are_kept() -> None:
    assert pseudo(E.HOSTNAME, "kubernetes.default.svc.cluster.local") == (
        "kubernetes.default.svc.cluster.local"
    )


def test_same_value_same_pseudonym_within_a_session() -> None:
    pseudonymizer = engine()
    first = pseudonymizer.pseudonym(E.BUCKET_NAME, "acme-logs")
    assert pseudonymizer.pseudonym(E.BUCKET_NAME, "acme-logs") == first
    assert pseudonymizer.session.original_of(first) == "acme-logs"


def test_collisions_are_retried() -> None:
    # A generator whose first candidate is always the same: the second value must not reuse it.
    def first_constant(value: str, ctx: Context, counter: int) -> str:
        return "constant" if counter == 0 else f"{value}-{counter}"

    pseudonymizer = engine()
    pseudonymizer = Pseudonymizer(
        pseudonymizer.session, generators={E.RESOURCE_NAME: first_constant}
    )
    assert pseudonymizer.pseudonym(E.RESOURCE_NAME, "a") == "constant"
    assert pseudonymizer.pseudonym(E.RESOURCE_NAME, "b") == "b-1"


def test_pseudonym_never_equals_another_original() -> None:
    def echo_previous(value: str, ctx: Context, counter: int) -> str:
        return "first" if counter == 0 else f"x{counter}"

    pseudonymizer = Pseudonymizer(engine().session, generators={E.RESOURCE_NAME: echo_previous})
    pseudonymizer.session.register(("resource_name", "first"), "zzz")
    assert pseudonymizer.pseudonym(E.RESOURCE_NAME, "second") == "x1"


def test_yaml_scalar_type_is_preserved() -> None:
    def to_bool(value: str, ctx: Context, counter: int) -> str:
        return "true" if counter == 0 else "tqzx"

    pseudonymizer = Pseudonymizer(engine().session, generators={E.RESOURCE_NAME: to_bool})
    assert pseudonymizer.pseudonym(E.RESOURCE_NAME, "acme") == "tqzx"


def test_fails_closed_when_no_pseudonym_is_acceptable() -> None:
    def identity(value: str, ctx: Context, counter: int) -> str:
        return value

    pseudonymizer = Pseudonymizer(generators={E.RESOURCE_NAME: identity}, max_attempts=3)
    with pytest.raises(PseudonymizationError) as error:
        pseudonymizer.pseudonym(E.RESOURCE_NAME, "jacquil-secret-project")
    assert "jacquil" not in str(error.value)  # error messages never carry the value
