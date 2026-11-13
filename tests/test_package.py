import cloakops


def test_version_is_exposed() -> None:
    assert cloakops.__version__ == "0.1.0"
