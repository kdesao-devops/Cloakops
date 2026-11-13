import base64

import pytest

from _fakes import ALNUM, BASE64, URLSAFE, fake, pem_private_key
from cloakops.detect.rules.crypto_keys import PRIVATE_KEY_BLOCK
from cloakops.detect.rules.identity import EMAIL
from cloakops.detect.rules.secrets import (
    AUTHORIZATION_HEADER,
    BEARER_TOKEN,
    JWT,
    SLACK_WEBHOOK,
    URL_PASSWORD,
    secret_rules,
)
from cloakops.model import EntityType as E
from rules_helpers import raw, resolved, values


@pytest.mark.parametrize(
    "token",
    [
        fake("ghp_", ALNUM, 36),
        fake("github_pat_", ALNUM + "_", 82),
        fake("glpat-", URLSAFE, 20),
        fake("xoxb-", ALNUM + "-", 40),
        fake("sk_live_", ALNUM, 24),
        fake("AIza", URLSAFE, 35),
        fake("sk-ant-api03-", URLSAFE, 80),
        fake("sk-proj-", URLSAFE, 48),
        fake("npm_", ALNUM, 36),
        fake("dckr_pat_", URLSAFE, 27),
        fake("hvs.", URLSAFE, 90),
        fake("", ALNUM, 14) + ".atlasv1." + fake("", URLSAFE, 67),
    ],
)
def test_vendor_tokens(token: str) -> None:
    assert values(f'token: "{token}"\n', *secret_rules()) == [token]


def test_publishable_stripe_key_is_not_a_secret() -> None:
    assert values(fake("pk_live_", ALNUM, 24), *secret_rules()) == []


def test_jwt() -> None:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    # header.payload.signature; header and payload are base64url JSON, hence the "eyJ" prefix.
    token = ".".join(
        [
            b64(b'{"alg":"RS256"}'),
            b64(b'{"sub":"' + fake("", ALNUM, 30).encode() + b'"}'),
            fake("", URLSAFE, 43),
        ]
    )
    assert values(f"Cookie: session={token}; Path=/", JWT) == [token]


def test_authorization_and_bearer() -> None:
    token = fake("", URLSAFE, 32)
    assert values(f"Authorization: Bearer {token}", AUTHORIZATION_HEADER) == [token]
    assert values(f"curl -H 'X: y' --oauth2-bearer bearer {token}", BEARER_TOKEN) == [token]


def test_slack_webhook() -> None:
    url = "https://hooks.slack.com/services/T0000/B0000/" + fake("", ALNUM, 24)
    assert values(f"webhook {url}", SLACK_WEBHOOK) == [url]


def test_url_password() -> None:
    text = "DATABASE_URL=postgres://app:Sup3r-S3cret@db.internal:5432/app"  # gitleaks:allow
    assert values(text, URL_PASSWORD) == ["Sup3r-S3cret"]


@pytest.mark.parametrize("label", ["RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", ""])
def test_private_key_blocks(label: str) -> None:
    key = pem_private_key(label)
    assert values(f"key:\n{key}\nnext: line", PRIVATE_KEY_BLOCK) == [key]


def test_private_key_in_json_with_escaped_newlines() -> None:
    key = pem_private_key("", escaped_newlines=True)
    assert values(f'{{"private_key": "{key}\\n", "x": 1}}', PRIVATE_KEY_BLOCK) == [key]


def test_truncated_private_key_is_masked_to_the_end_of_its_body() -> None:
    begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
    text = f"{begin}\n{fake('', BASE64, 64)}\n{fake('', BASE64, 30)}"
    [(entity_type, value)] = raw(text, PRIVATE_KEY_BLOCK)
    assert entity_type is E.PRIVATE_KEY
    assert value.rstrip() == text


def test_certificates_are_public() -> None:
    cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    assert values(cert, PRIVATE_KEY_BLOCK) == []


def test_emails_but_not_git_remotes() -> None:
    text = "owner jane.doe@acme.io, remote git@github.com:acme/infra.git"
    assert values(text, EMAIL) == ["jane.doe@acme.io"]


def test_vendor_token_wins_over_generic_detections() -> None:
    token = fake("ghp_", ALNUM, 36)
    assert resolved(f"GITHUB_TOKEN={token}") == [(E.API_TOKEN, token)]


def test_ssh_config_user() -> None:
    from cloakops.detect.rules.identity import SSH_CONFIG_USER

    text = "Host bastion\n    User lmercier\nHost *\n    User ec2-user\n"
    assert values(text, SSH_CONFIG_USER) == ["lmercier"]
