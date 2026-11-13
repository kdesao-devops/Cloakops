import pytest

from cloakops.detect.rules.keyvalue import EnvPairRule, KeyValueRule, classify_key
from cloakops.model import EntityType as E
from rules_helpers import raw, values

KV = KeyValueRule()


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("password", E.PASSWORD),
        ("DB_PASSWORD", E.PASSWORD),
        ("adminPwd", E.PASSWORD),
        ("client_secret", E.GENERIC_SECRET),
        ("clientSecret", E.GENERIC_SECRET),
        ("api-key", E.GENERIC_SECRET),
        ("aws_secret_access_key", E.AWS_SECRET_ACCESS_KEY),
        ("GITHUB_TOKEN", E.API_TOKEN),
        ("client-key-data", E.GENERIC_SECRET),
        ("database_url", E.GENERIC_SECRET),
        ("slack_webhook_url", E.GENERIC_SECRET),
        ("auth", E.GENERIC_SECRET),
        ("client", E.ORGANIZATION),
        ("customer_name", E.ORGANIZATION),
        ("owner", E.PERSON),
        ("bucket", E.BUCKET_NAME),
        ("cluster_name", E.CLUSTER_NAME),
        ("password_secret_arn", E.RESOURCE_NAME),  # points to a secret, does not hold it
        ("secretName", E.RESOURCE_NAME),
        # Organization-identifying IDs (often UUIDs), masked only in this explicit context.
        ("tenant_id", E.RESOURCE_NAME),
        ("ARM_SUBSCRIPTION_ID", E.RESOURCE_NAME),
        ("kms_key_id", E.RESOURCE_NAME),
        ("client_id", E.RESOURCE_NAME),
        ("ExternalId", E.RESOURCE_NAME),
    ],
)
def test_sensitive_keys(key: str, expected: E) -> None:
    result = classify_key(key)
    assert result is not None
    assert result[0] is expected


@pytest.mark.parametrize(
    "key",
    [
        "name",
        "image",
        "PWD",
        "request_id",
        "password_length",
        "token_url",
        "public_key",
        "author_x",
    ],
)
def test_non_sensitive_keys(key: str) -> None:
    assert classify_key(key) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password: hunter2-prod\n", ["hunter2-prod"]),  # gitleaks:allow
        ('  "client_secret": "abc\\"def",\n', ['abc\\"def']),
        ('db_password = "s3cr3t-v4lue"\n', ["s3cr3t-v4lue"]),  # gitleaks:allow
        ("export DB_PASSWORD=p4ss#word next\n", ["p4ss#word"]),  # '#' is part of the value
        ("password: p4ss word # rotate monthly\n", ["p4ss word"]),  # YAML comment stripped
        ("mysql --password=root-pw -h db\n", ["root-pw"]),
        ("tool --api-token tok-123456 run\n", ["tok-123456"]),
        # Pairs after the first one on the line are still found ("user" is a PERSON key).
        ("msg: login ok password=abc123 user=jdoe\n", ["abc123", "jdoe"]),
        ('~ db_pass = "old-value" -> "new-value"\n', ["new-value", "old-value"]),
        ("client: Jacquil Industries\n", ["Jacquil Industries"]),
    ],
)
def test_values_in_all_formats(text: str, expected: list[str]) -> None:
    assert values(text, KV) == expected


@pytest.mark.parametrize(
    "text",
    [
        "password: \n",
        "password: null\n",
        "password = (sensitive value)\n",
        "password = var.db_password\n",
        "password: ${DB_PASSWORD}\n",
        "password: {{ .Values.db.password }}\n",
        "DbPassword: !Ref DbPasswordParam\n",
        'token = "********"\n',
    ],
)
def test_placeholders_and_references_are_not_secrets(text: str) -> None:
    assert values(text, KV) == []


def test_yaml_block_scalar() -> None:
    text = "config:\n  private_key: |\n    line-one\n    line-two\n  next: value\n"
    assert values(text, KV) == ["line-one\n    line-two"]


def test_kubernetes_env_name_value_pairs() -> None:
    text = (
        "env:\n"
        "  - name: DB_PASSWORD\n"
        "    value: from-env-pair\n"
        "  - name: LOG_LEVEL\n"
        "    value: debug\n"
    )
    assert raw(text, EnvPairRule()) == [(E.PASSWORD, "from-env-pair")]


def test_ecs_json_name_value_pairs() -> None:
    text = '{"name": "API_TOKEN", "value": "tok-ecs-1"}, {"name": "PORT", "value": "80"}'
    assert values(text, EnvPairRule()) == ["tok-ecs-1"]


def test_uuid_masked_in_context_only() -> None:
    uuid = "3f2b8c1e-9a4d-4e7b-b1c2-5d6e7f8a9b0c"
    text = f'tenant_id = "{uuid}"\nrequest_id = "{uuid}"\n'
    assert raw(text, KV) == [(E.RESOURCE_NAME, uuid)]
