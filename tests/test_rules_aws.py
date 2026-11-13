from _fakes import BASE64, UPPER_DIGITS, fake
from cloakops.detect.rules import RulesDetector
from cloakops.detect.rules.aws import (
    ARN,
    AWS_ACCESS_KEY_ID,
    AWS_ACCOUNT_ID_BARE,
    AWS_ACCOUNT_ID_CONTEXT,
    AWS_ACCOUNT_ID_ECR,
    AWS_RESOURCE_HOSTNAME,
    AWS_SECRET_ACCESS_KEY,
    AWS_UNIQUE_ID,
    S3_PATH_STYLE_BUCKET,
    S3_URI_BUCKET,
    S3_VIRTUAL_HOST_BUCKET,
)
from cloakops.model import EntityType as E
from cloakops.resolve import resolve_overlaps
from rules_helpers import raw, resolved, values


def test_arns() -> None:
    text = (
        '"Arn": "arn:aws:iam::123456789012:role/deploy-prod",\n'
        "bucket arn:aws:s3:::acme-tfstate/env/prod.tfstate.\n"
        "cluster arn:aws-cn:eks:cn-north-1:123456789012:cluster/core\n"
        "managed arn:aws:iam::aws:policy/AdministratorAccess is public\n"
    )
    assert values(text, ARN) == [
        "arn:aws-cn:eks:cn-north-1:123456789012:cluster/core",
        "arn:aws:iam::123456789012:role/deploy-prod",
        "arn:aws:s3:::acme-tfstate/env/prod.tfstate",
    ]


def test_account_id_confidence_depends_on_context() -> None:
    rules = (AWS_ACCOUNT_ID_BARE, AWS_ACCOUNT_ID_CONTEXT, AWS_ACCOUNT_ID_ECR)
    text = '"AccountId": "123456789012"\norder 210987654321\n111122223333.dkr.ecr.eu-west-1'
    found = resolve_overlaps(RulesDetector(rules).detect(text))
    spans = {(s.text_of(text), s.confidence) for s in found}
    assert spans == {("123456789012", 1.0), ("210987654321", 0.6), ("111122223333", 1.0)}


def test_account_id_needs_exactly_twelve_digits() -> None:
    assert values("ts 1731535200123 and 12345678901", AWS_ACCOUNT_ID_BARE) == []


def test_access_key_ids_and_unique_ids() -> None:
    akia = fake("AKIA", UPPER_DIGITS, 16)
    asia = fake("ASIA", UPPER_DIGITS, 16, seed=1)
    aroa = fake("AROA", UPPER_DIGITS, 16, seed=2)
    text = f"key={akia} temp {asia}\nrole id {aroa}\nnot {akia}X"
    assert raw(text, AWS_ACCESS_KEY_ID, AWS_UNIQUE_ID) == sorted(
        [(E.AWS_ACCESS_KEY_ID, akia), (E.AWS_ACCESS_KEY_ID, asia), (E.RESOURCE_NAME, aroa)]
    )


def test_secret_access_key_requires_its_key_name() -> None:
    secret = fake("", BASE64, 40, seed=3)
    text = f"aws_secret_access_key = {secret}\nrandom {secret}\n"
    assert values(text, AWS_SECRET_ACCESS_KEY) == [secret]
    json_text = f'"SecretAccessKey": "{secret}"'
    assert values(json_text, AWS_SECRET_ACCESS_KEY) == [secret]


def test_buckets() -> None:
    rules = (S3_URI_BUCKET, S3_VIRTUAL_HOST_BUCKET, S3_PATH_STYLE_BUCKET)
    text = (
        "aws s3 cp out.json s3://acme-data-lake/raw/\n"
        "https://acme-assets.s3.eu-west-1.amazonaws.com/logo.png\n"
        "https://acme.backups.s3.amazonaws.com/x\n"
        "https://s3.eu-west-1.amazonaws.com/acme-legacy/file\n"
    )
    assert values(text, *rules) == ["acme-assets", "acme-data-lake", "acme-legacy", "acme.backups"]


def test_resource_hostnames_but_not_public_endpoints() -> None:
    text = (
        "db: orders.c9akciq32.eu-west-1.rds.amazonaws.com\n"
        "lb: k8s-ingress-1234.eu-west-1.elb.amazonaws.com\n"
        "sts: sts.eu-west-1.amazonaws.com\n"
    )
    assert values(text, AWS_RESOURCE_HOSTNAME) == [
        "k8s-ingress-1234.eu-west-1.elb.amazonaws.com",
        "orders.c9akciq32.eu-west-1.rds.amazonaws.com",
    ]


def test_arn_wins_over_its_account_id_after_resolution() -> None:
    text = "role arn:aws:iam::123456789012:role/deploy"
    assert resolved(text) == [(E.ARN, "arn:aws:iam::123456789012:role/deploy")]
