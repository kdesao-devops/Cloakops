"""Cross-value coherence: a component gets the same pseudonym in every value that contains it."""

import ipaddress
import re

from cloakops.model import EntityType as E
from pseudo_helpers import engine, mask


def test_bucket_is_consistent_across_uri_arn_and_endpoint() -> None:
    p = engine()
    bucket = p.pseudonym(E.BUCKET_NAME, "acme-logs")
    assert p.pseudonym(E.ARN, "arn:aws:s3:::acme-logs/env/prod.tfstate") == (
        f"arn:aws:s3:::{bucket}/env/prod.tfstate"
    )
    out = mask("aws s3 cp x s3://acme-logs/raw/ and https://acme-logs.s3.amazonaws.com/x", p)
    assert out.count(bucket) == 2


def test_account_is_consistent_across_arn_ecr_and_bare_id() -> None:
    p = engine()
    account = p.pseudonym(E.AWS_ACCOUNT_ID, "123456789012")
    assert p.pseudonym(E.ARN, "arn:aws:iam::123456789012:role/deploy").split(":")[4] == account
    ecr = p.pseudonym(E.HOSTNAME, "123456789012.dkr.ecr.eu-west-1.amazonaws.com")
    assert ecr == f"{account}.dkr.ecr.eu-west-1.amazonaws.com"


def test_eks_cluster_is_consistent_between_arn_and_name() -> None:
    p = engine()
    cluster = p.pseudonym(E.CLUSTER_NAME, "payments")
    arn = p.pseudonym(E.ARN, "arn:aws:eks:eu-west-1:123456789012:cluster/payments")
    assert arn.endswith(f":cluster/{cluster}")


def test_resource_id_inside_an_arn_is_consistent() -> None:
    p = engine()
    instance = p.pseudonym(E.AWS_RESOURCE_ID, "i-0abcdef1234567890")
    arn = p.pseudonym(E.ARN, "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abcdef1234567890")
    assert arn.endswith(f"instance/{instance}")


def test_ip_encoded_in_a_node_name_matches_the_ip() -> None:
    p = engine()
    address = p.pseudonym(E.IP_ADDRESS, "10.42.3.17")
    node = p.pseudonym(E.HOSTNAME, "ip-10-42-3-17.eu-west-1.compute.internal")
    assert node == "ip-" + address.replace(".", "-") + ".eu-west-1.compute.internal"
    network = ipaddress.ip_network(p.pseudonym(E.IP_NETWORK, "10.42.0.0/16"))
    assert ipaddress.ip_address(address) in network


def test_organization_word_is_consistent_across_types() -> None:
    p = engine()
    org = p.pseudonym(E.ORGANIZATION, "Acme")
    assert p.pseudonym(E.BUCKET_NAME, "acme-logs") == f"{org.lower()}-logs"
    assert p.pseudonym(E.HOSTNAME, "grafana.acme.io").endswith(f".{org.lower()}.io")
    assert p.pseudonym(E.EMAIL, "jane.doe@acme.io").endswith(f"@{org.lower()}.io")


def test_public_mail_domains_are_kept() -> None:
    assert engine().pseudonym(E.EMAIL, "jane.doe@gmail.com").endswith("@gmail.com")


def test_resource_type_and_region_are_kept_in_arns() -> None:
    out = engine().pseudonym(E.ARN, "arn:aws:lambda:eu-west-1:123456789012:function:acme-api")
    assert re.fullmatch(r"arn:aws:lambda:eu-west-1:[0-9]{12}:function:[a-z]+-api", out)
