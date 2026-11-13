"""Structural validity: if the input parses as JSON or YAML, the output parses too, with the same
shape. A pseudonymized tfstate that is no longer JSON is much less useful to the model."""

from __future__ import annotations

import json
from typing import Any

import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from _fakes import ALNUM, UPPER_DIGITS, fake, pem_private_key
from cloakops.resolve import resolve_overlaps
from pseudo_helpers import DETECTOR, engine, mask


def shape(node: Any) -> Any:
    """Structure without values: dict sizes, list lengths, scalar types."""
    if isinstance(node, dict):
        return ("dict", len(node), sorted(repr(shape(v)) for v in node.values()))
    if isinstance(node, list):
        return ["list", *(shape(v) for v in node)]
    return type(node).__name__


INSTANCE_ARN = "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abcdef1234567890"
TFSTATE = json.dumps(
    {
        "version": 4,
        "resources": [
            {
                "type": "aws_instance",
                "instances": [
                    {
                        "attributes": {
                            "id": "i-0abcdef1234567890",
                            "arn": INSTANCE_ARN,
                            "private_ip": "10.42.3.17",
                            "private_dns": "ip-10-42-3-17.eu-west-1.compute.internal",
                            "vpc_security_group_ids": ["sg-0a1b2c3d4e5f67890"],
                            "subnet_id": "subnet-0fedcba9876543210",
                            "tags": {"client": "Jacquil", "owner": "jane.doe@acme.io"},
                            "user_data": None,
                            "count": 3,
                        }
                    }
                ],
            },
            {
                "type": "aws_db_instance",
                "instances": [
                    {
                        "attributes": {
                            "password": "Summer2024!",  # gitleaks:allow
                            "endpoint": "orders.c9akciq32.eu-west-1.rds.amazonaws.com:5432",
                            "private_key": pem_private_key(""),
                            "access_key": fake("AKIA", UPPER_DIGITS, 16),
                            "token": fake("ghp_", ALNUM, 36),
                        }
                    }
                ],
            },
        ],
    },
    indent=2,
)

K8S = """\
apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: payments
data:
  DB_URL: cG9zdGdyZXM6Ly9hcHA6c2VjcmV0QGRiOjU0MzIvYXBw
stringData:
  tls.key: |
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  labels:
    client: Jacquil
spec:
  template:
    spec:
      containers:
        - name: api
          image: 123456789012.dkr.ecr.eu-west-1.amazonaws.com/api:1.2
          env:
            - name: DB_PASSWORD
              value: hunter2-prod
            - name: DB_HOST
              value: orders.c9akciq32.eu-west-1.rds.amazonaws.com
            - name: REPLICAS
              value: "3"
"""


def test_tfstate_stays_valid_json_with_the_same_shape() -> None:
    out = mask(TFSTATE)
    assert out != TFSTATE
    assert shape(json.loads(out)) == shape(json.loads(TFSTATE))


def test_kubernetes_manifests_stay_valid_yaml_with_the_same_shape() -> None:
    out = mask(K8S)
    assert out != K8S
    before = [shape(doc) for doc in yaml.safe_load_all(K8S)]
    after = [shape(doc) for doc in yaml.safe_load_all(out)]
    assert after == before


def test_no_detected_value_survives() -> None:
    for text in (TFSTATE, K8S):
        pseudonymizer = engine()
        spans = resolve_overlaps(DETECTOR.detect(text))
        out = pseudonymizer.pseudonymize_text(text, spans).text
        for span in spans:
            value = span.text_of(text)
            if value not in pseudonymizer.session.kept:
                assert value not in out


SENSITIVE = st.sampled_from(
    [
        "10.42.3.17",
        "10.42.0.0/16",
        "arn:aws:iam::123456789012:role/deploy",
        "vpc-0a1b2c3d4e5f67890",
        "jane.doe@acme.io",
        "grafana.acme.io",
        "s3://acme-logs/raw",
        fake("ghp_", ALNUM, 36),
        pem_private_key("", escaped_newlines=True),
        'quote " and backslash \\ inside',
    ]
)
JSON_VALUES = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), SENSITIVE, st.text(max_size=20)),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(
            st.sampled_from(["password", "client", "token", "name", "bucket", "ip", "note"]),
            children,
            max_size=4,
        ),
    ),
    max_leaves=12,
)


@given(JSON_VALUES)
@settings(max_examples=150, deadline=None)
def test_any_json_document_stays_valid_json(document: Any) -> None:
    text = json.dumps(document, indent=1)
    assert shape(json.loads(mask(text))) == shape(document)
