import pytest

from cloakops.detect.rules import default_rules_detector
from cloakops.detect.rules.organization import (
    AWS_SIGNIN_ALIAS,
    AWS_SSO_PORTAL,
    AZURE_REGISTRY,
    COPYRIGHT_HOLDER,
    LEGAL_ENTITY,
    TOOL_URL_ORGANIZATION,
    CertificateSubjectRule,
)
from cloakops.model import EntityType as E
from cloakops.pipeline import Pipeline
from cloakops.propagate import registered_domain
from cloakops.pseudo import KeyedDerivation, Session
from pseudo_helpers import KEY
from rules_helpers import raw


@pytest.mark.parametrize(
    "text",
    [
        "origin\tgit@github.com:korvane/platform-infra.git (fetch)",
        "url = ssh://git@gitlab.com:2222/korvane/infra.git",
        "image: ghcr.io/korvane/api:2.4.0",
        "workspace https://app.terraform.io/app/korvane/workspaces/prod",
    ],
)
def test_organization_in_tool_urls(text: str) -> None:
    assert raw(text, TOOL_URL_ORGANIZATION) == [(E.ORGANIZATION, "korvane")]


@pytest.mark.parametrize(
    "text",
    [
        "image: ghcr.io/bitnami/redis:7",
        "git@github.com:hashicorp/terraform.git",
        "ghcr.io/actions/runner:latest",
        "uses: actions/checkout@v4",  # not a remote at all
    ],
)
def test_public_organizations_are_not_the_users(text: str) -> None:
    assert raw(text, TOOL_URL_ORGANIZATION) == []


def test_azure_registry_and_aws_portals() -> None:
    text = (
        "korvaneprod.azurecr.io/api https://korvane-prod.signin.aws.amazon.com/console "
        "sso_start_url = https://korvane.awsapps.com/start"
    )
    assert raw(text, AZURE_REGISTRY, AWS_SIGNIN_ALIAS, AWS_SSO_PORTAL) == sorted(
        [
            (E.ORGANIZATION, "korvaneprod"),
            (E.RESOURCE_NAME, "korvane-prod"),
            (E.ORGANIZATION, "korvane"),
        ]
    )


def test_certificate_subject_but_not_issuer() -> None:
    text = (
        "        Issuer: C=US, O=Let's Encrypt, CN=R11\n"
        "        Subject: C=FR, O=Korvane SAS, CN=*.korvane.com\n"
        "subject=CN = api.korvane.io, O = Brindel Logistics\n"
    )
    assert raw(text, CertificateSubjectRule()) == sorted(
        [
            (E.ORGANIZATION, "Korvane SAS"),
            (E.HOSTNAME, "*.korvane.com"),
            (E.HOSTNAME, "api.korvane.io"),
            (E.ORGANIZATION, "Brindel Logistics"),
        ]
    )


def test_legal_entities_but_not_infrastructure_groups() -> None:
    text = "Invoice Brindel Logistics SAS and Acme GmbH; the Resource Group and Security Group."
    found = [v for _, v in raw(text, LEGAL_ENTITY)]
    # A capitalized word starting the sentence is swallowed ("Invoice Brindel Logistics SAS"):
    # over-masking, not a leak; telling them apart needs grammar (phase 2 NER).
    assert found == ["Acme GmbH", "Invoice Brindel Logistics SAS"]


def test_copyright_holders_but_not_public_projects() -> None:
    text = (
        "# Copyright (c) 2024-2026 Korvane Technologies. All rights reserved.\n"
        "// Copyright 2019 The Kubernetes Authors.\n"
        "# Copyright 2023 HashiCorp, Inc.\n"
    )
    assert raw(text, COPYRIGHT_HOLDER) == [(E.ORGANIZATION, "Korvane Technologies")]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("pay.eu.korvane.com", "korvane.com"),
        ("www.acme.co.uk", "acme.co.uk"),
        ("*.korvane.io", "korvane.io"),
    ],
)
def test_registered_domain(host: str, expected: str) -> None:
    assert registered_domain(host) == expected


def pipeline() -> Pipeline:
    return Pipeline([default_rules_detector()], Session(KeyedDerivation(KEY)))


def test_corporate_email_domain_masks_the_organization_everywhere() -> None:
    text = (
        "alert_email = oncall@korvane.com\n"
        "ingress host: pay.korvane.com\n"
        "# korvane checkout service, see KORVANE_API_URL\n"
    )
    out = pipeline().mask(text).text
    assert "korvane" not in out.lower()


def test_public_mail_domains_are_not_learned() -> None:
    out = pipeline().mask("contact: jane.doe@gmail.com\nsee https://mail.gmail.com\n").text
    assert "mail.gmail.com" in out


ARNS = [
    "arn:aws:iam::123456789012:role/orbita-deployer",
    "arn:aws:lambda:eu-west-1:123456789012:function:orbita-billing",
    "arn:aws:sqs:eu-west-1:123456789012:orbita-events",
]


def test_shared_prefix_of_resource_names_is_learned() -> None:
    # Names seen only inside ARNs: three of them share "orbita", so it is the org/project.
    text = "\n".join(ARNS) + "\nnote: the orbita launch is Monday\n"
    out = pipeline().mask(text).text
    assert "orbita" not in out.lower()


def test_two_resource_names_are_not_enough() -> None:
    text = "\n".join(ARNS[:2]) + "\nnote: the orbita launch is Monday\n"
    assert "orbita launch" in pipeline().mask(text).text
