"""High-confidence signals of the organization's own names (ADR 0015).

An explicit `client: Acme` is rare. The organization's name is, however, almost always present
in places with a precise format:

- tool URLs: Terraform Cloud organization, Git SSH remotes, private container registries;
- AWS sign-in and SSO portal URLs (account alias, SSO directory name);
- certificate subjects (O=, CN=);
- legal entity names (`Korvane SAS`, `Acme GmbH`);
- copyright headers.

These spans are ORGANIZATION (or HOSTNAME / RESOURCE_NAME) with high confidence, so the
propagation layer learns their words and masks every other mention of the organization.
Public organizations (GitHub Actions, HashiCorp, Bitnami...) are excluded: they are
dependencies, not the user's organization.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from cloakops.detect.rules.base import RegexRule, Rule, span_for
from cloakops.model import EntityType, Span
from cloakops.pseudo.text import is_generic

PUBLIC_ORGANIZATIONS = frozenset(
    {
        "actions", "github", "aws-actions", "hashicorp", "terraform-aws-modules", "kubernetes",
        "kubernetes-sigs", "k8s", "helm", "bitnami", "bitnamicharts", "prometheus",
        "prometheus-community", "grafana", "docker", "library", "open-telemetry", "fluxcd",
        "argoproj", "jetstack", "external-secrets", "kyverno", "sigstore", "aquasecurity",
        "cloudnative-pg", "cert-manager", "elastic", "datadog", "gruntwork-io", "astral-sh",
        "pypa", "python", "golang", "nodejs", "microsoft", "azure", "google", "googlecloudplatform",
        "aws", "awslabs", "aws-samples", "amazon", "ubuntu", "canonical", "redhat", "vercel",
        "renovatebot", "dependabot", "pre-commit", "anthropics", "openai", "mozilla", "apache",
    }
)  # fmt: skip


def _private_org(name: str) -> bool:
    return name.lower() not in PUBLIC_ORGANIZATIONS and not is_generic(name)


_ORG = r"([A-Za-z0-9][A-Za-z0-9_.-]{1,38}[A-Za-z0-9])"

TOOL_URL_ORGANIZATION = RegexRule(
    name="tool-url-organization",
    entity_type=EntityType.ORGANIZATION,
    pattern=re.compile(
        r"(?:"
        r"app\.terraform\.io/(?:app/)?"  # Terraform Cloud: app.terraform.io/<org>/...
        r"|git@(?:github\.com|gitlab\.com|bitbucket\.org|ssh\.dev\.azure\.com:v3)[:/]"  # SSH remote
        r"|ssh://git@(?:github\.com|gitlab\.com|bitbucket\.org)(?::\d+)?/"
        r"|(?:ghcr\.io|registry\.gitlab\.com|quay\.io)/"  # container registries
        rf"){_ORG}(?=[/:\s\"']|$)",
        re.I | re.M,
    ),
    group=1,
    validate=_private_org,
)

AZURE_REGISTRY = RegexRule(
    name="azure-registry",
    entity_type=EntityType.ORGANIZATION,
    pattern=re.compile(r"(?<![\w.-])([a-z0-9]{5,50})\.azurecr\.io\b"),
    group=1,
    validate=_private_org,
)

AWS_SIGNIN_ALIAS = RegexRule(
    name="aws-signin-alias",
    entity_type=EntityType.RESOURCE_NAME,
    # https://<account-alias>.signin.aws.amazon.com/console
    pattern=re.compile(r"(?<![\w.-])([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.signin\.aws\.amazon\.com"),
    group=1,
)

AWS_SSO_PORTAL = RegexRule(
    name="aws-sso-portal",
    entity_type=EntityType.ORGANIZATION,
    # https://<directory>.awsapps.com/start (IAM Identity Center portal)
    pattern=re.compile(r"(?<![\w.-])([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.awsapps\.com\b"),
    group=1,
)


class CertificateSubjectRule:
    """O= and CN= of a certificate SUBJECT (openssl text output, `subject=` lines, DN strings).
    The issuer is skipped: public CAs (Let's Encrypt, Amazon) are not the organization."""

    name = "cert-subject"
    _line = re.compile(r"(?im)^[^\n]*\bsubject\s*[:=][^\n]*$")
    _org = re.compile(r"\bO\s*=\s*\"?([^,/\n\"]+)")
    _cn = re.compile(r"\bCN\s*=\s*\"?([^,/\n\"\s]+)")

    def find(self, text: str) -> Iterator[Span]:
        for line in self._line.finditer(text):
            if re.search(r"(?i)\bissuer\b", line.group()):
                continue
            for pattern, entity_type in (
                (self._org, EntityType.ORGANIZATION),
                (self._cn, EntityType.HOSTNAME),
            ):
                for m in pattern.finditer(line.group()):
                    value = m.group(1).strip()
                    if not value or is_generic(value):
                        continue
                    start = line.start() + m.start(1)
                    yield span_for(
                        f"{self.name}-{'o' if entity_type is EntityType.ORGANIZATION else 'cn'}",
                        start,
                        start + len(value),
                        entity_type,
                        1.0,
                    )


_LEGAL_FORMS = r"SAS|SARL|SASU|Inc\.?|LLC|Ltd\.?|Limited|GmbH|B\.V\.|BV|N\.V\.|PLC|Corp\.?|Corporation|S\.A\.|S\.p\.A\.|Oy"
_CAPITALIZED = r"[A-Z][A-Za-z0-9&'-]+"

LEGAL_ENTITY = RegexRule(
    name="legal-entity",
    entity_type=EntityType.ORGANIZATION,
    # "Brindel Logistics SAS", "Acme GmbH": capitalized words followed by a legal form.
    pattern=re.compile(
        rf"\b({_CAPITALIZED}(?:[ \t]+{_CAPITALIZED}){{0,3}}[ \t,]+(?:{_LEGAL_FORMS}))(?![\w])"
    ),
    group=1,
    confidence=0.8,
    validate=lambda v: not is_generic(re.split(r"[ \t,]+", v)[0]),
)

_PUBLIC_COPYRIGHT_HOLDERS = re.compile(
    r"(?i)^(?:the\s+\w+\s+authors|amazon|google|microsoft|hashicorp|the\s+linux\s+foundation|"
    r"the\s+apache\s+software\s+foundation|python\s+software\s+foundation|github)"
)

COPYRIGHT_HOLDER = RegexRule(
    name="copyright-holder",
    entity_type=EntityType.ORGANIZATION,
    pattern=re.compile(
        rf"(?i:copyright)[ \t]*(?:\((?i:c)\)|©)?[ \t]*(?:\d{{4}}(?:[ \t]*[-\u2013][ \t]*\d{{4}})?,?[ \t]+)?"
        rf"({_CAPITALIZED}(?:[ \t]+{_CAPITALIZED}){{0,3}})"
    ),
    group=1,
    confidence=0.9,
    validate=lambda v: not _PUBLIC_COPYRIGHT_HOLDERS.match(v) and not is_generic(v),
)


def organization_rules() -> list[Rule]:
    return [
        TOOL_URL_ORGANIZATION,
        AZURE_REGISTRY,
        AWS_SIGNIN_ALIAS,
        AWS_SSO_PORTAL,
        CertificateSubjectRule(),
        LEGAL_ENTITY,
        COPYRIGHT_HOLDER,
    ]
