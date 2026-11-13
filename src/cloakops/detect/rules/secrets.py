"""Vendor tokens with a recognizable prefix, JWTs, bearer tokens and URL credentials.

Prefixes come from each vendor's documentation, cross-checked against the public gitleaks rule
set (MIT). A prefixed token is the easy case: near-zero false positives, so confidence 1.0.
"""

from __future__ import annotations

import re

from cloakops.detect.rules.base import RegexRule, Rule
from cloakops.model import EntityType

_B = r"(?<![A-Za-z0-9_-])"  # token start boundary
_E = r"(?![A-Za-z0-9_-])"  # token end boundary


def _token(name: str, body: str, entity_type: EntityType = EntityType.API_TOKEN) -> RegexRule:
    return RegexRule(name=name, entity_type=entity_type, pattern=re.compile(f"{_B}{body}{_E}"))


VENDOR_TOKENS: list[Rule] = [
    _token("github-token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}"),
    _token("github-fine-grained-pat", r"github_pat_[A-Za-z0-9_]{22,255}"),
    _token(
        "gitlab-token", r"gl(?:pat|rt|dt|ptt|soat|cbt|imt|oas|ft|ffct|agent)-[A-Za-z0-9_-]{20,}"
    ),
    _token("slack-token", r"xox[abposr]-[A-Za-z0-9-]{10,}"),
    _token("stripe-secret-key", r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    _token("google-api-key", r"AIza[0-9A-Za-z_-]{35}"),
    _token("anthropic-api-key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    _token("openai-api-key", r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
    _token("npm-token", r"npm_[A-Za-z0-9]{36}"),
    _token("pypi-token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    _token("docker-hub-pat", r"dckr_pat_[A-Za-z0-9_-]{20,}"),
    _token("vault-token", r"hv[sbr]\.[A-Za-z0-9_-]{24,}"),
    _token("terraform-cloud-token", r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}"),
    _token("sendgrid-api-key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    _token("age-secret-key", r"AGE-SECRET-KEY-1[0-9A-Z]{58}", EntityType.PRIVATE_KEY),
]

SLACK_WEBHOOK = RegexRule(
    name="slack-webhook",
    entity_type=EntityType.API_TOKEN,
    pattern=re.compile(r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]{20,}"),
)

JWT = RegexRule(
    name="jwt",
    entity_type=EntityType.JWT,
    # Header and payload are base64url JSON objects, so both start with "eyJ" ('{"').
    # The signature may be empty (alg "none").
    pattern=re.compile(rf"{_B}eyJ[A-Za-z0-9_-]{{5,}}\.eyJ[A-Za-z0-9_-]{{5,}}\.[A-Za-z0-9_-]*{_E}"),
)

AUTHORIZATION_HEADER = RegexRule(
    name="authorization-header",
    entity_type=EntityType.API_TOKEN,
    pattern=re.compile(
        r"(?i:authorization)[\"']?[ \t]*[:=][ \t]*[\"']?(?i:bearer|basic|token|apikey)[ \t]+"
        r"([A-Za-z0-9._~+/=-]{8,})"
    ),
    group=1,
)

BEARER_TOKEN = RegexRule(
    name="bearer-token",
    entity_type=EntityType.API_TOKEN,
    pattern=re.compile(r"(?<![\w-])(?i:bearer)[ \t]+([A-Za-z0-9._~+/-]{16,}=*)"),
    group=1,
)

URL_PASSWORD = RegexRule(
    name="url-password",
    entity_type=EntityType.PASSWORD,
    # scheme://user:password@host -- the password is percent-encoded, so no "@" or "/" in it.
    pattern=re.compile(r"(?<![\w+.-])[a-z][a-z0-9+.-]*://[^\s:/@\"']+:([^\s@/\"']+)@", re.I),
    group=1,
)

AZURE_ACCOUNT_KEY = RegexRule(
    name="azure-storage-account-key",
    entity_type=EntityType.GENERIC_SECRET,
    pattern=re.compile(r"(?i:accountkey)=([A-Za-z0-9+/]{86}==)"),
    group=1,
)


def secret_rules() -> list[Rule]:
    return [
        *VENDOR_TOKENS,
        SLACK_WEBHOOK,
        JWT,
        AUTHORIZATION_HEADER,
        BEARER_TOKEN,
        URL_PASSWORD,
        AZURE_ACCOUNT_KEY,
    ]
