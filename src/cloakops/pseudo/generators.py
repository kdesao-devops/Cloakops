"""One generator per entity type: original value -> pseudonym in the same format.

Generators are pure functions of (value, session key, counter). `counter` > 0 means the previous
candidate collided; generators then switch to a fallback that is guaranteed to differ.
Composite values (ARN, hostname, email) are split into components, and each component goes
through `ctx.pseudonym(...)` with its own type, so a bucket, an account or an IP gets the same
pseudonym wherever it appears (ADR 0010).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol

from cloakops.detect.rules.aws import AWS_RESOURCE_ID as _RESOURCE_ID_RULE
from cloakops.model import EntityType
from cloakops.pseudo.keyed import KeyedDerivation
from cloakops.pseudo.network import keeps_ip, pseudo_ip
from cloakops.pseudo.text import (
    ALNUM,
    DIGITS,
    HEX_LOWER,
    KEEP_WORDS,
    UPPER,
    class_preserving,
    pseudo_words,
)


class Context(Protocol):
    @property
    def derivation(self) -> KeyedDerivation: ...

    def pseudonym(self, entity_type: EntityType, value: str) -> str: ...


Generator = Callable[[str, Context, int], str]

E = EntityType

# --- Network ---------------------------------------------------------------------------------


def ip(value: str, ctx: Context, counter: int) -> str:
    return pseudo_ip(value, ctx.derivation, counter)


_REGION = re.compile(r"[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-[0-9]")
_IP_LABEL = re.compile(r"(ip|ec2)-([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})", re.I)
_HOST_KEEP = KEEP_WORDS | {
    "internal", "local", "localdomain", "corp", "lan", "intra", "intranet", "arpa", "home",
    "compute", "ec2", "dkr", "cache", "execute-api", "es", "elasticbeanstalk", "kafka", "mq",
    "redshift", "cloudfront", "sqs", "sns", "dynamodb", "dualstack", "s3-website",
}  # fmt: skip
WELL_KNOWN_HOSTS = frozenset(
    {
        "kubernetes.default.svc.cluster.local",
        "kubernetes.default.svc",
        "kubernetes.default",
        "instance-data.ec2.internal",
        "metadata.google.internal",
    }
)


def _host_label(label: str, ctx: Context) -> str:
    if label.lower() in _HOST_KEEP or _REGION.fullmatch(label.lower()):
        return label
    if re.fullmatch(r"[0-9]{12}", label):
        return ctx.pseudonym(E.AWS_ACCOUNT_ID, label)
    encoded_ip = _IP_LABEL.fullmatch(label)
    if encoded_ip and all(int(g) <= 255 for g in encoded_ip.groups()[1:]):
        address = ".".join(encoded_ip.groups()[1:])
        return f"{encoded_ip[1]}-" + ctx.pseudonym(E.IP_ADDRESS, address).replace(".", "-")
    return pseudo_words(label, ctx.derivation)


def hostname(value: str, ctx: Context, counter: int) -> str:
    labels = value.split(".")
    # The TLD is kept (io, com, internal...) when there is more than one label.
    head, tail = (labels[:-1], labels[-1:]) if len(labels) > 1 else (labels, [])
    if counter:
        head = [class_preserving(lbl, ctx.derivation, "host", counter) for lbl in head]
    else:
        head = [_host_label(lbl, ctx) for lbl in head]
    return ".".join(head + tail)


PUBLIC_MAIL_DOMAINS = frozenset(
    {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
     "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "orange.fr", "free.fr"}
)  # fmt: skip


def email(value: str, ctx: Context, counter: int) -> str:
    local, _, domain = value.rpartition("@")
    if counter:
        local = class_preserving(local, ctx.derivation, "email", counter)
    else:
        local = pseudo_words(local, ctx.derivation)
    if domain.lower() not in PUBLIC_MAIL_DOMAINS:
        domain = ctx.pseudonym(E.HOSTNAME, domain)
    return f"{local}@{domain}"


# --- AWS -------------------------------------------------------------------------------------

_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_IAM_UNIQUE_ID = re.compile(r"(?:AIDA|AROA|AIPA|ANPA|ANVA|APKA|AGPA|ASCA)[A-Z0-9]{16}")


def account_id(value: str, ctx: Context, counter: int) -> str:
    return ctx.derivation.choice(DIGITS, len(value), "aws-account", value, counter)


def resource_id(value: str, ctx: Context, counter: int) -> str:
    prefix, _, hex_part = value.rpartition("-")
    return f"{prefix}-" + ctx.derivation.choice(
        HEX_LOWER, len(hex_part), "aws-resource-id", value, counter
    )


def access_key_id(value: str, ctx: Context, counter: int) -> str:
    return value[:4] + ctx.derivation.choice(_BASE32, len(value) - 4, "aws-key-id", value, counter)


def _arn_segment(segment: str, ctx: Context) -> str:
    if segment in ("", "*") or segment.lower() == "aws":
        return segment
    if _RESOURCE_ID_RULE.pattern.fullmatch(segment):
        return ctx.pseudonym(E.AWS_RESOURCE_ID, segment)
    if re.fullmatch(r"[0-9]{12}", segment):
        return ctx.pseudonym(E.AWS_ACCOUNT_ID, segment)
    return pseudo_words(segment, ctx.derivation)


_EKS_NAMED_TYPES = frozenset(
    {"cluster", "nodegroup", "addon", "fargateprofile", "podidentityassociation"}
)


def _arn_resource(service: str, resource: str, ctx: Context) -> str:
    tokens = re.split(r"([/:])", resource)  # words at even indexes, delimiters at odd ones
    words = tokens[0::2]
    if service == "s3":
        if words[0] not in ("", "*"):
            words[0] = ctx.pseudonym(E.BUCKET_NAME, words[0])
        words[1:] = [_arn_segment(w, ctx) for w in words[1:]]
    elif len(words) == 1:
        words[0] = _arn_segment(words[0], ctx)  # sns topic, sqs queue: no resource type
    else:
        resource_type = words[0].lower()  # role, cluster, function, log-group...: kept
        for i in range(1, len(words)):
            if service == "eks" and resource_type in _EKS_NAMED_TYPES and i == 1:
                words[i] = ctx.pseudonym(E.CLUSTER_NAME, words[i])
            else:
                words[i] = _arn_segment(words[i], ctx)
    tokens[0::2] = words
    return "".join(tokens)


def arn(value: str, ctx: Context, counter: int) -> str:
    parts = value.split(":", 5)
    if len(parts) < 6:
        return class_preserving(value, ctx.derivation, "arn", counter)
    _, partition, service, region, account, resource = parts
    if account.isdigit():
        account = ctx.pseudonym(E.AWS_ACCOUNT_ID, account)
    if counter:
        resource = class_preserving(resource, ctx.derivation, "arn", counter)
    else:
        resource = _arn_resource(service, resource, ctx)
    return ":".join(("arn", partition, service, region, account, resource))


# --- Names -----------------------------------------------------------------------------------


def name(value: str, ctx: Context, counter: int) -> str:
    if _IAM_UNIQUE_ID.fullmatch(value):
        return value[:4] + ctx.derivation.choice(UPPER + DIGITS, 16, "iam-id", value, counter)
    if counter:
        return class_preserving(value, ctx.derivation, "name", counter)
    return pseudo_words(value, ctx.derivation)


# --- Secrets ---------------------------------------------------------------------------------

_TOKEN_PREFIXES = tuple(
    sorted(
        (
            "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "gldt-", "glrt-",
            "glptt-", "xoxb-", "xoxp-", "xoxa-", "xoxo-", "xoxs-", "xoxr-", "sk_live_",
            "sk_test_", "rk_live_", "rk_test_", "sk-ant-api03-", "sk-ant-admin01-", "sk-ant-",
            "sk-proj-", "sk-svcacct-", "sk-admin-", "sk-", "npm_", "pypi-", "dckr_pat_",
            "hvs.", "hvb.", "hvr.", "AIza", "SG.", "AGE-SECRET-KEY-1",
            "https://hooks.slack.com/services/", "https://hooks.slack.com/workflows/",
        ),
        key=len,
        reverse=True,
    )
)  # fmt: skip


def token(value: str, ctx: Context, counter: int) -> str:
    """Keeps the vendor prefix (the model still knows it is a GitHub token); the body is random
    with the same character classes. Bodies of vendor tokens carry a checksum (GitHub: CRC32),
    so the result is invalid by construction; other bodies are random 100+ bit strings."""
    prefix = next((p for p in _TOKEN_PREFIXES if value.startswith(p)), "")
    return prefix + class_preserving(value[len(prefix) :], ctx.derivation, "secret", counter)


_NUMERIC = re.compile(r"[-+]?[0-9][0-9.]*")


def password(value: str, ctx: Context, counter: int) -> str:
    """Passwords do not keep their shape: length and character-class pattern ("Summer2024!")
    would help an attacker and help the model with nothing."""
    if _NUMERIC.fullmatch(value):
        # Unquoted numeric value (PIN, `"password": -1234`): must stay a number in JSON/YAML.
        return class_preserving(value, ctx.derivation, "password", counter)
    return ctx.derivation.choice(ALNUM, 16, "password", value, counter)


def jwt(value: str, ctx: Context, counter: int) -> str:
    parts = value.split(".")
    out = []
    for part in parts:
        keep = "eyJ" if part.startswith("eyJ") else ""
        out.append(keep + class_preserving(part[len(keep) :], ctx.derivation, "jwt", counter))
    return ".".join(out)


_PEM = re.compile(r"(-----BEGIN [A-Z0-9 ]+-----)(.*?)(-----END [A-Z0-9 ]+-----)?$", re.S)


def private_key(value: str, ctx: Context, counter: int) -> str:
    match = _PEM.match(value)
    if not match:
        return class_preserving(value, ctx.derivation, "private-key", counter)
    body = class_preserving(match[2], ctx.derivation, "private-key", counter)
    return match[1] + body + (match[3] or "")


def opaque(value: str, ctx: Context, counter: int) -> str:
    """Merged spans (ADR 0006): no known format, so only character classes are preserved."""
    return class_preserving(value, ctx.derivation, "opaque", counter)


GENERATORS: dict[EntityType, Generator] = {
    E.IP_ADDRESS: ip,
    E.IP_NETWORK: ip,
    E.HOSTNAME: hostname,
    E.EMAIL: email,
    E.ARN: arn,
    E.AWS_ACCOUNT_ID: account_id,
    E.AWS_RESOURCE_ID: resource_id,
    E.AWS_ACCESS_KEY_ID: access_key_id,
    E.BUCKET_NAME: name,
    E.CLUSTER_NAME: name,
    E.RESOURCE_NAME: name,
    E.ORGANIZATION: name,
    E.PERSON: name,
    E.PASSWORD: password,
    E.API_TOKEN: token,
    E.GENERIC_SECRET: token,
    E.AWS_SECRET_ACCESS_KEY: token,
    E.JWT: jwt,
    E.PRIVATE_KEY: private_key,
}

# Generators that are bijections (prefix-preserving permutation): a candidate equal to the
# original is a coincidence, not a leak (the output is independent of the input without the key),
# and a candidate equal to another original cannot be ambiguous. Collision checks are skipped:
# retrying would break prefix preservation.
BIJECTIVE: frozenset[EntityType] = frozenset({E.IP_ADDRESS, E.IP_NETWORK})

# Values detected but intentionally left unchanged (they carry meaning, reveal nothing).
KEEP_IF: dict[EntityType, Callable[[str], bool]] = {
    E.IP_ADDRESS: keeps_ip,
    E.IP_NETWORK: keeps_ip,
    E.HOSTNAME: lambda v: v.lower() in WELL_KNOWN_HOSTS,
}
