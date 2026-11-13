"""AWS identifiers and credentials.

Formats follow AWS documentation (ARN syntax, IAM unique ID prefixes, S3 endpoints); prefix
lists cross-checked against the public gitleaks rule set (MIT).
"""

from __future__ import annotations

import re

from cloakops.detect.rules.base import RegexRule, Rule
from cloakops.model import EntityType

_PARTITION = r"aws(?:-cn|-us-gov|-iso(?:-[a-z])?)?"
# Resource part: anything up to a delimiter; must not end with "." or ":" (end of sentence).
_ARN_STOP = "\\s\"'`<>,;(){}\\[\\]\\\\"
_ARN_RESOURCE = f"[^{_ARN_STOP}]*[^{_ARN_STOP}.:]"


def _not_aws_managed(arn: str) -> bool:
    # arn:aws:iam::aws:policy/AdministratorAccess is a public, AWS-owned resource.
    parts = arn.split(":", 5)
    return len(parts) < 5 or parts[4] != "aws"


ARN = RegexRule(
    name="aws-arn",
    entity_type=EntityType.ARN,
    pattern=re.compile(
        rf"(?<![\w:/-])arn:{_PARTITION}:[a-z0-9-]+:[a-z0-9-]*:(?:[0-9]{{12}}|aws)?:{_ARN_RESOURCE}"
    ),
    validate=_not_aws_managed,
)

# Twelve digits are ambiguous (order numbers, IDs...). Recall first: every 12-digit number is a
# candidate with low confidence; context raises it. The resolver keeps the higher confidence.
AWS_ACCOUNT_ID_BARE = RegexRule(
    name="aws-account-id",
    entity_type=EntityType.AWS_ACCOUNT_ID,
    pattern=re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])"),
    confidence=0.6,
)

AWS_ACCOUNT_ID_CONTEXT = RegexRule(
    name="aws-account-id-context",
    entity_type=EntityType.AWS_ACCOUNT_ID,
    pattern=re.compile(
        r"(?i:account|owner|aws|principal)[\w\"' :=>-]{0,30}?(?<![0-9])([0-9]{12})(?![0-9])"
    ),
    group=1,
)

AWS_ACCOUNT_ID_ECR = RegexRule(
    name="aws-account-id-ecr",
    entity_type=EntityType.AWS_ACCOUNT_ID,
    pattern=re.compile(r"(?<![0-9])([0-9]{12})\.dkr\.ecr\.", re.I),
    group=1,
)

AWS_ACCESS_KEY_ID = RegexRule(
    name="aws-access-key-id",
    entity_type=EntityType.AWS_ACCESS_KEY_ID,
    # AKIA long-term, ASIA temporary (STS), ABIA/ACCA service-specific.
    pattern=re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
)

AWS_UNIQUE_ID = RegexRule(
    name="aws-unique-id",
    entity_type=EntityType.RESOURCE_NAME,
    # IAM unique IDs of users, roles, groups, instance profiles, policies (4 + 17 chars,
    # e.g. AIDACKCEVSQ6C2EXAMPLE): not secrets but stable identifiers of the principals.
    pattern=re.compile(
        r"(?<![A-Za-z0-9])(?:AIDA|AROA|AIPA|ANPA|ANVA|APKA|AGPA|ASCA)[A-Z0-9]{17}(?![A-Za-z0-9])"
    ),
)

AWS_SECRET_ACCESS_KEY = RegexRule(
    name="aws-secret-access-key",
    entity_type=EntityType.AWS_SECRET_ACCESS_KEY,
    # 40 base64 chars have no distinctive shape: require the key name in front.
    pattern=re.compile(
        r"(?i:aws_?secret_?access_?key|secret_?access_?key|aws_?secret_?key)[\"']?[ \t]*"
        r"(?:=>|:=|[:=])[ \t]*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
    ),
    group=1,
)

# EC2/VPC-family IDs: a type prefix, then 8 (legacy) or 17 hex chars. Not secrets, but unique,
# stable identifiers that link a prompt to an account; masking them is nearly free because the
# pseudonym keeps the prefix and length (ADR 0009). Longest prefixes first.
_RESOURCE_ID_PREFIXES = (
    "tgw-attach", "cvpn-endpoint", "eipalloc", "eipassoc", "rtbassoc", "subnet", "dopt", "eigw",
    "fsap", "snap", "vpce", "ami", "acl", "cgw", "eni", "igw", "nat", "pcx", "sgr", "tgw", "vgw",
    "vol", "vpc", "vpn", "key", "sir", "fs", "lt", "pl", "sg", "i", "r",
)  # fmt: skip

AWS_RESOURCE_ID = RegexRule(
    name="aws-resource-id",
    entity_type=EntityType.AWS_RESOURCE_ID,
    pattern=re.compile(
        rf"(?<![\w-])(?:{'|'.join(_RESOURCE_ID_PREFIXES)})-(?:[0-9a-f]{{17}}|[0-9a-f]{{8}})(?![\w-])"
    ),
)

_BUCKET = r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"

S3_URI_BUCKET = RegexRule(
    name="s3-uri-bucket",
    entity_type=EntityType.BUCKET_NAME,
    pattern=re.compile(rf"(?<![\w-])s3a?://({_BUCKET})", re.I),
    group=1,
)

S3_VIRTUAL_HOST_BUCKET = RegexRule(
    name="s3-virtual-host-bucket",
    entity_type=EntityType.BUCKET_NAME,
    pattern=re.compile(rf"(?<![\w.-])({_BUCKET})\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com", re.I),
    group=1,
)

S3_PATH_STYLE_BUCKET = RegexRule(
    name="s3-path-style-bucket",
    entity_type=EntityType.BUCKET_NAME,
    pattern=re.compile(rf"(?<![\w.-])s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com/({_BUCKET})", re.I),
    group=1,
)

EKS_CLI_CLUSTER = RegexRule(
    name="eks-cli-cluster",
    entity_type=EntityType.CLUSTER_NAME,
    # aws eks update-kubeconfig --name X, eksctl ... --cluster X, --cluster-name X
    pattern=re.compile(
        r"\b(?:aws\s+eks|eksctl)\b[^\n]*?--(?:name|cluster|cluster-name)[ =]([A-Za-z0-9][\w-]*)"
    ),
    group=1,
)

AWS_RESOURCE_HOSTNAME = RegexRule(
    name="aws-resource-hostname",
    entity_type=EntityType.HOSTNAME,
    # Endpoints of the account's own resources (RDS, ElastiCache, ELB, EKS, ECR, EC2 public
    # DNS...) have 3+ labels before amazonaws.com; public service endpoints
    # (sts.eu-west-1.amazonaws.com) have 2 and are left alone.
    pattern=re.compile(
        r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.){3,}amazonaws\.com(?:\.cn)?"
        r"(?![\w-]|\.[a-z0-9])",
        re.I,
    ),
)


def aws_rules() -> list[Rule]:
    return [
        ARN,
        AWS_ACCOUNT_ID_BARE,
        AWS_ACCOUNT_ID_CONTEXT,
        AWS_ACCOUNT_ID_ECR,
        AWS_ACCESS_KEY_ID,
        AWS_UNIQUE_ID,
        AWS_RESOURCE_ID,
        AWS_SECRET_ACCESS_KEY,
        S3_URI_BUCKET,
        S3_VIRTUAL_HOST_BUCKET,
        S3_PATH_STYLE_BUCKET,
        EKS_CLI_CLUSTER,
        AWS_RESOURCE_HOSTNAME,
    ]
