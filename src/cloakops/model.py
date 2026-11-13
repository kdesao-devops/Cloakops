"""Core data types shared by detectors, the resolver and pseudonymizers.

A `Span` points into the ORIGINAL text by character offsets and never stores the value itself:
spans travel through the pipeline, end up in audit receipts and may be printed in errors, so
keeping raw values out of them removes a whole class of accidental leaks.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class Category(IntEnum):
    """Sensitivity class. A higher value wins when spans of different classes compete."""

    INFRASTRUCTURE = 1
    PERSONAL = 2
    CREDENTIAL = 3


class EntityType(StrEnum):
    # Credentials: direct compromise if leaked.
    PRIVATE_KEY = "private_key"
    AWS_ACCESS_KEY_ID = "aws_access_key_id"
    AWS_SECRET_ACCESS_KEY = "aws_secret_access_key"  # noqa: S105 (type name, not a secret)
    API_TOKEN = "api_token"  # noqa: S105
    JWT = "jwt"
    PASSWORD = "password"  # noqa: S105
    GENERIC_SECRET = "generic_secret"  # noqa: S105

    # Infrastructure identifiers.
    IP_ADDRESS = "ip_address"
    IP_NETWORK = "ip_network"
    ARN = "arn"
    AWS_ACCOUNT_ID = "aws_account_id"
    AWS_RESOURCE_ID = "aws_resource_id"  # vpc-..., sg-..., i-... (ADR 0009)
    HOSTNAME = "hostname"
    BUCKET_NAME = "bucket_name"
    CLUSTER_NAME = "cluster_name"
    RESOURCE_NAME = "resource_name"

    # Personal and business data.
    EMAIL = "email"
    PERSON = "person"
    ORGANIZATION = "organization"

    @property
    def category(self) -> Category:
        return _CATEGORY[self]

    @property
    def is_generic(self) -> bool:
        """Generic types say "something sensitive" without a known format.

        When a generic and a specific detection cover the same text, the specific one wins: its
        pseudonym keeps more structure (an `AKIA...` key stays recognizable as an access key).
        """
        return self in _GENERIC

    @property
    def rank(self) -> tuple[int, int]:
        """Priority used by the resolver: category first, then specific over generic."""
        return (int(self.category), 0 if self.is_generic else 1)


_CATEGORY: dict[EntityType, Category] = {
    EntityType.PRIVATE_KEY: Category.CREDENTIAL,
    EntityType.AWS_ACCESS_KEY_ID: Category.CREDENTIAL,
    EntityType.AWS_SECRET_ACCESS_KEY: Category.CREDENTIAL,
    EntityType.API_TOKEN: Category.CREDENTIAL,
    EntityType.JWT: Category.CREDENTIAL,
    EntityType.PASSWORD: Category.CREDENTIAL,
    EntityType.GENERIC_SECRET: Category.CREDENTIAL,
    EntityType.IP_ADDRESS: Category.INFRASTRUCTURE,
    EntityType.IP_NETWORK: Category.INFRASTRUCTURE,
    EntityType.ARN: Category.INFRASTRUCTURE,
    EntityType.AWS_ACCOUNT_ID: Category.INFRASTRUCTURE,
    EntityType.AWS_RESOURCE_ID: Category.INFRASTRUCTURE,
    EntityType.HOSTNAME: Category.INFRASTRUCTURE,
    EntityType.BUCKET_NAME: Category.INFRASTRUCTURE,
    EntityType.CLUSTER_NAME: Category.INFRASTRUCTURE,
    EntityType.RESOURCE_NAME: Category.INFRASTRUCTURE,
    EntityType.EMAIL: Category.PERSONAL,
    EntityType.PERSON: Category.PERSONAL,
    EntityType.ORGANIZATION: Category.PERSONAL,
}

_GENERIC: frozenset[EntityType] = frozenset(
    {EntityType.PASSWORD, EntityType.GENERIC_SECRET, EntityType.RESOURCE_NAME}
)


@dataclass(frozen=True, slots=True)
class Span:
    """A detected entity: half-open interval [start, end) over the original text."""

    start: int
    end: int
    entity_type: EntityType
    detector: str
    confidence: float = 1.0
    merged: bool = False
    """True when the resolver fused partially overlapping detections into one span. The exact
    format is then unknown, so pseudonymizers must use an opaque placeholder."""

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"span start must be >= 0, got {self.start}")
        if self.end <= self.start:
            raise ValueError(f"span must be non-empty, got [{self.start}, {self.end})")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if not self.detector:
            raise ValueError("detector name must not be empty")

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Span) -> bool:
        """True if the spans share at least one character (touching spans do not overlap)."""
        return self.start < other.end and other.start < self.end

    def contains(self, other: Span) -> bool:
        return self.start <= other.start and other.end <= self.end

    def text_of(self, text: str) -> str:
        """The covered value. Call only where the raw value is genuinely needed."""
        return text[self.start : self.end]
