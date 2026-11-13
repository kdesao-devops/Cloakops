"""IP addresses, networks and internal hostnames."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator, Sequence

from cloakops.detect.rules.base import RegexRule, Rule, span_for
from cloakops.model import EntityType, Span

# One octet, 0-255, no leading zeros. Alternatives ordered longest first.
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4 = rf"{_OCTET}(?:\.{_OCTET}){{3}}"
# Not preceded by a word char, dot or dash: rejects version strings (v1.2.3.4), the tail of a
# longer dotted number, and hostnames like host-10.0.0.1.
_IPV4_BEFORE = r"(?<![\w.-])"

IPV4_NETWORK = RegexRule(
    name="ipv4-cidr",
    entity_type=EntityType.IP_NETWORK,
    pattern=re.compile(rf"{_IPV4_BEFORE}{_IPV4}/(?:3[0-2]|[12]?[0-9])(?![\w/]|\.[0-9])"),
)

IPV4_ADDRESS = RegexRule(
    name="ipv4",
    entity_type=EntityType.IP_ADDRESS,
    # Not followed by "/<digit>" (that is a CIDR, matched above) or ".<digit>" (5+ parts).
    pattern=re.compile(rf"{_IPV4_BEFORE}{_IPV4}(?![\w-]|\.[0-9]|/[0-9])"),
)

# EC2-style node names embed the private IP: ip-10-0-1-23 (Kubernetes node names, logs).
EC2_IP_HOSTNAME = RegexRule(
    name="ec2-ip-hostname",
    entity_type=EntityType.HOSTNAME,
    pattern=re.compile(
        r"(?<![\w-])ip-(?:[0-9]{1,3}-){3}[0-9]{1,3}(?:\.[a-z0-9-]+)*(?![\w-])", re.I
    ),
)


class IPv6Rule:
    """IPv6 is too irregular for a precise regex: match loosely, then validate with `ipaddress`.

    Requires at least three non-empty groups, which rejects times (12:30:45), MAC addresses
    (rejected by `ipaddress` anyway), Python slices (a[1::2]) and short special addresses
    (::1, fe80::1) that carry no sensitive information.
    """

    name = "ipv6"
    _candidate = re.compile(
        r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/[0-9]{1,3})?(?![\w:])"
    )

    def find(self, text: str) -> Iterator[Span]:
        for match in self._candidate.finditer(text):
            entity_type = self._classify(match.group())
            if entity_type is not None:
                yield span_for(self.name, match.start(), match.end(), entity_type, 1.0)

    @staticmethod
    def _classify(value: str) -> EntityType | None:
        address = value.split("/", 1)[0]
        if sum(1 for group in address.split(":") if group) < 3:
            return None
        try:
            if "/" in value:
                ipaddress.IPv6Network(value, strict=False)
                return EntityType.IP_NETWORK
            ipaddress.IPv6Address(value)
            return EntityType.IP_ADDRESS
        except ValueError:
            return None


DEFAULT_INTERNAL_SUFFIXES: tuple[str, ...] = (
    "internal",  # includes AWS *.compute.internal, *.ec2.internal
    "local",  # includes Kubernetes *.svc.cluster.local
    "localdomain",
    "corp",
    "lan",
    "intra",
    "intranet",
    "private",
    "home.arpa",
)

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# Must not continue as a longer hostname (foo.internal.example.com is a public name).
_HOST_AFTER = r"(?![\w-]|\.[a-z0-9])"


def _alternation(names: Sequence[str]) -> str:
    cleaned = sorted({n.strip(".").lower() for n in names if n.strip(".")}, key=len, reverse=True)
    return "|".join(re.escape(n) for n in cleaned)


def internal_hostname_rule(suffixes: Sequence[str] = DEFAULT_INTERNAL_SUFFIXES) -> RegexRule:
    """Hostnames under a private-use suffix: at least one label before the suffix."""
    return RegexRule(
        name="internal-hostname",
        entity_type=EntityType.HOSTNAME,
        pattern=re.compile(
            rf"(?<![\w.-])(?:{_LABEL}\.)+(?:{_alternation(suffixes)}){_HOST_AFTER}", re.I
        ),
    )


def organization_domain_rule(domains: Sequence[str]) -> RegexRule:
    """The organization's own domains (e.g. acme.com) and all their subdomains."""
    return RegexRule(
        name="organization-domain",
        entity_type=EntityType.HOSTNAME,
        pattern=re.compile(
            rf"(?<![\w.-])(?:{_LABEL}\.)*(?:{_alternation(domains)}){_HOST_AFTER}", re.I
        ),
    )


def network_rules(
    internal_suffixes: Sequence[str] = DEFAULT_INTERNAL_SUFFIXES,
    organization_domains: Sequence[str] = (),
) -> list[Rule]:
    rules: list[Rule] = [
        IPV4_NETWORK,
        IPV4_ADDRESS,
        IPv6Rule(),
        EC2_IP_HOSTNAME,
        internal_hostname_rule(internal_suffixes),
    ]
    if organization_domains:
        rules.append(organization_domain_rule(organization_domains))
    return rules
