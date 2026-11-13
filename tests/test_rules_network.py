import pytest

from cloakops.detect.rules.network import (
    EC2_IP_HOSTNAME,
    IPV4_ADDRESS,
    IPV4_NETWORK,
    IPv6Rule,
    internal_hostname_rule,
    organization_domain_rule,
)
from cloakops.model import EntityType as E
from rules_helpers import raw, values


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("connect to 10.0.1.23:5432", ["10.0.1.23"]),
        ('"PrivateIpAddress": "172.31.4.250",', ["172.31.4.250"]),
        ("client=203.0.113.9 status=200", ["203.0.113.9"]),
        ("http://192.168.1.1/admin", ["192.168.1.1"]),
        ("end of sentence 10.2.3.4.", ["10.2.3.4"]),
    ],
)
def test_ipv4_addresses(text: str, expected: list[str]) -> None:
    assert values(text, IPV4_ADDRESS) == expected


@pytest.mark.parametrize(
    "text",
    [
        "version v1.2.3.4",  # version string
        "1.2.3.4.5",  # five parts
        "256.1.1.1",  # out of range
        "build 2024.11.13.1",  # date-like
        "10.0.0.0/16",  # a network: matched by the CIDR rule, not here
    ],
)
def test_ipv4_non_addresses(text: str) -> None:
    assert values(text, IPV4_ADDRESS) == []


def test_ipv4_networks() -> None:
    text = 'cidr_block = "10.42.0.0/16"\nallow 0.0.0.0/0 and 192.168.0.0/33'
    assert values(text, IPV4_NETWORK) == ["0.0.0.0/0", "10.42.0.0/16"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("addr 2001:db8:85a3::8a2e:370:7334 up", [(E.IP_ADDRESS, "2001:db8:85a3::8a2e:370:7334")]),
        ("[2600:1f18:abcd:1200::12]:443", [(E.IP_ADDRESS, "2600:1f18:abcd:1200::12")]),
        (
            "ipv6_cidr_block = 2600:1f18:abcd:1200::/56",
            [(E.IP_NETWORK, "2600:1f18:abcd:1200::/56")],
        ),
    ],
)
def test_ipv6(text: str, expected: list[tuple[E, str]]) -> None:
    assert raw(text, IPv6Rule()) == expected


@pytest.mark.parametrize("text", ["at 12:30:45", "mac 00:1a:2b:3c:4d:5e", "x = a[1::2]", "::1"])
def test_ipv6_non_addresses(text: str) -> None:
    assert raw(text, IPv6Rule()) == []


def test_internal_hostnames() -> None:
    rule = internal_hostname_rule()
    text = (
        "node ip-10-0-1-23.eu-west-1.compute.internal ready\n"
        "dial payments.prod.svc.cluster.local:8080\n"
        "ldap://dc01.acme.corp\n"
        "public foo.internal.example.com is not internal\n"
        "file settings.local.json is a file\n"
    )
    assert values(text, rule) == [
        "dc01.acme.corp",
        "ip-10-0-1-23.eu-west-1.compute.internal",
        "payments.prod.svc.cluster.local",
    ]


def test_ec2_style_node_names() -> None:
    assert values("kubelet on ip-10-0-1-23 started", EC2_IP_HOSTNAME) == ["ip-10-0-1-23"]


def test_organization_domains_and_subdomains() -> None:
    rule = organization_domain_rule(["acme.io"])
    text = "see https://grafana.ops.acme.io/d/x and acme.io, not acme.io.evil.com"
    assert values(text, rule) == ["acme.io", "grafana.ops.acme.io"]
