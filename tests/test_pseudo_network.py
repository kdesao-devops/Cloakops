import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cloakops.model import EntityType as E
from pseudo_helpers import OTHER_KEY, engine, pseudo


def common_prefix(a: int, b: int, bits: int) -> int:
    return bits - (a ^ b).bit_length()


@pytest.mark.parametrize(
    ("value", "network"),
    [
        ("10.42.3.17", "10.0.0.0/8"),
        ("172.20.1.9", "172.16.0.0/12"),
        ("192.168.7.1", "192.168.0.0/16"),
        ("100.64.3.2", "100.64.0.0/10"),
    ],
)
def test_private_stays_in_its_block(value: str, network: str) -> None:
    out = pseudo(E.IP_ADDRESS, value)
    assert out != value
    assert ipaddress.ip_address(out) in ipaddress.ip_network(network)


def test_public_stays_public_in_the_same_slash_8() -> None:
    out = ipaddress.ip_address(pseudo(E.IP_ADDRESS, "52.94.236.248"))
    assert out.is_global and str(out).startswith("52.")


@pytest.mark.parametrize(
    "value",
    ["0.0.0.0/0", "127.0.0.1", "169.254.169.254", "10.0.0.0/8", "192.0.2.10", "fe80::1:2:3"],
)
def test_special_addresses_are_kept(value: str) -> None:
    pseudonymizer = engine()
    assert pseudonymizer.pseudonym(E.IP_NETWORK, value) == value
    assert value in pseudonymizer.session.kept


def test_network_keeps_its_prefix_length_and_zero_host_bits() -> None:
    out = ipaddress.ip_network(pseudo(E.IP_NETWORK, "10.42.0.0/16"))
    assert out.prefixlen == 16


def test_ipv6_global_keeps_first_16_bits() -> None:
    out = pseudo(E.IP_ADDRESS, "2600:1f18:abcd:1200::12")
    assert out.startswith("2600:") and out != "2600:1f18:abcd:1200::12"


def test_different_session_keys_give_unlinkable_pseudonyms() -> None:
    assert pseudo(E.IP_ADDRESS, "10.42.3.17") != pseudo(E.IP_ADDRESS, "10.42.3.17", OTHER_KEY)


private_v4 = st.integers(min_value=0, max_value=2**24 - 1).map(
    lambda n: ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.0.0.0")) + n)
)


@given(private_v4, private_v4)
def test_prefix_preservation(a: ipaddress.IPv4Address, b: ipaddress.IPv4Address) -> None:
    # Two addresses sharing n leading bits map to two addresses sharing exactly n leading bits.
    pseudonymizer = engine()
    pa = ipaddress.IPv4Address(pseudonymizer.pseudonym(E.IP_ADDRESS, str(a)))
    pb = ipaddress.IPv4Address(pseudonymizer.pseudonym(E.IP_ADDRESS, str(b)))
    assert common_prefix(int(pa), int(pb), 32) == common_prefix(int(a), int(b), 32)


@given(private_v4, st.integers(min_value=9, max_value=32))
def test_hosts_stay_inside_their_pseudonymized_subnet(
    host: ipaddress.IPv4Address, prefix: int
) -> None:
    pseudonymizer = engine()
    network = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
    p_host = ipaddress.ip_address(pseudonymizer.pseudonym(E.IP_ADDRESS, str(host)))
    p_net = ipaddress.ip_network(pseudonymizer.pseudonym(E.IP_NETWORK, str(network)))
    assert p_host in p_net
