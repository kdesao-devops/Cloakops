"""Prefix-preserving IP pseudonymization (in the spirit of Crypto-PAn).

Bit i of the output is bit i of the input XOR f(first i input bits), with f a keyed PRF. Two
addresses that share their first n bits therefore share their first n output bits: subnets keep
containing their hosts, and a CIDR still matches the addresses that were in it. The map is a
permutation (XOR with a function of the prefix can be undone bit by bit), so no two addresses
collide.

Address classes are preserved by not permuting the bits that define them:
- special-purpose ranges (0.0.0.0/8, loopback, link-local incl. 169.254.169.254, multicast,
  documentation ranges...) are left unchanged: they carry meaning and reveal nothing;
- RFC 1918 and CGNAT (100.64.0.0/10) keep their block prefix: private stays private, a 10.x stays
  a 10.x;
- public IPv4 keeps its first octet (a /8 holds 16M addresses), public IPv6 its first 16 bits.
"""

from __future__ import annotations

import ipaddress

from cloakops.pseudo.keyed import KeyedDerivation

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_V4_UNCHANGED = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)
_V4_FIXED_PREFIX = tuple(
    (ipaddress.IPv4Network(n), bits)
    for n, bits in (
        ("10.0.0.0/8", 8),
        ("172.16.0.0/12", 12),
        ("192.168.0.0/16", 16),
        ("100.64.0.0/10", 10),
    )
)
_V4_DEFAULT_KEEP = 8

_V6_UNCHANGED = tuple(
    ipaddress.IPv6Network(n)
    for n in ("::/127", "fe80::/10", "ff00::/8", "2001:db8::/32", "::ffff:0:0/96", "64:ff9b::/96")
)
_V6_FIXED_PREFIX = ((ipaddress.IPv6Network("fc00::/7"), 8),)
_V6_DEFAULT_KEEP = 16

_MAX_CLASS_RETRIES = 16


def _parse(value: str) -> tuple[IPAddress, int | None]:
    address, _, prefix = value.partition("/")
    return ipaddress.ip_address(address), (int(prefix) if prefix else None)


def _unchanged(address: IPAddress) -> bool:
    ranges = _V4_UNCHANGED if address.version == 4 else _V6_UNCHANGED
    return any(address in net for net in ranges)


def _kept_bits(address: IPAddress) -> int:
    fixed = _V4_FIXED_PREFIX if address.version == 4 else _V6_FIXED_PREFIX
    for net, bits in fixed:
        if address in net:
            return bits
    return _V4_DEFAULT_KEEP if address.version == 4 else _V6_DEFAULT_KEEP


def keeps_ip(value: str) -> bool:
    """True when the value must stay as is: special address, or a network no longer than the
    prefix we keep for its class (10.0.0.0/8 has nothing left to permute)."""
    address, prefix = _parse(value)
    return _unchanged(address) or (prefix is not None and prefix <= _kept_bits(address))


def _permute(address: IPAddress, derivation: KeyedDerivation, attempt: int) -> IPAddress:
    nbits = address.max_prefixlen
    keep = _kept_bits(address)
    bits = format(int(address), f"0{nbits}b")
    out = list(bits)
    domain = f"ipv{address.version}:{attempt}"
    for i in range(keep, nbits):
        if derivation.bit(domain, bits[:i]):
            out[i] = "1" if bits[i] == "0" else "0"
    as_int = int("".join(out), 2)
    if address.version == 4:
        return ipaddress.IPv4Address(as_int)
    return ipaddress.IPv6Address(as_int)


def pseudo_address(address: IPAddress, derivation: KeyedDerivation, counter: int) -> IPAddress:
    out = _permute(address, derivation, counter)
    # Rare: a public address lands in a special or non-global range inside its /8. Retry with
    # another permutation for this address only (it loses prefix preservation, nothing else).
    for attempt in range(counter + 1, counter + _MAX_CLASS_RETRIES):
        if not _unchanged(out) and (out.is_global or not address.is_global):
            break
        out = _permute(address, derivation, attempt)
    return out


def pseudo_ip(value: str, derivation: KeyedDerivation, counter: int) -> str:
    address, prefix = _parse(value)
    out = pseudo_address(address, derivation, counter)
    if prefix is None:
        return str(out)
    network: IPNetwork = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    if network.network_address == address:
        # A network: zero the host bits again (the permutation fills them).
        return str(ipaddress.ip_network(f"{out}/{prefix}", strict=False))
    return f"{out}/{prefix}"  # interface notation (10.0.1.5/24): keep the host
