"""Fake secrets built at runtime.

Tests never contain realistic secrets as literals: secret scanners (gitleaks in pre-commit and
CI) would flag them, and allowlisting the whole test tree would hide a real leak. Values are
assembled from a prefix and deterministic random characters instead.
"""

from __future__ import annotations

import random
import string

UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
BASE64 = ALNUM + "+/"
URLSAFE = ALNUM + "-_"
HEX = "0123456789abcdef"


def chars(alphabet: str, n: int, seed: int = 0) -> str:
    rng = random.Random(f"{alphabet}-{n}-{seed}")  # noqa: S311 (not cryptographic, on purpose)
    return "".join(rng.choice(alphabet) for _ in range(n))


def fake(prefix: str, alphabet: str, n: int, seed: int = 0) -> str:
    return prefix + chars(alphabet, n, seed)


def pem_private_key(label: str = "RSA ", lines: int = 3, escaped_newlines: bool = False) -> str:
    nl = "\\n" if escaped_newlines else "\n"
    body = nl.join(chars(BASE64, 64, seed=i) for i in range(lines))
    kind = f"{label}PRIVATE KEY"
    return f"-----BEGIN {kind}-----{nl}{body}{nl}-----END {kind}-----"
