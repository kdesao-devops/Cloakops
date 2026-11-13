"""Private key blocks (PEM, OpenSSH, PGP).

Certificates and public keys are public by design and are not matched.
"""

from __future__ import annotations

import re

from cloakops.detect.rules.base import RegexRule, Rule
from cloakops.model import EntityType

_LABEL = r"[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?"

PRIVATE_KEY_BLOCK = RegexRule(
    name="private-key-block",
    entity_type=EntityType.PRIVATE_KEY,
    pattern=re.compile(
        rf"-----BEGIN {_LABEL}-----"
        # Complete block, including JSON/tfstate-escaped newlines (the lazy scan crosses "\n").
        rf"(?:[\s\S]*?-----END {_LABEL}-----"
        # Truncated block (log cut, partial paste): fail safe, mask the base64-looking tail.
        r"|(?:\\n|[A-Za-z0-9+/=\s:,-])*)"
    ),
)


def crypto_key_rules() -> list[Rule]:
    return [PRIVATE_KEY_BLOCK]
