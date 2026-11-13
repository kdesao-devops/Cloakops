"""Personal identifiers with a fixed format. Names of people and organizations without a
format are caught by key/value context here and by NER/LLM layers in phase 2."""

from __future__ import annotations

import re

from cloakops.detect.rules.base import RegexRule, Rule
from cloakops.model import EntityType
from cloakops.pseudo.text import is_generic


def _not_git_remote(email: str) -> bool:
    # git@github.com:org/repo.git is an SSH remote, not a mailbox.
    return not email.lower().startswith("git@")


EMAIL = RegexRule(
    name="email",
    entity_type=EntityType.EMAIL,
    pattern=re.compile(
        r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"
    ),
    validate=_not_git_remote,
)


SSH_CONFIG_USER = RegexRule(
    name="ssh-config-user",
    entity_type=EntityType.PERSON,
    # ssh_config / sshd: "    User lmercier" (keyword and value separated by spaces)
    pattern=re.compile(r"^[ \t]*User[ \t]+([^\s#]+)", re.M),
    group=1,
    confidence=0.8,
    validate=lambda v: not is_generic(v) and not v.isdigit(),
)


def identity_rules() -> list[Rule]:
    return [EMAIL, SSH_CONFIG_USER]
