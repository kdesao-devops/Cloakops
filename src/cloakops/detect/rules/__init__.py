"""Deterministic rules layer (phase 1): regexes, key/value heuristics, entropy."""

from __future__ import annotations

from collections.abc import Sequence

from cloakops.detect.rules.aws import aws_rules
from cloakops.detect.rules.base import RegexRule, Rule, RulesDetector
from cloakops.detect.rules.crypto_keys import crypto_key_rules
from cloakops.detect.rules.entropy import entropy_rules
from cloakops.detect.rules.identity import identity_rules
from cloakops.detect.rules.k8s import k8s_rules
from cloakops.detect.rules.keyvalue import keyvalue_rules
from cloakops.detect.rules.network import DEFAULT_INTERNAL_SUFFIXES, network_rules
from cloakops.detect.rules.secrets import secret_rules

__all__ = [
    "DEFAULT_INTERNAL_SUFFIXES",
    "RegexRule",
    "Rule",
    "RulesDetector",
    "default_rules",
    "default_rules_detector",
]


def default_rules(
    internal_suffixes: Sequence[str] = DEFAULT_INTERNAL_SUFFIXES,
    organization_domains: Sequence[str] = (),
) -> list[Rule]:
    return [
        *crypto_key_rules(),
        *secret_rules(),
        *aws_rules(),
        *network_rules(internal_suffixes, organization_domains),
        *identity_rules(),
        *k8s_rules(),
        *keyvalue_rules(),
        *entropy_rules(),
    ]


def default_rules_detector(
    internal_suffixes: Sequence[str] = DEFAULT_INTERNAL_SUFFIXES,
    organization_domains: Sequence[str] = (),
) -> RulesDetector:
    return RulesDetector(default_rules(internal_suffixes, organization_domains))
