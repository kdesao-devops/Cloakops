"""Realistic fake values for the synthetic corpus, from a seeded RNG (reproducible).

Every value is fake by construction (random characters behind real prefixes), and names are
pronounceable random words, so they are never generic words the pseudonymizer would keep.
"""

from __future__ import annotations

import base64
import random
import string
from collections.abc import Callable
from dataclasses import dataclass, field

from cloakops.model import EntityType as E

_CONSONANTS = "bcdfghjklmnprstvz"
_VOWELS = "aeiou"
_FIRST_NAMES = ["Jane", "Malik", "Sofia", "Kenji", "Amara", "Lucas", "Ines", "Tomasz", "Priya"]
_LAST_NAMES = ["Martin", "Okafor", "Lindqvist", "Moreau", "Haddad", "Novak", "Tanaka", "Rossi"]
_LEGAL = ["SAS", "Inc", "GmbH", "Ltd", "Group"]
_REGIONS = ["eu-west-1", "eu-west-3", "us-east-1", "us-west-2", "ap-southeast-1"]
_TEAMS = ["billing", "checkout", "ledger", "payroll", "search", "catalog", "identity"]


@dataclass
class Fakes:
    """Fake values for one document. Values are memoized per key, so `{{account}}` used twice in
    a template is the same account (documents are internally consistent)."""

    rng: random.Random
    org: str = ""
    _cache: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.org = self.word(2, 3).capitalize()

    # --- primitives ------------------------------------------------------------------------

    def word(self, min_syllables: int = 2, max_syllables: int = 3) -> str:
        n = self.rng.randint(min_syllables, max_syllables)
        return "".join(self.rng.choice(_CONSONANTS) + self.rng.choice(_VOWELS) for _ in range(n))

    def chars(self, alphabet: str, n: int) -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(n))

    def hexs(self, n: int) -> str:
        return self.chars("0123456789abcdef", n)

    # --- factories (name -> (entity type, generator)) ---------------------------------------

    def get(self, key: str) -> tuple[E, str]:
        factory = key.split("#", 1)[0]  # {{bucket#2}}: a second, different bucket
        entity_type, make = FACTORIES[factory]
        if key not in self._cache:
            self._cache[key] = make(self)
        return entity_type, self._cache[key]

    @property
    def slug(self) -> str:
        return self.org.lower()


def _ip_private(f: Fakes) -> str:
    return f"10.{f.rng.randint(0, 255)}.{f.rng.randint(0, 255)}.{f.rng.randint(1, 254)}"


def _ip_public(f: Fakes) -> str:
    return f"{f.rng.choice([52, 54, 18, 3, 35])}.{f.rng.randint(0, 255)}.{f.rng.randint(0, 255)}.{f.rng.randint(1, 254)}"


def _cidr(f: Fakes) -> str:
    return f"10.{f.rng.randint(0, 255)}.0.0/{f.rng.choice([16, 20])}"


def _ipv6(f: Fakes) -> str:
    return f"2600:1f18:{f.hexs(4)}:{f.hexs(4)}::{f.hexs(2)}"


def _person(f: Fakes) -> str:
    return f"{f.rng.choice(_FIRST_NAMES)} {f.rng.choice(_LAST_NAMES)}"


def _email(f: Fakes) -> str:
    first, last = _person(f).lower().split()
    return f"{first}.{last}@{f.slug}.io"


def _password(f: Fakes) -> str:
    return f.word(2, 2).capitalize() + str(f.rng.randint(1000, 9999)) + f.rng.choice("!#%&*")


def _pem(f: Fakes) -> str:
    body = "\n".join(f.chars(string.ascii_letters + string.digits + "+/", 64) for _ in range(4))
    kind = "RSA PRIVATE KEY"
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


def _jwt(f: Fakes) -> str:
    def b64(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    payload = f'{{"sub":"{f.hexs(12)}","email":"{_email(f)}"}}'
    alnum = string.ascii_letters + string.digits
    return f"{b64('{"alg":"RS256","typ":"JWT"}')}.{b64(payload)}.{f.chars(alnum + '-_', 43)}"


def _k8s_secret(f: Fakes) -> str:
    return base64.b64encode(f"{f.word()}:{_password(f)}".encode()).decode()


_ALNUM = string.ascii_letters + string.digits
_UPPER_DIGITS = string.ascii_uppercase + string.digits

FACTORIES: dict[str, tuple[E, Callable[[Fakes], str]]] = {
    "ip_private": (E.IP_ADDRESS, _ip_private),
    "ip_public": (E.IP_ADDRESS, _ip_public),
    "cidr": (E.IP_NETWORK, _cidr),
    "ipv6": (E.IP_ADDRESS, _ipv6),
    "account": (E.AWS_ACCOUNT_ID, lambda f: f.chars(string.digits, 12)),
    "vpc_id": (E.AWS_RESOURCE_ID, lambda f: f"vpc-{f.hexs(17)}"),
    "sg_id": (E.AWS_RESOURCE_ID, lambda f: f"sg-{f.hexs(17)}"),
    "subnet_id": (E.AWS_RESOURCE_ID, lambda f: f"subnet-{f.hexs(17)}"),
    "instance_id": (E.AWS_RESOURCE_ID, lambda f: f"i-{f.hexs(17)}"),
    "ami_id": (E.AWS_RESOURCE_ID, lambda f: f"ami-{f.hexs(17)}"),
    "access_key": (E.AWS_ACCESS_KEY_ID, lambda f: "AKIA" + f.chars(_UPPER_DIGITS, 16)),
    "secret_key": (E.AWS_SECRET_ACCESS_KEY, lambda f: f.chars(_ALNUM + "+/", 40)),
    "gh_token": (E.API_TOKEN, lambda f: "ghp_" + f.chars(_ALNUM, 36)),
    "gl_token": (E.API_TOKEN, lambda f: "glpat-" + f.chars(_ALNUM + "-_", 20)),
    "slack_token": (E.API_TOKEN, lambda f: "xoxb-" + f.chars(string.digits, 12) + "-" + f.chars(_ALNUM, 24)),
    "openai_key": (E.API_TOKEN, lambda f: "sk-proj-" + f.chars(_ALNUM + "-_", 48)),
    "jwt": (E.JWT, _jwt),
    "pem": (E.PRIVATE_KEY, _pem),
    "password": (E.PASSWORD, _password),
    "k8s_secret": (E.GENERIC_SECRET, _k8s_secret),
    "org": (E.ORGANIZATION, lambda f: f"{f.org} {f.rng.choice(_LEGAL)}"),
    "org_word": (E.ORGANIZATION, lambda f: f.org),
    "person": (E.PERSON, _person),
    "email": (E.EMAIL, _email),
    "org_domain": (E.HOSTNAME, lambda f: f"{f.slug}.io"),
    "internal_host": (E.HOSTNAME, lambda f: f"{f.word()}-{f.rng.randint(1, 9):02d}.prod.{f.slug}.internal"),
    "svc_host": (E.HOSTNAME, lambda f: f"{f.rng.choice(_TEAMS)}.{f.slug}.svc.cluster.local"),
    "rds_host": (E.HOSTNAME, lambda f: f"{f.word()}.{f.chars(string.ascii_lowercase + string.digits, 12)}.{f.rng.choice(_REGIONS)}.rds.amazonaws.com"),
    "bucket": (E.BUCKET_NAME, lambda f: f"{f.slug}-{f.rng.choice(_TEAMS)}-{f.rng.choice(['logs', 'artifacts', 'exports'])}"),
    "cluster": (E.CLUSTER_NAME, lambda f: f"{f.slug}-{f.rng.choice(['prod', 'staging'])}-eks"),
    "project": (E.RESOURCE_NAME, lambda f: f"{f.slug}-{f.rng.choice(_TEAMS)}"),
    "role_name": (E.RESOURCE_NAME, lambda f: f"{f.slug}-{f.rng.choice(_TEAMS)}-deployer"),
    "tenant_id": (E.RESOURCE_NAME, lambda f: f"{f.hexs(8)}-{f.hexs(4)}-4{f.hexs(3)}-a{f.hexs(3)}-{f.hexs(12)}"),
}  # fmt: skip

REGIONS = _REGIONS
