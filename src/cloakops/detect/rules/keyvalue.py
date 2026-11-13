"""Key/value heuristics: the NAME of a field says its value is sensitive, whatever its shape.

Works on raw text across formats (ADR 0005):

    password: hunter2            YAML
    "client_secret": "abc"       JSON
    db_password = "abc"          HCL, .ini
    DB_PASSWORD=abc              .env, shell
    --api-token abc              CLI flags
    ~ password = "a" -> "b"      Terraform plan diff
    - name: DB_PASSWORD          Kubernetes env, ECS task definitions
      value: abc

The regexes only locate `key + separator`; the value is read in Python. Matching the value in
the regex would consume the rest of the line and hide a second pair on the same line
(`msg: login ok password=abc`).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from cloakops.detect.rules.base import Rule, span_for
from cloakops.model import EntityType, Span
from cloakops.pseudo.text import is_generic

# --- Key classification --------------------------------------------------------------------

_EXACT: dict[EntityType, frozenset[str]] = {
    EntityType.ORGANIZATION: frozenset(
        {
            "client", "clientname", "customer", "customername", "company", "companyname",
            "organization", "organisation", "organizationname", "org", "orgname",
            "tenant", "tenantname", "accountname", "partner", "vendor",
        }
    ),
    EntityType.PERSON: frozenset(
        {
            "owner", "author", "maintainer", "contact", "createdby", "requestedby",
            "approvedby", "assignee", "reviewer", "user", "username", "login", "fullname",
            "firstname", "lastname", "displayname",
        }
    ),
    EntityType.BUCKET_NAME: frozenset({"bucket", "bucketname", "s3bucket", "s3bucketname"}),
    EntityType.CLUSTER_NAME: frozenset({"cluster", "clustername", "ekscluster", "eksclustername"}),
    EntityType.RESOURCE_NAME: frozenset({"project", "projectname", "projectid", "codename"}),
}  # fmt: skip

_EXACT_CONFIDENCE = {
    EntityType.ORGANIZATION: 0.8,
    EntityType.PERSON: 0.8,
    EntityType.BUCKET_NAME: 0.9,
    EntityType.CLUSTER_NAME: 0.9,
    EntityType.RESOURCE_NAME: 0.8,
}

# Identifiers without a recognizable format (often UUIDs) that tie content to an organization:
# masked only in this explicit context (ADR 0009). Matched as a suffix: ARM_TENANT_ID, etc.
_ORG_ID_SUFFIXES = (
    "tenantid", "subscriptionid", "directoryid", "kmskeyid", "clientid", "applicationid",
    "appid", "organizationid", "orgid", "workspaceid", "externalid", "billingaccountid",
)  # fmt: skip

# Values that embed credentials even though the key ends in "url".
_URL_SECRETS = (
    "databaseurl", "dburl", "dsn", "connectionstring", "connstr", "webhook", "redisurl",
    "mongourl", "mongouri", "mongodburi", "amqpurl", "brokerurl",
)  # fmt: skip

_SECRET_WORDS = (
    "secret", "privatekey", "apikey", "accesskey", "signingkey", "encryptionkey", "masterkey",
    "clientkey", "sshkey", "authkey", "licensekey", "keydata", "credential", "salt",
    "authorization", "cookie", "sessionkey",
)  # fmt: skip
_SECRET_EXACT = frozenset({"auth", "pass", "pw", "pin"})

# Keys about a credential that do not hold it.
_METADATA_SUFFIXES = (
    "length", "type", "enabled", "required", "policy", "rotation", "ttl", "version", "expiry",
    "expiration", "expires", "count", "url", "uri", "endpoint", "host", "port", "algorithm",
    "format", "header", "mode", "minlength", "maxlength",
)  # fmt: skip
# Keys that point to a credential (a name, an ARN, a path): masked, but as an identifier.
_REFERENCE_SUFFIXES = ("name", "ref", "arn", "id", "path", "file", "location")


_PERSON_SUFFIXES = ("username", "user", "login")
_NOT_PERSON = frozenset({"runasuser", "runasnonroot", "nonrootuser", "enableuser"})


def normalize_key(key: str) -> str:
    """client_secret, clientSecret, CLIENT-SECRET -> clientsecret."""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def classify_key(key: str) -> tuple[EntityType, float] | None:
    """Entity type and confidence implied by a field name, or None if not sensitive."""
    norm = normalize_key(key)
    if not norm:
        return None

    for exact_type, names in _EXACT.items():
        if norm in names:
            return exact_type, _EXACT_CONFIDENCE[exact_type]

    if norm.endswith(_ORG_ID_SUFFIXES):
        return EntityType.RESOURCE_NAME, 0.8

    if any(word in norm for word in _URL_SECRETS):
        return EntityType.GENERIC_SECRET, 0.9

    entity_type: EntityType | None = None
    if "secretaccesskey" in norm:
        entity_type = EntityType.AWS_SECRET_ACCESS_KEY
    elif any(w in norm for w in ("password", "passwd", "passphrase")) or (
        norm.endswith("pwd") and norm not in ("pwd", "oldpwd")  # $PWD is the working directory
    ):
        entity_type = EntityType.PASSWORD
    elif norm.endswith("pass") and not norm.endswith(("bypass", "compass")):
        entity_type = EntityType.PASSWORD  # db_pass, ADMIN_PASS
    elif "token" in norm:
        entity_type = EntityType.API_TOKEN
    elif norm in _SECRET_EXACT or any(word in norm for word in _SECRET_WORDS):
        entity_type = EntityType.GENERIC_SECRET
    if entity_type is None:
        if norm.endswith(_PERSON_SUFFIXES) and norm not in _NOT_PERSON:
            return EntityType.PERSON, 0.8  # ansible_user, db_username, remote_login
        if "customer" in norm:
            return EntityType.ORGANIZATION, 0.8  # customer_tag, end_customer
        return None

    if norm.endswith(_METADATA_SUFFIXES):
        return None
    if norm.endswith(_REFERENCE_SUFFIXES):
        return EntityType.RESOURCE_NAME, 0.7
    return entity_type, 0.9


# --- Value filtering -----------------------------------------------------------------------

_PLACEHOLDERS = frozenset(
    {
        "", "null", "none", "nil", "~", "true", "false", "yes", "no", "on", "off", "read", "write",
        "redacted",
        "<redacted>", "[redacted]", "<sensitive>", "(sensitive)", "(sensitive value)",
        "(known after apply)", "-", "|", ">", "{", "[", "{}", "[]",
    }
)  # fmt: skip

# References to a value defined elsewhere: Terraform, Helm/Go templates, shell, CloudFormation.
_REFERENCE_VALUE = re.compile(
    r"^(?:\$\{|\$\(|\{\{|<%|%\{|\$[A-Za-z_]|!(?:Ref|Sub|GetAtt|ImportValue|FindInMap)\b"
    r"|(?:var|local|data|module|each|self)\.[\w.\[\]\"*-]+$)"
)


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return v.lower() in _PLACEHOLDERS or set(v) <= {"*"} or bool(_REFERENCE_VALUE.match(v))


# --- Value reading -------------------------------------------------------------------------

_BLOCK_SCALAR = re.compile(r"[|>][+-]?[0-9]?")
_ARROW = re.compile(r"[ \t]*->[ \t]*([\"'])")
_FIRST_WORD = re.compile(r"[ \t]*(\S*)")


def _read_quoted(text: str, pos: int) -> tuple[int, int] | None:
    """Span of the content of the quoted string opening at `pos` (same line), or None."""
    quote = text[pos]
    i = pos + 1
    while i < len(text) and text[i] != "\n":
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return pos + 1, i
        i += 1
    return None


def _line_indent(text: str, pos: int) -> int:
    line_start = text.rfind("\n", 0, pos) + 1
    line = text[line_start:pos]
    return len(line) - len(line.lstrip(" \t-"))


def _read_block_scalar(text: str, key_pos: int, after: int) -> tuple[int, int] | None:
    """YAML `key: |` block: every following line indented deeper than the key."""
    indent = _line_indent(text, key_pos)
    line_end = text.find("\n", after)
    if line_end < 0:
        return None
    start = end = -1
    pos = line_end + 1
    while pos < len(text):
        nxt = text.find("\n", pos)
        nxt = len(text) if nxt < 0 else nxt
        line = text[pos:nxt]
        stripped = line.strip()
        if stripped:
            if len(line) - len(line.lstrip(" \t")) <= indent:
                break
            if start < 0:
                start = pos + (len(line) - len(line.lstrip(" \t")))
            end = pos + len(line.rstrip())
        pos = nxt + 1
    return (start, end) if start >= 0 else None


def read_values(text: str, pos: int, sep: str, key_pos: int) -> list[tuple[int, int]]:
    """Spans of the value(s) starting at `pos`. `sep` is the separator that preceded it."""
    if pos >= len(text):
        return []
    if text[pos] in "\"'`":
        quoted = _read_quoted(text, pos)
        if quoted is None:
            return []
        spans = [quoted]
        # Terraform plan diff: ~ password = "old" -> "new"
        arrow = _ARROW.match(text, quoted[1] + 1)
        if arrow:
            second = _read_quoted(text, arrow.start(1))
            if second:
                spans.append(second)
        return [(a, b) for a, b in spans if not is_placeholder(text[a:b])]

    line_end = text.find("\n", pos)
    line_end = len(text) if line_end < 0 else line_end
    segment = text[pos:line_end]
    first_word = _FIRST_WORD.match(segment).group(1)  # type: ignore[union-attr]  # always matches

    if ":" in sep and _BLOCK_SCALAR.fullmatch(first_word):
        block = _read_block_scalar(text, key_pos, pos)
        return [block] if block else []
    if is_placeholder(segment) or is_placeholder(first_word):
        return []

    if ":" in sep and sep != ":=":
        # YAML-style: the value runs to the end of the line, minus a " #" comment.
        comment = re.search(r"[ \t]#", segment)
        value = segment[: comment.start()] if comment else segment
    else:
        # = and CLI flags: the value stops at the first whitespace.
        value = first_word
    value = value.rstrip(" \t\r,;")
    if value.endswith(("}", "]")) and not any(c in value for c in "{["):
        value = value.rstrip("}]").rstrip(" \t,;")
    if not value or is_placeholder(value):
        return []
    return [(pos, pos + len(value))]


# --- Rules ---------------------------------------------------------------------------------

_SEP = r"[ \t]*(?P<sep>=>|:=|[:=])[ \t]*"
_KEY_VALUE = re.compile(
    r"(?:(?P<kq>[\"'])(?P<qkey>[^\"'\n]{1,80})(?P=kq)|(?<![\w.-])(?P<key>[A-Za-z_][\w.-]{0,80}))"
    + _SEP
)
_CLI_FLAG = re.compile(r"(?<![\w-])--?(?P<key>[A-Za-z][\w-]{0,60})(?P<sep>=|[ \t]+)(?=[^\s-])")
_ENV_PAIR = re.compile(
    r"(?P<nq>[\"']?)name(?P=nq)[ \t]*[:=][ \t]*(?P<vq>[\"']?)(?P<name>[A-Za-z_][\w.-]*)(?P=vq)"
    r"[ \t]*,?[ \t]*(?:\r?\n[ \t]*(?:-[ \t]*)?)?"
    r"(?P<kq>[\"']?)value(?P=kq)" + _SEP
)


class KeyValueRule:
    """`sensitive_key <sep> value` in any common format."""

    name = "keyvalue"

    def find(self, text: str) -> Iterator[Span]:
        for pattern in (_KEY_VALUE, _CLI_FLAG):
            # Keys found inside a value already emitted are skipped: they are masked anyway,
            # and re-reading the rest of the line for each of them would be quadratic
            # (ReDoS-like slowdown on "password: password: password: ...").
            covered_until = -1
            for match in pattern.finditer(text):
                if match.start() < covered_until:
                    continue
                key = match.group("qkey") if "qkey" in pattern.groupindex else None
                key = key or match.group("key")
                classified = classify_key(key)
                if classified is None:
                    continue
                entity_type, confidence = classified
                sep = match.group("sep").strip() or " "
                for start, end in read_values(text, match.end(), sep, match.start()):
                    value = text[start:end]
                    if entity_type is EntityType.PERSON and (is_generic(value) or value.isdigit()):
                        continue  # user: deployer, owner: platform, uid 1000: not a person
                    covered_until = max(covered_until, end)
                    yield span_for(self.name, start, end, entity_type, confidence)


class EnvPairRule:
    """`name: SENSITIVE_NAME` followed by `value: ...` (Kubernetes env, ECS, Terraform)."""

    name = "env-pair"

    def find(self, text: str) -> Iterator[Span]:
        for match in _ENV_PAIR.finditer(text):
            classified = classify_key(match.group("name"))
            if classified is None:
                continue
            entity_type, confidence = classified
            for start, end in read_values(text, match.end(), match.group("sep"), match.start()):
                yield span_for(self.name, start, end, entity_type, confidence)


def keyvalue_rules() -> list[Rule]:
    return [KeyValueRule(), EnvPairRule()]
