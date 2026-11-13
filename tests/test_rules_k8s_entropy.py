import math

from _fakes import BASE64, HEX, chars
from cloakops.detect.rules.entropy import EntropyRule, looks_random, shannon_entropy
from cloakops.detect.rules.k8s import KubernetesSecretRule
from rules_helpers import values

K8S = KubernetesSecretRule()


def test_yaml_secret_data_values_are_masked_keys_are_kept() -> None:
    text = (
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "data:\n"
        "  LOG_LEVEL: debug\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: app\n"
        "data:\n"
        "  DB_URL: cG9zdGdyZXM6Ly8=\n"
        "  config.json: eyJhIjoxfQ==\n"
        "stringData:\n"
        "  tls.key: |\n"
        "    MIIEvQIBADAN\n"
        "    BgkqhkiG9w0B\n"
        "type: Opaque\n"
    )
    assert values(text, K8S) == ["BgkqhkiG9w0B", "MIIEvQIBADAN", "cG9zdGdyZXM6Ly8=", "eyJhIjoxfQ=="]


def test_json_secret_from_kubectl() -> None:
    text = '{"apiVersion": "v1", "kind": "Secret", "data": {"password": "aHVudGVyMg=="}}'
    assert values(text, K8S) == ["aHVudGVyMg=="]


def test_shannon_entropy_values() -> None:
    assert shannon_entropy("aaaa") == 0.0
    assert math.isclose(shannon_entropy("abcd"), 2.0)  # 4 equiprobable symbols = 2 bits


def test_random_strings_look_random_words_do_not() -> None:
    assert looks_random(chars(BASE64, 40))
    assert looks_random(chars(HEX, 40))
    assert not looks_random("AbstractSingletonProxyFactoryBean2")
    assert not looks_random("/usr/local/lib/python3/site-packages")
    assert not looks_random("my-very-long-kubernetes-deployment-name")


def test_entropy_rule_skips_content_digests() -> None:
    digest = chars(HEX, 64)
    secret = chars(BASE64, 40, seed=1)
    text = f"image: nginx@sha256:{digest}\nkey {secret}\n"
    assert values(text, EntropyRule()) == [secret]
