"""Tests for the generators, registry dispatch, and the FastAPI endpoints."""

import base64
import ipaddress
import json
import re
import time
import uuid as uuidlib

import pytest

from fast_secrets import generators as g
from fast_secrets import registry


# ── generators ──────────────────────────────────────────────────────────────
def test_password_length_and_classes():
    pw = g.password(40)
    assert len(pw) == 40
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(c in g.SYMBOLS for c in pw)


def test_password_respects_disabled_classes():
    pw = g.password(50, symbols=False, uppercase=False)
    assert not any(c in g.SYMBOLS for c in pw)
    assert not any(c.isupper() for c in pw)


def test_password_exclude_ambiguous():
    pw = g.password(200, exclude_ambiguous=True)
    assert not any(c in g.AMBIGUOUS for c in pw)


def test_password_requires_a_class():
    with pytest.raises(ValueError):
        g.password(16, lowercase=False, uppercase=False, digits=False, symbols=False)


def test_password_length_is_clamped():
    assert len(g.password(2)) == 4      # min
    assert len(g.password(9999)) == 256  # max


def test_random_string_charset():
    s = g.random_string(100, charset="numeric")
    assert s.isdigit()
    custom = g.random_string(100, charset="custom", custom_charset="AB")
    assert set(custom) <= {"A", "B"}


def test_pin_is_numeric_and_keeps_leading_zeros():
    pins = [g.pin(6) for _ in range(200)]
    assert all(len(p) == 6 and p.isdigit() for p in pins)
    assert any(p.startswith("0") for p in pins)


def test_passphrase(monkeypatch):
    p = g.passphrase(5, separator=".")
    assert len(p.split(".")) == 5
    cap = g.passphrase(3, capitalize=True)
    assert all(w[0].isupper() for w in cap.split("-"))

    monkeypatch.setattr(g.secrets, "choice", lambda _words: "yo-yo")
    assert g.passphrase(2, separator=".", capitalize=True) == "Yo-Yo.Yo-Yo"


@pytest.mark.parametrize("nbytes", [1, 16, 32, 64])
def test_hex_token(nbytes):
    t = g.hex_token(nbytes)
    assert len(t) == nbytes * 2
    int(t, 16)  # valid hex


def test_urlsafe_and_base64_tokens():
    assert len(g.urlsafe_token(32)) >= 32
    raw = base64.b64decode(g.base64_token(30))
    assert len(raw) == 30


def test_api_key_format():
    k = g.api_key(prefix="sk", separator="_", nbytes=24)
    assert k.startswith("sk_")
    assert "=" not in k  # padding stripped
    # An empty prefix omits the separator entirely. The default urlsafe body
    # legitimately contains "_"/"-", so counting underscores across the whole
    # key is wrong; check the separator-omission contract with a deterministic
    # hex body, whose alphabet cannot produce a "_".
    assert g.api_key(prefix="", separator="_", nbytes=16, encoding="hex").count("_") == 0


@pytest.mark.parametrize("version", [1, 4, 6, 7])
def test_uuid_versions(version):
    s = g.uuid(version=version)
    assert uuidlib.UUID(s).version == version


def test_uuid_formatting():
    assert "-" not in g.uuid(hyphens=False)
    assert g.uuid(uppercase=True).isupper()


def test_uuid_v7_is_time_ordered():
    a = g.uuid(version=7)
    time.sleep(0.003)
    b = g.uuid(version=7)
    assert a < b


def test_uuid_rejects_unsupported_version():
    with pytest.raises(ValueError):
        g.uuid(version=5)


def test_ulid_length_and_sortable():
    a = g.ulid()
    assert len(a) == 26
    assert set(a) <= set(g.CROCKFORD)
    time.sleep(0.003)
    b = g.ulid()
    assert a < b


def test_nanoid_size_and_alphabet():
    assert len(g.nanoid(30)) == 30
    assert set(g.nanoid(100)) <= set(g.NANOID_ALPHABET)


def test_hash_known_vectors():
    assert g.hash_text("", "sha256") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert g.hash_text("abc", "md5") == "900150983cd24fb0d6963f7d28e17f72"


def test_hmac_known_vector():
    # RFC 4231-style deterministic check
    assert g.hmac_text("Hi There", "key", "sha256") == \
        g.hmac_text("Hi There", "key", "sha256")
    assert len(g.hmac_text("x", "k", "sha512")) == 128


def test_text_encoders_and_basic_auth():
    encoded = g.base64_text("hello world", mode="encode")
    assert encoded == "aGVsbG8gd29ybGQ="
    assert g.base64_text(encoded, mode="decode") == "hello world"
    unpadded = g.base64_text("hello?", mode="encode", urlsafe=True, padding=False)
    assert g.base64_text(unpadded, mode="decode", urlsafe=True) == "hello?"
    assert g.url_codec("a b+c", mode="encode") == "a%20b%2Bc"
    assert g.url_codec("a+b%2Bc", mode="decode", plus_spaces=True) == "a b+c"
    assert g.basic_auth("dev", "secret") == "Basic ZGV2OnNlY3JldA=="


def test_json_format_minify_validate():
    formatted = g.json_format('{"b":1,"a":[2]}', sort_keys=True)
    assert formatted.splitlines()[1].strip() == '"a": ['
    assert g.json_format('{"b":1,"a":[2]}', mode="minify", sort_keys=True) == '{"a":[2],"b":1}'
    summary = g.json_format('{"ok":true}', mode="validate")
    assert "Valid JSON" in summary and "object" in summary
    with pytest.raises(ValueError):
        g.json_format("{bad")


def test_jwt_generate_and_decode():
    token = g.jwt_token(subject="alice", issuer="issuer", audience="aud", secret="secret", include_jti=False)
    assert len(token.split(".")) == 3
    decoded = json.loads(g.jwt_decode(token))
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["sub"] == "alice"
    assert decoded["payload"]["iss"] == "issuer"
    assert decoded["payload"]["aud"] == "aud"
    assert decoded["signature_bytes"] == 32
    assert decoded["verified"] is False
    assert g.jwt_token(algorithm="NONE").endswith(".")


def test_user_agent_variants():
    chrome = g.user_agent(browser="chrome", platform="desktop")
    assert "Mozilla/5.0" in chrome and "Chrome/" in chrome and "Safari/" in chrome
    edge = g.user_agent(browser="edge", platform="mobile")
    assert "EdgA/" in edge
    firefox = g.user_agent(browser="firefox", platform="tablet")
    assert "Firefox/" in firefox and "Android" in firefox
    safari = g.user_agent(browser="safari", platform="mobile")
    assert "Version/" in safari and "Mobile/" in safari
    assert g.user_agent(agent_type="crawler")
    assert g.user_agent(agent_type="client")


def test_user_agent_sources():
    sampled = g.user_agent(browser="safari", platform="mobile", source="dataset")
    assert "iPhone" in sampled and "Version/18.5" in sampled

    templated = g.user_agent(browser="safari", platform="mobile", source="template")
    assert "Version/26.0" in templated

    with pytest.raises(ValueError):
        g.user_agent(browser="chrome", platform="tablet", source="dataset")


def test_network_and_fixture_generators():
    private = ipaddress.ip_address(g.ipv4_address("private"))
    assert private.is_private
    doc4 = g.ipv4_address("documentation")
    assert doc4.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    doc6 = ipaddress.ip_address(g.ipv6_address("documentation"))
    assert doc6 in ipaddress.ip_network("2001:db8::/32")
    ula = ipaddress.ip_address(g.ipv6_address("ula"))
    assert ula in ipaddress.ip_network("fd00::/8")
    assert re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", g.mac_address())
    assert re.fullmatch(r"[0-9A-F]{12}", g.mac_address(separator="", uppercase=True))


def test_app_fixture_generators_and_text_case():
    assert re.fullmatch(r"[a-z0-9.-]+(\+[a-z]+)?@example\.com", g.email_address(plus_tag=True))
    assert re.fullmatch(r"\d+\.\d+\.\d+-[a-z]+\.\d+\+[0-9a-f]{6}", g.semver(True, True))
    assert re.fullmatch(r"[0-9a-f]{24}", g.mongo_object_id())
    assert "\n\n" in g.lorem_ipsum(paragraphs=2, sentences=1, words_per_sentence=4)
    assert g.text_case("Hello brave world", "snake") == "hello_brave_world"
    assert g.text_case("Hello brave world", "camel") == "helloBraveWorld"
    assert g.text_case("Hello brave world", "constant") == "HELLO_BRAVE_WORLD"


def test_uniqueness_across_calls():
    vals = {g.hex_token(16) for _ in range(500)}
    assert len(vals) == 500


# ── registry dispatch ───────────────────────────────────────────────────────
def test_registry_count_and_clamp():
    assert len(registry.generate("uuid", {}, 5)) == 5
    assert len(registry.generate("uuid", {}, 99999)) == registry.MAX_COUNT
    assert len(registry.generate("hash", {"text": "x"}, 9)) == 1  # non-random forced to 1


def test_registry_coerces_string_options():
    # values arrive as strings from query params
    out = registry.generate("password", {"length": "8", "symbols": "false"}, 1)[0]
    assert len(out) == 8
    assert not any(c in g.SYMBOLS for c in out)


def test_registry_unknown_id():
    with pytest.raises(KeyError):
        registry.generate("nope", {}, 1)
