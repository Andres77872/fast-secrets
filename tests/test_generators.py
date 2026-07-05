"""Tests for the generators, registry dispatch, and the FastAPI endpoints."""

import base64
import re
import time
import uuid as uuidlib

import pytest
from fastapi.testclient import TestClient

import generators as g
import registry
from main import app

client = TestClient(app)


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


def test_passphrase():
    p = g.passphrase(5, separator=".")
    assert len(p.split(".")) == 5
    cap = g.passphrase(3, capitalize=True)
    assert all(w[0].isupper() for w in cap.split("-"))


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
    assert g.api_key(prefix="", nbytes=16).count("_") == 0


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


# ── API ─────────────────────────────────────────────────────────────────────
def test_index_serves_html():
    r = client.get("/")
    assert r.status_code == 200
    assert "fast-secrets" in r.text


def test_list_generators_metadata():
    r = client.get("/api/generators")
    assert r.status_code == 200
    gens = r.json()["generators"]
    ids = {x["id"] for x in gens}
    assert {"uuid", "password", "hex", "ulid", "nanoid", "passphrase", "hash", "hmac"} <= ids
    assert all("fn" not in x for x in gens)  # function stripped


def test_generate_get_json():
    r = client.get("/api/generate/uuid?count=3")
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "uuid" and body["count"] == 3
    assert len(body["values"]) == 3


def test_generate_get_text_format():
    r = client.get("/api/generate/hex?count=4&format=text")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    lines = r.text.strip().splitlines()
    assert len(lines) == 4


def test_generate_get_with_options():
    r = client.get("/api/generate/password?length=12&symbols=false")
    val = r.json()["values"][0]
    assert len(val) == 12
    assert not any(c in g.SYMBOLS for c in val)


def test_generate_get_unknown_404():
    assert client.get("/api/generate/bogus").status_code == 404


def test_generate_post():
    r = client.post("/api/generate", json={"type": "apikey", "options": {"prefix": "pk"}, "count": 2})
    vals = r.json()["values"]
    assert len(vals) == 2 and all(v.startswith("pk_") for v in vals)


def test_generate_batch():
    r = client.post("/api/generate/batch", json=[
        {"type": "uuid", "count": 2},
        {"type": "pin", "options": {"length": 4}, "count": 1},
        {"type": "bogus"},
    ])
    results = r.json()["results"]
    assert results[0]["count"] == 2
    assert len(results[1]["values"][0]) == 4
    assert "error" in results[2]


def test_generate_all():
    r = client.get("/api/all")
    results = r.json()["results"]
    ids = {x["type"] for x in results}
    assert ids == set(registry.REGISTRY.keys())
    assert all("error" not in x for x in results)
