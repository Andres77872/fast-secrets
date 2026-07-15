"""Regression tests for correctness and input-hardening bugs found in the v2 review."""

import base64
import json

import pytest

from fast_secrets import generators as g


def _b64url_json(value) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_minimum_password_contains_every_enabled_class():
    for _ in range(100):
        value = g.password(length=4)
        assert any(ch.islower() for ch in value)
        assert any(ch.isupper() for ch in value)
        assert any(ch.isdigit() for ch in value)
        assert any(ch in g.SYMBOLS for ch in value)


def test_nanoid_deduplicates_and_rejects_degenerate_alphabets(monkeypatch):
    pools = []

    def choose(pool):
        pools.append(pool)
        return pool[0]

    monkeypatch.setattr(g.secrets, "choice", choose)
    assert g.nanoid(4, "AABB") == "AAAA"
    assert pools == ["AB"] * 4
    with pytest.raises(ValueError, match="two unique"):
        g.nanoid(21, "AAAA")


@pytest.mark.parametrize("payload", [None, [], "claims"])
def test_jwt_decode_rejects_non_object_claim_sets(payload):
    token = f"{_b64url_json({'alg': 'none'})}.{_b64url_json(payload)}."
    with pytest.raises(ValueError, match="JSON objects"):
        g.jwt_decode(token)


def test_jwt_decode_handles_out_of_range_numeric_dates():
    token = f"{_b64url_json({'alg': 'none'})}.{_b64url_json({'exp': 10**100})}."
    decoded = json.loads(g.jwt_decode(token))
    assert "outside the supported timestamp range" in decoded["warnings"][0]
