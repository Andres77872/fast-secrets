"""Standards vectors and boundary tests for the standalone feature engines."""

import base64
import concurrent.futures
import json
import uuid

import pytest

from fast_secrets import tool_features as f


def b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=")


def test_password_policy_meets_independent_constraints():
    result = f.password_policy(
        length=40,
        min_lowercase=3,
        min_uppercase=4,
        min_digits=5,
        min_symbols=6,
        symbols="!%",
        required="xyZ",
        excluded="0OIl1",
        exclude_ambiguous=True,
    )
    password = result["password"]
    assert len(password) == 40
    assert sum(char.islower() for char in password) >= 3
    assert sum(char.isupper() for char in password) >= 4
    assert sum(char.isdigit() for char in password) >= 5
    assert sum(char in "!%" for char in password) >= 6
    assert all(char in password for char in "xyZ")
    assert not set(password) & set("0OIl1")
    assert result["entropy_bits_lower_bound"] > 0


def test_password_policy_rejects_impossible_or_conflicting_policy():
    with pytest.raises(ValueError, match="exceed"):
        f.password_policy(length=3, min_lowercase=2, min_uppercase=2, min_digits=0, min_symbols=0)
    with pytest.raises(ValueError, match="also excluded"):
        f.password_policy(required="x", excluded="x")
    with pytest.raises(ValueError, match="symbols"):
        f.password_policy(min_symbols=1, symbols="")


def test_base32_rfc4648_vectors_and_secret_generation():
    assert f.base32_encode(text="foo")["value"] == "MZXW6"
    assert f.base32_encode(text="foo", padding=True)["value"] == "MZXW6==="
    assert f.base32_decode(value="mzxw6")["value"] == "foo"
    secret = f.base32_secret(nbytes=20)
    assert len(base64.b32decode(secret["secret"])) == 20
    with pytest.raises(ValueError):
        f.base32_decode(value="invalid-1")


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_jwt_round_trip_all_supported_algorithms(algorithm):
    encoded = f.jwt_encode(
        claims={"sub": "alice", "iss": "issuer", "aud": ["api", "web"], "exp": 2000},
        secret="correct horse",
        algorithm=algorithm,
    )
    result = f.jwt_verify(
        token=encoded["token"],
        secret="correct horse",
        allowed_algorithms=[algorithm],
        issuer="issuer",
        audience="api",
        now=1000,
    )
    assert result["verified"] is True
    assert result["status"] == {"syntax": "valid", "signature": "valid", "claims": "valid"}
    assert result["claims"]["sub"] == "alice"


def test_jwt_reports_signature_and_claim_status_separately():
    token = f.jwt_encode(claims={"exp": 10}, secret="right")["token"]
    result = f.jwt_verify(token=token, secret="wrong", now=20)
    assert result["status"]["syntax"] == "valid"
    assert result["status"]["signature"] == "invalid"
    assert result["status"]["claims"] == "invalid"
    assert result["verified"] is False


def test_jwt_none_is_decode_only_and_never_verified():
    head = f._b64url_encode(json.dumps({"alg": "none"}).encode())
    body = f._b64url_encode(json.dumps({"sub": "guest"}).encode())
    decoded = f.jwt_decode(token=f"{head}.{body}.")
    assert decoded["status"]["syntax"] == "valid"
    assert decoded["status"]["signature"] == "unsecured"
    assert any("never verified" in warning for warning in decoded["warnings"])
    with pytest.raises(ValueError, match="decode-only"):
        f.jwt_encode(claims={}, algorithm="none")


def test_jwt_malformed_and_scalar_payload_are_syntax_errors():
    assert f.jwt_decode(token="not.a.jwt.extra")["status"]["syntax"] == "invalid"
    head = f._b64url_encode(b'{"alg":"none"}')
    scalar = f._b64url_encode(b"123")
    result = f.jwt_decode(token=f"{head}.{scalar}.")
    assert result["status"]["syntax"] == "invalid"


def test_hotp_rfc4226_vectors():
    secret = b32(b"12345678901234567890")
    expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [f.hotp(secret=secret, counter=index)["code"] for index in range(10)] == expected


@pytest.mark.parametrize(
    ("algorithm", "raw", "expected"),
    [
        ("SHA1", b"12345678901234567890", "94287082"),
        ("SHA256", b"12345678901234567890123456789012", "46119246"),
        ("SHA512", b"1234567890123456789012345678901234567890123456789012345678901234", "90693936"),
    ],
)
def test_totp_rfc6238_time_59_vectors(algorithm, raw, expected):
    result = f.totp(secret=b32(raw), timestamp=59, period=30, digits=8, algorithm=algorithm)
    assert result["code"] == expected


def test_otp_verification_windows_and_otpauth_round_trip():
    secret = b32(b"12345678901234567890")
    code = f.totp(secret=secret, timestamp=59)["code"]
    assert f.totp_verify(secret=secret, code=code, timestamp=89, window=1)["matched_offset"] == -1
    hotp_code = f.hotp(secret=secret, counter=3)["code"]
    assert f.hotp_verify(secret=secret, code=hotp_code, counter=1, look_ahead=3)["next_counter"] == 4
    built = f.otpauth_build(
        otp_type="totp", secret=secret.lower(), account="alice@example.com", issuer="Example", algorithm="SHA256", digits=8, period=45
    )
    parsed = f.otpauth_parse(uri=built["uri"])
    assert parsed == {
        "type": "totp",
        "secret": secret,
        "account": "alice@example.com",
        "issuer": "Example",
        "algorithm": "SHA256",
        "digits": 8,
        "period": 45,
        "warnings": [],
    }


def test_pkce_rfc7636_vector_and_random_security_tokens():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert f.pkce_challenge(verifier=verifier)["code_challenge"] == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    generated = f.pkce_generate(length=128)
    assert len(generated["code_verifier"]) == 128
    assert f.pkce_challenge(verifier=generated["code_verifier"])["code_challenge"] == generated["code_challenge"]
    assert f.oauth_state(nbytes=16)["bits"] == 128
    assert f.oidc_nonce(nbytes=16)["purpose"] == "oidc_nonce"
    assert f.csp_nonce(nbytes=16)["directive"].startswith("'nonce-")


def test_webhook_hmac_known_vector_and_verification():
    result = f.webhook_hmac(payload="The quick brown fox jumps over the lazy dog", secret="key")
    assert result["signature"] == "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    assert f.webhook_verify(payload="The quick brown fox jumps over the lazy dog", secret="key", signature=result["signature"])["valid"]
    assert not f.webhook_verify(payload="changed", secret="key", signature=result["signature"])["valid"]


def test_dotenv_parser_is_literal_and_reports_duplicates():
    parsed = f.parse_dotenv(text='export A="hello\\nworld"\nB=${A}\nA=again\nBAD LINE\n')
    assert parsed["entries"][0]["value"] == "hello\nworld"
    assert parsed["entries"][1]["value"] == "${A}"
    assert any("literal" in warning["message"] for warning in parsed["warnings"])
    assert {error["line"] for error in parsed["errors"]} == {3, 4}
    assert parsed["valid"] is False


def test_dotenv_transformations_and_comparison():
    text = "B=two words\nEMPTY=\nA=1\n"
    assert f.dotenv_tool(text=text, action="sort")["text"] == 'A=1\nB="two words"\nEMPTY=""\n'
    assert f.dotenv_tool(text=text, action="redact")["text"] == "B=********\nEMPTY=\nA=********\n"
    assert f.dotenv_tool(text=text, action="example")["text"] == "B=\nEMPTY=\nA=\n"
    compared = f.dotenv_tool(text=text, other="A=x\nC=y", action="compare")
    assert compared["only_in_first"] == ["B", "EMPTY"]
    assert compared["only_in_second"] == ["C"]


def test_timestamp_epoch_and_iana_zone_conversion():
    result = f.timestamp_convert(value="1704067200000", output_timezones=["UTC", "America/Mexico_City"])
    assert result["detected_format"] == "epoch_milliseconds"
    assert result["utc"] == "2024-01-01T00:00:00Z"
    assert result["outputs"][1]["utc_offset_seconds"] == -21600


def test_timestamp_dst_ambiguity_and_gap():
    early = f.timestamp_convert(
        value="2024-11-03T01:30:00", input_timezone="America/New_York", output_timezones=["UTC"], fold=0
    )
    late = f.timestamp_convert(
        value="2024-11-03T01:30:00", input_timezone="America/New_York", output_timezones=["UTC"], fold=1
    )
    assert late["epoch_seconds"] - early["epoch_seconds"] == 3600
    assert "ambiguous" in early["warnings"][0]
    with pytest.raises(ValueError, match="does not exist"):
        f.timestamp_convert(
            value="2024-03-10T02:30:00", input_timezone="America/New_York", output_timezones=["UTC"]
        )


def test_regex_matches_groups_flags_and_replacement():
    result = f.regex_test(
        pattern=r"(?P<word>[a-z]+)-(\d+)", text="abc-12 DEF-3", flags="i", replacement=r"\g<word>"
    )
    assert result["valid"] and not result["timed_out"]
    assert result["matches"][0]["groups"] == ["abc", "12"]
    assert result["matches"][1]["named_groups"] == {"word": "DEF"}
    assert result["replacement_preview"] == "abc DEF"
    invalid = f.regex_test(pattern="(", text="x")
    assert invalid["valid"] is False and isinstance(invalid["error"]["position"], int)


def test_regex_catastrophic_pattern_hard_times_out_in_worker_thread():
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            f.regex_test,
            pattern=r"(?:a|aa)+$",
            text="a" * 50_000 + "!",
            timeout_ms=1,
        )
        result = future.result(timeout=1)
    assert result["timed_out"] is True
    assert result["matches"] == []


def test_jsonpath_fallback_child_union_slice_and_descendant():
    registered = f._JSONPATH_ENGINE
    f.register_jsonpath_engine(None)
    try:
        document = {"store": {"book": [{"title": "A"}, {"title": "B"}, {"title": "C"}]}, "title": "Root"}
        assert f.jsonpath_query(document=document, query="$.store.book[0,2].title")["values"] == ["A", "C"]
        assert f.jsonpath_query(document=document, query="$.store.book[0:2].title")["values"] == ["A", "B"]
        result = f.jsonpath_query(document=document, query="$..title")
        assert result["values"] == ["Root", "A", "B", "C"]
        with pytest.raises(ValueError, match="registered"):
            f.jsonpath_query(document=document, query="$.store.book[?(@.price < 10)]")
    finally:
        f.register_jsonpath_engine(registered)


def test_jsonpath_registered_engine_hook():
    f.register_jsonpath_engine(lambda document, query, limit: [document["x"], query, limit])
    try:
        result = f.jsonpath_query(document={"x": 3}, query="$[?true]", max_results=2)
        assert result["values"] == [3, "$[?true]"]
        assert result["truncated"] is True
    finally:
        f.register_jsonpath_engine(None)


def test_checksum_known_vectors_and_weak_hash_warning():
    result = f.file_checksum(data="abc", algorithms=["sha256", "md5"])
    assert result["digests"]["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert result["digests"]["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert result["warnings"]


def test_identifier_inspection_for_uuid7_ulid_and_objectid():
    milliseconds = 1_700_000_000_000
    uuid7 = uuid.UUID(int=(milliseconds << 80) | (7 << 76) | (2 << 62))
    inspected = f.inspect_identifier(value=str(uuid7))
    assert inspected["version"] == 7
    assert inspected["timestamp"]["epoch_milliseconds"] == milliseconds
    ulid = f.inspect_identifier(value="00000000000000000000000000")
    assert ulid["type"] == "ulid" and ulid["timestamp"]["epoch_milliseconds"] == 0
    objectid = f.inspect_identifier(value="507f1f77bcf86cd799439011")
    assert objectid["type"] == "objectid" and objectid["counter"] == 0x439011


def test_user_agent_client_hints_bundle():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"
    result = f.user_agent_client_hints(user_agent=ua)
    assert result["platform"] == "Windows" and result["mobile"] is False
    assert '"Microsoft Edge";v="137"' in result["headers"]["sec-ch-ua"]
    assert result["headers"]["sec-ch-ua-mobile"] == "?0"


def test_feature_handler_contract_count_and_json_serialisability():
    random_result = f.FEATURE_HANDLERS["base32_secret"]({}, {"nbytes": 10}, 3)
    assert random_result["kind"] == "list" and len(random_result["data"]) == 3
    deterministic = f.run_feature("checksum", {"data": "x"}, {"algorithms": ["sha256"]}, count=8)
    assert deterministic["kind"] == "record" and deterministic["meta"]["count"] == 1
    assert "ignored" in deterministic["warnings"][0]
    json.dumps(random_result)
    json.dumps(deterministic)
    with pytest.raises(KeyError):
        f.run_feature("missing")
    with pytest.raises(ValueError, match="repeat"):
        f.FEATURE_HANDLERS["base32_encode"]({"text": "x"}, {"text": "y"}, 1)
