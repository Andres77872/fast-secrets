"""Security and resource-boundary tests for the standards feature engines."""

from __future__ import annotations

import base64
import json
import math
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from fast_secrets import generators
from fast_secrets import tool_features as f


def compact_token(header: object, claims: object, signature: bytes = b"") -> str:
    encode = lambda value: f._b64url_encode(  # noqa: E731 - compact token fixture
        json.dumps(value, separators=(",", ":")).encode()
    )
    return f"{encode(header)}.{encode(claims)}.{f._b64url_encode(signature)}"


@contextmanager
def builtin_jsonpath() -> Iterator[None]:
    registered = f._JSONPATH_ENGINE
    f.register_jsonpath_engine(None)
    try:
        yield
    finally:
        f.register_jsonpath_engine(registered)


@pytest.mark.parametrize("value", [True, object(), "not-an-integer"])
def test_integer_boundary_rejects_boolean_and_non_numeric_values(value):
    with pytest.raises(ValueError, match="integer"):
        f._require_int("amount", value, 1, 3)


def test_shared_input_boundaries_reject_oversize_and_non_json_values():
    with pytest.raises(ValueError, match="between"):
        f._require_int("amount", 4, 1, 3)
    with pytest.raises(ValueError, match="string"):
        f._require_text("text", b"bytes")
    with pytest.raises(ValueError, match="byte limit"):
        f._require_text("text", "éé", maximum=3)
    with pytest.raises(ValueError, match="object"):
        f._require_mapping("record", [])
    with pytest.raises(ValueError, match="serialisable"):
        f._json_safe({"bad": {1, 2}})
    with pytest.raises(ValueError, match="serialisable"):
        f._json_safe({"bad": math.nan})
    with pytest.raises(ValueError, match="serialisable"):
        f._json_safe("too large", maximum=3)

    original = {"items": [1]}
    detached = f._json_safe(original)
    original["items"].append(2)
    assert detached == {"items": [1]}


def test_base64url_and_json_segment_validation_distinguishes_syntax_errors():
    with pytest.raises(ValueError, match="unpadded"):
        f._b64url_decode("abc=")
    with pytest.raises(ValueError, match="length"):
        f._b64url_decode("A")
    with pytest.raises(ValueError, match="UTF-8 JSON object"):
        f._json_segment(f._b64url_encode(b"\xff"), name="segment")
    with pytest.raises(ValueError, match="UTF-8 JSON object"):
        f._json_segment(f._b64url_encode(b"not-json"), name="segment")
    with pytest.raises(ValueError, match="JSON object"):
        f._json_segment(f._b64url_encode(b"[]"), name="segment")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"symbols": "!!"}, "duplicate"),
        ({"symbols": "! "}, "whitespace"),
        ({"symbols": "!a"}, "overlap"),
        (
            {
                "length": 1,
                "min_lowercase": 0,
                "min_uppercase": 0,
                "min_digits": 0,
                "min_symbols": 0,
                "symbols": "",
                "excluded": generators.LOWERCASE + generators.UPPERCASE + generators.DIGITS,
            },
            "no available",
        ),
    ],
)
def test_password_policy_rejects_ambiguous_character_policies(kwargs, message):
    with pytest.raises(ValueError, match=message):
        f.password_policy(**kwargs)


def test_short_password_policy_surfaces_entropy_warning():
    result = f.password_policy(
        length=4,
        min_lowercase=1,
        min_uppercase=1,
        min_digits=1,
        min_symbols=1,
        symbols="!",
    )
    assert len(result["password"]) == 4
    assert result["warnings"] == ["Estimated entropy is below 60 bits"]


def test_base32_empty_non_utf8_and_length_boundaries():
    assert f.base32_decode(value="  ")["value"] == ""
    invalid_utf8 = base64.b32encode(b"\xff").decode("ascii")
    with pytest.raises(ValueError, match="UTF-8"):
        f.base32_decode(value=invalid_utf8)
    with pytest.raises(ValueError, match="length"):
        f.base32_decode(value="A")
    padded = f.base32_secret(nbytes=11, padding=True)
    assert padded["secret"].endswith("=")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"claims": [], "secret": "x"}, "object"),
        ({"claims": {"value": math.nan}, "secret": "x"}, "serialisable"),
        ({"claims": {}, "secret": "x", "algorithm": "RS256"}, "HS256"),
        ({"claims": {}, "secret": ""}, "empty"),
        (
            {"claims": {}, "secret": "x", "algorithm": "HS256", "header": {"alg": "HS512"}},
            "conflicts",
        ),
    ],
)
def test_jwt_signing_rejects_unsafe_headers_claims_and_algorithms(kwargs, message):
    with pytest.raises(ValueError, match=message):
        f.jwt_encode(**kwargs)


def test_jwt_claim_validation_reports_each_registered_claim_failure():
    token = f.jwt_encode(
        claims={
            "exp": True,
            "nbf": 2_000,
            "iat": 2_001,
            "iss": "wrong",
            "aud": "other",
        },
        secret="key",
    )["token"]
    result = f.jwt_decode(
        token=token,
        secret="key",
        issuer="expected",
        audience="api",
        now=1_000,
    )
    failures = {(error.get("claim"), error["message"]) for error in result["errors"]}
    assert ("exp", "must be a finite NumericDate") in failures
    assert ("nbf", "token is not active yet") in failures
    assert ("iat", "issued-at time is in the future") in failures
    assert any(claim == "iss" for claim, _ in failures)
    assert any(claim == "aud" for claim, _ in failures)

    extreme = f.jwt_decode(
        token=f.jwt_encode(claims={"exp": 253_402_300_800}, secret="key")["token"],
        now=0,
    )
    assert any("outside" in error["message"] for error in extreme["errors"])


def test_jwt_signature_status_handles_missing_alg_none_signature_and_allow_list():
    missing_alg = f.jwt_decode(token=compact_token({}, {}), now=0)
    assert missing_alg["status"]["signature"] == "invalid"

    unsecured_with_signature = f.jwt_decode(
        token=compact_token({"alg": "none"}, {}, b"unexpected"), now=0
    )
    assert unsecured_with_signature["status"]["signature"] == "invalid"

    unsupported = f.jwt_decode(
        token=compact_token({"alg": "RS256"}, {}), allowed_algorithms=["HS256"], now=0
    )
    assert unsupported["status"]["signature"] == "unsupported"

    unchecked = f.jwt_decode(
        token=f.jwt_encode(claims={}, secret="key")["token"], now=0
    )
    assert unchecked["status"]["signature"] == "not_checked"
    assert any("no secret" in warning for warning in unchecked["warnings"])


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"allowed_algorithms": "HS256"}, "array"),
        ({"allowed_algorithms": ["HS256"] * 4}, "too many"),
        ({"allowed_algorithms": ["RS256"]}, "only"),
        ({"secret": ""}, "empty"),
        ({"now": True}, "finite number"),
        ({"now": "tomorrow"}, "finite number"),
        ({"now": math.inf}, "finite"),
    ],
)
def test_jwt_decode_validates_verification_configuration(kwargs, message):
    token = f.jwt_encode(claims={}, secret="key")["token"]
    with pytest.raises(ValueError, match=message):
        f.jwt_decode(token=token, **kwargs)
    with pytest.raises(ValueError, match="required"):
        f.jwt_verify(token=token, secret=None)


def test_otp_rejects_invalid_codes_algorithms_times_and_oversize_secrets():
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    with pytest.raises(ValueError, match="empty"):
        f.hotp(secret="", counter=0)
    with pytest.raises(ValueError, match="algorithm"):
        f.hotp(secret=secret, counter=0, algorithm="MD5")
    with pytest.raises(ValueError, match="exactly"):
        f.hotp_verify(secret=secret, code="12ab56", counter=0)
    with pytest.raises(ValueError, match="exactly"):
        f.totp_verify(secret=secret, code="123", timestamp=0)
    for invalid in (-1, math.inf, 253_402_300_800):
        with pytest.raises(ValueError, match="supported range"):
            f.totp(secret=secret, timestamp=invalid)
        with pytest.raises(ValueError, match="supported range"):
            f.totp_verify(secret=secret, code="000000", timestamp=invalid)

    oversize = base64.b32encode(b"x" * (f.MAX_SECRET_BYTES + 1)).decode("ascii")
    with pytest.raises(ValueError, match="byte limit"):
        f.hotp(secret=oversize, counter=0)


def test_otp_verification_false_paths_and_negative_window_candidate():
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    assert f.hotp_verify(
        secret=secret, code="000000", counter=(1 << 64) - 1, look_ahead=100
    ) == {
        "valid": False,
        "matched_counter": None,
        "next_counter": None,
        "warnings": [],
    }
    result = f.totp_verify(
        secret=secret, code="000000", timestamp=0, period=30, window=1
    )
    assert result["valid"] is False and result["matched_offset"] is None


def test_otpauth_hotp_round_trip_and_nonfatal_metadata_warnings():
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    built = f.otpauth_build(
        otp_type="hotp", secret=secret, account="alice@example.com", counter=7
    )
    assert "counter=7" in built["uri"] and "issuer=" not in built["uri"]
    parsed = f.otpauth_parse(uri=built["uri"] + "&vendor=local")
    assert parsed["counter"] == 7
    assert parsed["issuer"] == ""
    assert parsed["warnings"] == ["Ignored unknown parameters: vendor"]

    mismatched = f.otpauth_parse(
        uri=f"otpauth://totp/Label:alice?secret={secret}&issuer=Query"
    )
    assert any("differs" in warning for warning in mismatched["warnings"])


@pytest.mark.parametrize(
    ("uri", "message"),
    [
        ("https://example.com", "otpauth"),
        ("otpauth://totp/account?secret=JBSWY3DP#fragment", "fragment"),
        ("otpauth://totp/?secret=JBSWY3DP", "label"),
        ("otpauth://totp/account?secret=JBSWY3DP&secret=JBSWY3DP", "repeats"),
        ("otpauth://totp/account?issuer=Example", "missing secret"),
        ("otpauth://totp/account?secret=JBSWY3DP&algorithm=MD5", "algorithm"),
        ("otpauth://hotp/account?secret=JBSWY3DP", "missing counter"),
    ],
)
def test_otpauth_parser_rejects_ambiguous_or_incomplete_uris(uri, message):
    with pytest.raises(ValueError, match=message):
        f.otpauth_parse(uri=uri)


def test_pkce_nonce_and_webhook_configuration_boundaries():
    with pytest.raises(ValueError, match="43-128"):
        f.pkce_challenge(verifier="short")
    with pytest.raises(ValueError, match="purpose"):
        f.random_nonce(purpose="session")

    with pytest.raises(ValueError, match="empty"):
        f.webhook_hmac(payload="x", secret="")
    with pytest.raises(ValueError, match="algorithm"):
        f.webhook_hmac(payload="x", secret="key", algorithm="md5")
    with pytest.raises(ValueError, match="encoding"):
        f.webhook_hmac(payload="x", secret="key", encoding="raw")

    for encoding in ("base64", "base64url"):
        signed = f.webhook_hmac(
            payload="payload", secret="key", encoding=encoding, prefix=False
        )
        assert f.webhook_verify(
            payload="payload",
            secret="key",
            signature=signed["signature"],
            encoding=encoding,
        )["valid"]


def test_dotenv_quote_errors_comments_and_parse_action():
    parsed = f.parse_dotenv(
        text=(
            "# ignored\n"
            "export OK=value # comment\n"
            "HASH=https://example.test/#anchor\n"
            "1BAD=x\n"
            "MISSING\n"
            "UNCLOSED='value\n"
            'TAIL="value" extra\n'
        )
    )
    assert parsed["entries"][0]["exported"] is True
    assert parsed["entries"][0]["value"] == "value"
    assert parsed["entries"][1]["value"].endswith("#anchor")
    assert {error["line"] for error in parsed["errors"]} == {4, 5, 6, 7}

    inspected = f.dotenv_tool(text="A=1\n", action="parse")
    assert inspected["entries"][0]["key"] == "A"
    with pytest.raises(ValueError, match="action"):
        f.dotenv_tool(text="", action="execute")
    for mask in ("", "bad\nmask"):
        with pytest.raises(ValueError, match="mask"):
            f.dotenv_tool(text="A=secret", action="redact", mask=mask)
    with pytest.raises(ValueError, match="trailing escape"):
        f._dotenv_double_quoted("value\\", 1)


def test_timestamp_rejects_invalid_formats_values_and_timezone_collections():
    with pytest.raises(ValueError, match="input_format"):
        f.timestamp_convert(value=0, input_format="unix")
    with pytest.raises(ValueError, match="ISO-8601"):
        f.timestamp_convert(value="not-a-date", input_format="iso8601")
    with pytest.raises(ValueError, match="numeric"):
        f.timestamp_convert(value=True, input_format="epoch_seconds")
    with pytest.raises(ValueError, match="numeric"):
        f.timestamp_convert(value="abc", input_format="epoch_seconds")
    with pytest.raises(ValueError, match="datetime range"):
        f.timestamp_convert(value=math.inf, input_format="epoch_seconds")
    with pytest.raises(ValueError, match="array"):
        f.timestamp_convert(value=0, output_timezones="UTC")
    for zones in ([], ["UTC"] * 33):
        with pytest.raises(ValueError, match="between 1 and 32"):
            f.timestamp_convert(value=0, output_timezones=zones)
    with pytest.raises(ValueError, match="unknown IANA"):
        f.timestamp_convert(value=0, output_timezones=["Etc/Definitely-Missing"])

    aware = f.timestamp_convert(value="2024-01-01T00:00:00+02:00")
    assert aware["detected_format"] == "iso8601"
    assert aware["utc"] == "2023-12-31T22:00:00Z"
    seconds = f.timestamp_convert(value=1_700_000_000)
    assert seconds["detected_format"] == "epoch_seconds"


def test_regex_rejects_flags_and_nul_and_reports_truncation_and_replace_errors():
    with pytest.raises(ValueError, match="flags"):
        f.regex_test(pattern="x", text="x", flags="ii")
    with pytest.raises(ValueError, match="NUL"):
        f.regex_test(pattern="x\0", text="x")

    limited = f.regex_test(pattern="x", text="xxx", max_matches=1)
    assert limited["truncated"] is True
    assert limited["match_count"] == 1
    assert any("limited" in warning for warning in limited["warnings"])

    bad_replacement = f.regex_test(
        pattern="(?P<known>x)", text="x", replacement=r"\g<999>"
    )
    assert bad_replacement["valid"] is True
    assert "replacement error" in bad_replacement["error"]["message"]


@pytest.mark.parametrize(
    "query",
    [
        "items[0]",
        "$.",
        "$..",
        "$[",
        "$[]",
        "$[0:2:0]",
        "$[0:a]",
        "$[unknown]",
        "$!bad",
        "$['unterminated]",
    ],
)
def test_builtin_jsonpath_rejects_malformed_or_unsupported_queries(query):
    with builtin_jsonpath(), pytest.raises(ValueError):
        f.jsonpath_query(document={"items": [1, 2]}, query=query)


def test_builtin_jsonpath_wildcards_negative_indices_and_result_budget():
    document = {"items": ["zero", "one", "two"], "other": ["three"]}
    with builtin_jsonpath():
        wildcard = f.jsonpath_query(document=document, query="$.*[*]", max_results=10)
        assert wildcard["values"] == ["zero", "one", "two", "three"]
        negative = f.jsonpath_query(document=document, query="$.items[-1]")
        assert negative["values"] == ["two"]
        sliced = f.jsonpath_query(document=document, query="$.items[::-1]")
        assert sliced["values"] == ["two", "one", "zero"]
        limited = f.jsonpath_query(document=document, query="$..*", max_results=1)
        assert limited["truncated"] is True
        assert len(limited["values"]) == 1
        assert any("limited" in warning for warning in limited["warnings"])

    with pytest.raises(ValueError, match="callable"):
        f.register_jsonpath_engine(object())  # type: ignore[arg-type]


def test_checksum_decoding_and_algorithm_validation():
    raw = b"binary\x00payload"
    encodings = {
        "base64": base64.b64encode(raw).decode(),
        "base64url": f._b64url_encode(raw),
        "hex": raw.hex(),
    }
    for encoding, value in encodings.items():
        result = f.file_checksum(
            data=value, input_encoding=encoding, algorithms=["sha256", "blake2s"]
        )
        assert result["bytes"] == len(raw)
        assert set(result["digests"]) == {"sha256", "blake2s"}

    invalid_cases = (
        {"data": "x", "input_encoding": "raw"},
        {"data": "%%%", "input_encoding": "base64"},
        {"data": "x", "algorithms": "sha256"},
        {"data": "x", "algorithms": []},
        {"data": "x", "algorithms": ["sha256", "sha256"]},
        {"data": "x", "algorithms": ["crc32"]},
    )
    for kwargs in invalid_cases:
        with pytest.raises(ValueError):
            f.file_checksum(**kwargs)


def test_identifier_inspection_covers_time_bearing_uuid_versions_and_errors():
    version1 = f.inspect_identifier(value=str(uuid.uuid1()), kind="uuid")
    assert version1["version"] == 1
    assert version1["node"]
    assert any("creation time" in warning for warning in version1["warnings"])

    version6 = f.inspect_identifier(value=generators.uuid(version=6), kind="uuid")
    assert version6["version"] == 6 and version6["timestamp"]

    invalid = (
        {"value": "x", "kind": "snowflake"},
        {"value": "not-a-uuid", "kind": "uuid"},
        {"value": "Z" * 26, "kind": "ulid"},
        {"value": "8" + "0" * 25, "kind": "ulid"},
        {"value": "not-object-id", "kind": "objectid"},
    )
    for kwargs in invalid:
        with pytest.raises(ValueError):
            f.inspect_identifier(**kwargs)


@pytest.mark.parametrize(
    ("user_agent", "platform", "mobile"),
    [
        ("Firefox/140.0", None, None),
        ("Mozilla/5.0 (Linux; Android 15; Mobile) Chrome/140.0.0.0", "Android", True),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_5) Chrome/140.0.0.0", "iOS", False),
        ("Mozilla/5.0 (Macintosh; ARM Mac OS X 15_5) Chrome/140.0.0.0", "macOS", False),
        ("Mozilla/5.0 (X11; CrOS x86_64 16000.0.0) Chrome/140.0.0.0", "Chrome OS", False),
        ("Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0.0.0", "Linux", False),
    ],
)
def test_client_hints_platform_detection(user_agent, platform, mobile):
    result = f.user_agent_client_hints(user_agent=user_agent)
    assert result["platform"] == platform
    assert result["mobile"] is mobile
    if platform is None:
        assert "sec-ch-ua" not in result["headers"]
    else:
        assert '"Google Chrome";v="140"' in result["headers"]["sec-ch-ua"]
    with pytest.raises(ValueError, match="line breaks"):
        f.user_agent_client_hints(user_agent="Chrome/140\r\nX-Test: injected")


def test_feature_handler_boundary_deduplicates_warnings_and_rejects_nonrecords():
    calls = 0

    def warned() -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"value": calls, "warnings": [{"code": "same"}]}

    handler = f._make_handler("warned", warned, random_output=True)
    result = handler({}, {}, 2)
    assert [item["value"] for item in result["data"]] == [1, 2]
    assert result["warnings"] == [{"code": "same"}]

    preserved = f._make_handler(
        "preserved", lambda: {"value": 1, "warnings": "upstream warning"}
    )({}, {}, 1)
    assert preserved["data"]["warnings"] == "upstream warning"

    broken = f._make_handler("broken", lambda: [])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="non-record"):
        broken({}, {}, 1)
