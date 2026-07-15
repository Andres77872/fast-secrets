"""Standards-oriented feature engines for the fast-secrets workbench.

The functions in this module are deliberately independent from FastAPI and the
existing generator registry.  They accept ordinary Python/JSON values, enforce
their own resource limits, and return JSON-serialisable records.  ``run_feature``
is the small integration surface used by an API, CLI, or browser parity suite.

Secret generation uses :mod:`secrets` exclusively.  Sensitive input is never
cached or logged here.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import hmac
import json
import math
import re
import secrets
import string
import time
import urllib.parse
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import regex as _timeout_regex


MAX_TEXT = 256 * 1024
MAX_SECRET_BYTES = 4096
MAX_REGEX_PATTERN = 4096
MAX_REGEX_INPUT = 256 * 1024
MAX_REGEX_MATCHES = 1000
MAX_JSONPATH_RESULTS = 1000
MAX_RESULT_BYTES = 1024 * 1024
AMBIGUOUS = frozenset("Il1O0o|`'\"{}[]()")
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"
_PASSWORD_POOLS = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "digits": string.digits,
}
_JWT_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
_OTP_HASHES = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}
_CHECKSUM_HASHES = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_VALUES = {char: index for index, char in enumerate(_CROCKFORD)}


def _require_int(name: str, value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _require_text(name: str, value: Any, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} exceeds the {maximum}-byte limit")
    return value


def _require_mapping(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def _json_safe(value: Any, *, maximum: int = MAX_RESULT_BYTES) -> Any:
    """Validate the feature boundary and detach mutable JSON values."""
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > maximum:
            raise ValueError(f"JSON value exceeds the {maximum}-byte limit")
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("value must be JSON serialisable") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str, *, name: str = "value", maximum: int = MAX_TEXT) -> bytes:
    value = _require_text(name, value, maximum)
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError(f"{name} is not valid unpadded base64url")
    if len(value) % 4 == 1:
        raise ValueError(f"{name} has an invalid base64url length")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} is not valid base64url") from exc


def _json_segment(value: str, *, name: str) -> dict[str, Any]:
    raw = _b64url_decode(value, name=name)
    try:
        decoded = raw.decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name} must contain a UTF-8 JSON object") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return parsed


def _shuffle(values: list[str]) -> None:
    for index in range(len(values) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        values[index], values[other] = values[other], values[index]


def password_policy(
    *,
    length: int = 20,
    min_lowercase: int = 1,
    min_uppercase: int = 1,
    min_digits: int = 1,
    min_symbols: int = 1,
    symbols: str = DEFAULT_SYMBOLS,
    required: str = "",
    excluded: str = "",
    exclude_ambiguous: bool = False,
) -> dict[str, Any]:
    """Generate a password that satisfies independently configured constraints.

    Each character in ``required`` is included once in addition to class
    minima.  Duplicates are meaningful.  Exclusions take precedence and make a
    conflicting policy invalid rather than silently weakening it.
    """

    length = _require_int("length", length, 1, 1024)
    minima = {
        "lowercase": _require_int("min_lowercase", min_lowercase, 0, 1024),
        "uppercase": _require_int("min_uppercase", min_uppercase, 0, 1024),
        "digits": _require_int("min_digits", min_digits, 0, 1024),
        "symbols": _require_int("min_symbols", min_symbols, 0, 1024),
    }
    symbols = _require_text("symbols", symbols, 4096)
    required = _require_text("required", required, 4096)
    excluded = _require_text("excluded", excluded, 4096)
    if len(set(symbols)) != len(symbols):
        raise ValueError("symbols must not contain duplicate characters")
    if any(char.isspace() for char in symbols):
        raise ValueError("symbols must not contain whitespace")
    if set(symbols) & set(string.ascii_letters + string.digits):
        raise ValueError("symbols must not overlap the ASCII letter or digit classes")

    excluded_chars = set(excluded)
    if exclude_ambiguous:
        excluded_chars.update(AMBIGUOUS)
    conflicts = sorted(set(required) & excluded_chars)
    if conflicts:
        raise ValueError("required characters are also excluded")

    pools = dict(_PASSWORD_POOLS)
    pools["symbols"] = symbols
    pools = {
        key: "".join(char for char in pool if char not in excluded_chars)
        for key, pool in pools.items()
    }
    for key, minimum in minima.items():
        if minimum and not pools[key]:
            raise ValueError(f"{key} minimum cannot be met by the available characters")

    outstanding = {
        key: max(0, minimum - sum(char in pools[key] for char in required))
        for key, minimum in minima.items()
    }
    needed = len(required) + sum(outstanding.values())
    if needed > length:
        raise ValueError("required characters and class minima exceed password length")
    available = "".join(dict.fromkeys("".join(pools.values())))
    if not available:
        raise ValueError("policy leaves no available characters")

    chars = list(required)
    for key, minimum in outstanding.items():
        chars.extend(secrets.choice(pools[key]) for _ in range(minimum))
    chars.extend(secrets.choice(available) for _ in range(length - len(chars)))
    _shuffle(chars)

    # A conservative lower bound: fixed required/minimum slots are not credited.
    random_slots = length - len(required) - sum(outstanding.values())
    entropy_bits = random_slots * math.log2(len(available))
    entropy_bits += sum(
        minimum * math.log2(len(pools[key]))
        for key, minimum in outstanding.items()
        if minimum
    )
    warnings: list[str] = []
    if entropy_bits < 60:
        warnings.append("Estimated entropy is below 60 bits")
    return {
        "password": "".join(chars),
        "length": length,
        "entropy_bits_lower_bound": round(entropy_bits, 2),
        "requirements": minima | {"required_characters": len(required)},
        "warnings": warnings,
    }


def base32_encode(*, text: str, padding: bool = False) -> dict[str, Any]:
    raw = _require_text("text", text).encode("utf-8")
    encoded = base64.b32encode(raw).decode("ascii")
    if not padding:
        encoded = encoded.rstrip("=")
    return {"value": encoded, "encoding": "base32", "padding": bool(padding), "warnings": []}


def _decode_base32_bytes(value: str) -> bytes:
    value = _require_text("value", value).strip().replace(" ", "").replace("-", "")
    if not value:
        return b""
    if not re.fullmatch(r"[A-Za-z2-7]+=*", value):
        raise ValueError("value is not valid RFC 4648 Base32")
    unpadded = value.rstrip("=")
    if "=" in unpadded:
        raise ValueError("Base32 padding is only allowed at the end")
    if len(unpadded) % 8 in {1, 3, 6}:
        raise ValueError("value has an invalid Base32 length")
    try:
        return base64.b32decode(unpadded.upper() + "=" * (-len(unpadded) % 8), casefold=True)
    except binascii.Error as exc:
        raise ValueError("value is not valid RFC 4648 Base32") from exc


def base32_decode(*, value: str) -> dict[str, Any]:
    raw = _decode_base32_bytes(value)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("decoded Base32 is not valid UTF-8") from exc
    return {"value": text, "bytes": len(raw), "warnings": []}


def base32_secret(*, nbytes: int = 20, padding: bool = False) -> dict[str, Any]:
    nbytes = _require_int("nbytes", nbytes, 10, MAX_SECRET_BYTES)
    value = base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii")
    if not padding:
        value = value.rstrip("=")
    return {"secret": value, "bytes": nbytes, "bits": nbytes * 8, "warnings": []}


def jwt_encode(
    *,
    claims: Mapping[str, Any],
    secret: str = "",
    algorithm: str = "HS256",
    header: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Encode a compact JWT.  ``none`` is intentionally decode-only."""

    claims = _json_safe(_require_mapping("claims", claims), maximum=MAX_TEXT)
    header_value = _json_safe(_require_mapping("header", header or {}), maximum=64 * 1024)
    algorithm = _require_text("algorithm", algorithm, 16).upper()
    if algorithm == "NONE":
        raise ValueError("alg=none is decode-only; signing requires HS256, HS384, or HS512")
    if algorithm not in _JWT_HASHES:
        raise ValueError("algorithm must be HS256, HS384, or HS512")
    secret = _require_text("secret", secret, 64 * 1024)
    if not secret:
        raise ValueError("secret must not be empty")
    if "alg" in header_value and str(header_value["alg"]).upper() != algorithm:
        raise ValueError("header alg conflicts with algorithm")
    header_value = {"typ": "JWT", **header_value, "alg": algorithm}
    head = _b64url_encode(json.dumps(header_value, separators=(",", ":"), ensure_ascii=False).encode())
    body = _b64url_encode(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode())
    signing_input = f"{head}.{body}".encode("ascii")
    signature = hmac.new(secret.encode(), signing_input, _JWT_HASHES[algorithm]).digest()
    return {
        "token": f"{head}.{body}.{_b64url_encode(signature)}",
        "header": header_value,
        "claims": claims,
        "algorithm": algorithm,
        "warnings": [],
    }


def _claim_status(
    claims: Mapping[str, Any],
    *,
    now: float,
    leeway: int,
    issuer: str | None,
    audience: str | None,
) -> tuple[str, list[dict[str, str]], list[str]]:
    errors: list[dict[str, str]] = []
    warnings: list[str] = []
    for name in ("exp", "nbf", "iat"):
        if name not in claims:
            continue
        value = claims[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            errors.append({"claim": name, "message": "must be a finite NumericDate"})
            continue
        if abs(value) > 253402300799:
            errors.append({"claim": name, "message": "NumericDate is outside the supported range"})
    if isinstance(claims.get("exp"), (int, float)) and not isinstance(claims.get("exp"), bool):
        if now > float(claims["exp"]) + leeway:
            errors.append({"claim": "exp", "message": "token is expired"})
    if isinstance(claims.get("nbf"), (int, float)) and not isinstance(claims.get("nbf"), bool):
        if now + leeway < float(claims["nbf"]):
            errors.append({"claim": "nbf", "message": "token is not active yet"})
    if isinstance(claims.get("iat"), (int, float)) and not isinstance(claims.get("iat"), bool):
        if now + leeway < float(claims["iat"]):
            errors.append({"claim": "iat", "message": "issued-at time is in the future"})
    if issuer is not None and claims.get("iss") != issuer:
        errors.append({"claim": "iss", "message": "issuer does not match"})
    if audience is not None:
        token_audience = claims.get("aud")
        audiences = token_audience if isinstance(token_audience, list) else [token_audience]
        if audience not in audiences:
            errors.append({"claim": "aud", "message": "audience does not match"})
    if "exp" not in claims:
        warnings.append("Token has no expiration claim")
    return ("valid" if not errors else "invalid"), errors, warnings


def jwt_decode(
    *,
    token: str,
    secret: str | None = None,
    allowed_algorithms: Sequence[str] = ("HS256", "HS384", "HS512"),
    issuer: str | None = None,
    audience: str | None = None,
    leeway: int = 0,
    now: float | None = None,
) -> dict[str, Any]:
    """Decode and optionally verify a JWT with independent status dimensions."""

    token = _require_text("token", token)
    leeway = _require_int("leeway", leeway, 0, 86400)
    status = {"syntax": "invalid", "signature": "not_checked", "claims": "not_checked"}
    result: dict[str, Any] = {
        "header": None,
        "claims": None,
        "status": status,
        "errors": [],
        "warnings": [],
    }
    parts = token.split(".")
    if len(parts) != 3:
        result["errors"].append({"part": "syntax", "message": "JWT must have exactly three segments"})
        return result
    try:
        header = _json_segment(parts[0], name="header segment")
        claims = _json_segment(parts[1], name="claims segment")
        signature = _b64url_decode(parts[2], name="signature segment")
    except ValueError as exc:
        result["errors"].append({"part": "syntax", "message": str(exc)})
        return result

    status["syntax"] = "valid"
    result["header"] = header
    result["claims"] = claims
    algorithm = header.get("alg")
    if not isinstance(algorithm, str):
        status["signature"] = "invalid"
        result["errors"].append({"part": "signature", "message": "header alg must be a string"})
    elif algorithm.lower() == "none":
        status["signature"] = "unsecured"
        result["warnings"].append("alg=none is decoded for inspection only and is never verified")
        if signature:
            status["signature"] = "invalid"
            result["errors"].append({"part": "signature", "message": "alg=none must have an empty signature"})
    else:
        if isinstance(allowed_algorithms, str) or not isinstance(allowed_algorithms, Sequence):
            raise ValueError("allowed_algorithms must be an array")
        if len(allowed_algorithms) > len(_JWT_HASHES):
            raise ValueError("allowed_algorithms contains too many values")
        normalized_allowed = {str(value).upper() for value in allowed_algorithms}
        if normalized_allowed - set(_JWT_HASHES):
            raise ValueError("allowed_algorithms may contain only HS256, HS384, and HS512")
        if algorithm not in _JWT_HASHES or algorithm not in normalized_allowed:
            status["signature"] = "unsupported"
            result["errors"].append({"part": "signature", "message": "algorithm is not allow-listed"})
        elif secret is None:
            status["signature"] = "not_checked"
            result["warnings"].append("Signature was not checked because no secret was provided")
        else:
            secret = _require_text("secret", secret, 64 * 1024)
            if not secret:
                raise ValueError("secret must not be empty")
            expected = hmac.new(
                secret.encode(), f"{parts[0]}.{parts[1]}".encode("ascii"), _JWT_HASHES[algorithm]
            ).digest()
            status["signature"] = "valid" if hmac.compare_digest(signature, expected) else "invalid"
            if status["signature"] == "invalid":
                result["errors"].append({"part": "signature", "message": "signature does not match"})

    if isinstance(now, bool):
        raise ValueError("now must be a finite number")
    try:
        current = time.time() if now is None else float(now)
    except (TypeError, ValueError) as exc:
        raise ValueError("now must be a finite number") from exc
    if not math.isfinite(current):
        raise ValueError("now must be finite")
    claim_status, claim_errors, claim_warnings = _claim_status(
        claims, now=current, leeway=leeway, issuer=issuer, audience=audience
    )
    status["claims"] = claim_status
    result["errors"].extend({"part": "claims", **error} for error in claim_errors)
    result["warnings"].extend(claim_warnings)
    return result


def jwt_verify(**kwargs: Any) -> dict[str, Any]:
    if kwargs.get("secret") is None:
        raise ValueError("secret is required for verification")
    result = jwt_decode(**kwargs)
    result["verified"] = (
        result["status"]["syntax"] == "valid"
        and result["status"]["signature"] == "valid"
        and result["status"]["claims"] == "valid"
    )
    return result


def _otp_key(secret: str) -> bytes:
    raw = _decode_base32_bytes(secret)
    if not raw:
        raise ValueError("secret must not be empty")
    if len(raw) > MAX_SECRET_BYTES:
        raise ValueError(f"secret exceeds the {MAX_SECRET_BYTES}-byte limit")
    return raw


def hotp(
    *,
    secret: str,
    counter: int,
    digits: int = 6,
    algorithm: str = "SHA1",
) -> dict[str, Any]:
    """Generate an RFC 4226 HOTP value."""

    key = _otp_key(secret)
    counter = _require_int("counter", counter, 0, (1 << 64) - 1)
    digits = _require_int("digits", digits, 6, 8)
    algorithm = _require_text("algorithm", algorithm, 16).upper().replace("-", "")
    if algorithm not in _OTP_HASHES:
        raise ValueError("algorithm must be SHA1, SHA256, or SHA512")
    digest = hmac.new(key, counter.to_bytes(8, "big"), _OTP_HASHES[algorithm]).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    code = str(binary % (10**digits)).zfill(digits)
    warnings = []
    if algorithm == "SHA1":
        warnings.append("SHA-1 is retained for OTP interoperability; prefer SHA-256 when supported")
    return {
        "code": code,
        "counter": counter,
        "digits": digits,
        "algorithm": algorithm,
        "warnings": warnings,
    }


def hotp_verify(
    *,
    secret: str,
    code: str,
    counter: int,
    look_ahead: int = 0,
    digits: int = 6,
    algorithm: str = "SHA1",
) -> dict[str, Any]:
    code = _require_text("code", code, 16)
    digits = _require_int("digits", digits, 6, 8)
    if not re.fullmatch(rf"\d{{{digits}}}", code):
        raise ValueError(f"code must contain exactly {digits} digits")
    counter = _require_int("counter", counter, 0, (1 << 64) - 1)
    look_ahead = _require_int("look_ahead", look_ahead, 0, 100)
    upper = min((1 << 64) - 1, counter + look_ahead)
    matched_counter: int | None = None
    for candidate in range(counter, upper + 1):
        generated = hotp(
            secret=secret, counter=candidate, digits=digits, algorithm=algorithm
        )["code"]
        if hmac.compare_digest(generated, code):
            matched_counter = candidate
            break
    return {
        "valid": matched_counter is not None,
        "matched_counter": matched_counter,
        "next_counter": matched_counter + 1 if matched_counter is not None else None,
        "warnings": [],
    }


def totp(
    *,
    secret: str,
    timestamp: float | None = None,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
) -> dict[str, Any]:
    period = _require_int("period", period, 1, 86400)
    value = time.time() if timestamp is None else float(timestamp)
    if not math.isfinite(value) or value < 0 or value > 253402300799:
        raise ValueError("timestamp is outside the supported range")
    counter = int(value // period)
    generated = hotp(secret=secret, counter=counter, digits=digits, algorithm=algorithm)
    remaining = period - (int(value) % period)
    return {
        **generated,
        "timestamp": value,
        "period": period,
        "seconds_remaining": remaining,
    }


def totp_verify(
    *,
    secret: str,
    code: str,
    timestamp: float | None = None,
    period: int = 30,
    window: int = 1,
    digits: int = 6,
    algorithm: str = "SHA1",
) -> dict[str, Any]:
    code = _require_text("code", code, 16)
    digits = _require_int("digits", digits, 6, 8)
    if not re.fullmatch(rf"\d{{{digits}}}", code):
        raise ValueError(f"code must contain exactly {digits} digits")
    period = _require_int("period", period, 1, 86400)
    window = _require_int("window", window, 0, 10)
    value = time.time() if timestamp is None else float(timestamp)
    if not math.isfinite(value) or value < 0 or value > 253402300799:
        raise ValueError("timestamp is outside the supported range")
    counter = int(value // period)
    matched_offset: int | None = None
    for offset in range(-window, window + 1):
        candidate = counter + offset
        if candidate < 0:
            continue
        generated = hotp(
            secret=secret, counter=candidate, digits=digits, algorithm=algorithm
        )["code"]
        if hmac.compare_digest(generated, code):
            matched_offset = offset
            break
    return {
        "valid": matched_offset is not None,
        "matched_offset": matched_offset,
        "counter": counter,
        "window": window,
        "warnings": [],
    }


def otpauth_build(
    *,
    otp_type: str = "totp",
    secret: str,
    account: str,
    issuer: str = "",
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
    counter: int = 0,
) -> dict[str, Any]:
    otp_type = _require_text("otp_type", otp_type, 8).lower()
    if otp_type not in {"hotp", "totp"}:
        raise ValueError("otp_type must be hotp or totp")
    raw_secret = _otp_key(secret)
    canonical_secret = base64.b32encode(raw_secret).decode("ascii").rstrip("=")
    account = _require_text("account", account, 1024)
    issuer = _require_text("issuer", issuer, 1024)
    if not account:
        raise ValueError("account must not be empty")
    if ":" in account or ":" in issuer:
        raise ValueError("account and issuer must not contain a colon")
    algorithm = _require_text("algorithm", algorithm, 16).upper().replace("-", "")
    if algorithm not in _OTP_HASHES:
        raise ValueError("algorithm must be SHA1, SHA256, or SHA512")
    digits = _require_int("digits", digits, 6, 8)
    label = f"{issuer}:{account}" if issuer else account
    query: list[tuple[str, str]] = [("secret", canonical_secret)]
    if issuer:
        query.append(("issuer", issuer))
    query.extend((("algorithm", algorithm), ("digits", str(digits))))
    if otp_type == "totp":
        query.append(("period", str(_require_int("period", period, 1, 86400))))
    else:
        query.append(("counter", str(_require_int("counter", counter, 0, (1 << 64) - 1))))
    uri = f"otpauth://{otp_type}/{urllib.parse.quote(label, safe='')}?{urllib.parse.urlencode(query)}"
    return {"uri": uri, "type": otp_type, "label": label, "warnings": []}


def otpauth_parse(*, uri: str) -> dict[str, Any]:
    uri = _require_text("uri", uri)
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() not in {"hotp", "totp"}:
        raise ValueError("URI must use otpauth://hotp or otpauth://totp")
    if parsed.fragment:
        raise ValueError("otpauth URI must not contain a fragment")
    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    if not label:
        raise ValueError("otpauth URI label must not be empty")
    try:
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ValueError("otpauth URI contains a malformed query") from exc
    query: dict[str, str] = {}
    for key, value in pairs:
        if key in query:
            raise ValueError(f"otpauth URI repeats the {key!r} parameter")
        query[key] = value
    if "secret" not in query:
        raise ValueError("otpauth URI is missing secret")
    raw_secret = _otp_key(query["secret"])
    secret = base64.b32encode(raw_secret).decode("ascii").rstrip("=")
    algorithm = query.get("algorithm", "SHA1").upper().replace("-", "")
    if algorithm not in _OTP_HASHES:
        raise ValueError("otpauth algorithm must be SHA1, SHA256, or SHA512")
    digits = _require_int("digits", query.get("digits", 6), 6, 8)
    otp_type = parsed.netloc.lower()
    issuer = query.get("issuer", "")
    label_issuer, separator, account = label.partition(":")
    if not separator:
        account = label
        label_issuer = ""
    warnings: list[str] = []
    if issuer and label_issuer and issuer != label_issuer:
        warnings.append("Issuer query parameter differs from label issuer")
    result: dict[str, Any] = {
        "type": otp_type,
        "secret": secret,
        "account": account,
        "issuer": issuer or label_issuer,
        "algorithm": algorithm,
        "digits": digits,
        "warnings": warnings,
    }
    if otp_type == "totp":
        result["period"] = _require_int("period", query.get("period", 30), 1, 86400)
    else:
        if "counter" not in query:
            raise ValueError("HOTP URI is missing counter")
        result["counter"] = _require_int("counter", query["counter"], 0, (1 << 64) - 1)
    unknown = sorted(set(query) - {"secret", "issuer", "algorithm", "digits", "period", "counter"})
    if unknown:
        warnings.append("Ignored unknown parameters: " + ", ".join(unknown))
    return result


def pkce_generate(*, length: int = 64) -> dict[str, Any]:
    length = _require_int("length", length, 43, 128)
    alphabet = string.ascii_letters + string.digits + "-._~"
    verifier = "".join(secrets.choice(alphabet) for _ in range(length))
    challenge = _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return {
        "code_verifier": verifier,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "warnings": [],
    }


def pkce_challenge(*, verifier: str) -> dict[str, Any]:
    verifier = _require_text("verifier", verifier, 128)
    if not 43 <= len(verifier) <= 128 or not re.fullmatch(r"[A-Za-z0-9._~-]+", verifier):
        raise ValueError("verifier must be 43-128 RFC 7636 unreserved ASCII characters")
    return {
        "code_challenge": _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest()),
        "code_challenge_method": "S256",
        "warnings": [],
    }


def random_nonce(*, purpose: str = "state", nbytes: int = 32) -> dict[str, Any]:
    purpose = _require_text("purpose", purpose, 16).lower()
    if purpose not in {"state", "oidc_nonce", "csp_nonce"}:
        raise ValueError("purpose must be state, oidc_nonce, or csp_nonce")
    nbytes = _require_int("nbytes", nbytes, 16, 256)
    raw = secrets.token_bytes(nbytes)
    if purpose == "csp_nonce":
        value = base64.b64encode(raw).decode("ascii")
        return {
            "value": value,
            "purpose": purpose,
            "directive": f"'nonce-{value}'",
            "bits": nbytes * 8,
            "warnings": [],
        }
    return {
        "value": _b64url_encode(raw),
        "purpose": purpose,
        "bits": nbytes * 8,
        "warnings": [],
    }


def webhook_hmac(
    *,
    payload: str,
    secret: str,
    algorithm: str = "sha256",
    encoding: str = "hex",
    prefix: bool = True,
) -> dict[str, Any]:
    payload = _require_text("payload", payload)
    secret = _require_text("secret", secret, 64 * 1024)
    if not secret:
        raise ValueError("secret must not be empty")
    algorithm = _require_text("algorithm", algorithm, 16).lower().replace("-", "")
    hashes = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
    if algorithm not in hashes:
        raise ValueError("algorithm must be sha256, sha384, or sha512")
    encoding = _require_text("encoding", encoding, 16).lower()
    digest = hmac.new(secret.encode(), payload.encode(), hashes[algorithm]).digest()
    if encoding == "hex":
        signature = digest.hex()
    elif encoding == "base64":
        signature = base64.b64encode(digest).decode("ascii")
    elif encoding == "base64url":
        signature = _b64url_encode(digest)
    else:
        raise ValueError("encoding must be hex, base64, or base64url")
    if prefix:
        signature = f"{algorithm}={signature}"
    return {
        "signature": signature,
        "algorithm": algorithm,
        "encoding": encoding,
        "warnings": [],
    }


def webhook_verify(
    *,
    payload: str,
    secret: str,
    signature: str,
    algorithm: str = "sha256",
    encoding: str = "hex",
) -> dict[str, Any]:
    signature = _require_text("signature", signature, 2048).strip()
    expected = webhook_hmac(
        payload=payload, secret=secret, algorithm=algorithm, encoding=encoding, prefix=False
    )
    supplied = signature
    prefix = expected["algorithm"] + "="
    if supplied.lower().startswith(prefix):
        supplied = supplied[len(prefix) :]
    valid = hmac.compare_digest(supplied, expected["signature"])
    return {"valid": valid, "algorithm": expected["algorithm"], "warnings": []}


_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _dotenv_double_quoted(value: str, line: int) -> str:
    output: list[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}
    while index < len(value):
        char = value[index]
        if char == "\\":
            if index + 1 >= len(value):
                raise ValueError(f"line {line}: trailing escape in double-quoted value")
            following = value[index + 1]
            output.append(escapes.get(following, "\\" + following))
            index += 2
        else:
            output.append(char)
            index += 1
    return "".join(output)


def _dotenv_value(raw: str, line: int) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {'"', "'"}:
        quote = value[0]
        escaped = False
        closing: int | None = None
        for index in range(1, len(value)):
            if quote == '"' and value[index] == "\\" and not escaped:
                escaped = True
                continue
            if value[index] == quote and not escaped:
                closing = index
                break
            escaped = False
        if closing is None:
            raise ValueError(f"line {line}: unterminated quoted value")
        tail = value[closing + 1 :].strip()
        if tail and not tail.startswith("#"):
            raise ValueError(f"line {line}: unexpected text after quoted value")
        content = value[1:closing]
        return _dotenv_double_quoted(content, line) if quote == '"' else content

    # An inline comment begins at a # preceded by whitespace.  A literal # in
    # URLs, tokens, and similar unquoted values is preserved.
    marker = re.search(r"\s+#", value)
    if marker:
        value = value[: marker.start()].rstrip()
    return value


def parse_dotenv(*, text: str) -> dict[str, Any]:
    """Parse dotenv assignments without expansion, interpolation, or execution."""

    text = _require_text("text", text)
    entries: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    for line_number, original in enumerate(text.splitlines(), 1):
        stripped = original.strip()
        if not stripped or stripped.startswith("#"):
            continue
        candidate = stripped
        exported = False
        if candidate.startswith("export") and (
            len(candidate) == 6 or candidate[6].isspace()
        ):
            candidate = candidate[6:].lstrip()
            exported = True
        if "=" not in candidate:
            errors.append({"line": line_number, "message": "assignment is missing ="})
            continue
        key, raw = candidate.split("=", 1)
        key = key.strip()
        if not _ENV_KEY.fullmatch(key):
            errors.append({"line": line_number, "message": "invalid variable name", "key": key})
            continue
        try:
            value = _dotenv_value(raw, line_number)
        except ValueError as exc:
            errors.append({"line": line_number, "message": str(exc).split(": ", 1)[-1], "key": key})
            continue
        if key in seen:
            errors.append(
                {
                    "line": line_number,
                    "message": f"duplicate variable; first defined on line {seen[key]}",
                    "key": key,
                }
            )
        else:
            seen[key] = line_number
        if re.search(r"\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)", value):
            warnings.append(
                {"line": line_number, "key": key, "message": "interpolation-like text is kept literal"}
            )
        entries.append({"key": key, "value": value, "line": line_number, "exported": exported})
    return {
        "valid": not errors,
        "entries": entries,
        "keys": [entry["key"] for entry in entries],
        "errors": errors,
        "warnings": warnings,
    }


def _quote_env(value: str) -> str:
    if value and not re.search(r"[\s#'\"\\]", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def dotenv_tool(
    *,
    text: str,
    action: str = "validate",
    other: str = "",
    mask: str = "********",
) -> dict[str, Any]:
    action = _require_text("action", action, 16).lower()
    if action not in {"parse", "validate", "sort", "redact", "example", "compare"}:
        raise ValueError("action must be parse, validate, sort, redact, example, or compare")
    parsed = parse_dotenv(text=text)
    base = {"valid": parsed["valid"], "errors": parsed["errors"], "warnings": parsed["warnings"]}
    if action in {"parse", "validate"}:
        if action == "parse":
            base["entries"] = parsed["entries"]
        base["keys"] = parsed["keys"]
        return base
    if action == "compare":
        second = parse_dotenv(text=_require_text("other", other))
        left = set(parsed["keys"])
        right = set(second["keys"])
        return {
            "valid": parsed["valid"] and second["valid"],
            "only_in_first": sorted(left - right),
            "only_in_second": sorted(right - left),
            "in_both": sorted(left & right),
            "errors": {"first": parsed["errors"], "second": second["errors"]},
            "warnings": {"first": parsed["warnings"], "second": second["warnings"]},
        }
    entries = parsed["entries"]
    if action == "sort":
        entries = sorted(entries, key=lambda entry: entry["key"])
        rendered = [f'{entry["key"]}={_quote_env(entry["value"])}' for entry in entries]
    elif action == "redact":
        mask = _require_text("mask", mask, 64)
        if not mask or "\n" in mask or "\r" in mask:
            raise ValueError("mask must be a non-empty single-line string")
        rendered = [f'{entry["key"]}={mask if entry["value"] else ""}' for entry in entries]
    else:
        rendered = [f'{entry["key"]}=' for entry in entries]
    return {**base, "text": "\n".join(rendered) + ("\n" if rendered else ""), "keys": parsed["keys"]}


def _zone(name: str) -> ZoneInfo:
    name = _require_text("timezone", name, 255)
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown IANA timezone: {name}") from exc


def _iso_datetime(value: str, input_timezone: str, fold: int) -> tuple[_dt.datetime, list[str]]:
    value = _require_text("value", value, 256).strip()
    try:
        parsed = _dt.datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value)
    except ValueError as exc:
        raise ValueError("value is not a valid ISO-8601 date-time") from exc
    warnings: list[str] = []
    if parsed.tzinfo is not None:
        return parsed, warnings
    fold = _require_int("fold", fold, 0, 1)
    zone = _zone(input_timezone)
    candidate = parsed.replace(tzinfo=zone, fold=fold)
    round_trip = candidate.astimezone(_dt.timezone.utc).astimezone(zone).replace(tzinfo=None)
    if round_trip != parsed:
        raise ValueError("local time does not exist in the selected timezone (DST gap)")
    alternate = parsed.replace(tzinfo=zone, fold=1 - fold)
    if alternate.utcoffset() != candidate.utcoffset():
        warnings.append(f"Local time is ambiguous; fold={fold} was selected")
    return candidate, warnings


def timestamp_convert(
    *,
    value: str | int | float,
    input_format: str = "auto",
    input_timezone: str = "UTC",
    output_timezones: Sequence[str] = ("UTC",),
    fold: int = 0,
) -> dict[str, Any]:
    input_format = _require_text("input_format", input_format, 32).lower()
    if input_format not in {"auto", "iso8601", "epoch_seconds", "epoch_milliseconds"}:
        raise ValueError("input_format must be auto, iso8601, epoch_seconds, or epoch_milliseconds")
    warnings: list[str] = []
    chosen = input_format
    if input_format == "auto":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            chosen = "epoch_milliseconds" if abs(float(value)) >= 100_000_000_000 else "epoch_seconds"
        elif isinstance(value, str) and re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value.strip()):
            numeric = float(value)
            chosen = "epoch_milliseconds" if abs(numeric) >= 100_000_000_000 else "epoch_seconds"
        else:
            chosen = "iso8601"
    if chosen == "iso8601":
        moment, iso_warnings = _iso_datetime(str(value), input_timezone, fold)
        warnings.extend(iso_warnings)
        timestamp = moment.timestamp()
    else:
        if isinstance(value, bool):
            raise ValueError("value must be numeric")
        try:
            timestamp = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("value must be numeric") from exc
        if chosen == "epoch_milliseconds":
            timestamp /= 1000
    if not math.isfinite(timestamp) or timestamp < -62135596800 or timestamp > 253402300799:
        raise ValueError("timestamp is outside the supported datetime range")
    try:
        utc = _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError("timestamp is outside the platform datetime range") from exc
    if isinstance(output_timezones, str) or not isinstance(output_timezones, Sequence):
        raise ValueError("output_timezones must be an array of IANA timezone names")
    if not output_timezones or len(output_timezones) > 32:
        raise ValueError("output_timezones must contain between 1 and 32 entries")
    outputs: list[dict[str, Any]] = []
    for name in output_timezones:
        zone = _zone(str(name))
        local = utc.astimezone(zone)
        outputs.append(
            {
                "timezone": str(name),
                "iso8601": local.isoformat(),
                "utc_offset_seconds": int((local.utcoffset() or _dt.timedelta()).total_seconds()),
                "abbreviation": local.tzname(),
                "fold": local.fold,
            }
        )
    return {
        "detected_format": chosen,
        "epoch_seconds": timestamp,
        "epoch_milliseconds": timestamp * 1000,
        "utc": utc.isoformat().replace("+00:00", "Z"),
        "outputs": outputs,
        "warnings": warnings,
    }


def _regex_flags(flags: str) -> tuple[int, str]:
    flags = _require_text("flags", flags, 16).lower()
    if len(set(flags)) != len(flags) or any(char not in "aimsx" for char in flags):
        raise ValueError("flags may contain each of a, i, m, s, and x at most once")
    mapping = {
        "a": _timeout_regex.ASCII,
        "i": _timeout_regex.IGNORECASE,
        "m": _timeout_regex.MULTILINE,
        "s": _timeout_regex.DOTALL,
        "x": _timeout_regex.VERBOSE,
    }
    value = 0
    for char in flags:
        value |= mapping[char]
    return value, "".join(sorted(flags))


def regex_test(
    *,
    pattern: str,
    text: str,
    flags: str = "",
    replacement: str | None = None,
    max_matches: int = 100,
    timeout_ms: int = 100,
) -> dict[str, Any]:
    """Test a Python regular expression with input, result, and time budgets."""

    pattern = _require_text("pattern", pattern, MAX_REGEX_PATTERN)
    text = _require_text("text", text, MAX_REGEX_INPUT)
    if "\x00" in pattern or "\x00" in text:
        raise ValueError("NUL characters are not supported")
    max_matches = _require_int("max_matches", max_matches, 1, MAX_REGEX_MATCHES)
    timeout_ms = _require_int("timeout_ms", timeout_ms, 1, 5000)
    compiled_flags, canonical_flags = _regex_flags(flags)
    try:
        # The parser is bounded by MAX_REGEX_PATTERN. Runtime operations below
        # use the regex package's native hard timeout, which also works from
        # FastAPI worker threads.
        compiled = _timeout_regex.compile(pattern, compiled_flags)
    except _timeout_regex.error as exc:
        return {
            "valid": False,
            "timed_out": False,
            "error": {"message": str(exc), "position": getattr(exc, "pos", None)},
            "matches": [],
            "warnings": [],
        }

    warnings: list[str] = []
    started = time.perf_counter()
    deadline = started + timeout_ms / 1000
    matches: list[dict[str, Any]] = []
    match_bytes = 0
    truncated = False
    preview: str | None = None
    try:
        for match in compiled.finditer(text, timeout=timeout_ms / 1000, concurrent=True):
            if len(matches) >= max_matches:
                truncated = True
                break
            groups = [value if value is not None else None for value in match.groups()]
            record = {
                "match": match.group(0),
                "span": [match.start(), match.end()],
                "groups": groups,
                "named_groups": {key: value for key, value in match.groupdict().items()},
            }
            record_bytes = len(json.dumps(record, ensure_ascii=False).encode("utf-8"))
            if match_bytes + record_bytes > MAX_RESULT_BYTES // 2:
                truncated = True
                warnings.append("Match details reached the output-size budget")
                break
            match_bytes += record_bytes
            matches.append(record)
        if replacement is not None:
            replacement = _require_text("replacement", replacement, 16 * 1024)
            input_bytes = len(text.encode("utf-8"))
            replacement_bytes = len(replacement.encode("utf-8"))
            references = len(re.findall(r"\\(?:g<[^>]+>|[1-9]\d*)", replacement))
            conservative_size = input_bytes * (references + 1) + replacement_bytes * max_matches
            if conservative_size > MAX_RESULT_BYTES:
                raise ValueError("replacement preview could exceed the output-size budget")
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise TimeoutError("regex timed out")
            preview = compiled.sub(
                replacement,
                text,
                count=max_matches,
                timeout=remaining,
                concurrent=True,
            )
            if len(preview.encode("utf-8")) > MAX_RESULT_BYTES:
                raise ValueError("replacement preview exceeds the output-size budget")
    except TimeoutError:
        return {
            "valid": True,
            "timed_out": True,
            "timeout_ms": timeout_ms,
            "matches": [],
            "warnings": ["Regular expression exceeded its execution budget"],
        }
    except _timeout_regex.error as exc:
        return {
            "valid": True,
            "timed_out": False,
            "error": {"message": f"replacement error: {exc}", "position": getattr(exc, "pos", None)},
            "matches": matches,
            "warnings": warnings,
        }
    elapsed_ms = (time.perf_counter() - started) * 1000
    if truncated:
        warnings.append(f"Results were limited to {max_matches} matches")
    return {
        "valid": True,
        "timed_out": False,
        "flags": canonical_flags,
        "matches": matches,
        "match_count": len(matches),
        "truncated": truncated,
        "replacement_preview": preview,
        "elapsed_ms": round(elapsed_ms, 3),
        "warnings": warnings,
    }


_JSONPATH_ENGINE: Callable[[Any, str, int], Sequence[Any]] | None = None


def register_jsonpath_engine(
    engine: Callable[[Any, str, int], Sequence[Any]] | None,
) -> None:
    """Register an RFC 9535 engine with ``(document, query, limit)`` signature.

    The dependency-free fallback covers child/descendant names, wildcards,
    array indices, unions, and slices.  Applications can inject a pinned RFC
    9535 implementation to add filter selectors and its compliance suite.
    """

    global _JSONPATH_ENGINE
    if engine is not None and not callable(engine):
        raise ValueError("engine must be callable or None")
    _JSONPATH_ENGINE = engine


def _jsonpath_selectors(content: str) -> list[str]:
    selectors: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(content):
        if quote:
            if char == "\\" and not escaped:
                escaped = True
                continue
            if char == quote and not escaped:
                quote = None
            escaped = False
        elif char in {'"', "'"}:
            quote = char
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            selectors.append(content[start:index].strip())
            start = index + 1
    if quote or depth:
        raise ValueError("unterminated JSONPath selector")
    selectors.append(content[start:].strip())
    if not all(selectors):
        raise ValueError("empty JSONPath selector")
    return selectors


def _jsonpath_unquote(selector: str) -> str:
    if len(selector) < 2 or selector[0] not in {'"', "'"} or selector[-1] != selector[0]:
        raise ValueError("invalid JSONPath member-name selector")
    if selector[0] == '"':
        try:
            value = json.loads(selector)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSONPath string literal") from exc
        if not isinstance(value, str):
            raise ValueError("JSONPath member name must be a string")
        return value
    # RFC 9535 single-quoted strings use JSON escapes plus escaped apostrophe.
    body = selector[1:-1]
    body = body.replace('\\"', '\\\\"').replace('"', '\\"').replace("\\'", "'")
    try:
        value = json.loads(f'"{body}"')
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSONPath string literal") from exc
    return value


def _jsonpath_parse(query: str) -> list[tuple[bool, list[tuple[str, Any]]]]:
    query = _require_text("query", query, 16 * 1024)
    if not query.startswith("$"):
        raise ValueError("JSONPath query must start with $")
    index = 1
    segments: list[tuple[bool, list[tuple[str, Any]]]] = []
    while index < len(query):
        recursive = False
        selectors: list[tuple[str, Any]]
        if query.startswith("..", index):
            recursive = True
            index += 2
            if index >= len(query):
                raise ValueError("descendant segment is missing a selector")
            if query[index] != "[":
                if query[index] == "*":
                    selectors = [("wildcard", None)]
                    index += 1
                    segments.append((recursive, selectors))
                    continue
                else:
                    end = index
                    while end < len(query) and query[end] not in ".[":
                        end += 1
                    name = query[index:end]
                    if not name:
                        raise ValueError("empty descendant member name")
                    selectors = [("name", name)]
                    index = end
                    segments.append((recursive, selectors))
                    continue
            else:
                selectors = []  # parsed below
        elif query[index] == ".":
            index += 1
            if index >= len(query):
                raise ValueError("child segment is missing a selector")
            if query[index] == "*":
                selectors = [("wildcard", None)]
                index += 1
            else:
                end = index
                while end < len(query) and query[end] not in ".[":
                    end += 1
                name = query[index:end]
                if not name:
                    raise ValueError("empty child member name")
                selectors = [("name", name)]
                index = end
            segments.append((recursive, selectors))
            continue
        elif query[index] != "[":
            raise ValueError(f"unexpected JSONPath character at position {index}")
        if index >= len(query) or query[index] != "[":
            segments.append((recursive, selectors))
            continue
        quote: str | None = None
        escaped = False
        close: int | None = None
        for cursor in range(index + 1, len(query)):
            char = query[cursor]
            if quote:
                if char == "\\" and not escaped:
                    escaped = True
                    continue
                if char == quote and not escaped:
                    quote = None
                escaped = False
            elif char in {'"', "'"}:
                quote = char
            elif char == "]":
                close = cursor
                break
        if close is None:
            raise ValueError("unterminated JSONPath bracket segment")
        selectors = []
        for selector in _jsonpath_selectors(query[index + 1 : close]):
            if selector == "*":
                selectors.append(("wildcard", None))
            elif selector.startswith(("'", '"')):
                selectors.append(("name", _jsonpath_unquote(selector)))
            elif selector.startswith("?"):
                raise ValueError("filter selectors require a registered RFC 9535 JSONPath engine")
            elif ":" in selector:
                parts = selector.split(":")
                if len(parts) not in {2, 3}:
                    raise ValueError("invalid JSONPath array slice")
                try:
                    values = [int(part) if part else None for part in parts]
                except ValueError as exc:
                    raise ValueError("JSONPath slice values must be integers") from exc
                if len(values) == 2:
                    values.append(None)
                if values[2] == 0:
                    raise ValueError("JSONPath slice step must not be zero")
                selectors.append(("slice", slice(*values)))
            elif re.fullmatch(r"-?(?:0|[1-9]\d*)", selector):
                selectors.append(("index", int(selector)))
            else:
                raise ValueError(f"unsupported JSONPath selector: {selector}")
        segments.append((recursive, selectors))
        index = close + 1
    return segments


def _jsonpath_children(node: tuple[Any, str]) -> list[tuple[Any, str]]:
    value, path = node
    if isinstance(value, dict):
        return [(child, path + "[" + json.dumps(str(key), ensure_ascii=False) + "]") for key, child in value.items()]
    if isinstance(value, list):
        return [(child, f"{path}[{index}]") for index, child in enumerate(value)]
    return []


def _jsonpath_descendants(node: tuple[Any, str]) -> list[tuple[Any, str]]:
    output: list[tuple[Any, str]] = []
    stack = [node]
    while stack:
        current = stack.pop()
        output.append(current)
        if len(output) > 100_000:
            raise ValueError("JSONPath traversal exceeds the node budget")
        stack.extend(reversed(_jsonpath_children(current)))
    return output


def _jsonpath_apply(node: tuple[Any, str], selector: tuple[str, Any]) -> list[tuple[Any, str]]:
    value, path = node
    kind, argument = selector
    if kind == "wildcard":
        return _jsonpath_children(node)
    if kind == "name":
        if isinstance(value, dict) and argument in value:
            return [(value[argument], path + "[" + json.dumps(argument, ensure_ascii=False) + "]")]
        return []
    if kind == "index":
        if isinstance(value, list) and -len(value) <= argument < len(value):
            actual = argument % len(value) if value else argument
            return [(value[argument], f"{path}[{actual}]")]
        return []
    if kind == "slice" and isinstance(value, list):
        return [(value[index], f"{path}[{index}]") for index in range(*argument.indices(len(value)))]
    return []


def jsonpath_query(
    *, document: Any,
    query: str,
    max_results: int = 100,
) -> dict[str, Any]:
    max_results = _require_int("max_results", max_results, 1, MAX_JSONPATH_RESULTS)
    document = _json_safe(document, maximum=MAX_TEXT)
    query = _require_text("query", query, 16 * 1024)
    if _JSONPATH_ENGINE is not None:
        values = list(_JSONPATH_ENGINE(document, query, max_results + 1))
        truncated = len(values) > max_results
        return _json_safe({
            "values": _json_safe(values[:max_results]),
            "count": min(len(values), max_results),
            "truncated": truncated,
            "engine": "registered-rfc9535",
            "warnings": [f"Results were limited to {max_results}"] if truncated else [],
        })
    nodes: list[tuple[Any, str]] = [(document, "$")]
    for recursive, selectors in _jsonpath_parse(query):
        selected: list[tuple[Any, str]] = []
        for node in nodes:
            candidates = _jsonpath_descendants(node) if recursive else [node]
            for candidate in candidates:
                for selector in selectors:
                    selected.extend(_jsonpath_apply(candidate, selector))
                    if len(selected) > max_results:
                        break
                if len(selected) > max_results:
                    break
            if len(selected) > max_results:
                break
        nodes = selected
    truncated = len(nodes) > max_results
    nodes = nodes[:max_results]
    warnings = [
        "Dependency-free JSONPath fallback supports RFC 9535 child, descendant, wildcard, index, union, and slice selectors; filters require a registered engine"
    ]
    if truncated:
        warnings.append(f"Results were limited to {max_results}")
    return _json_safe({
        "values": [node[0] for node in nodes],
        "paths": [node[1] for node in nodes],
        "count": len(nodes),
        "truncated": truncated,
        "engine": "builtin-rfc9535-subset",
        "warnings": warnings,
    })


def file_checksum(
    *,
    data: str,
    input_encoding: str = "text",
    algorithms: Sequence[str] = ("sha256",),
) -> dict[str, Any]:
    data = _require_text("data", data, 4 * 1024 * 1024)
    input_encoding = _require_text("input_encoding", input_encoding, 16).lower()
    try:
        if input_encoding == "text":
            raw = data.encode("utf-8")
        elif input_encoding == "base64":
            raw = base64.b64decode(data, validate=True)
        elif input_encoding == "base64url":
            raw = _b64url_decode(data, name="data", maximum=4 * 1024 * 1024)
        elif input_encoding == "hex":
            raw = bytes.fromhex(data)
        else:
            raise ValueError("input_encoding must be text, base64, base64url, or hex")
    except (binascii.Error, ValueError) as exc:
        if str(exc).startswith("input_encoding"):
            raise
        raise ValueError(f"data is not valid {input_encoding}") from exc
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("decoded data exceeds the 4 MiB limit")
    if isinstance(algorithms, str) or not isinstance(algorithms, Sequence):
        raise ValueError("algorithms must be an array")
    normalized = [str(value).lower().replace("-", "_") for value in algorithms]
    if not normalized or len(normalized) > 8 or len(set(normalized)) != len(normalized):
        raise ValueError("algorithms must contain 1-8 unique values")
    unknown = sorted(set(normalized) - set(_CHECKSUM_HASHES))
    if unknown:
        raise ValueError("unsupported checksum algorithms: " + ", ".join(unknown))
    digests = {name: _CHECKSUM_HASHES[name](raw).hexdigest() for name in normalized}
    warnings = []
    if "md5" in normalized or "sha1" in normalized:
        warnings.append("MD5 and SHA-1 are collision-prone and should not be used for security decisions")
    return {"bytes": len(raw), "digests": digests, "warnings": warnings}


def _datetime_from_epoch(timestamp: float) -> str:
    try:
        return _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError("identifier timestamp is outside the supported range") from exc


def _inspect_uuid(value: str) -> dict[str, Any]:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("value is not a valid UUID") from exc
    result: dict[str, Any] = {
        "type": "uuid",
        "canonical": str(parsed),
        "version": parsed.version,
        "variant": parsed.variant,
        "timestamp": None,
        "warnings": [],
    }
    if parsed.version == 1:
        unix = (parsed.time - 0x01B21DD213814000) / 10_000_000
        result["timestamp"] = {"epoch_seconds": unix, "iso8601": _datetime_from_epoch(unix)}
        result["node"] = f"{parsed.node:012x}"
        result["warnings"].append("UUIDv1 exposes a creation time and may expose a hardware-derived node")
    elif parsed.version == 6:
        timestamp_100ns = (((parsed.int >> 80) & ((1 << 48) - 1)) << 12) | ((parsed.int >> 64) & 0xFFF)
        unix = (timestamp_100ns - 0x01B21DD213814000) / 10_000_000
        result["timestamp"] = {"epoch_seconds": unix, "iso8601": _datetime_from_epoch(unix)}
        result["node"] = f"{parsed.node:012x}"
        result["warnings"].append("UUIDv6 exposes a creation time and may expose a hardware-derived node")
    elif parsed.version == 7:
        milliseconds = (parsed.int >> 80) & ((1 << 48) - 1)
        result["timestamp"] = {
            "epoch_milliseconds": milliseconds,
            "iso8601": _datetime_from_epoch(milliseconds / 1000),
        }
    return result


def _inspect_ulid(value: str) -> dict[str, Any]:
    canonical = value.upper()
    if len(canonical) != 26 or any(char not in _CROCKFORD_VALUES for char in canonical):
        raise ValueError("value is not a valid 26-character ULID")
    if canonical[0] > "7":
        raise ValueError("ULID exceeds 128 bits")
    number = 0
    for char in canonical:
        number = (number << 5) | _CROCKFORD_VALUES[char]
    milliseconds = number >> 80
    return {
        "type": "ulid",
        "canonical": canonical,
        "timestamp": {
            "epoch_milliseconds": milliseconds,
            "iso8601": _datetime_from_epoch(milliseconds / 1000),
        },
        "randomness_hex": (number & ((1 << 80) - 1)).to_bytes(10, "big").hex(),
        "warnings": [],
    }


def _inspect_objectid(value: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9A-Fa-f]{24}", value):
        raise ValueError("value is not a valid 24-character ObjectId")
    raw = bytes.fromhex(value)
    timestamp = int.from_bytes(raw[:4], "big")
    return {
        "type": "objectid",
        "canonical": value.lower(),
        "timestamp": {"epoch_seconds": timestamp, "iso8601": _datetime_from_epoch(timestamp)},
        "process_unique_hex": raw[4:9].hex(),
        "counter": int.from_bytes(raw[9:], "big"),
        "warnings": ["ObjectId exposes its creation time"],
    }


def inspect_identifier(*, value: str, kind: str = "auto") -> dict[str, Any]:
    value = _require_text("value", value, 256).strip()
    kind = _require_text("kind", kind, 16).lower()
    if kind not in {"auto", "uuid", "ulid", "objectid"}:
        raise ValueError("kind must be auto, uuid, ulid, or objectid")
    if kind == "auto":
        if re.fullmatch(r"[0-9A-Fa-f]{24}", value):
            kind = "objectid"
        elif len(value) == 26:
            kind = "ulid"
        else:
            kind = "uuid"
    if kind == "uuid":
        return _inspect_uuid(value)
    if kind == "ulid":
        return _inspect_ulid(value)
    return _inspect_objectid(value)


def user_agent_client_hints(*, user_agent: str) -> dict[str, Any]:
    user_agent = _require_text("user_agent", user_agent, 8192)
    if "\r" in user_agent or "\n" in user_agent:
        raise ValueError("user_agent must not contain header line breaks")
    headers: dict[str, str] = {"user-agent": user_agent}
    warnings = ["Client Hints are browser-controlled; this bundle is for request testing only"]
    chrome = re.search(r"(?:Chrome|Chromium)/(\d+)(?:\.([0-9.]+))?", user_agent)
    edge = re.search(r"Edg(?:A|iOS)?/(\d+)(?:\.([0-9.]+))?", user_agent)
    if not chrome:
        warnings.append("User-Agent is not Chromium-based, so Sec-CH-UA headers were not inferred")
        return {"headers": headers, "platform": None, "mobile": None, "warnings": warnings}
    chrome_major = chrome.group(1)
    chrome_full = chrome.group(0).split("/", 1)[1]
    brands = ['"Not.A/Brand";v="99"', f'"Chromium";v="{chrome_major}"']
    full_brands = ['"Not.A/Brand";v="99.0.0.0"', f'"Chromium";v="{chrome_full}"']
    if edge:
        edge_major = edge.group(1)
        edge_full = edge.group(0).split("/", 1)[1]
        brands.append(f'"Microsoft Edge";v="{edge_major}"')
        full_brands.append(f'"Microsoft Edge";v="{edge_full}"')
    else:
        brands.append(f'"Google Chrome";v="{chrome_major}"')
        full_brands.append(f'"Google Chrome";v="{chrome_full}"')
    mobile = bool(re.search(r"\bMobile\b", user_agent))
    if "Windows" in user_agent:
        platform, architecture, bitness = "Windows", "x86", "64" if re.search(r"Win64|x64", user_agent) else "32"
        version_match = re.search(r"Windows NT ([0-9.]+)", user_agent)
    elif "Android" in user_agent:
        platform, architecture, bitness = "Android", "arm", ""
        version_match = re.search(r"Android ([0-9.]+)", user_agent)
    elif re.search(r"iPhone|iPad", user_agent):
        platform, architecture, bitness = "iOS", "arm", ""
        version_match = re.search(r"OS ([0-9_]+)", user_agent)
    elif "Macintosh" in user_agent:
        platform, architecture, bitness = "macOS", "arm" if "ARM" in user_agent else "x86", "64"
        version_match = re.search(r"Mac OS X ([0-9_]+)", user_agent)
    elif "CrOS" in user_agent:
        platform, architecture, bitness = "Chrome OS", "x86", "64"
        version_match = None
    else:
        platform, architecture, bitness = "Linux", "x86", "64" if "x86_64" in user_agent else ""
        version_match = None
    platform_version = version_match.group(1).replace("_", ".") if version_match else ""
    headers.update(
        {
            "sec-ch-ua": ", ".join(brands),
            "sec-ch-ua-mobile": "?1" if mobile else "?0",
            "sec-ch-ua-platform": f'"{platform}"',
            "sec-ch-ua-full-version-list": ", ".join(full_brands),
            "sec-ch-ua-platform-version": f'"{platform_version}"',
            "sec-ch-ua-arch": f'"{architecture}"',
            "sec-ch-ua-bitness": f'"{bitness}"',
        }
    )
    return {"headers": headers, "platform": platform, "mobile": mobile, "warnings": warnings}


def oauth_state(*, nbytes: int = 32) -> dict[str, Any]:
    return random_nonce(purpose="state", nbytes=nbytes)


def oidc_nonce(*, nbytes: int = 32) -> dict[str, Any]:
    return random_nonce(purpose="oidc_nonce", nbytes=nbytes)


def csp_nonce(*, nbytes: int = 24) -> dict[str, Any]:
    return random_nonce(purpose="csp_nonce", nbytes=nbytes)


FeatureHandler = Callable[[dict[str, Any], dict[str, Any], int], dict[str, Any]]


def _make_handler(
    tool_id: str,
    function: Callable[..., dict[str, Any]],
    *,
    random_output: bool = False,
) -> FeatureHandler:
    def handler(
        inputs: dict[str, Any], options: dict[str, Any], count: int
    ) -> dict[str, Any]:
        input_values = _require_mapping("inputs", inputs)
        option_values = _require_mapping("options", options)
        collisions = sorted(set(input_values) & set(option_values))
        if collisions:
            raise ValueError("inputs and options repeat fields: " + ", ".join(collisions))
        requested = _require_int("count", count, 1, 1000)
        actual = requested if random_output else 1
        arguments = {**input_values, **option_values}
        records: list[dict[str, Any]] = []
        warnings: list[Any] = []
        seen_warnings: set[str] = set()
        if requested != actual:
            warning = "count is ignored for deterministic tools"
            warnings.append(warning)
            seen_warnings.add(json.dumps(warning))
        for _ in range(actual):
            record = function(**arguments)
            if not isinstance(record, dict):
                raise TypeError(f"{tool_id} handler returned a non-record value")
            record = _json_safe(record)
            nested = record.pop("warnings", [])
            if isinstance(nested, list):
                for warning in nested:
                    marker = json.dumps(warning, ensure_ascii=False, sort_keys=True)
                    if marker not in seen_warnings:
                        seen_warnings.add(marker)
                        warnings.append(warning)
            elif nested:
                record["warnings"] = nested
            records.append(record)
        data: Any = records if random_output and requested != 1 else records[0]
        response = {
            "tool": tool_id,
            "kind": "list" if isinstance(data, list) else "record",
            "data": data,
            "warnings": warnings,
            "meta": {"requested_count": requested, "count": actual, "random": random_output},
        }
        return _json_safe(response)

    handler.__name__ = f"handle_{tool_id}"
    return handler


FEATURE_METADATA: dict[str, dict[str, Any]] = {
    "password_policy": {"category": "Passwords", "sensitive_inputs": [], "random": True},
    "base32_encode": {"category": "Encoders", "sensitive_inputs": ["text"], "random": False},
    "base32_decode": {"category": "Encoders", "sensitive_inputs": ["value"], "random": False},
    "base32_secret": {"category": "Tokens", "sensitive_inputs": [], "random": True},
    "jwt_encode": {"category": "Web/API", "sensitive_inputs": ["claims", "secret"], "random": False},
    "jwt_decode": {"category": "Web/API", "sensitive_inputs": ["token", "secret"], "random": False},
    "jwt_verify": {"category": "Web/API", "sensitive_inputs": ["token", "secret"], "random": False},
    "hotp": {"category": "OTP", "sensitive_inputs": ["secret"], "random": False},
    "hotp_verify": {"category": "OTP", "sensitive_inputs": ["secret", "code"], "random": False},
    "totp": {"category": "OTP", "sensitive_inputs": ["secret"], "random": False},
    "totp_verify": {"category": "OTP", "sensitive_inputs": ["secret", "code"], "random": False},
    "otpauth_build": {"category": "OTP", "sensitive_inputs": ["secret"], "random": False},
    "otpauth_parse": {"category": "OTP", "sensitive_inputs": ["uri"], "random": False},
    "pkce_generate": {"category": "OAuth", "sensitive_inputs": [], "random": True},
    "pkce_challenge": {"category": "OAuth", "sensitive_inputs": ["verifier"], "random": False},
    "oauth_state": {"category": "OAuth", "sensitive_inputs": [], "random": True},
    "oidc_nonce": {"category": "OAuth", "sensitive_inputs": [], "random": True},
    "csp_nonce": {"category": "Web/API", "sensitive_inputs": [], "random": True},
    "webhook_sign": {"category": "Web/API", "sensitive_inputs": ["payload", "secret"], "random": False},
    "webhook_verify": {
        "category": "Web/API",
        "sensitive_inputs": ["payload", "secret", "signature"],
        "random": False,
    },
    "dotenv": {"category": "Config", "sensitive_inputs": ["text", "other"], "random": False},
    "timestamp": {"category": "Date/Time", "sensitive_inputs": [], "random": False},
    "regex": {"category": "Text", "sensitive_inputs": ["text"], "random": False},
    "jsonpath": {"category": "JSON", "sensitive_inputs": ["document"], "random": False},
    "checksum": {"category": "Hashing", "sensitive_inputs": ["data"], "random": False},
    "id_inspect": {"category": "IDs", "sensitive_inputs": [], "random": False},
    "user_agent_hints": {"category": "Web/API", "sensitive_inputs": [], "random": False},
}


FEATURE_HANDLERS: dict[str, FeatureHandler] = {
    "password_policy": _make_handler("password_policy", password_policy, random_output=True),
    "base32_encode": _make_handler("base32_encode", base32_encode),
    "base32_decode": _make_handler("base32_decode", base32_decode),
    "base32_secret": _make_handler("base32_secret", base32_secret, random_output=True),
    "jwt_encode": _make_handler("jwt_encode", jwt_encode),
    "jwt_decode": _make_handler("jwt_decode", jwt_decode),
    "jwt_verify": _make_handler("jwt_verify", jwt_verify),
    "hotp": _make_handler("hotp", hotp),
    "hotp_verify": _make_handler("hotp_verify", hotp_verify),
    "totp": _make_handler("totp", totp),
    "totp_verify": _make_handler("totp_verify", totp_verify),
    "otpauth_build": _make_handler("otpauth_build", otpauth_build),
    "otpauth_parse": _make_handler("otpauth_parse", otpauth_parse),
    "pkce_generate": _make_handler("pkce_generate", pkce_generate, random_output=True),
    "pkce_challenge": _make_handler("pkce_challenge", pkce_challenge),
    "oauth_state": _make_handler("oauth_state", oauth_state, random_output=True),
    "oidc_nonce": _make_handler("oidc_nonce", oidc_nonce, random_output=True),
    "csp_nonce": _make_handler("csp_nonce", csp_nonce, random_output=True),
    "webhook_sign": _make_handler("webhook_sign", webhook_hmac),
    "webhook_verify": _make_handler("webhook_verify", webhook_verify),
    "dotenv": _make_handler("dotenv", dotenv_tool),
    "timestamp": _make_handler("timestamp", timestamp_convert),
    "regex": _make_handler("regex", regex_test),
    "jsonpath": _make_handler("jsonpath", jsonpath_query),
    "checksum": _make_handler("checksum", file_checksum),
    "id_inspect": _make_handler("id_inspect", inspect_identifier),
    "user_agent_hints": _make_handler("user_agent_hints", user_agent_client_hints),
}


def run_feature(
    tool_id: str,
    inputs: Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
    count: int = 1,
) -> dict[str, Any]:
    """Dispatch a feature through the integration-friendly handler contract."""

    tool_id = _require_text("tool_id", tool_id, 128)
    try:
        handler = FEATURE_HANDLERS[tool_id]
    except KeyError as exc:
        raise KeyError(f"unknown feature: {tool_id}") from exc
    return handler(dict(inputs or {}), dict(options or {}), count)
