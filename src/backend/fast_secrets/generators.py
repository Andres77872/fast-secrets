"""Core secret generators.

Pure functions, cryptographically secure. Every random draw uses Python's
``secrets`` module (a CSPRNG) — never ``random``. This module has **no** FastAPI
imports so it can be imported and unit-tested in isolation.

Each function returns a single secret as a ``str``; callers handle ``count``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as _hmac
import ipaddress
import json
import re
import secrets
import string
import time
import urllib.parse
import uuid as _uuid

from .wordlist import WORDS

# --- character sets ---------------------------------------------------------
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"
# Visually confusing characters, dropped when ``exclude_ambiguous`` is on.
AMBIGUOUS = "Il1O0o"
# Crockford base32 alphabet used by ULID (no I, L, O, U).
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# Default Nano ID alphabet: 64 URL-safe characters.
NANOID_ALPHABET = "_-" + DIGITS + UPPERCASE + LOWERCASE

CHARSET_PRESETS = {
    "alphanumeric": LOWERCASE + UPPERCASE + DIGITS,
    "alpha": LOWERCASE + UPPERCASE,
    "lower": LOWERCASE,
    "upper": UPPERCASE,
    "numeric": DIGITS,
    "hex": "0123456789abcdef",
    "hex_upper": "0123456789ABCDEF",
}

LOREM_WORDS = (
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt "
    "ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation "
    "ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in "
    "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur"
).split()

USER_AGENT_BROWSER_WEIGHTS = [
    # StatCounter Global Stats, Browser Market Share Worldwide, June 2026.
    ("chrome", 6965),
    ("safari", 1531),
    ("edge", 521),
    ("firefox", 333),
    ("samsung", 195),
    ("opera", 174),
]
USER_AGENT_PLATFORM_WEIGHTS = [
    # StatCounter Global Stats, Desktop vs Mobile vs Tablet Worldwide, June 2026.
    ("mobile", 5151),
    ("desktop", 4712),
    ("tablet", 136),
]

REAL_USER_AGENT_DATASET = (
    # Compact sample from fake-useragent's April 2025 JSONL data, sourced from
    # user-agents.net. The full upstream file is ~3.8 MB, too large for this app.
    {
        "browser": "chrome",
        "platform": "desktop",
        "weight": 64,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    },
    {
        "browser": "chrome",
        "platform": "desktop",
        "weight": 51,
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    },
    {
        "browser": "chrome",
        "platform": "desktop",
        "weight": 31,
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    },
    {
        "browser": "chrome",
        "platform": "mobile",
        "weight": 80,
        "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
    },
    {
        "browser": "safari",
        "platform": "desktop",
        "weight": 58,
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
    },
    {
        "browser": "safari",
        "platform": "mobile",
        "weight": 94,
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
    },
    {
        "browser": "safari",
        "platform": "tablet",
        "weight": 12,
        "ua": "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
    },
    {
        "browser": "edge",
        "platform": "desktop",
        "weight": 48,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
    },
    {
        "browser": "edge",
        "platform": "mobile",
        "weight": 30,
        "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36 EdgA/137.0.0.0",
    },
    {
        "browser": "edge",
        "platform": "tablet",
        "weight": 1,
        "ua": "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/134.0.3124.68 Version/17.0 Mobile/15E148 Safari/604.1",
    },
    {
        "browser": "firefox",
        "platform": "desktop",
        "weight": 56,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0",
    },
    {
        "browser": "firefox",
        "platform": "desktop",
        "weight": 40,
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0",
    },
    {
        "browser": "firefox",
        "platform": "mobile",
        "weight": 32,
        "ua": "Mozilla/5.0 (Android 10; Mobile; rv:139.0) Gecko/139.0 Firefox/139.0",
    },
    {
        "browser": "samsung",
        "platform": "mobile",
        "weight": 51,
        "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36",
    },
    {
        "browser": "opera",
        "platform": "desktop",
        "weight": 26,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/119.0.0.0",
    },
    {
        "browser": "opera",
        "platform": "mobile",
        "weight": 12,
        "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36 OPR/90.0.0.0",
    },
)

UA_CLIENTS = (
    "curl/{curl_version}",
    "PostmanRuntime/7.{minor}.{patch}",
    "python-requests/2.{minor}.0",
    "HTTPie/3.2.{patch}",
    "Wget/1.21.{patch}",
    "Go-http-client/1.1",
)

UA_CRAWLERS = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
)


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def _shuffle(items: list) -> None:
    """In-place Fisher-Yates shuffle backed by the CSPRNG."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def _choice(items):
    return items[secrets.randbelow(len(items))]


def _weighted_choice(items: list[tuple[str, int]]) -> str:
    total = sum(weight for _, weight in items)
    pick = secrets.randbelow(total)
    upto = 0
    for value, weight in items:
        upto += weight
        if pick < upto:
            return value
    return items[-1][0]


def _weighted_record(items: list[dict]) -> dict:
    total = sum(item["weight"] for item in items)
    pick = secrets.randbelow(total)
    upto = 0
    for item in items:
        upto += item["weight"]
        if pick < upto:
            return item
    return items[-1]


def _randint(lo: int, hi: int) -> int:
    return lo + secrets.randbelow(hi - lo + 1)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    try:
        s = text.encode("ascii")
        s += b"=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("Invalid base64url input") from exc


# --- passwords & random strings --------------------------------------------
def password(
    length: int = 16,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Random password drawn from the selected character classes.

    Guarantees at least one character from every enabled class (when the
    requested length leaves room), then shuffles so positions are unbiased.
    """
    length = _clamp(int(length), 4, 256)
    pools = []
    if lowercase:
        pools.append(LOWERCASE)
    if uppercase:
        pools.append(UPPERCASE)
    if digits:
        pools.append(DIGITS)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("Enable at least one character class")

    if exclude_ambiguous:
        filtered = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]
        pools = [p for p in filtered if p]
        if not pools:
            raise ValueError("No characters left after excluding ambiguous ones")

    full = "".join(pools)
    if length < len(pools):
        chars = [secrets.choice(full) for _ in range(length)]
    else:
        chars = [secrets.choice(pool) for pool in pools]
        chars += [secrets.choice(full) for _ in range(length - len(pools))]
    _shuffle(chars)
    return "".join(chars)


def random_string(length: int = 32, charset: str = "alphanumeric", custom_charset: str = "") -> str:
    """Random string over a preset or custom character set."""
    length = _clamp(int(length), 1, 1024)
    if charset == "custom":
        pool = custom_charset or CHARSET_PRESETS["alphanumeric"]
    else:
        pool = CHARSET_PRESETS.get(charset, CHARSET_PRESETS["alphanumeric"])
    pool = "".join(dict.fromkeys(pool))  # dedupe, keep order
    if not pool:
        raise ValueError("Charset is empty")
    return "".join(secrets.choice(pool) for _ in range(length))


def pin(length: int = 6) -> str:
    """Numeric PIN / OTP, leading zeros preserved."""
    length = _clamp(int(length), 3, 12)
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def passphrase(
    words: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
) -> str:
    """Diceware-style passphrase from the EFF short wordlist."""
    words = _clamp(int(words), 2, 16)
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        chosen = [w.title() for w in chosen]
    if add_number:
        idx = secrets.randbelow(len(chosen))
        chosen[idx] = f"{chosen[idx]}{secrets.randbelow(10)}"
    return separator.join(chosen)


# --- tokens -----------------------------------------------------------------
def hex_token(nbytes: int = 32, uppercase: bool = False) -> str:
    """Hex-encoded random token (``secrets.token_hex``)."""
    s = secrets.token_hex(_clamp(int(nbytes), 1, 512))
    return s.upper() if uppercase else s


def urlsafe_token(nbytes: int = 32) -> str:
    """URL-safe base64 token without padding (``secrets.token_urlsafe``)."""
    return secrets.token_urlsafe(_clamp(int(nbytes), 1, 512))


def base64_token(nbytes: int = 32, urlsafe: bool = False) -> str:
    """Base64-encoded random bytes (standard or URL-safe alphabet)."""
    raw = secrets.token_bytes(_clamp(int(nbytes), 1, 512))
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return enc(raw).decode("ascii")


def api_key(prefix: str = "sk", separator: str = "_", nbytes: int = 24, encoding: str = "urlsafe") -> str:
    """Prefixed API key, e.g. ``sk_AbC123...`` (Stripe-style)."""
    raw = secrets.token_bytes(_clamp(int(nbytes), 8, 256))
    if encoding == "hex":
        body = raw.hex()
    else:
        body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return f"{prefix}{separator}{body}" if prefix else body


# --- identifiers ------------------------------------------------------------
def _uuid6() -> _uuid.UUID:
    """RFC 9562 UUIDv6 — v1 fields reordered so the timestamp sorts naturally."""
    u1 = _uuid.uuid1()
    ts = u1.time & 0x0FFFFFFFFFFFFFFF  # 60-bit Gregorian timestamp
    time_high = (ts >> 28) & 0xFFFFFFFF
    time_mid = (ts >> 12) & 0xFFFF
    time_low = ts & 0xFFF
    msb = (time_high << 32) | (time_mid << 16) | (0x6 << 12) | time_low
    lsb = (0b10 << 62) | ((u1.clock_seq & 0x3FFF) << 48) | (u1.node & 0xFFFFFFFFFFFF)
    return _uuid.UUID(int=(msb << 64) | lsb)


def _uuid7() -> _uuid.UUID:
    """RFC 9562 UUIDv7 — 48-bit Unix-ms timestamp + 74 random bits."""
    ms = time.time_ns() // 1_000_000
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    msb = ((ms & 0xFFFFFFFFFFFF) << 16) | (0x7 << 12) | rand_a
    lsb = (0b10 << 62) | rand_b
    return _uuid.UUID(int=(msb << 64) | lsb)


def uuid(version: int = 4, uppercase: bool = False, hyphens: bool = True) -> str:
    """UUID string for version 1, 4, 6 or 7."""
    version = int(version)
    if version == 1:
        u = _uuid.uuid1()
    elif version == 4:
        u = _uuid.uuid4()
    elif version == 6:
        u = _uuid6()
    elif version == 7:
        u = _uuid7()
    else:
        raise ValueError(f"Unsupported UUID version: {version}")
    s = str(u)
    if not hyphens:
        s = s.replace("-", "")
    return s.upper() if uppercase else s


def ulid(uppercase: bool = True) -> str:
    """Lexicographically sortable 26-char ULID (48-bit time + 80-bit random)."""
    ms = time.time_ns() // 1_000_000
    value = ((ms & ((1 << 48) - 1)) << 80) | secrets.randbits(80)
    chars = []
    for _ in range(26):
        chars.append(CROCKFORD[value & 0x1F])
        value >>= 5
    s = "".join(reversed(chars))
    return s if uppercase else s.lower()


def nanoid(size: int = 21, alphabet: str = NANOID_ALPHABET) -> str:
    """Nano ID — compact, URL-safe, uniformly random over ``alphabet``."""
    size = _clamp(int(size), 2, 256)
    pool = "".join(dict.fromkeys(alphabet or NANOID_ALPHABET))
    if len(pool) < 2:
        raise ValueError("Nano ID alphabet must contain at least two unique characters")
    return "".join(secrets.choice(pool) for _ in range(size))


# --- hashing (input-derived, not random) -----------------------------------
def hash_text(text: str = "", algorithm: str = "sha256", uppercase: bool = False) -> str:
    """Hex digest of ``text`` for md5 / sha1 / sha256 / sha512."""
    algo = algorithm.lower()
    if algo not in ("md5", "sha1", "sha256", "sha512"):
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    digest = hashlib.new(algo, text.encode("utf-8")).hexdigest()
    return digest.upper() if uppercase else digest


def hmac_text(text: str = "", key: str = "", algorithm: str = "sha256", uppercase: bool = False) -> str:
    """Keyed HMAC hex digest of ``text`` for sha256 / sha512."""
    algo = algorithm.lower()
    if algo not in ("sha256", "sha512"):
        raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
    digest = _hmac.new(key.encode("utf-8"), text.encode("utf-8"), algo).hexdigest()
    return digest.upper() if uppercase else digest


# --- encoders / decoders ----------------------------------------------------
def base64_text(text: str = "", mode: str = "encode", urlsafe: bool = False, padding: bool = True) -> str:
    """Encode/decode UTF-8 text as Base64 or URL-safe Base64."""
    if mode == "decode":
        compact = "".join(text.split())
        try:
            raw = compact.encode("ascii")
            raw += b"=" * (-len(raw) % 4)
            decoded = base64.b64decode(raw, altchars=b"-_" if urlsafe else None, validate=True)
            return decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, UnicodeEncodeError) as exc:
            raise ValueError("Invalid Base64 input or decoded bytes are not UTF-8") from exc

    raw = text.encode("utf-8")
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    out = enc(raw).decode("ascii")
    return out if padding else out.rstrip("=")


def url_codec(text: str = "", mode: str = "encode", component: bool = True, plus_spaces: bool = False) -> str:
    """Encode/decode URL text using percent-encoding."""
    if mode == "decode":
        return urllib.parse.unquote_plus(text) if plus_spaces else urllib.parse.unquote(text)
    safe = "" if component else "/:?&=#[]@!$&'()*+,;%"
    quote = urllib.parse.quote_plus if plus_spaces else urllib.parse.quote
    return quote(text, safe=safe)


def basic_auth(username: str = "user", password: str = "password", include_scheme: bool = True) -> str:
    """HTTP Basic Authorization header value."""
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}" if include_scheme else token


# --- structured data tools --------------------------------------------------
def _json_summary(value) -> str:
    if isinstance(value, dict):
        kind = "object"
        detail = f"{len(value)} keys"
    elif isinstance(value, list):
        kind = "array"
        detail = f"{len(value)} items"
    else:
        kind = type(value).__name__
        detail = "scalar"
    return f"Valid JSON\nType: {kind}\nSize: {detail}"


def json_format(text: str = "", mode: str = "format", indent: int = 2, sort_keys: bool = False) -> str:
    """Format, minify, or validate JSON text."""
    if not text.strip():
        raise ValueError("Enter JSON input")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc

    if mode == "validate":
        return _json_summary(value)
    if mode == "minify":
        return json.dumps(value, ensure_ascii=False, sort_keys=sort_keys, separators=(",", ":"))
    indent = _clamp(int(indent), 1, 8)
    return json.dumps(value, ensure_ascii=False, sort_keys=sort_keys, indent=indent)


def jwt_token(
    subject: str = "user_123",
    issuer: str = "fast-secrets",
    audience: str = "local-dev",
    ttl_seconds: int = 3600,
    secret: str = "dev-secret",
    algorithm: str = "HS256",
    include_jti: bool = True,
) -> str:
    """Development JWT signed with HS256/HS512, or alg=none for local fixtures."""
    algo = algorithm.upper()
    if algo not in ("HS256", "HS512", "NONE"):
        raise ValueError(f"Unsupported JWT algorithm: {algorithm}")
    now = int(time.time())
    ttl = _clamp(int(ttl_seconds), 60, 31_536_000)
    header = {"typ": "JWT", "alg": "none" if algo == "NONE" else algo}
    payload = {
        "sub": subject or "user_123",
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    if include_jti:
        payload["jti"] = str(_uuid.uuid4())

    signing_input = ".".join([
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ])
    if algo == "NONE":
        return signing_input + "."
    digest = "sha512" if algo == "HS512" else "sha256"
    sig = _hmac.new((secret or "dev-secret").encode("utf-8"), signing_input.encode("ascii"), digest).digest()
    return signing_input + "." + _b64url(sig)


def jwt_decode(token: str = "", pretty: bool = True) -> str:
    """Decode a JWT header/payload without verifying its signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three dot-separated parts")
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JWT header or payload is not valid JSON") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header and payload must be JSON objects")

    meta = {
        "header": header,
        "payload": payload,
        "signature_bytes": len(_b64url_decode(parts[2])) if parts[2] else 0,
        "verified": False,
    }
    warnings = []
    for key in ("iat", "nbf", "exp"):
        if isinstance(payload.get(key), int):
            try:
                meta[f"{key}_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(payload[key]))
            except (OverflowError, OSError, ValueError):
                warnings.append(f"{key} is outside the supported timestamp range")
    if warnings:
        meta["warnings"] = warnings
    return json.dumps(meta, indent=2 if pretty else None, sort_keys=False)


# --- user agents / network fixtures ----------------------------------------
def _chrome_version(reduced: bool = True) -> str:
    major = _randint(139, 143)
    if reduced:
        return f"{major}.0.0.0"
    return f"{major}.0.{_randint(7000, 7600)}.{_randint(40, 160)}"


def _edge_version(reduced: bool = True) -> str:
    major = _randint(139, 143)
    return f"{major}.0.0.0" if reduced else f"{major}.0.{_randint(3000, 3600)}.{_randint(30, 120)}"


def _firefox_version() -> str:
    return f"{_randint(140, 146)}.0"


def _desktop_system(browser: str) -> str:
    if browser == "safari":
        return "Macintosh; Intel Mac OS X 10_15_7"
    return _weighted_choice([
        ("Windows NT 10.0; Win64; x64", 650),
        ("Macintosh; Intel Mac OS X 10_15_7", 250),
        ("X11; Linux x86_64", 100),
    ])


def _android_system(reduced: bool, tablet: bool = False) -> str:
    if reduced:
        return "Linux; Android 10; K"
    phones = ("Pixel 9", "SM-S928B", "SM-S921U", "CPH2581", "M2012K11AC")
    tablets = ("SM-X910", "Pixel Tablet", "Lenovo TB350FU")
    device = _choice(tablets if tablet else phones)
    return f"Linux; Android {_choice(('14', '15', '16'))}; {device}"


def _ios_system(tablet: bool = False) -> str:
    version = _choice(("18_5", "18_6", "26_0"))
    return f"iPad; CPU OS {version} like Mac OS X" if tablet else f"iPhone; CPU iPhone OS {version} like Mac OS X"


def _blink_user_agent(browser: str, platform: str, reduced: bool) -> str:
    tablet = platform == "tablet"
    mobile = platform == "mobile"
    chrome = _chrome_version(reduced)
    if platform == "desktop":
        system = _desktop_system(browser)
        base = f"Mozilla/5.0 ({system}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome} Safari/537.36"
        if browser == "edge":
            return f"{base} Edg/{_edge_version(reduced)}"
        if browser == "opera":
            return f"{base} OPR/{_randint(121, 126)}.0.0.0"
        return base

    system = _android_system(reduced, tablet=tablet)
    mobile_part = " Mobile" if mobile else ""
    base = f"Mozilla/5.0 ({system}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome}{mobile_part} Safari/537.36"
    if browser == "edge":
        return f"{base} EdgA/{_edge_version(reduced)}"
    if browser == "opera":
        return f"{base} OPR/{_randint(91, 94)}.0.0.0"
    if browser == "samsung":
        return f"{base} SamsungBrowser/{_randint(25, 29)}.0"
    return base


def _safari_user_agent(platform: str) -> str:
    if platform == "desktop":
        return (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/26.0 Safari/605.1.15"
        )
    tablet = platform == "tablet"
    return (
        f"Mozilla/5.0 ({_ios_system(tablet=tablet)}) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
    )


def _firefox_user_agent(platform: str) -> str:
    version = _firefox_version()
    if platform == "desktop":
        return f"Mozilla/5.0 ({_desktop_system('firefox')}; rv:{version}) Gecko/20100101 Firefox/{version}"
    mobile = "Tablet" if platform == "tablet" else "Mobile"
    return f"Mozilla/5.0 (Android 16; {mobile}; rv:{version}) Gecko/{version} Firefox/{version}"


def _real_user_agent(browser: str, platform: str) -> str | None:
    matches = [
        row for row in REAL_USER_AGENT_DATASET
        if row["browser"] == browser and row["platform"] == platform
    ]
    if not matches:
        return None
    return _weighted_record(matches)["ua"]


def _real_user_agent_from_filters(browser: str, platform: str) -> str | None:
    matches = list(REAL_USER_AGENT_DATASET)
    if browser != "weighted":
        matches = [row for row in matches if row["browser"] == browser]
    if platform != "weighted":
        matches = [row for row in matches if row["platform"] == platform]
    if not matches:
        return None
    return _weighted_record(matches)["ua"]


def _template_user_agent(browser: str, platform: str, reduced: bool) -> str:
    if browser == "safari":
        return _safari_user_agent(platform)
    if browser == "firefox":
        return _firefox_user_agent(platform)
    if browser in ("chrome", "edge", "opera", "samsung"):
        return _blink_user_agent(browser, platform, reduced)
    raise ValueError(f"Unsupported browser: {browser}")


def user_agent(
    agent_type: str = "browser",
    browser: str = "weighted",
    platform: str = "weighted",
    reduced: bool = True,
    source: str = "auto",
) -> str:
    """Random modern User-Agent string, weighted toward common browsers/platforms."""
    if agent_type not in ("browser", "crawler", "client"):
        raise ValueError(f"Unsupported user-agent type: {agent_type}")
    if browser not in ("weighted", "chrome", "safari", "edge", "firefox", "samsung", "opera"):
        raise ValueError(f"Unsupported browser: {browser}")
    if platform not in ("weighted", "desktop", "mobile", "tablet"):
        raise ValueError(f"Unsupported platform: {platform}")
    if source not in ("auto", "dataset", "template"):
        raise ValueError(f"Unsupported user-agent source: {source}")

    if agent_type == "crawler":
        return _choice(UA_CRAWLERS)
    if agent_type == "client":
        template = _choice(UA_CLIENTS)
        return template.format(
            curl_version=f"{_randint(7, 8)}.{_randint(60, 89)}.{_randint(0, 9)}",
            minor=_randint(26, 40),
            patch=_randint(0, 9),
        )

    if source == "dataset":
        sampled = _real_user_agent_from_filters(browser, platform)
        if sampled is None:
            raise ValueError(f"No real sample for browser={browser}, platform={platform}")
        return sampled

    chosen_platform = _weighted_choice(USER_AGENT_PLATFORM_WEIGHTS) if platform == "weighted" else platform
    browser_weights = USER_AGENT_BROWSER_WEIGHTS
    if chosen_platform == "desktop":
        browser_weights = [(name, weight) for name, weight in browser_weights if name != "samsung"]
    chosen_browser = _weighted_choice(browser_weights) if browser == "weighted" else browser

    if chosen_browser == "samsung":
        chosen_platform = "tablet" if chosen_platform == "tablet" else "mobile"

    if source == "auto":
        sampled = _real_user_agent(chosen_browser, chosen_platform)
        if sampled is not None:
            return sampled

    return _template_user_agent(chosen_browser, chosen_platform, reduced)


def ipv4_address(kind: str = "private") -> str:
    """IPv4 fixture address from private, documentation, or loopback ranges."""
    if kind == "documentation":
        prefix = _choice(((192, 0, 2), (198, 51, 100), (203, 0, 113)))
        return f"{prefix[0]}.{prefix[1]}.{prefix[2]}.{_randint(1, 254)}"
    if kind == "loopback":
        return f"127.{_randint(0, 255)}.{_randint(0, 255)}.{_randint(1, 254)}"
    if kind == "public":
        # Avoid special-use networks by using documentation ranges unless the caller opts out later.
        return ipv4_address("documentation")
    private = secrets.randbelow(3)
    if private == 0:
        return f"10.{_randint(0, 255)}.{_randint(0, 255)}.{_randint(1, 254)}"
    if private == 1:
        return f"172.{_randint(16, 31)}.{_randint(0, 255)}.{_randint(1, 254)}"
    return f"192.168.{_randint(0, 255)}.{_randint(1, 254)}"


def ipv6_address(kind: str = "documentation") -> str:
    """IPv6 fixture address from documentation, unique-local, or loopback ranges."""
    if kind == "loopback":
        return "::1"
    if kind == "ula":
        value = (0xFD << 120) | secrets.randbits(120)
    else:
        value = (0x20010DB8 << 96) | secrets.randbits(96)
    return str(ipaddress.IPv6Address(value))


def mac_address(separator: str = ":", uppercase: bool = False, locally_administered: bool = True) -> str:
    """Random MAC address, locally administered by default."""
    sep = separator if separator in (":", "-", "") else ":"
    octets = [secrets.randbelow(256) for _ in range(6)]
    if locally_administered:
        octets[0] = (octets[0] | 0b00000010) & 0b11111110
    text = sep.join(f"{b:02x}" for b in octets)
    return text.upper() if uppercase else text


# --- application fixture data ----------------------------------------------
def email_address(domain: str = "example.com", plus_tag: bool = False) -> str:
    """Random safe email fixture, defaulting to the reserved example.com domain."""
    clean_domain = domain.strip().lower().removeprefix("@") or "example.com"
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", clean_domain):
        clean_domain = "example.com"
    local = f"{_choice(WORDS)}.{_choice(WORDS)}{_randint(10, 9999)}"
    if plus_tag:
        local += f"+{_choice(('dev', 'test', 'qa', 'local'))}"
    return f"{local}@{clean_domain}"


def semver(include_prerelease: bool = False, include_build: bool = False) -> str:
    """Random semantic version string."""
    version = f"{_randint(0, 4)}.{_randint(0, 20)}.{_randint(0, 50)}"
    if include_prerelease:
        version += f"-{_choice(('alpha', 'beta', 'rc'))}.{_randint(1, 9)}"
    if include_build:
        version += f"+{hex_token(3)}"
    return version


def mongo_object_id(uppercase: bool = False) -> str:
    """MongoDB-style 24-character ObjectId hex string."""
    ts = int(time.time()).to_bytes(4, "big")
    body = ts + secrets.token_bytes(5) + secrets.randbelow(0xFFFFFF).to_bytes(3, "big")
    text = body.hex()
    return text.upper() if uppercase else text


def lorem_ipsum(paragraphs: int = 1, sentences: int = 3, words_per_sentence: int = 12) -> str:
    """Lorem ipsum text for UI and API fixtures."""
    paragraphs = _clamp(int(paragraphs), 1, 8)
    sentences = _clamp(int(sentences), 1, 12)
    words_per_sentence = _clamp(int(words_per_sentence), 4, 30)
    out = []
    for _ in range(paragraphs):
        lines = []
        for _ in range(sentences):
            words = [_choice(LOREM_WORDS) for _ in range(words_per_sentence)]
            lines.append(" ".join(words).capitalize() + ".")
        out.append(" ".join(lines))
    return "\n\n".join(out)


# --- text utilities ---------------------------------------------------------
def _text_words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9]+", text)


def text_case(text: str = "", case: str = "snake") -> str:
    """Convert text between common identifier/display cases."""
    words = _text_words(text)
    if not words:
        return ""
    lowered = [w.lower() for w in words]
    if case == "camel":
        return lowered[0] + "".join(w.capitalize() for w in lowered[1:])
    if case == "pascal":
        return "".join(w.capitalize() for w in lowered)
    if case == "kebab":
        return "-".join(lowered)
    if case == "slug":
        return "-".join(lowered)
    if case == "constant":
        return "_".join(lowered).upper()
    if case == "title":
        return " ".join(w.capitalize() for w in lowered)
    if case == "upper":
        return text.upper()
    if case == "lower":
        return text.lower()
    return "_".join(lowered)
