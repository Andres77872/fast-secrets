"""Core secret generators.

Pure functions, cryptographically secure. Every random draw uses Python's
``secrets`` module (a CSPRNG) — never ``random``. This module has **no** FastAPI
imports so it can be imported and unit-tested in isolation.

Each function returns a single secret as a ``str``; callers handle ``count``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import secrets
import string
import time
import uuid as _uuid

from wordlist import WORDS

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


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def _shuffle(items: list) -> None:
    """In-place Fisher-Yates shuffle backed by the CSPRNG."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


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
    if length <= len(pools):
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
        chosen = [w.capitalize() for w in chosen]
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
    pool = alphabet or NANOID_ALPHABET
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
