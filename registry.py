"""Generator registry — the single source of truth.

Each entry pairs a generator function with UI/validation metadata. The API serves
the metadata (``public_metadata``), the web UI renders forms from it, and
``generate`` dispatches by id. Adding a generator means adding one entry here.

Option schema per field::

    {"key", "label", "type", "default", ...}

``type`` is one of: ``int`` (with ``min``/``max``), ``bool``, ``select`` (with
``choices`` = list of {value, label}), ``string``, ``text`` (multiline).
"""

from __future__ import annotations

import generators as g

GENERATORS = [
    # --- identifiers --------------------------------------------------------
    {
        "id": "uuid",
        "label": "UUID",
        "category": "IDs",
        "description": "RFC 9562 universally unique identifier (v1/v4/v6/v7).",
        "fn": g.uuid,
        "options": [
            {"key": "version", "label": "Version", "type": "select", "default": 4, "choices": [
                {"value": 4, "label": "v4 (random)"},
                {"value": 7, "label": "v7 (time-sortable)"},
                {"value": 1, "label": "v1 (time + MAC)"},
                {"value": 6, "label": "v6 (reordered time)"},
            ]},
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": False},
            {"key": "hyphens", "label": "Hyphens", "type": "bool", "default": True},
        ],
    },
    {
        "id": "ulid",
        "label": "ULID",
        "category": "IDs",
        "description": "Lexicographically sortable 26-char identifier (Crockford base32).",
        "fn": g.ulid,
        "options": [
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": True},
        ],
    },
    {
        "id": "nanoid",
        "label": "Nano ID",
        "category": "IDs",
        "description": "Compact URL-safe identifier with a configurable size and alphabet.",
        "fn": g.nanoid,
        "options": [
            {"key": "size", "label": "Size", "type": "int", "default": 21, "min": 2, "max": 256},
            {"key": "alphabet", "label": "Alphabet", "type": "string", "default": g.NANOID_ALPHABET},
        ],
    },
    # --- tokens -------------------------------------------------------------
    {
        "id": "hex",
        "label": "Hex token",
        "category": "Tokens",
        "description": "Hex-encoded random bytes (secrets.token_hex).",
        "fn": g.hex_token,
        "options": [
            {"key": "nbytes", "label": "Bytes", "type": "int", "default": 32, "min": 1, "max": 512},
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": False},
        ],
    },
    {
        "id": "urlsafe",
        "label": "URL-safe token",
        "category": "Tokens",
        "description": "URL-safe base64 token without padding (secrets.token_urlsafe).",
        "fn": g.urlsafe_token,
        "options": [
            {"key": "nbytes", "label": "Bytes", "type": "int", "default": 32, "min": 1, "max": 512},
        ],
    },
    {
        "id": "base64",
        "label": "Base64 secret",
        "category": "Tokens",
        "description": "Base64-encoded random bytes (standard or URL-safe alphabet).",
        "fn": g.base64_token,
        "options": [
            {"key": "nbytes", "label": "Bytes", "type": "int", "default": 32, "min": 1, "max": 512},
            {"key": "urlsafe", "label": "URL-safe alphabet", "type": "bool", "default": False},
        ],
    },
    {
        "id": "apikey",
        "label": "API key",
        "category": "Tokens",
        "description": "Prefixed API key such as sk_AbC123… (Stripe-style).",
        "fn": g.api_key,
        "options": [
            {"key": "prefix", "label": "Prefix", "type": "string", "default": "sk"},
            {"key": "separator", "label": "Separator", "type": "string", "default": "_"},
            {"key": "nbytes", "label": "Bytes", "type": "int", "default": 24, "min": 8, "max": 256},
            {"key": "encoding", "label": "Encoding", "type": "select", "default": "urlsafe", "choices": [
                {"value": "urlsafe", "label": "URL-safe base64"},
                {"value": "hex", "label": "Hex"},
            ]},
        ],
    },
    # --- passwords ----------------------------------------------------------
    {
        "id": "password",
        "label": "Password",
        "category": "Passwords",
        "description": "Strong password with configurable character classes.",
        "fn": g.password,
        "options": [
            {"key": "length", "label": "Length", "type": "int", "default": 16, "min": 4, "max": 256},
            {"key": "lowercase", "label": "Lowercase", "type": "bool", "default": True},
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": True},
            {"key": "digits", "label": "Digits", "type": "bool", "default": True},
            {"key": "symbols", "label": "Symbols", "type": "bool", "default": True},
            {"key": "exclude_ambiguous", "label": "Exclude ambiguous (Il1O0o)", "type": "bool", "default": False},
        ],
    },
    {
        "id": "string",
        "label": "Random string",
        "category": "Passwords",
        "description": "Random string over a preset or custom character set.",
        "fn": g.random_string,
        "options": [
            {"key": "length", "label": "Length", "type": "int", "default": 32, "min": 1, "max": 1024},
            {"key": "charset", "label": "Charset", "type": "select", "default": "alphanumeric", "choices": [
                {"value": "alphanumeric", "label": "Alphanumeric"},
                {"value": "alpha", "label": "Letters"},
                {"value": "lower", "label": "Lowercase"},
                {"value": "upper", "label": "Uppercase"},
                {"value": "numeric", "label": "Digits"},
                {"value": "hex", "label": "Hex (lower)"},
                {"value": "hex_upper", "label": "Hex (upper)"},
                {"value": "custom", "label": "Custom…"},
            ]},
            {"key": "custom_charset", "label": "Custom charset", "type": "string", "default": ""},
        ],
    },
    {
        "id": "pin",
        "label": "Numeric PIN",
        "category": "Passwords",
        "description": "Numeric PIN / OTP, leading zeros preserved.",
        "fn": g.pin,
        "options": [
            {"key": "length", "label": "Length", "type": "int", "default": 6, "min": 3, "max": 12},
        ],
    },
    {
        "id": "passphrase",
        "label": "Passphrase",
        "category": "Passwords",
        "description": "Memorable diceware passphrase from the EFF short wordlist.",
        "fn": g.passphrase,
        "options": [
            {"key": "words", "label": "Words", "type": "int", "default": 4, "min": 2, "max": 16},
            {"key": "separator", "label": "Separator", "type": "string", "default": "-"},
            {"key": "capitalize", "label": "Capitalize", "type": "bool", "default": False},
            {"key": "add_number", "label": "Append number", "type": "bool", "default": False},
        ],
    },
    # --- hashing (input-derived) -------------------------------------------
    {
        "id": "hash",
        "label": "Hash",
        "category": "Hashing",
        "description": "Hex digest of your input (md5/sha1/sha256/sha512).",
        "fn": g.hash_text,
        "random": False,
        "options": [
            {"key": "text", "label": "Input", "type": "text", "default": ""},
            {"key": "algorithm", "label": "Algorithm", "type": "select", "default": "sha256", "choices": [
                {"value": "sha256", "label": "SHA-256"},
                {"value": "sha512", "label": "SHA-512"},
                {"value": "sha1", "label": "SHA-1"},
                {"value": "md5", "label": "MD5"},
            ]},
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": False},
        ],
    },
    {
        "id": "hmac",
        "label": "HMAC",
        "category": "Hashing",
        "description": "Keyed HMAC hex digest of your input (sha256/sha512).",
        "fn": g.hmac_text,
        "random": False,
        "options": [
            {"key": "text", "label": "Input", "type": "text", "default": ""},
            {"key": "key", "label": "Key", "type": "string", "default": ""},
            {"key": "algorithm", "label": "Algorithm", "type": "select", "default": "sha256", "choices": [
                {"value": "sha256", "label": "SHA-256"},
                {"value": "sha512", "label": "SHA-512"},
            ]},
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": False},
        ],
    },
]

REGISTRY = {spec["id"]: spec for spec in GENERATORS}

MAX_COUNT = 1000


def public_metadata() -> list[dict]:
    """Registry without the (non-serializable) ``fn`` — safe to return as JSON."""
    out = []
    for spec in GENERATORS:
        meta = {k: v for k, v in spec.items() if k != "fn"}
        meta.setdefault("random", True)
        out.append(meta)
    return out


def _coerce(spec_options: list[dict], raw: dict | None) -> dict:
    """Coerce/validate raw option values against the schema, applying defaults."""
    raw = raw or {}
    out = {}
    for opt in spec_options:
        key = opt["key"]
        val = raw.get(key, opt.get("default"))
        kind = opt["type"]
        if kind == "int":
            try:
                val = int(val)
            except (TypeError, ValueError):
                val = int(opt.get("default", 0))
            if "min" in opt:
                val = max(opt["min"], val)
            if "max" in opt:
                val = min(opt["max"], val)
        elif kind == "bool":
            if isinstance(val, str):
                val = val.strip().lower() in ("1", "true", "yes", "on")
            else:
                val = bool(val)
        elif kind == "select":
            choices = [c["value"] for c in opt["choices"]]
            if val not in choices:
                try:
                    iv = int(val)
                except (TypeError, ValueError):
                    iv = None
                val = iv if iv in choices else opt.get("default")
        else:  # string / text
            val = "" if val is None else str(val)
        out[key] = val
    return out


def generate(gen_id: str, options: dict | None = None, count: int = 1) -> list[str]:
    """Generate ``count`` values for ``gen_id``. Raises KeyError for unknown ids
    and ValueError for invalid options."""
    spec = REGISTRY.get(gen_id)
    if spec is None:
        raise KeyError(gen_id)
    kwargs = _coerce(spec["options"], options)
    is_random = spec.get("random", True)
    try:
        n = int(count)
    except (TypeError, ValueError):
        n = 1
    n = 1 if not is_random else max(1, min(n, MAX_COUNT))
    return [spec["fn"](**kwargs) for _ in range(n)]
