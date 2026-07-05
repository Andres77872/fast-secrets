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
    {
        "id": "objectid",
        "label": "Mongo ObjectId",
        "category": "IDs",
        "description": "MongoDB-style 24-character ObjectId hex string with current timestamp.",
        "fn": g.mongo_object_id,
        "options": [
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": False},
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
    {
        "id": "jwt",
        "label": "JWT",
        "category": "Web/API",
        "description": "Development JSON Web Token with common claims and HS256/HS512 signing.",
        "fn": g.jwt_token,
        "options": [
            {"key": "subject", "label": "Subject", "type": "string", "default": "user_123"},
            {"key": "issuer", "label": "Issuer", "type": "string", "default": "fast-secrets"},
            {"key": "audience", "label": "Audience", "type": "string", "default": "local-dev"},
            {"key": "ttl_seconds", "label": "TTL seconds", "type": "int", "default": 3600, "min": 60, "max": 31536000},
            {"key": "secret", "label": "HMAC secret", "type": "string", "default": "dev-secret"},
            {"key": "algorithm", "label": "Algorithm", "type": "select", "default": "HS256", "choices": [
                {"value": "HS256", "label": "HS256"},
                {"value": "HS512", "label": "HS512"},
                {"value": "NONE", "label": "none"},
            ]},
            {"key": "include_jti", "label": "Include jti", "type": "bool", "default": True},
        ],
    },
    {
        "id": "user_agent",
        "label": "User-Agent",
        "category": "Web/API",
        "description": "Modern browser, crawler, or HTTP-client User-Agent string with weighted browser/platform defaults.",
        "fn": g.user_agent,
        "options": [
            {"key": "agent_type", "label": "Type", "type": "select", "default": "browser", "choices": [
                {"value": "browser", "label": "Browser"},
                {"value": "crawler", "label": "Crawler / bot"},
                {"value": "client", "label": "HTTP client"},
            ]},
            {"key": "browser", "label": "Browser", "type": "select", "default": "weighted", "choices": [
                {"value": "weighted", "label": "Weighted current mix"},
                {"value": "chrome", "label": "Chrome"},
                {"value": "safari", "label": "Safari"},
                {"value": "edge", "label": "Edge"},
                {"value": "firefox", "label": "Firefox"},
                {"value": "samsung", "label": "Samsung Internet"},
                {"value": "opera", "label": "Opera"},
            ]},
            {"key": "platform", "label": "Platform", "type": "select", "default": "weighted", "choices": [
                {"value": "weighted", "label": "Weighted current mix"},
                {"value": "desktop", "label": "Desktop"},
                {"value": "mobile", "label": "Mobile"},
                {"value": "tablet", "label": "Tablet"},
            ]},
            {"key": "reduced", "label": "Reduced modern format", "type": "bool", "default": True},
        ],
    },
    {
        "id": "basic_auth",
        "label": "Basic Auth",
        "category": "Web/API",
        "description": "HTTP Basic Authorization header from username and password.",
        "fn": g.basic_auth,
        "random": False,
        "options": [
            {"key": "username", "label": "Username", "type": "string", "default": "user"},
            {"key": "password", "label": "Password", "type": "string", "default": "password"},
            {"key": "include_scheme", "label": "Include Basic", "type": "bool", "default": True},
        ],
    },
    {
        "id": "jwt_decode",
        "label": "JWT decode",
        "category": "Web/API",
        "description": "Decode a JWT header and payload without verifying the signature.",
        "fn": g.jwt_decode,
        "random": False,
        "options": [
            {
                "key": "token",
                "label": "JWT",
                "type": "text",
                "default": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyXzEyMyIsImlzcyI6ImZhc3Qtc2VjcmV0cyJ9.",
                "placeholder": "Paste a JWT...",
            },
            {"key": "pretty", "label": "Pretty JSON", "type": "bool", "default": True},
        ],
    },
    {
        "id": "base64_text",
        "label": "Base64 text",
        "category": "Encoders",
        "description": "Encode or decode UTF-8 text as Base64 or URL-safe Base64.",
        "fn": g.base64_text,
        "random": False,
        "options": [
            {"key": "text", "label": "Input", "type": "text", "default": "", "placeholder": "Text or Base64..."},
            {"key": "mode", "label": "Mode", "type": "select", "default": "encode", "choices": [
                {"value": "encode", "label": "Encode"},
                {"value": "decode", "label": "Decode"},
            ]},
            {"key": "urlsafe", "label": "URL-safe alphabet", "type": "bool", "default": False},
            {"key": "padding", "label": "Keep padding", "type": "bool", "default": True},
        ],
    },
    {
        "id": "url_codec",
        "label": "URL encode",
        "category": "Encoders",
        "description": "Percent-encode or decode URL text, components, and query-style spaces.",
        "fn": g.url_codec,
        "random": False,
        "options": [
            {"key": "text", "label": "Input", "type": "text", "default": "", "placeholder": "URL or component text..."},
            {"key": "mode", "label": "Mode", "type": "select", "default": "encode", "choices": [
                {"value": "encode", "label": "Encode"},
                {"value": "decode", "label": "Decode"},
            ]},
            {"key": "component", "label": "Component mode", "type": "bool", "default": True},
            {"key": "plus_spaces", "label": "Spaces as +", "type": "bool", "default": False},
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
    # --- fixture data -------------------------------------------------------
    {
        "id": "email",
        "label": "Email address",
        "category": "Fixture data",
        "description": "Safe random email fixture using a configurable domain.",
        "fn": g.email_address,
        "options": [
            {"key": "domain", "label": "Domain", "type": "string", "default": "example.com"},
            {"key": "plus_tag", "label": "Plus tag", "type": "bool", "default": False},
        ],
    },
    {
        "id": "ipv4",
        "label": "IPv4 address",
        "category": "Fixture data",
        "description": "IPv4 fixture from private, documentation, or loopback ranges.",
        "fn": g.ipv4_address,
        "options": [
            {"key": "kind", "label": "Range", "type": "select", "default": "private", "choices": [
                {"value": "private", "label": "Private RFC1918"},
                {"value": "documentation", "label": "Documentation"},
                {"value": "loopback", "label": "Loopback"},
                {"value": "public", "label": "Safe public-style"},
            ]},
        ],
    },
    {
        "id": "ipv6",
        "label": "IPv6 address",
        "category": "Fixture data",
        "description": "IPv6 fixture from documentation, unique-local, or loopback ranges.",
        "fn": g.ipv6_address,
        "options": [
            {"key": "kind", "label": "Range", "type": "select", "default": "documentation", "choices": [
                {"value": "documentation", "label": "Documentation 2001:db8::/32"},
                {"value": "ula", "label": "Unique local fd00::/8"},
                {"value": "loopback", "label": "Loopback"},
            ]},
        ],
    },
    {
        "id": "mac",
        "label": "MAC address",
        "category": "Fixture data",
        "description": "Random MAC address, locally administered by default.",
        "fn": g.mac_address,
        "options": [
            {"key": "separator", "label": "Separator", "type": "select", "default": ":", "choices": [
                {"value": ":", "label": "Colon"},
                {"value": "-", "label": "Hyphen"},
                {"value": "", "label": "None"},
            ]},
            {"key": "uppercase", "label": "Uppercase", "type": "bool", "default": False},
            {"key": "locally_administered", "label": "Locally administered", "type": "bool", "default": True},
        ],
    },
    {
        "id": "semver",
        "label": "SemVer",
        "category": "Fixture data",
        "description": "Random semantic version string for package and API fixtures.",
        "fn": g.semver,
        "options": [
            {"key": "include_prerelease", "label": "Prerelease", "type": "bool", "default": False},
            {"key": "include_build", "label": "Build metadata", "type": "bool", "default": False},
        ],
    },
    {
        "id": "lorem",
        "label": "Lorem ipsum",
        "category": "Fixture data",
        "description": "Random lorem ipsum paragraphs for UI and API fixtures.",
        "fn": g.lorem_ipsum,
        "options": [
            {"key": "paragraphs", "label": "Paragraphs", "type": "int", "default": 1, "min": 1, "max": 8},
            {"key": "sentences", "label": "Sentences", "type": "int", "default": 3, "min": 1, "max": 12},
            {"key": "words_per_sentence", "label": "Words / sentence", "type": "int", "default": 12, "min": 4, "max": 30},
        ],
    },
    # --- formatters / text tools -------------------------------------------
    {
        "id": "json",
        "label": "JSON",
        "category": "Formatters",
        "description": "Format, minify, or validate JSON text.",
        "fn": g.json_format,
        "random": False,
        "options": [
            {"key": "text", "label": "JSON", "type": "text", "default": "{\"hello\":\"world\"}", "placeholder": "{\"hello\":\"world\"}"},
            {"key": "mode", "label": "Mode", "type": "select", "default": "format", "choices": [
                {"value": "format", "label": "Format"},
                {"value": "minify", "label": "Minify"},
                {"value": "validate", "label": "Validate"},
            ]},
            {"key": "indent", "label": "Indent", "type": "int", "default": 2, "min": 1, "max": 8},
            {"key": "sort_keys", "label": "Sort keys", "type": "bool", "default": False},
        ],
    },
    {
        "id": "text_case",
        "label": "Text case",
        "category": "Text",
        "description": "Convert text to snake, camel, Pascal, kebab, slug, constant, title, upper, or lower case.",
        "fn": g.text_case,
        "random": False,
        "options": [
            {"key": "text", "label": "Input", "type": "text", "default": "", "placeholder": "Example text or identifier"},
            {"key": "case", "label": "Case", "type": "select", "default": "snake", "choices": [
                {"value": "snake", "label": "snake_case"},
                {"value": "camel", "label": "camelCase"},
                {"value": "pascal", "label": "PascalCase"},
                {"value": "kebab", "label": "kebab-case"},
                {"value": "slug", "label": "slug"},
                {"value": "constant", "label": "CONSTANT_CASE"},
                {"value": "title", "label": "Title Case"},
                {"value": "upper", "label": "UPPER"},
                {"value": "lower", "label": "lower"},
            ]},
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
