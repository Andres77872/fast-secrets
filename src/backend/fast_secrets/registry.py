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

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from . import diffing
from . import generators as g


OutputKind = Literal["text", "list", "record", "table"]
ExecutionMode = Literal["server", "browser", "both"]
FieldType = Literal[
    "int",
    "float",
    "bool",
    "select",
    "string",
    "text",
    "json",
    "list",
]


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """Typed metadata and validation hints for one tool field."""

    key: str
    label: str
    type: FieldType
    default: Any = None
    required: bool = False
    nullable: bool = False
    strict: bool = False
    sensitive: bool = False
    persist: bool = True
    min: int | None = None
    max: int | None = None
    max_length: int | None = None
    choices: tuple[dict[str, Any], ...] = ()
    placeholder: str | None = None

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        sensitive: bool = False,
    ) -> "FieldSpec":
        kind = value["type"]
        max_length = value.get("max_length")
        if max_length is None and kind in {"string", "text"}:
            max_length = 65_536
        return cls(
            key=value["key"],
            label=value["label"],
            type=kind,
            default=value.get("default"),
            required=bool(value.get("required", False)),
            nullable=bool(value.get("nullable", False)),
            strict=bool(value.get("strict", False)),
            sensitive=bool(value.get("sensitive", sensitive)),
            persist=bool(value.get("persist", not sensitive)),
            min=value.get("min"),
            max=value.get("max"),
            max_length=max_length,
            choices=tuple(dict(choice) for choice in value.get("choices", ())),
            placeholder=value.get("placeholder"),
        )

    def public_metadata(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "type": self.type,
            "default": self.default,
            "required": self.required,
            "nullable": self.nullable,
            "strict": self.strict,
            "sensitive": self.sensitive,
            "persist": self.persist,
        }
        for key in ("min", "max", "max_length", "placeholder"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.choices:
            out["choices"] = [dict(choice) for choice in self.choices]
        return out


@dataclass(slots=True)
class ToolResult:
    """Transport-neutral result returned by a registered tool handler."""

    kind: OutputKind
    data: Any
    warnings: list[Any] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


ToolHandler = Callable[[dict[str, Any], dict[str, Any], int], ToolResult]
OutputSizeEstimator = Callable[[dict[str, Any], dict[str, Any], int], int]


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A typed tool definition shared by metadata, dispatch, and the API."""

    id: str
    label: str
    category: str
    description: str
    handler: ToolHandler
    inputs: tuple[FieldSpec, ...] = ()
    options: tuple[FieldSpec, ...] = ()
    random: bool = True
    execution_mode: ExecutionMode = "both"
    output_kind: OutputKind = "list"
    batchable: bool = True
    max_count: int = 1000
    sensitive: bool = False
    output_size_estimator: OutputSizeEstimator | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _legacy_fn: Callable[..., str] | None = field(default=None, repr=False, compare=False)

    def public_metadata(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "category": self.category,
            "description": self.description,
            "inputs": [item.public_metadata() for item in self.inputs],
            "options": [item.public_metadata() for item in self.options],
            "random": self.random,
            "execution_mode": self.execution_mode,
            "output_kind": self.output_kind,
            "batchable": self.batchable,
            "max_count": self.max_count,
            "sensitive": self.sensitive,
        }

    def __getitem__(self, key: str) -> Any:
        """Keep read-only indexing compatibility for older Python callers."""
        if key == "fn":
            return self._legacy_fn or self.handler
        if key == "options":
            return [item.public_metadata() for item in (*self.inputs, *self.options)]
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)


_LEGACY_GENERATORS = [
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
        "description": "Modern browser, crawler, or HTTP-client User-Agent string from real samples or generated templates.",
        "fn": g.user_agent,
        "options": [
            {"key": "agent_type", "label": "Type", "type": "select", "default": "browser", "choices": [
                {"value": "browser", "label": "Browser"},
                {"value": "crawler", "label": "Crawler / bot"},
                {"value": "client", "label": "HTTP client"},
            ]},
            {"key": "source", "label": "Source", "type": "select", "default": "auto", "choices": [
                {"value": "auto", "label": "Auto real samples"},
                {"value": "dataset", "label": "Real sample dataset"},
                {"value": "template", "label": "Generated templates"},
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

MAX_COUNT = 1000

# Fields containing caller-provided material are separated from nonsensitive
# configuration in the v2 API. Direct ``generate`` callers may still pass all
# values in the legacy options mapping.
_INPUT_KEYS: dict[str, set[str]] = {
    "jwt": {"secret"},
    "basic_auth": {"username", "password"},
    "jwt_decode": {"token"},
    "base64_text": {"text"},
    "url_codec": {"text"},
    "json": {"text"},
    "text_case": {"text"},
    "hash": {"text"},
    "hmac": {"text", "key"},
}

_SENSITIVE_INPUT_KEYS = {
    "key",
    "password",
    "secret",
    "text",
    "token",
}

# Random outputs that are fixtures rather than credentials or secret material.
_NONSENSITIVE_RANDOM_TOOLS = {
    "email",
    "ipv4",
    "ipv6",
    "lorem",
    "mac",
    "objectid",
    "semver",
    "user_agent",
    "uuid",
}


def _coerce_fields(fields: tuple[FieldSpec, ...], raw: Mapping[str, Any] | None) -> dict[str, Any]:
    """Coerce values using the same forgiving rules as the v1 registry."""
    values = raw or {}
    out: dict[str, Any] = {}
    for item in fields:
        val = values.get(item.key, item.default)
        if val is None and item.required:
            raise ValueError(f"Missing required field '{item.key}'")
        if val is None and item.nullable:
            out[item.key] = None
            continue
        if item.type == "int":
            if isinstance(val, bool) or (
                item.strict and isinstance(val, float) and not val.is_integer()
            ):
                raise ValueError(f"Field '{item.key}' must be an integer")
            try:
                val = int(val)
            except (TypeError, ValueError):
                if item.strict:
                    raise ValueError(f"Field '{item.key}' must be an integer") from None
                val = int(item.default or 0)
            if item.min is not None and val < item.min:
                if item.strict:
                    raise ValueError(f"Field '{item.key}' must be at least {item.min}")
                val = item.min
            if item.max is not None and val > item.max:
                if item.strict:
                    raise ValueError(f"Field '{item.key}' must be at most {item.max}")
                val = item.max
        elif item.type == "float":
            if isinstance(val, bool):
                raise ValueError(f"Field '{item.key}' must be a number")
            try:
                val = float(val)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Field '{item.key}' must be a number") from exc
        elif item.type == "bool":
            if isinstance(val, str):
                normalized = val.strip().lower()
                if item.strict and normalized not in {
                    "0", "1", "false", "no", "off", "on", "true", "yes"
                }:
                    raise ValueError(f"Field '{item.key}' must be a boolean")
                val = normalized in ("1", "true", "yes", "on")
            elif item.strict and not isinstance(val, bool):
                raise ValueError(f"Field '{item.key}' must be a boolean")
            else:
                val = bool(val)
        elif item.type == "select":
            choices = [choice["value"] for choice in item.choices]
            if val not in choices:
                if item.strict:
                    raise ValueError(
                        f"Field '{item.key}' must be one of: "
                        + ", ".join(str(choice) for choice in choices)
                    )
                try:
                    integer_value = int(val)
                except (TypeError, ValueError):
                    integer_value = None
                val = integer_value if integer_value in choices else item.default
        elif item.type == "json":
            # JSON bodies are already decoded by FastAPI; preserve objects,
            # arrays, numbers, booleans, and null without stringification.
            val = val
        elif item.type == "list":
            if not isinstance(val, (list, tuple)):
                raise ValueError(f"Field '{item.key}' must be an array")
            val = list(val)
        else:
            if item.strict and not isinstance(val, str):
                raise ValueError(f"Field '{item.key}' must be a string")
            val = "" if val is None else str(val)
            if item.max_length is not None and len(val) > item.max_length:
                raise ValueError(
                    f"Field '{item.key}' exceeds the {item.max_length}-character limit"
                )
        out[item.key] = val
    return out


def _legacy_handler(
    fn: Callable[..., str],
    fields: tuple[FieldSpec, ...],
    *,
    random: bool,
    output_kind: OutputKind,
) -> ToolHandler:
    def run(inputs: dict[str, Any], options: dict[str, Any], count: int) -> ToolResult:
        merged = {**inputs, **options}
        kwargs = _coerce_fields(fields, merged)
        actual_count = count if random else 1
        values = [fn(**kwargs) for _ in range(actual_count)]
        if output_kind == "text":
            return ToolResult(kind="text", data=values[0], meta={"count": 1})
        return ToolResult(kind="list", data=values, meta={"count": len(values)})

    return run


def _compact_json_size(value: Any) -> int:
    """Return a UTF-8 JSON size bound that is safe for ensure_ascii=False output."""
    return len(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    )


def _json_text_content_bound(value: str) -> int:
    # ensure_ascii=True is never shorter in bytes than the API's UTF-8
    # ensure_ascii=False representation, and it safely handles lone surrogates.
    return _compact_json_size(value) - 2


def _max_json_character_bound(value: str) -> int:
    return max((_json_text_content_bound(char) for char in value), default=1)


def _json_string_bound(content_bytes: int) -> int:
    return content_bytes + 2


def _json_list_bound(item_bytes: int, count: int) -> int:
    return 2 + (item_bytes * count) + max(0, count - 1)


def _unpadded_base64_length(nbytes: int) -> int:
    return (4 * nbytes + 2) // 3


def _legacy_item_size_bound(tool_id: str, options: dict[str, Any]) -> int:
    """Upper-bound one legacy random result as compact JSON, without entropy use."""
    if tool_id == "uuid":
        return _json_string_bound(36 if options["hyphens"] else 32)
    if tool_id == "ulid":
        return _json_string_bound(26)
    if tool_id == "nanoid":
        alphabet = options["alphabet"] or g.NANOID_ALPHABET
        return _json_string_bound(
            options["size"] * _max_json_character_bound(alphabet)
        )
    if tool_id == "objectid":
        return _json_string_bound(24)
    if tool_id == "hex":
        return _json_string_bound(options["nbytes"] * 2)
    if tool_id == "urlsafe":
        return _json_string_bound(_unpadded_base64_length(options["nbytes"]))
    if tool_id == "base64":
        return _json_string_bound(4 * ((options["nbytes"] + 2) // 3))
    if tool_id == "apikey":
        body = (
            options["nbytes"] * 2
            if options["encoding"] == "hex"
            else _unpadded_base64_length(options["nbytes"])
        )
        prefix = options["prefix"]
        fixed = (
            _json_text_content_bound(prefix)
            + _json_text_content_bound(options["separator"])
            if prefix
            else 0
        )
        return _json_string_bound(fixed + body)
    if tool_id == "jwt":
        algorithm = options["algorithm"].upper()
        header = {"typ": "JWT", "alg": "none" if algorithm == "NONE" else algorithm}
        ttl = options["ttl_seconds"]
        digits = max(10, len(str(int(time.time()) + ttl)))
        timestamp = int("9" * digits)
        payload = {
            "sub": options["subject"] or "user_123",
            "iss": options["issuer"],
            "aud": options["audience"],
            "iat": timestamp,
            "nbf": timestamp,
            "exp": timestamp,
        }
        if options["include_jti"]:
            payload["jti"] = "f" * 36
        header_size = len(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_size = len(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        signature_size = 0 if algorithm == "NONE" else (86 if algorithm == "HS512" else 43)
        content = (
            _unpadded_base64_length(header_size)
            + _unpadded_base64_length(payload_size)
            + signature_size
            + 2
        )
        return _json_string_bound(content)
    if tool_id == "user_agent":
        return _json_string_bound(512)
    if tool_id == "password":
        return _json_string_bound(options["length"])
    if tool_id == "string":
        if options["charset"] == "custom":
            alphabet = options["custom_charset"] or g.CHARSET_PRESETS["alphanumeric"]
        else:
            alphabet = g.CHARSET_PRESETS.get(
                options["charset"],
                g.CHARSET_PRESETS["alphanumeric"],
            )
        return _json_string_bound(
            options["length"] * _max_json_character_bound(alphabet)
        )
    if tool_id == "pin":
        return _json_string_bound(options["length"])
    if tool_id == "passphrase":
        words = options["words"]
        content = words * max(map(len, g.WORDS))
        content += max(0, words - 1) * _json_text_content_bound(options["separator"])
        if options["add_number"]:
            content += 1
        return _json_string_bound(content)
    if tool_id == "email":
        longest_word = max(map(len, g.WORDS))
        local = (2 * longest_word) + 5
        if options["plus_tag"]:
            local += 6
        domain = options["domain"] or "example.com"
        return _json_string_bound(
            local + 1 + _json_text_content_bound(domain)
        )
    if tool_id == "ipv4":
        return _json_string_bound(15)
    if tool_id == "ipv6":
        return _json_string_bound(39)
    if tool_id == "mac":
        return _json_string_bound(17 if options["separator"] else 12)
    if tool_id == "semver":
        return _json_string_bound(32)
    if tool_id == "lorem":
        paragraphs = options["paragraphs"]
        sentences = options["sentences"]
        words = options["words_per_sentence"]
        sentence = (words * max(map(len, g.LOREM_WORDS))) + (words - 1) + 1
        paragraph = (sentences * sentence) + max(0, sentences - 1)
        # Each newline is escaped as two bytes in a JSON string.
        content = (paragraphs * paragraph) + max(0, paragraphs - 1) * 4
        return _json_string_bound(content)
    raise RuntimeError(f"No output-size estimator for random tool '{tool_id}'")


def _legacy_output_size_estimator(tool_id: str) -> OutputSizeEstimator:
    def estimate(
        _inputs: dict[str, Any], options: dict[str, Any], count: int
    ) -> int:
        return _json_list_bound(_legacy_item_size_bound(tool_id, options), count)

    return estimate


def _typed_legacy_spec(value: Mapping[str, Any]) -> ToolSpec:
    tool_id = str(value["id"])
    input_keys = _INPUT_KEYS.get(tool_id, set())
    all_fields = tuple(
        FieldSpec.from_mapping(
            option,
            sensitive=option["key"] in _SENSITIVE_INPUT_KEYS,
        )
        for option in value.get("options", ())
    )
    inputs = tuple(item for item in all_fields if item.key in input_keys)
    options = tuple(item for item in all_fields if item.key not in input_keys)
    random = bool(value.get("random", True))
    output_kind: OutputKind = "list" if random else "text"
    max_count = MAX_COUNT if random else 1
    sensitive = (
        tool_id not in _NONSENSITIVE_RANDOM_TOOLS
        if random
        else any(item.sensitive for item in inputs)
    )
    fn = value["fn"]
    return ToolSpec(
        id=tool_id,
        label=str(value["label"]),
        category=str(value["category"]),
        description=str(value["description"]),
        handler=_legacy_handler(
            fn,
            all_fields,
            random=random,
            output_kind=output_kind,
        ),
        inputs=inputs,
        options=options,
        random=random,
        output_kind=output_kind,
        max_count=max_count,
        sensitive=sensitive,
        output_size_estimator=(
            _legacy_output_size_estimator(tool_id) if random else None
        ),
        _legacy_fn=fn,
    )


GENERATORS: list[ToolSpec] = [_typed_legacy_spec(spec) for spec in _LEGACY_GENERATORS]
REGISTRY: dict[str, ToolSpec] = {spec.id: spec for spec in GENERATORS}


def register_tool(spec: ToolSpec, *, replace: bool = False) -> None:
    """Register a rich tool without coupling its handler to FastAPI.

    Feature modules can call this during application startup. Duplicate ids are
    rejected unless replacement is explicitly requested.
    """
    existing = REGISTRY.get(spec.id)
    if existing is not None and not replace:
        raise ValueError(f"Tool '{spec.id}' is already registered")
    if existing is not None:
        GENERATORS.remove(existing)
    REGISTRY[spec.id] = spec
    GENERATORS.append(spec)


def get_tool(tool_id: str) -> ToolSpec:
    try:
        return REGISTRY[tool_id]
    except KeyError:
        raise KeyError(tool_id) from None


def prepare_tool_call(
    tool_id: str,
    inputs: Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
    count: int = 1,
) -> tuple[ToolSpec, dict[str, Any], dict[str, Any]]:
    """Validate a call and resolve defaults without invoking its handler."""
    spec = get_tool(tool_id)
    if not isinstance(count, int) or isinstance(count, bool):
        raise ValueError("count must be an integer")
    if count < 1 or count > spec.max_count:
        raise ValueError(f"count must be between 1 and {spec.max_count} for '{tool_id}'")
    if count > 1 and not spec.batchable:
        raise ValueError(f"Tool '{tool_id}' does not support multiple results")

    raw_inputs = dict(inputs or {})
    raw_options = dict(options or {})
    known_inputs = {item.key for item in spec.inputs}
    known_options = {item.key for item in spec.options}
    unexpected_inputs = sorted(raw_inputs.keys() - known_inputs)
    unexpected_options = sorted(raw_options.keys() - known_options)
    if unexpected_inputs:
        raise ValueError(f"Unknown input field(s): {', '.join(unexpected_inputs)}")
    if unexpected_options:
        raise ValueError(f"Unknown option field(s): {', '.join(unexpected_options)}")

    prepared_inputs = _coerce_fields(spec.inputs, raw_inputs)
    prepared_options = _coerce_fields(spec.options, raw_options)
    return spec, prepared_inputs, prepared_options


def estimate_tool_output_bytes(
    tool_id: str,
    inputs: Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
    count: int = 1,
) -> int | None:
    """Bound compact JSON bytes for result data without running the tool.

    A missing estimator means that the caller must enforce its response limit
    after execution. All entropy-backed built-ins provide an estimator.
    """
    spec, prepared_inputs, prepared_options = prepare_tool_call(
        tool_id,
        inputs,
        options,
        count,
    )
    if spec.output_size_estimator is None:
        return None
    estimate = spec.output_size_estimator(
        prepared_inputs,
        prepared_options,
        count,
    )
    if not isinstance(estimate, int) or isinstance(estimate, bool) or estimate < 0:
        raise TypeError(f"Output-size estimator for '{tool_id}' returned an invalid size")
    return estimate


def run_tool(
    tool_id: str,
    inputs: Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
    count: int = 1,
) -> ToolResult:
    """Validate dispatch limits and invoke a transport-neutral tool handler."""
    spec, prepared_inputs, prepared_options = prepare_tool_call(
        tool_id,
        inputs,
        options,
        count,
    )
    result = spec.handler(prepared_inputs, prepared_options, count)
    if not isinstance(result, ToolResult):
        raise TypeError(f"Handler for '{tool_id}' did not return ToolResult")
    if result.kind not in {"text", "list", "record", "table"}:
        raise TypeError(f"Handler for '{tool_id}' returned an invalid output kind")
    return result


def public_metadata() -> list[dict]:
    """Return JSON-safe typed metadata for every registered tool."""
    return [spec.public_metadata() for spec in GENERATORS]


def generate(gen_id: str, options: dict | None = None, count: int = 1) -> list[str]:
    """Generate ``count`` values for ``gen_id``. Raises KeyError for unknown ids
    and ValueError for invalid options."""
    spec = REGISTRY.get(gen_id)
    if spec is None:
        raise KeyError(gen_id)
    if spec._legacy_fn is None:
        result = run_tool(gen_id, {}, options, count)
        if result.kind == "text":
            return [str(result.data)]
        if result.kind == "list" and isinstance(result.data, list):
            return [str(value) for value in result.data]
        raise ValueError(f"Tool '{gen_id}' cannot be represented as legacy string output")
    fields = (*spec.inputs, *spec.options)
    kwargs = _coerce_fields(fields, options)
    is_random = spec.random
    try:
        n = int(count)
    except (TypeError, ValueError):
        n = 1
    n = 1 if not is_random else max(1, min(n, MAX_COUNT))
    return [spec._legacy_fn(**kwargs) for _ in range(n)]


# --- rich v2 feature tools -------------------------------------------------

def _text_diff_handler(
    inputs: dict[str, Any], options: dict[str, Any], _count: int
) -> ToolResult:
    """Adapt the bounded text-diff engine to the typed tool contract."""
    data = diffing.diff_texts(
        inputs["text1"],
        inputs["text2"],
        ignore_whitespace=options["ignore_whitespace"],
        ignore_case=options["ignore_case"],
        granularity=options["granularity"],
    )
    return ToolResult(
        kind="record",
        data=data,
        meta={
            "max_bytes_per_side": diffing.MAX_BYTES,
            "max_lines_per_side": diffing.MAX_LINES,
        },
    )


def _register_text_diff_tool() -> None:
    def sensitive_text(key: str, label: str) -> FieldSpec:
        return FieldSpec(
            key=key,
            label=label,
            type="text",
            required=True,
            strict=True,
            sensitive=True,
            persist=False,
            max_length=diffing.MAX_BYTES,
        )

    register_tool(
        ToolSpec(
            id="text_diff",
            label="Text diff",
            category="Debugging",
            description="Compare two bounded text inputs with aligned and unified output.",
            handler=_text_diff_handler,
            inputs=(
                sensitive_text("text1", "Original text"),
                sensitive_text("text2", "Changed text"),
            ),
            options=(
                FieldSpec(
                    "ignore_whitespace",
                    "Ignore whitespace",
                    "bool",
                    False,
                    strict=True,
                ),
                FieldSpec(
                    "ignore_case",
                    "Ignore case",
                    "bool",
                    False,
                    strict=True,
                ),
                FieldSpec(
                    "granularity",
                    "Intra-line granularity",
                    "select",
                    "word",
                    strict=True,
                    choices=(
                        {"value": "word", "label": "Word"},
                        {"value": "char", "label": "Character"},
                    ),
                ),
            ),
            random=False,
            output_kind="record",
            batchable=True,
            max_count=1,
            sensitive=True,
        )
    )


def _feature_field(
    key: str,
    label: str,
    field_type: FieldType,
    default: Any = None,
    *,
    required: bool = False,
    nullable: bool = False,
    sensitive: bool = False,
    min_value: int | None = None,
    max_value: int | None = None,
    max_length: int | None = None,
    choices: tuple[dict[str, Any], ...] = (),
    placeholder: str | None = None,
) -> FieldSpec:
    return FieldSpec(
        key=key,
        label=label,
        type=field_type,
        default=default,
        required=required,
        nullable=nullable,
        strict=True,
        sensitive=sensitive,
        persist=not sensitive,
        min=min_value,
        max=max_value,
        max_length=max_length,
        choices=choices,
        placeholder=placeholder,
    )


def _choice_specs(*values: Any) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "value": value,
            "label": str(value).replace("_", " ").title(),
        }
        for value in values
    )


def _adapt_feature_handler(handler: Callable[..., dict[str, Any]], *, random: bool) -> ToolHandler:
    def run(inputs: dict[str, Any], options: dict[str, Any], count: int) -> ToolResult:
        payload = handler(inputs, options, count)
        if not isinstance(payload, dict):
            raise TypeError("Feature handler returned a non-record response")
        kind = payload.get("kind")
        data = payload.get("data")
        if random and kind == "record":
            # Random tools consistently expose list output, even for count=1.
            kind = "list"
            data = [data]
        if kind not in {"text", "list", "record", "table"}:
            raise TypeError("Feature handler returned an invalid output kind")
        warnings = payload.get("warnings", [])
        meta = payload.get("meta", {})
        if not isinstance(warnings, list) or not isinstance(meta, dict):
            raise TypeError("Feature handler returned invalid warnings or metadata")
        return ToolResult(kind=kind, data=data, warnings=warnings, meta=meta)

    return run


def _feature_item_size_bound(tool_id: str, options: dict[str, Any]) -> int:
    """Upper-bound one random feature record as compact JSON."""
    if tool_id == "password_policy":
        alphabet = (
            g.LOWERCASE
            + g.UPPERCASE
            + g.DIGITS
            + options["symbols"]
            + options["required"]
        )
        password_bytes = (
            options["length"] * _max_json_character_bound(alphabet)
        )
        record = {
            "password": "x" * password_bytes,
            "length": options["length"],
            "entropy_bits_lower_bound": 99999.99,
            "requirements": {
                "lowercase": options["min_lowercase"],
                "uppercase": options["min_uppercase"],
                "digits": options["min_digits"],
                "symbols": options["min_symbols"],
                "required_characters": len(options["required"]),
            },
        }
        return _compact_json_size(record)
    if tool_id == "base32_secret":
        nbytes = options["nbytes"]
        secret_length = (
            8 * ((nbytes + 4) // 5)
            if options["padding"]
            else (8 * nbytes + 4) // 5
        )
        return _compact_json_size(
            {
                "secret": "A" * secret_length,
                "bytes": nbytes,
                "bits": nbytes * 8,
            }
        )
    if tool_id == "pkce_generate":
        return _compact_json_size(
            {
                "code_verifier": "A" * options["length"],
                "code_challenge": "A" * 43,
                "code_challenge_method": "S256",
            }
        )
    if tool_id in {"oauth_state", "oidc_nonce", "csp_nonce"}:
        nbytes = options["nbytes"]
        purpose = {
            "oauth_state": "state",
            "oidc_nonce": "oidc_nonce",
            "csp_nonce": "csp_nonce",
        }[tool_id]
        value_length = (
            4 * ((nbytes + 2) // 3)
            if tool_id == "csp_nonce"
            else _unpadded_base64_length(nbytes)
        )
        record: dict[str, Any] = {
            "value": "A" * value_length,
            "purpose": purpose,
            "bits": nbytes * 8,
        }
        if tool_id == "csp_nonce":
            record["directive"] = f"'nonce-{'A' * value_length}'"
        return _compact_json_size(record)
    raise RuntimeError(f"No output-size estimator for random feature '{tool_id}'")


def _feature_output_size_estimator(tool_id: str) -> OutputSizeEstimator:
    def estimate(
        _inputs: dict[str, Any], options: dict[str, Any], count: int
    ) -> int:
        return _json_list_bound(_feature_item_size_bound(tool_id, options), count)

    return estimate


def _register_feature_tools() -> None:
    """Expose the standards-oriented feature engines through registry dispatch."""
    import inspect

    from . import tool_features as features

    text_limit = 256 * 1024
    secret_limit = 65_536
    algorithms_jwt = _choice_specs("HS256", "HS384", "HS512")
    algorithms_otp = _choice_specs("SHA1", "SHA256", "SHA512")
    algorithms_hmac = _choice_specs("sha256", "sha384", "sha512")

    definitions: dict[str, dict[str, Any]] = {
        "password_policy": {
            "label": "Password policy",
            "description": "Generate passwords with explicit per-class minimums and exclusions.",
            "inputs": (),
            "options": (
                _feature_field("length", "Length", "int", 20, min_value=1, max_value=1024),
                _feature_field("min_lowercase", "Minimum lowercase", "int", 1, min_value=0, max_value=1024),
                _feature_field("min_uppercase", "Minimum uppercase", "int", 1, min_value=0, max_value=1024),
                _feature_field("min_digits", "Minimum digits", "int", 1, min_value=0, max_value=1024),
                _feature_field("min_symbols", "Minimum symbols", "int", 1, min_value=0, max_value=1024),
                _feature_field("symbols", "Symbol set", "string", features.DEFAULT_SYMBOLS, max_length=4096),
                _feature_field("required", "Required characters", "string", "", max_length=4096),
                _feature_field("excluded", "Excluded characters", "string", "", max_length=4096),
                _feature_field("exclude_ambiguous", "Exclude ambiguous characters", "bool", False),
            ),
        },
        "base32_encode": {
            "label": "Base32 encode",
            "description": "Encode UTF-8 text using RFC 4648 Base32.",
            "inputs": (_feature_field("text", "Text", "text", None, required=True, sensitive=True, max_length=text_limit),),
            "options": (_feature_field("padding", "Keep padding", "bool", False),),
        },
        "base32_decode": {
            "label": "Base32 decode",
            "description": "Decode RFC 4648 Base32 into UTF-8 text.",
            "inputs": (_feature_field("value", "Base32 value", "text", None, required=True, sensitive=True, max_length=text_limit),),
            "options": (),
        },
        "base32_secret": {
            "label": "Base32 secret",
            "description": "Generate a cryptographically random Base32 secret.",
            "inputs": (),
            "options": (
                _feature_field("nbytes", "Bytes", "int", 20, min_value=10, max_value=4096),
                _feature_field("padding", "Keep padding", "bool", False),
            ),
        },
        "jwt_encode": {
            "label": "JWT sign",
            "description": "Sign JSON claims with an allow-listed HMAC JWT algorithm.",
            "inputs": (
                _feature_field("claims", "Claims", "json", {}),
                _feature_field("secret", "HMAC secret", "string", None, required=True, sensitive=True, max_length=secret_limit),
                _feature_field("header", "Additional header", "json", {}),
            ),
            "options": (_feature_field("algorithm", "Algorithm", "select", "HS256", choices=algorithms_jwt),),
        },
        "jwt_decode": {
            "label": "JWT decode",
            "description": "Decode a JWT and independently report syntax, signature, and claim status.",
            "inputs": (
                _feature_field("token", "JWT", "text", None, required=True, sensitive=True, max_length=text_limit),
                _feature_field("secret", "Optional HMAC secret", "string", None, nullable=True, sensitive=True, max_length=secret_limit),
            ),
            "options": (
                _feature_field("allowed_algorithms", "Allowed algorithms", "list", ["HS256", "HS384", "HS512"]),
                _feature_field("issuer", "Expected issuer", "string", None, nullable=True, max_length=1024),
                _feature_field("audience", "Expected audience", "string", None, nullable=True, max_length=1024),
                _feature_field("leeway", "Clock skew seconds", "int", 0, min_value=0, max_value=86_400),
                _feature_field("now", "Evaluation time", "float", None, nullable=True),
            ),
        },
        "jwt_verify": {
            "label": "JWT verify",
            "description": "Verify an HMAC JWT and validate common registered claims.",
            "inputs": (
                _feature_field("token", "JWT", "text", None, required=True, sensitive=True, max_length=text_limit),
                _feature_field("secret", "HMAC secret", "string", None, required=True, sensitive=True, max_length=secret_limit),
            ),
            "options": (
                _feature_field("allowed_algorithms", "Allowed algorithms", "list", ["HS256", "HS384", "HS512"]),
                _feature_field("issuer", "Expected issuer", "string", None, nullable=True, max_length=1024),
                _feature_field("audience", "Expected audience", "string", None, nullable=True, max_length=1024),
                _feature_field("leeway", "Clock skew seconds", "int", 0, min_value=0, max_value=86_400),
                _feature_field("now", "Evaluation time", "float", None, nullable=True),
            ),
        },
        "hotp": {
            "label": "HOTP",
            "description": "Generate an RFC 4226 counter-based one-time password.",
            "inputs": (_feature_field("secret", "Base32 secret", "string", None, required=True, sensitive=True, max_length=secret_limit),),
            "options": (
                _feature_field("counter", "Counter", "int", 0, min_value=0, max_value=(1 << 64) - 1),
                _feature_field("digits", "Digits", "select", 6, choices=_choice_specs(6, 8)),
                _feature_field("algorithm", "Algorithm", "select", "SHA1", choices=algorithms_otp),
            ),
        },
        "hotp_verify": {
            "label": "HOTP verify",
            "description": "Verify an HOTP code within a bounded look-ahead window.",
            "inputs": (
                _feature_field("secret", "Base32 secret", "string", None, required=True, sensitive=True, max_length=secret_limit),
                _feature_field("code", "One-time code", "string", None, required=True, sensitive=True, max_length=16),
            ),
            "options": (
                _feature_field("counter", "Counter", "int", 0, min_value=0, max_value=(1 << 64) - 1),
                _feature_field("look_ahead", "Look-ahead", "int", 0, min_value=0, max_value=100),
                _feature_field("digits", "Digits", "select", 6, choices=_choice_specs(6, 8)),
                _feature_field("algorithm", "Algorithm", "select", "SHA1", choices=algorithms_otp),
            ),
        },
        "totp": {
            "label": "TOTP",
            "description": "Generate an RFC 6238 time-based one-time password.",
            "inputs": (_feature_field("secret", "Base32 secret", "string", None, required=True, sensitive=True, max_length=secret_limit),),
            "options": (
                _feature_field("timestamp", "Timestamp", "float", None, nullable=True),
                _feature_field("period", "Period seconds", "int", 30, min_value=1, max_value=86_400),
                _feature_field("digits", "Digits", "select", 6, choices=_choice_specs(6, 8)),
                _feature_field("algorithm", "Algorithm", "select", "SHA1", choices=algorithms_otp),
            ),
        },
        "totp_verify": {
            "label": "TOTP verify",
            "description": "Verify a TOTP code within a bounded time window.",
            "inputs": (
                _feature_field("secret", "Base32 secret", "string", None, required=True, sensitive=True, max_length=secret_limit),
                _feature_field("code", "One-time code", "string", None, required=True, sensitive=True, max_length=16),
            ),
            "options": (
                _feature_field("timestamp", "Timestamp", "float", None, nullable=True),
                _feature_field("period", "Period seconds", "int", 30, min_value=1, max_value=86_400),
                _feature_field("window", "Window", "int", 1, min_value=0, max_value=10),
                _feature_field("digits", "Digits", "select", 6, choices=_choice_specs(6, 8)),
                _feature_field("algorithm", "Algorithm", "select", "SHA1", choices=algorithms_otp),
            ),
        },
        "otpauth_build": {
            "label": "OTPAuth URI builder",
            "description": "Build an interoperable otpauth enrollment URI.",
            "inputs": (
                _feature_field("secret", "Base32 secret", "string", None, required=True, sensitive=True, max_length=secret_limit),
                _feature_field("account", "Account", "string", None, required=True, max_length=1024),
                _feature_field("issuer", "Issuer", "string", "", max_length=1024),
            ),
            "options": (
                _feature_field("otp_type", "OTP type", "select", "totp", choices=_choice_specs("totp", "hotp")),
                _feature_field("algorithm", "Algorithm", "select", "SHA1", choices=algorithms_otp),
                _feature_field("digits", "Digits", "select", 6, choices=_choice_specs(6, 8)),
                _feature_field("period", "Period seconds", "int", 30, min_value=1, max_value=86_400),
                _feature_field("counter", "Counter", "int", 0, min_value=0, max_value=(1 << 64) - 1),
            ),
        },
        "otpauth_parse": {
            "label": "OTPAuth URI parser",
            "description": "Parse and validate an otpauth enrollment URI.",
            "inputs": (_feature_field("uri", "OTPAuth URI", "text", None, required=True, sensitive=True, max_length=text_limit),),
            "options": (),
        },
        "pkce_generate": {
            "label": "PKCE pair",
            "description": "Generate an RFC 7636 verifier and S256 challenge.",
            "inputs": (),
            "options": (_feature_field("length", "Verifier length", "int", 64, min_value=43, max_value=128),),
        },
        "pkce_challenge": {
            "label": "PKCE challenge",
            "description": "Derive an RFC 7636 S256 challenge from a verifier.",
            "inputs": (_feature_field("verifier", "Verifier", "string", None, required=True, sensitive=True, max_length=128),),
            "options": (),
        },
        "oauth_state": {
            "label": "OAuth state",
            "description": "Generate a random OAuth state value.",
            "inputs": (),
            "options": (_feature_field("nbytes", "Bytes", "int", 32, min_value=16, max_value=256),),
        },
        "oidc_nonce": {
            "label": "OIDC nonce",
            "description": "Generate a random OpenID Connect nonce.",
            "inputs": (),
            "options": (_feature_field("nbytes", "Bytes", "int", 32, min_value=16, max_value=256),),
        },
        "csp_nonce": {
            "label": "CSP nonce",
            "description": "Generate a random Content Security Policy nonce.",
            "inputs": (),
            "options": (_feature_field("nbytes", "Bytes", "int", 24, min_value=16, max_value=256),),
        },
        "webhook_sign": {
            "label": "Webhook sign",
            "description": "Sign a webhook payload with HMAC SHA-2.",
            "inputs": (
                _feature_field("payload", "Payload", "text", None, required=True, sensitive=True, max_length=text_limit),
                _feature_field("secret", "Secret", "string", None, required=True, sensitive=True, max_length=secret_limit),
            ),
            "options": (
                _feature_field("algorithm", "Algorithm", "select", "sha256", choices=algorithms_hmac),
                _feature_field("encoding", "Encoding", "select", "hex", choices=_choice_specs("hex", "base64", "base64url")),
                _feature_field("prefix", "Include algorithm prefix", "bool", True),
            ),
        },
        "webhook_verify": {
            "label": "Webhook verify",
            "description": "Constant-time verification of a webhook HMAC signature.",
            "inputs": (
                _feature_field("payload", "Payload", "text", None, required=True, sensitive=True, max_length=text_limit),
                _feature_field("secret", "Secret", "string", None, required=True, sensitive=True, max_length=secret_limit),
                _feature_field("signature", "Signature", "string", None, required=True, sensitive=True, max_length=2048),
            ),
            "options": (
                _feature_field("algorithm", "Algorithm", "select", "sha256", choices=algorithms_hmac),
                _feature_field("encoding", "Encoding", "select", "hex", choices=_choice_specs("hex", "base64", "base64url")),
            ),
        },
        "dotenv": {
            "label": ".env inspector",
            "description": "Validate, compare, sort, redact, or derive a literal .env file.",
            "inputs": (
                _feature_field("text", ".env input", "text", None, required=True, sensitive=True, max_length=text_limit),
                _feature_field("other", "Comparison .env", "text", "", sensitive=True, max_length=text_limit),
            ),
            "options": (
                _feature_field("action", "Action", "select", "validate", choices=_choice_specs("validate", "compare", "sort", "redact", "example")),
                _feature_field("mask", "Redaction mask", "string", "********", max_length=128),
            ),
        },
        "timestamp": {
            "label": "Timestamp converter",
            "description": "Convert epoch or ISO-8601 values across IANA time zones.",
            "inputs": (_feature_field("value", "Timestamp", "json", None, required=True),),
            "options": (
                _feature_field("input_format", "Input format", "select", "auto", choices=_choice_specs("auto", "iso8601", "epoch_seconds", "epoch_milliseconds")),
                _feature_field("input_timezone", "Input time zone", "string", "UTC", max_length=255),
                _feature_field("output_timezones", "Output time zones", "list", ["UTC"]),
                _feature_field("fold", "DST fold", "select", 0, choices=_choice_specs(0, 1)),
            ),
        },
        "regex": {
            "label": "Regex tester",
            "description": "Test regular expressions with match, group, replacement, and timeout limits.",
            "inputs": (
                _feature_field("pattern", "Pattern", "string", None, required=True, max_length=4096),
                _feature_field("text", "Input", "text", None, required=True, sensitive=True, max_length=text_limit),
                _feature_field("replacement", "Replacement", "string", None, nullable=True, max_length=text_limit),
            ),
            "options": (
                _feature_field("flags", "Flags", "string", "", max_length=16),
                _feature_field("max_matches", "Maximum matches", "int", 100, min_value=1, max_value=1000),
                _feature_field("timeout_ms", "Timeout milliseconds", "int", 100, min_value=1, max_value=5000),
            ),
        },
        "jsonpath": {
            "label": "JSONPath",
            "description": "Query JSON with strict RFC 9535 JSONPath semantics.",
            "inputs": (
                _feature_field("document", "JSON document", "json", None, required=True, sensitive=True),
                _feature_field("query", "JSONPath", "string", "$", max_length=16_384),
            ),
            "options": (_feature_field("max_results", "Maximum results", "int", 100, min_value=1, max_value=1000),),
        },
        "checksum": {
            "label": "Checksum",
            "description": "Calculate one or more checksums for text or encoded bytes.",
            "inputs": (_feature_field("data", "Data", "text", None, required=True, sensitive=True, max_length=text_limit),),
            "options": (
                _feature_field("input_encoding", "Input encoding", "select", "text", choices=_choice_specs("text", "base64", "base64url", "hex")),
                _feature_field("algorithms", "Algorithms", "list", ["sha256"]),
            ),
        },
        "id_inspect": {
            "label": "Identifier inspector",
            "description": "Inspect UUID, ULID, or MongoDB ObjectId structure and timestamps.",
            "inputs": (_feature_field("value", "Identifier", "string", None, required=True, max_length=256),),
            "options": (_feature_field("kind", "Identifier kind", "select", "auto", choices=_choice_specs("auto", "uuid", "ulid", "objectid")),),
        },
        "user_agent_hints": {
            "label": "User-Agent Client Hints",
            "description": "Derive a consistent Chromium Client Hints request bundle.",
            "inputs": (_feature_field("user_agent", "User-Agent", "text", None, required=True, max_length=8192),),
            "options": (),
        },
    }

    missing = set(features.FEATURE_HANDLERS) - set(definitions)
    extra = set(definitions) - set(features.FEATURE_HANDLERS)
    if missing or extra:
        raise RuntimeError(
            "Feature registry metadata is out of sync: "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )

    for tool_id, definition in definitions.items():
        closure_values = [cell.cell_contents for cell in (features.FEATURE_HANDLERS[tool_id].__closure__ or ())]
        functions = [value for value in closure_values if inspect.isfunction(value)]
        if len(functions) != 1:
            raise RuntimeError(f"Cannot inspect the feature function for '{tool_id}'")
        parameters = inspect.signature(functions[0]).parameters.values()
        declared = {
            parameter.name
            for parameter in parameters
            if parameter.kind not in {inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL}
        }
        fields = {field.key for field in (*definition["inputs"], *definition["options"])}
        if declared and fields != declared:
            raise RuntimeError(
                f"Feature fields for '{tool_id}' do not match its function: "
                f"fields={sorted(fields)}, parameters={sorted(declared)}"
            )

    for tool_id, definition in definitions.items():
        metadata = features.FEATURE_METADATA[tool_id]
        random = bool(metadata["random"])
        spec = ToolSpec(
            id=tool_id,
            label=definition["label"],
            category=metadata["category"],
            description=definition["description"],
            handler=_adapt_feature_handler(features.FEATURE_HANDLERS[tool_id], random=random),
            inputs=definition["inputs"],
            options=definition["options"],
            random=random,
            output_kind="list" if random else "record",
            batchable=True,
            max_count=MAX_COUNT if random else 1,
            sensitive=bool(metadata["sensitive_inputs"]) or random,
            output_size_estimator=(
                _feature_output_size_estimator(tool_id) if random else None
            ),
        )
        register_tool(spec, replace=tool_id in REGISTRY)

    # Inject the pinned RFC 9535 implementation while retaining tool_features'
    # explicit engine boundary and result limit.
    from itertools import islice

    import jsonpath

    def strict_jsonpath_engine(document: Any, query: str, limit: int) -> list[Any]:
        try:
            matches = jsonpath.finditer(query, document, strict=True)
            return [match.obj for match in islice(matches, limit)]
        except jsonpath.JSONPathError as exc:
            raise ValueError(f"invalid RFC 9535 JSONPath: {exc}") from exc

    features.register_jsonpath_engine(strict_jsonpath_engine)


_register_text_diff_tool()
_register_feature_tools()
