import { WORDS } from "./words.js";

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";
const AMBIGUOUS = new Set("Il1O0o");
const NANOID = "_-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const URLSAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const CHARSETS = {
  alphanumeric: LOWER + UPPER + DIGITS,
  alpha: LOWER + UPPER,
  lower: LOWER,
  upper: UPPER,
  numeric: DIGITS,
  hex: "0123456789abcdef",
  hex_upper: "0123456789ABCDEF",
};

const f = (key, label, type, defaultValue, extra = {}) => ({ key, label, type, default: defaultValue, ...extra });
const tool = (id, label, category, description, inputs = [], options = [], extra = {}) => ({
  id, label, category, description, inputs, options, random: false, batchable: false,
  output_kind: "text", execution_mode: "browser", max_count: 1, ...extra,
});
const randomTool = (id, label, category, description, options, extra = {}) => tool(
  id, label, category, description, [], options,
  { random: true, batchable: true, max_count: 1000, sensitive: true, ...extra },
);
const secret = { sensitive: true, persist: false, autocomplete: "off" };
const freeform = { persist: false };

export const LOCAL_SPECS = [
  randomTool("uuid", "UUID", "IDs", "RFC 9562 UUID v1, v4, v6, or v7.", [
    f("version", "Version", "select", 4, { choices: [4, 7, 1, 6].map(v => ({ value: v, label: `v${v}` })) }),
    f("uppercase", "Uppercase", "bool", false), f("hyphens", "Hyphens", "bool", true),
  ], { sensitive: false }),
  randomTool("ulid", "ULID", "IDs", "Time-sortable Crockford Base32 identifier.", [f("uppercase", "Uppercase", "bool", true)], { sensitive: false }),
  randomTool("nanoid", "Nano ID", "IDs", "Compact identifier with an unbiased custom alphabet.", [
    f("size", "Size", "int", 21, { min: 2, max: 256 }), f("alphabet", "Alphabet", "string", NANOID, { max_length: 1024 }),
  ]),
  randomTool("objectid", "Mongo ObjectId", "IDs", "MongoDB-style ObjectId containing the current timestamp.", [f("uppercase", "Uppercase", "bool", false)], { sensitive: false }),
  tool("id_inspect", "ID inspector", "IDs", "Inspect UUID, ULID, and Mongo ObjectId structure and timestamps.", [
    f("value", "Identifier", "string", "", { ...freeform, placeholder: "UUID, ULID, or ObjectId" }),
  ]),

  randomTool("hex", "Hex token", "Tokens", "Hex-encoded cryptographically random bytes.", [
    f("nbytes", "Bytes", "int", 32, { min: 1, max: 512 }), f("uppercase", "Uppercase", "bool", false),
  ]),
  randomTool("urlsafe", "URL-safe token", "Tokens", "Unpadded URL-safe Base64 random bytes.", [f("nbytes", "Bytes", "int", 32, { min: 1, max: 512 })]),
  randomTool("base64", "Base64 secret", "Tokens", "Base64-encoded cryptographically random bytes.", [
    f("nbytes", "Bytes", "int", 32, { min: 1, max: 512 }), f("urlsafe", "URL-safe alphabet", "bool", false),
  ]),
  randomTool("apikey", "API key", "Tokens", "Prefixed API key for local development.", [
    f("prefix", "Prefix", "string", "sk", { max_length: 64 }), f("separator", "Separator", "string", "_", { max_length: 8 }),
    f("nbytes", "Bytes", "int", 24, { min: 8, max: 256 }),
    f("encoding", "Encoding", "select", "urlsafe", { choices: [{ value: "urlsafe", label: "URL-safe Base64" }, { value: "hex", label: "Hex" }] }),
  ]),
  randomTool("pkce", "PKCE & nonces", "OAuth", "Generate PKCE S256 pairs and OAuth/OIDC/CSP nonces.", [
    f("kind", "Value", "select", "pkce", { choices: [
      { value: "pkce", label: "PKCE S256 pair" }, { value: "state", label: "OAuth state" },
      { value: "oidc", label: "OIDC nonce" }, { value: "csp", label: "CSP nonce" },
    ] }), f("length", "Verifier length", "int", 64, { min: 43, max: 128 }),
  ]),

  randomTool("password", "Password", "Passwords", "Strong password with per-class policy guarantees.", [
    f("length", "Length", "int", 20, { min: 4, max: 256 }),
    f("lowercase", "Lowercase", "bool", true), f("uppercase", "Uppercase", "bool", true),
    f("digits", "Digits", "bool", true), f("symbols", "Symbols", "bool", true),
    f("min_lowercase", "Min lowercase", "int", 1, { min: 0, max: 256 }),
    f("min_uppercase", "Min uppercase", "int", 1, { min: 0, max: 256 }),
    f("min_digits", "Min digits", "int", 1, { min: 0, max: 256 }),
    f("min_symbols", "Min symbols", "int", 1, { min: 0, max: 256 }),
    f("custom_symbols", "Symbol set", "string", SYMBOLS, { max_length: 256 }),
    f("required_chars", "Required characters", "string", "", { max_length: 256 }),
    f("excluded_chars", "Excluded characters", "string", "", { max_length: 256 }),
    f("exclude_ambiguous", "Exclude ambiguous (Il1O0o)", "bool", false),
  ]),
  randomTool("password_policy", "Password policy", "Passwords", "Generate passwords that satisfy explicit per-class rules.", [
    f("length", "Length", "int", 20, { min: 4, max: 256 }),
    f("lowercase", "Lowercase", "bool", true), f("uppercase", "Uppercase", "bool", true),
    f("digits", "Digits", "bool", true), f("symbols", "Symbols", "bool", true),
    f("min_lowercase", "Min lowercase", "int", 1, { min: 0, max: 256 }),
    f("min_uppercase", "Min uppercase", "int", 1, { min: 0, max: 256 }),
    f("min_digits", "Min digits", "int", 1, { min: 0, max: 256 }),
    f("min_symbols", "Min symbols", "int", 1, { min: 0, max: 256 }),
    f("custom_symbols", "Symbol set", "string", SYMBOLS, { max_length: 256 }),
    f("required_chars", "Required characters", "string", "", { max_length: 256 }),
    f("excluded_chars", "Excluded characters", "string", "", { max_length: 256 }),
    f("exclude_ambiguous", "Exclude ambiguous (Il1O0o)", "bool", false),
  ]),
  randomTool("string", "Random string", "Passwords", "Random string over a preset or custom character set.", [
    f("length", "Length", "int", 32, { min: 1, max: 1024 }),
    f("charset", "Charset", "select", "alphanumeric", { choices: [
      ["alphanumeric", "Alphanumeric"], ["alpha", "Letters"], ["lower", "Lowercase"], ["upper", "Uppercase"],
      ["numeric", "Digits"], ["hex", "Hex (lower)"], ["hex_upper", "Hex (upper)"], ["custom", "Custom…"],
    ].map(([value, label]) => ({ value, label })) }), f("custom_charset", "Custom charset", "string", "", { max_length: 1024 }),
  ]),
  randomTool("pin", "Numeric PIN", "Passwords", "Numeric PIN with leading zeros preserved.", [f("length", "Length", "int", 6, { min: 3, max: 12 })]),
  randomTool("passphrase", "Passphrase", "Passwords", "Memorable passphrase from the EFF short wordlist.", [
    f("words", "Words", "int", 4, { min: 2, max: 16 }), f("separator", "Separator", "string", "-", { max_length: 16 }),
    f("capitalize", "Capitalize", "bool", false), f("add_number", "Append number", "bool", false),
  ]),

  tool("jwt", "JWT builder", "Web/API", "Build a development JWT using HS256, HS384, HS512, or decode-only alg none.", [
    f("subject", "Subject", "string", "user_123", freeform), f("issuer", "Issuer", "string", "fast-secrets", freeform),
    f("audience", "Audience", "string", "local-dev", freeform), f("secret", "HMAC secret", "password", "dev-secret", secret),
  ], [
    f("ttl_seconds", "TTL seconds", "int", 3600, { min: 1, max: 31536000 }),
    f("algorithm", "Algorithm", "select", "HS256", { choices: ["HS256", "HS384", "HS512", "none"].map(value => ({ value, label: value })) }),
    f("include_jti", "Include jti", "bool", true),
  ], { random: true, max_count: 100, sensitive: true }),
  tool("jwt_decode", "JWT decode", "Web/API", "Decode a JWT without treating it as verified.", [
    f("token", "JWT", "password", "", { ...secret, placeholder: "eyJ…" }),
  ], [f("pretty", "Pretty JSON", "bool", true)], { sensitive: true }),
  tool("jwt_debugger", "JWT debugger", "Web/API", "Decode, sign, verify, and evaluate common JWT claims locally.", [
    f("token", "JWT", "password", "", { ...secret, placeholder: "Token for decode/verify" }),
    f("header", "Header JSON", "text", "{\n  \"typ\": \"JWT\",\n  \"alg\": \"HS256\"\n}", freeform),
    f("payload", "Claims JSON", "text", "{\n  \"sub\": \"user_123\",\n  \"iss\": \"fast-secrets\",\n  \"aud\": \"local-dev\"\n}", freeform),
    f("secret", "HMAC secret", "password", "", secret),
    f("expected_issuer", "Expected issuer", "string", "", freeform), f("expected_audience", "Expected audience", "string", "", freeform),
  ], [
    f("mode", "Action", "select", "decode", { choices: ["decode", "sign", "verify"].map(value => ({ value, label: value[0].toUpperCase() + value.slice(1) })) }),
    f("algorithm", "Signing algorithm", "select", "HS256", { choices: ["HS256", "HS384", "HS512"].map(value => ({ value, label: value })) }),
    f("allowed_algorithms", "Allowed verification algorithms", "string", "HS256,HS384,HS512", { max_length: 64 }),
    f("clock_skew", "Clock skew seconds", "int", 60, { min: 0, max: 86400 }),
  ], { sensitive: true }),
  tool("basic_auth", "Basic Auth", "Web/API", "Build an HTTP Basic Authorization value.", [
    f("username", "Username", "string", "user", freeform), f("password", "Password", "password", "", secret),
  ], [f("include_scheme", "Include Basic", "bool", true)], { sensitive: true }),
  tool("webhook_hmac", "Webhook HMAC", "Web/API", "Sign or verify a webhook payload with HMAC.", [
    f("text", "Payload", "text", "", { ...secret, placeholder: "Raw request body" }), f("key", "Signing secret", "password", "", secret),
    f("signature", "Expected signature", "password", "", { ...secret, placeholder: "Hex signature for verify" }),
  ], [
    f("mode", "Action", "select", "sign", { choices: [{ value: "sign", label: "Sign" }, { value: "verify", label: "Verify" }] }),
    f("algorithm", "Algorithm", "select", "sha256", { choices: ["sha256", "sha384", "sha512"].map(value => ({ value, label: value.toUpperCase() })) }),
  ], { sensitive: true }),
  randomTool("user_agent", "User-Agent", "Web/API", "Generate a modern browser, crawler, or HTTP client User-Agent.", [
    f("agent_type", "Type", "select", "browser", { choices: ["browser", "crawler", "client"].map(value => ({ value, label: value })) }),
    f("browser", "Browser", "select", "weighted", { choices: ["weighted", "chrome", "safari", "edge", "firefox", "samsung", "opera"].map(value => ({ value, label: value })) }),
    f("platform", "Platform", "select", "weighted", { choices: ["weighted", "desktop", "mobile", "tablet"].map(value => ({ value, label: value })) }),
    f("reduced", "Reduced modern format", "bool", true),
  ], { sensitive: false }),
  tool("user_agent_bundle", "UA request bundle", "Web/API", "Generate a User-Agent with matching Client Hints headers.", [], [
    f("browser", "Browser", "select", "chrome", { choices: ["chrome", "edge", "safari", "firefox"].map(value => ({ value, label: value })) }),
    f("platform", "Platform", "select", "desktop", { choices: ["desktop", "mobile", "tablet"].map(value => ({ value, label: value })) }),
  ], { random: true, batchable: true, max_count: 100, sensitive: false }),

  tool("base64_text", "Base64 text", "Encoders", "Encode or decode UTF-8 Base64 text.", [f("text", "Input", "text", "", freeform)], [
    f("mode", "Mode", "select", "encode", { choices: [{ value: "encode", label: "Encode" }, { value: "decode", label: "Decode" }] }),
    f("urlsafe", "URL-safe alphabet", "bool", false), f("padding", "Keep padding", "bool", true),
  ]),
  tool("base32", "Base32", "Encoders", "Encode or decode RFC 4648 Base32 text.", [f("text", "Input", "text", "", freeform)], [
    f("mode", "Mode", "select", "encode", { choices: [{ value: "encode", label: "Encode" }, { value: "decode", label: "Decode" }] }),
    f("padding", "Keep padding", "bool", true),
  ]),
  tool("url_codec", "URL encode", "Encoders", "Percent-encode or decode URL text.", [f("text", "Input", "text", "", freeform)], [
    f("mode", "Mode", "select", "encode", { choices: [{ value: "encode", label: "Encode" }, { value: "decode", label: "Decode" }] }),
    f("component", "Component mode", "bool", true), f("plus_spaces", "Spaces as +", "bool", false),
  ]),

  tool("hotp", "HOTP", "Authentication", "Generate RFC 4226 counter-based one-time passwords.", [
    f("secret", "Base32 secret", "password", "", { ...secret, placeholder: "Leave blank to generate" }),
    f("issuer", "Issuer", "string", "fast-secrets", freeform), f("account", "Account", "string", "user@example.com", freeform),
  ], [
    f("algorithm", "Algorithm", "select", "SHA-1", { choices: ["SHA-1", "SHA-256", "SHA-512"].map(value => ({ value, label: value })) }),
    f("digits", "Digits", "select", 6, { choices: [6, 8].map(value => ({ value, label: String(value) })) }),
    f("counter", "Counter", "int", 0, { min: 0, max: Number.MAX_SAFE_INTEGER }),
  ], { sensitive: true }),
  tool("totp", "TOTP", "Authentication", "Generate RFC 6238 time-based one-time passwords and enrollment URIs.", [
    f("secret", "Base32 secret", "password", "", { ...secret, placeholder: "Leave blank to generate" }),
    f("issuer", "Issuer", "string", "fast-secrets", freeform), f("account", "Account", "string", "user@example.com", freeform),
  ], [
    f("algorithm", "Algorithm", "select", "SHA-1", { choices: ["SHA-1", "SHA-256", "SHA-512"].map(value => ({ value, label: value })) }),
    f("digits", "Digits", "select", 6, { choices: [6, 8].map(value => ({ value, label: String(value) })) }),
    f("period", "Period seconds", "int", 30, { min: 1, max: 86400 }),
  ], { sensitive: true }),

  tool("env", ".env inspector", "Config", "Inspect, compare, sort, redact, or derive a .env.example without evaluation.", [
    f("text", ".env input", "text", "", { ...secret, placeholder: "KEY=value" }),
    f("compare", "Compare with", "text", "", { ...secret, placeholder: "Optional second .env" }),
  ], [f("mode", "Action", "select", "inspect", { choices: [
    ["inspect", "Inspect"], ["compare", "Compare keys"], ["sort", "Sort"], ["redact", "Redact"], ["example", "Create .env.example"],
  ].map(([value, label]) => ({ value, label })) })], { sensitive: true }),
  tool("timestamp", "Timestamp & time zones", "Date/Time", "Convert epoch or ISO-8601 input across UTC, local, and IANA zones.", [
    f("value", "Timestamp", "string", "", { ...freeform, placeholder: "Now, epoch seconds/ms, or ISO-8601" }),
  ], [f("timezone", "IANA time zone", "string", "UTC", { placeholder: "America/Mexico_City" })]),
  tool("regex", "Regex tester", "Text", "Test regular expressions in a time-limited worker.", [
    f("pattern", "Pattern", "string", "", { ...freeform, max_length: 2000 }), f("text", "Input", "text", "", { ...freeform, max_length: 20000 }),
    f("replacement", "Replacement", "string", "", { ...freeform, max_length: 2000 }),
  ], [f("flags", "Flags", "string", "g", { max_length: 8 })]),
  tool("jsonpath", "JSONPath", "Structured data", "Query JSON locally using the RFC 9535 standard.", [
    f("text", "JSON", "text", "", freeform), f("path", "Path", "string", "$", { ...freeform, placeholder: "$.items[*].id" }),
  ]),
  tool("json", "JSON", "Formatters", "Format, minify, or validate JSON text.", [f("text", "JSON", "text", "{\"hello\":\"world\"}", freeform)], [
    f("mode", "Mode", "select", "format", { choices: ["format", "minify", "validate"].map(value => ({ value, label: value })) }),
    f("indent", "Indent", "int", 2, { min: 1, max: 8 }), f("sort_keys", "Sort keys", "bool", false),
  ]),
  tool("text_case", "Text case", "Text", "Convert text between common identifier and display cases.", [f("text", "Input", "text", "", freeform)], [
    f("case", "Case", "select", "snake", { choices: ["snake", "camel", "pascal", "kebab", "slug", "constant", "title", "upper", "lower"].map(value => ({ value, label: value })) }),
  ]),
  tool("hash", "Hash", "Hashing", "Hash text locally with Web Crypto; MD5 is compatibility-only.", [f("text", "Input", "text", "", freeform)], [
    f("algorithm", "Algorithm", "select", "sha256", { choices: ["sha256", "sha384", "sha512", "sha1", "md5"].map(value => ({ value, label: value.toUpperCase() })) }),
    f("uppercase", "Uppercase", "bool", false),
  ]),
  tool("hmac", "HMAC", "Hashing", "Compute a keyed HMAC locally with Web Crypto.", [
    f("text", "Input", "text", "", { ...secret, sensitive: true }), f("key", "Key", "password", "", secret),
  ], [
    f("algorithm", "Algorithm", "select", "sha256", { choices: ["sha256", "sha384", "sha512"].map(value => ({ value, label: value.toUpperCase() })) }),
    f("uppercase", "Uppercase", "bool", false),
  ], { sensitive: true }),
  tool("checksum", "File checksum", "Hashing", "Hash a local file without uploading it.", [f("file", "File", "file", null, { persist: false })], [
    f("algorithm", "Algorithm", "select", "sha256", { choices: ["sha256", "sha384", "sha512", "sha1"].map(value => ({ value, label: value.toUpperCase() })) }),
  ], { max_input_bytes: 268435456 }),

  randomTool("email", "Email address", "Fixture data", "Safe random email fixture using a configurable domain.", [
    f("domain", "Domain", "string", "example.com", { max_length: 253 }), f("plus_tag", "Plus tag", "bool", false),
  ], { sensitive: false }),
  randomTool("ipv4", "IPv4 address", "Fixture data", "Private, documentation, or loopback IPv4 fixture.", [
    f("kind", "Range", "select", "private", { choices: ["private", "documentation", "loopback", "public"].map(value => ({ value, label: value })) }),
  ], { sensitive: false }),
  randomTool("ipv6", "IPv6 address", "Fixture data", "Documentation, unique-local, or loopback IPv6 fixture.", [
    f("kind", "Range", "select", "documentation", { choices: ["documentation", "ula", "loopback"].map(value => ({ value, label: value })) }),
  ], { sensitive: false }),
  randomTool("mac", "MAC address", "Fixture data", "Random locally-administered MAC address.", [
    f("separator", "Separator", "select", ":", { choices: [{ value: ":", label: "Colon" }, { value: "-", label: "Hyphen" }, { value: "", label: "None" }] }),
    f("uppercase", "Uppercase", "bool", false), f("locally_administered", "Locally administered", "bool", true),
  ], { sensitive: false }),
  randomTool("semver", "SemVer", "Fixture data", "Random semantic version fixture.", [
    f("include_prerelease", "Prerelease", "bool", false), f("include_build", "Build metadata", "bool", false),
  ], { sensitive: false }),
  randomTool("lorem", "Lorem ipsum", "Fixture data", "Random lorem ipsum paragraphs.", [
    f("paragraphs", "Paragraphs", "int", 1, { min: 1, max: 8 }), f("sentences", "Sentences", "int", 3, { min: 1, max: 12 }),
    f("words_per_sentence", "Words / sentence", "int", 12, { min: 4, max: 30 }),
  ], { sensitive: false }),
];

// API-shaped aliases remain independently discoverable while sharing the same
// audited browser-local primitives as the consolidated workbench tools above.
LOCAL_SPECS.push(
  tool("base32_encode", "Base32 encode", "Encoders", "Encode UTF-8 text using RFC 4648 Base32.", [f("text", "Text", "text", "", freeform)], [f("padding", "Keep padding", "bool", false)]),
  tool("base32_decode", "Base32 decode", "Encoders", "Decode RFC 4648 Base32 into UTF-8 text.", [f("value", "Base32 value", "text", "", freeform)]),
  randomTool("base32_secret", "Base32 secret", "Tokens", "Generate a cryptographically random Base32 secret.", [f("nbytes", "Bytes", "int", 20, { min: 10, max: 4096 }), f("padding", "Keep padding", "bool", false)]),
  tool("jwt_encode", "JWT sign", "Web/API", "Sign JSON claims with HS256, HS384, or HS512.", [
    f("claims", "Claims JSON", "text", "{\n  \"sub\": \"user_123\"\n}", freeform), f("header", "Additional header JSON", "text", "{}", freeform),
    f("secret", "HMAC secret", "password", "", secret),
  ], [f("algorithm", "Algorithm", "select", "HS256", { choices: ["HS256", "HS384", "HS512"].map(value => ({ value, label: value })) })], { sensitive: true }),
  tool("jwt_verify", "JWT verify", "Web/API", "Verify an HMAC JWT and validate common registered claims.", [
    f("token", "JWT", "password", "", secret), f("secret", "HMAC secret", "password", "", secret),
    f("issuer", "Expected issuer", "string", "", freeform), f("audience", "Expected audience", "string", "", freeform),
  ], [
    f("allowed_algorithms", "Allowed algorithms", "string", "HS256,HS384,HS512", { max_length: 64 }),
    f("leeway", "Clock skew seconds", "int", 0, { min: 0, max: 86400 }),
  ], { sensitive: true }),
  tool("hotp_verify", "HOTP verify", "Authentication", "Verify an HOTP code within a bounded look-ahead window.", [
    f("secret", "Base32 secret", "password", "", secret), f("code", "One-time code", "password", "", secret),
  ], [
    f("counter", "Counter", "int", 0, { min: 0, max: Number.MAX_SAFE_INTEGER }), f("look_ahead", "Look-ahead", "int", 0, { min: 0, max: 100 }),
    f("digits", "Digits", "select", 6, { choices: [6, 8].map(value => ({ value, label: String(value) })) }),
    f("algorithm", "Algorithm", "select", "SHA-1", { choices: ["SHA-1", "SHA-256", "SHA-512"].map(value => ({ value, label: value })) }),
  ], { sensitive: true }),
  tool("totp_verify", "TOTP verify", "Authentication", "Verify a TOTP code within a bounded time window.", [
    f("secret", "Base32 secret", "password", "", secret), f("code", "One-time code", "password", "", secret),
  ], [
    f("period", "Period seconds", "int", 30, { min: 1, max: 86400 }), f("window", "Window", "int", 1, { min: 0, max: 10 }),
    f("digits", "Digits", "select", 6, { choices: [6, 8].map(value => ({ value, label: String(value) })) }),
    f("algorithm", "Algorithm", "select", "SHA-1", { choices: ["SHA-1", "SHA-256", "SHA-512"].map(value => ({ value, label: value })) }),
  ], { sensitive: true }),
  tool("otpauth_build", "OTPAuth URI builder", "Authentication", "Build an interoperable otpauth enrollment URI and QR.", [
    f("secret", "Base32 secret", "password", "", secret), f("issuer", "Issuer", "string", "fast-secrets", freeform), f("account", "Account", "string", "user@example.com", freeform),
  ], [
    f("otp_type", "OTP type", "select", "totp", { choices: ["totp", "hotp"].map(value => ({ value, label: value.toUpperCase() })) }),
    f("algorithm", "Algorithm", "select", "SHA-1", { choices: ["SHA-1", "SHA-256", "SHA-512"].map(value => ({ value, label: value })) }),
    f("digits", "Digits", "select", 6, { choices: [6, 8].map(value => ({ value, label: String(value) })) }),
    f("period", "Period seconds", "int", 30, { min: 1, max: 86400 }), f("counter", "Counter", "int", 0, { min: 0, max: Number.MAX_SAFE_INTEGER }),
  ], { sensitive: true }),
  tool("otpauth_parse", "OTPAuth URI parser", "Authentication", "Parse and validate an otpauth enrollment URI locally.", [f("uri", "OTPAuth URI", "password", "", secret)], [], { sensitive: true }),
  randomTool("pkce_generate", "PKCE pair", "OAuth", "Generate an RFC 7636 verifier and S256 challenge.", [f("length", "Verifier length", "int", 64, { min: 43, max: 128 })]),
  tool("pkce_challenge", "PKCE challenge", "OAuth", "Derive an RFC 7636 S256 challenge from a verifier.", [f("verifier", "Verifier", "password", "", secret)], [], { sensitive: true }),
  randomTool("oauth_state", "OAuth state", "OAuth", "Generate a random OAuth state value.", [f("nbytes", "Bytes", "int", 32, { min: 16, max: 256 })]),
  randomTool("oidc_nonce", "OIDC nonce", "OAuth", "Generate a random OpenID Connect nonce.", [f("nbytes", "Bytes", "int", 32, { min: 16, max: 256 })]),
  randomTool("csp_nonce", "CSP nonce", "OAuth", "Generate a random Content Security Policy nonce.", [f("nbytes", "Bytes", "int", 24, { min: 16, max: 256 })]),
  tool("webhook_sign", "Webhook sign", "Web/API", "Sign a webhook payload with HMAC SHA-2.", [
    f("payload", "Payload", "password", "", secret), f("secret", "Secret", "password", "", secret),
  ], [
    f("algorithm", "Algorithm", "select", "sha256", { choices: ["sha256", "sha384", "sha512"].map(value => ({ value, label: value.toUpperCase() })) }),
    f("encoding", "Encoding", "select", "hex", { choices: ["hex", "base64", "base64url"].map(value => ({ value, label: value })) }), f("prefix", "Include algorithm prefix", "bool", true),
  ], { sensitive: true }),
  tool("webhook_verify", "Webhook verify", "Web/API", "Constant-time verification of a webhook HMAC signature.", [
    f("payload", "Payload", "password", "", secret), f("secret", "Secret", "password", "", secret), f("signature", "Signature", "password", "", secret),
  ], [
    f("algorithm", "Algorithm", "select", "sha256", { choices: ["sha256", "sha384", "sha512"].map(value => ({ value, label: value.toUpperCase() })) }),
    f("encoding", "Encoding", "select", "hex", { choices: ["hex", "base64", "base64url"].map(value => ({ value, label: value })) }),
  ], { sensitive: true }),
  tool("dotenv", ".env inspector (API)", "Config", "Validate, compare, sort, redact, or derive a literal .env file.", [
    f("text", ".env input", "password", "", secret), f("other", "Comparison .env", "password", "", secret),
  ], [
    f("action", "Action", "select", "validate", { choices: ["validate", "compare", "sort", "redact", "example"].map(value => ({ value, label: value })) }),
    f("mask", "Redaction mask", "string", "********", { max_length: 128 }),
  ], { sensitive: true }),
  tool("user_agent_hints", "User-Agent Client Hints", "Web/API", "Derive a consistent Chromium Client Hints request bundle.", [f("user_agent", "User-Agent", "text", "", freeform)]),
);

export const LOCAL_BY_ID = Object.fromEntries(LOCAL_SPECS.map(spec => [spec.id, spec]));

export function mergeSpecs(remote) {
  const remoteList = Array.isArray(remote) ? remote : (remote && (remote.tools || remote.generators)) || [];
  const byId = new Map(LOCAL_SPECS.map(spec => [spec.id, spec]));
  for (const incoming of remoteList) {
    if (!incoming || !incoming.id || !LOCAL_BY_ID[incoming.id]) continue;
    const local = LOCAL_BY_ID[incoming.id];
    byId.set(incoming.id, {
      ...local,
      label: incoming.label || local.label,
      category: incoming.category || local.category,
      description: incoming.description || local.description,
      max_count: Math.min(local.max_count || 1, Number(incoming.max_count) || local.max_count || 1),
      sensitive: !!(local.sensitive || incoming.sensitive),
      execution_mode: "browser",
    });
  }
  return [...byId.values()];
}

function clamp(value, min, max) {
  const n = Math.floor(Number(value));
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : min;
}

function requireInteger(name, value, minimum, maximum) {
  if (typeof value === "boolean" || value == null || (typeof value === "string" && !/^[+-]?\d+$/.test(value.trim()))) {
    throw new Error(`${name} must be a safe integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} must be a safe integer`);
  if (parsed < minimum || parsed > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  return parsed;
}

function requireFiniteNumber(name, value, minimum, maximum) {
  if (typeof value === "boolean" || value == null || (typeof value === "string" && !value.trim())) throw new Error(`${name} must be a finite number`);
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`${name} must be a finite number`);
  if (parsed < minimum || parsed > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  return parsed;
}

export function randomBytes(length) {
  const out = new Uint8Array(clamp(length, 0, 65536));
  crypto.getRandomValues(out);
  return out;
}

export function randomInt(max) {
  if (!Number.isSafeInteger(max) || max < 1 || max > 0x100000000) throw new Error("Invalid random range");
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return buf[0] % max;
}

const choice = values => values[randomInt(values.length)];
function shuffled(values) {
  const out = [...values];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
function randomString(length, alphabet) {
  const pool = [...new Set([...String(alphabet)])];
  if (pool.length < 2) throw new Error("Alphabet must contain at least two distinct characters");
  return Array.from({ length: clamp(length, 1, 4096) }, () => choice(pool)).join("");
}
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
const bytesEqual = (a, b) => a.length === b.length && a.reduce((v, n, i) => v | (n ^ b[i]), 0) === 0;

function bytesToBase64(bytes, urlsafe = false, padding = true) {
  let binary = "";
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i += 0x8000) binary += String.fromCharCode(...view.subarray(i, i + 0x8000));
  let value = btoa(binary);
  if (urlsafe) value = value.replace(/\+/g, "-").replace(/\//g, "_");
  return padding ? value : value.replace(/=+$/, "");
}
function base64ToBytes(value, urlsafe = false) {
  let normalized = String(value).replace(/\s/g, "");
  if (urlsafe) normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) throw new Error("Invalid Base64 input");
  normalized += "=".repeat((4 - normalized.length % 4) % 4);
  try { return Uint8Array.from(atob(normalized), c => c.charCodeAt(0)); }
  catch (_) { throw new Error("Invalid Base64 input"); }
}
const b64url = bytes => bytesToBase64(bytes, true, false);
const b64urlJson = value => b64url(te.encode(JSON.stringify(value)));

async function digestBytes(algorithm, value) {
  const names = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
  const name = names[String(algorithm).toLowerCase()];
  if (!name) throw new Error(`Unsupported digest: ${algorithm}`);
  const bytes = value instanceof ArrayBuffer || ArrayBuffer.isView(value) ? value : te.encode(String(value));
  return new Uint8Array(await crypto.subtle.digest(name, bytes));
}
async function hmacBytes(algorithm, key, data) {
  const names = { "SHA-1": "SHA-1", "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512", sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
  const name = names[algorithm] || names[String(algorithm).toLowerCase()];
  if (!name) throw new Error(`Unsupported HMAC digest: ${algorithm}`);
  const rawKey = typeof key === "string" ? te.encode(key) : key;
  const rawData = typeof data === "string" ? te.encode(data) : data;
  const cryptoKey = await crypto.subtle.importKey("raw", rawKey, { name: "HMAC", hash: name }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, rawData));
}

function formatUuid(bytes, uppercase, hyphens) {
  const h = hex(bytes);
  const value = hyphens === false ? h : `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  return uppercase ? value.toUpperCase() : value;
}
function uuidValue(o) {
  const version = Number(o.version ?? 4);
  const bytes = randomBytes(16);
  if (version === 4) {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
  } else if (version === 7) {
    let ms = BigInt(Date.now());
    for (let i = 5; i >= 0; i--) { bytes[i] = Number(ms & 255n); ms >>= 8n; }
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
  } else if (version === 1 || version === 6) {
    const gregorian = BigInt(Date.now()) * 10000n + 0x01b21dd213814000n;
    if (version === 1) {
      const low = Number(gregorian & 0xffffffffn);
      const mid = Number((gregorian >> 32n) & 0xffffn);
      const high = Number((gregorian >> 48n) & 0xfffn);
      bytes.set([low >>> 24, low >>> 16, low >>> 8, low, mid >>> 8, mid, 0x10 | (high >>> 8), high]);
    } else {
      const high = Number((gregorian >> 28n) & 0xffffffffn);
      const mid = Number((gregorian >> 12n) & 0xffffn);
      const low = Number(gregorian & 0xfffn);
      bytes.set([high >>> 24, high >>> 16, high >>> 8, high, mid >>> 8, mid, 0x60 | (low >>> 8), low]);
    }
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes[10] |= 0x02;
  } else throw new Error("UUID version must be 1, 4, 6, or 7");
  return formatUuid(bytes, o.uppercase, o.hyphens);
}
function ulidValue(o) {
  let value = (BigInt(Date.now()) << 80n) | BigInt(`0x${hex(randomBytes(10))}`);
  let out = "";
  for (let i = 0; i < 26; i++) { out = CROCKFORD[Number(value & 31n)] + out; value >>= 5n; }
  return o.uppercase === false ? out.toLowerCase() : out;
}
function objectIdValue(o) {
  const bytes = randomBytes(12);
  const seconds = Math.floor(Date.now() / 1000);
  bytes.set([seconds >>> 24, seconds >>> 16, seconds >>> 8, seconds], 0);
  const out = hex(bytes);
  return o.uppercase ? out.toUpperCase() : out;
}

function passwordValue(o) {
  const length = clamp(o.length ?? 20, 4, 256);
  const excluded = new Set(String(o.excluded_chars || ""));
  if (o.exclude_ambiguous) for (const char of AMBIGUOUS) excluded.add(char);
  const symbols = String(o.custom_symbols ?? SYMBOLS);
  const groups = [
    [o.lowercase !== false, LOWER, clamp(o.min_lowercase ?? 1, 0, 256), "lowercase"],
    [o.uppercase !== false, UPPER, clamp(o.min_uppercase ?? 1, 0, 256), "uppercase"],
    [o.digits !== false, DIGITS, clamp(o.min_digits ?? 1, 0, 256), "digits"],
    [o.symbols !== false, symbols, clamp(o.min_symbols ?? 1, 0, 256), "symbols"],
  ].filter(([enabled]) => enabled).map(([_, pool, min, label]) => [[...new Set([...pool])].filter(c => !excluded.has(c)).join(""), min, label]);
  if (!groups.length) throw new Error("Enable at least one character class");
  for (const [pool, min, label] of groups) if (!pool && min) throw new Error(`No ${label} characters remain after exclusions`);
  const required = [...new Set([...String(o.required_chars || "")])];
  if (required.some(c => excluded.has(c))) throw new Error("A required character is also excluded");
  const requiredSet = new Set(required);
  const chars = [...required];
  for (const [pool, min] of groups) {
    const already = chars.filter(c => pool.includes(c)).length;
    for (let i = already; i < min; i++) chars.push(choice([...pool]));
  }
  if (chars.length > length) throw new Error("Minimum and required character counts exceed the password length");
  const full = [...new Set(groups.map(([pool]) => pool).join("") + required.join(""))].filter(c => !excluded.has(c));
  if (full.length < 2 && length > chars.length) throw new Error("Policy leaves fewer than two usable characters");
  while (chars.length < length) chars.push(choice(full));
  return shuffled(chars).join("");
}

function passphraseValue(o) {
  const count = clamp(o.words ?? 4, 2, 16);
  const words = Array.from({ length: count }, () => choice(WORDS));
  if (o.capitalize) for (let i = 0; i < words.length; i++) {
    words[i] = words[i].replace(/(^|-)([a-z])/g, (_match, prefix, letter) => prefix + letter.toUpperCase());
  }
  if (o.add_number) { const i = randomInt(words.length); words[i] += randomInt(10); }
  return words.join(String(o.separator ?? "-"));
}

function base32Encode(bytes, padding = true) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0, out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return padding ? out.padEnd(Math.ceil(out.length / 8) * 8, "=") : out;
}
function base32Decode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const compact = String(text).toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  if (!compact || /[^A-Z2-7]/.test(compact)) throw new Error("Invalid Base32 input");
  if ([1, 3, 6].includes(compact.length % 8)) throw new Error("Invalid Base32 length");
  let value = 0, bits = 0; const out = [];
  for (const char of compact) {
    value = (value << 5) | alphabet.indexOf(char); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Uint8Array.from(out);
}

const JWT_ALGORITHMS = new Set(["HS256", "HS384", "HS512"]);

function parseJsonObject(value, name) {
  let parsed;
  try { parsed = JSON.parse(value || "{}"); } catch (_) { throw new Error(`${name} must be valid JSON`); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${name} must be a JSON object`);
  return parsed;
}

function allowedJwtAlgorithms(value) {
  let algorithms;
  if (value == null) algorithms = [...JWT_ALGORITHMS];
  else if (Array.isArray(value)) algorithms = value.map(item => String(item).toUpperCase());
  else if (typeof value === "string") algorithms = value.split(/[\s,]+/).filter(Boolean).map(item => item.toUpperCase());
  else throw new Error("Allowed algorithms must be an array or comma-separated string");
  if (algorithms.length > JWT_ALGORITHMS.size || algorithms.some(algorithm => !JWT_ALGORITHMS.has(algorithm))) {
    throw new Error("Allowed algorithms may contain only HS256, HS384, and HS512");
  }
  return new Set(algorithms);
}

async function jwtSign(header, payload, secretValue, algorithm) {
  if (!header || typeof header !== "object" || Array.isArray(header) || !payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Header and claims must be JSON objects");
  }
  const alg = String(algorithm || header.alg || "HS256").toUpperCase();
  if (!JWT_ALGORITHMS.has(alg)) throw new Error("Only HS256, HS384, and HS512 can be signed");
  if (!String(secretValue || "")) throw new Error("HMAC secret must not be empty");
  if (Object.prototype.hasOwnProperty.call(header, "alg") && String(header.alg).toUpperCase() !== alg) {
    throw new Error("Header alg conflicts with the selected signing algorithm");
  }
  const normalizedHeader = { ...header, alg };
  const signingInput = `${b64urlJson(normalizedHeader)}.${b64urlJson(payload)}`;
  const signature = await hmacBytes(`SHA-${alg.slice(2)}`, String(secretValue || ""), signingInput);
  return `${signingInput}.${b64url(signature)}`;
}
function decodeJwt(token) {
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1]) throw new Error("JWT must have three dot-separated parts");
  let header, payload;
  try { header = JSON.parse(td.decode(base64ToBytes(parts[0], true))); payload = JSON.parse(td.decode(base64ToBytes(parts[1], true))); }
  catch (_) { throw new Error("JWT header and claims must be valid Base64URL JSON objects"); }
  if (!header || typeof header !== "object" || Array.isArray(header) || !payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("JWT header and claims must be JSON objects");
  }
  return { parts, header, payload };
}
function claimStatuses(payload, expectedIssuer, expectedAudience, skew = 60) {
  const now = Math.floor(Date.now() / 1000); const statuses = [];
  for (const claim of ["exp", "nbf", "iat"]) {
    if (Object.prototype.hasOwnProperty.call(payload, claim) && (typeof payload[claim] !== "number" || !Number.isFinite(payload[claim]))) {
      throw new Error(`${claim} must be a finite NumericDate number`);
    }
    if (typeof payload[claim] === "number" && Math.abs(payload[claim]) > 253402300799) throw new Error(`${claim} is outside the supported NumericDate range`);
  }
  if (typeof payload.exp === "number") statuses.push({ claim: "exp", ok: now <= payload.exp + skew, detail: now <= payload.exp + skew ? "not expired" : "expired" });
  if (typeof payload.nbf === "number") statuses.push({ claim: "nbf", ok: now + skew >= payload.nbf, detail: now + skew >= payload.nbf ? "active" : "not active yet" });
  if (typeof payload.iat === "number") statuses.push({ claim: "iat", ok: payload.iat <= now + skew, detail: payload.iat <= now + skew ? "not in the future" : "issued in the future" });
  if (expectedIssuer) statuses.push({ claim: "iss", ok: payload.iss === expectedIssuer, detail: payload.iss === expectedIssuer ? "matches" : "does not match" });
  if (expectedAudience) {
    const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    statuses.push({ claim: "aud", ok: audience.includes(expectedAudience), detail: audience.includes(expectedAudience) ? "matches" : "does not match" });
  }
  return statuses;
}
async function jwtDebugger(o) {
  if (o.mode === "sign") {
    const header = parseJsonObject(o.header, "Header");
    const payload = parseJsonObject(o.payload, "Claims");
    const token = await jwtSign(header, payload, o.secret, o.algorithm);
    return { value: token, warnings: ["Development HMAC tokens are only as strong as their shared secret."] };
  }
  const decoded = decodeJwt(o.token);
  const skew = requireInteger("Clock skew", o.clock_skew ?? 60, 0, 86400);
  const result = { header: decoded.header, claims: decoded.payload, signature: "not verified", claim_status: claimStatuses(decoded.payload, o.expected_issuer, o.expected_audience, skew) };
  const warnings = [];
  if (String(decoded.header.alg).toLowerCase() === "none") {
    result.signature = "unsigned (decode only)";
    warnings.push("alg none is never treated as verified.");
  } else if (o.mode === "verify") {
    const alg = decoded.header.alg;
    const allowed = allowedJwtAlgorithms(o.allowed_algorithms);
    if (typeof alg !== "string" || !JWT_ALGORITHMS.has(alg) || !allowed.has(alg)) throw new Error("JWT algorithm is not in the explicit verification allow-list");
    if (!String(o.secret || "")) throw new Error("HMAC secret must not be empty");
    const expected = await hmacBytes(`SHA-${alg.slice(2)}`, String(o.secret || ""), `${decoded.parts[0]}.${decoded.parts[1]}`);
    let actual; try { actual = base64ToBytes(decoded.parts[2], true); } catch (_) { actual = new Uint8Array(); }
    const verified = bytesEqual(expected, actual);
    result.signature = verified ? "verified" : "invalid";
    result.signature_verified = verified;
    result.claims_valid = result.claim_status.every(status => status.ok);
    result.verified = verified && result.claims_valid;
  } else warnings.push("Decoded only; the signature has not been verified.");
  return { value: JSON.stringify(result, null, 2), warnings };
}

function otpAlgorithm(value) {
  const compact = String(value || "SHA1").toUpperCase().replace(/-/g, "");
  const webCrypto = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" }[compact];
  if (!webCrypto) throw new Error("OTP algorithm must be SHA1, SHA256, or SHA512");
  return { compact, webCrypto };
}

function otpDigits(value) {
  const digits = requireInteger("OTP digits", value ?? 6, 6, 8);
  if (![6, 8].includes(digits)) throw new Error("OTP digits must be 6 or 8");
  return digits;
}

function otpLabel(o) {
  const issuer = o.issuer == null ? "fast-secrets" : String(o.issuer);
  const account = o.account == null ? "user" : String(o.account);
  if (!account) throw new Error("OTP account must not be empty");
  if (issuer.includes(":") || account.includes(":")) throw new Error("OTP issuer and account must not contain a colon");
  return { issuer, account, label: issuer ? `${issuer}:${account}` : account };
}

async function otpValue(o, kind) {
  let secretText = String(o.secret || "").trim();
  if (!secretText) secretText = base32Encode(randomBytes(20), false);
  const key = base32Decode(secretText);
  const canonicalSecret = base32Encode(key, false);
  const digits = otpDigits(o.digits);
  const { compact: algorithm, webCrypto } = otpAlgorithm(o.algorithm);
  let period; let currentSeconds; let counter;
  if (kind === "totp") {
    period = requireInteger("OTP period", o.period ?? 30, 1, 86400);
    const timestamp = o.timestamp == null ? Date.now() / 1000 : o.timestamp;
    currentSeconds = Math.floor(requireFiniteNumber("Timestamp", timestamp, 0, 253402300799));
    counter = Math.floor(currentSeconds / period);
  } else {
    counter = requireInteger("HOTP counter", o.counter ?? 0, 0, Number.MAX_SAFE_INTEGER);
  }
  let n = BigInt(counter); const msg = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const mac = await hmacBytes(webCrypto, key, msg);
  const offset = mac[mac.length - 1] & 15;
  const binary = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  const code = String(binary % 10 ** digits).padStart(digits, "0");
  const { issuer, label } = otpLabel(o);
  const params = new URLSearchParams({ secret: canonicalSecret, algorithm, digits: String(digits) });
  if (issuer) params.set("issuer", issuer);
  if (kind === "totp") params.set("period", String(period)); else params.set("counter", String(counter));
  const uri = `otpauth://${kind}/${encodeURIComponent(label)}?${params}`;
  return {
    value: JSON.stringify({ code, secret: canonicalSecret, counter, remaining_seconds: kind === "totp" ? period - (currentSeconds % period) : undefined, otpauth_uri: uri }, null, 2),
    meta: { qr_text: uri, qr_label: `${kind.toUpperCase()} enrollment QR` },
  };
}

async function verifyOtp(o, kind) {
  if (!String(o.secret || "").trim()) throw new Error("OTP secret must not be empty");
  const code = String(o.code || ""); const digits = otpDigits(o.digits);
  if (!new RegExp(`^\\d{${digits}}$`).test(code)) throw new Error(`Code must contain exactly ${digits} digits`);
  otpAlgorithm(o.algorithm);
  const span = kind === "hotp" ? requireInteger("HOTP look-ahead", o.look_ahead ?? 0, 0, 100) : requireInteger("TOTP window", o.window ?? 1, 0, 10);
  const period = kind === "totp" ? requireInteger("OTP period", o.period ?? 30, 1, 86400) : undefined;
  const now = kind === "totp" ? Math.floor(requireFiniteNumber("Timestamp", o.timestamp == null ? Date.now() / 1000 : o.timestamp, 0, 253402300799)) : undefined;
  const initialCounter = kind === "hotp" ? requireInteger("HOTP counter", o.counter ?? 0, 0, Number.MAX_SAFE_INTEGER) : undefined;
  const offsets = kind === "hotp" ? Array.from({ length: Math.min(span, Number.MAX_SAFE_INTEGER - initialCounter) + 1 }, (_, i) => i) : Array.from({ length: span * 2 + 1 }, (_, i) => i - span);
  for (const offset of offsets) {
    const candidateTimestamp = kind === "totp" ? now + offset * period : undefined;
    if (kind === "totp" && candidateTimestamp < 0) continue;
    const candidate = await otpValue({ ...o, ...(kind === "hotp" ? { counter: initialCounter + offset } : { timestamp: candidateTimestamp }) }, kind);
    const generated = JSON.parse(candidate.value).code;
    if (bytesEqual(te.encode(generated), te.encode(code))) return JSON.stringify({ verified: true, offset, counter: JSON.parse(candidate.value).counter }, null, 2);
  }
  return JSON.stringify({ verified: false }, null, 2);
}

async function buildOtpAuth(o) {
  const kind = String(o.otp_type || "totp").toLowerCase();
  if (!["hotp", "totp"].includes(kind)) throw new Error("OTP type must be hotp or totp");
  if (!String(o.secret || "").trim()) throw new Error("OTP secret must not be empty");
  otpLabel(o);
  const result = await otpValue(o, kind); const parsed = JSON.parse(result.value);
  return { value: parsed.otpauth_uri, meta: result.meta };
}

function parseOtpAuth(o) {
  let uri; try { uri = new URL(String(o.uri || "")); } catch (_) { throw new Error("Enter a valid OTPAuth URI"); }
  if (uri.protocol !== "otpauth:" || !["hotp", "totp"].includes(uri.hostname)) throw new Error("OTPAuth URI must use otpauth://hotp or otpauth://totp");
  if (uri.hash) throw new Error("OTPAuth URI must not contain a fragment");
  let label; try { label = decodeURIComponent(uri.pathname.replace(/^\//, "")); } catch (_) { throw new Error("OTPAuth URI label is malformed"); }
  if (!label) throw new Error("OTPAuth URI label must not be empty");
  const colon = label.indexOf(":");
  if (colon === 0 || colon === label.length - 1 || (colon >= 0 && label.indexOf(":", colon + 1) >= 0)) {
    throw new Error("OTPAuth URI label has an ambiguous issuer/account colon");
  }
  const query = {};
  for (const [key, value] of uri.searchParams) {
    if (Object.prototype.hasOwnProperty.call(query, key)) throw new Error(`OTPAuth URI repeats the ${key} parameter`);
    query[key] = value;
  }
  if (!Object.prototype.hasOwnProperty.call(query, "secret")) throw new Error("OTPAuth URI is missing secret");
  const secretBytes = base32Decode(query.secret);
  const secretText = base32Encode(secretBytes, false);
  const { compact: algorithm } = otpAlgorithm(query.algorithm || "SHA1");
  const digits = otpDigits(query.digits);
  const labelIssuer = colon >= 0 ? label.slice(0, colon) : "";
  const account = colon >= 0 ? label.slice(colon + 1) : label;
  const queryIssuer = query.issuer || "";
  if (queryIssuer.includes(":")) throw new Error("OTPAuth issuer must not contain a colon");
  const warnings = [];
  if (queryIssuer && labelIssuer && queryIssuer !== labelIssuer) warnings.push("Issuer query parameter differs from label issuer");
  const result = { type: uri.hostname, label, issuer: queryIssuer || labelIssuer, account, secret: secretText, algorithm, digits, warnings };
  if (uri.hostname === "totp") result.period = requireInteger("OTP period", query.period ?? 30, 1, 86400);
  else {
    if (!Object.prototype.hasOwnProperty.call(query, "counter")) throw new Error("HOTP URI is missing counter");
    result.counter = requireInteger("HOTP counter", query.counter, 0, Number.MAX_SAFE_INTEGER);
  }
  const unknown = Object.keys(query).filter(key => !["secret", "issuer", "algorithm", "digits", "period", "counter"].includes(key)).sort();
  if (unknown.length) warnings.push(`Ignored unknown parameters: ${unknown.join(", ")}`);
  return { value: JSON.stringify(result, null, 2), meta: { qr_text: uri.toString(), qr_label: `${uri.hostname.toUpperCase()} enrollment QR` } };
}

function decodeDoubleQuotedEnv(value, line) {
  const escapes = { n: "\n", r: "\r", t: "\t", "\\": "\\", '"': '"' }; let output = "";
  for (let index = 0; index < value.length; index++) {
    if (value[index] !== "\\") { output += value[index]; continue; }
    if (index + 1 >= value.length) throw new Error(`line ${line}: trailing escape in double-quoted value`);
    const following = value[++index]; output += Object.prototype.hasOwnProperty.call(escapes, following) ? escapes[following] : `\\${following}`;
  }
  return output;
}

function parseEnvValue(raw, line) {
  let value = raw.trim();
  if (!value) return "";
  if (value[0] === '"' || value[0] === "'") {
    const quote = value[0]; let escaped = false; let closing = -1;
    for (let index = 1; index < value.length; index++) {
      if (quote === '"' && value[index] === "\\" && !escaped) { escaped = true; continue; }
      if (value[index] === quote && !escaped) { closing = index; break; }
      escaped = false;
    }
    if (closing < 0) throw new Error(`line ${line}: unterminated quoted value`);
    const tail = value.slice(closing + 1).trim();
    if (tail && !tail.startsWith("#")) throw new Error(`line ${line}: unexpected text after quoted value`);
    const content = value.slice(1, closing);
    return quote === '"' ? decodeDoubleQuotedEnv(content, line) : content;
  }
  const marker = value.search(/\s+#/);
  if (marker >= 0) value = value.slice(0, marker).trimEnd();
  return value;
}

function parseEnv(text) {
  const entries = []; const errors = []; const warnings = []; const seen = new Map();
  String(text || "").split(/\r?\n/).forEach((raw, index) => {
    const lineNumber = index + 1; const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    let line = trimmed; let exported = false;
    if (line.startsWith("export") && (line.length === 6 || /\s/.test(line[6]))) { line = line.slice(6).trimStart(); exported = true; }
    const separator = line.indexOf("=");
    if (separator < 0) { errors.push({ line: lineNumber, error: "assignment is missing =" }); return; }
    const key = line.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) { errors.push({ line: lineNumber, error: "invalid variable name", key }); return; }
    let value;
    try { value = parseEnvValue(line.slice(separator + 1), lineNumber); }
    catch (error) { errors.push({ line: lineNumber, error: error.message.replace(/^line \d+: /, ""), key }); return; }
    if (seen.has(key)) errors.push({ line: lineNumber, error: `duplicate key (first seen on line ${seen.get(key)})`, key });
    else seen.set(key, lineNumber);
    if (/\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)/.test(value)) warnings.push({ line: lineNumber, key, warning: "interpolation-like text is kept literal" });
    entries.push({ key, value, line: lineNumber, exported });
  });
  return { valid: errors.length === 0, entries, errors, warnings, keys: [...new Set(entries.map(item => item.key))] };
}

function quoteEnv(value) {
  if (value && !/[\s#'"\\]/.test(value)) return value;
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r");
  return `"${escaped}"`;
}

function envValue(o) {
  const a = parseEnv(o.text); const mode = o.mode || "inspect";
  if (!["inspect", "compare", "sort", "redact", "example"].includes(mode)) throw new Error("Unknown .env action");
  if (mode === "compare") {
    const b = parseEnv(o.compare); const ak = new Set(a.keys), bk = new Set(b.keys);
    return JSON.stringify({ valid: a.valid && b.valid, only_in_first: a.keys.filter(k => !bk.has(k)), only_in_second: b.keys.filter(k => !ak.has(k)), shared: a.keys.filter(k => bk.has(k)), first_errors: a.errors, second_errors: b.errors }, null, 2);
  }
  if (mode === "inspect") return JSON.stringify({ valid: a.valid, keys: a.keys, count: a.keys.length, errors: a.errors, warnings: a.warnings }, null, 2);
  if (!a.valid) { const first = a.errors[0]; throw new Error(`Invalid .env input on line ${first.line}: ${first.error}`); }
  const entries = mode === "sort" ? [...a.entries].sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0) : a.entries;
  let rendered;
  if (mode === "sort") rendered = entries.map(item => `${item.key}=${quoteEnv(item.value)}`);
  else if (mode === "example") rendered = entries.map(item => `${item.key}=`);
  else {
    const mask = String(o.mask ?? "***");
    if (!mask || /[\r\n]/.test(mask)) throw new Error("Redaction mask must be a non-empty single-line string");
    rendered = entries.map(item => `${item.key}=${item.value ? quoteEnv(mask) : ""}`);
  }
  return rendered.length ? `${rendered.join("\n")}\n` : "";
}

function timestampValue(o) {
  const raw = String(o.value || "").trim(); let date;
  if (!raw || raw.toLowerCase() === "now") date = new Date();
  else if (/^-?\d+(\.\d+)?$/.test(raw)) { const n = Number(raw); date = new Date(Math.abs(n) < 1e11 ? n * 1000 : n); }
  else date = new Date(raw);
  if (!Number.isFinite(date.getTime())) throw new Error("Enter a valid epoch or ISO-8601 timestamp");
  const zone = String(o.timezone || "UTC"); let inZone;
  try { inZone = new Intl.DateTimeFormat(undefined, { timeZone: zone, dateStyle: "full", timeStyle: "long" }).format(date); }
  catch (_) { throw new Error(`Unknown IANA time zone: ${zone}`); }
  return JSON.stringify({ iso_utc: date.toISOString(), epoch_seconds: Math.floor(date.getTime() / 1000), epoch_milliseconds: date.getTime(), local: date.toString(), [zone]: inZone }, null, 2);
}

async function runJsonPathWorker(o) {
  const payload = { text: o.text ?? "", path: o.path ?? "$", maxResults: 500 };
  if (typeof Worker === "undefined") {
    const { runJsonPath } = await import("./jsonpath-engine.js");
    const result = runJsonPath(payload.text, payload.path, payload.maxResults);
    return {
      value: result.result,
      warnings: result.truncated ? ["Only the first 500 JSONPath matches are shown."] : [],
      meta: { match_count: result.count, truncated: result.truncated },
    };
  }
  return new Promise((resolve, reject) => {
    const worker = new Worker("/static/jsonpath-worker.js", { type: "module" });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error("JSONPath exceeded the 1 second execution budget"));
    }, 1000);
    const finish = callback => value => { clearTimeout(timer); worker.terminate(); callback(value); };
    worker.onmessage = finish(event => event.data.ok
      ? resolve({
        value: event.data.result,
        warnings: event.data.truncated ? ["Only the first 500 JSONPath matches are shown."] : [],
        meta: { match_count: event.data.count, truncated: event.data.truncated },
      })
      : reject(new Error(event.data.error)));
    worker.onerror = finish(() => reject(new Error("JSONPath worker failed")));
    worker.postMessage(payload);
  });
}

function runRegexWorker(o) {
  return new Promise((resolve, reject) => {
    if (String(o.pattern || "").length > 2000 || String(o.text || "").length > 20000) { reject(new Error("Regex patterns are limited to 2,000 chars and input to 20,000 chars")); return; }
    const worker = new Worker("/static/regex-worker.js");
    const timer = setTimeout(() => { worker.terminate(); reject(new Error("Regex exceeded the 250 ms execution budget")); }, 250);
    worker.onmessage = event => { clearTimeout(timer); worker.terminate(); event.data.ok ? resolve(JSON.stringify(event.data.result, null, 2)) : reject(new Error(event.data.error)); };
    worker.onerror = () => { clearTimeout(timer); worker.terminate(); reject(new Error("Regex worker failed")); };
    worker.postMessage({ pattern: o.pattern || "", text: o.text || "", flags: o.flags || "", replacement: o.replacement || "" });
  });
}

function idInspectValue(o) {
  const value = String(o.value || "").trim();
  const compact = value.replace(/-/g, "");
  if (/^[0-9a-fA-F]{32}$/.test(compact)) {
    const version = Number.parseInt(compact[12], 16); const result = { type: "UUID", version, variant: ["8", "9", "a", "b"].includes(compact[16].toLowerCase()) ? "RFC" : "non-RFC", canonical: `${compact.slice(0, 8)}-${compact.slice(8, 12)}-${compact.slice(12, 16)}-${compact.slice(16, 20)}-${compact.slice(20)}`.toLowerCase() };
    if (version === 7) result.timestamp = new Date(Number.parseInt(compact.slice(0, 12), 16)).toISOString();
    return JSON.stringify(result, null, 2);
  }
  if (/^[0-9A-HJKMNP-TV-Z]{26}$/i.test(value)) {
    let ms = 0n; for (const char of value.slice(0, 10).toUpperCase()) ms = (ms << 5n) | BigInt(CROCKFORD.indexOf(char));
    return JSON.stringify({ type: "ULID", timestamp: new Date(Number(ms)).toISOString(), canonical: value.toUpperCase() }, null, 2);
  }
  if (/^[0-9a-fA-F]{24}$/.test(value)) return JSON.stringify({ type: "Mongo ObjectId", timestamp: new Date(Number.parseInt(value.slice(0, 8), 16) * 1000).toISOString(), canonical: value.toLowerCase() }, null, 2);
  throw new Error("Not a recognized UUID, ULID, or Mongo ObjectId");
}

const UA_CRAWLERS = [
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
];
function userAgentValue(o) {
  if (o.agent_type === "crawler") return choice(UA_CRAWLERS);
  if (o.agent_type === "client") return choice([`curl/8.${randomInt(10)}.${randomInt(10)}`, `python-requests/2.${26 + randomInt(15)}.0`, "Go-http-client/1.1"]);
  const browser = o.browser && o.browser !== "weighted" ? o.browser : choice(["chrome", "chrome", "chrome", "safari", "edge", "firefox"]);
  const platform = o.platform && o.platform !== "weighted" ? o.platform : choice(["desktop", "desktop", "mobile"]);
  const major = 139 + randomInt(8);
  if (browser === "safari") return platform === "desktop" ? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15" : "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1";
  if (browser === "firefox") return `Mozilla/5.0 (${platform === "desktop" ? "X11; Linux x86_64" : "Android 16; Mobile"}; rv:${major}.0) Gecko/20100101 Firefox/${major}.0`;
  const system = platform === "desktop" ? "Windows NT 10.0; Win64; x64" : "Linux; Android 10; K";
  const mobile = platform === "desktop" ? "" : " Mobile";
  const base = `Mozilla/5.0 (${system}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0${mobile} Safari/537.36`;
  if (browser === "edge") return `${base} Edg/${major}.0.0.0`;
  if (browser === "opera") return `${base} OPR/${121 + randomInt(6)}.0.0.0`;
  if (browser === "samsung") return `${base} SamsungBrowser/${25 + randomInt(5)}.0`;
  return base;
}
function uaBundleValue(o) {
  const ua = userAgentValue({ ...o, agent_type: "browser" }); const mobile = o.platform !== "desktop";
  const chrome = ua.match(/Chrome\/(\d+)/); const edge = ua.match(/Edg\/(\d+)/);
  const brand = edge ? `\"Microsoft Edge\";v=\"${edge[1]}\", \"Chromium\";v=\"${chrome ? chrome[1] : edge[1]}\"` : chrome ? `\"Chromium\";v=\"${chrome[1]}\", \"Google Chrome\";v=\"${chrome[1]}\"` : "";
  return JSON.stringify({ "User-Agent": ua, ...(brand ? { "Sec-CH-UA": brand, "Sec-CH-UA-Mobile": mobile ? "?1" : "?0", "Sec-CH-UA-Platform": `\"${mobile ? "Android" : "Windows"}\"` } : {}) }, null, 2);
}

function userAgentHintsValue(o) {
  const ua = String(o.user_agent || ""); if (!ua) throw new Error("Enter a User-Agent");
  if (/[\u0000-\u001f\u007f-\u009f]/.test(ua)) throw new Error("User-Agent must not contain control characters or header line breaks");
  const chrome = ua.match(/(?:Chrome|Chromium)\/(\d+)/); const edge = ua.match(/Edg\/(\d+)/);
  if (!chrome && !edge) return JSON.stringify({ "User-Agent": ua, client_hints_supported: false, reason: "Client Hints are emitted only for Chromium-family User-Agents" }, null, 2);
  const major = edge ? edge[1] : chrome[1]; const brand = edge ? `\"Microsoft Edge\";v=\"${edge[1]}\", \"Chromium\";v=\"${chrome ? chrome[1] : edge[1]}\"` : `\"Chromium\";v=\"${major}\", \"Google Chrome\";v=\"${major}\"`;
  const mobile = /Mobile|Android/.test(ua); const platform = /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : /Macintosh/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "Unknown";
  return JSON.stringify({ "User-Agent": ua, "Sec-CH-UA": brand, "Sec-CH-UA-Mobile": mobile ? "?1" : "?0", "Sec-CH-UA-Platform": `\"${platform}\"` }, null, 2);
}

function ipv4Value(o) {
  const byte = (lo = 0, hi = 255) => lo + randomInt(hi - lo + 1);
  if (o.kind === "documentation" || o.kind === "public") { const p = choice([[192, 0, 2], [198, 51, 100], [203, 0, 113]]); return `${p.join(".")}.${byte(1, 254)}`; }
  if (o.kind === "loopback") return `127.${byte()}.${byte()}.${byte(1, 254)}`;
  const kind = randomInt(3);
  return kind === 0 ? `10.${byte()}.${byte()}.${byte(1, 254)}` : kind === 1 ? `172.${byte(16, 31)}.${byte()}.${byte(1, 254)}` : `192.168.${byte()}.${byte(1, 254)}`;
}
function ipv6Value(o) {
  if (o.kind === "loopback") return "::1";
  const ula = o.kind === "ula";
  const parts = Array.from({ length: ula ? 7 : 6 }, () => randomInt(65536).toString(16));
  return `${ula ? `fd${randomInt(256).toString(16).padStart(2, "0")}` : "2001:db8"}:${parts.join(":")}`;
}
function emailValue(o) {
  const domain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(o.domain || "")) ? String(o.domain).toLowerCase().replace(/^@/, "") : "example.com";
  const local = `${choice(WORDS)}.${choice(WORDS)}${10 + randomInt(9990)}` + (o.plus_tag ? `+${choice(["dev", "test", "qa", "local"])}` : "");
  return `${local}@${domain}`;
}
const LOREM = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit voluptate velit esse cillum fugiat nulla pariatur".split(" ");
function loremValue(o) {
  return Array.from({ length: clamp(o.paragraphs ?? 1, 1, 8) }, () => Array.from({ length: clamp(o.sentences ?? 3, 1, 12) }, () => {
    const text = Array.from({ length: clamp(o.words_per_sentence ?? 12, 4, 30) }, () => choice(LOREM)).join(" ");
    return text[0].toUpperCase() + text.slice(1) + ".";
  }).join(" ")).join("\n\n");
}
function textCaseValue(o) {
  const text = String(o.text || ""); const words = text.match(/[A-Za-z0-9]+/g) || []; const lower = words.map(w => w.toLowerCase());
  if (o.case === "upper") return text.toUpperCase(); if (o.case === "lower") return text.toLowerCase();
  if (o.case === "camel") return (lower[0] || "") + lower.slice(1).map(w => w[0].toUpperCase() + w.slice(1)).join("");
  if (o.case === "pascal") return lower.map(w => w[0].toUpperCase() + w.slice(1)).join("");
  if (["kebab", "slug"].includes(o.case)) return lower.join("-");
  if (o.case === "constant") return lower.join("_").toUpperCase();
  if (o.case === "title") return lower.map(w => w[0].toUpperCase() + w.slice(1)).join(" ");
  return lower.join("_");
}
function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(key => [key, sortJson(value[key])]));
  return value;
}
function jsonValue(o) {
  let value; try { value = JSON.parse(o.text); } catch (err) { throw new Error(`Invalid JSON: ${err.message}`); }
  if (o.mode === "validate") return JSON.stringify({ valid: true, type: Array.isArray(value) ? "array" : value === null ? "null" : typeof value, size: value && typeof value === "object" ? Object.keys(value).length : undefined }, null, 2);
  if (o.sort_keys) value = sortJson(value);
  return o.mode === "minify" ? JSON.stringify(value) : JSON.stringify(value, null, clamp(o.indent ?? 2, 1, 8));
}

// Small, local MD5 implementation retained only for compatibility fixtures.
function md5(text) {
  const bytes = [...te.encode(String(text))]; const bitLength = bytes.length * 8;
  bytes.push(0x80); while (bytes.length % 64 !== 56) bytes.push(0);
  for (let i = 0; i < 8; i++) bytes.push(Math.floor(bitLength / 2 ** (8 * i)) & 255);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const shifts = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const constants = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
  const rot = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  for (let offset = 0; offset < bytes.length; offset += 64) {
    const m = Array.from({ length: 16 }, (_, i) => (bytes[offset + i * 4] | bytes[offset + i * 4 + 1] << 8 | bytes[offset + i * 4 + 2] << 16 | bytes[offset + i * 4 + 3] << 24) >>> 0);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const next = d; d = c; c = b; b = (b + rot((a + f + constants[i] + m[g]) >>> 0, shifts[i])) >>> 0; a = next;
    }
    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }
  return [a0, b0, c0, d0].map(n => [n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255].map(b => b.toString(16).padStart(2, "0")).join("")).join("");
}

const handlers = {
  uuid: uuidValue,
  ulid: ulidValue,
  nanoid: o => randomString(clamp(o.size ?? 21, 2, 256), o.alphabet || NANOID),
  objectid: objectIdValue,
  id_inspect: idInspectValue,
  hex: o => { const value = hex(randomBytes(clamp(o.nbytes ?? 32, 1, 512))); return o.uppercase ? value.toUpperCase() : value; },
  urlsafe: o => bytesToBase64(randomBytes(clamp(o.nbytes ?? 32, 1, 512)), true, false),
  base64: o => bytesToBase64(randomBytes(clamp(o.nbytes ?? 32, 1, 512)), !!o.urlsafe, true),
  apikey: o => { const body = o.encoding === "hex" ? hex(randomBytes(clamp(o.nbytes ?? 24, 8, 256))) : bytesToBase64(randomBytes(clamp(o.nbytes ?? 24, 8, 256)), true, false); return o.prefix ? `${o.prefix}${o.separator ?? "_"}${body}` : body; },
  password: passwordValue,
  password_policy: passwordValue,
  string: o => randomString(clamp(o.length ?? 32, 1, 1024), o.charset === "custom" ? o.custom_charset : CHARSETS[o.charset] || CHARSETS.alphanumeric),
  pin: o => randomString(clamp(o.length ?? 6, 3, 12), DIGITS),
  passphrase: passphraseValue,
  pkce: async o => {
    if (o.kind !== "pkce") return o.kind === "csp" ? bytesToBase64(randomBytes(24), false, false) : bytesToBase64(randomBytes(32), true, false);
    const verifier = randomString(clamp(o.length ?? 64, 43, 128), URLSAFE);
    return JSON.stringify({ code_verifier: verifier, code_challenge: b64url(await digestBytes("sha256", verifier)), code_challenge_method: "S256" }, null, 2);
  },
  jwt: async o => {
    const now = Math.floor(Date.now() / 1000); const alg = String(o.algorithm || "HS256");
    const payload = { sub: o.subject || "user_123", iss: o.issuer || "", aud: o.audience || "", iat: now, nbf: now, exp: now + clamp(o.ttl_seconds ?? 3600, 1, 31536000) };
    if (o.include_jti !== false) payload.jti = uuidValue({ version: 4, hyphens: true });
    if (alg.toLowerCase() === "none") return { value: `${b64urlJson({ typ: "JWT", alg: "none" })}.${b64urlJson(payload)}.`, warnings: ["Unsigned JWT: decode-only, never verified."] };
    return jwtSign({ typ: "JWT", alg }, payload, o.secret, alg);
  },
  jwt_decode: o => jwtDebugger({ ...o, mode: "decode" }),
  jwt_debugger: jwtDebugger,
  basic_auth: o => `${o.include_scheme === false ? "" : "Basic "}${bytesToBase64(te.encode(`${o.username || ""}:${o.password || ""}`))}`,
  webhook_hmac: async o => {
    if (!String(o.key || "")) throw new Error("Webhook signing secret must not be empty");
    const signature = hex(await hmacBytes(o.algorithm || "sha256", o.key || "", o.text || ""));
    if (o.mode === "verify") { const expected = String(o.signature || "").replace(/^sha\d+=/i, "").toLowerCase(); return JSON.stringify({ verified: bytesEqual(te.encode(signature), te.encode(expected)), computed_signature: signature }, null, 2); }
    return signature;
  },
  user_agent: userAgentValue,
  user_agent_bundle: uaBundleValue,
  base64_text: o => o.mode === "decode" ? td.decode(base64ToBytes(o.text, !!o.urlsafe)) : bytesToBase64(te.encode(o.text || ""), !!o.urlsafe, o.padding !== false),
  base32: o => o.mode === "decode" ? td.decode(base32Decode(o.text)) : base32Encode(te.encode(o.text || ""), o.padding !== false),
  base32_encode: o => base32Encode(te.encode(o.text || ""), o.padding !== false),
  base32_decode: o => td.decode(base32Decode(o.value)),
  base32_secret: o => base32Encode(randomBytes(clamp(o.nbytes ?? 20, 10, 4096)), o.padding !== false),
  url_codec: o => {
    const text = String(o.text || "");
    if (o.mode === "decode") return o.plus_spaces ? decodeURIComponent(text.replace(/\+/g, " ")) : decodeURIComponent(text);
    let value = encodeURIComponent(text); if (!o.component) value = value.replace(/%2F/gi, "/").replace(/%3A/gi, ":").replace(/%3F/gi, "?").replace(/%26/gi, "&").replace(/%3D/gi, "=").replace(/%23/gi, "#");
    return o.plus_spaces ? value.replace(/%20/g, "+") : value;
  },
  hotp: o => otpValue(o, "hotp"),
  totp: o => otpValue(o, "totp"),
  hotp_verify: o => verifyOtp(o, "hotp"),
  totp_verify: o => verifyOtp(o, "totp"),
  otpauth_build: buildOtpAuth,
  otpauth_parse: parseOtpAuth,
  jwt_encode: async o => {
    const claims = parseJsonObject(o.claims, "Claims"); const header = parseJsonObject(o.header, "Header");
    return jwtSign({ typ: "JWT", ...header }, claims, o.secret || "", o.algorithm || "HS256");
  },
  jwt_verify: o => jwtDebugger({ mode: "verify", token: o.token, secret: o.secret, expected_issuer: o.issuer, expected_audience: o.audience, allowed_algorithms: o.allowed_algorithms, clock_skew: o.leeway ?? 0 }),
  pkce_generate: async o => {
    const verifier = randomString(clamp(o.length ?? 64, 43, 128), URLSAFE);
    return JSON.stringify({ code_verifier: verifier, code_challenge: b64url(await digestBytes("sha256", verifier)), code_challenge_method: "S256" }, null, 2);
  },
  pkce_challenge: async o => {
    const verifier = String(o.verifier || ""); if (verifier.length < 43 || verifier.length > 128 || !/^[A-Za-z0-9._~-]+$/.test(verifier)) throw new Error("Verifier must be 43–128 RFC 7636 unreserved characters");
    return b64url(await digestBytes("sha256", verifier));
  },
  oauth_state: o => bytesToBase64(randomBytes(requireInteger("Nonce bytes", o.nbytes ?? 32, 16, 256)), true, false),
  oidc_nonce: o => bytesToBase64(randomBytes(requireInteger("Nonce bytes", o.nbytes ?? 32, 16, 256)), true, false),
  csp_nonce: o => bytesToBase64(randomBytes(requireInteger("Nonce bytes", o.nbytes ?? 24, 16, 256)), false, false),
  webhook_sign: async o => {
    if (!String(o.secret || "")) throw new Error("Webhook signing secret must not be empty");
    const raw = await hmacBytes(o.algorithm || "sha256", o.secret || "", o.payload || "");
    const signature = o.encoding === "base64" ? bytesToBase64(raw) : o.encoding === "base64url" ? bytesToBase64(raw, true, false) : hex(raw);
    return o.prefix === false ? signature : `${o.algorithm || "sha256"}=${signature}`;
  },
  webhook_verify: async o => {
    if (!String(o.secret || "")) throw new Error("Webhook signing secret must not be empty");
    const raw = await hmacBytes(o.algorithm || "sha256", o.secret || "", o.payload || "");
    const computed = o.encoding === "base64" ? bytesToBase64(raw) : o.encoding === "base64url" ? bytesToBase64(raw, true, false) : hex(raw);
    const supplied = String(o.signature || "").replace(new RegExp(`^${o.algorithm || "sha256"}=` , "i"), "");
    return JSON.stringify({ verified: bytesEqual(te.encode(computed), te.encode(supplied)), computed_signature: computed }, null, 2);
  },
  env: envValue,
  dotenv: o => envValue({ text: o.text, compare: o.other, mode: o.action === "validate" ? "inspect" : o.action, mask: o.mask }),
  timestamp: timestampValue,
  regex: runRegexWorker,
  jsonpath: runJsonPathWorker,
  json: jsonValue,
  text_case: textCaseValue,
  hash: async o => {
    const algorithm = String(o.algorithm || "sha256").toLowerCase(); let value = algorithm === "md5" ? md5(o.text || "") : hex(await digestBytes(algorithm, o.text || ""));
    if (o.uppercase) value = value.toUpperCase();
    return algorithm === "md5" || algorithm === "sha1" ? { value, warnings: [`${algorithm.toUpperCase()} is retained only for compatibility, not security.`] } : value;
  },
  hmac: async o => { let value = hex(await hmacBytes(o.algorithm || "sha256", o.key || "", o.text || "")); return o.uppercase ? value.toUpperCase() : value; },
  checksum: async o => {
    if (!(o.file instanceof File)) throw new Error("Choose a file first");
    if (o.file.size > 268435456) throw new Error("Files are limited to 256 MiB in this browser tool");
    return JSON.stringify({ name: o.file.name, bytes: o.file.size, algorithm: o.algorithm || "sha256", digest: hex(await digestBytes(o.algorithm || "sha256", await o.file.arrayBuffer())) }, null, 2);
  },
  user_agent_hints: userAgentHintsValue,
  email: emailValue,
  ipv4: ipv4Value,
  ipv6: ipv6Value,
  mac: o => { const bytes = randomBytes(6); if (o.locally_administered !== false) bytes[0] = (bytes[0] | 2) & 254; let value = [...bytes].map(v => v.toString(16).padStart(2, "0")).join([":", "-", ""].includes(o.separator) ? o.separator : ":"); return o.uppercase ? value.toUpperCase() : value; },
  semver: o => `${randomInt(5)}.${randomInt(21)}.${randomInt(51)}${o.include_prerelease ? `-${choice(["alpha", "beta", "rc"])}.${1 + randomInt(9)}` : ""}${o.include_build ? `+${hex(randomBytes(3))}` : ""}`,
  lorem: loremValue,
};

export async function runLocal(id, options = {}, count = 1) {
  const handler = handlers[id];
  if (!handler) throw new Error(`No browser-local implementation for ${id}`);
  const spec = LOCAL_BY_ID[id]; const limit = spec ? spec.max_count || (spec.random ? 1000 : 1) : 1;
  const n = spec && spec.random ? clamp(count, 1, limit) : 1;
  const normalized = spec ? { ...Object.fromEntries([...(spec.inputs || []), ...(spec.options || [])].map(field => [field.key, field.default])), ...options } : options;
  const values = []; const warnings = []; const meta = {};
  for (let i = 0; i < n; i++) {
    const result = await handler(normalized);
    if (result && typeof result === "object" && Object.prototype.hasOwnProperty.call(result, "value")) {
      values.push(String(result.value)); if (result.warnings) warnings.push(...result.warnings); if (result.meta) Object.assign(meta, result.meta);
    } else values.push(typeof result === "string" ? result : JSON.stringify(result, null, 2));
  }
  if (["uuid"].includes(id) && [1, 6].includes(Number(normalized.version))) warnings.push("UUID v1/v6 reveal their creation time; this local implementation uses a random node value.");
  return { values, warnings: [...new Set(warnings)], meta };
}

export function entropyBitsFor(id, o) {
  if (id === "password" || id === "password_policy") {
    const excluded = new Set(String(o.excluded_chars || "")); if (o.exclude_ambiguous) for (const c of AMBIGUOUS) excluded.add(c);
    let pool = ""; if (o.lowercase !== false) pool += LOWER; if (o.uppercase !== false) pool += UPPER; if (o.digits !== false) pool += DIGITS; if (o.symbols !== false) pool += String(o.custom_symbols ?? SYMBOLS);
    const size = new Set([...pool].filter(c => !excluded.has(c))).size;
    return size > 1 ? clamp(o.length ?? 20, 4, 256) * Math.log2(size) : 0;
  }
  if (id === "passphrase") return clamp(o.words ?? 4, 2, 16) * Math.log2(WORDS.length) + (o.add_number ? Math.log2(10) : 0);
  if (id === "pin") return clamp(o.length ?? 6, 3, 12) * Math.log2(10);
  if (id === "string") { const pool = o.charset === "custom" ? o.custom_charset : CHARSETS[o.charset] || CHARSETS.alphanumeric; const size = new Set([...String(pool || "")]).size; return size > 1 ? clamp(o.length ?? 32, 1, 1024) * Math.log2(size) : 0; }
  if (["hex", "urlsafe", "base64", "apikey"].includes(id)) return clamp(o.nbytes ?? 32, 1, 512) * 8;
  if (id === "nanoid") return clamp(o.size ?? 21, 2, 256) * Math.log2(new Set([...(o.alphabet || NANOID)]).size);
  if (id === "ulid") return 80;
  if (id === "pkce") return o.kind === "pkce" ? clamp(o.length ?? 64, 43, 128) * Math.log2(URLSAFE.length) : 256;
  return null;
}

export function detectInput(text) {
  const value = String(text || "").trim(); if (!value) return [];
  const found = [];
  if (value.split(".").length === 3 && value.startsWith("eyJ")) found.push({ id: "jwt_debugger", label: "Inspect as JWT" });
  if (/^[0-9a-fA-F-]{24,36}$/.test(value) || /^[0-9A-HJKMNP-TV-Z]{26}$/i.test(value)) found.push({ id: "id_inspect", label: "Inspect identifier" });
  if (/^-?\d{10,13}$/.test(value) || /^\d{4}-\d{2}-\d{2}T/.test(value)) found.push({ id: "timestamp", label: "Convert timestamp" });
  if (/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=/m.test(value)) found.push({ id: "env", label: "Inspect as .env" });
  try { JSON.parse(value); found.push({ id: "json", label: "Format as JSON" }); } catch (_) { /* not JSON */ }
  if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) && value.length >= 8) found.push({ id: "base64_text", label: "Decode Base64" });
  return found.slice(0, 3);
}
