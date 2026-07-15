# fast-secrets

fast-secrets is a privacy-first secrets and API workbench. The installable web app
runs its 60 tools locally with native JavaScript and Web Crypto; a separate, explicit
FastAPI v2 surface exposes 55 typed tool operations for curl, CI, and automation.

It is deliberately a focused toolbox, not a secret vault: there are no accounts,
server-side storage, recovery, rotation, or audit-history features.

## Trust model

- The browser fetches static assets and non-sensitive tool metadata. Tool inputs,
  generated secrets, files, JWTs, signing keys, `.env` content, and diff text stay in
  page memory and are never POSTed by the UI.
- Sensitive/free-form fields are excluded from local storage, URLs, favorites, and
  presets. Copying or downloading an output is always an explicit user action.
- Calling `POST /api/tools/{id}/run` or `POST /api/batch` intentionally sends the JSON
  body to that server. Execution responses use `Cache-Control: no-store`.
- The application is stateless and does not intentionally log request/response bodies.
  Public operators still need HTTPS, safe edge logs, resource limits, and rate limiting.

See [the full privacy boundary](docs/privacy.md) and [security policy](SECURITY.md).

## Workbench features

| Area | Tools |
|---|---|
| Secrets and passwords | policy-based passwords, random strings, PINs, passphrases, hex/Base64/URL-safe tokens, API keys |
| IDs and fixtures | UUID v1/v4/v6/v7, ULID, Nano ID, ObjectId, ID inspector, email, IP/MAC, SemVer, lorem ipsum |
| API and auth | JWT build/decode/HS256/384/512 verification, PKCE, OAuth state, OIDC/CSP nonces, Basic Auth, webhook HMAC |
| OTP | RFC 4226 HOTP, RFC 6238 TOTP, Base32 secrets, otpauth enrollment URIs, offline QR rendering |
| Encoders and config | Base32/Base64, URL codec, JSON formatting, text cases, `.env` inspect/compare/sort/redact/example |
| Debugging | bounded regex worker, RFC 9535 JSONPath, text diff, timestamp/IANA time-zone conversion, hashes/HMAC, local file checksums |
| HTTP fixtures | modern User-Agent generation and matching Client Hints request bundles |

The UI also includes smart input detection, favorites, non-sensitive preferences,
password-rule presets, strength estimates, keyboard navigation, dark/light themes,
copy/export controls, and an offline PWA shell. QR rendering uses the vendored MIT
[Project Nayuki QR generator](https://www.nayuki.io/page/qr-code-generator-library),
and browser JSONPath uses the vendored Apache-2.0
[`jsonpath-rfc9535`](https://github.com/P0lip/jsonpath-rfc9535) engine. There
are no CDN runtime dependencies or frontend build step.

## Run locally

Python 3.11 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn --app-dir src/backend fast_secrets.main:app --reload
```

Open <http://127.0.0.1:8000/> for the workbench or
<http://127.0.0.1:8000/docs> for the CSP-compatible API reference.

## Local CLI

Installing the project adds a CLI that invokes the same registry without making a
network request:

```bash
pip install -e .
fast-secrets tools
fast-secrets run uuid --option version=7 --count 3
fast-secrets run password_policy --option length=24 --format json
fast-secrets batch requests.json
```

Use repeated `--input KEY=VALUE` and `--option KEY=VALUE` flags. JSON scalars,
objects, and arrays are accepted as values. `fast-secrets batch -` reads JSON from
standard input.

## HTTP API v2

Inputs and secret material belong in POST bodies, never query strings:

```bash
curl -sS http://127.0.0.1:8000/api/tools/uuid/run \
  -H 'Content-Type: application/json' \
  -d '{"inputs":{},"options":{"version":7},"count":3}'
```

Every successful JSON execution has one envelope:

```json
{
  "tool": "uuid",
  "kind": "list",
  "data": ["019…"],
  "warnings": [],
  "meta": {"count": 3}
}
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/tools` | Typed metadata for all registered tools |
| `POST` | `/api/tools/{id}/run` | Run one tool with `{inputs, options, count}` |
| `POST` | `/api/batch` | Run up to 25 explicit requests |
| `GET` | `/healthz` | Liveness check |

Compatible list results support `Accept: application/x-ndjson`; scalar text/list
results also support `Accept: text/plain`. Errors use
`application/problem+json` RFC 9457-style documents.

The application enforces 256 KiB request bodies, 25 batch items, 1,000 total values,
and 1 MiB responses. The sample Nginx edge adds 60 requests/minute per address with a
burst of 20 and returns 429 when limited. The v1 GET generation routes were removed;
see [the v2 migration guide](docs/api-v2-migration.md) and [request examples](test_main.http).

## Production container

```bash
docker build -t fast-secrets .
docker run --read-only --tmpfs /tmp -p 8000:8000 fast-secrets
```

The image runs as a non-root user with two workers and no Uvicorn access log. Put it
behind a trusted HTTPS edge; [deploy/nginx.conf](deploy/nginx.conf) demonstrates body
limits, safe URI-only logging, and anonymous rate limiting. Operational requirements
are documented in [deploy/README.md](deploy/README.md).

## Tests and packaging

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m pytest --cov --cov-report=term-missing
node --check src/frontend/app.js
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

The suite covers standards vectors, generator invariants, registry coercion, API
budgets/content negotiation/problem details/security headers, CLI behavior, local JS
cryptographic parity/privacy invariants, and a real Firefox WebDriver flow when Firefox
and geckodriver are available. CI runs on Python 3.11 and 3.13, makes a pinned
Playwright Firefox smoke mandatory, tests the installed wheel outside the checkout,
and builds the container.

## Layout

```text
src/
├── backend/
│   └── fast_secrets/   installable API/CLI package, registry, and tool engines
└── frontend/           no-build ES-module workbench, PWA, and local API docs
tests/                  pure, API, CLI, JS-contract, and browser tests
scripts/                packaging and installed-application checks
docs/                   privacy, research, and API migration documentation
deploy/                 public reverse-proxy guidance
```

New dual-surface tools should add a typed registry contract, a browser-local handler,
shared standards vectors/invariants, explicit sensitivity/persistence metadata, and
resource limits. See [CONTRIBUTING.md](CONTRIBUTING.md).
