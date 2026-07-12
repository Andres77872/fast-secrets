# 🔑 fast-secrets

A tiny **FastAPI** service for generating random secrets and developer fixtures fast —
for tests, local dev, API work and debugging. Inspired by the [IntelliJ Developer
Tools plugin][plugin], DevToys and CyberChef-style utility workflows, with a
curl-friendly API and a minimal, modern web UI (no build step) served at `/`.

Every value is produced with Python's cryptographically secure
[`secrets`](https://docs.python.org/3/library/secrets.html) module — never `random`.

## Generators

| Category | Generators |
|----------|------------|
| **IDs** | UUID (v1 / v4 / v6 / v7), ULID, Nano ID, Mongo ObjectId |
| **Tokens** | Hex token, URL-safe token, Base64 secret, API key (`sk_…`) |
| **Web/API** | JWT generator, JWT decode, real-sample User-Agent, Basic Auth |
| **Encoders** | Base64 text encode/decode, URL encode/decode |
| **Passwords** | Password, Random string, Numeric PIN, Passphrase (diceware) |
| **Fixture data** | Email, IPv4, IPv6, MAC address, SemVer, Lorem ipsum |
| **Formatters / Text** | JSON format/minify/validate, text case conversion |
| **Hashing** | MD5 / SHA-1 / SHA-256 / SHA-512, HMAC |

The full option set for each is self-documented at `GET /api/generators` (and in the
interactive Swagger docs at `/docs`).

Feature selection and User-Agent data-source notes live in [`docs/research.md`](docs/research.md).

## Run

```bash
python -m venv .venv && source .venv/bin/activate   # or use the existing .venv
pip install -r requirements.txt
uvicorn main:app --reload
```

Then open <http://127.0.0.1:8000/> for the UI, or <http://127.0.0.1:8000/docs> for the API.

## API — fast generation from the shell

```bash
# A UUID
curl -s localhost:8000/api/generate/uuid

# 5 time-sortable UUID v7s
curl -s 'localhost:8000/api/generate/uuid?version=7&count=5'

# 3 passwords, raw text — one per line (perfect for scripts / `export`)
curl -s 'localhost:8000/api/generate/password?length=24&count=3&format=text'

# A 32-byte hex token
curl -s 'localhost:8000/api/generate/hex?nbytes=32&format=text'

# A modern weighted User-Agent string from real samples or generated templates
curl -s 'localhost:8000/api/generate/user_agent?format=text'

# URL-safe Base64 encode text
curl -s 'localhost:8000/api/generate/base64_text?text=hello&urlsafe=true&format=text'

# Format JSON
curl -s 'localhost:8000/api/generate/json?text=%7B%22b%22%3A1%2C%22a%22%3A2%7D&format=text'

# One of every generator with defaults
curl -s localhost:8000/api/all
```

Any generator option can be passed as a query parameter. Add `format=text` to get
newline-separated raw values instead of JSON, and `count=N` for bulk output.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Web UI |
| `GET` | `/api/generators` | Metadata for every generator + options |
| `GET` | `/api/generate/{id}` | Generate via query params (`count`, `format=json\|text`) |
| `POST` | `/api/generate` | Generate via JSON body `{type, options, count}` |
| `POST` | `/api/generate/batch` | Generate several generators at once |
| `GET` | `/api/all` | One value of each generator (defaults) |
| `POST` | `/api/diff` | Compare two texts → aligned rows for inline + side-by-side |

```bash
# Compare two texts (word-level highlighting, summary stats)
curl -s -X POST localhost:8000/api/diff -H 'Content-Type: application/json' \
  -d '{"text1":"hello world","text2":"hello brave world"}'
```

Options: `ignore_whitespace`, `ignore_case`, `granularity` (`word` | `char`). The
response is one canonical list of aligned rows that the UI renders as either an inline
or a side-by-side diff, plus a ready-to-copy `unified` diff.

## Web UI

- **Single** mode — pick a generator from the sidebar, tweak its options, hit
  **Generate** (or toggle **Live** to regenerate as you type). A live **strength
  meter** shows estimated entropy for passwords, passphrases, PINs and tokens. Copy
  each value, regenerate a single value (`↻`), copy all, or download as `.txt` /
  `.json` / `.csv`.
- **Generate all** mode — a grid of every generator; check the ones you want and
  generate them in one click.
- **Developer utilities** — JSON formatting, Base64/URL transforms, JWT decode,
  Basic Auth, User-Agent strings, text case conversion, and common fixture data.
- **Text diff** mode — paste two texts and compare them **inline** or **side-by-side**
  (toggle without re-running), with word/char-level highlighting, a similarity summary,
  and "copy unified diff".
- **Keyboard shortcuts**: `Ctrl/Cmd + Enter` generates / compares, `/` focuses the
  filter, `Esc` clears it.
- Dark/light theme (follows your system preference until you choose), accessible focus
  states, and your last-used options are remembered (localStorage).

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

Covers generator correctness (formats, charset constraints, UUID versions, known hash
vectors, JWT decode, User-Agent variants, fixture ranges, utility round-trips,
uniqueness) and every API endpoint.

## Project layout

```
main.py          FastAPI app: routes, serves the UI
generators.py    pure, secure generator functions (the core)
registry.py      generator metadata + dispatch (single source of truth)
diffing.py       pure text-diff engine (stdlib difflib, no deps)
wordlist.py      embedded EFF short wordlist for passphrases
static/          index.html · style.css · app.js  (the UI, no build step)
tests/           pytest suite (generators + diff)
```

Adding a generator = add a function in `generators.py` and one entry in `registry.py`;
the API and UI pick it up automatically.

[plugin]: https://github.com/marcelkliemannel/intellij-developer-tools-plugin
