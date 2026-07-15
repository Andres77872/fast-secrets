# Contributing

## Development

Use Python 3.11 or newer and install `requirements-dev.txt`. The browser application is
plain HTML, CSS, and native JavaScript modules; it intentionally has no build step.

Run the complete suite before submitting a change:

```bash
python -m pytest
```

New random generators must use `secrets` on Python and Web Crypto in the browser.
Sensitive inputs must be marked non-persistent, excluded from exports and logs, and
covered by browser privacy tests. New dual-surface tools need deterministic shared
vectors or invariant tests proving that browser and API behavior agree.

Keep third-party browser code vendored, pinned, attributed, and covered by the Content
Security Policy; do not add runtime CDN dependencies.
