"""Mandatory-in-CI Firefox smoke using the project-pinned Playwright runtime."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest
from playwright.sync_api import Page, sync_playwright


REQUIRED = os.environ.get("FAST_SECRETS_REQUIRE_PLAYWRIGHT") == "1"
BROWSER_NAME = os.environ.get("FAST_SECRETS_PLAYWRIGHT_BROWSER", "firefox")
ROOT = Path(__file__).parents[1]


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait(url: str, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for {url}")


def _wait_output(page: Page, predicate: Callable[[str], bool], timeout: float = 5) -> str:
    """Poll output without injecting eval-like code that the app CSP forbids."""
    deadline = time.monotonic() + timeout
    output = ""
    while time.monotonic() < deadline:
        output = page.locator(".out-row code").text_content() or ""
        if predicate(output):
            return output
        time.sleep(0.025)
    raise AssertionError(f"Timed out waiting for browser output; last value: {output!r}")


@pytest.mark.browser
@pytest.mark.skipif(
    not REQUIRED,
    reason="set FAST_SECRETS_REQUIRE_PLAYWRIGHT=1 after installing Playwright Firefox",
)
def test_playwright_firefox_runs_local_tools_and_nested_jsonpath_modules():
    port = _port()
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "--app-dir",
            str(ROOT / "src" / "backend"),
            "fast_secrets.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-access-log",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        base_url = f"http://127.0.0.1:{port}"
        _wait(f"{base_url}/healthz")
        with sync_playwright() as playwright:
            if BROWSER_NAME not in {"chromium", "firefox", "webkit"}:
                raise ValueError(f"Unsupported Playwright browser: {BROWSER_NAME}")
            browser = getattr(playwright, BROWSER_NAME).launch(headless=True)
            page = browser.new_page()
            requests: list[tuple[str, str]] = []
            page.on("request", lambda request: requests.append((request.method, request.url)))
            page.goto(base_url, wait_until="networkidle")
            assert page.locator(".gen-item").count() >= 60

            sentinel = "playwright-secret-must-stay-local"
            page.locator('.gen-item[data-id="hmac"]').click()
            page.locator('[data-key="text"]').fill("payload")
            page.locator('[data-key="key"]').fill(sentinel)
            page.locator("#generate").click()
            assert len(_wait_output(page, lambda output: len(output) == 64)) == 64

            page.locator('.gen-item[data-id="jsonpath"]').click()
            page.locator('[data-key="text"]').fill(
                json.dumps(
                    {
                        "items": [
                            {"name": "budget", "price": 8},
                            {"name": "premium", "price": 20},
                        ]
                    }
                )
            )
            page.locator('[data-key="path"]').fill("$.items[?@.price < 10].name")
            page.locator("#generate").click()
            output = _wait_output(page, lambda value: "budget" in value)
            assert json.loads(output) == ["budget"]

            persisted = page.evaluate("JSON.stringify(Object.entries(localStorage))")
            assert sentinel not in persisted
            assert all(method == "GET" for method, _url in requests)
            assert any(
                "/static/vendor/jsonpath-rfc9535/core/functions/utils/construct-regex.js"
                in url
                for _method, url in requests
            )
            browser.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
