"""Real-browser smoke test using the standard WebDriver protocol.

The test runs when Firefox and geckodriver are available. CI still exercises the
same ES modules with Node on hosts without a browser runtime.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).parents[1]
FIREFOX = shutil.which("firefox") or shutil.which("firefox-esr")
GECKODRIVER = shutil.which("geckodriver")


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request(url: str, method: str = "GET", payload: Any = None) -> Any:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def _wait(url: str, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _request(url)
            return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for {url}")


@pytest.mark.browser
@pytest.mark.skipif(not FIREFOX or not GECKODRIVER, reason="Firefox WebDriver is unavailable")
def test_local_workbench_executes_without_api_post_or_secret_storage():
    app_port, driver_port = _port(), _port()
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
            str(app_port),
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    driver = subprocess.Popen(
        [GECKODRIVER, "--port", str(driver_port), "--log", "fatal"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    session_id: str | None = None
    driver_url = f"http://127.0.0.1:{driver_port}"
    try:
        _wait(f"http://127.0.0.1:{app_port}/healthz")
        _wait(f"{driver_url}/status")
        created = _request(
            f"{driver_url}/session",
            "POST",
            {"capabilities": {"alwaysMatch": {"browserName": "firefox", "moz:firefoxOptions": {"args": ["-headless"]}}}},
        )
        session_id = created["value"]["sessionId"]
        session = f"{driver_url}/session/{session_id}"
        _request(f"{session}/url", "POST", {"url": f"http://127.0.0.1:{app_port}/"})

        deadline = time.monotonic() + 10
        state: dict[str, Any] = {}
        while time.monotonic() < deadline:
            state = _request(f"{session}/execute/sync", "POST", {
                "script": "return {title: document.title, tools: document.querySelectorAll('.gen-item').length};",
                "args": [],
            })["value"]
            if state["tools"] >= 60:
                break
            time.sleep(0.05)
        assert "fast-secrets" in state["title"]
        assert state["tools"] >= 60

        sentinel = "browser-secret-must-not-persist"
        result = _request(f"{session}/execute/async", "POST", {
            "script": """
                const done = arguments[arguments.length - 1];
                window.__networkCalls = [];
                const originalFetch = window.fetch;
                window.fetch = (...args) => { window.__networkCalls.push(args); return originalFetch(...args); };
                document.querySelector('.gen-item[data-id="hmac"]').click();
                const text = document.querySelector('[data-key="text"]');
                const key = document.querySelector('[data-key="key"]');
                text.value = 'payload'; key.value = arguments[0];
                text.dispatchEvent(new Event('input', {bubbles: true}));
                key.dispatchEvent(new Event('input', {bubbles: true}));
                document.querySelector('#generate').click();
                const deadline = Date.now() + 5000;
                const poll = () => {
                  const output = document.querySelector('.out-row code')?.textContent;
                  if (output || Date.now() > deadline) done({
                    output,
                    calls: window.__networkCalls.map(call => String(call[0])),
                    storage: Object.entries(localStorage),
                  });
                  else setTimeout(poll, 25);
                };
                poll();
            """,
            "args": [sentinel],
        })["value"]
        assert len(result["output"]) == 64
        assert result["calls"] == []
        assert sentinel not in json.dumps(result["storage"])

        qr = _request(f"{session}/execute/async", "POST", {
            "script": """
                const done = arguments[arguments.length - 1];
                document.querySelector('.gen-item[data-id="totp"]').click();
                document.querySelector('#generate').click();
                const deadline = Date.now() + 5000;
                const poll = () => {
                  const canvas = document.querySelector('#visual-output canvas');
                  const output = document.querySelector('.out-row code')?.textContent || '';
                  if (canvas || Date.now() > deadline) done({
                    hasCanvas: !!canvas,
                    width: canvas?.width || 0,
                    hasUri: output.includes('otpauth://totp/'),
                  });
                  else setTimeout(poll, 25);
                };
                poll();
            """,
            "args": [],
        })["value"]
        assert qr == {"hasCanvas": True, "width": qr["width"], "hasUri": True}
        assert qr["width"] > 100

        online_contracts = _request(f"{session}/execute/sync", "POST", {
            "script": """
                document.querySelector('.gen-item[data-id="jsonpath"]').click();
                const keys = [...document.querySelectorAll('#options-form [data-key]')].map(node => node.dataset.key);
                document.querySelector('.gen-item[data-id="hash"]').click();
                return {keys, staleQrVisible: !document.querySelector('#visual-output').hidden};
            """,
            "args": [],
        })["value"]
        assert online_contracts == {"keys": ["text", "path"], "staleQrVisible": False}

        jsonpath_result = _request(f"{session}/execute/async", "POST", {
            "script": """
                const done = arguments[arguments.length - 1];
                document.querySelector('.gen-item[data-id="jsonpath"]').click();
                const text = document.querySelector('[data-key="text"]');
                const path = document.querySelector('[data-key="path"]');
                text.value = JSON.stringify({items: [{name: 'budget', price: 8}, {name: 'premium', price: 20}]});
                path.value = '$.items[?@.price < 10].name';
                text.dispatchEvent(new Event('input', {bubbles: true}));
                path.dispatchEvent(new Event('input', {bubbles: true}));
                document.querySelector('#generate').click();
                const deadline = Date.now() + 5000;
                const poll = () => {
                  const output = document.querySelector('.out-row code')?.textContent || '';
                  if (output || Date.now() > deadline) done({output, title: document.querySelector('#gen-title').textContent});
                  else setTimeout(poll, 25);
                };
                poll();
            """,
            "args": [],
        })["value"]
        assert jsonpath_result["title"] == "JSONPath"
        assert json.loads(jsonpath_result["output"]) == ["budget"]

        preset_privacy = _request(f"{session}/execute/sync", "POST", {
            "script": """
                document.querySelector('.gen-item[data-id="password_policy"]').click();
                const required = document.querySelector('[data-key="required_chars"]');
                required.value = arguments[0];
                required.dispatchEvent(new Event('input', {bubbles: true}));
                window.prompt = () => 'privacy-test';
                document.querySelector('#preset-save').click();
                return localStorage.getItem('fs:passwordPresets') || '';
            """,
            "args": [sentinel],
        })["value"]
        assert sentinel not in preset_privacy
        assert "required_chars" not in preset_privacy

        race = _request(f"{session}/execute/async", "POST", {
            "script": """
                const done = arguments[arguments.length - 1];
                document.querySelector('.gen-item[data-id="regex"]').click();
                document.querySelector('[data-key="pattern"]').value = '(a+)+$';
                document.querySelector('[data-key="text"]').value = 'a'.repeat(19999) + '!';
                document.querySelector('#generate').click();
                document.querySelector('.gen-item[data-id="hash"]').click();
                const input = document.querySelector('[data-key="text"]');
                input.value = 'abc'; input.dispatchEvent(new Event('input', {bubbles: true}));
                document.querySelector('#generate').click();
                setTimeout(() => done({
                  title: document.querySelector('#gen-title').textContent,
                  output: document.querySelector('.out-row code')?.textContent || '',
                  busy: !!document.querySelector('#generate').dataset.busy,
                }), 500);
            """,
            "args": [],
        })["value"]
        assert race == {
            "title": "Hash",
            "output": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "busy": False,
        }

        _request(f"{session}/url", "POST", {"url": f"http://127.0.0.1:{app_port}/docs"})
        deadline = time.monotonic() + 5
        docs: dict[str, Any] = {}
        while time.monotonic() < deadline:
            docs = _request(f"{session}/execute/sync", "POST", {
                "script": "return {title: document.title, endpoints: document.querySelectorAll('.endpoint').length};",
                "args": [],
            })["value"]
            if docs["endpoints"] >= 4:
                break
            time.sleep(0.05)
        assert docs["title"] == "fast-secrets · API v2"
        assert docs["endpoints"] >= 4
    finally:
        if session_id is not None:
            try:
                _request(f"{driver_url}/session/{session_id}", "DELETE")
            except (OSError, urllib.error.URLError):
                pass
        driver.terminate()
        server.terminate()
        for process in (driver, server):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
