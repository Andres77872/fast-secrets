"""No-build browser-module vectors and privacy invariants, executed with Node."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from fast_secrets import diffing


ROOT = Path(__file__).parents[1]
FRONTEND = ROOT / "src" / "frontend"
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node is unavailable")
def test_browser_local_crypto_and_tool_contracts():
    completed = subprocess.run(
        [NODE, str(ROOT / "tests" / "browser_contract.mjs")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    payload = json.loads(completed.stdout)
    assert payload["toolCount"] >= 60
    assert payload["sensitiveFieldsAreEphemeral"] is True
    assert payload["mergedContracts"]["jsonpath"] == ["text", "path"]
    assert payload["mergedContracts"]["checksum"][0] == "file"
    assert payload["mergedContracts"]["passwordSymbolsType"] == "bool"
    assert payload["base64"] == "aGVsbG8="
    assert payload["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert payload["hmac"] == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    assert payload["uuid4"].split("-")[2].startswith("4")
    assert payload["passwordPolicy"]["length"] == 24
    assert all(payload["passwordPolicy"][key] >= 2 for key in ("lower", "upper", "digits", "symbols"))
    assert payload["jsonpath"] == [1]
    assert set(payload["jsonpathRfc"]["recursive"]) == {"A", "B", "C"}
    assert payload["jsonpathRfc"]["reverseSlice"] == [2, 1]
    assert payload["jsonpathRfc"]["functionFilter"] == ["A"]
    assert payload["diffSimilarity"]["changed"] == 1
    expected_similarity = diffing.diff_texts("xabcdef", "yabcdef")["stats"]["similarity"]
    assert abs(payload["diffSimilarity"]["similarity"] - expected_similarity) <= 0.5
    assert payload["jwtDetection"] == "jwt_debugger"


def test_ui_has_no_api_execution_request_path():
    application = (FRONTEND / "app.js").read_text(encoding="utf-8")
    local_tools = (FRONTEND / "local-tools.js").read_text(encoding="utf-8")
    assert 'fetch("/api/tools"' in application
    assert "/api/tools/" not in application
    assert "method: \"POST\"" not in application
    assert "fetch(" not in local_tools


def test_service_worker_caches_only_explicit_get_shell_assets():
    worker = (FRONTEND / "sw.js").read_text(encoding="utf-8")
    assert 'request.method !== "GET"' in worker
    assert "/api/" not in worker
    assert "SHELL.has(url.pathname)" in worker
    assert '"/static/jsonpath-worker.js"' in worker
    vendor_modules = {
        f'"/static/{path.relative_to(FRONTEND).as_posix()}"'
        for path in (FRONTEND / "vendor" / "jsonpath-rfc9535").rglob("*.js")
    }
    assert all(module in worker for module in vendor_modules)


def test_vendored_jsonpath_has_license_and_no_dynamic_code_execution():
    vendor = FRONTEND / "vendor" / "jsonpath-rfc9535"
    assert "Apache License" in (vendor / "LICENSE").read_text(encoding="utf-8")
    source = "\n".join(path.read_text(encoding="utf-8") for path in vendor.rglob("*.js"))
    assert "eval(" not in source
    assert "new Function" not in source


def test_manifest_has_installable_png_and_maskable_icons():
    manifest = json.loads((FRONTEND / "manifest.webmanifest").read_text(encoding="utf-8"))
    icons = manifest["icons"]
    assert {icon["sizes"] for icon in icons if icon["type"] == "image/png"} >= {
        "192x192", "512x512"
    }
    assert any(icon.get("purpose") == "maskable" for icon in icons)
    for icon in icons:
        if icon["type"] != "image/png":
            continue
        path = FRONTEND / icon["src"].removeprefix("/static/")
        raw = path.read_bytes()
        assert raw.startswith(b"\x89PNG\r\n\x1a\n")
        width, height = struct.unpack(">II", raw[16:24])
        expected = tuple(int(value) for value in icon["sizes"].split("x"))
        assert (width, height) == expected
