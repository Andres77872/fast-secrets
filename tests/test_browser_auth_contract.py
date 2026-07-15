"""Focused browser parity contracts for auth, encoding, headers, and dotenv."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node is unavailable")
def test_browser_auth_and_parser_parity_contracts():
    completed = subprocess.run(
        [NODE, str(ROOT / "tests" / "browser_auth_contract.mjs")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    payload = json.loads(completed.stdout)
    assert payload == {
        "jwt": True,
        "hotpCounter": 2_147_483_648,
        "otpauth": True,
        "base32": True,
        "userAgent": True,
        "dotenv": True,
        "nonce": True,
    }
