"""CLI contract tests: local execution, formatting, and batch limits."""

from __future__ import annotations

import json

from fast_secrets import cli


def test_tools_json(capsys):
    assert cli.main(["tools", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(tool["id"] == "uuid" for tool in payload["tools"])


def test_run_text(capsys):
    assert cli.main(["run", "uuid", "--option", "version=7", "--count", "2"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert all(line.split("-")[2].startswith("7") for line in lines)


def test_run_json_and_jsonish_options(capsys):
    assert cli.main([
        "run", "password", "--option", "length=12", "--option", "symbols=false",
        "--format", "json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "password"
    assert len(payload["data"][0]) == 12


def test_bad_assignment_is_a_clean_cli_error(capsys):
    assert cli.main(["run", "uuid", "--option", "missing-equals"]) == 2
    assert "KEY=VALUE" in capsys.readouterr().err


def test_batch_file(tmp_path, capsys):
    batch = tmp_path / "batch.json"
    batch.write_text(json.dumps({"requests": [
        {"tool": "hex", "options": {"nbytes": 4}, "count": 2},
        {"tool": "hash", "inputs": {"text": "hello"}, "options": {}, "count": 1},
    ]}), encoding="utf-8")

    assert cli.main(["batch", str(batch)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["results"][0]["data"]) == 2
    assert payload["results"][1]["kind"] == "text"


def test_batch_total_is_limited(tmp_path, capsys):
    batch = tmp_path / "too-many.json"
    batch.write_text(json.dumps([
        {"tool": "uuid", "options": {}, "count": 1000},
        {"tool": "uuid", "options": {}, "count": 1},
    ]), encoding="utf-8")

    assert cli.main(["batch", str(batch)]) == 2
    assert "1,000 total" in capsys.readouterr().err
