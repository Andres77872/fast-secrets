"""Local command-line interface for the fast-secrets tool registry.

The CLI invokes the same transport-neutral handlers as the HTTP API.  Nothing is
sent over the network, which makes it suitable for shell pipelines containing
secrets.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from .registry import public_metadata, run_tool


def _jsonish(value: str) -> Any:
    """Parse JSON scalars/containers while keeping ordinary strings ergonomic."""
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _assignments(values: Iterable[str], flag: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise ValueError(f"{flag} expects KEY=VALUE, got {item!r}")
        if key in result:
            raise ValueError(f"Duplicate {flag} key: {key}")
        result[key] = _jsonish(value)
    return result


def _envelope(tool: str, result: Any) -> dict[str, Any]:
    return {
        "tool": tool,
        "kind": result.kind,
        "data": result.data,
        "warnings": result.warnings,
        "meta": result.meta,
    }


def _print_result(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    data = payload["data"]
    if isinstance(data, str):
        print(data)
    elif isinstance(data, list) and all(isinstance(item, str) for item in data):
        print("\n".join(data))
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    for warning in payload.get("warnings", []):
        print(f"warning: {warning}", file=sys.stderr)


def _cmd_tools(args: argparse.Namespace) -> int:
    tools = public_metadata()
    if args.json:
        print(json.dumps({"tools": tools}, ensure_ascii=False, indent=2))
        return 0
    for tool in tools:
        marker = "local/server" if tool["execution_mode"] == "both" else tool["execution_mode"]
        print(f"{tool['id']:<22} {tool['category']:<14} {marker:<12} {tool['label']}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    inputs = _assignments(args.input, "--input")
    options = _assignments(args.option, "--option")
    result = run_tool(args.tool, inputs, options, args.count)
    _print_result(_envelope(args.tool, result), args.format)
    return 0


def _read_batch(source: str) -> list[dict[str, Any]]:
    raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    value = json.loads(raw)
    if isinstance(value, dict):
        value = value.get("requests")
    if not isinstance(value, list) or not value:
        raise ValueError("Batch input must be a non-empty array or an object with 'requests'")
    if len(value) > 25:
        raise ValueError("Batch input is limited to 25 requests")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("Every batch request must be an object")
    return value


def _cmd_batch(args: argparse.Namespace) -> int:
    responses: list[dict[str, Any]] = []
    total = 0
    for index, request in enumerate(_read_batch(args.file), start=1):
        tool = request.get("tool")
        if not isinstance(tool, str) or not tool:
            raise ValueError(f"Batch request {index} needs a non-empty 'tool'")
        count = request.get("count", 1)
        if not isinstance(count, int) or isinstance(count, bool):
            raise ValueError(f"Batch request {index} has an invalid count")
        total += count
        if total > 1000:
            raise ValueError("Batch input is limited to 1,000 total results")
        result = run_tool(
            tool,
            request.get("inputs", {}),
            request.get("options", {}),
            count,
        )
        responses.append(_envelope(tool, result))
    print(json.dumps({"results": responses}, ensure_ascii=False, indent=2))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fast-secrets",
        description="Run the fast-secrets workbench locally without a network request.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    tools_parser = subparsers.add_parser("tools", help="List registered tools")
    tools_parser.add_argument("--json", action="store_true", help="Print full typed metadata")
    tools_parser.set_defaults(func=_cmd_tools)

    run_parser = subparsers.add_parser("run", help="Run one tool")
    run_parser.add_argument("tool", help="Tool id (see: fast-secrets tools)")
    run_parser.add_argument(
        "-i", "--input", action="append", default=[], metavar="KEY=VALUE",
        help="Set an input; repeat for multiple fields. JSON scalar values are accepted.",
    )
    run_parser.add_argument(
        "-o", "--option", action="append", default=[], metavar="KEY=VALUE",
        help="Set an option; repeat for multiple fields. JSON scalar values are accepted.",
    )
    run_parser.add_argument("-n", "--count", type=int, default=1)
    run_parser.add_argument("--format", choices=("json", "text"), default="text")
    run_parser.set_defaults(func=_cmd_run)

    batch_parser = subparsers.add_parser("batch", help="Run a JSON batch locally")
    batch_parser.add_argument("file", help="JSON file, or '-' to read stdin")
    batch_parser.set_defaults(func=_cmd_batch)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        detail = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        print(f"fast-secrets: {detail}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
