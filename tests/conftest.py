"""Test helpers that exercise the ASGI app without the deprecated TestClient."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from fast_secrets.main import app

_UNSET = object()


@dataclass(slots=True)
class ASGIResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.content)


class ASGIClient:
    """Small synchronous facade over a direct ASGI request."""

    def __init__(self) -> None:
        # Reuse one loop like a real ASGI server. This also keeps executor-backed
        # tool calls deterministic across multiple requests in one test.
        self._runner = asyncio.Runner()

    def close(self) -> None:
        self._runner.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = _UNSET,
        content: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> ASGIResponse:
        return self._runner.run(
            self._request(
                method,
                path,
                json_body=json_body,
                content=content,
                headers=headers,
            )
        )

    def get(self, path: str, *, headers: dict[str, str] | None = None) -> ASGIResponse:
        return self.request("GET", path, headers=headers)

    def post(
        self,
        path: str,
        *,
        json_body: Any = _UNSET,
        content: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> ASGIResponse:
        return self.request(
            "POST",
            path,
            json_body=json_body,
            content=content,
            headers=headers,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any,
        content: bytes | str | None,
        headers: dict[str, str] | None,
    ) -> ASGIResponse:
        if json_body is not _UNSET and content is not None:
            raise ValueError("Use either json_body or content, not both")
        request_headers = {"host": "testserver", **(headers or {})}
        if json_body is not _UNSET:
            body = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("content-type", "application/json")
        elif isinstance(content, str):
            body = content.encode("utf-8")
        else:
            body = content or b""
        if body:
            request_headers.setdefault("content-length", str(len(body)))

        target = urlsplit(path)
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": target.path,
            "raw_path": target.path.encode("ascii"),
            "query_string": target.query.encode("ascii"),
            "root_path": "",
            "headers": [
                (key.lower().encode("latin-1"), value.encode("latin-1"))
                for key, value in request_headers.items()
            ],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "state": {},
            "extensions": {"http.response.pathsend": {}},
        }
        incoming = [{"type": "http.request", "body": body, "more_body": False}]
        outgoing: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            if incoming:
                return incoming.pop(0)
            # A real connection does not disconnect immediately after sending its
            # request body. FileResponse listens for disconnect concurrently; an
            # eager synthetic disconnect can race and cancel the response stream.
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.pathsend":
                # Starlette can hand a file path directly to supporting servers.
                # Materialize it here so the tiny client remains transport-complete.
                outgoing.append(
                    {
                        "type": "http.response.body",
                        "body": Path(message["path"]).read_bytes(),
                        "more_body": False,
                    }
                )
            else:
                outgoing.append(message)

        await app(scope, receive, send)
        start = next(message for message in outgoing if message["type"] == "http.response.start")
        response_body = b"".join(
            message.get("body", b"")
            for message in outgoing
            if message["type"] == "http.response.body"
        )
        response_headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in start.get("headers", ())
        }
        return ASGIResponse(start["status"], response_headers, response_body)


@pytest.fixture
def api_client() -> Iterator[ASGIClient]:
    client = ASGIClient()
    try:
        yield client
    finally:
        client.close()
