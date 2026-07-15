"""fast-secrets v2 — stateless developer-secret tools and automation API."""

from __future__ import annotations

import asyncio
import json
import sysconfig
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from http import HTTPStatus
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import registry
from .api_models import (
    BatchRequest,
    ProblemDetails,
    ToolRunRequest,
    ToolRunResponse,
    ToolsResponse,
)

PACKAGE_DIR = Path(__file__).resolve().parent
SOURCE_STATIC_DIR = PACKAGE_DIR.parents[1] / "frontend"
INSTALLED_STATIC_DIR = (
    Path(sysconfig.get_path("data")) / "share" / "fast-secrets" / "static"
)
ADJACENT_STATIC_DIR = PACKAGE_DIR.parent / "share" / "fast-secrets" / "static"
STATIC_DIR = next(
    (
        directory
        for directory in (SOURCE_STATIC_DIR, INSTALLED_STATIC_DIR, ADJACENT_STATIC_DIR)
        if directory.is_dir()
    ),
    INSTALLED_STATIC_DIR,
)

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_BATCH_ITEMS = 25
MAX_TOTAL_VALUES = 1000
# Estimators cover the JSON-encoded ``data`` value. These conservative fixed
# allowances cover the response envelope, warnings, metadata, and batch item
# envelopes for every built-in entropy-backed tool.
MAX_RESPONSE_ENVELOPE_BYTES = 4 * 1024
MAX_BATCH_ITEM_ENVELOPE_BYTES = 512

PROBLEM_PREFIX = "urn:fast-secrets:problem:"

# Keep CPU-bound deterministic transforms off the event loop. Python 3.13's
# global SystemRandom can block when first entered from a worker on some
# sandboxed runtimes, so entropy-backed generators remain on the event loop;
# their work is strictly bounded and does not perform I/O.
_CPU_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fast-secrets")

SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; base-uri 'self'; connect-src 'self'; "
        "font-src 'self'; form-action 'self'; frame-ancestors 'none'; "
        "img-src 'self' data:; object-src 'none'; script-src 'self'; "
        "style-src 'self'; worker-src 'self'"
    ),
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "camera=(), geolocation=(), microphone=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-permitted-cross-domain-policies": "none",
}


class APIProblem(Exception):
    """An expected API failure rendered as RFC 9457 problem details."""

    def __init__(
        self,
        status: int,
        title: str,
        detail: str,
        problem_type: str,
        *,
        errors: list[dict[str, Any]] | None = None,
    ) -> None:
        self.status = status
        self.title = title
        self.detail = detail
        self.problem_type = problem_type
        self.errors = errors
        super().__init__(detail)


def _problem_payload(
    *,
    status: int,
    title: str,
    detail: str,
    problem_type: str,
    instance: str,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return ProblemDetails(
        type=f"{PROBLEM_PREFIX}{problem_type}",
        title=title,
        status=status,
        detail=detail,
        instance=instance,
        errors=errors,
    ).model_dump(exclude_none=True)


def _problem_response(
    request: Request,
    *,
    status: int,
    title: str,
    detail: str,
    problem_type: str,
    errors: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    # Use the path only: query strings can contain user-controlled secret data.
    payload = _problem_payload(
        status=status,
        title=title,
        detail=detail,
        problem_type=problem_type,
        instance=request.url.path,
        errors=errors,
    )
    return JSONResponse(
        payload,
        status_code=status,
        media_type="application/problem+json",
        headers={"Cache-Control": "no-store"},
    )


def _response_title(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "HTTP error"


def _problem_openapi(status: int) -> dict[str, Any]:
    """Document the runtime RFC 9457 media type without a misleading JSON entry."""
    return {
        "description": _response_title(status),
        "content": {
            "application/problem+json": {
                "schema": ProblemDetails.model_json_schema(),
            }
        },
    }


NEGOTIATED_SUCCESS = {
    "description": "Successful tool result",
    "content": {
        "text/plain": {"schema": {"type": "string"}},
        "application/x-ndjson": {"schema": {"type": "string"}},
    },
}


class APISafetyMiddleware:
    """Bound API bodies and attach security/cache headers without buffering output."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        is_execution = method == "POST" and (
            path == "/api/batch"
            or (path.startswith("/api/tools/") and path.endswith("/run"))
        )

        async def guarded_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = list(message.get("headers", ()))
                existing = {key.lower() for key, _ in headers}
                for key, value in SECURITY_HEADERS.items():
                    encoded_key = key.encode("latin-1")
                    if encoded_key not in existing:
                        headers.append((encoded_key, value.encode("latin-1")))
                if (is_execution or status >= 400) and b"cache-control" not in existing:
                    headers.append((b"cache-control", b"no-store"))
                if path == "/static/sw.js" and b"service-worker-allowed" not in existing:
                    headers.append((b"service-worker-allowed", b"/"))
                message["headers"] = headers
            await send(message)

        if not is_execution:
            await self.app(scope, receive, guarded_send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", ())
        }
        media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        content_encoding = headers.get("content-encoding", "identity").strip().lower()
        if media_type != "application/json" or content_encoding not in {"", "identity"}:
            response = JSONResponse(
                _problem_payload(
                    status=415,
                    title="Unsupported Media Type",
                    detail="Execution requests require an uncompressed application/json body.",
                    problem_type="unsupported-media-type",
                    instance=path,
                ),
                status_code=415,
                media_type="application/problem+json",
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, guarded_send)
            return

        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = -1
            if declared_size < 0:
                response = JSONResponse(
                    _problem_payload(
                        status=400,
                        title="Bad Request",
                        detail="Content-Length must be a nonnegative integer.",
                        problem_type="invalid-content-length",
                        instance=path,
                    ),
                    status_code=400,
                    media_type="application/problem+json",
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, guarded_send)
                return
            if declared_size > MAX_REQUEST_BYTES:
                response = JSONResponse(
                    _problem_payload(
                        status=413,
                        title="Content Too Large",
                        detail=f"Request bodies are limited to {MAX_REQUEST_BYTES} bytes.",
                        problem_type="request-too-large",
                        instance=path,
                    ),
                    status_code=413,
                    media_type="application/problem+json",
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, guarded_send)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > MAX_REQUEST_BYTES:
                response = JSONResponse(
                    _problem_payload(
                        status=413,
                        title="Content Too Large",
                        detail=f"Request bodies are limited to {MAX_REQUEST_BYTES} bytes.",
                        problem_type="request-too-large",
                        instance=path,
                    ),
                    status_code=413,
                    media_type="application/problem+json",
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, guarded_send)
                return
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay_body() -> Message:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_body, guarded_send)


app = FastAPI(
    title="fast-secrets",
    description="Stateless developer-secret utilities and a curl-friendly automation API.",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(APISafetyMiddleware)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.exception_handler(APIProblem)
async def api_problem_handler(request: Request, exc: APIProblem) -> JSONResponse:
    return _problem_response(
        request,
        status=exc.status,
        title=exc.title,
        detail=exc.detail,
        problem_type=exc.problem_type,
        errors=exc.errors,
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Pydantic includes raw inputs in its errors; omit them because they may be secrets.
    errors: list[dict[str, Any]] = []
    for item in exc.errors():
        sanitized = {
            "type": item.get("type", "validation_error"),
            "loc": [str(part) for part in item.get("loc", ())],
            "msg": item.get("msg", "Invalid value"),
        }
        if item.get("ctx"):
            sanitized["ctx"] = {
                str(key): str(value) for key, value in item["ctx"].items()
            }
        errors.append(sanitized)
    return _problem_response(
        request,
        status=422,
        title="Validation Error",
        detail="The request body does not match the API contract.",
        problem_type="validation-error",
        errors=errors,
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else _response_title(exc.status_code)
    return _problem_response(
        request,
        status=exc.status_code,
        title=_response_title(exc.status_code),
        detail=detail,
        problem_type=f"http-{exc.status_code}",
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, _exc: Exception) -> JSONResponse:
    # Do not disclose exception details or caller inputs in the public response.
    return _problem_response(
        request,
        status=500,
        title="Internal Server Error",
        detail="The tool could not be executed.",
        problem_type="internal-error",
    )


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/docs", include_in_schema=False)
async def api_docs() -> FileResponse:
    return FileResponse(STATIC_DIR / "api-docs.html")


@app.get("/healthz", tags=["service"])
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/tools", tags=["tools"], response_model=ToolsResponse)
async def list_tools() -> JSONResponse:
    return JSONResponse(
        {"tools": registry.public_metadata()},
        headers={"Cache-Control": "public, max-age=300"},
    )


def _tool_response(tool_id: str, result: registry.ToolResult) -> ToolRunResponse:
    return ToolRunResponse(
        tool=tool_id,
        kind=result.kind,
        data=result.data,
        warnings=list(result.warnings),
        meta=dict(result.meta),
    )


def _raise_estimated_response_too_large() -> None:
    raise APIProblem(
        413,
        "Content Too Large",
        f"The result exceeds the {MAX_RESPONSE_BYTES}-byte response limit.",
        "response-too-large",
    )


def _preflight_tool_response(tool_id: str, payload: ToolRunRequest) -> int | None:
    estimate = registry.estimate_tool_output_bytes(
        tool_id,
        payload.inputs,
        payload.options,
        payload.count,
    )
    if (
        estimate is not None
        and estimate + MAX_RESPONSE_ENVELOPE_BYTES > MAX_RESPONSE_BYTES
    ):
        _raise_estimated_response_too_large()
    return estimate


async def _execute_tool(tool_id: str, payload: ToolRunRequest) -> ToolRunResponse:
    try:
        spec = registry.get_tool(tool_id)
        _preflight_tool_response(tool_id, payload)
        args = (tool_id, payload.inputs, payload.options, payload.count)
        if spec.random:
            result = registry.run_tool(*args)
        else:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                _CPU_EXECUTOR,
                partial(registry.run_tool, *args),
            )
    except KeyError:
        raise APIProblem(
            404,
            "Tool Not Found",
            f"Unknown tool '{tool_id}'.",
            "tool-not-found",
        ) from None
    except ValueError as exc:
        raise APIProblem(
            422,
            "Invalid Tool Input",
            str(exc),
            "invalid-tool-input",
        ) from None
    return _tool_response(tool_id, result)


def _parse_accept(value: str | None) -> list[tuple[str, float, int]]:
    if not value:
        return [("application/json", 1.0, 0)]
    parsed: list[tuple[str, float, int]] = []
    for position, raw_item in enumerate(value.split(",")):
        parts = [part.strip() for part in raw_item.split(";")]
        media_type = parts[0].lower()
        quality = 1.0
        for parameter in parts[1:]:
            if parameter.lower().startswith("q="):
                try:
                    quality = float(parameter[2:])
                except ValueError:
                    quality = 0.0
        if quality > 0:
            parsed.append((media_type, min(quality, 1.0), position))
    return sorted(parsed, key=lambda item: (-item[1], item[2]))


def _matches(media_range: str, media_type: str) -> bool:
    if media_range == "*/*":
        return True
    if media_range.endswith("/*"):
        return media_type.startswith(media_range[:-1])
    return media_range == media_type


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _negotiated_type(request: Request, payload: ToolRunResponse) -> str:
    compatible = ["application/json"]
    if payload.kind == "text" and _is_scalar(payload.data):
        compatible.append("text/plain")
    elif payload.kind == "list" and isinstance(payload.data, list):
        compatible.append("application/x-ndjson")
        if all(_is_scalar(item) for item in payload.data):
            compatible.append("text/plain")
    elif payload.kind == "table" and isinstance(payload.data, list):
        compatible.append("application/x-ndjson")

    for media_range, _quality, _position in _parse_accept(request.headers.get("accept")):
        for media_type in compatible:
            if _matches(media_range, media_type):
                return media_type
    raise APIProblem(
        406,
        "Not Acceptable",
        f"This {payload.kind} result is available as {', '.join(compatible)}.",
        "not-acceptable",
    )


def _bounded_response(content: bytes, *, media_type: str, headers: dict[str, str]) -> Response:
    if len(content) > MAX_RESPONSE_BYTES:
        raise APIProblem(
            413,
            "Content Too Large",
            f"The result exceeds the {MAX_RESPONSE_BYTES}-byte response limit.",
            "response-too-large",
        )
    return Response(content=content, media_type=media_type, headers=headers)


def _render_result(request: Request, payload: ToolRunResponse) -> Response:
    media_type = _negotiated_type(request, payload)
    headers = {
        "Cache-Control": "no-store",
        "X-Tool-Id": payload.tool,
    }
    if media_type == "application/json":
        encoded = json.dumps(
            jsonable_encoder(payload.model_dump()),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return _bounded_response(encoded, media_type=media_type, headers=headers)

    if media_type == "text/plain":
        values = payload.data if isinstance(payload.data, list) else [payload.data]
        encoded = ("\n".join("" if value is None else str(value) for value in values) + "\n").encode(
            "utf-8"
        )
        headers["X-Result-Count"] = str(len(values))
        return _bounded_response(encoded, media_type=media_type, headers=headers)

    values = payload.data
    encoded = b"".join(
        json.dumps(
            jsonable_encoder(value),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
        for value in values
    )
    headers["X-Result-Count"] = str(len(values))
    return _bounded_response(encoded, media_type=media_type, headers=headers)


@app.post(
    "/api/tools/{tool_id}/run",
    tags=["tools"],
    response_model=ToolRunResponse,
    responses={
        200: NEGOTIATED_SUCCESS,
        406: _problem_openapi(406),
        413: _problem_openapi(413),
        415: _problem_openapi(415),
        422: _problem_openapi(422),
    },
)
async def run_tool(tool_id: str, payload: ToolRunRequest, request: Request) -> Response:
    result = await _execute_tool(tool_id, payload)
    return _render_result(request, result)


def _batch_problem(
    *,
    index: int,
    tool_id: str,
    status: int,
    title: str,
    detail: str,
    problem_type: str,
) -> dict[str, Any]:
    problem = _problem_payload(
        status=status,
        title=title,
        detail=detail,
        problem_type=problem_type,
        instance=f"/api/batch#item-{index}",
    )
    problem["tool"] = tool_id
    return problem


async def _execute_batch(payload: BatchRequest) -> ToolRunResponse:
    data: list[dict[str, Any]] = []
    failures = 0
    for index, item in enumerate(payload.requests):
        try:
            spec = registry.get_tool(item.tool)
            args = (item.tool, item.inputs, item.options, item.count)
            if spec.random:
                result = registry.run_tool(*args)
            else:
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    _CPU_EXECUTOR,
                    partial(registry.run_tool, *args),
                )
        except KeyError:
            failures += 1
            data.append(
                _batch_problem(
                    index=index,
                    tool_id=item.tool,
                    status=404,
                    title="Tool Not Found",
                    detail=f"Unknown tool '{item.tool}'.",
                    problem_type="tool-not-found",
                )
            )
        except ValueError as exc:
            failures += 1
            data.append(
                _batch_problem(
                    index=index,
                    tool_id=item.tool,
                    status=422,
                    title="Invalid Tool Input",
                    detail=str(exc),
                    problem_type="invalid-tool-input",
                )
            )
        else:
            data.append(_tool_response(item.tool, result).model_dump())
    return ToolRunResponse(
        tool="batch",
        kind="list",
        data=data,
        warnings=[],
        meta={
            "count": len(data),
            "failed": failures,
            "total_values": sum(item.count for item in payload.requests),
        },
    )


def _preflight_batch_response(payload: BatchRequest) -> None:
    estimated_bytes = MAX_RESPONSE_ENVELOPE_BYTES + 2
    for item in payload.requests:
        try:
            estimate = registry.estimate_tool_output_bytes(
                item.tool,
                item.inputs,
                item.options,
                item.count,
            )
        except (KeyError, ValueError):
            # Batch execution preserves unknown/invalid tools as per-item
            # problem details. They do not perform entropy-backed work.
            continue
        if estimate is None:
            continue
        estimated_bytes += estimate + MAX_BATCH_ITEM_ENVELOPE_BYTES
        if estimated_bytes > MAX_RESPONSE_BYTES:
            _raise_estimated_response_too_large()


@app.post(
    "/api/batch",
    tags=["tools"],
    response_model=ToolRunResponse,
    responses={
        200: NEGOTIATED_SUCCESS,
        406: _problem_openapi(406),
        413: _problem_openapi(413),
        415: _problem_openapi(415),
        422: _problem_openapi(422),
    },
)
async def run_batch(payload: BatchRequest, request: Request) -> Response:
    if len(payload.requests) > MAX_BATCH_ITEMS:
        # Pydantic enforces this too; keep the invariant near dispatch.
        raise APIProblem(
            422,
            "Invalid Batch",
            f"A batch can contain at most {MAX_BATCH_ITEMS} requests.",
            "invalid-batch",
        )
    total_values = sum(item.count for item in payload.requests)
    if total_values > MAX_TOTAL_VALUES:
        raise APIProblem(
            422,
            "Invalid Batch",
            f"A batch can request at most {MAX_TOTAL_VALUES} total values.",
            "invalid-batch",
        )
    _preflight_batch_response(payload)
    result = await _execute_batch(payload)
    return _render_result(request, result)
