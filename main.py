"""fast-secrets — a tiny FastAPI service for generating random secrets.

Serves a minimal web UI at ``/`` and a curl-friendly JSON/text API under
``/api``. All generation lives in ``generators.py`` / ``registry.py``.

Run:  uvicorn main:app --reload
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import diffing
import registry

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="fast-secrets",
    description="Generate random secrets fast — UUIDs, tokens, passwords, API keys and more.",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --- request models ---------------------------------------------------------
class GenerateRequest(BaseModel):
    type: str = Field(..., description="Generator id, e.g. 'uuid'.")
    options: dict = Field(default_factory=dict)
    count: int = 1


class DiffRequest(BaseModel):
    text1: str = Field(default="", description="Original text.")
    text2: str = Field(default="", description="Changed text.")
    ignore_whitespace: bool = False
    ignore_case: bool = False
    granularity: str = Field(default="word", description="Intra-line unit: 'word' or 'char'.")


# --- UI ---------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


# --- API --------------------------------------------------------------------
@app.get("/api/generators")
async def list_generators() -> dict:
    """Metadata for every generator — drives the UI and documents the options."""
    return {"generators": registry.public_metadata()}


@app.get("/api/generate/{gen_id}")
async def generate_get(gen_id: str, request: Request):
    """Generate via query params. Extra params become generator options.

    ``count`` controls how many; ``format=text`` returns newline-joined raw
    values as text/plain (great for shell scripts and curl).
    """
    params = dict(request.query_params)
    count = params.pop("count", 1)
    fmt = params.pop("format", "json")
    try:
        values = registry.generate(gen_id, params, count)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown generator '{gen_id}'")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if fmt == "text":
        return PlainTextResponse("\n".join(values) + "\n")
    return {"type": gen_id, "count": len(values), "values": values}


@app.post("/api/generate")
async def generate_post(req: GenerateRequest) -> dict:
    """Generate via JSON body — used by the UI for rich options."""
    try:
        values = registry.generate(req.type, req.options, req.count)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown generator '{req.type}'")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"type": req.type, "count": len(values), "values": values}


@app.post("/api/generate/batch")
async def generate_batch(reqs: list[GenerateRequest]) -> dict:
    """Generate several generators in one call — powers 'Generate selected'."""
    results = []
    for req in reqs:
        try:
            values = registry.generate(req.type, req.options, req.count)
            results.append({"type": req.type, "count": len(values), "values": values})
        except KeyError:
            results.append({"type": req.type, "error": "unknown generator"})
        except ValueError as exc:
            results.append({"type": req.type, "error": str(exc)})
    return {"results": results}


@app.get("/api/all")
async def generate_all() -> dict:
    """One value of every generator with default options — quick 'generate all'."""
    results = []
    for spec in registry.GENERATORS:
        try:
            values = registry.generate(spec["id"], {}, 1)
            results.append({"type": spec["id"], "label": spec["label"], "values": values})
        except Exception as exc:  # noqa: BLE001 - report rather than 500 the whole call
            results.append({"type": spec["id"], "label": spec["label"], "error": str(exc)})
    return {"results": results}


@app.post("/api/diff")
async def diff(req: DiffRequest) -> dict:
    """Compare two texts. Returns aligned rows for inline + side-by-side rendering."""
    try:
        return diffing.diff_texts(
            req.text1,
            req.text2,
            ignore_whitespace=req.ignore_whitespace,
            ignore_case=req.ignore_case,
            granularity=req.granularity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
