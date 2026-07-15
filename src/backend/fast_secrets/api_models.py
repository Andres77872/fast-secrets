"""Typed v2 API contracts for fast-secrets."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator


class ToolRunRequest(BaseModel):
    """Inputs for one tool invocation."""

    model_config = ConfigDict(extra="forbid")

    inputs: dict[str, Any] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)
    count: StrictInt = Field(default=1, ge=1, le=1000)


class BatchToolRunRequest(ToolRunRequest):
    """A tool invocation embedded in a batch."""

    tool: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class BatchRequest(BaseModel):
    """A bounded collection of tool invocations.

    The documented shape is ``{"requests": [...]}``. A bare JSON array is
    accepted as a convenience for NDJSON-oriented and older API clients.
    """

    model_config = ConfigDict(extra="forbid")

    requests: list[BatchToolRunRequest] = Field(min_length=1, max_length=25)

    @model_validator(mode="before")
    @classmethod
    def accept_bare_list(cls, value: Any) -> Any:
        if isinstance(value, list):
            return {"requests": value}
        return value


class ToolRunResponse(BaseModel):
    """Stable response envelope for one execution or a batch."""

    tool: str
    kind: str
    data: Any
    warnings: list[Any] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class ToolsResponse(BaseModel):
    """Typed metadata collection returned by the discovery endpoint."""

    tools: list[dict[str, Any]]


class ProblemDetails(BaseModel):
    """RFC 9457 problem details, with optional validation extensions."""

    type: str
    title: str
    status: int
    detail: str
    instance: str
    errors: list[dict[str, Any]] | None = None
