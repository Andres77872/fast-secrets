"""Integration tests for the bounded, stateless v2 API."""

from __future__ import annotations

import json
import threading
from dataclasses import replace

import pytest

from fast_secrets import generators as g
from fast_secrets import registry
from fast_secrets.main import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    MAX_RESPONSE_ENVELOPE_BYTES,
)


def test_health_and_index_have_security_headers(api_client):
    health = api_client.get("/healthz")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    for header in (
        "content-security-policy",
        "referrer-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    ):
        assert header in health.headers

    index = api_client.get("/")
    assert index.status_code == 200
    assert "fast-secrets" in index.text

    docs = api_client.get("/docs")
    assert docs.status_code == 200
    assert "/static/api-docs.js" in docs.text
    assert "content-security-policy" in docs.headers
    assert api_client.get("/redoc").status_code == 404


def test_tool_metadata_is_typed_and_safe(api_client):
    response = api_client.get("/api/tools")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    tools = response.json()["tools"]
    by_id = {tool["id"]: tool for tool in tools}
    assert {
        "uuid",
        "password",
        "hex",
        "ulid",
        "nanoid",
        "objectid",
        "passphrase",
        "hash",
        "hmac",
        "jwt",
        "jwt_decode",
        "user_agent",
        "base64_text",
        "url_codec",
        "json",
        "text_case",
        "email",
        "ipv4",
        "ipv6",
        "mac",
        "semver",
        "lorem",
        "basic_auth",
        "text_diff",
    } <= by_id.keys()
    assert set(by_id["uuid"]) == {
        "id",
        "label",
        "category",
        "description",
        "inputs",
        "options",
        "random",
        "execution_mode",
        "output_kind",
        "batchable",
        "max_count",
        "sensitive",
    }
    assert by_id["uuid"]["output_kind"] == "list"
    assert by_id["hash"]["output_kind"] == "text"
    jwt_secret = next(field for field in by_id["jwt"]["inputs"] if field["key"] == "secret")
    assert jwt_secret["sensitive"] is True
    assert jwt_secret["persist"] is False
    assert "fn" not in response.text


def test_all_standards_feature_engines_are_registered(api_client):
    from fast_secrets import tool_features

    tools = {tool["id"]: tool for tool in api_client.get("/api/tools").json()["tools"]}
    assert len(tools) == 55
    assert set(tool_features.FEATURE_HANDLERS) <= tools.keys()
    assert tools["jwt_encode"]["output_kind"] == "record"
    assert tools["password_policy"]["output_kind"] == "list"
    claims = next(field for field in tools["jwt_encode"]["inputs"] if field["key"] == "claims")
    timezones = next(
        field for field in tools["timestamp"]["options"] if field["key"] == "output_timezones"
    )
    assert claims["type"] == "json"
    assert timezones["type"] == "list"


def test_text_diff_migration_target_has_private_typed_contract_and_runs(
    api_client, monkeypatch
):
    spec = registry.get_tool("text_diff")
    assert spec.random is False  # deterministic tools run in main's CPU executor
    assert spec.output_kind == "record"
    assert spec.max_count == 1
    assert spec.sensitive is True
    assert [field.key for field in spec.inputs] == ["text1", "text2"]
    assert all(field.sensitive and not field.persist for field in spec.inputs)
    assert [field.key for field in spec.options] == [
        "ignore_whitespace",
        "ignore_case",
        "granularity",
    ]

    worker_threads = []
    original_diff = registry.diffing.diff_texts

    def tracked_diff(*args, **kwargs):
        worker_threads.append(threading.current_thread().name)
        return original_diff(*args, **kwargs)

    monkeypatch.setattr(registry.diffing, "diff_texts", tracked_diff)
    response = api_client.post(
        "/api/tools/text_diff/run",
        json_body={
            "inputs": {"text1": "hello world", "text2": "hello brave world"},
            "options": {"granularity": "word"},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tool"] == "text_diff"
    assert body["kind"] == "record"
    assert body["data"]["stats"]["changed"] == 1
    assert body["data"]["stats"]["identical"] is False
    assert body["data"]["unified"].startswith("--- original\n+++ changed")
    assert body["meta"] == {
        "max_bytes_per_side": 200_000,
        "max_lines_per_side": 5_000,
    }
    assert worker_threads and worker_threads[0].startswith("fast-secrets")


def test_json_tool_execution_envelope(api_client):
    response = api_client.post(
        "/api/tools/uuid/run",
        json_body={"inputs": {}, "options": {}, "count": 3},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"tool", "kind", "data", "warnings", "meta"}
    assert body["tool"] == "uuid"
    assert body["kind"] == "list"
    assert len(body["data"]) == 3
    assert body["meta"]["count"] == 3


def test_execution_preserves_generator_options_and_separates_inputs(api_client):
    password = api_client.post(
        "/api/tools/password/run",
        json_body={"options": {"length": 12, "symbols": False}},
    )
    assert password.status_code == 200
    value = password.json()["data"][0]
    assert len(value) == 12
    assert not any(character in g.SYMBOLS for character in value)

    digest = api_client.post(
        "/api/tools/hash/run",
        json_body={"inputs": {"text": "abc"}, "options": {"algorithm": "sha256"}},
    )
    assert digest.status_code == 200
    assert digest.json()["data"] == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_rich_json_and_list_inputs_are_preserved(api_client):
    signed = api_client.post(
        "/api/tools/jwt_encode/run",
        json_body={
            "inputs": {
                "claims": {"sub": "alice", "aud": ["api", "web"], "exp": 2_000},
                "secret": "correct horse",
                "header": {"kid": "local-key"},
            },
            "options": {"algorithm": "HS384"},
        },
    )
    assert signed.status_code == 200
    assert signed.json()["kind"] == "record"
    token = signed.json()["data"]["token"]

    verified = api_client.post(
        "/api/tools/jwt_verify/run",
        json_body={
            "inputs": {"token": token, "secret": "correct horse"},
            "options": {
                "allowed_algorithms": ["HS384"],
                "audience": "api",
                "now": 1_000,
            },
        },
    )
    assert verified.status_code == 200
    assert verified.json()["data"]["verified"] is True

    converted = api_client.post(
        "/api/tools/timestamp/run",
        json_body={
            "inputs": {"value": 1_704_067_200_000},
            "options": {"output_timezones": ["UTC", "America/Mexico_City"]},
        },
    )
    assert converted.status_code == 200
    assert converted.json()["data"]["detected_format"] == "epoch_milliseconds"
    assert len(converted.json()["data"]["outputs"]) == 2


def test_api_jsonpath_uses_pinned_strict_rfc9535_engine(api_client):
    response = api_client.post(
        "/api/tools/jsonpath/run",
        json_body={
            "inputs": {
                "document": {
                    "items": [
                        {"name": "small", "price": 5},
                        {"name": "large", "price": 20},
                    ]
                },
                "query": "$.items[?@.price < 10].name",
            }
        },
    )
    assert response.status_code == 200
    assert response.json()["data"] == {
        "values": ["small"],
        "count": 1,
        "truncated": False,
        "engine": "registered-rfc9535",
    }


def test_text_and_ndjson_content_negotiation(api_client):
    plain = api_client.post(
        "/api/tools/hex/run",
        json_body={"count": 4},
        headers={"accept": "text/plain"},
    )
    assert plain.status_code == 200
    assert plain.headers["content-type"].startswith("text/plain")
    assert len(plain.text.strip().splitlines()) == 4

    ndjson = api_client.post(
        "/api/tools/uuid/run",
        json_body={"count": 2},
        headers={"accept": "application/x-ndjson"},
    )
    assert ndjson.status_code == 200
    values = [json.loads(line) for line in ndjson.text.strip().splitlines()]
    assert len(values) == 2
    assert all(isinstance(value, str) for value in values)

    preferred_plain = api_client.post(
        "/api/tools/hash/run",
        json_body={"inputs": {"text": "x"}},
        headers={"accept": "text/plain, application/json;q=0.5"},
    )
    assert preferred_plain.status_code == 200
    assert preferred_plain.headers["content-type"].startswith("text/plain")


@pytest.mark.parametrize("accept", ["application/xml", "application/x-ndjson"])
def test_incompatible_accept_returns_problem(api_client, accept):
    response = api_client.post(
        "/api/tools/hash/run",
        json_body={"inputs": {"text": "x"}},
        headers={"accept": accept},
    )
    assert response.status_code == 406
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["type"].endswith(":not-acceptable")


def test_problem_details_for_unknown_tool_and_invalid_fields(api_client):
    unknown = api_client.post("/api/tools/missing/run", json_body={})
    assert unknown.status_code == 404
    assert unknown.headers["content-type"] == "application/problem+json"
    assert unknown.headers["cache-control"] == "no-store"
    assert unknown.json() == {
        "type": "urn:fast-secrets:problem:tool-not-found",
        "title": "Tool Not Found",
        "status": 404,
        "detail": "Unknown tool 'missing'.",
        "instance": "/api/tools/missing/run",
    }

    invalid = api_client.post(
        "/api/tools/uuid/run",
        json_body={"inputs": {"private_value": "DO_NOT_REFLECT"}},
    )
    assert invalid.status_code == 422
    assert invalid.json()["type"].endswith(":invalid-tool-input")
    assert "DO_NOT_REFLECT" not in invalid.text


def test_schema_errors_are_sanitized(api_client):
    response = api_client.post(
        "/api/tools/uuid/run",
        json_body={"count": "SECRET_COUNT_VALUE", "extra": "SECRET_EXTRA_VALUE"},
    )
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert "SECRET_COUNT_VALUE" not in response.text
    assert "SECRET_EXTRA_VALUE" not in response.text
    assert response.json()["errors"]


def test_strict_content_type_and_request_budget(api_client):
    unsupported = api_client.post("/api/tools/uuid/run", content=b"{}")
    assert unsupported.status_code == 415
    assert unsupported.json()["type"].endswith(":unsupported-media-type")

    compressed = api_client.post(
        "/api/tools/uuid/run",
        content=b"{}",
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )
    assert compressed.status_code == 415

    oversized = api_client.post(
        "/api/tools/uuid/run",
        content=b"x" * (MAX_REQUEST_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert oversized.status_code == 413
    assert oversized.json()["type"].endswith(":request-too-large")


def test_count_and_batch_budgets(api_client):
    count = api_client.post("/api/tools/uuid/run", json_body={"count": 1001})
    assert count.status_code == 422

    total = api_client.post(
        "/api/batch",
        json_body={
            "requests": [
                {"tool": "uuid", "count": 600},
                {"tool": "hex", "count": 401},
            ]
        },
    )
    assert total.status_code == 422
    assert total.json()["type"].endswith(":invalid-batch")

    too_many = api_client.post(
        "/api/batch",
        json_body={"requests": [{"tool": "uuid"}] * 26},
    )
    assert too_many.status_code == 422


def test_batch_results_partial_errors_and_bare_list(api_client):
    response = api_client.post(
        "/api/batch",
        json_body={
            "requests": [
                {"tool": "uuid", "count": 2},
                {"tool": "pin", "options": {"length": 4}},
                {"tool": "missing"},
            ]
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tool"] == "batch"
    assert body["kind"] == "list"
    assert len(body["data"][0]["data"]) == 2
    assert len(body["data"][1]["data"][0]) == 4
    assert body["data"][2]["status"] == 404
    assert body["meta"] == {"count": 3, "failed": 1, "total_values": 4}

    bare = api_client.post("/api/batch", json_body=[{"tool": "uuid"}])
    assert bare.status_code == 200
    assert bare.json()["meta"]["count"] == 1


def test_batch_ndjson_and_plain_rejection(api_client):
    ndjson = api_client.post(
        "/api/batch",
        json_body={"requests": [{"tool": "uuid"}, {"tool": "hex"}]},
        headers={"accept": "application/x-ndjson"},
    )
    assert ndjson.status_code == 200
    assert len([json.loads(line) for line in ndjson.text.strip().splitlines()]) == 2

    plain = api_client.post(
        "/api/batch",
        json_body={"requests": [{"tool": "uuid"}]},
        headers={"accept": "text/plain"},
    )
    assert plain.status_code == 406


def test_response_budget_is_enforced(api_client):
    tool_id = "test_oversized_response"

    def oversized_handler(_inputs, _options, _count):
        return registry.ToolResult(kind="text", data="x" * (MAX_RESPONSE_BYTES + 1))

    spec = registry.ToolSpec(
        id=tool_id,
        label="Oversized test",
        category="Tests",
        description="Test-only oversized response.",
        handler=oversized_handler,
        random=False,
        output_kind="text",
        max_count=1,
    )
    registry.register_tool(spec)
    try:
        response = api_client.post(f"/api/tools/{tool_id}/run", json_body={})
        assert response.status_code == 413
        assert response.json()["type"].endswith(":response-too-large")
    finally:
        registry.REGISTRY.pop(tool_id)
        registry.GENERATORS.remove(spec)


@pytest.mark.parametrize(
    ("tool_id", "options"),
    [
        ("password_policy", {"length": 1024}),
        ("base32_secret", {"nbytes": 4096}),
    ],
)
def test_entropy_response_preflight_skips_oversized_handler(
    api_client, monkeypatch, tool_id, options
):
    original = registry.get_tool(tool_id)
    calls = []

    def forbidden_handler(_inputs, _options, _count):
        calls.append(True)
        raise AssertionError("oversized entropy-backed handler must not run")

    monkeypatch.setitem(
        registry.REGISTRY,
        original.id,
        replace(original, handler=forbidden_handler),
    )

    response = api_client.post(
        f"/api/tools/{tool_id}/run",
        json_body={"options": options, "count": 1000},
    )

    assert response.status_code == 413
    assert response.json()["type"].endswith(":response-too-large")
    assert calls == []


def test_batch_preflight_sums_estimates_before_entropy_dispatch(
    api_client, monkeypatch
):
    original = registry.get_tool("base32_secret")
    calls = []

    def forbidden_handler(_inputs, _options, _count):
        calls.append(True)
        raise AssertionError("oversized entropy-backed batch handler must not run")

    monkeypatch.setitem(
        registry.REGISTRY,
        original.id,
        replace(original, handler=forbidden_handler),
    )
    item = {
        "tool": "base32_secret",
        "options": {"nbytes": 650},
        "count": 500,
    }
    single_estimate = registry.estimate_tool_output_bytes(
        item["tool"],
        options=item["options"],
        count=item["count"],
    )
    assert single_estimate is not None
    assert single_estimate + MAX_RESPONSE_ENVELOPE_BYTES < MAX_RESPONSE_BYTES

    response = api_client.post(
        "/api/batch",
        json_body={"requests": [item, item]},
    )

    assert response.status_code == 413
    assert response.json()["type"].endswith(":response-too-large")
    assert calls == []


def test_entropy_preflight_keeps_count_1000_for_bounded_outputs(api_client):
    response = api_client.post("/api/tools/uuid/run", json_body={"count": 1000})

    assert response.status_code == 200
    assert len(response.json()["data"]) == 1000

    for tool_id, options in (
        ("string", {"length": 1024}),
        ("hex", {"nbytes": 512}),
        ("base64", {"nbytes": 512}),
    ):
        estimate = registry.estimate_tool_output_bytes(
            tool_id,
            options=options,
            count=1000,
        )
        assert estimate is not None
        assert estimate + MAX_RESPONSE_ENVELOPE_BYTES <= MAX_RESPONSE_BYTES

    lorem = registry.estimate_tool_output_bytes(
        "lorem",
        options={
            "paragraphs": 8,
            "sentences": 12,
            "words_per_sentence": 30,
        },
        count=1000,
    )
    assert lorem is not None
    assert lorem + MAX_RESPONSE_ENVELOPE_BYTES > MAX_RESPONSE_BYTES


def test_rich_tool_registration_hook(api_client):
    tool_id = "test_rich_record"

    def rich_handler(inputs, options, count):
        return registry.ToolResult(
            kind="record",
            data={"echo": inputs["value"], "uppercase": options["uppercase"]},
            warnings=["test warning"],
            meta={"count": count},
        )

    spec = registry.ToolSpec(
        id=tool_id,
        label="Rich record test",
        category="Tests",
        description="Test-only registration hook.",
        handler=rich_handler,
        inputs=(
            registry.FieldSpec(
                key="value",
                label="Value",
                type="string",
                default="",
                sensitive=True,
                persist=False,
                max_length=20,
            ),
        ),
        options=(
            registry.FieldSpec(
                key="uppercase",
                label="Uppercase",
                type="bool",
                default=False,
            ),
        ),
        random=False,
        output_kind="record",
        max_count=1,
        sensitive=True,
    )
    registry.register_tool(spec)
    try:
        response = api_client.post(
            f"/api/tools/{tool_id}/run",
            json_body={"inputs": {"value": "hello"}, "options": {"uppercase": True}},
        )
        assert response.status_code == 200
        assert response.json() == {
            "tool": tool_id,
            "kind": "record",
            "data": {"echo": "hello", "uppercase": True},
            "warnings": ["test warning"],
            "meta": {"count": 1},
        }
        with pytest.raises(ValueError, match="already registered"):
            registry.register_tool(spec)
    finally:
        registry.REGISTRY.pop(tool_id)
        registry.GENERATORS.remove(spec)


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/generators"),
        ("GET", "/api/generate/uuid"),
        ("POST", "/api/generate"),
        ("POST", "/api/generate/batch"),
        ("GET", "/api/all"),
        ("POST", "/api/diff"),
    ],
)
def test_v1_routes_are_removed(api_client, method, path):
    response = api_client.request(method, path)
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


def test_openapi_exposes_only_v2_tool_routes(api_client):
    response = api_client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/tools" in paths
    assert "/api/tools/{tool_id}/run" in paths
    assert "/api/batch" in paths
    assert "/healthz" in paths
    assert all(not path.startswith("/api/generate") for path in paths)
    tools_schema = paths["/api/tools"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert tools_schema["$ref"].endswith("/ToolsResponse")
    run_responses = paths["/api/tools/{tool_id}/run"]["post"]["responses"]
    assert run_responses["200"]["content"]["application/json"]["schema"][
        "$ref"
    ].endswith("/ToolRunResponse")
    assert {"application/json", "text/plain", "application/x-ndjson"} <= set(
        run_responses["200"]["content"]
    )
    assert set(run_responses["422"]["content"]) == {"application/problem+json"}
