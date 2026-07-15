"""Boundary tests for the transport-neutral registry contract."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from fast_secrets import registry


def _result(
    inputs: dict[str, Any], options: dict[str, Any], count: int
) -> registry.ToolResult:
    return registry.ToolResult(
        kind="record",
        data={"inputs": inputs, "options": options, "count": count},
    )


@contextmanager
def registered(spec: registry.ToolSpec) -> Iterator[registry.ToolSpec]:
    """Register a disposable tool and leave the global registry unchanged."""

    previous = registry.REGISTRY.get(spec.id)
    registry.register_tool(spec, replace=previous is not None)
    try:
        yield spec
    finally:
        current = registry.REGISTRY.pop(spec.id, None)
        if current in registry.GENERATORS:
            registry.GENERATORS.remove(current)
        if previous is not None:
            registry.REGISTRY[previous.id] = previous
            registry.GENERATORS.append(previous)


def test_field_metadata_applies_safe_string_and_sensitive_defaults():
    source_choice = {"value": "one", "label": "One"}
    field = registry.FieldSpec.from_mapping(
        {
            "key": "secret",
            "label": "Secret",
            "type": "string",
            "required": 1,
            "nullable": 0,
            "strict": 1,
            "min": 1,
            "max": 9,
            "placeholder": "enter a value",
            "choices": [source_choice],
        },
        sensitive=True,
    )
    source_choice["label"] = "mutated"

    metadata = field.public_metadata()
    assert metadata["max_length"] == 65_536
    assert metadata["sensitive"] is True
    assert metadata["persist"] is False
    assert metadata["choices"] == [{"value": "one", "label": "One"}]
    assert metadata["placeholder"] == "enter a value"
    assert metadata["min"] == 1 and metadata["max"] == 9

    numeric = registry.FieldSpec.from_mapping(
        {"key": "size", "label": "Size", "type": "int"}
    ).public_metadata()
    assert "max_length" not in numeric
    assert "choices" not in numeric


def test_tool_spec_metadata_and_legacy_indexing_are_read_only():
    input_field = registry.FieldSpec("value", "Value", "string")
    option_field = registry.FieldSpec("upper", "Upper", "bool", False)
    legacy = lambda value="": value  # noqa: E731 - tiny callable identity fixture
    spec = registry.ToolSpec(
        id="edge_metadata",
        label="Edge metadata",
        category="Tests",
        description="Typed metadata test",
        handler=_result,
        inputs=(input_field,),
        options=(option_field,),
        random=False,
        output_kind="record",
        sensitive=True,
        _legacy_fn=legacy,
    )

    assert spec["fn"] is legacy
    assert [field["key"] for field in spec["options"]] == ["value", "upper"]
    assert spec["id"] == "edge_metadata"
    assert spec.public_metadata()["sensitive"] is True
    with pytest.raises(KeyError):
        _ = spec["missing"]


def test_coerce_fields_accepts_json_lists_and_supported_scalar_forms():
    fields = (
        registry.FieldSpec("integer", "Integer", "int", 2, min=1, max=5),
        registry.FieldSpec("number", "Number", "float", 1.5),
        registry.FieldSpec("enabled", "Enabled", "bool", False),
        registry.FieldSpec(
            "choice",
            "Choice",
            "select",
            1,
            choices=({"value": 1, "label": "One"}, {"value": 2, "label": "Two"}),
        ),
        registry.FieldSpec("payload", "Payload", "json", {}),
        registry.FieldSpec("items", "Items", "list", []),
        registry.FieldSpec("name", "Name", "string", None),
        registry.FieldSpec("optional", "Optional", "string", None, nullable=True),
    )
    payload = {"nested": [1, True, None]}
    result = registry._coerce_fields(
        fields,
        {
            "integer": "99",
            "number": "2.25",
            "enabled": "YES",
            "choice": "2",
            "payload": payload,
            "items": ("a", "b"),
        },
    )

    assert result == {
        "integer": 5,
        "number": 2.25,
        "enabled": True,
        "choice": 2,
        "payload": payload,
        "items": ["a", "b"],
        "name": "",
        "optional": None,
    }

    fallback = registry._coerce_fields(
        (
            registry.FieldSpec("integer", "Integer", "int", 3, min=1, max=5),
            registry.FieldSpec(
                "choice",
                "Choice",
                "select",
                "safe",
                choices=({"value": "safe", "label": "Safe"},),
            ),
            registry.FieldSpec("enabled", "Enabled", "bool", False),
        ),
        {"integer": "not-an-int", "choice": "unknown", "enabled": []},
    )
    assert fallback == {"integer": 3, "choice": "safe", "enabled": False}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (registry.FieldSpec("x", "X", "string", required=True), None, "required"),
        (registry.FieldSpec("x", "X", "int", strict=True), True, "integer"),
        (registry.FieldSpec("x", "X", "int", strict=True), 1.5, "integer"),
        (registry.FieldSpec("x", "X", "int", strict=True), "bad", "integer"),
        (registry.FieldSpec("x", "X", "int", strict=True, min=2), 1, "at least"),
        (registry.FieldSpec("x", "X", "int", strict=True, max=2), 3, "at most"),
        (registry.FieldSpec("x", "X", "float", strict=True), True, "number"),
        (registry.FieldSpec("x", "X", "float", strict=True), "bad", "number"),
        (registry.FieldSpec("x", "X", "bool", strict=True), "perhaps", "boolean"),
        (registry.FieldSpec("x", "X", "bool", strict=True), 1, "boolean"),
        (
            registry.FieldSpec(
                "x",
                "X",
                "select",
                "a",
                strict=True,
                choices=({"value": "a", "label": "A"},),
            ),
            "b",
            "one of",
        ),
        (registry.FieldSpec("x", "X", "list", strict=True), "not-list", "array"),
        (registry.FieldSpec("x", "X", "string", strict=True), 3, "string"),
        (registry.FieldSpec("x", "X", "string", max_length=2), "abc", "limit"),
    ],
)
def test_strict_field_validation_rejects_ambiguous_values(field, value, message):
    with pytest.raises(ValueError, match=message):
        registry._coerce_fields((field,), {"x": value})


def test_register_replace_and_get_tool_lifecycle():
    first = registry.ToolSpec(
        "edge_lifecycle", "First", "Tests", "first", _result, random=False
    )
    second = registry.ToolSpec(
        "edge_lifecycle", "Second", "Tests", "second", _result, random=False
    )
    with registered(first):
        assert registry.get_tool(first.id) is first
        with pytest.raises(ValueError, match="already registered"):
            registry.register_tool(second)
        registry.register_tool(second, replace=True)
        assert registry.get_tool(first.id) is second

    with pytest.raises(KeyError):
        registry.get_tool("edge_lifecycle")


def test_run_tool_enforces_count_fields_and_handler_contracts():
    value = registry.FieldSpec("value", "Value", "string", required=True, strict=True)
    mode = registry.FieldSpec(
        "mode",
        "Mode",
        "select",
        "safe",
        strict=True,
        choices=({"value": "safe", "label": "Safe"},),
    )
    spec = registry.ToolSpec(
        "edge_run",
        "Run",
        "Tests",
        "run validation",
        _result,
        inputs=(value,),
        options=(mode,),
        random=False,
        output_kind="record",
        batchable=False,
        max_count=3,
    )
    with registered(spec):
        result = registry.run_tool(
            spec.id, {"value": "hello"}, {"mode": "safe"}, count=1
        )
        assert result.data == {
            "inputs": {"value": "hello"},
            "options": {"mode": "safe"},
            "count": 1,
        }
        for invalid in (True, "1", 1.0):
            with pytest.raises(ValueError, match="integer"):
                registry.run_tool(spec.id, {"value": "x"}, count=invalid)
        for invalid in (0, 4):
            with pytest.raises(ValueError, match="between"):
                registry.run_tool(spec.id, {"value": "x"}, count=invalid)
        with pytest.raises(ValueError, match="multiple"):
            registry.run_tool(spec.id, {"value": "x"}, count=2)
        with pytest.raises(ValueError, match="Unknown input"):
            registry.run_tool(spec.id, {"value": "x", "secret": "hidden"})
        with pytest.raises(ValueError, match="Unknown option"):
            registry.run_tool(spec.id, {"value": "x"}, {"extra": True})

    bad_return = registry.ToolSpec(
        "edge_bad_return", "Bad", "Tests", "bad", lambda *_: {"data": 1}
    )
    with registered(bad_return), pytest.raises(TypeError, match="ToolResult"):
        registry.run_tool(bad_return.id)

    bad_kind = registry.ToolSpec(
        "edge_bad_kind",
        "Bad kind",
        "Tests",
        "bad kind",
        lambda *_: registry.ToolResult(kind="binary", data=b"x"),  # type: ignore[arg-type]
    )
    with registered(bad_kind), pytest.raises(TypeError, match="output kind"):
        registry.run_tool(bad_kind.id)


def test_feature_adapter_validates_envelope_and_normalizes_random_singletons():
    adapted = registry._adapt_feature_handler(
        lambda *_: {
            "kind": "record",
            "data": {"secret": "value"},
            "warnings": ["careful"],
            "meta": {"count": 1},
        },
        random=True,
    )
    result = adapted({}, {}, 1)
    assert result.kind == "list" and result.data == [{"secret": "value"}]
    assert result.warnings == ["careful"]

    invalid_payloads = (
        [],
        {"kind": "binary", "data": "x"},
        {"kind": "record", "data": {}, "warnings": "bad"},
        {"kind": "record", "data": {}, "meta": []},
    )
    for payload in invalid_payloads:
        handler = registry._adapt_feature_handler(lambda *_, value=payload: value, random=False)
        with pytest.raises(TypeError):
            handler({}, {}, 1)


def test_generate_legacy_compatibility_handles_all_result_shapes_and_counts():
    with pytest.raises(KeyError):
        registry.generate("edge_missing")

    def handler_for(kind: str, data: Any):
        return lambda *_: registry.ToolResult(kind=kind, data=data)

    text = registry.ToolSpec(
        "edge_text", "Text", "Tests", "text", handler_for("text", 42), random=False
    )
    values = registry.ToolSpec(
        "edge_list", "List", "Tests", "list", handler_for("list", [1, 2]), random=False
    )
    record = registry.ToolSpec(
        "edge_record", "Record", "Tests", "record", handler_for("record", {"x": 1}), random=False
    )
    with registered(text):
        assert registry.generate(text.id) == ["42"]
    with registered(values):
        assert registry.generate(values.id) == ["1", "2"]
    with registered(record), pytest.raises(ValueError, match="legacy string"):
        registry.generate(record.id)

    legacy = registry.ToolSpec(
        "edge_legacy",
        "Legacy",
        "Tests",
        "legacy count",
        _result,
        random=True,
        _legacy_fn=lambda prefix="x": prefix,
        options=(registry.FieldSpec("prefix", "Prefix", "string", "x"),),
    )
    with registered(legacy):
        assert registry.generate(legacy.id, {"prefix": "ok"}, count="bad") == ["ok"]
        assert registry.generate(legacy.id, count=0) == ["x"]


def test_registry_metadata_helpers_expose_strict_nonpersistent_secrets():
    field = registry._feature_field(
        "token",
        "Token",
        "string",
        required=True,
        sensitive=True,
        min_value=1,
        max_value=3,
        max_length=10,
        choices=registry._choice_specs("first_value", 2),
        placeholder="paste",
    )
    assert field.strict is True and field.persist is False
    assert field.choices == (
        {"value": "first_value", "label": "First Value"},
        {"value": 2, "label": "2"},
    )
    assert any(tool["id"] == "password_policy" for tool in registry.public_metadata())


@pytest.mark.parametrize("tool_id", ["oauth_state", "oidc_nonce", "csp_nonce"])
def test_nonce_registry_metadata_matches_the_engine_boundary(tool_id):
    spec = registry.get_tool(tool_id)
    nbytes = next(field for field in spec.options if field.key == "nbytes")
    assert (nbytes.min, nbytes.max) == (16, 256)
    assert len(registry.run_tool(tool_id, options={"nbytes": 256}).data) == 1
    with pytest.raises(ValueError, match="at most 256"):
        registry.run_tool(tool_id, options={"nbytes": 257})


def test_every_random_builtin_has_a_safe_default_output_size_bound():
    for spec in registry.GENERATORS:
        if not spec.random:
            continue
        estimate = registry.estimate_tool_output_bytes(spec.id)
        result = registry.run_tool(spec.id)
        actual = len(
            json.dumps(
                result.data,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
        assert estimate is not None and estimate >= actual, spec.id
