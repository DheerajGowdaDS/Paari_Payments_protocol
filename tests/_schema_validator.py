"""Tiny stdlib-only JSON Schema subset validator for Paari tests.

Supports the subset actually used by paari-*.v1.schema.json:
- type (string or ["string","null"] etc), const, enum, pattern, minLength,
  maxLength, minimum, format (date-time, uri, uri-template), required,
  properties, additionalProperties: false, array items, object
  additionalProperties schemas, and oneOf.

Intentionally strict: an unimplemented keyword raises rather than being
skipped, so a schema can never silently stop being checked.
"""
from __future__ import annotations

import re
from datetime import datetime

_URI_RE = re.compile(r"^https?://\S+$")

# Keywords this validator implements. Anything outside this set (and outside
# the JSON Schema annotation keywords below) is a hard error, never a no-op.
_SUPPORTED = {
    "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum",
    "format", "required", "properties", "additionalProperties", "items", "oneOf",
}
_ANNOTATION = {
    "$schema", "$id", "$comment", "title", "description", "default",
    "examples", "example", "$defs", "definitions",
}


def _assert_supported(schema: dict, path: str) -> None:
    for keyword in schema:
        if keyword in _ANNOTATION:
            continue
        if keyword not in _SUPPORTED:
            raise AssertionError(
                f"{path}: unsupported JSON Schema keyword '{keyword}' - "
                "extend tests/_schema_validator.py instead of letting it pass unchecked"
            )


def _check_format(value: str, fmt: str, path: str):
    if fmt == "date-time":
        # Accept ISO-8601 with optional Z; use fromisoformat after normalizing
        v = value.replace("Z", "+00:00")
        try:
            datetime.fromisoformat(v)
        except Exception as e:
            raise AssertionError(f"{path}: format date-time invalid '{value}': {e}") from e
    elif fmt == "uri":
        if not _URI_RE.match(value):
            raise AssertionError(f"{path}: format uri invalid '{value}'")
    elif fmt == "uri-template":
        # Must look like a URI possibly containing {var}; basic check
        if "://" not in value:
            raise AssertionError(f"{path}: format uri-template invalid '{value}'")
    else:
        raise AssertionError(f"{path}: unsupported format '{fmt}'")


def _type_match(value, type_decl) -> bool:
    types = [type_decl] if isinstance(type_decl, str) else list(type_decl)
    for t in types:
        if t == "null" and value is None:
            return True
        if t == "string" and isinstance(value, str):
            return True
        if t == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if t == "boolean" and isinstance(value, bool):
            return True
        if t == "array" and isinstance(value, list):
            return True
        if t == "object" and isinstance(value, dict):
            return True
        if t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
    return False


def _matches(instance, schema: dict) -> bool:
    try:
        validate(instance, schema)
    except AssertionError:
        return False
    return True


def assert_schema_supported(schema: dict, path: str = "$") -> None:
    """Walk a whole schema tree and fail on any keyword this validator lacks.

    Keyword checks during validate() only reach branches the instance visits,
    so a schema can hold an unsupported construct in a property nobody sent.
    Call this over every shipped schema to keep that from rotting silently.
    """
    if not isinstance(schema, dict):
        raise AssertionError(f"{path}: schema node is not an object")
    _assert_supported(schema, path)
    for key, sub in (schema.get("properties") or {}).items():
        assert_schema_supported(sub, f"{path}.{key}")
    if isinstance(schema.get("items"), dict):
        assert_schema_supported(schema["items"], f"{path}[]")
    if isinstance(schema.get("additionalProperties"), dict):
        assert_schema_supported(schema["additionalProperties"], f"{path}+extra")
    for i, sub in enumerate(schema.get("oneOf") or []):
        assert_schema_supported(sub, f"{path}|oneOf[{i}]")


def validate(instance, schema: dict, path: str = "$"):
    _assert_supported(schema, path)

    # type
    if "type" in schema:
        if not _type_match(instance, schema["type"]):
            raise AssertionError(f"{path}: type mismatch: got {type(instance).__name__} {instance!r} expected {schema['type']}")
        # null is terminal for union types: skip other keywords
        if instance is None:
            return

    # const
    if "const" in schema:
        if instance != schema["const"]:
            raise AssertionError(f"{path}: const mismatch {instance!r} != {schema['const']!r}")

    # enum
    if "enum" in schema:
        if instance not in schema["enum"]:
            raise AssertionError(f"{path}: not in enum {schema['enum']}: {instance!r}")

    # string keywords
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise AssertionError(f"{path}: minLength {schema['minLength']} violated: {instance!r}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise AssertionError(f"{path}: maxLength {schema['maxLength']} violated: {instance!r}")
        if "pattern" in schema:
            if not re.search(schema["pattern"], instance):
                raise AssertionError(f"{path}: pattern {schema['pattern']} mismatch: {instance!r}")
        if "format" in schema:
            _check_format(instance, schema["format"], path)

    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise AssertionError(f"{path}: minimum {schema['minimum']} violated: {instance}")

    # array
    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            validate(item, schema["items"], f"{path}[{i}]")

    # oneOf: exactly one branch must validate
    if "oneOf" in schema:
        matched = [i for i, sub in enumerate(schema["oneOf"]) if _matches(instance, sub)]
        if len(matched) != 1:
            raise AssertionError(
                f"{path}: oneOf matched {len(matched)} of {len(schema['oneOf'])} "
                f"branches (need exactly 1): {instance!r}"[:400]
            )

    # object
    if isinstance(instance, dict):
        if "required" in schema:
            for key in schema["required"]:
                if key not in instance:
                    raise AssertionError(f"{path}: missing required key '{key}'")
        if "properties" in schema:
            for key, subschema in schema["properties"].items():
                if key in instance:
                    validate(instance[key], subschema, f"{path}.{key}")
        if schema.get("additionalProperties") is False:
            # A key with no `properties` entry is additional, even when it
            # appears in `required` - matching JSON Schema semantics.
            allowed = set(schema.get("properties", {}))
            for key in instance:
                if key not in allowed:
                    raise AssertionError(f"{path}: additional property '{key}' not allowed")
        elif isinstance(schema.get("additionalProperties"), dict):
            for key, val in instance.items():
                if key not in schema.get("properties", {}):
                    validate(val, schema["additionalProperties"], f"{path}.{key}")
