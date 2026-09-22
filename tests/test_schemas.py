import json
import pathlib

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

SCHEMA_DIR = pathlib.Path(__file__).resolve().parents[1] / "schemas"


def test_all_v1_schemas_are_valid_json():
    for path in SCHEMA_DIR.glob("paari-*.v1.schema.json"):
        data = json.loads(path.read_text())
        assert "$schema" in data
        assert "type" in data


def test_each_schema_has_example():
    for path in SCHEMA_DIR.glob("paari-*.v1.schema.json"):
        data = json.loads(path.read_text())
        assert "examples" in data or "example" in data, f"{path.name} missing example"


def test_discovery_endpoint_matches_schema():
    r = client.get("/.well-known/paari")
    assert r.status_code == 200
    body = r.json()
    assert "protocol" in body
    assert body["protocol"] == "paari"
    assert body["protocol_version"] == "1.0"


STAGE_SCHEMAS = [
    "paari-parent-trust.v1.schema.json",
    "paari-delegation.v1.schema.json",
    "paari-governance-decision.v1.schema.json",
    "paari-payment-result.v1.schema.json",
    "paari-audit-record.v1.schema.json",
    "paari-proof-bundle.v1.schema.json",
]

def test_stage_artifact_schemas_exist_with_required_and_example():
    for name in STAGE_SCHEMAS:
        path = SCHEMA_DIR / name
        assert path.exists(), f"missing schema {name}"
        data = json.loads(path.read_text())
        assert data["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert isinstance(data["required"], list) and len(data["required"]) > 0
        assert "examples" in data and len(data["examples"]) > 0
        example = data["examples"][0]
        for key in data["required"]:
            assert key in example, f"{name} example missing required key {key}"


def test_every_schema_stays_inside_the_supported_keyword_subset():
    """A keyword the test validator lacks must fail loudly, never be skipped."""
    from tests._schema_validator import assert_schema_supported
    for path in sorted(SCHEMA_DIR.glob("paari-*.v1.schema.json")):
        data = json.loads(path.read_text())
        assert_schema_supported(data, path.name)


def test_validator_rejects_unknown_keywords_and_enforces_bounds():
    from tests._schema_validator import validate
    for sneaky in ({"requird": ["x"]}, {"type": "string", "not": {}},
                   {"type": "string", "anyOf": []}):
        try:
            validate("x", sneaky)
        except AssertionError as exc:
            assert "unsupported JSON Schema keyword" in str(exc), str(exc)
        else:
            raise AssertionError(f"validator silently ignored {sneaky}")
    try:
        validate("x" * 130, {"type": "string", "maxLength": 100})
    except AssertionError as exc:
        assert "maxLength" in str(exc)
    else:
        raise AssertionError("maxLength was not enforced")
    # A required key absent from `properties` is still an additional property.
    try:
        validate({"a": 1, "ghost": 2}, {"type": "object", "required": ["a", "ghost"],
                                        "properties": {"a": {"type": "integer"}},
                                        "additionalProperties": False})
    except AssertionError as exc:
        assert "additional property 'ghost'" in str(exc), str(exc)
    else:
        raise AssertionError("additionalProperties:false did not reject an unlisted key")
