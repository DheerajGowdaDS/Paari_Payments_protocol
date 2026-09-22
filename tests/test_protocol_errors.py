from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_unknown_protocol_version_returns_structured_error():
    r = client.post("/v1/agents/register", json={"envelope": {"version": "9.9"}})
    assert r.status_code == 400
    body = r.json()
    assert "code" in body
    assert body["code"] == "UNSUPPORTED_PROTOCOL_VERSION"


def test_error_response_has_required_fields(paari_client):
    ctx = paari_client
    r = ctx.client.post("/v1/agents/register", json={"envelope": {"version": "1.0", "protocol": "paari", "payload": {}}})
    assert r.status_code == 401
    body = r.json()
    assert "code" in body
    assert "detail" in body
    assert "request_id" in body
    assert body["code"] == "ENVELOPE_SIGNATURE_INVALID"
