"""Task G2: rich health check."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_returns_env_and_db_status():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert "env" in body
    assert "database" in body
