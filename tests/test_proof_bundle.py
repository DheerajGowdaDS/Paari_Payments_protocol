from tests.conftest import make_intent
from app.proof_bundle import collect_proof_bundle


def test_bundle_contains_all_artifacts_for_decided_intent(paari_client):
    ctx = paari_client
    intent = make_intent(ctx, amount=100)
    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, intent["transaction_id"])
    finally:
        db.close()
    assert bundle["protocol"] == "paari"
    assert bundle["protocol_version"] == "1.0"
    expected = ["discovery", "parent_trust", "delegation", "agent_identity",
                "agent_card", "credential", "authentication", "payment_intent",
                "governance_decision", "bounded_authorization",
                "payment_execution", "payment_result", "audit_record",
                "revocation"]
    for key in expected:
        assert key in bundle["artifacts"], f"bundle missing {key}"
    assert bundle["artifacts"]["governance_decision"]["decision"] == intent["decision"]
    assert bundle["artifacts"]["agent_identity"]["agent_id"] == ctx.agent_id


def test_proof_endpoint_exposes_bundle(paari_client):
    from tests.conftest import make_intent

    ctx = paari_client
    intent = make_intent(ctx, amount=100)
    tx = intent["transaction_id"]
    r = ctx.client.get(f"/v1/proof/{tx}", headers={"Authorization": f"Bearer {ctx.session_token}"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["transaction_id"] == tx
    assert "artifacts" in body
    assert body["artifacts"]["governance_decision"]["merchant"] == "TestMerchant"
    # cross-agent isolation: second agent cannot fetch first agent's bundle
    agent2_id, session2, _priv2, _cred2 = ctx.register_extra_agent(suffix="proof-iso")
    r2 = ctx.client.get(f"/v1/proof/{tx}", headers={"Authorization": f"Bearer {session2}"})
    assert r2.status_code == 403, r2.text


def test_bundle_sections_satisfy_schema_required_keys(paari_client):
    import json
    import pathlib
    from tests.conftest import make_intent
    from tests._schema_validator import validate
    from app.proof_bundle import collect_proof_bundle
    ctx = paari_client
    intent = make_intent(ctx, amount=100)
    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, intent["transaction_id"])
    finally:
        db.close()
    schema_dir = pathlib.Path(__file__).resolve().parents[1] / "schemas"
    # Validate every artifact that should be present on the ALLOW path
    section_to_schema = {
        "discovery": "paari-discovery.v1.schema.json",
        "parent_trust": "paari-parent-trust.v1.schema.json",
        "delegation": "paari-delegation.v1.schema.json",
        "agent_card": "paari-agent-card.v1.schema.json",
        "governance_decision": "paari-governance-decision.v1.schema.json",
        "payment_result": "paari-payment-result.v1.schema.json",
        "audit_record": "paari-audit-record.v1.schema.json",
        "bounded_authorization": "paari-bounded-authorization.v1.schema.json",
    }
    for section, schema_name in section_to_schema.items():
        schema = json.loads((schema_dir / schema_name).read_text())
        node = bundle["artifacts"][section]
        assert node is not None, f"{section} unexpectedly null"
        validate(node, schema, path=f"$.artifacts.{section}")
    # Nullable slots must be object-or-null on ALLOW path (payment_result present, but provider_order_id may be null)
    assert bundle["artifacts"]["payment_result"]["provider_order_id"] is None or isinstance(
        bundle["artifacts"]["payment_result"]["provider_order_id"], str
    )


def test_proof_endpoint_fails_closed_for_unknown_and_ambiguous_transaction(paari_client):
    """Documented 404/409 paths of GET /v1/proof/{transaction_id} must actually hold."""
    ctx = paari_client
    headers = {"Authorization": f"Bearer {ctx.session_token}"}
    unknown = ctx.client.get("/v1/proof/TXN-never-submitted", headers=headers)
    assert unknown.status_code == 404, unknown.text

    for key in ("idem-ambiguous-a", "idem-ambiguous-b"):
        r = ctx.client.post("/payments/intent", json={
            "session_token": ctx.session_token, "transaction_id": "TXN-ambiguous",
            "idempotency_key": key, "merchant": "TestMerchant",
            "amount_minor_units": 100, "currency": "INR",
            "action": "make_payment", "purpose": "ambiguity"})
        assert r.status_code == 200, r.text
        assert r.json()["decision"] == "allow"

    ambiguous = ctx.client.get("/v1/proof/TXN-ambiguous", headers=headers)
    assert ambiguous.status_code == 409, ambiguous.text
    assert "ambiguous" in ambiguous.json()["detail"]


def test_bundle_reports_revocation_without_parent_signed_record(paari_client, monkeypatch):
    """Stage 15 must reflect an admin revocation, which writes no RevocationRecord."""
    import app.security as security
    ctx = paari_client
    monkeypatch.setattr(security, "_ADMIN_API_KEY", "bundle-test-admin")
    intent = make_intent(ctx, amount=100)
    revoked = ctx.client.post(f"/agents/{ctx.agent_id}/revoke",
                              headers={"X-Admin-Api-Key": "bundle-test-admin"})
    assert revoked.status_code == 200, revoked.text
    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, intent["transaction_id"])
    finally:
        db.close()
    artifacts = bundle["artifacts"]
    assert artifacts["revocation"]["revoked"] is True
    assert artifacts["revocation"]["revocation_id"] is None
    assert artifacts["agent_identity"]["status"] == "revoked"
    assert artifacts["authentication"]["authenticated"] is False
    assert artifacts["credential"]["status"] == "revoked"
