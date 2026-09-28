"""Provider provenance: the artifact must be able to say who settled it.

A `PAID` in Paari's exportable evidence bundle used to mean "a webhook with a
verified signature arrived and moved this row". That is true and useless at the
same time: the same sentence describes a settlement Razorpay reported and one
produced by `scripts/stub_razorpay.py` on a laptop, and
`schemas/paari-payment-result.v1.schema.json` set `additionalProperties: false`,
leaving no legal place in the pinned artifact to record the difference. The
console banner that said "local stub" expires; the bundle is what an auditor, a
counterparty, or a future marketing claim quotes.

So the distinction is now a column, stamped from the adapter that actually made
the call. These tests pin the classifier that writes it, the mapping the
collector derives from it, and the two deployment mistakes that would make the
whole thing a lie: a simulator wired to a production posture, and a production
posture that treats the user mandate as optional.
"""
import pytest

from app.config import PaariEnv
from app.main import PRODUCTION_API_BASE, startup_guards
from app.proof_bundle import _settlement_source
from app.providers.razorpay import classify_environment


def _prod_config(**overrides):
    """A correctly-configured live deployment, which the guards must accept."""
    config = {
        "env": PaariEnv.PROD,
        "is_live": False,
        "mandate_required": True,
        "database_url": "postgresql+psycopg://u:p@db.example:5432/paari_live",
    }
    config.update(overrides)
    return config


@pytest.mark.parametrize("key_id,api_base,expected", [
    # A real key against the real endpoint.
    ("rzp_test_ABC123", "https://api.razorpay.com/v1", "test"),
    ("rzp_live_XYZ789", "https://api.razorpay.com/v1", "live"),
    ("rzp_test_ABC123", "https://api.razorpay.com/v1/", "test"),
    # Anything served from a non-production base is a simulation, no matter how
    # Razorpay-shaped the key looks - a stub can hand out `rzp_test_...` too.
    ("rzp_test_ABC123", "http://127.0.0.1:55999/v1", "simulated"),
    ("rzp_live_XYZ789", "https://razorpay.example", "simulated"),
    # Unclassifiable must NOT collapse into "test": an operator who forgot a
    # credential should get `unknown`, which the bundle refuses to present as a
    # provider settlement, rather than a reassuring default.
    ("some-other-key", "https://api.razorpay.com/v1", "unknown"),
    ("", "https://api.razorpay.com/v1", "unknown"),
])
def test_classifier_is_total_and_conservative(key_id, api_base, expected):
    assert classify_environment(key_id, api_base) == expected


def test_unset_base_url_means_the_production_endpoint():
    """The adapter's own default is the real API, so an unset base classifies by
    the key alone rather than falling into "simulated" by accident."""
    assert classify_environment("rzp_test_ABC", "") == "test"
    assert classify_environment("", "") == "unknown"


def test_settlement_source_mapping_never_rounds_upward():
    assert _settlement_source("test") == "provider"
    assert _settlement_source("live") == "provider"
    assert _settlement_source("simulated") == "simulator"
    assert _settlement_source("unknown") == "unattributed"
    assert _settlement_source(None) == "unattributed"
    assert _settlement_source("definitely-not-an-environment") == "unattributed"


def test_provenance_is_stamped_on_the_row_and_reaches_the_bundle(paari_client, monkeypatch):
    """End to end: consume -> the row carries an environment -> the bundle echoes
    it. A column nobody writes and an artifact nobody reads are both decoration."""
    import app.models as models
    import app.routers.payments as payments_router
    from app.proof_bundle import collect_proof_bundle
    from tests.conftest import make_intent

    stub_base = "http://127.0.0.1:5599/v1"

    class SimulatedProvider:
        """Stands in for an adapter whose orders come from the local simulator."""

        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_prov_1", "status": "created", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency}

        def provenance(self):
            key_id = "rzp_test_SIMULATEDKEY"
            return {
                "provider_environment": classify_environment(key_id, stub_base),
                "provider_key_id_prefix": key_id[:12],
                "provider_api_base": stub_base,
            }

    monkeypatch.setattr(payments_router, "get_provider", lambda: SimulatedProvider())
    body = make_intent(paari_client, suffix="provenance")
    auth_id = body["authorization"]["authorization_id"]
    r = paari_client.client.post(f"/payments/authorizations/{auth_id}/consume",
                                 json={"session_token": paari_client.session_token})
    assert r.status_code == 200, r.text

    db = paari_client.Session()
    try:
        txn = db.query(models.ProviderTransaction).filter_by(
            razorpay_order_id="order_prov_1").first()
        assert txn is not None, "the consume never created a provider row"
        assert txn.provider_environment == "simulated"
        assert txn.provider_api_base == stub_base
        # A prefix identifies which key was in play; the full key id is already
        # more than an evidence artifact needs, and secrets never belong here.
        assert txn.provider_key_id_prefix == "rzp_test_SIM"
        assert "ULATEDKEY" not in txn.provider_key_id_prefix

        # Read the artifact through the collector itself. /v1/proof additionally
        # demands a sender-constrained proof, and that is covered in
        # test_proof_bundle.py - this test is about provenance.
        result = collect_proof_bundle(db, body["transaction_id"])["artifacts"]["payment_result"]
        assert result["provider_environment"] == "simulated"
        assert result["settlement_source"] == "simulator"
        assert result["provider_api_base"] == stub_base
        # `webhook_verified` keeps its narrow, accurate meaning. Conflating it
        # with the environment would break genuinely verified webhooks.
        assert result["webhook_verified"] is False
        assert result["final_state"] == "PROVIDER_SUBMITTED"
    finally:
        db.close()


def test_simulator_can_never_back_a_production_deployment(monkeypatch):
    """`PAARI_ENV=prod` with a mistyped RAZORPAY_API_BASE would turn every local
    simulation into production evidence. Refuse at boot instead."""
    monkeypatch.setenv("RAZORPAY_API_BASE", "http://127.0.0.1:55999/v1")
    reasons = startup_guards(_prod_config())
    assert any("RAZORPAY_API_BASE" in r for r in reasons), reasons

    monkeypatch.setenv("RAZORPAY_API_BASE", PRODUCTION_API_BASE)
    assert startup_guards(_prod_config()) == []


def test_sqlite_never_backs_a_live_deployment(monkeypatch):
    monkeypatch.setenv("RAZORPAY_API_BASE", PRODUCTION_API_BASE)
    reasons = startup_guards(_prod_config(database_url="sqlite:///./paari.db"))
    assert any("PostgreSQL" in r for r in reasons), reasons


def test_production_without_the_autonomous_posture_refuses_to_boot(monkeypatch):
    """A live deployment in standard posture can authorize payments the user
    never granted - the mandate is the entire point of the product."""
    monkeypatch.setenv("RAZORPAY_API_BASE", PRODUCTION_API_BASE)
    reasons = startup_guards(_prod_config(env=PaariEnv.PROD_LIVE, mandate_required=False))
    assert any("autonomous" in r for r in reasons), reasons


def test_development_postures_are_not_blocked(monkeypatch):
    """The guard must not tax development, or people will disable it - which is
    how guards like this usually die."""
    monkeypatch.setenv("RAZORPAY_API_BASE", "http://127.0.0.1:55999/v1")
    assert startup_guards(_prod_config(env=PaariEnv.SANDBOX,
                                       database_url="sqlite:///./paari.db")) == []
    assert startup_guards(_prod_config(env=PaariEnv.TEST,
                                       database_url="sqlite:///./.phase5_test.db")) == []
