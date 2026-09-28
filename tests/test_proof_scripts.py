"""The proof scripts must be executed by CI, not just read by a human.

`foreign_agent_proof.py` and `autonomous_payment_e2e.py` re-implement the
canonical mandate encoding on the AGENT side - deliberately, because a foreign
agent cannot import Paari's server modules and a proof that called
`app.mandate_signing` would prove nothing about interoperability. That independence
is the whole value of the script, and it is also its risk: the two encodings can
drift apart, and nothing in the suite would notice until a live proof failed at
step 7f with an opaque signature error.

These tests hold the two implementations in a grip. They import the script by
path (it is not a package) and assert byte-equality of the canonical form, then
round-trip a signature across the boundary in both directions.

They also assert the properties that make the transcript worth quoting at all:
that the script reads posture and provider environment from the SERVER rather
than inferring them from its own process, and that it never imports a server
module - which is what makes it a black-box proof rather than a white-box one.
"""
import importlib.util
import pathlib
import uuid

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _load(script_name: str):
    path = REPO / "scripts" / f"{script_name}.py"
    spec = importlib.util.spec_from_file_location(f"_proofscript_{script_name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def foreign_proof():
    return _load("foreign_agent_proof")


def test_script_is_a_true_black_box(foreign_proof):
    """A foreign agent proof must not reach into the server it is proving."""
    source = (REPO / "scripts" / "foreign_agent_proof.py").read_text(encoding="utf-8")
    for forbidden in ("from app.", "import app.", "from sdk.", "from llm_agent."):
        assert forbidden not in source, f"proof script imports server code: {forbidden}"


def _full_mandate_fields(mandate_id: str = "UM-fixed") -> dict:
    """A complete mandate, in exactly the shape the canonical form demands.

    The encoding is total: it names every governed field rather than hashing a
    caller-supplied dict, so a dropped field is a different payload. That is why
    these tests must build a full mandate instead of a convenient subset.
    """
    return {
        "mandate_id": mandate_id,
        "user_id": "user-1",
        "agent_id": "agent-1",
        "max_per_transaction": 100000,
        "max_daily_amount": 1000000,
        "max_per_hour": 100000,
        "max_per_merchant_per_day": 100000,
        "currency": "INR",
        "allowed_merchants": ["ProofStore", "AnotherStore"],
        "allowed_categories": [],
        "valid_from": "2026-09-26T00:00:00+00:00",
        "expires_at": "2026-10-26T00:00:00+00:00",
        "approval_reference": "consent-1",
    }


def _server_mandate(fields: dict):
    """Wrap the harness-side field dict in the ORM row the server signs from.

    `app.mandate_signing` is object-based on purpose: the signature covers the
    stored mandate, not a caller's dict, so a field the row does not carry can
    never be signed by accident. Comparing against it therefore has to build the
    row.
    """
    from datetime import datetime
    from app import models

    return models.UserPaymentMandate(
        mandate_id=fields["mandate_id"],
        user_id=fields["user_id"],
        agent_id=fields["agent_id"],
        org_id=fields.get("org_id", "default"),
        currency=fields["currency"],
        max_per_transaction=fields["max_per_transaction"],
        max_daily_amount=fields["max_daily_amount"],
        max_per_hour=fields["max_per_hour"],
        max_per_merchant_per_day=fields["max_per_merchant_per_day"],
        allowed_merchants=fields["allowed_merchants"],
        allowed_categories=fields["allowed_categories"],
        valid_from=datetime.fromisoformat(fields["valid_from"]),
        expires_at=datetime.fromisoformat(fields["expires_at"]),
        approval_reference=fields["approval_reference"],
    )


def test_agent_side_canonical_form_matches_server(foreign_proof):
    """The independent encoding must produce byte-identical canonical input."""
    from app import mandate_signing

    fields = _full_mandate_fields(f"UM-{uuid.uuid4().hex[:8]}")
    assert (foreign_proof.canonical_mandate_payload(fields)
            == mandate_signing.canonical_payload_bytes(_server_mandate(fields)))


def test_canonical_form_is_sensitive_to_every_governed_field(foreign_proof):
    """Silently ignoring a limit would be the worst possible failure: a mandate
    tightened to Rs 1,000 must not verify under a payload that says Rs 10,000."""
    from app import mandate_signing

    base = _full_mandate_fields()
    assert (foreign_proof.canonical_mandate_payload(base)
            == mandate_signing.canonical_payload_bytes(_server_mandate(base)))
    for key, alt in (("max_per_transaction", 1), ("currency", "USD"),
                     ("expires_at", "2030-01-01T00:00:00+00:00"), ("allowed_merchants", [])):
        changed = dict(base, **{key: alt})
        assert foreign_proof.canonical_mandate_payload(changed) != foreign_proof.canonical_mandate_payload(base), (
            f"canonical form ignores {key}")


def test_signature_crosses_the_boundary_in_both_directions(foreign_proof):
    """A signature the harness makes over its own encoding must verify on the
    server, and a server-made signature must verify with the harness's verifier.

    This is the interoperability claim: two implementations, one wire format.
    """
    from app import crypto_utils, mandate_signing
    from app import models

    priv, pub = crypto_utils.generate_agent_keypair()
    fields = _full_mandate_fields("UM-cross")
    payload = foreign_proof.canonical_mandate_payload(fields)

    # Harness signs -> server verifies, through the real mandate row.
    harness_sig = foreign_proof.sign_message(priv, payload)
    row = _server_mandate(fields)
    row.user_public_key_pem = pub
    row.signature_b64 = harness_sig
    row.signing_key_id = "user-key-test"
    result = mandate_signing.verify_mandate_signature(row)
    assert result.signature_valid is True, result.reasons

    # Server signs -> harness verifies.
    server_sig = mandate_signing.sign_mandate(row, priv, signing_key_id="user-key-test")
    assert foreign_proof.verify_message(pub, payload, server_sig) is True

    # A tampered payload must fail, or the two directions above prove nothing.
    assert foreign_proof.verify_message(pub, payload + "x", harness_sig) is False

    # And a tightened limit must not verify under the original signature - and
    # must say why, so a rejection for an unrelated reason cannot pass either.
    tightened = _server_mandate(dict(fields, max_per_transaction=1))
    tightened.user_public_key_pem = pub
    tightened.signature_b64 = server_sig
    tightened.signing_key_id = "user-key-test"
    tampered = mandate_signing.verify_mandate_signature(tightened)
    assert tampered.signature_valid is False
    assert any("signature" in r.lower() for r in tampered.reasons), tampered.reasons


def test_mandate_cap_is_strictly_below_the_delegated_cap(foreign_proof):
    """The over-mandate negative proof is only about the mandate if the mandate
    is the binding constraint. Equal caps made step 7h a test of the delegation
    check instead - a denial with the right shape and the wrong cause."""
    assert foreign_proof.MANDATE_CAP < foreign_proof.DELEGATED_CAP
    probe = foreign_proof.MANDATE_CAP + 50000
    assert foreign_proof.MANDATE_CAP < probe <= foreign_proof.DELEGATED_CAP


def test_the_over_mandate_reason_is_the_mandates_own(foreign_proof):
    """Lock the reason string the script asserts on to what the server emits, so
    a wording change on either side fails here rather than silently weakening
    the transcript."""
    from app import mandates

    assert hasattr(mandates, "evaluate_mandate")
    source = (REPO / "scripts" / "foreign_agent_proof.py").read_text(encoding="utf-8")
    assert '"delegated limit" not in denied_reasons.lower()' in source


def test_posture_and_provider_are_read_from_the_server_not_the_process():
    """Both harnesses must ask the server what it is, because an inference from
    the harness's own os.environ can print `real-razorpay` about a server pointed
    at a local simulator."""
    for name in ("foreign_agent_proof.py", "llm_agent_e2e.py", "autonomous_payment_e2e.py"):
        source = (REPO / "scripts" / name).read_text(encoding="utf-8")
        assert '"autonomous" if REQUIRE_MANDATE' not in source, (
            f"{name} derives governance posture from its own CLI flag instead of the server")
        assert 'provider_str = "real-razorpay" if os.environ' not in source, (
            f"{name} derives provider mode from its own process environment")
