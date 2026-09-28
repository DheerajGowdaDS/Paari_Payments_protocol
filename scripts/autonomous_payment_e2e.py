"""Paari autonomous-payment protocol E2E/conformance harness.

Default mode uses the explicit in-memory reference provider. It exercises the
complete no-human-checkout protocol path without pretending that real money moved:

    signed user mandate
      -> agent delegation + authentication
      -> governance ALLOW
      -> bounded single-use authorization
      -> provider-native authorization
      -> provider capture
      -> direct provider read corroboration
      -> PAID

Use `--provider real-razorpay` only after a real provider-native server-to-server
mandate/debit contract has been enabled for the account. Normal Razorpay orders
are never treated as autonomous settlement evidence.

The real-LLM variant is `scripts/llm_agent_e2e.py --with-server --require-mandate`.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk"))

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from paari_agent import (  # noqa: E402
    PaariAgentClient,
    fingerprint,
    generate_keypair,
    sign_delegation,
)

DELEGATION_CAP = 500_000
CURRENCY = "INR"
AMOUNT = 150_000
MERCHANT = "AutonomousProofStore"
RUN = uuid.uuid4().hex[:6]
failures: list[str] = []
PROVIDER_MODE = "unknown"


def check(name: str, ok: bool, evidence) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {json.dumps(evidence, default=str)[:350]}", flush=True)
    if not ok:
        failures.append(name)
    return ok


def canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def canonical_mandate_payload(fields: dict) -> str:
    payload = {
        "purpose": "paari_user_payment_mandate",
        "mandate_version": 1,
        "mandate_id": fields["mandate_id"],
        "user_id": fields["user_id"],
        "agent_id": fields["agent_id"],
        "org_id": "default",
        "constraints": {
            "currency": fields["currency"],
            "max_per_transaction": int(fields["max_per_transaction"]),
            "max_daily_amount": int(fields["max_daily_amount"]),
            "max_per_hour": fields.get("max_per_hour"),
            "max_per_merchant_per_day": fields.get("max_per_merchant_per_day"),
            "max_category_per_day": fields.get("max_category_per_day"),
            "allowed_merchants": sorted(str(m) for m in (fields.get("allowed_merchants") or [])),
            "allowed_categories": sorted(str(c) for c in (fields.get("allowed_categories") or [])),
            "require_review_above": fields.get("require_review_above"),
        },
        "issued_at": int(datetime.fromisoformat(fields["valid_from"]).timestamp()),
        "expires_at": int(datetime.fromisoformat(fields["expires_at"]).timestamp()),
    }
    return canonical_json(payload)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def start_stack(provider_mode: str) -> tuple[str, str, list[subprocess.Popen], Path]:
    global PROVIDER_MODE
    procs: list[subprocess.Popen] = []
    db_path = ROOT / "_tmp_autonomous_e2e.db"
    if db_path.exists():
        db_path.unlink()
    admin_key = "local-dev-" + uuid.uuid4().hex[:12]
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
        "ALEMBIC_URL": f"sqlite:///{db_path.as_posix()}",
        "PAARI_ADMIN_API_KEY": admin_key,
        "PAARI_MODE": "autonomous",
        "PAARI_REQUIRE_USER_MANDATE": "1",
        "PYTHONIOENCODING": "utf-8",
    }

    if provider_mode == "reference":
        env["PAARI_AGENTIC_PROVIDER"] = (
            "app.providers.reference_autonomous:ReferenceAutonomousProvider"
        )
        actual = "reference-autonomous"
    elif provider_mode == "real-razorpay":
        env["PAARI_AGENTIC_PROVIDER"] = (
            "app.providers.razorpay_agentic:RazorpayAgenticProvider"
        )
        actual = "real-razorpay-agentic"
    else:
        raise ValueError(provider_mode)

    PROVIDER_MODE = actual
    print(f"[note] autonomous provider mode: {actual}", flush=True)

    migrated = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if migrated.returncode != 0:
        sys.exit(f"ABORT: alembic upgrade head failed\n{(migrated.stderr or '')[-1200:]}")

    port = _free_port()
    procs.append(
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
            env=env,
        )
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 45
    while time.time() < deadline:
        try:
            if httpx.get(f"{base_url}/health", timeout=2).status_code == 200:
                return base_url, admin_key, procs, db_path
        except httpx.HTTPError:
            pass
        time.sleep(1)
    for proc in procs:
        proc.terminate()
    sys.exit(f"ABORT: server never became healthy at {base_url}")


def onboard(base_url: str, admin_key: str) -> PaariAgentClient:
    parent_priv, parent_pub = generate_keypair()
    with httpx.Client(base_url=base_url, timeout=30.0) as boot:
        r = boot.post(
            "/parents/register",
            json={
                "name": f"Autonomous Parent {RUN}",
                "parent_type": "developer",
                "contact": "autonomous@example.com",
                "public_key_pem": parent_pub,
            },
        )
        r.raise_for_status()
        parent_id = r.json()["parent_id"]
        r = boot.post(f"/parents/{parent_id}/approve", headers={"X-Admin-Api-Key": admin_key})
        r.raise_for_status()

    agent_priv, agent_pub = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": parent_id,
        "agent_public_key_fingerprint": fingerprint(agent_pub),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": DELEGATION_CAP,
        "currency": CURRENCY,
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=7)).timestamp()),
    }
    client = PaariAgentClient(base_url, agent_priv, agent_pub)
    client.register(
        name=f"Autonomous Agent {RUN}",
        agent_type="shopping_assistant",
        purpose="provider-native autonomous settlement conformance",
        delegation=delegation,
        delegation_signature_b64=sign_delegation(parent_priv, delegation),
    )
    client.authenticate()
    return client


def create_signed_mandate(
    base_url: str,
    admin_key: str,
    agent_id: str,
    user_private_pem: str,
    user_public_pem: str,
    *,
    mandate_id: str,
    sign_bytes_override: str | None = None,
) -> httpx.Response:
    from paari_agent.crypto import sign_text

    now = datetime.now(timezone.utc)
    fields = {
        "mandate_id": mandate_id,
        "user_id": f"user-{RUN}",
        "agent_id": agent_id,
        "max_per_transaction": DELEGATION_CAP,
        "max_daily_amount": DELEGATION_CAP * 2,
        "max_per_hour": DELEGATION_CAP,
        "max_per_merchant_per_day": DELEGATION_CAP,
        "max_category_per_day": None,
        "currency": CURRENCY,
        "allowed_merchants": [MERCHANT],
        "allowed_categories": [],
        "require_review_above": None,
        "valid_from": now.isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "approval_reference": f"autonomous-consent-{RUN}",
    }
    canonical = sign_bytes_override or canonical_mandate_payload(fields)
    signature = sign_text(user_private_pem, canonical)
    return httpx.post(
        f"{base_url}/v1/mandates",
        json={
            **fields,
            "user_public_key_pem": user_public_pem,
            "mandate_signature_b64": signature,
            "signing_key_id": f"user-key-{RUN}",
        },
        headers={"X-Admin-Api-Key": admin_key},
        timeout=20.0,
    )



def main() -> int:
    parser = argparse.ArgumentParser(description="Paari autonomous payment protocol E2E")
    parser.add_argument(
        "--provider",
        choices=("reference", "real-razorpay"),
        default="reference",
        help="reference = no-money protocol conformance; real-razorpay = provider-native contract only",
    )
    args = parser.parse_args()

    base_url, admin_key, procs, db_path = start_stack(args.provider)
    try:
        health = httpx.get(f"{base_url}/health", timeout=5).json()
        check("0. server healthy", health.get("status") == "ok", health)
        check(
            "0b. autonomous provider capability is configured",
            health.get("autonomous_settlement") is True,
            {
                "agentic_adapter_configured": health.get("agentic_adapter_configured"),
                "autonomous_settlement": health.get("autonomous_settlement"),
            },
        )
        if failures:
            return 1

        print("\n" + "=" * 64)
        print(" Paari Autonomous Payment Protocol E2E")
        print(f" provider mode: {PROVIDER_MODE}")
        print(f" mandate mode:  {health.get('mandate_mode')}")
        print(" LLM:           deterministic")
        print(" human checkout: NO")
        print("=" * 64 + "\n", flush=True)

        client = onboard(base_url, admin_key)
        check(
            "1. agent delegated + authenticated over /v1",
            bool(client.agent_id and client.session_token),
            {"agent_id": client.agent_id},
        )

        user_priv, user_pub = generate_keypair()
        mandate = create_signed_mandate(
            base_url,
            admin_key,
            client.agent_id,
            user_priv,
            user_pub,
            mandate_id=f"UM-E2E-{RUN}",
        )
        check(
            "2. signed user mandate accepted",
            mandate.status_code == 200 and mandate.json().get("signature_valid") is True,
            mandate.json() if mandate.status_code == 200 else mandate.text,
        )
        mandate_id = mandate.json()["mandate_id"]

        forged = create_signed_mandate(
            base_url,
            admin_key,
            client.agent_id,
            user_priv,
            user_pub,
            mandate_id=f"UM-E2E-FORGED-{RUN}",
            sign_bytes_override=canonical_json({"tampered": True}),
        )
        check("3. forged mandate signature rejected", forged.status_code == 400, forged.text[:200])

        authority = client.get_active_mandate()
        check(
            "4. agent reads user payment authority",
            authority.get("signature_valid") is True and authority.get("max_per_hour") == DELEGATION_CAP,
            authority,
        )

        now = datetime.now(timezone.utc)
        expired = httpx.post(
            f"{base_url}/v1/mandates",
            json={
                "user_id": f"user-{RUN}",
                "agent_id": client.agent_id,
                "max_per_transaction": 1000,
                "max_daily_amount": 2000,
                "currency": CURRENCY,
                "valid_from": (now - timedelta(days=2)).isoformat(),
                "expires_at": (now - timedelta(days=1)).isoformat(),
            },
            headers={"X-Admin-Api-Key": admin_key},
            timeout=20,
        )
        bind_expired = httpx.post(
            f"{base_url}/v1/mandates/{expired.json()['mandate_id']}/provider-binding",
            json={
                "provider": "reference-autonomous" if args.provider == "reference" else "razorpay",
                "provider_mandate_ref": "expired-ref",
                "currency": CURRENCY,
                "max_amount_minor_units": 1000,
            },
            headers={"X-Admin-Api-Key": admin_key},
            timeout=20,
        )
        check("5. expired mandate cannot take a provider binding", bind_expired.status_code == 409,
              {"http": bind_expired.status_code})

        # The binding stores only a provider-issued reference. The reference adapter
        # uses an opaque mandate reference; a real provider must supply the actual one.
        bind = httpx.post(
            f"{base_url}/v1/mandates/{mandate_id}/provider-binding",
            json={
                "provider": "reference-autonomous" if args.provider == "reference" else "razorpay",
                "provider_mandate_ref": f"provider-mandate-{mandate_id}",
                "currency": CURRENCY,
                "max_amount_minor_units": DELEGATION_CAP,
            },
            headers={"X-Admin-Api-Key": admin_key},
            timeout=20,
        )
        check("5b. active provider mandate/instrument reference bound", bind.status_code == 200, bind.text[:250])

        causal = {
            "llm_run_id": f"RUN-{RUN}",
            "llm_model": "deterministic-harness",
            "llm_tool_call_id": f"call_{RUN}",
            "llm_tool_name": "propose_payment",
        }
        intent = client.payment_intent(
            transaction_id=f"TXN-auto-{RUN}",
            idempotency_key=f"idem-auto-{RUN}",
            merchant=MERCHANT,
            amount_minor_units=AMOUNT,
            currency=CURRENCY,
            purpose="autonomous payment protocol proof",
            **causal,
        )
        check(
            "6. governance ALLOW under signed mandate + causal ids",
            intent.get("decision") == "allow" and intent.get("mandate_id") == mandate_id,
            {"decision": intent.get("decision"), "mandate_id": intent.get("mandate_id")},
        )

        auth_id = (intent.get("authorization") or {}).get("authorization_id") or ""
        consumed = client.consume(auth_id)
        final_state = consumed.get("state")
        payment_ref = consumed.get("razorpay_payment_id") or ""
        check(
            "7. provider-native autonomous settlement -> PAID",
            consumed.get("consumed") is True and final_state == "PAID" and payment_ref.startswith("pay_"),
            {"state": final_state, "provider_payment_id": payment_ref, "order_id": consumed.get("razorpay_order_id")},
        )

        from paari_agent.client import PaariProtocolError
        try:
            client.consume(auth_id)
            replay_ok = False
            replay_detail = "replay unexpectedly accepted"
        except PaariProtocolError as exc:
            replay_ok = exc.status_code == 409
            replay_detail = str(exc.detail)
        check("8. authorization replay refused", replay_ok, {"detail": replay_detail[:160]})

        bundle = client.proof_bundle(f"TXN-auto-{RUN}")
        audit_record = (bundle.get("artifacts") or {}).get("audit_record") or {}
        events = audit_record.get("events") or []
        kinds = [e.get("event_type") or e.get("kind") for e in events]
        expected_tail = ["authorization_consumed", "provider_submitted", "agentic_settlement"]
        check(
            "9. audit chain verified through PAID",
            bool(audit_record.get("chain_verified"))
            and kinds[:2] == ["llm_tool_call", "intent_decided"]
            and all(kind in kinds for kind in expected_tail)
            and kinds[-1] == "agentic_settlement",
            {"chain_verified": audit_record.get("chain_verified"), "kinds": kinds},
        )

        result = (bundle.get("artifacts") or {}).get("payment_result") or {}
        check(
            "10. payment-result evidence is self-describing",
            result.get("final_state") == "PAID"
            and result.get("settlement_source") in {"simulator", "provider"},
            result,
        )
        check(
            "11. agent/SDK expose no raw capture or payment-instrument path",
            not hasattr(client, "capture")
            and not hasattr(client, "capture_payment"),
            {"sdk_methods": [m for m in dir(client) if not m.startswith("_") and callable(getattr(client, m))]},
        )

        print("\nPaari Autonomous Payment Protocol E2E", flush=True)
        print("─" * 76, flush=True)
        print(f"PROVIDER MODE       {PROVIDER_MODE}")
        print(f"MANDATE             Ed25519 signed + active")
        print(f"GOVERNANCE          ALLOW")
        print(f"AUTHORIZATION       single-use bounded")
        print(f"PROVIDER PAYMENT    {result.get('provider_payment_id', payment_ref)}")
        print(f"SETTLEMENT SOURCE   {result.get('settlement_source')}")
        print(f"FINAL STATE         {result.get('final_state')}")
        print(f"HUMAN CHECKOUT      NO")
        print("─" * 76, flush=True)
        if args.provider == "reference":
            print("REFERENCE MODE: protocol-only in-memory settlement; NO REAL MONEY MOVED.", flush=True)
        else:
            print("REAL PROVIDER MODE: this result is valid only because the provider-native contract returned corroborated capture.", flush=True)

        verdict = (
            "AUTONOMOUS PAYMENT PROTOCOL E2E GREEN: PAID without human checkout"
            if not failures
            else f"AUTONOMOUS PAYMENT PROTOCOL E2E RED: {failures}"
        )
        print(f"\n{verdict}", flush=True)
        return 0 if not failures else 1
    finally:
        for proc in reversed(procs):
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        if db_path.exists():
            db_path.unlink()


if __name__ == "__main__":
    sys.exit(main())
