"""Small, dependency-light reference client for Paari Protocol v1.0."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .crypto import build_envelope, build_request_proof, fingerprint, verify_paari_card


class PaariProtocolError(RuntimeError):
    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Paari request failed ({status_code}): {detail}")


@dataclass
class PaariAgentClient:
    base_url: str
    private_key_pem: str
    public_key_pem: str
    http: httpx.Client | None = None

    def __post_init__(self):
        self.base_url = self.base_url.rstrip("/")
        self.http = self.http or httpx.Client(base_url=self.base_url, timeout=30.0)
        self.agent_id: str | None = None
        self.credential_jwt: str | None = None
        self.session_token: str | None = None
        self.card: dict[str, Any] | None = None

    @property
    def agent_fingerprint(self) -> str:
        return fingerprint(self.public_key_pem)

    def _request(self, method: str, path: str, *, json: dict | None = None,
                 auth: bool = False) -> httpx.Response:
        headers: dict[str, str] = {}
        if auth:
            if not self.session_token or not self.agent_id:
                raise PaariProtocolError(401, "client is not authenticated")
            headers["Authorization"] = f"Bearer {self.session_token}"
            headers["X-Paari-Proof"] = build_request_proof(
                self.private_key_pem,
                agent_id=self.agent_id,
                access_token=self.session_token,
                method=method,
                path=path,
            )
        response = self.http.request(method, path, json=json, headers=headers)
        if response.status_code >= 400:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            raise PaariProtocolError(response.status_code, detail)
        return response

    def discover(self) -> dict[str, Any]:
        return self._request("GET", "/.well-known/paari").json()

    def register(self, *, name: str, agent_type: str, purpose: str,
                 delegation: dict[str, Any], delegation_signature_b64: str) -> dict[str, Any]:
        payload = {
            "name": name,
            "agent_type": agent_type,
            "purpose": purpose,
            "public_key_pem": self.public_key_pem,
            "delegation": delegation,
            "delegation_signature_b64": delegation_signature_b64,
        }
        envelope = build_envelope(
            self.private_key_pem,
            sender=self.agent_fingerprint,
            message_type="agent.register",
            payload=payload,
        )
        data = self._request("POST", "/v1/agents/register", json={"envelope": envelope}).json()
        self.agent_id = data["agent_card"]["agent_id"]
        self.credential_jwt = data["credential_jwt"]
        self.card = data["agent_card"]
        if not verify_paari_card(self.card):
            raise PaariProtocolError(502, "Paari returned an Agent Card with an invalid signature")
        return data

    def get_card(self) -> dict[str, Any]:
        if not self.agent_id:
            raise PaariProtocolError(400, "register first")
        card = self._request("GET", f"/v1/agents/{self.agent_id}/card").json()
        if not verify_paari_card(card):
            raise PaariProtocolError(502, "Agent Card signature verification failed")
        self.card = card
        return card

    def authenticate(self) -> dict[str, Any]:
        if not self.agent_id or not self.credential_jwt:
            raise PaariProtocolError(400, "register first")
        challenge = self._request("POST", "/v1/auth/challenge", json={"agent_id": self.agent_id}).json()
        from .crypto import sign_text
        verified = self._request(
            "POST", "/v1/auth/verify",
            json={
                "agent_id": self.agent_id,
                "nonce": challenge["nonce"],
                "signature_b64": sign_text(self.private_key_pem, challenge["nonce"]),
                "credential_jwt": self.credential_jwt,
            },
        ).json()
        self.session_token = verified["session_token"]
        return verified

    def payment_intent(self, *, transaction_id: str, idempotency_key: str,
                       merchant: str, amount_minor_units: int, currency: str,
                       action: str = "make_payment", purpose: str = "") -> dict[str, Any]:
        if not self.agent_id:
            raise PaariProtocolError(400, "register first")
        return self._request(
            "POST", "/v1/payments/intent",
            auth=True,
            json={
                "agent_id": self.agent_id,
                "transaction_id": transaction_id,
                "idempotency_key": idempotency_key,
                "merchant": merchant,
                "amount_minor_units": amount_minor_units,
                "currency": currency,
                "action": action,
                "purpose": purpose,
            },
        ).json()

    def consume(self, authorization_id: str) -> dict[str, Any]:
        path = f"/v1/payments/authorizations/{authorization_id}/consume"
        return self._request("POST", path, auth=True, json={}).json()

    def reconcile(self, authorization_id: str) -> dict[str, Any]:
        path = f"/v1/reconcile/{authorization_id}"
        return self._request("POST", path, auth=True, json={}).json()

    def revoke_authorization(self, authorization_id: str) -> dict[str, Any]:
        path = f"/v1/authorizations/{authorization_id}/revoke"
        return self._request("POST", path, auth=True, json={}).json()

    def proof_bundle(self, transaction_id: str) -> dict[str, Any]:
        """Read-only stage-output proof bundle for one payment request."""
        path = f"/v1/proof/{transaction_id}"
        return self._request("GET", path, auth=True).json()
