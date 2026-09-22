"""Provider reconciliation worker for missed webhooks and unknown executions."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging import getLogger
from typing import Callable

from sqlalchemy.orm import Session, sessionmaker

from app import models
from app.database import get_engine
from app.reconcile import reconcile_one
from app.transitions import TERMINAL_STATES

logger = getLogger("paari.reconcile")


@dataclass
class ReconciliationAlertSink:
    webhook_url: str = ""

    def alert(self, event: str, authorization_id: str, org_id: str, detail: str = ""):
        msg = f"[reconcile] {event} auth={authorization_id} org={org_id} {detail}".strip()
        logger.warning(msg)
        if not self.webhook_url:
            return
        import httpx
        try:
            httpx.post(
                self.webhook_url,
                json={"event": event, "authorization_id": authorization_id, "org_id": org_id, "detail": detail},
                timeout=5.0,
            )
        except Exception:
            pass


@dataclass
class ReconciliationWorker:
    interval_seconds: int = 60
    dead_letter_after: int = 5
    alert_sink: ReconciliationAlertSink = field(default_factory=ReconciliationAlertSink)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    def start(self, db_url: str | None = None):
        engine = get_engine(db_url) if db_url else None
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(engine,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 5)

    def _loop(self, engine):
        SessionLocal = sessionmaker(bind=engine) if engine else None
        while not self._stop.is_set():
            try:
                self._run_batch(SessionLocal() if SessionLocal else None)
            except Exception:
                logger.exception("reconciliation batch failed")
            self._stop.wait(self.interval_seconds)

    def _run_batch(self, session: Session | None):
        from app.reconcile import reconcile_one as _reconcile_one
        from app.reconcile import _audit
        from app.transitions import transition_txn, IllegalTransitionError
        from app.audit import record_audit

        txns = (
            session.query(models.ProviderTransaction)
            .filter(models.ProviderTransaction.state.notin_(TERMINAL_STATES))
            .all()
        )
        for txn in txns:
            try:
                result = _reconcile_one(session, txn.authorization_id)
            except Exception as exc:
                txn.last_error = str(exc)[:2000]
                session.commit()
                continue
            if result.get("status") == "reconciled":
                continue
            txn.attempts = (txn.attempts or 0) + 1
            if txn.attempts >= self.dead_letter_after:
                try:
                    old = txn.state
                    transition_txn(txn, "PROVIDER_UNKNOWN")
                    _audit(session, txn, "reconcile_dead_letter", {
                        "from_state": old, "to_state": "PROVIDER_UNKNOWN",
                        "attempts": txn.attempts, "reason": "dead-letter: exceeded max reconcile attempts",
                    })
                except IllegalTransitionError:
                    pass
                txn.last_error = "dead-letter: exceeded max reconcile attempts"
                self.alert_sink.alert("dead_letter", txn.authorization_id, txn.org_id, txn.last_error)
            session.commit()
