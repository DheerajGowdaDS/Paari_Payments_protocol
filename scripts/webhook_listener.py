"""Webhook-only listener for proving a REAL provider webhook end to end.

Why this exists as a separate process
-------------------------------------
Closing Phase 6 properly means letting Razorpay itself POST to a URL it can
reach, so that "webhook verified" describes a delivery the provider made rather
than one we signed ourselves. That requires exposing an endpoint to the public
internet, and the full application is the wrong thing to expose: it also serves
agent registration, parent approval, mandate creation, consume, reconcile and
the admin-gated surface. A temporary tunnel is exactly when an attacker looks.

So this app mounts ONE route - the Razorpay webhook handler, the same function
the real server uses - plus a liveness probe. Nothing else is reachable, because
nothing else is registered. It shares the same database as the main app, so a
delivery it accepts moves the same `ProviderTransaction` rows the payment flow
created, and the resulting `PAID` is the real thing.

It refuses to start without `RAZORPAY_WEBHOOK_SECRET`. Without that value every
delivery would fail verification anyway, and a listener that silently accepts
nothing is worse than one that says why it will not run.

    python scripts/webhook_listener.py --port 8000
    cloudflared tunnel --url http://127.0.0.1:8000   # keep the printed URL

Tear the tunnel down when the test is over. This is a test fixture, not a
deployment topology.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Depends, FastAPI, Header, Request  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.database import get_db  # noqa: E402

WEBHOOK_PATH = "/v1/payments/webhooks/razorpay"


def create_app() -> FastAPI:
    app = FastAPI(title="Paari webhook listener", version="test-fixture")

    @app.get("/health")
    def health():
        # Deliberately minimal: confirms reachability through the tunnel without
        # disclosing posture, provider identity, or database state to the public.
        return {"service": "paari-webhook-listener", "webhook_path": WEBHOOK_PATH}

    @app.post(WEBHOOK_PATH)
    # `Header(...)` is load-bearing: annotated as a bare default, FastAPI binds
    # x_razorpay_signature as a QUERY parameter, the real header is never read,
    # and every delivery fails verification - which looks identical to a secure
    # endpoint that is rejecting forgeries. Caught by testing a correctly signed
    # delivery, not a wrongly signed one.
    def webhook(request: Request,
                x_razorpay_signature: str = Header(default="", alias="X-Razorpay-Signature"),
                db: Session = Depends(get_db)):
        from app.routers.payments import razorpay_webhook
        return razorpay_webhook(request=request,
                                x_razorpay_signature=x_razorpay_signature, db=db)

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    if not secret:
        print("ABORT: RAZORPAY_WEBHOOK_SECRET is not set.\n"
              "       Copy the secret from the Razorpay dashboard's webhook "
              "configuration into the environment first - with no secret every "
              "delivery is rejected, and the test would prove nothing.", flush=True)
        return 2

    import uvicorn
    print(f"Paari webhook listener on http://{args.host}:{args.port}{WEBHOOK_PATH}",
          flush=True)
    print("  Exposed routes: /health, " + WEBHOOK_PATH + "  (nothing else)", flush=True)
    print("  Webhook secret: configured (len=" + str(len(secret)) + ")", flush=True)
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
