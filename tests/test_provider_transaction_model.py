def test_provider_transaction_table_exists():
    import app.models  # noqa: F401 -- registers tables on Base.metadata
    from app.database import Base
    assert "provider_transactions" in Base.metadata.tables
    cols = Base.metadata.tables["provider_transactions"].columns
    assert set(["authorization_id", "state", "razorpay_order_id"]) <= set(cols.keys())
