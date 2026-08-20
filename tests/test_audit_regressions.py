from pathlib import Path

from sqlalchemy import create_engine, inspect, text

from app import database
from app.main import _settle_and_confirm
from app.models import Merchant, PaymentIntent
from app.wema import TransferResult, STATE_FAILED


ROOT = Path(__file__).parents[1]


def test_customer_and_merchant_templates_have_runtime_contract():
    required = {
        "customer.html": ["auth", "verify", "console", "pattern", "tokenPanel", "incomingList", "transferBtn"],
        "merchant.html": ["auth", "verify", "merchantConsole", "onboard", "summary", "connect", "createIntent", "intents"],
    }
    for filename, ids in required.items():
        html = (ROOT / "app" / "templates" / filename).read_text(encoding="utf-8")
        assert '/static/app.js' in html
        assert "moncTheme" in html
        for element_id in ids:
            assert f'id="{element_id}"' in html


def test_existing_sqlite_schema_is_upgraded_without_dropping_data(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE merchants (id VARCHAR(36) PRIMARY KEY, business_name VARCHAR(160))"))
        connection.execute(text("CREATE TABLE payment_intents (id VARCHAR(36) PRIMARY KEY, status VARCHAR(20))"))
        connection.execute(text("INSERT INTO merchants (id, business_name) VALUES ('m1', 'Existing Merchant')"))
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database, "DATABASE_URL", f"sqlite:///{tmp_path / 'old.db'}")
    database.upgrade_existing_schema()
    inspector = inspect(engine)
    merchant_columns = {column["name"] for column in inspector.get_columns("merchants")}
    intent_columns = {column["name"] for column in inspector.get_columns("payment_intents")}
    assert "settlement_account_number" in merchant_columns
    assert {"wema_state", "merchant_credited", "state_reason", "settlement_reference"} <= intent_columns
    with engine.connect() as connection:
        assert connection.execute(text("SELECT business_name FROM merchants WHERE id='m1'" )).scalar_one() == "Existing Merchant"


class FailedFundingGateway:
    mode = "test"

    def fund_wallet(self, *args, **kwargs):
        return TransferResult(False, STATE_FAILED, None, "Funding rejected")

    def confirm_transfer_status(self, *args, **kwargs):
        raise AssertionError("failed funding must not be confirmed")


def test_failed_funding_never_records_settlement_or_credits_merchant(client):
    from app.database import SessionLocal

    with SessionLocal() as db:
        merchant = Merchant(
            id="m-failed", owner_id=1, business_name="Failure Test", merchant_type="test", city="Lagos",
            country="NG", account_number_masked="******6789", settlement_account_number="0123456789",
            account_fingerprint="fp-failed", account_name="Failure Test", account_verified=True,
            api_key_hash="key-failed", credit_balance_minor=0,
        )
        intent = PaymentIntent(
            id="i-failed", merchant_id=merchant.id, order_id="ORDER-FAIL", amount_minor=10000,
            currency="NGN", product_name="Test", product_type="food", checkout_domain="example.test",
            initiator_type="human", status="debited", context_hash="ctx",
            expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        db.add_all([merchant, intent])
        db.commit()
        result = _settle_and_confirm(db, FailedFundingGateway(), intent, merchant)
        assert not result.successful
        assert intent.status == STATE_FAILED
        assert intent.settlement_reference is None
        assert merchant.credit_balance_minor == 0
        assert not intent.merchant_credited
