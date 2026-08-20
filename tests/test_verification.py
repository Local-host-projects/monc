from datetime import datetime, timedelta, timezone

from app.models import Merchant, PaymentIntent
from app.verification import live_check_for, report_for, unverified_conditions
from app.wema import SandboxWemaGateway


class BrokenGateway(SandboxWemaGateway):
    def verify_account(self, account_number):
        raise RuntimeError("network unreachable to Wema")


def sample(account: str = "0123456789", city: str = "", gateway=None):
    gw = gateway or SandboxWemaGateway()
    try:
        enquiry = gw.verify_account(account)
    except Exception:
        enquiry = None
    merchant = Merchant(
        id="harness", owner_id=0, business_name="Example Foods", merchant_type="restaurant",
        city=city or (enquiry.city if enquiry else "lagos"), country="NG",
        account_number_masked="******" + account[-4:],
        settlement_account_number=account, account_fingerprint="harness",
        account_name=(enquiry.account_name if enquiry else "Example Foods"),
        account_verified=True, api_key_hash="harness",
    )
    intent = PaymentIntent(
        id="harness-intent", merchant_id="harness", order_id="DEMO-1", amount_minor=450000, currency="NGN",
        product_name="University textbook", product_type="education", checkout_domain="shop.example.ng",
        initiator_type="human", context_hash="harness",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    return intent, merchant


def decisive_conditions(results):
    return {c["condition"] for c in results if c.get("decisive")}


def test_harness_verifies_everything_when_city_comes_from_source():
    intent, merchant = sample()
    results = live_check_for(intent, merchant)
    assert "merchant_verified" in decisive_conditions(results)
    assert "city" in decisive_conditions(results)
    assert all(c["verified"] for c in results if c["decisive"])
    assert unverified_conditions(results) == []
    assert report_for(intent, merchant)["all_verified"] is True


def test_harness_fails_closed_when_claimed_city_contradicts_source():
    wrong_city = "yola"
    intent, merchant = sample(city=wrong_city)
    results = live_check_for(intent, merchant)
    city_check = next(c for c in results if c["condition"] == "city")
    assert city_check["observed"] != wrong_city
    assert city_check["verified"] is False
    assert {c["condition"] for c in unverified_conditions(results)} == {"city"}


def test_harness_fails_closed_when_source_is_unreachable():
    broken = BrokenGateway()
    intent, merchant = sample(gateway=broken)
    results = live_check_for(intent, merchant, gateway=broken)
    unverified = unverified_conditions(results)
    assert {c["condition"] for c in unverified} == {"merchant_verified", "city"}


def test_merchant_lookup_minimizes_entry(client):
    from tests.conftest import register_verified

    register_verified(client, "lookup@example.com", "Lookup User")
    r = client.get("/api/merchants/lookup?account=0123456789")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["account_name"].startswith("MONC SANDBOX")
    assert data["city"]
    assert data["source"] == "wema.account_enquiry"


def test_verify_run_endpoint_sandbox_sample(client):
    from tests.conftest import register_verified

    register_verified(client, "harness@example.com", "Harness User")
    r = client.post("/api/verify/run", json={})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["all_verified"] is True
    assert data["checks"]
    assert data["sources"]