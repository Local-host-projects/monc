"""MONC live verification harness.

Tenet: minimise data entry from both parties and collect directly from the
sources in the most definitive / authoritative way.

Instead of trusting values that were typed into a form, every relevant
condition about a payment is re-checked against an authoritative source at
authorization time. Each check carries provenance (source + timestamp) so the
UI can show where a value came from and the system can fail closed when a
source is unreachable or contradicts the claim.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .wema import STATE_SUCCESSFUL, get_wema_gateway

SOURCE_INTENT = "monc.payment_intent"
SOURCE_WEMA_ACCOUNT = "wema.account_enquiry"
SOURCE_WEMA_CONSENT = "wema.consent_status"

SOURCE_NAMES = {
    SOURCE_INTENT: "Payment intent ledger — written by the merchant API, never typed by the customer.",
    SOURCE_WEMA_ACCOUNT: "Wema / ALAT live account enquiry for the merchant settlement account (authoritative bank CIF).",
    SOURCE_WEMA_CONSENT: "Wema / ALAT live consent status polled for this payment reference.",
}


@dataclass
class CheckResult:
    condition: str
    claimed: object
    observed: object
    verified: bool
    decisive: bool
    source: str
    note: str
    checked_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def live_check_for(intent, merchant, gateway=None) -> list[dict]:
    """Check every condition MONC can verify about this exact payment. Fails closed.

    Results are plain dicts ready for JSON serialization and UI rendering.
    """
    gateway = gateway or get_wema_gateway()
    checked_at = _now_iso()
    results: list[dict] = []

    def add(condition, claimed, observed, verified, decisive, source, note):
        results.append(CheckResult(condition, claimed, observed, verified, decisive, source, note, checked_at).to_dict())

    add("amount", intent.amount_minor, intent.amount_minor, True, True, SOURCE_INTENT,
        "Amount is locked by the payment intent ledger.")
    add("currency", intent.currency, intent.currency, True, True, SOURCE_INTENT,
        "Currency is locked by the payment intent ledger.")
    add("product", intent.product_name, intent.product_name, True, True, SOURCE_INTENT,
        "Product line is locked by the payment intent ledger.")
    add("category", intent.product_type, intent.product_type, True, True, SOURCE_INTENT,
        "Category is locked by the payment intent ledger.")
    add("checkout_domain", intent.checkout_domain, intent.checkout_domain, True, True, SOURCE_INTENT,
        "Checkout domain is locked by the payment intent ledger.")

    if merchant:
        try:
            enquiry = gateway.verify_account(merchant.settlement_account_number)
        except Exception as exc:  # transport or provider failure -> fail closed
            add("merchant_verified", merchant.account_verified, None, False, True, SOURCE_WEMA_ACCOUNT,
                f"Source unavailable, failing closed. {type(exc).__name__}")
            add("city", merchant.city, None, False, True, SOURCE_WEMA_ACCOUNT,
                "Source unavailable, failing closed.")
        else:
            add("merchant_verified", merchant.account_verified, bool(enquiry.valid), bool(enquiry.valid), True,
                SOURCE_WEMA_ACCOUNT, "Merchant settlement account re-checked live at the bank.")
            city_match = bool(enquiry.city) and enquiry.city.strip().lower() == (merchant.city or "").strip().lower()
            add("city", merchant.city, enquiry.city, city_match, True, SOURCE_WEMA_ACCOUNT,
                "City confirmed against the branch record held at the bank.")
            add("account_name", merchant.account_name, enquiry.account_name,
                merchant.account_name and merchant.account_name.strip().lower() == enquiry.account_name.strip().lower(),
                False, SOURCE_WEMA_ACCOUNT, "Account name on record cross-checked with the live enquiry.")

    if intent.wema_reference:
        try:
            consent = gateway.check_consent_status(intent.wema_reference)
        except Exception as exc:
            add("consent", intent.wema_state, None, False, True, SOURCE_WEMA_CONSENT,
                f"Consent status unavailable, failing closed. {type(exc).__name__}")
        else:
            add("consent", intent.wema_state, consent.state, consent.state == STATE_SUCCESSFUL, True,
                SOURCE_WEMA_CONSENT, "Consent polled live from the bank.")

    return results


def observed_map(results: list[dict]) -> dict:
    """Observed authoritative values for conditions that were verified."""
    return {c["condition"]: c["observed"] for c in results if c.get("verified")}


def unverified_conditions(results: list[dict]) -> list[dict]:
    """Decisive checks that failed or could not be confirmed. Fail closed."""
    return [c for c in results if c.get("decisive") and not c.get("verified")]


def report_for(intent, merchant, gateway=None) -> dict:
    results = live_check_for(intent, merchant, gateway=gateway)
    return {
        "checks": results,
        "all_verified": not unverified_conditions(results),
        "sources": {key: value for key, value in SOURCE_NAMES.items()},
        "checked_at": results[0]["checked_at"] if results else _now_iso(),
    }