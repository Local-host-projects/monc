"""MONC verification harness (CLI).

Runs the live verification pipeline against authoritative sources and prints a
readable report. Demonstrates the tenet: minimize data entry, collect from the
most definitive source. Failing sources fail closed.

Usage:
    python scripts/verify_harness.py [--account 0123456789] [--city lagos] [--amount 450000]
    python scripts/verify_harness.py --fail-source    # simulate a source outage -> fail closed
"""
import argparse
import os

os.environ.setdefault("MONC_WEMA_MODE", "sandbox")
os.environ.setdefault("MONC_DATABASE_URL", "sqlite://")

from datetime import datetime, timedelta, timezone

from app.models import Merchant, PaymentIntent
from app.verification import SOURCE_NAMES, live_check_for
from app.wema import SandboxWemaGateway


class BrokenGateway(SandboxWemaGateway):
    def verify_account(self, account_number):
        raise RuntimeError("network unreachable to Wema")


def build_sample(account: str, city: str, amount: int, broken: bool = False):
    gateway = BrokenGateway() if broken else SandboxWemaGateway()
    enquiry = gateway.verify_account(account)
    merchant = Merchant(
        id="harness", owner_id=0, business_name="Example Foods", merchant_type="restaurant",
        city=city or enquiry.city, country="NG", account_number_masked="******" + account[-4:],
        settlement_account_number=account, account_fingerprint="harness",
        account_name=enquiry.account_name, account_verified=True, api_key_hash="harness",
    )
    intent = PaymentIntent(
        id="harness-intent", merchant_id="harness", order_id="DEMO-1", amount_minor=amount, currency="NGN",
        product_name="University textbook", product_type="education", checkout_domain="shop.example.ng",
        initiator_type="human", context_hash="harness",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    return intent, merchant, gateway


def render(title: str, report: list[dict]):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)
    for check in report:
        icon = "PASS" if check["verified"] else ("WARN" if not check["decisive"] else "FAIL")
        print(f"[{icon:>4}] {check['condition']:<20} source={check['source']}")
        print(f"        claimed={check['claimed']!r}  observed={check['observed']!r}")
        print(f"        {check['note']}")
    verdict = "ALLOW (every decisive condition verified)" if all(
        c["verified"] for c in report if c["decisive"]
    ) else "FAIL CLOSED (a decisive condition could not be verified)"
    print("-" * 72)
    print(f"Verdict: {verdict}")
    print()
    print("Sources:")
    for key, note in SOURCE_NAMES.items():
        print(f"  - {key}: {note}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", default="0123456789", help="settlement account to check")
    parser.add_argument("--city", default="", help="claimed city (leave empty to take it from the source)")
    parser.add_argument("--amount", type=int, default=450000, help="amount in minor units (kobo)")
    parser.add_argument("--fail-source", action="store_true", help="simulate a source outage -> fail closed")
    args = parser.parse_args()

    intent, merchant, gateway = build_sample(args.account, args.city, args.amount, broken=args.fail_source)
    if args.city and not args.fail_source:
        title = f"Harness: claimed city '{args.city}' vs source"
    elif args.fail_source:
        title = "Harness: source outage (verify_account raises) -> must fail closed"
    else:
        title = f"Harness: account {args.account}, city taken from source {merchant.city!r}"
    report = live_check_for(intent, merchant, gateway=gateway)
    render(title, report)


if __name__ == "__main__":
    main()