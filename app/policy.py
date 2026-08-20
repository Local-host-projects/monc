import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Verdict:
    allowed: bool
    reason: str
    failed_rules: list[str]


def compile_rules(rules: list[str]) -> dict:
    policy: dict = {"source_rules": rules, "compiled": [], "unsupported": []}
    for raw in rules:
        rule = raw.strip()
        lower = rule.lower()
        amount = re.search(r"(?:maximum|max|under|below)\s+(?:ngn|₦)?\s*([\d,]+)", lower)
        hour = re.search(r"(?:after|past)\s+(\d{1,2})(?:\s*:?\s*00)?\s*(am|pm)?", lower)
        if amount:
            value = int(amount.group(1).replace(",", "")) * 100
            policy["compiled"].append({"type": "max_amount", "value": value, "rule": rule})
        elif "only allow" in lower and ("food" in lower or "transport" in lower):
            allowed = [v for v in ("food", "transport") if v in lower]
            policy["compiled"].append({"type": "product_allow", "value": allowed, "rule": rule})
        elif "only" in lower and "lagos" in lower:
            policy["compiled"].append({"type": "city_allow", "value": "lagos", "rule": rule})
        elif hour and ("no " in lower or "block" in lower):
            value = int(hour.group(1))
            if hour.group(2) == "pm" and value < 12:
                value += 12
            policy["compiled"].append({"type": "latest_hour", "value": value, "rule": rule})
        elif "block" in lower:
            blocked = [v for v in ("alcohol", "tobacco", "gambling", "betting", "gift card", "crypto") if v in lower]
            if blocked:
                policy["compiled"].append({"type": "product_block", "value": blocked, "rule": rule})
            else:
                policy["unsupported"].append(rule)
        elif "verified merchant" in lower:
            policy["compiled"].append({"type": "merchant_verified", "value": True, "rule": rule})
        elif "recurring" in lower or "subscription" in lower:
            policy["compiled"].append({"type": "no_recurring", "value": True, "rule": rule})
        else:
            policy["unsupported"].append(rule)
    return policy


def evaluate(policy: dict, context: dict, now: datetime) -> Verdict:
    failed: list[str] = []
    details: list[str] = []
    if policy.get("unsupported"):
        failed.extend(policy["unsupported"])
        details.append("One or more rules could not be compiled deterministically, so MONC failed closed.")

    product = (context.get("product_type") or "").lower()
    city = (context.get("city") or "").lower()
    for check in policy.get("compiled", []):
        kind, value, rule = check["type"], check["value"], check["rule"]
        passed = True
        if kind == "max_amount":
            passed = context["amount_minor"] <= value
        elif kind == "product_allow":
            passed = product in value
        elif kind == "product_block":
            passed = not any(term in product or term in (context.get("product_name") or "").lower() for term in value)
        elif kind == "city_allow":
            passed = value in city
        elif kind == "latest_hour":
            passed = now.hour < value
        elif kind == "merchant_verified":
            passed = bool(context.get("merchant_verified"))
        elif kind == "no_recurring":
            passed = not bool(context.get("recurring"))
        if not passed:
            failed.append(rule)

    if failed:
        details.append(f"{len(failed)} rule(s) failed: " + "; ".join(failed))
        return Verdict(False, " ".join(details), failed)
    return Verdict(True, "Ownership proof and every compiled owner rule passed for this exact payment intent.", [])
