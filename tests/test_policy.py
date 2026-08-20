from datetime import datetime, timezone

from app.policy import compile_rules, evaluate


def test_compiled_policy_allows_matching_transaction():
    policy = compile_rules([
        "Only allow food and transport purchases",
        "Maximum NGN 10,000 per transaction",
        "Only allow transactions in Lagos",
        "No purchases after 10 PM",
    ])
    result = evaluate(
        policy,
        {
            "amount_minor": 450_000,
            "product_name": "Lunch",
            "product_type": "food",
            "city": "Lagos Island",
            "merchant_verified": True,
            "recurring": False,
        },
        datetime(2026, 8, 18, 13, tzinfo=timezone.utc),
    )
    assert result.allowed


def test_compiled_policy_denies_wrong_product_and_amount():
    policy = compile_rules([
        "Only allow food and transport purchases",
        "Maximum NGN 10,000 per transaction",
    ])
    result = evaluate(
        policy,
        {
            "amount_minor": 1_500_000,
            "product_name": "Headphones",
            "product_type": "electronics",
            "city": "Lagos",
            "merchant_verified": True,
            "recurring": False,
        },
        datetime(2026, 8, 18, 13, tzinfo=timezone.utc),
    )
    assert not result.allowed
    assert len(result.failed_rules) == 2


def test_unknown_rule_fails_closed():
    policy = compile_rules(["Only buy things that feel sensible"])
    result = evaluate(
        policy,
        {
            "amount_minor": 100,
            "product_name": "Water",
            "product_type": "food",
            "city": "Lagos",
            "merchant_verified": True,
            "recurring": False,
        },
        datetime.now(timezone.utc),
    )
    assert not result.allowed
    assert result.failed_rules == ["Only buy things that feel sensible"]
