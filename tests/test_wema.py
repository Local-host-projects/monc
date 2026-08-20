import pytest

from app.wema import (
    AlatWemaGateway,
    SandboxWemaGateway,
    STATE_CUSTOMER_ACTION,
    STATE_FAILED,
    STATE_SUCCESSFUL,
    STATE_UNKNOWN,
    get_wema_gateway,
    normalize_wema_state,
    SANDBOX_CONSENTS,
    SANDBOX_HISTORY,
    SANDBOX_TRANSFERS,
)


def test_normalize_maps_wema_statuses_to_monc_vocabulary():
    assert normalize_wema_state("SUCCESSFUL") == STATE_SUCCESSFUL
    assert normalize_wema_state("00") == STATE_SUCCESSFUL
    assert normalize_wema_state("customer_action_required") == STATE_CUSTOMER_ACTION
    assert normalize_wema_state("pending") == "processing"
    assert normalize_wema_state("reversed") == "reversed"
    assert normalize_wema_state("failed") == STATE_FAILED
    assert normalize_wema_state("") == STATE_UNKNOWN


def test_default_gateway_is_deterministic_sandbox(monkeypatch):
    monkeypatch.delenv("MONC_WEMA_MODE", raising=False)
    assert get_wema_gateway().mode == "sandbox"


def test_alat_gateway_requires_subscription_key(monkeypatch):
    monkeypatch.delenv("WEMA_SUBSCRIPTION_KEY", raising=False)
    monkeypatch.setenv("MONC_WEMA_MODE", "playground")
    with pytest.raises(RuntimeError, match="WEMA_SUBSCRIPTION_KEY"):
        get_wema_gateway()


def test_sandbox_consent_lifecycle_reaches_successful():
    gateway = SandboxWemaGateway()
    result = gateway.initiate_consent("0123456789", 450000, "intent-1", "MONC unit test")
    assert result.state == STATE_CUSTOMER_ACTION
    assert result.demo_code and len(result.demo_code) == 6

    approved = gateway.approve_consent(result.reference, result.demo_code)
    assert approved.state == STATE_SUCCESSFUL

    settled = gateway.fund_wallet("9876543210", 450000, "intent-1-set", "MONC settlement")
    assert settled.successful
    assert settled.platform_reference

    confirmed = gateway.confirm_transfer_status("intent-1-set")
    assert confirmed.successful
    assert confirmed.state == STATE_SUCCESSFUL


def test_sandbox_approve_rejects_wrong_code():
    gateway = SandboxWemaGateway()
    result = gateway.initiate_consent("0123456789", 100, "intent-2", "wrong code")
    approved = gateway.approve_consent(result.reference, "000000")
    assert approved.state == STATE_FAILED


def test_sandbox_merchant_settlement_and_reconciliation():
    gateway = SandboxWemaGateway()
    gateway.initiate_consent("0123456789", 450000, "intent-3", "reconcile me")
    gateway.fund_wallet("9876543210", 450000, "intent-3-set", "MONC reconciliation test")
    history = gateway.transaction_history("9876543210", keyword="intent-3-set")
    assert any(h["type"] == "fund_wallet" for h in history)
    rec = gateway.reconcile("9876543210", keyword="intent-3-set")
    assert rec.matched


def test_alat_account_name_enquiry_with_mock_transport(monkeypatch):
    import httpx
    import json

    monkeypatch.setenv("WEMA_SUBSCRIPTION_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Ocp-Apim-Subscription-Key") == "test-key"
        if "/Wallet/" in request.url.path:
            return httpx.Response(200, json={
                "result": {"accountName": "MONC BUSINESS 1234", "accountNumber": "0123456789"},
                "hasError": False,
                "errorMessage": None,
                "timeGenerated": "2026-08-19T00:00:00Z",
            })
        raise AssertionError(f"unexpected call: {request.url}")

    transport = httpx.MockTransport(handler)
    gateway = AlatWemaGateway(mode="playground", transport=transport)
    gateway.account_api_key = "k"
    result = gateway.account_name_enquiry("0123456789")
    assert result.valid
    assert result.account_name == "MONC BUSINESS 1234"


def test_alat_consent_and_status_with_mock_transport(monkeypatch):
    import httpx

    monkeypatch.setenv("WEMA_SUBSCRIPTION_KEY", "test-key")
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and "/transfer-fund-request" in request.url.path:
            calls.append(request.url.path)
            return httpx.Response(200, json={
                "result": {"message": "Transaction recorded", "status": "pending",
                           "transactionReference": "ref-xyz"},
                "hasError": False, "errorMessage": None,
            })
        if "/CheckTransactionStatus/" in request.url.path:
            calls.append(request.url.path)
            return httpx.Response(200, json={
                "result": {"status": "successful", "platformTransactionReference": "plat-1"},
                "hasError": False, "errorMessage": None,
            })
        raise AssertionError(f"unexpected call: {request.url}")

    gateway = AlatWemaGateway(mode="playground", transport=httpx.MockTransport(handler))
    consent = gateway.initiate_consent("0123456789", 450000, "intent-9", "MONC test")
    assert consent.state == "processing"
    assert consent.reference == "ref-xyz"
    status = gateway.check_consent_status(consent.reference)
    assert status.state == STATE_SUCCESSFUL
    assert len(calls) == 2


def test_alat_fund_wallet_has_error_fails_closed(monkeypatch):
    import httpx

    monkeypatch.setenv("WEMA_SUBSCRIPTION_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "result": None, "hasError": True,
            "errorMessage": "Insufficient funds", "errorMessages": [],
        })

    gateway = AlatWemaGateway(mode="playground", transport=httpx.MockTransport(handler))
    result = gateway.fund_wallet("9876543210", 5_000_000, "intent-set", "MONC test")
    assert not result.successful
    assert result.state == STATE_FAILED