import base64
import json
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def register_verified(client, email: str, name: str) -> None:
    r = client.post("/api/auth/register", json={
        "email": email, "display_name": name, "password": "test-password-123"})
    assert r.status_code == 200, r.text
    code = r.json()["demo_verification_code"]
    r = client.post("/api/auth/verify", json={"code": code})
    assert r.status_code == 200, r.text


def jwk_from_public(key: ec.EllipticCurvePublicKey) -> dict:
    nums = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }


def sign_raw(private_key: ec.EllipticCurvePrivateKey, message: str) -> str:
    der = private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def issue_instrument(client, keypair) -> dict:
    private_key, public_key = keypair
    instrument_id = str(uuid.uuid4())
    locator = b64u(uuid.uuid4().bytes)
    r = client.post("/api/instruments", json={
        "instrument_id": instrument_id,
        "alias": "WORK SUPPLIES",
        "locator": locator,
        "encrypted_server_half": base64.b64encode(b"x" * 40).decode(),
        "public_key_jwk": jwk_from_public(public_key),
        "rules": ["Only allow food and transport purchases", "Maximum NGN 10,000 per transaction"],
    })
    assert r.status_code == 200, r.text
    return {"instrument_id": instrument_id, "locator": locator}


def test_full_payment_lifecycle_authorize_consent_approve(client):
    register_verified(client, "customer@monc.test", "Customer One")
    customer_key = ec.generate_private_key(ec.SECP256R1())
    instrument = issue_instrument(client, (customer_key, customer_key.public_key()))

    register_verified(client, "merchant@monc.test", "Merchant One")
    r = client.post("/api/merchants", json={
        "business_name": "Test Foods Ltd", "merchant_type": "restaurant", "city": "Lagos",
        "account_number": "0123456789"})
    assert r.status_code == 200, r.text
    api_key = r.json()["api_key"]

    r = client.post("/api/v1/payment-intents", headers={"X-MONC-API-Key": api_key}, json={
        "order_id": "ORD-001", "amount_minor": 450000, "currency": "NGN",
        "product_name": "Lunch", "product_type": "food", "checkout_domain": "shop.example.ng",
        "initiator_type": "human"})
    assert r.status_code == 200, r.text
    intent = r.json()
    intent_id = intent["payment_intent_id"]

    # Auth-only screen: verifying the fixed intent context
    r = client.get(f"/checkout/{intent_id}")
    assert r.status_code == 200

    # Switch to the customer so their session owns the instrument.
    r = client.post("/api/auth/login", json={"email": "customer@monc.test", "password": "test-password-123"})
    assert r.status_code == 200

    message = f"MONC-AUTH-V1|{intent_id}|{intent['context_hash']}|{instrument['instrument_id']}"
    # Authorization only: the intent is bound and allowed, but nothing has moved yet.
    r = client.post(f"/api/payment-intents/{intent_id}/authorize", json={
        "locator": instrument["locator"], "signature": sign_raw(customer_key, message)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "allowed"
    assert body["next"] == "consent"
    assert body["monc_status"] == "authorized"
    status = client.get(f"/api/payment-intents/{intent_id}/status").json()
    assert status["settlement_reference"] is None
    assert status["merchant_credited"] is False

    # Consent: customer supplies their Wema/ALAT account for the ALAT Authenticator.
    r = client.post(f"/api/payment-intents/{intent_id}/consent", json={"source_account": "9876543210"})
    assert r.status_code == 200, r.text
    consent = r.json()
    assert consent["monc_status"] == "consent_pending"
    assert consent["wema_state"] == "customer_action_required"
    assert consent["demo_code"]

    # Wrong approval code must fail closed.
    r = client.post(f"/api/payment-intents/{intent_id}/approve", json={"code": "000000"})
    assert r.status_code == 400
    r = client.get(f"/api/payment-intents/{intent_id}/status")
    assert r.json()["status"] == "failed"

    # Re-open by re-authorizing on a fresh intent to test the happy path.
    r = client.post("/api/v1/payment-intents", headers={"X-MONC-API-Key": api_key}, json={
        "order_id": "ORD-002", "amount_minor": 450000, "currency": "NGN",
        "product_name": "Lunch", "product_type": "food", "checkout_domain": "shop.example.ng",
        "initiator_type": "human"})
    intent2 = r.json()
    message2 = f"MONC-AUTH-V1|{intent2['payment_intent_id']}|{intent2['context_hash']}|{instrument['instrument_id']}"
    r = client.post(f"/api/payment-intents/{intent2['payment_intent_id']}/authorize", json={
        "locator": instrument["locator"], "signature": sign_raw(customer_key, message2)})
    assert r.json()["monc_status"] == "authorized"

    r = client.post(f"/api/payment-intents/{intent2['payment_intent_id']}/consent", json={"source_account": "9876543210"})
    consent = r.json()
    r = client.post(f"/api/payment-intents/{intent2['payment_intent_id']}/approve", json={"code": consent["demo_code"]})
    assert r.status_code == 200, r.text
    settled = r.json()
    assert settled["status"] == "successful"
    assert settled["merchant_credited"] is True
    assert settled["settlement_reference"]


def test_consent_requires_authorized_intent_and_owner(client):
    register_verified(client, "customer@monc.test", "Customer One")
    customer_key = ec.generate_private_key(ec.SECP256R1())
    instrument = issue_instrument(client, (customer_key, customer_key.public_key()))
    register_verified(client, "merchant@monc.test", "Merchant One")
    r = client.post("/api/merchants", json={
        "business_name": "Test Foods Ltd", "merchant_type": "restaurant", "city": "Lagos",
        "account_number": "0123456789"})
    api_key = r.json()["api_key"]
    r = client.post("/api/v1/payment-intents", headers={"X-MONC-API-Key": api_key}, json={
        "order_id": "ORD-003", "amount_minor": 450000, "currency": "NGN",
        "product_name": "Lunch", "product_type": "food", "checkout_domain": "shop.example.ng",
        "initiator_type": "human"})
    before = r.json()["payment_intent_id"]
    r = client.post("/api/v1/payment-intents", headers={"X-MONC-API-Key": api_key}, json={
        "order_id": "ORD-004", "amount_minor": 450000, "currency": "NGN",
        "product_name": "Lunch", "product_type": "food", "checkout_domain": "shop.example.ng",
        "initiator_type": "human"})
    authorized_intent = r.json()

    # Consent before authorization must be rejected.
    client.post("/api/auth/login", json={"email": "customer@monc.test", "password": "test-password-123"})
    r = client.post(f"/api/payment-intents/{before}/consent", json={"source_account": "9876543210"})
    assert r.status_code == 409

    # Owner authorizes the intent, then a different verified user cannot approve consent.
    message = (f"MONC-AUTH-V1|{authorized_intent['payment_intent_id']}"
               f"|{authorized_intent['context_hash']}|{instrument['instrument_id']}")
    r = client.post(f"/api/payment-intents/{authorized_intent['payment_intent_id']}/authorize", json={
        "locator": instrument["locator"], "signature": sign_raw(customer_key, message)})
    assert r.json()["monc_status"] == "authorized"

    register_verified(client, "other@monc.test", "Other Person")
    r = client.post(f"/api/payment-intents/{authorized_intent['payment_intent_id']}/consent",
                    json={"source_account": "9876543210"})
    assert r.status_code == 403