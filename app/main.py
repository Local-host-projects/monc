import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
import httpx

from .database import Base, engine, get_db, upgrade_existing_schema
from .models import AuthorizationLog, Instrument, Merchant, PaymentIntent, TokenTransfer, User
from .policy import compile_rules, evaluate
from .security import (
    decrypt_policy,
    encrypt_policy,
    hash_password,
    random_token,
    read_session,
    session_token,
    sha256,
    verify_browser_signature,
    verify_password,
)
from .wema import (
    STATE_CUSTOMER_ACTION,
    STATE_FAILED,
    STATE_REVERSED,
    STATE_SUCCESSFUL,
    get_wema_gateway,
)


ROOT = Path(__file__).parent
app = FastAPI(title="MONC", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")
Base.metadata.create_all(bind=engine)
upgrade_existing_schema()
COOKIE_SECURE = os.getenv("MONC_COOKIE_SECURE", "0") == "1"


class RegisterIn(BaseModel):
    email: str
    display_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=10, max_length=200)


class LoginIn(BaseModel):
    email: str
    password: str


class VerifyIn(BaseModel):
    code: str


class InstrumentIn(BaseModel):
    instrument_id: str
    alias: str = Field(min_length=1, max_length=80)
    locator: str = Field(min_length=20, max_length=200)
    encrypted_server_half: str = Field(min_length=40)
    public_key_jwk: dict
    rules: list[str] = Field(min_length=1, max_length=20)


class ResolveIn(BaseModel):
    locator: str = Field(min_length=20, max_length=200)


class TransferIn(BaseModel):
    locator: str
    recipient_email: str


class AcceptTransferIn(BaseModel):
    transfer_id: str


class MerchantIn(BaseModel):
    business_name: str = Field(min_length=2, max_length=160)
    merchant_type: str = Field(min_length=2, max_length=50)
    city: str = Field(min_length=2, max_length=80)
    account_number: str


class IntentIn(BaseModel):
    order_id: str = Field(min_length=1, max_length=100)
    amount_minor: int = Field(gt=0, le=100_000_000_00)
    currency: str = Field(default="NGN", pattern="^[A-Z]{3}$")
    product_name: str = Field(min_length=1, max_length=160)
    product_type: str = Field(min_length=1, max_length=50)
    product_code: str | None = Field(default=None, max_length=100)
    checkout_domain: str = Field(default="localhost", max_length=255)
    initiator_type: str = Field(default="human", pattern="^(human|agent)$")


class AuthorizeIn(BaseModel):
    locator: str
    signature: str


class ConsentIn(BaseModel):
    source_account: str = Field(pattern="^[0-9]{10}$", description="Customer Wema/ALAT account number")


class ApproveIn(BaseModel):
    code: str | None = None


def current_user(
    monc_session: str | None = Cookie(default=None), db: Session = Depends(get_db)
) -> User:
    user_id = read_session(monc_session)
    user = db.get(User, user_id) if user_id else None
    if not user:
        raise HTTPException(401, "Sign in required")
    return user


def verified_user(user: User = Depends(current_user)) -> User:
    if not user.verified:
        raise HTTPException(403, "Verify your account before using MONC")
    return user


def merchant_from_key(
    x_monc_api_key: str | None = Header(default=None), db: Session = Depends(get_db)
) -> Merchant:
    if not x_monc_api_key:
        raise HTTPException(401, "X-MONC-API-Key required")
    merchant = db.scalar(select(Merchant).where(Merchant.api_key_hash == sha256(x_monc_api_key)))
    if not merchant:
        raise HTTPException(401, "Invalid merchant API key")
    return merchant


def serialize_intent(intent: PaymentIntent) -> dict:
    return {
        "payment_intent_id": intent.id,
        "merchant_id": intent.merchant_id,
        "order_id": intent.order_id,
        "amount_minor": intent.amount_minor,
        "currency": intent.currency,
        "product_name": intent.product_name,
        "product_type": intent.product_type,
        "product_code": intent.product_code,
        "checkout_domain": intent.checkout_domain,
        "initiator_type": intent.initiator_type,
        "context_hash": intent.context_hash,
        "expires_at": intent.expires_at.isoformat(),
        "status": intent.status,
        "wema_state": intent.wema_state,
        "wema_reference": intent.wema_reference,
        "settlement_reference": intent.settlement_reference,
        "source_account_masked": intent.source_account_masked,
        "state_reason": intent.state_reason,
    }


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.get("/app", response_class=HTMLResponse)
def customer_app(request: Request):
    return templates.TemplateResponse(request, "customer.html", {})


@app.get("/merchant", response_class=HTMLResponse)
def merchant_app(request: Request):
    return templates.TemplateResponse(request, "merchant.html", {})


@app.get("/checkout/{intent_id}", response_class=HTMLResponse)
def checkout_page(request: Request, intent_id: str):
    return templates.TemplateResponse(request, "checkout.html", {"intent_id": intent_id})


@app.post("/api/auth/register")
def register(payload: RegisterIn, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "An account already exists for this email")
    code = f"{secrets.randbelow(1_000_000):06d}"
    user = User(
        email=email,
        display_name=payload.display_name.strip(),
        password_hash=hash_password(payload.password),
        verification_code_hash=sha256(code),
    )
    db.add(user)
    db.commit()
    response.set_cookie("monc_session", session_token(user.id), httponly=True, samesite="strict", secure=COOKIE_SECURE, path="/", max_age=7 * 24 * 60 * 60)
    return {"user": user_view(user), "demo_verification_code": code}


@app.post("/api/auth/login")
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.strip().lower()))
    if not user or not verify_password(user.password_hash, payload.password):
        raise HTTPException(401, "Invalid email or password")
    response.set_cookie("monc_session", session_token(user.id), httponly=True, samesite="strict", secure=COOKIE_SECURE, path="/", max_age=7 * 24 * 60 * 60)
    return {"user": user_view(user)}


@app.post("/api/auth/verify")
def verify_account(payload: VerifyIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not user.verification_code_hash or sha256(payload.code) != user.verification_code_hash:
        raise HTTPException(400, "Invalid verification code")
    user.verified = True
    user.verification_code_hash = None
    db.commit()
    return {"user": user_view(user)}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("monc_session")
    return {"ok": True}


@app.get("/api/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    instruments = db.scalars(select(Instrument).where(Instrument.owner_id == user.id)).all()
    transfers = db.scalars(
        select(TokenTransfer).where(TokenTransfer.recipient_id == user.id, TokenTransfer.status == "pending")
    ).all()
    merchant = db.scalar(select(Merchant).where(Merchant.owner_id == user.id))
    return {
        "user": user_view(user),
        "instruments": [{"id": i.id, "alias": i.alias, "status": i.status, "created_at": i.created_at} for i in instruments],
        "incoming_transfers": [{"id": t.id, "instrument_id": t.instrument_id, "created_at": t.created_at} for t in transfers],
        "merchant": merchant_view(merchant) if merchant else None,
    }


def user_view(user: User) -> dict:
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "verified": user.verified}


def merchant_view(merchant: Merchant) -> dict:
    return {
        "id": merchant.id,
        "business_name": merchant.business_name,
        "merchant_type": merchant.merchant_type,
        "city": merchant.city,
        "country": merchant.country,
        "account_number_masked": merchant.account_number_masked,
        "account_name": merchant.account_name,
        "account_verified": merchant.account_verified,
        "credit_balance_minor": merchant.credit_balance_minor,
    }


def public_merchant_view(merchant: Merchant) -> dict:
    """The public checkout needs identity context, never settlement account data."""
    return {
        "id": merchant.id,
        "business_name": merchant.business_name,
        "merchant_type": merchant.merchant_type,
        "city": merchant.city,
        "country": merchant.country,
        "account_verified": merchant.account_verified,
    }


@app.post("/api/instruments")
def create_instrument(payload: InstrumentIn, user: User = Depends(verified_user), db: Session = Depends(get_db)):
    try:
        uuid.UUID(payload.instrument_id)
    except ValueError:
        raise HTTPException(400, "Invalid instrument ID")
    locator_hash = sha256(payload.locator)
    if db.get(Instrument, payload.instrument_id) or db.scalar(select(Instrument).where(Instrument.locator_hash == locator_hash)):
        raise HTTPException(409, "Instrument or locator already exists")
    policy = compile_rules(payload.rules)
    encrypted_policy, nonce = encrypt_policy(policy)
    instrument = Instrument(
        id=payload.instrument_id,
        owner_id=user.id,
        alias=payload.alias,
        locator_hash=locator_hash,
        encrypted_server_half=payload.encrypted_server_half,
        public_key_jwk=json.dumps(payload.public_key_jwk, separators=(",", ":")),
        encrypted_policy=encrypted_policy,
        policy_nonce=nonce,
    )
    db.add(instrument)
    db.commit()
    return {"instrument_id": instrument.id, "alias": instrument.alias, "status": instrument.status}


@app.post("/api/instruments/resolve")
def resolve_instrument(payload: ResolveIn, user: User = Depends(verified_user), db: Session = Depends(get_db)):
    instrument = db.scalar(select(Instrument).where(Instrument.locator_hash == sha256(payload.locator)))
    if not instrument or instrument.owner_id != user.id or instrument.status != "armed":
        raise HTTPException(404, "No active instrument for this account and locator")
    return {
        "instrument_id": instrument.id,
        "encrypted_server_half": instrument.encrypted_server_half,
        "rules_version": instrument.rules_version,
    }


@app.post("/api/transfers")
def transfer(payload: TransferIn, user: User = Depends(verified_user), db: Session = Depends(get_db)):
    instrument = db.scalar(select(Instrument).where(Instrument.locator_hash == sha256(payload.locator)))
    recipient = db.scalar(select(User).where(User.email == payload.recipient_email.strip().lower()))
    if not instrument or instrument.owner_id != user.id:
        raise HTTPException(404, "Instrument not found")
    if not recipient or not recipient.verified:
        raise HTTPException(400, "Recipient must have a verified MONC account")
    if recipient.id == user.id:
        raise HTTPException(400, "You already own this instrument")
    instrument.status = "transfer_pending"
    transfer_row = TokenTransfer(
        id=str(uuid.uuid4()), instrument_id=instrument.id, sender_id=user.id, recipient_id=recipient.id
    )
    db.add(transfer_row)
    db.commit()
    return {"transfer_id": transfer_row.id, "status": transfer_row.status, "recipient": recipient.email}


@app.post("/api/transfers/accept")
def accept_transfer(payload: AcceptTransferIn, user: User = Depends(verified_user), db: Session = Depends(get_db)):
    row = db.get(TokenTransfer, payload.transfer_id)
    if not row or row.recipient_id != user.id or row.status != "pending":
        raise HTTPException(404, "Pending transfer not found")
    instrument = db.get(Instrument, row.instrument_id)
    instrument.owner_id = user.id
    instrument.status = "armed"
    row.status = "accepted"
    row.accepted_at = datetime.now(timezone.utc)
    db.commit()
    return {"instrument_id": instrument.id, "status": "armed"}


@app.post("/api/merchants")
def create_merchant(payload: MerchantIn, user: User = Depends(verified_user), db: Session = Depends(get_db)):
    if db.scalar(select(Merchant).where(Merchant.owner_id == user.id)):
        raise HTTPException(409, "This account already has a merchant profile")
    result = get_wema_gateway().verify_account(payload.account_number)
    if not result.valid:
        raise HTTPException(400, "Wema account enquiry could not verify this account")
    api_key = "monc_test_" + random_token(28)
    merchant = Merchant(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        business_name=payload.business_name.strip(),
        merchant_type=payload.merchant_type.strip().lower(),
        city=payload.city.strip(),
        country="NG",
        account_number_masked="******" + payload.account_number[-4:],
        settlement_account_number=payload.account_number,
        account_fingerprint=sha256("wema:" + payload.account_number),
        account_name=result.account_name,
        account_verified=True,
        api_key_hash=sha256(api_key),
    )
    db.add(merchant)
    db.commit()
    return {"merchant": merchant_view(merchant), "api_key": api_key, "note": "API key is displayed once"}


@app.post("/api/v1/payment-intents")
def create_intent(payload: IntentIn, merchant: Merchant = Depends(merchant_from_key), db: Session = Depends(get_db)):
    intent_id = str(uuid.uuid4())
    canonical = "|".join(
        [intent_id, merchant.id, payload.order_id, str(payload.amount_minor), payload.currency,
         payload.product_name, payload.product_type, payload.product_code or "", payload.checkout_domain,
         payload.initiator_type]
    )
    intent = PaymentIntent(
        id=intent_id,
        merchant_id=merchant.id,
        order_id=payload.order_id,
        amount_minor=payload.amount_minor,
        currency=payload.currency,
        product_name=payload.product_name,
        product_type=payload.product_type.lower(),
        product_code=payload.product_code,
        checkout_domain=payload.checkout_domain.lower(),
        initiator_type=payload.initiator_type,
        context_hash=sha256(canonical),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(intent)
    db.commit()
    return {**serialize_intent(intent), "checkout_url": f"/checkout/{intent.id}"}


@app.get("/api/payment-intents/{intent_id}")
def get_intent(intent_id: str, db: Session = Depends(get_db)):
    intent = db.get(PaymentIntent, intent_id)
    if not intent:
        raise HTTPException(404, "Payment intent not found")
    merchant = db.get(Merchant, intent.merchant_id)
    return {**serialize_intent(intent), "merchant": public_merchant_view(merchant)}


@app.post("/api/payment-intents/{intent_id}/authorize")
def authorize(
    intent_id: str,
    payload: AuthorizeIn,
    user: User = Depends(verified_user),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    intent = db.get(PaymentIntent, intent_id)
    instrument = db.scalar(select(Instrument).where(Instrument.locator_hash == sha256(payload.locator)))
    if not intent or intent.status != "pending":
        raise HTTPException(409, "Payment intent is unavailable or already used")
    if intent.expires_at.replace(tzinfo=timezone.utc) <= now:
        intent.status = "expired"
        db.commit()
        raise HTTPException(410, "Payment intent expired")
    if not instrument or instrument.owner_id != user.id or instrument.status != "armed":
        return log_denial(db, intent, instrument, "Instrument is missing, inactive, or not owned by this verified account.")

    message = f"MONC-AUTH-V1|{intent.id}|{intent.context_hash}|{instrument.id}"
    proof_ok = verify_browser_signature(instrument.public_key_jwk, message, payload.signature)
    if not proof_ok:
        return log_denial(db, intent, instrument, "Transaction-bound cryptographic proof failed.")

    merchant = db.get(Merchant, intent.merchant_id)
    policy = decrypt_policy(instrument.encrypted_policy, instrument.policy_nonce)
    verdict = evaluate(
        policy,
        {
            "amount_minor": intent.amount_minor,
            "product_name": intent.product_name,
            "product_type": intent.product_type,
            "city": merchant.city,
            "merchant_verified": merchant.account_verified,
            "recurring": False,
        },
        now,
    )
    log = AuthorizationLog(
        id=str(uuid.uuid4()), instrument_id=instrument.id, payment_intent_id=intent.id,
        verdict="allowed" if verdict.allowed else "denied", reason=verdict.reason,
        failed_rules=json.dumps(verdict.failed_rules), proof_verified=True,
    )
    db.add(log)
    if verdict.allowed:
        intent.status = "authorized"
        intent.authorized_by = instrument.id
        intent.wema_state = "initiated"
        intent.state_reason = "Policy allowed; awaiting ALAT Authenticator customer consent"
    else:
        intent.status = "denied"
    db.commit()
    return {
        "verdict": log.verdict,
        "reason": log.reason,
        "failed_rules": verdict.failed_rules,
        "payment_intent_id": intent.id,
        "monc_status": intent.status,
        "next": "consent" if verdict.allowed else None,
        "merchant_credit_minor": intent.amount_minor if verdict.allowed else 0,
        "note": "Authorization is not settlement. The next step is ALAT Authenticator customer consent.",
    }


def log_denial(db: Session, intent: PaymentIntent, instrument: Instrument | None, reason: str) -> dict:
    log = AuthorizationLog(
        id=str(uuid.uuid4()), instrument_id=instrument.id if instrument else None,
        payment_intent_id=intent.id, verdict="denied", reason=reason,
        failed_rules="[]", proof_verified=False,
    )
    intent.status = "denied"
    db.add(log)
    db.commit()
    return {"verdict": "denied", "reason": reason, "failed_rules": [], "payment_intent_id": intent.id}


def _settle_and_confirm(db: Session, gateway, intent: PaymentIntent, merchant: Merchant):
    """Fund the merchant wallet once (idempotent) and confirm the settlement reference."""
    if not intent.settlement_reference:
        ref = intent.id + "-set"
        narration = f"MONC settlement {intent.id} {merchant.business_name}"
        try:
            result = gateway.fund_wallet(merchant.settlement_account_number, intent.amount_minor, ref, narration)
        except (httpx.HTTPError, ValueError, RuntimeError):
            intent.wema_state = STATE_FAILED
            intent.state_reason = "Wema settlement request failed"
            intent.status = STATE_FAILED
            db.commit()
            return None
        if not result.successful and result.state in (STATE_FAILED, STATE_REVERSED):
            intent.wema_state = result.state
            intent.state_reason = result.message
            intent.status = result.state
            db.commit()
            return result
        intent.settlement_reference = ref
        intent.settlement_provider_reference = result.platform_reference
        intent.wema_state = result.state
        intent.state_reason = result.message
        db.commit()
    try:
        confirmed = gateway.confirm_transfer_status(intent.settlement_reference)
    except (httpx.HTTPError, ValueError, RuntimeError):
        intent.state_reason = "Wema settlement status is temporarily unavailable"
        db.commit()
        return None
    intent.wema_state = confirmed.state
    intent.state_reason = confirmed.message
    if confirmed.successful and not intent.merchant_credited:
        merchant.credit_balance_minor += intent.amount_minor
        intent.merchant_credited = True
        intent.status = "successful"
    elif confirmed.state in (STATE_FAILED, STATE_REVERSED):
        intent.status = confirmed.state
    db.commit()
    return confirmed


def _advance_intent(db: Session, intent: PaymentIntent) -> PaymentIntent:
    """Drive the lifecycle one Wema hop per call: consent -> debit -> payout -> reconciliation."""
    if intent.status in ("successful", "failed", "reversed", "denied", "expired"):
        return intent
    gateway = get_wema_gateway()
    merchant = db.get(Merchant, intent.merchant_id)
    now = datetime.now(timezone.utc)
    if intent.expires_at.replace(tzinfo=timezone.utc) <= now:
        intent.status = "failed"
        intent.state_reason = "Payment intent expired before settlement"
        db.commit()
        return intent
    if intent.status in ("authorized", "consent_pending", "debited") and not intent.settlement_reference:
        consent_state = intent.wema_state
        if consent_state != STATE_SUCCESSFUL:
            try:
                consent = gateway.check_consent_status(intent.wema_reference or "")
            except (httpx.HTTPError, ValueError, RuntimeError):
                intent.state_reason = "Wema consent status is temporarily unavailable"
                db.commit()
                return intent
            consent_state = consent.state
            intent.wema_state = consent_state
            intent.state_reason = consent.message
        if consent_state == STATE_SUCCESSFUL:
            if intent.status == "consent_pending":
                intent.status = "debited"
            _settle_and_confirm(db, gateway, intent, merchant)
        elif consent_state == STATE_FAILED:
            intent.status = STATE_FAILED
        elif consent_state == STATE_REVERSED:
            intent.status = STATE_REVERSED
        db.commit()
    if intent.settlement_reference and intent.status in ("consent_pending", "debited", "authorized"):
        _settle_and_confirm(db, gateway, intent, merchant)
    return intent


@app.post("/api/payment-intents/{intent_id}/consent")
def initiate_consent(
    intent_id: str,
    payload: ConsentIn,
    user: User = Depends(verified_user),
    db: Session = Depends(get_db),
):
    intent = db.get(PaymentIntent, intent_id)
    if not intent or intent.status != "authorized":
        raise HTTPException(409, "Intent is not awaiting customer consent")
    if intent.authorized_by:
        instrument = db.get(Instrument, intent.authorized_by)
        if not instrument or instrument.owner_id != user.id:
            raise HTTPException(403, "Only the instrument owner may approve consent")
    if intent.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        intent.status = "failed"
        intent.state_reason = "Payment intent expired before consent"
        db.commit()
        raise HTTPException(410, "Payment intent expired before consent")
    merchant = db.get(Merchant, intent.merchant_id)
    narration = f"MONC {merchant.business_name} | {merchant.city} | {intent.product_name}"
    gateway = get_wema_gateway()
    try:
        result = gateway.initiate_consent(payload.source_account, intent.amount_minor, intent.id, narration)
    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
        intent.status = STATE_FAILED
        intent.wema_state = STATE_FAILED
        intent.source_account_masked = "******" + payload.source_account[-4:]
        intent.state_reason = "Wema consent request failed"
        db.commit()
        raise HTTPException(502, "Wema consent request failed") from exc
    if result.state in (STATE_FAILED, STATE_REVERSED):
        intent.status = result.state
        intent.wema_state = result.state
        intent.wema_reference = result.reference
        intent.source_account_masked = "******" + payload.source_account[-4:]
        intent.state_reason = result.message
        db.commit()
        raise HTTPException(502, result.message)
    intent.status = "consent_pending"
    intent.wema_state = result.state
    intent.wema_reference = result.reference
    intent.source_account_masked = "******" + payload.source_account[-4:]
    intent.state_reason = result.message
    db.commit()
    return {
        "payment_intent_id": intent.id,
        "monc_status": intent.status,
        "wema_state": result.state,
        "wema_reference": result.reference,
        "demo_code": result.demo_code if gateway.mode == "sandbox" else None,
        "message": result.message,
    }


@app.post("/api/payment-intents/{intent_id}/approve")
def approve_payment(
    intent_id: str,
    payload: ApproveIn,
    user: User = Depends(verified_user),
    db: Session = Depends(get_db),
):
    intent = db.get(PaymentIntent, intent_id)
    if not intent or intent.status not in ("consent_pending", "debited"):
        raise HTTPException(409, "Intent is not awaiting ALAT Authenticator approval")
    if intent.authorized_by:
        instrument = db.get(Instrument, intent.authorized_by)
        if not instrument or instrument.owner_id != user.id:
            raise HTTPException(403, "Only the instrument owner may approve this consent")
    gateway = get_wema_gateway()
    if gateway.mode != "sandbox":
        raise HTTPException(409, "Approval happens inside the ALAT Authenticator app; MONC only polls status")
    approved = gateway.approve_consent(intent.wema_reference or "", payload.code or "")
    if approved.state == STATE_FAILED:
        intent.status = "failed"
        intent.wema_state = STATE_FAILED
        intent.state_reason = approved.message
        db.commit()
        raise HTTPException(400, approved.message)
    intent.wema_state = approved.state
    intent.status = "debited"
    intent.state_reason = approved.message
    db.commit()
    _advance_intent(db, intent)
    return _payment_status_view(db, intent)


@app.get("/api/payment-intents/{intent_id}/status")
def payment_status(intent_id: str, db: Session = Depends(get_db)):
    intent = db.get(PaymentIntent, intent_id)
    if not intent:
        raise HTTPException(404, "Payment intent not found")
    intent = _advance_intent(db, intent)
    return _payment_status_view(db, intent)


def _payment_status_view(db: Session, intent: PaymentIntent) -> dict:
    gateway = get_wema_gateway()
    merchant = db.get(Merchant, intent.merchant_id)
    answer = {
        **serialize_intent(intent),
        "merchant": public_merchant_view(merchant),
        "merchant_credit_minor": merchant.credit_balance_minor,
        "merchant_credited": intent.merchant_credited,
        "wema_mode": gateway.mode,
    }
    return answer


@app.get("/api/merchant/summary")
def merchant_summary(user: User = Depends(verified_user), db: Session = Depends(get_db)):
    merchant = db.scalar(select(Merchant).where(Merchant.owner_id == user.id))
    if not merchant:
        raise HTTPException(404, "Merchant profile not found")
    intents = db.scalars(
        select(PaymentIntent).where(PaymentIntent.merchant_id == merchant.id).order_by(PaymentIntent.created_at.desc())
    ).all()
    return {"merchant": merchant_view(merchant), "payment_intents": [serialize_intent(i) for i in intents[:30]]}


@app.get("/health")
def health():
    gateway = get_wema_gateway()
    return {"status": "ok", "wema_mode": gateway.mode}
