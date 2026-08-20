from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SessionToken(Base):
    __tablename__ = "sessions"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(100))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Instrument(Base):
    __tablename__ = "instruments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    alias: Mapped[str] = mapped_column(String(80))
    locator_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_server_half: Mapped[str] = mapped_column(Text)
    public_key_jwk: Mapped[str] = mapped_column(Text)
    encrypted_policy: Mapped[str] = mapped_column(Text)
    policy_nonce: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="armed")
    rules_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner: Mapped[User] = relationship()


class TokenTransfer(Base):
    __tablename__ = "token_transfers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    instrument_id: Mapped[str] = mapped_column(ForeignKey("instruments.id"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Merchant(Base):
    __tablename__ = "merchants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)
    business_name: Mapped[str] = mapped_column(String(160))
    merchant_type: Mapped[str] = mapped_column(String(50))
    city: Mapped[str] = mapped_column(String(80))
    country: Mapped[str] = mapped_column(String(2), default="NG")
    account_number_masked: Mapped[str] = mapped_column(String(20))
    settlement_account_number: Mapped[str | None] = mapped_column(String(10), nullable=True)
    account_fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    account_name: Mapped[str] = mapped_column(String(160))
    account_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    credit_balance_minor: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PaymentIntent(Base):
    __tablename__ = "payment_intents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(ForeignKey("merchants.id"), index=True)
    order_id: Mapped[str] = mapped_column(String(100), index=True)
    amount_minor: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), default="NGN")
    product_name: Mapped[str] = mapped_column(String(160))
    product_type: Mapped[str] = mapped_column(String(50))
    product_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    checkout_domain: Mapped[str] = mapped_column(String(255))
    initiator_type: Mapped[str] = mapped_column(String(20), default="human")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    authorized_by: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    source_account_masked: Mapped[str | None] = mapped_column(String(20), nullable=True)
    wema_reference: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    settlement_reference: Mapped[str | None] = mapped_column(String(80), nullable=True)
    settlement_provider_reference: Mapped[str | None] = mapped_column(String(80), nullable=True)
    wema_state: Mapped[str] = mapped_column(String(30), default="none")
    merchant_credited: Mapped[bool] = mapped_column(Boolean, default=False)
    state_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    context_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    merchant: Mapped[Merchant] = relationship()


class AuthorizationLog(Base):
    __tablename__ = "authorization_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    instrument_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    payment_intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text)
    failed_rules: Mapped[str] = mapped_column(Text, default="[]")
    proof_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_report: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
