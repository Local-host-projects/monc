import base64
import hashlib
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256


_secret = os.getenv("MONC_SECRET_KEY", "dev-only-change-me-before-production")
_master_key = hashlib.sha256(("monc-policy:" + _secret).encode()).digest()
_passwords = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)


def hash_password(password: str) -> str:
    return _passwords.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _passwords.verify(password_hash, password)
    except Exception:
        return False


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def random_token(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def generate_refresh_token() -> str:
    return random_token(48)


def generate_csrf_token() -> str:
    return random_token(24)


def issue_access_token(user_id: int, jti: str | None = None, ttl_minutes: int = 15) -> str:
    """Issue a short-lived access JWT (exp as epoch seconds)."""
    now = datetime.now(timezone.utc)
    if not jti:
        jti = str(uuid.uuid4())
    exp = int((now + timedelta(minutes=ttl_minutes)).timestamp())
    payload = {"sub": str(user_id), "jti": jti, "iat": int(now.timestamp()), "exp": exp}
    return jwt.encode(payload, _secret, algorithm="HS256")


def session_token(user_id: int, jti: str | None = None, lifetime_days: int = 7) -> str:
    """Backward-compatible long-lived session token (used in earlier flows)."""
    now = datetime.now(timezone.utc)
    if not jti:
        jti = str(uuid.uuid4())
    payload = {"sub": str(user_id), "jti": jti, "iat": int(now.timestamp()), "exp": int((now + timedelta(days=lifetime_days)).timestamp())}
    return jwt.encode(payload, _secret, algorithm="HS256")


def decode_session(token: str) -> dict | None:
    """Decode a JWT and return the payload dict, or None on failure."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, _secret, algorithms=["HS256"])  # PyJWT will validate exp
        return payload
    except (jwt.PyJWTError, ValueError, KeyError):
        return None


def encrypt_policy(policy: dict) -> tuple[str, str]:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_master_key).encrypt(nonce, json.dumps(policy, separators=(",", ":")).encode(), b"monc-policy-v1")
    return base64.urlsafe_b64encode(ciphertext).decode(), base64.urlsafe_b64encode(nonce).decode()


def decrypt_policy(ciphertext: str, nonce: str) -> dict:
    raw = AESGCM(_master_key).decrypt(
        base64.urlsafe_b64decode(nonce),
        base64.urlsafe_b64decode(ciphertext),
        b"monc-policy-v1",
    )
    return json.loads(raw)


def verify_browser_signature(public_jwk: str, message: str, signature_b64: str) -> bool:
    try:
        jwk = json.loads(public_jwk)
        x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big")
        y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big")
        key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
        if len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der = ec.ECDSA(SHA256())
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        key.verify(encode_dss_signature(r, s), message.encode(), der)
        return True
    except (ValueError, KeyError, InvalidSignature, json.JSONDecodeError, TypeError):
        return False
