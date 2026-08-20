import os

os.environ.setdefault("MONC_DATABASE_URL", "sqlite:///./test_monc.db")
os.environ.setdefault("MONC_SECRET_KEY", "test-secret-key-for-policy-encryption")
os.environ.setdefault("MONC_WEMA_MODE", "sandbox")

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app
from app.wema import SANDBOX_CONSENTS, SANDBOX_HISTORY, SANDBOX_TRANSFERS


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    SANDBOX_CONSENTS.clear()
    SANDBOX_TRANSFERS.clear()
    SANDBOX_HISTORY.clear()
    with TestClient(app) as c:
        yield c


def register_verified(client: TestClient, email: str, name: str) -> None:
    r = client.post("/api/auth/register", json={
        "email": email, "display_name": name, "password": "test-password-123"})
    assert r.status_code == 200, r.text
    code = r.json()["demo_verification_code"]
    r = client.post("/api/auth/verify", json={"code": code})
    assert r.status_code == 200, r.text