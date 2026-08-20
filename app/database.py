import json
import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker


DATABASE_URL = os.getenv("MONC_DATABASE_URL", "sqlite:///./monc.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def upgrade_existing_schema() -> None:
    """Add columns introduced by the prototype without destroying local data.

    This is intentionally small and SQLite-focused for the current demo. A deployed
    version should replace it with Alembic migrations.
    """
    if not DATABASE_URL.startswith("sqlite"):
        return
    additions = {
        "merchants": {
            "settlement_account_number": "VARCHAR(10)",
        },
        "payment_intents": {
            "authorized_by": "VARCHAR(36)",
            "source_account_masked": "VARCHAR(20)",
            "wema_reference": "VARCHAR(80)",
            "settlement_reference": "VARCHAR(80)",
            "settlement_provider_reference": "VARCHAR(80)",
            "wema_state": "VARCHAR(30) DEFAULT 'none'",
            "merchant_credited": "BOOLEAN DEFAULT 0",
            "state_reason": "TEXT",
        },
        "authorization_logs": {
            "verification_report": "TEXT",
        },
    }
    with engine.begin() as connection:
        inspector = inspect(connection)
        for table, columns in additions.items():
            if not inspector.has_table(table):
                continue
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}'))

        # Create sessions table if it does not exist (simple SQLite inline migration)
        tables = inspector.get_table_names()
        if "sessions" not in tables:
            connection.execute(text(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    jti VARCHAR(64) PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    created_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    revoked BOOLEAN DEFAULT 0
                )
                """
            ))
