#!/usr/bin/env python3
"""
Reset lab script: Clears all lab data and reseeds users.

Run with: python scripts/reset_lab.py
Or: docker compose run --rm backend python scripts/reset_lab.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password
from app.db import Base
from app.models import LabCounter, LabTokenSample, PasswordResetToken, Session, User

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://acmedesk:acmedesk_lab_password@localhost:5432/acmedesk"
)

DEFAULT_USERS = [
    {"email": "alice@example.com", "password": "Password123!"},
    {"email": "bob@example.com", "password": "Password123!"},
    {"email": "admin@example.com", "password": "AdminPassword123!"},
]


async def reset():
    engine = create_async_engine(DATABASE_URL, echo=False)
    AsyncSessionLocal = sessionmaker(engine, class_=sessionmaker, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Delete lab data (keep users)
        await db.execute(delete(LabTokenSample))
        await db.execute(delete(PasswordResetToken))
        await db.execute(delete(LabCounter))
        await db.execute(delete(Session))
        await db.commit()
        print("Cleared lab data: samples, tokens, counters, sessions")

        # Reseed users
        for u in DEFAULT_USERS:
            result = await db.execute(select(User).where(User.email == u["email"]))
            existing = result.scalar_one_or_none()
            if existing:
                print(f"User {u['email']} exists, updating password.")
                existing.password_hash = hash_password(u["password"])
            else:
                user = User(
                    email=u["email"],
                    password_hash=hash_password(u["password"]),
                )
                db.add(user)
                print(f"Created user: {u['email']}")

        await db.commit()

    print("Lab reset complete!")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(reset())