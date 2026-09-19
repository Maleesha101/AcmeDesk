#!/usr/bin/env python3
"""
Seed script: Creates default test users for AcmeDesk lab.

Run with: python scripts/seed_users.py
Or: docker compose run --rm backend python scripts/seed_users.py
"""
import asyncio
import os
import sys

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password
from app.db import Base
from app.models import User

# Use environment variable or default
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://acmedesk:acmedesk_lab_password@localhost:5432/acmedesk"
)

DEFAULT_USERS = [
    {"email": "alice@example.com", "password": "Password123!"},
    {"email": "bob@example.com", "password": "Password123!"},
    {"email": "admin@example.com", "password": "AdminPassword123!"},
]


async def seed():
    engine = create_async_engine(DATABASE_URL, echo=False)
    AsyncSessionLocal = sessionmaker(engine, class_=sessionmaker, expire_on_commit=False)

    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        for u in DEFAULT_USERS:
            result = await db.execute(select(User).where(User.email == u["email"]))
            existing = result.scalar_one_or_none()
            if existing:
                print(f"User {u['email']} already exists, skipping.")
                continue

            user = User(
                email=u["email"],
                password_hash=hash_password(u["password"]),
            )
            db.add(user)
            print(f"Created user: {u['email']}")

        await db.commit()

    print("Seeding complete!")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed())