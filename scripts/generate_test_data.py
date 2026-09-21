#!/usr/bin/env python3
"""
Generate test data script: Produces bulk token samples for Burp Sequencer analysis.

Run with: python scripts/generate_test_data.py [email] [strategy] [count]

Example: python scripts/generate_test_data.py alice@example.com timestamp 500
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import LabTokenSample, PasswordResetToken, User, token_expiry
from app.token_strategies import get_strategy, list_strategies

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://acmedesk:acmedesk_lab_password@localhost:5432/acmedesk"
)


async def generate(email: str, strategy_name: str, count: int):
    if strategy_name not in list_strategies():
        print(f"Error: Unknown strategy '{strategy_name}'. Available: {list_strategies()}")
        return

    engine = create_async_engine(DATABASE_URL, echo=False)
    AsyncSessionLocal = sessionmaker(engine, class_=sessionmaker, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == email.lower()))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Error: User '{email}' not found.")
            await engine.dispose()
            return

        strategy = get_strategy(strategy_name)
        tokens = []

        print(f"Generating {count} tokens for {email} using strategy '{strategy_name}'...")

        for i in range(count):
            if hasattr(strategy, "generate_with_db"):
                raw_token = await strategy.generate_with_db(db, user.id, email)
            else:
                raw_token = strategy.generate(user.id, email)

            # Store hash in reset tokens table
            import hashlib
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            reset_token = PasswordResetToken(
                user_id=user.id,
                token_hash=token_hash,
                strategy=strategy_name,
                expires_at=token_expiry(),
                token_metadata={"token_length": len(raw_token)},
            )
            db.add(reset_token)

            # Store plaintext in lab samples (if vulnerable)
            strat = get_strategy(strategy_name)
            if strat.stores_plaintext_sample:
                sample = LabTokenSample(user_id=user.id, strategy=strategy_name, token=raw_token)
                db.add(sample)

            tokens.append(raw_token)

            if (i + 1) % 50 == 0:
                await db.commit()
                print(f"  Generated {i + 1}/{count}...")

        await db.commit()
        print(f"Done! Generated {len(tokens)} tokens.")

    await engine.dispose()

    # Output as JSON for easy piping
    print(json.dumps({"strategy": strategy_name, "count": len(tokens), "tokens": tokens}))


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python scripts/generate_test_data.py <email> <strategy> <count>")
        print(f"Available strategies: {list_strategies()}")
        sys.exit(1)

    email = sys.argv[1]
    strategy = sys.argv[2]
    count = int(sys.argv[3])

    if count > 500:
        print("Warning: Limiting to 500 tokens (max per request)")
        count = 500

    asyncio.run(generate(email, strategy, count))