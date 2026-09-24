"""
Pytest configuration and shared fixtures for AcmeDesk tests.
"""
import asyncio
import json
import os
import sys

import pytest
import pytest_asyncio
import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select as sa_select

from app.db import Base, engine as app_engine
from app.models import User, LabTokenSample, PasswordResetToken
from app.auth import hash_password, create_session, hash_token
from app.token_strategies import get_strategy, list_strategies

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://acmedesk:acmedesk_lab_password@localhost:5432/acmedesk"
)

TEST_DATABASE_URL = DATABASE_URL.replace("acmedesk", "acmedesk_test")

# Test credentials
TEST_EMAIL = "testuser@example.com"
TEST_PASSWORD = "TestPass123!"
TEST_LOGIN_HEADERS = {"Authorization": "Bearer test-token-123"}
TEST_LAB_HEADERS = {"X-Lab-Mode": "true"}


@pytest.fixture(scope="session")
def event_loop():
    """Provide a session-scoped event loop."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Create test database engine and tables."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def async_client(test_engine):
    """Create a test HTTP client with authenticated session."""
    async with httpx.AsyncClient(base_url="http://localhost:8080", timeout=30.0) as client:
        # Ensure user exists in database
        async with sessionmaker(test_engine, class_=sessionmaker, expire_on_commit=False)() as session:
            result = await session.execute(sa_select(User).where(User.email == TEST_EMAIL))
            user = result.scalar_one_or_none()
            if not user:
                user = User(email=TEST_EMAIL, password_hash=hash_password(TEST_PASSWORD))
                session.add(user)
                await session.flush()

            # Create a session for this user
            token, _ = await create_session(session, user)

        client._headers["Authorization"] = f"Bearer {token}"
        yield client


@pytest_asyncio.fixture
async def async_user_registered(async_client):
    """Ensure a separate test user exists and is logged in."""
    email = f"registered_{os.getpid()}_{id(async_client)}@example.com"
    async with sessionmaker(test_engine, class_=sessionmaker, expire_on_commit=False)() as session:
        result = await session.execute(sa_select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user:
            user = User(email=email, password_hash=hash_password(TEST_PASSWORD))
            session.add(user)
            await session.flush()
    return email


@pytest_asyncio.fixture
async def valid_token_for_reset(async_client, async_user_registered):
    """Create and return a valid secure reset token."""
    email = async_user_registered if async_user_registered else TEST_EMAIL
    await async_client.post(f"{TEST_EMAIL}/auth/register", json={"email": email, "password": TEST_PASSWORD})
    await async_client.post(f"{TEST_EMAIL}/auth/forgot-password", json={"email": email, "strategy": "secure"})

    # Get the token from the database
    async with sessionmaker(test_engine, class_=sessionmaker, expire_on_commit=False)() as session:
        result = await session.execute(
            sa_select(PasswordResetToken)
            .where(PasswordResetToken.user_id == (
                sa_select(User.id).where(User.email == email)
            ).scalar_subquery())
            .where(PasswordResetToken.used_at.is_(None))
        )
        token_record = result.scalar_one_or_none()
        assert token_record is not None
        # Return the token hash - we need the actual token, which is in lab samples for vulnerable strategies
        # For secure strategy, we need to regenerate
        strategy = get_strategy("secure")
        raw_token = strategy.generate(user_id=token_record.user_id, email=email)
    return raw_token


@pytest_asyncio.fixture
async def lab_headers():
    """Return headers for lab endpoints."""
    return {"X-Lab-Mode": "true"}


@pytest.fixture
async def valid_payload_timestamp():
    """Return payload for timestamp strategy forgot password."""
    return {"email": "timestamp@example.com", "strategy": "timestamp"}


@pytest_asyncio.fixture(scope="session")
async def lab_mode_disabled():
    """Context manager for testing with LAB_MODE disabled."""
    # Just a marker fixture; actual behavior depends on config
    return True


@pytest_asyncio.fixture(scope="session")
async def valid_token_headers():
    """Headers for token validation tests."""
    return {"Authorization": "Bearer valid-token"}