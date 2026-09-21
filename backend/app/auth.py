"""
Authentication utilities for AcmeDesk
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from .config import settings
from .models import Session as SessionModel, User, token_expiry, session_expiry

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def hash_token(token: str) -> str:
    """SHA-256 hash of a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: int) -> Optional[User]:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def create_session(
    db: AsyncSession, user: User
) -> tuple[str, datetime]:
    token = generate_session_token()
    token_hash = hash_token(token)
    expires = session_expiry()
    session = SessionModel(
        user_id=user.id,
        session_token_hash=token_hash,
        expires_at=expires,
    )
    db.add(session)
    await db.flush()
    return token, expires


async def verify_session(
    db: AsyncSession, token: str
) -> Optional[User]:
    token_hash = hash_token(token)
    result = await db.execute(
        select(SessionModel)
        .where(SessionModel.session_token_hash == token_hash)
        .where(SessionModel.used_at.is_(None))
        .where(SessionModel.expires_at > datetime.utcnow())
    )
    session = result.scalar_one_or_none()
    if not session:
        return None
    return await get_user_by_id(db, session.user_id)


async def invalidate_session(db: AsyncSession, token: str) -> bool:
    token_hash = hash_token(token)
    result = await db.execute(
        select(SessionModel).where(SessionModel.session_token_hash == token_hash)
    )
    session = result.scalar_one_or_none()
    if session:
        session.used_at = datetime.utcnow()
        await db.flush()
        return True
    return False


async def get_user_tokens(
    db: AsyncSession, user_id: int, strategy: Optional[str] = None
):
    from .models import PasswordResetToken
    query = select(PasswordResetToken).where(
        PasswordResetToken.user_id == user_id
    )
    if strategy:
        query = query.where(PasswordResetToken.strategy == strategy)
    result = await db.execute(query)
    return result.scalars().all()


async def get_valid_token(
    db: AsyncSession, user_id: int, token: str
) -> Optional[dict]:
    """Retrieve a valid (not expired, not used) reset token for a user."""
    from .models import PasswordResetToken
    token_hash = hash_token(token)
    result = await db.execute(
        select(PasswordResetToken)
        .where(PasswordResetToken.user_id == user_id)
        .where(PasswordResetToken.token_hash == token_hash)
        .where(PasswordResetToken.expires_at > datetime.utcnow())
        .where(PasswordResetToken.used_at.is_(None))
    )
    row = result.scalar_one_or_none()
    if not row:
        return None
    return {
        "id": row.id,
        "user_id": row.user_id,
        "strategy": row.strategy,
        "created_at": row.created_at,
        "expires_at": row.expires_at,
        "used_at": row.used_at,
        "metadata": row.token_metadata,
    }