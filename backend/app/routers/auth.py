"""
Authentication router: registration, login, logout, session handling.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import (
    create_session,
    get_user_by_email,
    hash_password,
    invalidate_session,
    verify_password,
)
from ..db import get_db
from ..models import User
from ..schemas import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    MessageResponse,
    RegisterRequest,
    UserProfile,
)
from .deps import get_current_user

router = APIRouter(tags=["auth"])


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Create a new user account.

    This is the realistic SaaS entry point. Passwords are stored as bcrypt
    hashes (production-style), not plaintext.
    """
    email = str(payload.email).lower()
    if await get_user_by_email(db, email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()

    # Auto-log in the new user after registration
    token, _ = await create_session(db, user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email},
    }


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and issue a session token."""
    email = str(payload.email).lower()
    user = await get_user_by_email(db, email)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token, _ = await create_session(db, user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email},
    }


@router.post("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    """Invalidate the current session."""
    token = request.cookies.get("session_token")
    if token:
        await invalidate_session(db, token)
    return {"message": "Logged out"}


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    payload: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    user: object = Depends(get_current_user),
):
    """Change password while authenticated (not via reset token)."""
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if not verify_password(payload.old_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password incorrect")
    user.password_hash = hash_password(payload.new_password)
    await db.flush()
    return {"message": "Password changed"}


@router.get("/me", response_model=UserProfile)
async def me(
    db: AsyncSession = Depends(get_db),
    user: object = Depends(get_current_user),
):
    """Get the current user's profile."""
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return UserProfile(
        id=user.id,
        email=user.email,
        created_at=user.created_at,
    )


@router.get("/me/userinfo")
async def me_userinfo(
    db: AsyncSession = Depends(get_db),
    user: object = Depends(get_current_user),
):
    """Return full profile object for frontend use."""
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
