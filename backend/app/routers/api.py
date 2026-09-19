"""
Non-auth API endpoints: profile, settings, etc.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..schemas import UserProfile
from .deps import get_current_user

router = APIRouter()

router = APIRouter()


@router.get("/me", response_model=UserProfile)
async def me(
    db: AsyncSession = Depends(get_db),
    user: object = Depends(get_current_user),
):
    """Get current user profile (also available at /api/me)."""
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return UserProfile(
        id=user.id,
        email=user.email,
        created_at=user.created_at,
    )


@router.get("/settings")
async def settings(
    db: AsyncSession = Depends(get_db),
    user: object = Depends(get_current_user),
):
    """Get non-sensitive user settings."""
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {
        "theme": "system",
        "notifications": True,
        "lab_mode": True,
        "timezone": "UTC",
    }