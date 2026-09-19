"""
User-specific endpoints.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import verify_password
from ..db import get_db
from ..models import User
from ..schemas import MessageResponse, UserProfile
from .deps import get_current_user

router = APIRouter()


@router.get("/profile", response_model=UserProfile)
async def profile(
    db: AsyncSession = Depends(get_db),
    user: object = Depends(get_current_user),
):
    """Get user profile (also available at /api/me)."""
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return UserProfile(
        id=user.id,
        email=user.email,
        created_at=user.created_at,
    )