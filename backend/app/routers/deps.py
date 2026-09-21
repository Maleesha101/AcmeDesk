"""
Common dependencies for AcmeDesk routers.
"""
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import verify_session
from ..config import settings
from ..db import get_db
from ..models import Session


def lab_mode_required() -> bool:
    """Dependency that enforces lab mode. Raises 404 if disabled."""
    if not settings.lab_mode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not Found",
        )
    return True


def instructor_mode_required() -> bool:
    """Dependency that enforces instructor mode. Raises 403 if disabled."""
    if not settings.lab_instructor_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Instructor mode required.",
        )
    return True


def get_instructor_mode() -> bool:
    """Return the current instructor mode setting (does not raise)."""
    return settings.lab_instructor_mode


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[object]:
    """Resolve the current user from the session cookie.

    Returns None for unauthenticated requests (used on public endpoints).
    Raises HTTPException(401) on protected endpoints.
    """
    session_token = request.cookies.get("session_token") or (
        request.headers.get("Authorization", "").replace("Bearer ", "")
        if request.headers.get("Authorization", "").startswith("Bearer ")
        else None
    )
    if not session_token:
        return None
    user = await verify_session(db, session_token)
    return user