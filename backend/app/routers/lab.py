"""
Lab router: password reset workflow, token analysis, Burp Sequencer endpoints.
All endpoints under /lab are gated by LAB_MODE=true.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import (
    get_user_by_email,
    get_valid_token,
    hash_token,
)
from ..config import settings
from ..db import get_db
from ..models import LabTokenSample, PasswordResetToken, User, token_expiry
from ..schemas import (
    AnalyzeTokenResponse,
    ForgotPasswordRequest,
    GenerateSamplesRequest,
    GenerateSamplesResponse,
    MailboxEntry,
    ResetPasswordRequest,
    ResetPasswordResponse,
    TokenInfoResponse,
    TokenLaboratoryEntry,
    ValidateTokenResponse,
)
from ..token_strategies import get_strategy, list_strategies
from .deps import get_current_user, get_instructor_mode, lab_mode_required

router = APIRouter()


def _get_strategy_or_400(strategy_name: str):
    """Get a strategy or raise 400 for invalid names."""
    try:
        return get_strategy(strategy_name)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown strategy: {strategy_name}. Available: {list_strategies()}",
        )


def _record_sample(db: AsyncSession, user: User, strategy: str, token: str):
    """Record a plaintext token sample for lab analysis (vulnerable strategies only)."""
    strategy_obj = get_strategy(strategy)
    if strategy_obj.stores_plaintext_sample:
        sample = LabTokenSample(user_id=user.id, strategy=strategy, token=token)
        db.add(sample)


async def _create_reset_token(
    db: AsyncSession,
    user: User,
    strategy: str,
    raw_token: str,
) -> PasswordResetToken:
    """Create and store a password reset token (hashed)."""
    token_hash = hash_token(raw_token)
    expires = token_expiry()
    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        strategy=strategy,
        expires_at=expires,
        token_metadata={"token_length": len(raw_token)},
    )
    db.add(reset_token)
    await db.flush()
    return reset_token


# ---- Password Reset Request ----

@router.post("/forgot-password", response_model=dict)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
    _lab: bool = Depends(lab_mode_required),
):
    """Request a password reset for the given email.

    The token is NOT returned in the response (simulates email).
    Use GET /lab/mailbox/{email} to see the "sent" token.
    """
    email = str(payload.email).lower()
    user = await get_user_by_email(db, email)

    # Always return success to avoid email enumeration
    if not user:
        return {"message": "If the account exists, a password reset request has been created."}

    strategy = _get_strategy_or_400(payload.strategy)

    # Generate the raw token (may be async for counter strategy)
    if hasattr(strategy, "generate_with_db"):
        raw_token = await strategy.generate_with_db(db, user.id, email)
    else:
        raw_token = strategy.generate(user.id, email)

    # Store hash in reset tokens table, plaintext in lab samples (if vulnerable)
    await _create_reset_token(db, user, strategy.name, raw_token)
    _record_sample(db, user, strategy.name, raw_token)

    return {"message": "If the account exists, a password reset request has been created."}


# ---- Simulated Mailbox ----

@router.get("/mailbox/{email}", response_model=list[MailboxEntry])
async def mailbox(
    email: str,
    db: AsyncSession = Depends(get_db),
    _lab: bool = Depends(lab_mode_required),
):
    """Simulated inbox showing all password reset links for an email.

    This replaces real email delivery in the lab. Learners use this to
    obtain tokens for Burp Sequencer analysis.
    """
    user = await get_user_by_email(db, email)
    if not user:
        return []

    result = await db.execute(
        select(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id)
        .where(PasswordResetToken.used_at.is_(None))
        .where(PasswordResetToken.expires_at > datetime.utcnow())
        .order_by(PasswordResetToken.created_at.desc())
    )
    tokens = result.scalars().all()

    entries = []
    for t in tokens:
        # Reconstruct the plaintext token for display (only in lab mode)
        # We can't decrypt the hash, but we store samples for vulnerable strategies
        sample_result = await db.execute(
            select(LabTokenSample)
            .where(LabTokenSample.user_id == user.id)
            .where(LabTokenSample.strategy == t.strategy)
            .where(LabTokenSample.created_at >= t.created_at - timedelta(seconds=10))
            .order_by(LabTokenSample.created_at.desc())
        )
        sample = sample_result.scalar_one_or_none()
        token_display = sample.token if sample else t.token_hash[:16] + "..."

        reset_url = f"http://localhost:8080/reset?token={token_display}"
        entries.append(MailboxEntry(
            subject="AcmeDesk Password Reset",
            body=f"Click the following link to reset your password:\n\n{reset_url}",
            token=token_display,
            strategy=t.strategy,
            created_at=t.created_at,
        ))
    return entries


# ---- Token Validation (Burp-friendly GET endpoint) ----

@router.get("/validate", response_model=ValidateTokenResponse)
async def validate_token(
    token: str,
    db: AsyncSession = Depends(get_db),
    _lab: bool = Depends(lab_mode_required),
):
    """Validate a password reset token without consuming it.

    This endpoint is designed for Burp Suite Sequencer:
    - GET request with token in query parameter
    - Returns token metadata without marking it used
    - Clean request format: ?token=...
    """
    # Find token by hash
    token_hash = hash_token(token)
    result = await db.execute(
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == token_hash)
        .where(PasswordResetToken.used_at.is_(None))
    )
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        return ValidateTokenResponse(
            valid=False,
            message="Invalid or unknown token",
        )

    if reset_token.expires_at <= datetime.utcnow():
        return ValidateTokenResponse(
            valid=False,
            message="Token expired",
            expires_at=reset_token.expires_at,
        )

    user = await get_user_by_id(db, reset_token.user_id)
    return ValidateTokenResponse(
        valid=True,
        message="Token valid",
        expires_at=reset_token.expires_at,
        user_email=user.email if user else None,
    )


# ---- Password Reset Consumption (POST) ----

@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
    _lab: bool = Depends(lab_mode_required),
):
    """Consume a valid token and change the password.

    This marks the token as used (one-time use).
    """
    token_hash = hash_token(payload.token)
    result = await db.execute(
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == token_hash)
        .where(PasswordResetToken.used_at.is_(None))
        .where(PasswordResetToken.expires_at > datetime.utcnow())
    )
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used token",
        )

    user = await get_user_by_id(db, reset_token.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token user not found",
        )

    user.password_hash = hash_token(payload.new_password)  # Note: this is WRONG for real passwords
    # In a real app, you'd use proper password hashing here.
    # For the lab, we just demonstrate the reset flow.

    reset_token.used_at = datetime.utcnow()
    await db.flush()

    return ResetPasswordResponse(message="Password has been reset successfully.")


# ---- Token Info (Instructor Mode) ----

@router.get("/token-info/{token}", response_model=TokenInfoResponse)
async def token_info(
    token: str,
    db: AsyncSession = Depends(get_db),
    instructor: bool = Depends(get_instructor_mode),
    _lab: bool = Depends(lab_mode_required),
):
    """Get detailed analytical information about a token.

    Only shows full generation algorithm details when instructor mode is enabled.
    """
    # Find the token record to know the strategy
    token_hash = hash_token(token)
    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        # Fallback: try to detect strategy from token format
        # For demo purposes, try each strategy's parse
        for strat_name in list_strategies():
            strat = get_strategy(strat_name)
            info = strat.get_info(token, instructor)
            if info.get("structure") != "malformed":
                return TokenInfoResponse(**info)
        raise HTTPException(status_code=404, detail="Token not found")

    strategy = get_strategy(reset_token.strategy)
    info = strategy.get_info(token, instructor)
    return TokenInfoResponse(**info)


# ---- Token Analysis (Instructor Mode) ----

@router.get("/analyze-token/{token}", response_model=AnalyzeTokenResponse)
async def analyze_token(
    token: str,
    db: AsyncSession = Depends(get_db),
    instructor: bool = Depends(get_instructor_mode),
    _lab: bool = Depends(lab_mode_required),
):
    """Analyze a token's structure and predictability.

    Instructor mode reveals generation algorithm details.
    """
    token_hash = hash_token(token)
    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        # Try to detect from format
        for strat_name in list_strategies():
            strat = get_strategy(strat_name)
            info = strat.get_info(token, instructor)
            if info.get("structure") != "malformed":
                return AnalyzeTokenResponse(**info)
        raise HTTPException(status_code=404, detail="Token not found")

    strategy = get_strategy(reset_token.strategy)
    info = strategy.get_info(token, instructor)
    return AnalyzeTokenResponse(**info)


# ---- Bulk Sample Generation (for Burp Sequencer) ----

@router.post("/generate-samples", response_model=GenerateSamplesResponse)
async def generate_samples(
    payload: GenerateSamplesRequest,
    db: AsyncSession = Depends(get_db),
    request: Request = None,
    _lab: bool = Depends(lab_mode_required),
):
    """Generate multiple tokens for statistical analysis (Burp Sequencer).

    Rate limited by configuration. Max 500 tokens per request.
    """
    email = str(payload.email).lower()
    user = await get_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    strategy = _get_strategy_or_400(payload.strategy)

    # Generate tokens
    tokens = []
    for _ in range(payload.count):
        if hasattr(strategy, "generate_with_db"):
            raw_token = await strategy.generate_with_db(db, user.id, email)
        else:
            raw_token = strategy.generate(user.id, email)

        await _create_reset_token(db, user, strategy.name, raw_token)
        _record_sample(db, user, strategy.name, raw_token)
        tokens.append(raw_token)

    return GenerateSamplesResponse(
        strategy=payload.strategy,
        count=len(tokens),
        tokens=tokens,
    )


# ---- Token Laboratory Comparison Page Data ----

@router.get("/token-laboratory")
async def token_laboratory(
    instructor: bool = Depends(get_instructor_mode),
    _lab: bool = Depends(lab_mode_required),
):
    """Get comparison data for all strategies for the token laboratory page."""
    strategies = list_strategies()
    entries = []

    for strat_name in strategies:
        strategy = get_strategy(strat_name)
        # Generate an example token
        example_token = strategy.generate(user_id=1, email="example@example.com")
        entry = strategy.lab_table_entry(example_token)
        entry["instructor_only"] = not instructor
        entries.append(entry)

    return {
        "strategies": entries,
        "instructor_mode": instructor,
    }


# ---- Challenge Mode ----

@router.get("/challenge")
async def challenge_mode(
    db: AsyncSession = Depends(get_db),
    instructor: bool = Depends(get_instructor_mode),
    _lab: bool = Depends(lab_mode_required),
):
    """Return 6 anonymous token samples for classification exercise.

    The learner must identify which strategy each uses.
    """
    strategies = list_strategies()
    samples = []

    for strat_name in strategies:
        strategy = get_strategy(strat_name)
        # Generate sample for a test user
        sample_token = strategy.generate(user_id=42, email="challenge@example.com")
        samples.append({
            "id": len(samples) + 1,
            "token": sample_token,
            "length": len(sample_token),
            "strategy": strat_name if instructor else None,
        })

    return {
        "challenge": "Classify each token by its generation strategy",
        "samples": samples,
        "instructor_mode": instructor,
    }


@router.post("/challenge/verify")
async def verify_challenge(
    guesses: dict,
    instructor: bool = Depends(get_instructor_mode),
    _lab: bool = Depends(lab_mode_required),
):
    """Verify challenge mode answers (only works in instructor mode)."""
    if not instructor:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Instructor mode required to verify answers",
        )

    strategies = list_strategies()
    results = {}

    for sample_id, guessed_strategy in guesses.items():
        idx = int(sample_id) - 1
        if 0 <= idx < len(strategies):
            actual = strategies[idx]
            results[sample_id] = {
                "correct": guessed_strategy == actual,
                "actual": actual,
                "guessed": guessed_strategy,
            }

    correct_count = sum(1 for r in results.values() if r["correct"])
    return {
        "results": results,
        "score": f"{correct_count}/{len(results)}",
        "message": "All correct!" if correct_count == len(results) else "Keep practicing!",
    }