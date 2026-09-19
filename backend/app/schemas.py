"""
Pydantic schemas for AcmeDesk API
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# ---- Auth ----
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


# ---- Password Reset ----
class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    strategy: str = Field(default="secure")


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)


class ResetPasswordResponse(BaseModel):
    message: str


class ValidateTokenResponse(BaseModel):
    valid: bool
    message: str
    expires_at: Optional[datetime] = None
    user_email: Optional[str] = None


# ---- Lab ----
class GenerateSamplesRequest(BaseModel):
    email: EmailStr
    strategy: str = Field(default="secure")
    count: int = Field(default=100, ge=1, le=500)


class GenerateSamplesResponse(BaseModel):
    strategy: str
    count: int
    tokens: list[str]


class TokenInfoResponse(BaseModel):
    token: str
    length: int
    alphabet_size: int
    encoding: str
    structure: str
    source: str
    known_predictable_components: list[str]
    generation_algorithm: str
    effective_entropy_bits: Optional[float] = None
    instructor_only: bool = False


class AnalyzeTokenResponse(BaseModel):
    length: int
    alphabet_size: int
    encoding: str
    structure: str
    source: str
    known_predictable_components: list[str]
    generation_algorithm: Optional[str] = None
    effective_entropy_bits: Optional[float] = None
    instructor_only: bool = False


class MailboxEntry(BaseModel):
    subject: str
    body: str
    token: Optional[str] = None
    strategy: Optional[str] = None
    created_at: Optional[datetime] = None


class TokenLaboratoryEntry(BaseModel):
    strategy: str
    token_example: str
    length: int
    alphabet: str
    alphabet_size: int
    encoding: str
    generation: str
    predictability: str
    effective_entropy_bits: Optional[float] = None
    recommended_usage: str
    instructor_only: bool = False


# ---- Profile ----
class UserProfile(BaseModel):
    id: int
    email: str
    created_at: datetime


class MessageResponse(BaseModel):
    message: str