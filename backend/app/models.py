"""
SQLAlchemy models for AcmeDesk
"""
from datetime import datetime, timedelta

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    reset_tokens = relationship("PasswordResetToken", back_populates="user")
    sessions = relationship("Session", back_populates="user")
    lab_samples = relationship("LabTokenSample", back_populates="user")
    counters = relationship("LabCounter", back_populates="user")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    strategy = Column(String(50), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    metadata = Column(JSONB, nullable=False, default=dict)

    user = relationship("User", back_populates="reset_tokens")


class LabTokenSample(Base):
    __tablename__ = "lab_token_samples"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    strategy = Column(String(50), nullable=False, index=True)
    token = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    user = relationship("User", back_populates="lab_samples")


class LabCounter(Base):
    __tablename__ = "lab_counters"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    counter = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    user = relationship("User", back_populates="counters")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    session_token_hash = Column(String(255), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="sessions")


def token_expiry() -> datetime:
    """Return token expiry timestamp based on configured TTL."""
    return datetime.utcnow() + timedelta(minutes=settings.token_expiry_minutes)


def session_expiry() -> datetime:
    """Return session expiry timestamp (24 hours)."""
    return datetime.utcnow() + timedelta(hours=24)