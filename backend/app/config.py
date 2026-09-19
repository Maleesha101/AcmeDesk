"""
Configuration management for AcmeDesk
"""
import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    app_name: str = Field(default="AcmeDesk", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")

    # Database
    postgres_user: str = Field(default="acmedesk", env="POSTGRES_USER")
    postgres_password: str = Field(default="", env="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="acmedesk", env="POSTGRES_DB")
    database_url: Optional[str] = Field(default=None, env="DATABASE_URL")

    # Security
    secret_key: str = Field(default="change-me-in-production", env="SECRET_KEY")
    bcrypt_rounds: int = Field(default=12, env="BCRYPT_ROUNDS")

    # Token Configuration
    token_expiry_minutes: int = Field(default=15, env="TOKEN_EXPIRY_MINUTES")
    token_single_use: bool = Field(default=True, env="TOKEN_SINGLE_USE")

    # Lab Configuration
    lab_mode: bool = Field(default=True, env="LAB_MODE")
    lab_instructor_mode: bool = Field(default=False, env="LAB_INSTRUCTOR_MODE")

    # Rate Limiting
    lab_rate_limit_requests: int = Field(default=5, env="LAB_RATE_LIMIT_REQUESTS")
    lab_rate_limit_window_seconds: int = Field(default=60, env="LAB_RATE_LIMIT_WINDOW_SECONDS")
    lab_max_samples_per_request: int = Field(default=500, env="LAB_MAX_SAMPLES_PER_REQUEST")

    # Frontend
    frontend_url: str = Field(default="http://localhost:8080", env="FRONTEND_URL")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()