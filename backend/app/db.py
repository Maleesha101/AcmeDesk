"""
Database connection and session management for AcmeDesk
"""
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

from .config import settings

# Build database URL
DATABASE_URL = settings.database_url
if not DATABASE_URL:
    DATABASE_URL = (
        f"postgresql+asyncpg://"
        f"{settings.postgres_user}:{settings.postgres_password}"
        f"@db:5432/{settings.postgres_db}"
    )

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.debug,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=5,
    max_overflow=10,
)

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Base for declarative models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides a database session to each request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database tables (create if not exist)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)