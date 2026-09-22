"""
AcmeDesk Token Security Lab - FastAPI Application
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .config import settings
from .db import engine, init_db

# Resolve static directory relative to this file
BASE_DIR = Path(__file__).resolve().parent  # /app/app
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "static"

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("acmedesk")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    await init_db()
    logger.info(f"AcmeDesk {settings.app_version} started (LAB_MODE={settings.lab_mode}, INSTRUCTOR={settings.lab_instructor_mode})")
    yield
    logger.info("AcmeDesk shutting down")


app = FastAPI(
    title="AcmeDesk Token Security Lab",
    description="Educational lab demonstrating token length ≠ token security",
    version=settings.app_version,
    lifespan=lifespan,
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LabModeMiddleware(BaseHTTPMiddleware):
    """Enforce lab mode restrictions on /lab endpoints."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/lab") and not settings.lab_mode:
            return JSONResponse(
                status_code=404,
                content={"detail": "Not Found"},
            )
        return await call_next(request)


app.add_middleware(LabModeMiddleware)


# --- Router imports (will be set up below) ---
# Lazy import to avoid circular issues at startup
from .routers import auth, lab, api, user

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(lab.router, prefix="/lab", tags=["lab"])
app.include_router(api.router, prefix="/api", tags=["api"])
app.include_router(user.router, prefix="/api", tags=["user"])

# Mount static files (frontend)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.get("/health")
async def health():
    return {"status": "ok", "service": settings.app_name, "version": settings.app_version}


@app.get("/")
async def root(request: Request):
    """Serve the main frontend page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/{path:path}")
async def catch_all(request: Request, path: str):
    """Serve frontend for any unmatched route (SPA)."""
    try:
        return templates.TemplateResponse(f"{path}.html", {"request": request})
    except Exception:
        return templates.TemplateResponse("index.html", {"request": request})