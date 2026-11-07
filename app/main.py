"""Application entry point."""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from .config import get_settings
from .db import init_db
from .routers import access_requests, admin, auth

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
log = logging.getLogger("accessdesk")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    get_settings()  # fail fast if the JWT secret is missing or too short
    init_db()
    yield


app = FastAPI(
    title="AccessDesk",
    version="0.1.0",
    description=(
        "Internal access-request approval API demonstrating JWT authentication, "
        "role-based access control, and object-level authorization. "
        "First-party JWT auth only: this is not OAuth2/OIDC."
    ),
    lifespan=lifespan,
)


@app.middleware("http")
async def access_log(request: Request, call_next):
    """Log method, path and status only. Never headers, query strings, or bodies,
    because those are where tokens and passwords live."""
    start = time.perf_counter()
    response = await call_next(request)
    log.info(
        "%s %s -> %s (%.0f ms)",
        request.method,
        request.url.path,
        response.status_code,
        (time.perf_counter() - start) * 1000,
    )
    return response


app.include_router(auth.router)
app.include_router(access_requests.router)
app.include_router(admin.router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}
