"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import db
from .config import DB_PATH, ensure_dirs
from .routers import admin, conversion, documents, integrations, reports, webhooks
from .security import SecurityError

VERSION = "1.4.0"


def create_app(db_path: Path | str | None = None) -> FastAPI:
    path = Path(db_path) if db_path else DB_PATH

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ensure_dirs()
        app.state.db_path = path
        app.state.connect = lambda: db.connect(path)
        conn = app.state.connect()
        try:
            db.init_schema(conn)
        finally:
            conn.close()
        yield

    app = FastAPI(
        title="DocVault",
        version=VERSION,
        summary="Internal document and report service",
        lifespan=lifespan,
    )

    @app.exception_handler(SecurityError)
    async def _security_error(request: Request, exc: SecurityError) -> JSONResponse:
        """A boundary refusal is a client error, and the detail is safe to show."""
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict:
        return {"status": "ok", "version": VERSION}

    for module in (reports, documents, conversion, webhooks, integrations, admin):
        app.include_router(module.router)
    return app


app = create_app()
