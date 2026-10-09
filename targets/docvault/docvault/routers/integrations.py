"""Integrations: pull a team logo from the internal asset CDN.

Design teams keep brand assets on the internal CDN rather than attaching them to
tickets, so an admin can point DocVault at an asset URL instead of uploading a
file. The URL is user-supplied and therefore checked against the outbound
allowlist in :mod:`docvault.security` before any connection is opened, and the
downloaded bytes are written through :func:`ensure_within` like any other file.
"""
from __future__ import annotations

import sqlite3

import httpx
from fastapi import APIRouter, Depends, HTTPException

from .. import db
from ..auth import User, get_conn, require_admin
from ..config import OUTBOUND_TIMEOUT, STORAGE_ROOT
from ..models import LogoImport
from ..security import SecurityError, ensure_within, sanitize_filename

router = APIRouter(tags=["integrations"])

MAX_LOGO_BYTES = 2 * 1024 * 1024
ALLOWED_LOGO_TYPES = ("image/png", "image/jpeg", "image/svg+xml", "image/webp")
LOGO_SUFFIX = {"image/png": ".png", "image/jpeg": ".jpg", "image/svg+xml": ".svg", "image/webp": ".webp"}


@router.get("/teams/me/logo")
def read_logo(
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(require_admin),
) -> dict:
    row = db.query_one(conn, "SELECT logo_path FROM teams WHERE id = ?", (user.team_id,))
    return {"logo_path": row["logo_path"] if row else None}


@router.post("/teams/me/logo", status_code=201)
def import_logo(
    body: LogoImport,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(require_admin),
) -> dict:
    """Fetch a logo from the asset CDN and store it for the caller's team."""
    try:
        source = validate_logo_url(body.url)
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Redirects are not followed: the allowlist check above applies to the URL we
    # were given, and an allowlisted host must not be able to bounce us onto a
    # host that is not allowlisted. The CDN's object paths are already final.
    with httpx.Client(timeout=OUTBOUND_TIMEOUT, follow_redirects=False) as client:
        try:
            response = client.get(source)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"logo fetch failed: {exc}") from exc

    content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type not in ALLOWED_LOGO_TYPES:
        raise HTTPException(status_code=415, detail=f"unsupported logo type: {content_type!r}")
    if len(response.content) > MAX_LOGO_BYTES:
        raise HTTPException(status_code=413, detail="logo too large")

    stored = store_logo(user.team_id, content_type, response.content)
    db.execute(conn, "UPDATE teams SET logo_path = ? WHERE id = ?", (stored, user.team_id))
    return {"logo_path": stored, "bytes": len(response.content)}


def validate_logo_url(url: str) -> str:
    """Allowlist check plus the media-specific rules for logo sources."""
    from ..security import validate_outbound_url

    checked = validate_outbound_url(url)
    if len(checked) > 2000:
        raise SecurityError("logo url too long")
    return checked


def store_logo(team_id: int, content_type: str, payload: bytes) -> str:
    """Write logo bytes under STORAGE_ROOT/<team>/branding/ and return the key."""
    name = sanitize_filename(f"logo{LOGO_SUFFIX.get(content_type, '.bin')}", "logo.bin")
    directory = ensure_within(STORAGE_ROOT, str(int(team_id)), "branding")
    directory.mkdir(parents=True, exist_ok=True)
    target = ensure_within(directory, name)
    target.write_bytes(payload)
    return f"{int(team_id)}/branding/{name}"
