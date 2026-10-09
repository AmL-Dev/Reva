"""Outbound webhooks.

A team can register one webhook URL; DocVault posts report events to it. The URL
is user-supplied, so it goes through :func:`docvault.security.validate_outbound_url`
both when it is stored and again immediately before the connection is opened --
the second check is the one that matters, because the allowlist can change
between the two.

Redirects are **not** followed: an allowlisted host must not be able to bounce
the request onto something that is not allowlisted.
"""
from __future__ import annotations

import sqlite3

import httpx
from fastapi import APIRouter, Depends, HTTPException

from .. import db
from ..auth import User, current_user, get_conn
from ..config import OUTBOUND_HOST_ALLOWLIST, OUTBOUND_TIMEOUT
from ..models import WebhookConfig, WebhookTest
from ..security import SecurityError, validate_outbound_url

router = APIRouter(tags=["webhooks"])


def _record(conn: sqlite3.Connection, team_id: int, event: str, url: str, status: int | None, error: str | None) -> None:
    db.execute(
        conn,
        "INSERT INTO webhook_deliveries (team_id, event, target_url, status_code, error) VALUES (?, ?, ?, ?, ?)",
        (team_id, event, url, status, error),
    )


def deliver(conn: sqlite3.Connection, team_id: int, event: str, payload: dict) -> int | None:
    """Post one event to the team's configured webhook, if it has one.

    Returns the upstream status code, or ``None`` if no webhook is configured.
    """
    row = db.query_one(conn, "SELECT webhook_url FROM teams WHERE id = ?", (team_id,))
    url = row["webhook_url"] if row else None
    if not url:
        return None
    try:
        target = validate_outbound_url(url)
    except SecurityError as exc:
        _record(conn, team_id, event, url, None, str(exc))
        return None

    body = {"event": event, "team_id": team_id, "data": payload}
    try:
        response = httpx.post(target, json=body, timeout=OUTBOUND_TIMEOUT, follow_redirects=False)
        _record(conn, team_id, event, target, response.status_code, None)
        return response.status_code
    except httpx.HTTPError as exc:
        _record(conn, team_id, event, target, None, str(exc))
        return None


@router.get("/teams/me/webhook")
def read_webhook(
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> dict:
    row = db.query_one(conn, "SELECT webhook_url FROM teams WHERE id = ?", (user.team_id,))
    return {"url": row["webhook_url"] if row else None, "allowed_hosts": list(OUTBOUND_HOST_ALLOWLIST)}


@router.put("/teams/me/webhook")
def set_webhook(
    body: WebhookConfig,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> dict:
    """Store a webhook URL. Rejected at write time if it is not allowlisted."""
    try:
        url = validate_outbound_url(body.url)
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    conn.execute("UPDATE teams SET webhook_url = ? WHERE id = ?", (url, user.team_id))
    conn.commit()
    return {"url": url}


@router.post("/teams/me/webhook/test")
def test_webhook(
    body: WebhookTest,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> dict:
    status = deliver(conn, user.team_id, body.event, body.payload)
    if status is None:
        raise HTTPException(status_code=502, detail="no webhook configured, or delivery refused")
    return {"status_code": status}


@router.get("/teams/me/webhook/deliveries")
def list_deliveries(
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> list[dict]:
    rows = db.query(
        conn,
        "SELECT event, target_url, status_code, error, sent_at FROM webhook_deliveries "
        "WHERE team_id = ? ORDER BY sent_at DESC LIMIT 50",
        (user.team_id,),
    )
    return [dict(r) for r in rows]
