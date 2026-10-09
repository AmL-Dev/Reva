"""API-key authentication.

Clients send ``X-API-Key``. Keys live in the ``users`` table; there is no session
state. Some endpoints are intentionally public (health, the public report feed)
and simply do not depend on :func:`current_user`.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request

from . import db


@dataclass(frozen=True)
class User:
    id: int
    email: str
    name: str
    role: str
    team_id: int

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def get_conn(request: Request) -> sqlite3.Connection:
    """Per-request connection, created by the app lifespan's factory."""
    conn = request.app.state.connect()
    try:
        yield conn
    finally:
        conn.close()


def verify_api_key(key: str, conn: sqlite3.Connection) -> User:
    """Look the key up and return the owning user, or raise 401."""
    row = db.query_one(
        conn,
        "SELECT id, email, name, role, team_id FROM users WHERE api_key = ?",
        (key,),
    )
    if row is None:
        raise HTTPException(status_code=401, detail="invalid API key")
    return User(id=row["id"], email=row["email"], name=row["name"], role=row["role"], team_id=row["team_id"])


def current_user(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    conn: sqlite3.Connection = Depends(get_conn),
) -> User:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="missing X-API-Key header")
    return verify_api_key(x_api_key, conn)


def require_admin(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="admin role required")
    return user
