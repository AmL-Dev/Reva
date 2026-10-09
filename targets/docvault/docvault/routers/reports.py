"""Reports: create, read, update, list, and the public published feed."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import db
from ..auth import User, current_user, get_conn
from ..models import ReportCreate, ReportOut, ReportUpdate
from ..security import SecurityError, validate_sort_column, validate_sort_direction

router = APIRouter(tags=["reports"])

#: Columns a client is allowed to order the report list by.
SORTABLE = ("id", "title", "status", "created_at", "updated_at")

SELECT_COLS = "id, title, summary, status, owner_id, team_id, created_at, updated_at"


def _row_to_report(row: sqlite3.Row) -> ReportOut:
    return ReportOut(**{k: row[k] for k in ReportOut.model_fields})


def load_report(conn: sqlite3.Connection, report_id: int, user: User) -> sqlite3.Row:
    """Fetch a report the caller's team owns, or raise 404."""
    row = db.query_one(
        conn,
        f"SELECT {SELECT_COLS} FROM reports WHERE id = ? AND team_id = ?",
        (report_id, user.team_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")
    return row


@router.get("/reports", response_model=list[ReportOut])
def list_reports(
    status: str | None = Query(default=None, max_length=32),
    owner: str | None = Query(default=None, max_length=200),
    sort: str = Query(default="updated_at"),
    direction: str = Query(default="desc"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> list[ReportOut]:
    """List the caller's team's reports.

    ``sort``/``direction`` are identifiers, so they go through the allowlist in
    :mod:`docvault.security`; every other filter is a bound parameter.
    """
    try:
        column = validate_sort_column(sort, SORTABLE)
        order = validate_sort_direction(direction)
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    where = ["reports.team_id = ?"]
    params: list[object] = [user.team_id]
    if status:
        where.append("reports.status = ?")
        params.append(status)
    if owner:
        where.append("users.email = ?")
        params.append(owner)

    sql = (
        f"SELECT {', '.join('reports.' + c for c in ReportOut.model_fields)} "
        "FROM reports JOIN users ON users.id = reports.owner_id "
        f"WHERE {' AND '.join(where)} "
        f"ORDER BY reports.{column} {order} LIMIT ? OFFSET ?"
    )
    # The SQL text is assembled only from the literals above; every filter value
    # is bound, including the two the client controls last.
    rows = conn.execute(sql, (*params, limit, offset)).fetchall()
    return [_row_to_report(r) for r in rows]


@router.get("/reports/published", response_model=list[ReportOut])
def published_feed(
    team: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=20, ge=1, le=100),
    conn: sqlite3.Connection = Depends(get_conn),
) -> list[ReportOut]:
    """Public feed of published reports. No authentication."""
    sql = (
        f"SELECT {', '.join('reports.' + c for c in ReportOut.model_fields)} "
        "FROM reports JOIN teams ON teams.id = reports.team_id "
        "WHERE reports.status = 'published'"
    )
    params: list[object] = []
    if team:
        sql += " AND teams.slug = ?"
        params.append(team)
    sql += " ORDER BY reports.updated_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, tuple(params)).fetchall()
    return [_row_to_report(r) for r in rows]


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> ReportOut:
    return _row_to_report(load_report(conn, report_id, user))


@router.post("/reports", response_model=ReportOut, status_code=201)
def create_report(
    body: ReportCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> ReportOut:
    new_id = db.execute(
        conn,
        "INSERT INTO reports (title, summary, status, owner_id, team_id) VALUES (?, ?, ?, ?, ?)",
        (body.title, body.summary, body.status, user.id, user.team_id),
    )
    return _row_to_report(load_report(conn, new_id, user))


@router.patch("/reports/{report_id}", response_model=ReportOut)
def update_report(
    report_id: int,
    body: ReportUpdate,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> ReportOut:
    load_report(conn, report_id, user)
    fields = body.model_dump(exclude_none=True)
    if not fields:
        return _row_to_report(load_report(conn, report_id, user))

    # Column names come from the model's own field list, values are bound.
    assignments = ", ".join(f"{name} = ?" for name in fields)
    conn.execute(
        f"UPDATE reports SET {assignments}, updated_at = datetime('now') WHERE id = ? AND team_id = ?",
        (*fields.values(), report_id, user.team_id),
    )
    conn.commit()
    return _row_to_report(load_report(conn, report_id, user))


@router.delete("/reports/{report_id}", status_code=204)
def delete_report(
    report_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> None:
    load_report(conn, report_id, user)
    db.execute(conn, "DELETE FROM reports WHERE id = ? AND team_id = ?", (report_id, user.team_id))
