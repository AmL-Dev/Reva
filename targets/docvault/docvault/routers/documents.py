"""Documents: upload, download, delete, and CSV export of a report's manifest.

Every path in this module is built with :func:`docvault.security.ensure_within`.
Storage layout is ``STORAGE_ROOT/<team-id>/<stored_name>`` where ``stored_name``
is a server-generated UUID plus the sanitised extension -- the name the user
uploaded is kept in the database for display only and never becomes a path.
"""
from __future__ import annotations

import csv
import io
import sqlite3
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse

from .. import db
from ..auth import User, current_user, get_conn
from ..config import EXPORT_ROOT, MAX_UPLOAD_BYTES, STORAGE_ROOT
from ..models import DocumentOut
from ..security import SecurityError, ensure_within, sanitize_filename
from .reports import load_report

router = APIRouter(tags=["documents"])


def team_dir(team_id: int) -> Path:
    """Storage directory for one team, created on demand."""
    d = ensure_within(STORAGE_ROOT, str(int(team_id)))
    d.mkdir(parents=True, exist_ok=True)
    return d


def stored_path(team_id: int, stored_name: str) -> Path:
    """Resolve a row's ``stored_name`` back to a path inside the team's directory."""
    return ensure_within(team_dir(team_id), stored_name)


def _new_stored_name(filename: str) -> str:
    suffix = Path(sanitize_filename(filename, "upload")).suffix[:16]
    return f"{uuid.uuid4().hex}{suffix}"


@router.get("/reports/{report_id}/documents", response_model=list[DocumentOut])
def list_documents(
    report_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> list[DocumentOut]:
    load_report(conn, report_id, user)
    rows = db.query(
        conn,
        "SELECT id, report_id, filename, content_type, size_bytes, uploaded_at "
        "FROM documents WHERE report_id = ? ORDER BY uploaded_at DESC",
        (report_id,),
    )
    return [DocumentOut(**dict(r)) for r in rows]


@router.post("/reports/{report_id}/documents", response_model=DocumentOut, status_code=201)
async def upload_document(
    report_id: int,
    file: UploadFile,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> DocumentOut:
    """Store an uploaded file against a report.

    The uploaded filename is attacker-controlled, so it is only ever used for
    its extension (sanitised) and as a display string in the database.
    """
    load_report(conn, report_id, user)
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="upload too large")

    stored_name = _new_stored_name(file.filename or "upload")
    try:
        destination = ensure_within(team_dir(user.team_id), stored_name)
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    destination.write_bytes(data)

    doc_id = db.execute(
        conn,
        "INSERT INTO documents (report_id, filename, stored_name, content_type, size_bytes) "
        "VALUES (?, ?, ?, ?, ?)",
        (report_id, file.filename or "upload", stored_name, file.content_type or "application/octet-stream", len(data)),
    )
    row = db.query_one(
        conn,
        "SELECT id, report_id, filename, content_type, size_bytes, uploaded_at FROM documents WHERE id = ?",
        (doc_id,),
    )
    return DocumentOut(**dict(row))


def _load_document(conn: sqlite3.Connection, document_id: int, user: User) -> sqlite3.Row:
    row = conn.execute(
        "SELECT d.id, d.report_id, d.filename, d.stored_name, d.content_type, d.size_bytes "
        "FROM documents d JOIN reports r ON r.id = d.report_id "
        "WHERE d.id = ? AND r.team_id = ?",
        (document_id, user.team_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="document not found")
    return row


@router.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
):
    row = _load_document(conn, document_id, user)
    try:
        source = ensure_within(team_dir(user.team_id), row["stored_name"])
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not source.is_file():
        raise HTTPException(status_code=410, detail="document content is gone")
    return FileResponse(
        path=source,
        media_type=row["content_type"],
        filename=sanitize_filename(row["filename"]),
    )


@router.delete("/documents/{document_id}", status_code=204)
def delete_document(
    document_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> None:
    row = _load_document(conn, document_id, user)
    target = ensure_within(team_dir(user.team_id), row["stored_name"])
    if target.is_file():
        target.unlink()
    db.execute(conn, "DELETE FROM documents WHERE id = ?", (document_id,))


@router.get("/reports/{report_id}/manifest.csv")
def export_manifest(
    report_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
) -> StreamingResponse:
    """Stream a CSV listing of the documents attached to a report."""
    report = load_report(conn, report_id, user)
    rows = db.query(
        conn,
        "SELECT filename, content_type, size_bytes, uploaded_at FROM documents "
        "WHERE report_id = ? ORDER BY uploaded_at",
        (report_id,),
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["filename", "content_type", "size_bytes", "uploaded_at"])
    for r in rows:
        writer.writerow([r["filename"], r["content_type"], r["size_bytes"], r["uploaded_at"]])

    name = sanitize_filename(f"manifest-{report['title']}", f"manifest-{report_id}")
    return StreamingResponse(
        io.BytesIO(buffer.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}.csv"'},
    )


def write_export(team_id: int, name: str, payload: bytes) -> Path:
    """Persist a generated artefact under EXPORT_ROOT/<team-id>/ and return it.

    Shared by the manifest and conversion code paths: the caller passes a
    display name of any shape, and this reduces it to one safe component before
    the containment check.
    """
    directory = ensure_within(EXPORT_ROOT, str(int(team_id)))
    directory.mkdir(parents=True, exist_ok=True)
    target = ensure_within(directory, sanitize_filename(name, "export"))
    with open(target, "wb") as fh:
        fh.write(payload)
    return target
