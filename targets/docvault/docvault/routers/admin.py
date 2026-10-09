"""Admin and maintenance endpoints.

Admin-only, behind :func:`docvault.auth.require_admin`. These are the endpoints
support staff use when something looks wrong: tail the service log, look at the
audit trail, check storage usage, and download a report bundle.

Report templates are stored as JSON and parsed with ``json.loads`` into a
pydantic model -- never with a format that can construct objects.
"""
from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from .. import db
from ..auth import User, get_conn, require_admin
from ..config import DIAGNOSTICS_ROOT, EXPORT_ROOT, LOG_PATH, STORAGE_ROOT
from ..models import TemplateIn
from ..security import SecurityError, ensure_within, sanitize_filename, validate_tool_argument
from .documents import team_dir
from .reports import load_report

router = APIRouter(prefix="/admin", tags=["admin"])

TEMPLATE_DIR_NAME = "templates"
LOG_TAIL_MAX = 500

#: Dump names the nightly job produces: word characters, dots, dashes and the
#: date-directory separator.
DIAGNOSTIC_NAME = re.compile(r"^[\w.\-/]+$")


@router.get("/audit")
def read_audit(
    action: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(require_admin),
) -> list[dict]:
    sql = "SELECT actor, action, detail, at FROM audit_log"
    params: list[object] = []
    if action:
        sql += " WHERE action = ?"
        params.append(action)
    sql += " ORDER BY at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, tuple(params)).fetchall()
    return [dict(r) for r in rows]


@router.get("/log")
def tail_log(
    lines: int = Query(default=50, ge=1, le=LOG_TAIL_MAX),
    user: User = Depends(require_admin),
) -> dict:
    """Last ``lines`` lines of the service log.

    ``tail`` is invoked with an argument list; ``lines`` has already been
    coerced to a bounded integer by the signature above.
    """
    if not LOG_PATH.is_file():
        return {"lines": []}
    count = validate_tool_argument(str(int(lines)))
    result = subprocess.run(
        ["tail", "-n", count, str(LOG_PATH)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    return {"lines": result.stdout.decode(errors="replace").splitlines()}


@router.get("/diagnostics")
def read_diagnostic(
    name: str = Query(..., max_length=120),
    user: User = Depends(require_admin),
) -> dict:
    """Read one dump written by the nightly diagnostics job.

    Dumps are filed in dated subdirectories (``2026-10-08/queues.json``), so the
    name is allowed to contain a separator. The job picks the names itself, so
    the only thing worth checking here is the character set.
    """
    if not DIAGNOSTIC_NAME.match(name):
        raise HTTPException(status_code=400, detail="bad diagnostic name")
    target = DIAGNOSTICS_ROOT / name
    if not target.is_file():
        raise HTTPException(status_code=404, detail="no such diagnostic dump")
    return {"name": name, "content": target.read_text(errors="replace")[:20000]}


@router.get("/diagnostics/index")
def list_diagnostics(user: User = Depends(require_admin)) -> list[str]:
    if not DIAGNOSTICS_ROOT.is_dir():
        return []
    return sorted(
        p.relative_to(DIAGNOSTICS_ROOT).as_posix()
        for p in DIAGNOSTICS_ROOT.rglob("*.json")
        if p.is_file()
    )


@router.get("/storage")
def storage_usage(user: User = Depends(require_admin)) -> dict:
    """Bytes used per team directory under the storage root."""
    usage: dict[str, int] = {}
    for child in sorted(STORAGE_ROOT.iterdir()) if STORAGE_ROOT.is_dir() else []:
        if child.is_dir():
            usage[child.name] = sum(f.stat().st_size for f in child.rglob("*") if f.is_file())
    return {"root": str(STORAGE_ROOT), "bytes_per_team": usage}


@router.get("/reports/{report_id}/bundle")
def download_bundle(
    report_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(require_admin),
):
    """Zip a report's documents and hand the archive back.

    Archive members are named from the database display name, reduced to a
    single safe component; the files added come from ``stored_name`` resolved
    inside the team directory.
    """
    report = load_report(conn, report_id, user)
    rows = db.query(
        conn,
        "SELECT filename, stored_name FROM documents WHERE report_id = ? ORDER BY id",
        (report_id,),
    )
    directory = ensure_within(EXPORT_ROOT, str(int(user.team_id)), "bundles")
    directory.mkdir(parents=True, exist_ok=True)
    archive = ensure_within(directory, sanitize_filename(f"report-{report_id}-{report['title']}") + ".zip")

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            member_source = ensure_within(team_dir(user.team_id), row["stored_name"])
            if member_source.is_file():
                zf.write(member_source, arcname=sanitize_filename(row["filename"], row["stored_name"]))
    return FileResponse(path=archive, media_type="application/zip", filename=archive.name)


def template_dir() -> Path:
    """``EXPORT_ROOT/templates/``, created on demand."""
    directory = ensure_within(EXPORT_ROOT, TEMPLATE_DIR_NAME)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


@router.put("/templates/{name}", status_code=201)
def save_template(name: str, body: TemplateIn, user: User = Depends(require_admin)) -> dict:
    try:
        target = ensure_within(template_dir(), sanitize_filename(name, "template") + ".json")
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    target.write_text(json.dumps(body.model_dump(), indent=2))
    return {"name": target.stem, "sections": len(body.sections)}


@router.get("/templates/{name}")
def read_template(name: str, user: User = Depends(require_admin)) -> TemplateIn:
    """Load a stored template. JSON only, then validated into the model."""
    try:
        target = ensure_within(template_dir(), sanitize_filename(name, "template") + ".json")
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not target.is_file():
        raise HTTPException(status_code=404, detail="template not found")
    try:
        raw = json.loads(target.read_text())
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"template is not valid JSON: {exc}") from exc
    return TemplateIn.model_validate(raw)
