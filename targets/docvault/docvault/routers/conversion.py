"""Thumbnails and PDF rendering.

Both run an external binary. Three rules hold everywhere in this module:

* the command is always a **list** of arguments and ``shell`` is never set, so no
  part of a filename can be read as shell syntax;
* every input and output path is resolved with
  :func:`docvault.security.ensure_within` **in the same function that starts the
  process**, so there is no gap between the containment check and the exec;
* anything derived from stored data goes through
  :func:`docvault.security.validate_tool_argument` first, because ImageMagick
  and LibreOffice both read a leading ``-`` as an option even inside an argv
  list.

The binaries are optional. If one is not installed the endpoint answers 503
rather than failing the upload path.
"""
from __future__ import annotations

import logging
import shutil
import sqlite3
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from ..auth import User, current_user, get_conn
from ..config import CONVERT_TIMEOUT, EXPORT_ROOT
from ..security import SecurityError, ensure_within, validate_tool_argument
from .documents import _load_document, team_dir

router = APIRouter(prefix="/documents", tags=["conversion"])

LOG = logging.getLogger(__name__)

THUMBNAIL_BIN = "convert"          # ImageMagick
PDF_BIN = "soffice"                # LibreOffice headless
THUMBNAIL_GEOMETRY = "320x320"


class ToolMissing(RuntimeError):
    pass


def _binary(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise ToolMissing(name)
    return found


def output_dir(team_id: int, kind: str) -> Path:
    """``EXPORT_ROOT/<team-id>/<kind>/``, created on demand."""
    directory = ensure_within(EXPORT_ROOT, str(int(team_id)), kind)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def render_thumbnail(team_id: int, stored_name: str) -> Path:
    """Render a 320px PNG preview of one stored document and return its path."""
    binary = _binary(THUMBNAIL_BIN)
    source = ensure_within(team_dir(team_id), stored_name)
    destination = ensure_within(output_dir(team_id, "thumbs"), Path(stored_name).stem + ".png")
    if not source.is_file():
        raise FileNotFoundError(stored_name)

    argv = [
        binary,
        validate_tool_argument(f"{source}[0]"),
        "-thumbnail",
        THUMBNAIL_GEOMETRY,
        validate_tool_argument(str(destination)),
    ]
    result = subprocess.run(argv, cwd=str(destination.parent), capture_output=True,
                            timeout=CONVERT_TIMEOUT, check=False)
    if result.returncode != 0 or not destination.is_file():
        # The tool's stderr carries absolute paths, so it goes to the log, not
        # to the client.
        LOG.warning("thumbnail failed rc=%s: %s", result.returncode,
                    result.stderr.decode(errors="replace")[:400])
        raise RuntimeError("thumbnail failed")
    return destination


def render_pdf(team_id: int, stored_name: str) -> Path:
    """Convert one stored office document to PDF with LibreOffice headless."""
    binary = _binary(PDF_BIN)
    source = ensure_within(team_dir(team_id), stored_name)
    out_dir = ensure_within(output_dir(team_id, "pdf"), ".")
    if not source.is_file():
        raise FileNotFoundError(stored_name)

    argv = [
        binary,
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        validate_tool_argument(str(out_dir)),
        validate_tool_argument(str(source)),
    ]
    result = subprocess.run(argv, cwd=str(out_dir), capture_output=True,
                            timeout=CONVERT_TIMEOUT, check=False)
    produced = ensure_within(out_dir, Path(stored_name).stem + ".pdf")
    if result.returncode != 0 or not produced.is_file():
        LOG.warning("pdf conversion failed rc=%s: %s", result.returncode,
                    result.stderr.decode(errors="replace")[:400])
        raise RuntimeError("conversion failed")
    return produced


def _render(renderer, team_id: int, stored_name: str) -> Path:
    """Shared error mapping for the two render endpoints."""
    try:
        return renderer(team_id, stored_name)
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=410, detail="document content is gone") from exc
    except ToolMissing as exc:
        raise HTTPException(status_code=503, detail=f"{exc} is not installed") from exc
    except (subprocess.TimeoutExpired, RuntimeError) as exc:
        raise HTTPException(status_code=502, detail=f"render failed: {exc}") from exc


@router.get("/{document_id}/thumbnail")
def get_thumbnail(
    document_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
):
    row = _load_document(conn, document_id, user)
    produced = _render(render_thumbnail, user.team_id, row["stored_name"])
    return FileResponse(path=produced, media_type="image/png")


@router.post("/{document_id}/pdf")
def convert_to_pdf(
    document_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    user: User = Depends(current_user),
):
    row = _load_document(conn, document_id, user)
    produced = _render(render_pdf, user.team_id, row["stored_name"])
    return FileResponse(path=produced, media_type="application/pdf", filename=produced.name)
