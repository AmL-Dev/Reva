"""Internal report service, hardened: bound SQL parameters, contained paths, allowlisted egress."""
import os
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.security import ALLOWED_HOSTS, validated_path

app = FastAPI()
DATA = Path(os.environ.get("REPORT_DATA", "data"))
DOCS = DATA / "docs"
DB = DATA / "reports.db"


def connect():
    DOCS.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS reports (id TEXT, owner TEXT, title TEXT, body TEXT)")
    conn.commit()
    return conn


class ImportRequest(BaseModel):
    url: str
    name: str = "imported"


@app.get("/reports/search")
def search_reports(owner: str):
    cur = connect().cursor()
    cur.execute("SELECT id, title, body FROM reports WHERE owner = ?", (owner,))
    return {"rows": cur.fetchall()}


@app.get("/reports/legacy")
def legacy_search(request: Request):
    owner = request.query_params["owner"]
    cur = connect().cursor()
    cur.execute("SELECT id, title, body FROM reports WHERE owner = ?", (owner,))
    return {"rows": cur.fetchall()}


@app.get("/reports/{report_id}")
def get_report(report_id: str):
    cur = connect().cursor()
    cur.execute("SELECT id, title FROM reports WHERE id = ?", (report_id,))
    return {"rows": cur.fetchall()}


@app.get("/documents")
def read_document(name: str):
    path = validated_path(DOCS, name)
    return {"name": name, "content": open(path).read()}


@app.post("/imports")
def import_document(body: ImportRequest):
    parts = urlparse(body.url)
    if parts.scheme not in ("http", "https") or parts.hostname not in ALLOWED_HOSTS:
        raise HTTPException(400, "url host is not allowlisted")
    resp = requests.get(body.url, timeout=5)
    return {"bytes": len(resp.content), "preview": resp.text[:200]}


@app.post("/exports")
def export_document(name: str, fmt: str = "txt"):
    out = DATA / f"export.{fmt}"
    subprocess.run(["cp", validated_path(DOCS, name), str(out)], check=False)
    return {"export": str(out)}
