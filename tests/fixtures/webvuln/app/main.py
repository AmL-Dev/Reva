"""Internal report service: documents on disk, metadata in sqlite, imports from remote URLs."""
import base64
import os
import pickle
import sqlite3
import subprocess
from pathlib import Path

import requests
from fastapi import FastAPI, Request
from pydantic import BaseModel

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
    cur.execute(f"SELECT id, title, body FROM reports WHERE owner = '{owner}'")
    return {"rows": cur.fetchall()}


@app.get("/reports/legacy")
def legacy_search(request: Request):
    owner = request.query_params["owner"]
    cur = connect().cursor()
    cur.execute("SELECT id, title, body FROM reports WHERE owner = '%s'" % owner)
    return {"rows": cur.fetchall()}


@app.get("/reports/{report_id}")
def get_report(report_id: str):
    cur = connect().cursor()
    cur.execute("SELECT id, title FROM reports WHERE id = ?", (report_id,))
    return {"rows": cur.fetchall()}


@app.get("/documents")
def read_document(name: str):
    path = os.path.join(DOCS, name)
    return {"name": name, "content": open(path).read()}


@app.post("/imports")
def import_document(body: ImportRequest):
    resp = requests.get(body.url, timeout=5)
    return {"bytes": len(resp.content), "preview": resp.text[:200]}


@app.post("/exports")
def export_document(name: str, fmt: str = "txt"):
    out = DATA / f"export.{fmt}"
    subprocess.run(f"cat {DOCS}/{name} > {out}", shell=True)
    return {"export": str(out)}


@app.post("/sessions/restore")
def restore_session(blob: str):
    state = pickle.loads(base64.b64decode(blob))
    return {"keys": sorted(state)}
