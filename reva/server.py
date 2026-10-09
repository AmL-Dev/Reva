"""FastAPI app: UI, state, SSE, full scan, and the live file watcher pipeline."""
from __future__ import annotations

import ast
import asyncio
import difflib
import json
import logging
import subprocess
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from watchfiles import awatch

from . import analytics, detector, llm, patch, sarif, threatmodel, validate
from .store import Store
from .types import Finding, Flow

UI = Path(__file__).resolve().parent.parent / "ui" / "index.html"
SKIP_DIRS = {".git", ".reva", "__pycache__", ".venv", "venv", "node_modules"}

log = logging.getLogger("reva")
store = Store()
repo: Path | None = None
snapshot: dict[tuple[str, str], str] = {}   # (file, function) -> last seen source
lock = asyncio.Lock()                        # one analysis pipeline at a time
WATCH = False


def configure(repo_dir: str | Path, watch: bool = True) -> None:
    global repo, WATCH
    repo, WATCH = Path(repo_dir).resolve(), watch
    analytics.start(repo.name)


def py_files(root: Path):
    return [p for p in sorted(root.rglob("*.py")) if not SKIP_DIRS & set(p.relative_to(root).parts)]


def functions_of(text: str) -> dict[str, str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    out: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name not in out:
            out[n.name] = ast.get_source_segment(text, n) or ""
    return out


def rel(path: Path) -> str:
    return path.relative_to(repo).as_posix()


def take_snapshot() -> None:
    snapshot.clear()
    for p in py_files(repo):
        for name, src in functions_of(p.read_text(errors="replace")).items():
            snapshot[(rel(p), name)] = src


def changed_functions(path: Path) -> list[detector.Change]:
    text = path.read_text(errors="replace")
    funcs, file = functions_of(text), rel(path)
    if not funcs:
        return []  # unparseable mid-edit: keep the old snapshot
    changes = [detector.Change(file, n, snapshot.get((file, n), ""), s, text)
               for n, s in funcs.items() if snapshot.get((file, n)) != s]
    for n in [k[1] for k in snapshot if k[0] == file]:
        if n not in funcs:
            del snapshot[(file, n)]
    for c in changes:
        snapshot[(file, c.function)] = c.new_code
    return changes


def flow_hits(function: str) -> list[int]:
    tm = store.threat_model
    if not tm:
        return []
    return [i for i, f in enumerate(tm.flows)
            if function in (f.source.function, f.sink.function, *f.path)]


def learn_flows(change: detector.Change, flows: list[Flow]) -> list[int]:
    """Merge the flows just computed for this function into the shared model; return the indices to show."""
    tm = store.threat_model
    if tm is None:
        return []
    before = list(tm.flows)
    found = threatmodel.relearn(tm, change.file, change.function, flows)
    if tm.flows != before:
        store.set_threat_model(tm)          # republish first: the edit event's indices point into this model
        threatmodel.save(tm, repo)
    return sorted(set(found) | set(flow_hits(change.function)))


def unified(change: detector.Change) -> str:
    """Unified diff. Both bodies are newline-terminated first: ast.get_source_segment strips the
    trailing newline from every function, which would otherwise merge two hunk lines into one."""
    def lines(code: str) -> list[str]:
        return (code + "\n" if code and not code.endswith("\n") else code).splitlines(True)

    return "".join(difflib.unified_diff(lines(change.old_code), lines(change.new_code),
                                        f"a/{change.file}", f"b/{change.file}", n=2))


def set_status(f: Finding, status: str) -> None:
    f.status = status
    store.upsert(f)


async def handle_finding(f: Finding, source: str) -> None:
    if prev := store.findings.get(f.id):
        f.resolution = prev.resolution      # a rediscovery must not undo the developer's decision
    store.mark("flagged", f.id)
    store.upsert(f)
    set_status(f, "validating")
    t = time.perf_counter()
    f = await asyncio.to_thread(validate.validate, f, str(repo))
    analytics.log_outcome(f.id, f.status, (time.perf_counter() - t) * 1000)
    if f.status != "confirmed":
        return store.upsert(f)   # "rejected" = proven false, "suspected" = could not be proven
    store.mark("confirmed", f.id)
    store.upsert(f)
    f.patch = await asyncio.to_thread(patch.propose, f, source)
    if not f.patch:
        f.validation = "no patch could be generated for this finding"
    store.upsert(f)
    if f.patch:
        f = await asyncio.to_thread(patch.verify, f, str(repo), f.patch)
        store.upsert(f)


async def process(change: detector.Change) -> None:
    store.bump("screened")
    flows = await asyncio.to_thread(detector.discover, change)
    store.publish("edit", file=change.file, function=change.function, diff=unified(change),
                  flows=learn_flows(change, flows))
    findings = await asyncio.to_thread(detector.screen, change, store.threat_model)
    if not findings:
        store.bump("quiet")
        store.publish("quiet", file=change.file, function=change.function)
        return
    for f in findings:
        await handle_finding(f, change.source)


async def ensure_threat_model(rebuild: bool = False) -> None:
    tm = None
    if not rebuild:
        with suppress(Exception):
            tm = await asyncio.to_thread(threatmodel.load, str(repo))
    if tm is None:
        store.publish("scan", state="threat model")
        tm = await asyncio.to_thread(threatmodel.build, repo, llm.complete_json if llm.available() else None)
        threatmodel.save(tm, repo)
    store.set_threat_model(tm)


async def full_scan(rebuild: bool = True) -> None:
    async with lock:
        store.publish("scan", state="start")
        await ensure_threat_model(rebuild)
        store.publish("scan", state="scanning")
        take_snapshot()
        for p in py_files(repo):
            text = p.read_text(errors="replace")
            for name, src in functions_of(text).items():
                await process(detector.Change(rel(p), name, "", src, text))
        store.publish("scan", state="done")


async def watch_loop() -> None:
    async with lock:
        await ensure_threat_model()
        take_snapshot()
    store.publish("scan", state="watching", repo=str(repo))
    async for batch in awatch(repo, watch_filter=lambda _, p: p.endswith(".py")
                              and not SKIP_DIRS & set(Path(p).parts)):
        async with lock:
            for _, p in sorted(batch):
                path = Path(p)
                if not path.exists():
                    continue
                try:
                    for change in changed_functions(path):
                        await process(change)
                except Exception as exc:
                    log.exception("analysis failed for %s", path)
                    store.publish("scan", state=f"analysis failed for {path.name}: {type(exc).__name__}: {exc}")


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(watch_loop()) if repo and WATCH else None
    yield
    if task:
        task.cancel()
    analytics.close()                        # flush every queued row before the process goes away


app = FastAPI(title="Reva", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(UI)


@app.get("/api/state")
def state():
    return {**store.snapshot(), "repo": str(repo) if repo else None}


@app.get("/api/events")
async def events(request: Request):
    after = int(request.headers.get("last-event-id") or request.query_params.get("after") or 0)

    async def gen():
        yield "retry: 1500\n\n"
        async for e in store.subscribe(after):
            yield f"id: {e['id']}\nevent: {e['type']}\ndata: {json.dumps(e)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


TOTALS_SQL = ("SELECT count(), countIf(escalated = 1), countIf(outcome != ''), countIf(sink_kind = ''), "
              "coalesce(round(avgOrNull(total_ms), 2), 0) FROM {db}.screenings FINAL")
BY_SINK_SQL = ("SELECT sink_kind, sum(confirmed), sum(total) FROM {db}.prior_rollup "
               "WHERE rule = '' AND sink_kind != '' GROUP BY sink_kind ORDER BY sum(total) DESC")


@app.get("/api/analytics")
async def analytics_panel():
    """What the calibration memory knows. Always 200: `enabled: false` when there is no ClickHouse."""
    out = {"enabled": analytics.enabled(), "latency": analytics.latency_percentiles(),
           "min_samples": detector.PRIOR_MIN_SAMPLES, "weight": detector.PRIOR_WEIGHT,
           "totals": {}, "by_sink": []}
    if not out["enabled"]:
        return out
    totals = await asyncio.to_thread(analytics.query, TOTALS_SQL)
    if totals:
        out["totals"] = dict(zip(("screenings", "escalated", "labelled", "quiet", "avg_ms"), totals[0]))
    out["by_sink"] = [{"sink_kind": k, "confirmed": int(c), "total": int(n),
                       "rate": round(int(c) / int(n), 3) if int(n) else None,
                       "trusted": int(n) >= detector.PRIOR_MIN_SAMPLES}
                      for k, c, n in await asyncio.to_thread(analytics.query, BY_SINK_SQL)]
    return out


def _finding(fid: str) -> Finding:
    if fid not in store.findings:
        raise HTTPException(404, "no such finding")
    return store.findings[fid]


@app.post("/api/findings/{fid}/apply")
async def apply_fix(fid: str):
    """Write the verified patch into the watched repo. Only a fix whose exploit re-run came back clean."""
    f = _finding(fid)
    if f.status != "patched" or not f.patch:
        raise HTTPException(409, "only a verified fix can be applied")
    if f.resolution:
        raise HTTPException(409, f"already {f.resolution}")
    for args in (["--dry-run"], []):
        out = await asyncio.to_thread(subprocess.run, ["patch", "-p1", "--forward", *args, "-d", str(repo)],
                                      input=f.patch, text=True, capture_output=True)
        if out.returncode != 0:
            raise HTTPException(409, f"patch no longer applies: {(out.stdout + out.stderr).strip()[-300:]}")
    f.resolution = "applied"
    store.upsert(f)
    return f.model_dump()


@app.post("/api/findings/{fid}/dismiss")
def dismiss(fid: str):
    f = _finding(fid)
    f.resolution = "dismissed"
    store.upsert(f)
    return f.model_dump()


@app.post("/api/candidates/{i}/{decision}")
def decide_candidate(i: int, decision: str):
    tm = store.threat_model
    if decision not in ("accepted", "dismissed", "none") or not tm or not tm.agent or not 0 <= i < len(tm.agent.candidates):
        raise HTTPException(404, "no such proposal")
    tm.agent.candidates[i].decision = "" if decision == "none" else decision
    threatmodel.save(tm, repo)
    store.set_threat_model(tm)
    return {"ok": True}


@app.get("/api/sarif")
def sarif_export():
    """Proven findings as SARIF 2.1.0, for GitHub code scanning or any SARIF viewer."""
    doc = sarif.build(list(store.findings.values()), repo, store.threat_model)
    name = f"reva-{repo.name if repo else 'findings'}.sarif"
    return JSONResponse(doc, media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.post("/api/scan", status_code=202)
async def scan():
    if repo is None:
        raise HTTPException(400, "no target repo configured")
    if lock.locked():
        raise HTTPException(409, "analysis in progress")
    asyncio.create_task(full_scan())
    return {"started": True}
