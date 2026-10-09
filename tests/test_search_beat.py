"""The DocVault search beat end to end, plus the SARIF export and the developer actions around it."""
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from reva import patch, sarif, server, validate
from reva.dataflow import analyze, flows_for_function
from reva.store import Store
from reva.types import Finding

DOCVAULT = Path(__file__).resolve().parent.parent / "targets" / "docvault"
REPORTS = "docvault/routers/reports.py"
SCHEMA = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"

QUERY = '''import sqlite3


@router.get("/reports")
def list_reports(q: str = None, sort: str = "updated_at", conn=None):
    column = validate_sort_column(sort, SORTABLE)
    where = ["team_id = ?"]
    params = [1]
    if q:
        where.append(f"title LIKE '%{q}%'")
    sql = f"SELECT * FROM reports WHERE {' AND '.join(where)} ORDER BY {column}"
    return conn.execute(sql, (*params,)).fetchall()
'''


def search_edit(root: Path) -> None:
    """The naive implementation of backlog item 2, as an agent writes it."""
    p = root / REPORTS
    s = p.read_text()
    s = s.replace('    owner: str | None = Query(default=None, max_length=200),\n',
                  '    owner: str | None = Query(default=None, max_length=200),\n'
                  '    q: str | None = Query(default=None, max_length=200),\n', 1)
    anchor = '        params.append(owner)\n'
    p.write_text(s.replace(anchor, anchor + '    if q:\n        where.append(f"reports.title LIKE \'%{q}%\'")\n', 1))


def flows(src):
    return {f.source.param: f for f in flows_for_function(analyze(src, "r.py"), "list_reports") if f.sink.kind == "sql"}


def test_taint_flows_through_list_append_and_guards_stay_per_input():
    fl = flows(QUERY)
    assert not fl["q"].guarded                                   # reached the query through where.append(...)
    assert fl["sort"].guarded and fl["sort"].guards == ["validate_sort_column"]


def test_flag_operand_extend_is_not_a_sink():
    src = ("def git_log(repo, since):\n    args = []\n    args.extend(['--since', since])\n"
           "    return repo.git.log(*args)\n\n\n@app.call_tool()\nasync def call_tool(name, arguments):\n"
           "    return git_log(None, arguments['since'])\n")
    assert not [f for f in analyze(src, "s.py") if f.sink.kind == "git_arg" and not f.guarded]


def test_fragment_fix_binds_the_value():
    fixed = patch._fix_sql_fragment(QUERY, "list_reports")
    assert "where.append('title LIKE ?')" in fixed and "params.append(f'%{q}%')" in fixed
    assert "q" not in flows(fixed) or flows(fixed)["q"].guarded     # a bound parameter is not an injectable sink
    assert patch._fix_sql_fragment(QUERY.replace("'%{q}%'", "{q}"), "list_reports") is None   # identifier: no placeholder


@pytest.fixture(scope="module")
def proven(tmp_path_factory):
    if not DOCVAULT.exists():
        pytest.skip("DocVault target not present")
    root = tmp_path_factory.mktemp("dv") / "docvault"
    shutil.copytree(DOCVAULT, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    clean = validate.validate(Finding(id="c", title="t", file=REPORTS, function="list_reports", line=1, cwe="CWE-89"), str(root))
    search_edit(root)
    f = Finding(id="s1", title="CWE-89: unvalidated q reaches sql sink in list_reports", file=REPORTS,
                function="list_reports", line=80, cwe="CWE-89")
    f = validate.validate(f, str(root))
    f.patch = patch.propose(f, (root / REPORTS).read_text())
    return root, clean, patch.verify(f, str(root), f.patch)


def test_search_injection_is_proven_fixed_and_verified(proven):
    _, clean, f = proven
    assert clean.status == "rejected"                            # the control: unmodified DocVault does not leak
    assert f.status == "patched" and "[query:q]" in f.evidence and "fix holds" in f.validation
    assert "+        params.append(f'%{q}%')" in f.patch


def test_sarif_export_is_schema_valid(proven):
    jsonschema = pytest.importorskip("jsonschema")
    root, _, f = proven
    rejected = f.model_copy(update={"id": "r", "status": "rejected"})
    doc = sarif.build([f, rejected], root)
    jsonschema.validate(doc, json.loads(SCHEMA.read_text()))
    [res] = doc["runs"][0]["results"]                            # only proven findings are exported
    assert res["ruleId"] == "reva/CWE-89" and res["locations"][0]["physicalLocation"]["region"]["startLine"] == 80
    assert res["properties"]["fixVerified"] and res["fixes"][0]["artifactChanges"][0]["replacements"]
    assert "external/cwe/cwe-89" in doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]


@pytest.fixture
def api(monkeypatch, proven, tmp_path):
    root, _, f = proven
    work = tmp_path / "repo"
    shutil.copytree(root, work)
    monkeypatch.setattr(server, "store", Store())
    monkeypatch.setattr(server, "repo", work)
    server.store.upsert(f.model_copy())
    return TestClient(server.app), work


def test_apply_writes_the_verified_patch_once(api):
    client, work = api
    r = client.post("/api/findings/s1/apply")
    assert r.status_code == 200 and r.json()["resolution"] == "applied"
    assert "params.append(f'%{q}%')" in (work / REPORTS).read_text()
    assert client.post("/api/findings/s1/apply").status_code == 409
    assert client.get("/api/sarif").json()["runs"][0]["results"][0]["properties"]["resolution"] == "applied"


def test_only_a_verified_fix_can_be_applied(api):
    client, _ = api
    server.store.upsert(server.store.findings["s1"].model_copy(update={"status": "confirmed"}))
    assert client.post("/api/findings/s1/apply").status_code == 409
    assert client.post("/api/findings/s1/dismiss").json()["resolution"] == "dismissed"
    assert client.post("/api/findings/nope/dismiss").status_code == 404


def test_a_validator_wrapping_the_sink_argument_guards_it():
    src = ("import httpx\n\n\n@router.post('/logo')\ndef import_logo(body: LogoImport):\n"
           "    return httpx.get(validate_logo_url(body.url))\n")
    [f] = [f for f in analyze(src, "i.py") if f.sink.kind == "http"]
    assert f.guarded and f.guards == ["validate_logo_url"]
    assert not [f for f in analyze(src.replace("validate_logo_url(body.url)", "body.url"), "i.py") if f.guarded]
