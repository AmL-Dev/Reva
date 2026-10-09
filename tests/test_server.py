import asyncio

import pytest

from reva import server, threatmodel
from reva.detector import Change
from reva.store import Store
from reva.types import Finding, ThreatModel

SRC = '''import git


@app.call_tool()
async def call_tool(name, arguments):
    repo = git.Repo(".")
    return git_diff(repo, arguments["target"])


def git_diff(repo, target):
    return repo.git.diff(target)
'''


def finding(cwe="CWE-78"):
    return Finding(id="t", title="t", file="s.py", function="call_tool", line=1, cwe=cwe)


def empty_model():
    return ThreatModel(summary="s", assets=[], trust_boundaries=["--repository"], flows=[], questions=[])


@pytest.fixture
def pipeline(monkeypatch, tmp_path):
    def install(verdict, patch_ok=True, passes=1):
        monkeypatch.setattr(server, "store", Store())
        monkeypatch.setattr(server, "repo", tmp_path)
        monkeypatch.setattr(server.validate, "validate", lambda f, d: f.model_copy(update=verdict))
        monkeypatch.setattr(server.patch, "propose", lambda f, s: "diff" if patch_ok else "")
        monkeypatch.setattr(server.patch, "verify", lambda f, d, diff: f.model_copy(update={"status": "patched", "patch": diff}))
        for _ in range(passes):
            asyncio.run(server.handle_finding(finding(), "source"))
        return server.store
    return install


@pytest.fixture
def live(monkeypatch, tmp_path):
    """server.process wired to the real dataflow, with screening stubbed out."""
    monkeypatch.setattr(server, "store", Store())
    monkeypatch.setattr(server, "repo", tmp_path)
    monkeypatch.setattr(server.detector, "screen", lambda change, tm: [])
    server.store.set_threat_model(empty_model())
    return server.store


def test_unproven_finding_is_not_counted_as_confirmed(pipeline):
    store = pipeline({"status": "suspected", "evidence": "unproven: no exploit probe for CWE-78 in call_tool"})
    assert store.counters == {"screened": 0, "flagged": 1, "confirmed": 0, "quiet": 0}
    [f] = store.findings.values()
    assert f.status == "suspected" and "unproven" in f.evidence and not f.patch


def test_rejected_finding_is_kept_but_not_counted(pipeline):
    store = pipeline({"status": "rejected", "evidence": "did not reproduce"})
    assert store.counters["confirmed"] == 0
    [f] = store.findings.values()
    assert f.status == "rejected" and not f.patch


def test_confirmed_finding_is_patched_and_counted(pipeline):
    store = pipeline({"status": "confirmed", "impact": 5, "likelihood": 4})
    assert store.counters["confirmed"] == 1
    [f] = store.findings.values()
    assert f.status == "patched" and f.patch == "diff"


def test_counters_count_distinct_findings_not_passes(pipeline):
    store = pipeline({"status": "confirmed", "impact": 5, "likelihood": 4}, passes=3)
    assert store.counters == {"screened": 0, "flagged": 1, "confirmed": 1, "quiet": 0}
    assert len(store.findings) == 1


def test_edit_publishes_the_flows_found_in_the_saved_function(live):
    asyncio.run(server.process(Change("s.py", "git_diff", "", "def git_diff(repo, target): ...", SRC)))
    tm = live.threat_model
    assert [(f.sink.function, f.sink.kind, f.source.param) for f in tm.flows] == [("git_diff", "git_arg", "target")]
    edit = [e for e in live.events if e["type"] == "edit"][-1]
    assert edit["data"]["flows"] == [0]
    model = [e for e in live.events if e["type"] == "threatmodel"][-1]
    assert model["id"] < edit["id"]                      # indices point into an already-published model


def test_learned_flows_reach_the_stored_threat_model(live, tmp_path):
    change = Change("s.py", "git_diff", "", "def git_diff(repo, target): ...", SRC)
    asyncio.run(server.process(change))
    saved = threatmodel.load(tmp_path)
    assert saved is not None and saved.flows == live.threat_model.flows
    assert any("git_diff" in q and "target" in q for q in saved.questions)
    asyncio.run(server.process(change))                  # rescreening the same body learns nothing new
    assert len(live.threat_model.flows) == 1
    assert [e for e in live.events if e["type"] == "edit"][-1]["data"]["flows"] == [0]


def test_screening_a_function_without_flows_publishes_none(live):
    asyncio.run(server.process(Change("s.py", "git_status", "", "def git_status(repo): ...", SRC)))
    assert live.threat_model.flows == []
    assert [e for e in live.events if e["type"] == "edit"][-1]["data"]["flows"] == []


def test_diff_of_a_body_with_no_trailing_newline_keeps_hunk_lines_separate():
    out = server.unified(Change("s.py", "f", "def f():\n    raise NotImplementedError",
                                "def f():\n    return repo.git.diff(target)", ""))
    lines = out.splitlines()
    assert "-    raise NotImplementedError" in lines and "+    return repo.git.diff(target)" in lines
    assert not any(line.startswith("-") and "+" in line for line in lines[3:])
    assert all(line[:1] in ("-", "+", " ", "@") for line in lines)
    assert "No newline at end of file" not in out   # every function body hits this; it is pure noise
