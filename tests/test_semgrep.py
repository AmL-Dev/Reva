import json
import subprocess
import sys
import types

import pytest

from reva import detector, semgrep
from reva.detector import Change
from reva.types import Flow, SemgrepHit, Sink, Source, ThreatModel

REAL_SCAN = semgrep._scan   # captured before conftest's autouse stub replaces it

REPORT = {
    "version": "1.180.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
            "path": "/tmp/reva-semgrep-x/bad.py",
            "start": {"line": 13, "col": 31, "offset": 231},
            "end": {"line": 13, "col": 35, "offset": 235},
            "extra": {
                "message": "Found 'subprocess' function 'run' with 'shell=True'.\nThis is dangerous.",
                "metadata": {
                    "owasp": ["A03:2021 - Injection"],
                    "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"],
                    "confidence": "MEDIUM",
                },
                "severity": "ERROR",
            },
        },
        {
            "check_id": "python.lang.security.audit.eval-detected.eval-detected",
            "path": "/tmp/reva-semgrep-x/bad.py",
            "start": {"line": 14, "col": 12, "offset": 260},
            "end": {"line": 14, "col": 21, "offset": 269},
            "extra": {"message": "Detected the use of eval().",
                      "metadata": {"cwe": ["CWE-95: Eval Injection"]}, "severity": "WARNING"},
        },
        {"check_id": "", "start": {"line": 3}, "extra": {}},
    ],
    "errors": [],
}


@pytest.fixture(autouse=True)
def hermetic(monkeypatch):
    """No REVA_SEMGREP* inherited from the shell; conftest clears the cache and stubs the subprocess."""
    for var in ("REVA_SEMGREP", "REVA_SEMGREP_TIMEOUT"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def real_scan(monkeypatch):
    """Undo conftest's stub for the tests that exercise the failure paths of the real _scan."""
    monkeypatch.setattr(semgrep, "_scan", REAL_SCAN)


def test_parses_real_report_into_hits():
    shell, ev = semgrep.parse(REPORT)
    assert len(semgrep.parse(REPORT)) == 2          # the id-less result is dropped
    assert shell == SemgrepHit(check_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                               line=13, severity="ERROR", cwe="CWE-78",
                               message="Found 'subprocess' function 'run' with 'shell=True'. This is dangerous.")
    assert (ev.line, ev.cwe, ev.severity) == (14, "CWE-95", "WARNING")


def test_parse_survives_junk():
    assert semgrep.parse({}) == [] and semgrep.parse({"results": None}) == []


def test_in_lines_keeps_only_the_changed_function():
    hits = semgrep.parse(REPORT)
    assert [h.line for h in semgrep.in_lines(hits, 10, 13)] == [13]
    assert semgrep.in_lines(hits, 20, 40) == []


def test_missing_binary_returns_empty(real_scan, monkeypatch):
    monkeypatch.setattr(semgrep, "binary", lambda: None)
    assert semgrep.scan("s.py", "x = 1\n") == []


def test_timeout_and_crashes_return_empty(real_scan, monkeypatch):
    monkeypatch.setattr(semgrep, "binary", lambda: "/nonexistent/semgrep")
    for exc in (subprocess.TimeoutExpired("semgrep", 20), OSError("no such file"),
                json.JSONDecodeError("bad", "", 0)):
        monkeypatch.setattr(semgrep, "_run", lambda *a, _e=exc, **k: (_ for _ in ()).throw(_e))
        semgrep._cache.clear()
        assert semgrep.scan("s.py", "x = 1\n") == []


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("REVA_SEMGREP", "0")
    monkeypatch.setattr(semgrep, "_scan", lambda *a: [SemgrepHit(check_id="r", line=1, message="m", severity="ERROR")])
    assert semgrep.scan("s.py", "x = 1\n") == []
    assert not semgrep.enabled()


def test_timeout_is_configurable(monkeypatch):
    assert semgrep._timeout() == semgrep.TIMEOUT
    monkeypatch.setenv("REVA_SEMGREP_TIMEOUT", "3.5")
    assert semgrep._timeout() == 3.5
    monkeypatch.setenv("REVA_SEMGREP_TIMEOUT", "soon")
    assert semgrep._timeout() == semgrep.TIMEOUT


def test_one_scan_per_content_hash(monkeypatch):
    calls = []
    monkeypatch.setattr(semgrep, "_scan", lambda f, c: calls.append((f, c)) or [])
    for _ in range(3):
        semgrep.scan("s.py", "x = 1\n")
    semgrep.scan("s.py", "x = 2\n")
    semgrep.scan("t.py", "x = 1\n")
    assert len(calls) == 3


# ---------- the pipeline ----------

HIT = SemgrepHit(check_id="python.lang.security.audit.dangerous-subprocess-use",
                 line=1, message="Detected subprocess function with user input.", severity="ERROR", cwe="CWE-78")
SRC = "def call_tool(repo_path):\n    return git.Repo(repo_path)\n"


@pytest.fixture
def hits(monkeypatch):
    def install(found):
        monkeypatch.setattr(semgrep, "_scan", lambda file, content: list(found))
    return install


@pytest.fixture
def fake_dataflow(monkeypatch):
    def install(flows):
        monkeypatch.setitem(sys.modules, "reva.dataflow", types.SimpleNamespace(
            analyze=lambda source, file: flows,
            flows_for_function=lambda fl, name: [f for f in fl if f.sink.function == name]))
        monkeypatch.setattr(detector.llm, "available", lambda: False)
    return install


def flow(function, guarded=False, guards=()):
    return Flow(source=Source(function=function, param="repo_path", file="s.py", line=1),
                sink=Sink(kind="path", function=function, file="s.py", line=2, code="git.Repo(repo_path)"),
                guarded=guarded, guards=list(guards), path=[function])


def tm():
    return ThreatModel(summary="git MCP server", assets=["repos"], trust_boundaries=["--repository"],
                       flows=[], questions=["Can call_tool escape the repository?"])


def changed(function):
    return Change(file="s.py", function=function, old_code="", new_code=SRC, source=SRC)


def test_calibration_bonus_is_bounded_and_opt_in():
    assert detector.calibrate(True, False, None) == detector.BASE_UNGUARDED
    assert detector.calibrate(True, False, None, True) == detector.BASE_UNGUARDED + detector.SEMGREP_BONUS
    both = detector.BASE_UNGUARDED + detector.SIBLING_BONUS
    assert detector.calibrate(True, True, None, True) == pytest.approx(both + detector.SEMGREP_BONUS)
    assert detector.calibrate(True, True, None, True) <= 1.0
    assert detector.calibrate(True, False, 0.5, True) > detector.calibrate(True, False, 0.5)


def test_semgrep_alone_never_raises_a_finding():
    assert detector.calibrate(False, True, 1.0, True) == 0.0


def test_guarded_flow_plus_semgrep_hit_stays_quiet(fake_dataflow, hits):
    hits([HIT])
    fake_dataflow([flow("call_tool", guarded=True, guards=["validate_repo_path"])])
    assert detector.screen(changed("call_tool"), tm()) == []


def test_gate_runs_no_scan_when_nothing_is_unguarded(fake_dataflow, monkeypatch):
    monkeypatch.setattr(semgrep, "_scan", lambda *a: pytest.fail("semgrep ran behind a closed gate"))
    fake_dataflow([flow("call_tool", guarded=True, guards=["validate_repo_path"])])
    assert detector.screen(changed("call_tool"), tm()) == []
    fake_dataflow([])
    assert detector.screen(changed("call_tool"), tm()) == []


def test_hits_corroborate_an_unguarded_flow(fake_dataflow, hits):
    fake_dataflow([flow("call_tool")])
    [bare] = detector.screen(changed("call_tool"), tm())
    semgrep._cache.clear()
    hits([HIT])
    [corroborated] = detector.screen(changed("call_tool"), tm())
    assert bare.semgrep == [] and corroborated.semgrep == [HIT.check_id]
    assert corroborated.confidence > bare.confidence
    assert HIT.check_id in corroborated.reasoning


def test_absent_semgrep_leaves_the_pipeline_identical(fake_dataflow, monkeypatch):
    fake_dataflow([flow("call_tool")])
    monkeypatch.setattr(semgrep, "binary", lambda: None)
    [f] = detector.screen(changed("call_tool"), tm())
    assert f.semgrep == [] and f.confidence == detector.BASE_UNGUARDED and "Semgrep" not in f.reasoning


def test_hits_outside_the_changed_function_are_ignored(fake_dataflow, hits):
    hits([HIT.model_copy(update={"line": 99})])
    fake_dataflow([flow("call_tool")])
    [f] = detector.screen(changed("call_tool"), tm())
    assert f.semgrep == []


def test_hits_reach_the_context_pack(fake_dataflow, hits, monkeypatch):
    hits([HIT])
    fake_dataflow([flow("call_tool")])
    seen = []
    monkeypatch.setattr(detector.llm, "available", lambda: True)
    monkeypatch.setattr(detector.llm, "complete_json", lambda sys_, user, schema: seen.append(user) or {
        "answers": [{"question": "q", "answer": "yes", "justification": "no check", "probability": 0.9}]})
    detector.screen(changed("call_tool"), tm())
    assert HIT.check_id in seen[0] and "CWE-78" in seen[0] and semgrep.CONFIG in seen[0]


def test_unlocatable_function_yields_no_hits(hits):
    hits([HIT])
    assert detector._semgrep(Change("s.py", "absent", "", SRC, SRC)) == []
    assert detector._semgrep(Change("s.py", "call_tool", "", SRC, "def (:\n")) == []
