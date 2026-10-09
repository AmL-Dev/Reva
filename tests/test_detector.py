import types

import pytest

from reva import detector
from reva.detector import Change, screen
from reva.types import Flow, Sink, Source, ThreatModel


def flow(function, kind="path", guarded=False, guards=()):
    return Flow(
        source=Source(function=function, param="repo_path", file="s.py", line=1),
        sink=Sink(kind=kind, function=function, file="s.py", line=5, code="git.Repo(repo_path)"),
        guarded=guarded, guards=list(guards), path=[function],
    )


def tm(*flows):
    return ThreatModel(summary="git MCP server", assets=["repos"], trust_boundaries=["--repository"], flows=list(flows), questions=["Can call_tool escape the repository?"])


@pytest.fixture
def fake_dataflow(monkeypatch):
    def install(flows):
        mod = types.SimpleNamespace(
            analyze=lambda source, file: flows,
            flows_for_function=lambda fl, name: [f for f in fl if f.sink.function == name],
        )
        monkeypatch.setitem(__import__("sys").modules, "reva.dataflow", mod)
        monkeypatch.setattr(detector.llm, "available", lambda: False)
    return install


def change(function):
    return Change(file="s.py", function=function, old_code="", new_code=f"def {function}(repo_path): ...", source="x = 1\n")


def test_unguarded_flow_is_suspected(fake_dataflow):
    fake_dataflow([flow("call_tool")])
    [f] = screen(change("call_tool"), tm())
    assert f.status == "suspected" and f.cwe == "CWE-22" and f.confidence >= detector.THRESHOLD


def test_control_guarded_function_stays_quiet(fake_dataflow):
    fake_dataflow([flow("safe_tool", guarded=True, guards=["validate_repo_path"])])
    assert screen(change("safe_tool"), tm()) == []


def test_no_flows_stays_quiet(fake_dataflow):
    fake_dataflow([])
    assert screen(change("call_tool"), tm()) == []


def test_guarded_siblings_raise_confidence(fake_dataflow):
    bare = flow("call_tool")
    fake_dataflow([bare])
    [lone] = screen(change("call_tool"), tm())
    fake_dataflow([bare, flow("other_tool", guarded=True, guards=["validate_repo_path"])])
    [with_sibling] = screen(change("call_tool"), tm())
    assert with_sibling.confidence > lone.confidence
    assert "validate_repo_path" in with_sibling.reasoning


def test_sink_kind_maps_to_cwe(fake_dataflow):
    fake_dataflow([flow("git_diff", kind="git_arg")])
    assert screen(change("git_diff"), tm())[0].cwe == "CWE-88"


def test_llm_probability_calibrates(monkeypatch, fake_dataflow):
    fake_dataflow([flow("call_tool")])
    monkeypatch.setattr(detector.llm, "available", lambda: True)
    monkeypatch.setattr(detector.llm, "complete_json", lambda *a, **k: {"answers": [{"question": "q", "answer": "no", "justification": "guarded", "probability": 0.95}]})
    assert screen(change("call_tool"), tm()) == []
    monkeypatch.setattr(detector.llm, "complete_json", lambda *a, **k: {"answers": [{"question": "q", "answer": "yes", "justification": "no check", "probability": 0.95}]})
    [f] = screen(change("call_tool"), tm())
    assert f.confidence > 0.7 and "no check" in f.reasoning


def test_discover_returns_the_flows_screen_reasoned_about(fake_dataflow):
    mine = flow("git_diff", kind="git_arg")
    fake_dataflow([mine, flow("other_tool", guarded=True)])
    assert detector.discover(change("git_diff")) == [mine]
    assert detector.discover(change("git_status")) == []


def test_calibrate_unguarded_required():
    assert detector.calibrate(False, True, 1.0) == 0.0


def test_probability_is_vulnerability_likelihood_not_answer_confidence(monkeypatch, fake_dataflow):
    """A confident "no" must talk the score DOWN. Reading `probability` as answer confidence made a
    correct "no" raise it, which is the opposite of what the LLM stage is for."""
    fake_dataflow([flow("call_tool")])
    monkeypatch.setattr(detector.llm, "available", lambda: True)

    def answers(verdict, p):
        return lambda *a, **k: {"answers": [{"question": f"q{i}", "answer": verdict,
                                             "justification": "j", "probability": p} for i in range(3)]}

    monkeypatch.setattr(detector.llm, "complete_json", answers("no", 0.95))
    assert detector._llm_probability("ctx")[0] == pytest.approx(0.05)
    assert screen(change("call_tool"), tm()) == []                  # every answer "no": silence

    monkeypatch.setattr(detector.llm, "complete_json", answers("yes", 0.95))
    assert detector._llm_probability("ctx")[0] == pytest.approx(0.95)
    [f] = screen(change("call_tool"), tm())
    assert f.confidence > detector.THRESHOLD                        # every answer "yes": a finding


def test_a_confident_no_outvotes_nothing_it_should_not():
    vp = detector.vulnerability_probability
    assert vp({"answer": "no", "probability": 0.8}) == pytest.approx(0.2)
    assert vp({"answer": "yes", "probability": 0.8}) == pytest.approx(0.8)
    assert vp({"answer": "NO", "probability": 0.2}) == pytest.approx(0.8)
    assert vp({"answer": "maybe", "probability": 0.9}) == pytest.approx(0.1)   # not "yes" reads as "no"
    assert vp({"answer": "yes", "probability": 7}) == 1.0 and vp({"answer": "yes", "probability": -3}) == 0.0
