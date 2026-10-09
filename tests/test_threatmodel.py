import shutil
from pathlib import Path

from reva.threatmodel import build, load, merge, relearn, save
from reva.types import Flow, Sink, Source

FIX = Path(__file__).parent / "fixtures"


def repo(tmp_path, name):
    shutil.copy(FIX / name, tmp_path / "server.py")
    return tmp_path


def test_build_vulnerable(tmp_path):
    tm = build(repo(tmp_path, "server_vulnerable.py"))
    assert any(f.sink.kind == "path" and not f.guarded for f in tm.flows)
    assert any("git_diff" in q and "'-'" in q and "'target'" in q for q in tm.questions)
    assert any("repo_path" in q for q in tm.questions)
    assert tm.assets and len(tm.trust_boundaries) >= 2


def test_fixed_has_fewer_questions(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    vuln = build(repo(tmp_path / "a", "server_vulnerable.py"))
    fixed = build(repo(tmp_path / "b", "server_fixed.py"))
    assert not any("repo_path" in q or "git_diff" in q for q in fixed.questions)
    assert len(fixed.questions) < len(vuln.questions)


def flow(function, line, param, code):
    return Flow(source=Source(function="call_tool", param=param, file="server.py", line=300),
                sink=Sink(kind="git_arg", function=function, file="server.py", line=line, code=code),
                guarded=False, path=["call_tool", function])


def test_merge_learns_each_flow_once(tmp_path):
    tm = build(repo(tmp_path, "server_vulnerable.py"))
    known, questions = len(tm.flows), len(tm.questions)
    seen = flow("git_checkout", 182, "branch_name", "repo.git.checkout(branch_name)")
    learned = flow("git_apply", 500, "patch_file", "repo.git.apply(patch_file)")
    assert merge(tm, [seen, learned]) == [1, known]      # the known sink dedupes, the new one is appended
    assert tm.flows[known] == learned and len(tm.questions) == questions + 1
    assert merge(tm, [learned]) == [known] and len(tm.flows) == known + 1


def test_save_load_roundtrip(tmp_path):
    tm = build(repo(tmp_path, "server_vulnerable.py"))
    out = save(tm, tmp_path)
    assert out == tmp_path / ".reva" / "threatmodel.json"
    assert load(tmp_path) == tm
    assert load(tmp_path / "missing") is None


def test_llm_summary_leaves_deterministic_model(tmp_path):
    d = repo(tmp_path, "server_vulnerable.py")
    tm = build(d, llm=lambda s, u, h: {"summary": "custom"})
    base = build(d)
    assert tm.summary == "custom" and tm.flows == base.flows and tm.questions == base.questions and tm.agent is None


def test_llm_failure_falls_back(tmp_path):
    def boom(*a):
        raise RuntimeError

    d = repo(tmp_path, "server_vulnerable.py")
    assert build(d, llm=boom).summary == build(d).summary


def test_relearn_replaces_a_functions_stale_flows(tmp_path):
    tm = build(repo(tmp_path, "server_vulnerable.py"))
    old = next(f for f in tm.flows if f.sink.function == "git_checkout")
    moved = old.model_copy(update={"sink": old.sink.model_copy(update={"line": old.sink.line + 3}), "guarded": True})
    relearn(tm, old.sink.file, "git_checkout", [moved])
    mine = [f for f in tm.flows if f.sink.function == "git_checkout"]
    assert mine == [moved]                                    # the line-shifted, now-guarded flow replaced the old one
    relearn(tm, old.sink.file, "git_checkout", [])
    assert not [f for f in tm.flows if f.sink.function == "git_checkout"]
