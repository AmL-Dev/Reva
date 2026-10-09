import json
import shutil
import time
from pathlib import Path

import pytest

from reva import agents, detector
from reva.detector import Change, screen
from reva.threatmodel import build, save

FIX = Path(__file__).parent / "fixtures"
REVIEW = {
    "assets": ["Commit history of every repository the server can open", 7],
    "trust_boundaries": ["MCP client (LLM) -> git subprocess"],
    "questions": [{"function": "git_reset", "question": "Can a tool call discard uncommitted work?"},
                  {"function": "made_up_fn", "question": "Hallucinated?"}],
    "candidates": [
        {"role": "sink", "kind": "exec", "file": "server.py", "function": "git_reset", "reason": "index reset"},
        {"role": "sink", "kind": "git_arg", "file": "server.py", "function": "git_diff", "reason": "already known"},
        {"role": "sink", "kind": "exec", "file": "nowhere.py", "function": "git_reset", "reason": "bad file"},
        {"role": "entry", "kind": "mcp", "file": "server.py", "function": "imaginary", "reason": "bad function"},
    ],
}


@pytest.fixture(autouse=True)
def agent_on(monkeypatch):
    monkeypatch.delenv("REVA_AGENT", raising=False)


@pytest.fixture
def repo(tmp_path):
    shutil.copy(FIX / "server_vulnerable.py", tmp_path / "server.py")
    return tmp_path


def stub(review, prompts=None):
    def llm(system, user, hint):
        if system != agents.SYSTEM:
            return {"summary": "custom"}
        if prompts is not None:
            prompts.append(user)
        if isinstance(review, Exception):
            raise review
        return review
    return llm


def _old_save(model) -> str:
    return model.model_dump_json(indent=2, exclude={"agent"})


def test_agent_unavailable_is_todays_model(repo, monkeypatch):
    base = build(repo)
    assert base.agent is None and save(base, repo).read_text() == _old_save(base)
    assert build(repo, llm=stub(RuntimeError("down"))).model_dump(exclude={"summary"}) == base.model_dump(exclude={"summary"})
    monkeypatch.setenv("REVA_AGENT", "0")
    assert build(repo, llm=stub(REVIEW)).agent is None


def test_agent_timeout_degrades(repo, monkeypatch):
    monkeypatch.setattr(agents, "TIMEOUT", 0.05)

    def slow(system, user, hint):
        if system == agents.SYSTEM:
            time.sleep(1)
        return {"summary": "custom"}

    t = time.perf_counter()
    tm = build(repo, llm=slow)
    assert tm.agent is None and tm.questions == build(repo).questions and time.perf_counter() - t < 0.9


@pytest.mark.parametrize("bad", [
    "not json", ["a list"], {}, {"assets": "x", "trust_boundaries": [None, 3]},
    {"questions": [1, "q", {"function": ["git_reset"]}, {"function": "git_reset"}],
     "candidates": [None, "s", {"role": "bogus", "kind": "x", "file": "server.py", "function": "git_reset", "reason": ""},
                    {"role": "sink"}]},
])
def test_malformed_agent_output_is_ignored(repo, bad):
    base = build(repo)
    tm = build(repo, llm=stub(bad))
    assert tm.agent is None and tm.flows == base.flows and tm.questions == base.questions and tm.assets == base.assets
    assert save(tm, repo).read_text() == _old_save(tm)


def test_agent_output_merged_and_marked(repo):
    base, prompts = build(repo), []
    tm = build(repo, llm=stub(REVIEW, prompts))
    rv = tm.agent
    assert rv.provenance == "agent" and json.loads(save(tm, repo).read_text())["agent"]["provenance"] == "agent"
    assert rv.assets == [REVIEW["assets"][0]] and rv.trust_boundaries == REVIEW["trust_boundaries"]
    assert rv.questions == ["[agent] git_reset(): Can a tool call discard uncommitted work?"]
    assert [(c.function, c.kind) for c in rv.candidates] == [("git_reset", "exec")]   # grounded, not a known flow
    assert tm.flows == base.flows and tm.assets == base.assets and tm.trust_boundaries == base.trust_boundaries
    assert tm.questions == base.questions + rv.questions
    assert "git_diff" in prompts[0] and "server.py" in prompts[0] and "def git_reset" in prompts[0]


def test_agent_sink_does_not_open_gate(repo, monkeypatch):
    tm = build(repo, llm=stub(REVIEW))
    assert any(c.function == "git_reset" for c in tm.agent.candidates)
    assert not any(f.sink.function == "git_reset" for f in tm.flows)

    def no_llm(*a):
        raise AssertionError("the gate must stay closed")

    monkeypatch.setattr(detector.llm, "available", no_llm)
    source = (repo / "server.py").read_text()
    assert screen(Change(file="server.py", function="git_reset", old_code="", new_code="", source=source), tm) == []
    assert not any("git_reset" in q for q in detector._questions(tm, "git_diff"))   # scoped to its own function


def test_prompt_is_bounded(tmp_path):
    for i in range(12):
        (tmp_path / f"m{i}.py").write_text("from flask import request\n@app.get('/x')\ndef v(p):\n    open(p)\n" + "#" * 20_000)
    prompts = []
    build(tmp_path, llm=stub({}, prompts))
    assert len(prompts) == 1 and len(prompts[0]) < agents.MAX_SOURCE_CHARS + 5_000
