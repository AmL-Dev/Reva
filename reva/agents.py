"""Agent review of the threat model: one bounded LLM pass proposing what the AST cannot see.

Advisory only. Proposals are grounded against the real code (unknown files or functions are dropped)
and stored under ThreatModel.agent; none of them becomes a Flow, so none can open the static gate.
Cost: one complete_json call (at most two requests if the first reply has no JSON), a prompt of at
most ~MAX_PROMPT_CHARS characters, llm.MAX_TOKENS output, abandoned after TIMEOUT seconds.
"""
from __future__ import annotations

import ast
import os
import threading
from pathlib import Path
from typing import Callable

from .dataflow import entry_kinds
from .types import AgentReview, Candidate, Flow

MAX_SOURCE_CHARS = 40_000
MAX_FILE_CHARS = 8_000
MAX_TREE = 150
MAX_FLOWS = 60
MAX_ITEMS = 8
MAX_TEXT = 300
TIMEOUT = 180.0
SKIP = {"__pycache__", "node_modules", "venv", "env", "site-packages", ".git"}
SYSTEM = (
    "You are a senior threat modeller reviewing a codebase after a deterministic taint analysis. "
    "Propose only what that analysis cannot see: assets worth protecting and trust boundaries specific "
    "to THIS project, screening questions for named functions, and entry points or sinks it missed "
    "(indirection, frameworks it does not model, config-driven routes). Every question must be phrased so "
    "that 'yes' means a vulnerability exists. Name only files and functions that appear in the source shown."
)
SCHEMA = ('{"assets":[str],"trust_boundaries":[str],"questions":[{"function":str,"question":str}],'
          '"candidates":[{"role":"entry"|"sink","kind":str,"file":str,"function":str,"reason":str}]}')


def enabled() -> bool:
    return os.environ.get("REVA_AGENT", "1") != "0"


def _tree(repo_dir: Path) -> list[str]:
    files = (p.relative_to(repo_dir) for p in sorted(repo_dir.rglob("*")) if p.is_file())
    return [r.as_posix() for r in files if not any(x in SKIP or x.startswith(".") for x in r.parts)][:MAX_TREE]


def _sources(texts: list[tuple[str, str]], flows: list[Flow]) -> str:
    hot = {f.sink.file for f in flows if not f.guarded}
    wanted = {f.sink.file for f in flows} | {f.source.file for f in flows}
    picked = sorted((rel, t) for rel, t in texts if rel in wanted or entry_kinds(t))
    out, budget = [], MAX_SOURCE_CHARS
    for rel, text in sorted(picked, key=lambda p: p[0] not in hot):
        body = text[:min(MAX_FILE_CHARS, budget)]
        if not body:
            break
        out.append(f"--- {rel}{' (truncated)' if len(body) < len(text) else ''}\n{body}")
        budget -= len(body)
    return "\n".join(out)


def _prompt(repo_dir: Path, texts: list[tuple[str, str]], flows: list[Flow]) -> str:
    facts = [f"- {f.source.function}({f.source.param}) -> {f.sink.kind} `{f.sink.code}` in {f.sink.function} "
             f"({f.sink.file}:{f.sink.line}) guarded={f.guarded}" for f in flows[:MAX_FLOWS]]
    return "\n".join([f"PROJECT: {repo_dir.name}", "FILE TREE:", *_tree(repo_dir),
                      "DETERMINISTIC FLOWS (already known, do not repeat):", *(facts or ["none"]),
                      "SOURCE OF FILES WITH ENTRY POINTS OR SINKS:", _sources(texts, flows)])


def _functions(texts: list[tuple[str, str]]) -> dict[str, set[str]]:
    out = {}
    for rel, text in texts:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        out[rel] = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return out


def _strings(items) -> list[str]:
    items = items if isinstance(items, list) else []
    return list(dict.fromkeys(s.strip()[:MAX_TEXT] for s in items if isinstance(s, str) and s.strip()))[:MAX_ITEMS]


def _questions(items, funcs: dict[str, set[str]]) -> list[str]:
    known = set().union(*funcs.values()) if funcs else set()
    out = [f"[agent] {q['function']}(): {str(q.get('question', '')).strip()[:MAX_TEXT]}"
           for q in (items if isinstance(items, list) else [])
           if isinstance(q, dict) and isinstance(q.get("function"), str) and q["function"] in known and str(q.get("question", "")).strip()]
    return list(dict.fromkeys(out))[:MAX_ITEMS]


def _candidates(items, funcs: dict[str, set[str]], flows: list[Flow]) -> list[Candidate]:
    seen = {("sink", f.sink.file, f.sink.function, f.sink.kind) for f in flows}
    seen |= {("entry", f.source.file, f.source.function, k) for f in flows for k in ("http", "mcp")}
    out = []
    for c in items if isinstance(items, list) else []:
        try:
            cand = Candidate(**{k: str(c[k])[:MAX_TEXT] for k in ("role", "kind", "file", "function", "reason")})
        except (TypeError, KeyError, ValueError):
            continue
        if cand.function in funcs.get(cand.file, ()) and (cand.role, cand.file, cand.function, cand.kind) not in seen:
            seen.add((cand.role, cand.file, cand.function, cand.kind))
            out.append(cand)
    return out[:MAX_ITEMS]


def _call(llm: Callable, prompt: str) -> dict | None:
    """A daemon thread, so a hung endpoint costs at most TIMEOUT and never blocks interpreter exit."""
    box = {}

    def run():
        try:
            box["out"] = llm(SYSTEM, prompt, SCHEMA)
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(TIMEOUT)
    out = box.get("out")
    return out if isinstance(out, dict) else None


def review(repo_dir: Path, texts: list[tuple[str, str]], flows: list[Flow], llm: Callable) -> AgentReview | None:
    """None whenever the agent is off, unreachable, slow, or says nothing usable."""
    out = _call(llm, _prompt(repo_dir, texts, flows)) if enabled() else None
    if out is None:
        return None
    funcs = _functions(texts)
    rv = AgentReview(assets=_strings(out.get("assets")), trust_boundaries=_strings(out.get("trust_boundaries")),
                     questions=_questions(out.get("questions"), funcs),
                     candidates=_candidates(out.get("candidates"), funcs, flows))
    return rv if rv.assets or rv.trust_boundaries or rv.questions or rv.candidates else None
