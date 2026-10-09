"""Build, save and load the project threat model: deterministic dataflow, then an optional agent review."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from . import agents
from .dataflow import analyze, entry_kinds
from .types import Flow, ThreatModel

SKIP = {"__pycache__", "node_modules", "venv", "env", "site-packages", "tests", "test"}
ENTRY = {
    "mcp": "Untrusted: MCP tool-call arguments chosen by an LLM client (prompt injection) -> server process",
    "http": "Untrusted: HTTP request data (path and query parameters, bodies, headers, uploads) -> application process",
}
BOUNDARY = {
    "path": "Filesystem boundary: untrusted paths must stay inside the allowed directory",
    "git_arg": "Git CLI boundary: tool-supplied values become git command-line arguments (option injection)",
    "exec": "Process boundary: untrusted values reach command execution",
    "sql": "Database boundary: untrusted values are interpolated into SQL statements",
    "http": "Egress boundary: untrusted values choose the destination of an outbound request",
    "deserialize": "Deserialization boundary: untrusted bytes are revived into live objects",
}
ASSET = {
    "path": "Files and repositories outside the configured repository directory",
    "git_arg": "Repository integrity (refs, config, working tree) reachable through git commands",
    "exec": "Host command execution",
    "sql": "Every row in the application database, not only the caller's own",
    "http": "Internal services and cloud metadata reachable from the application host",
    "deserialize": "In-process code execution through object construction",
}


def _source_files(repo_dir: Path):
    for p in sorted(repo_dir.rglob("*.py")):
        rel = p.relative_to(repo_dir)
        if not any(part in SKIP or part.startswith(".") for part in rel.parts):
            yield p, rel.as_posix()


def _question(f: Flow) -> str:
    where = f"{f.sink.function} ({f.sink.file}:{f.sink.line})"
    if f.sink.kind == "git_arg":
        return (f"Does {where} pass the tool argument '{f.source.param}' to a git command without "
                f"rejecting a leading '-' or validating it as a ref?")
    if f.sink.kind == "path":
        return (f"Does {where} use the untrusted value '{f.source.param}' as a filesystem path "
                f"without checking it is contained in the allowed repository?")
    if f.sink.kind == "sql":
        return (f"Does {where} interpolate '{f.source.param}' into a SQL statement instead of "
                f"binding it as a query parameter?")
    if f.sink.kind == "http":
        return (f"Does {where} send an outbound request to a URL built from '{f.source.param}' without "
                f"validating its scheme and host against an allowlist?")
    return f"Does {where} execute or deserialize untrusted data built from '{f.source.param}'?"


def _summary(flows: list[Flow], repo_dir: Path, llm: Callable | None) -> str:
    open_ = [f for f in flows if not f.guarded]
    text = (f"{repo_dir.name}: {len(flows)} flow(s) from untrusted input to sensitive sinks, "
            f"{len(open_)} without a recognised guard.")
    if llm is None:
        return text
    try:
        facts = "\n".join(f"{f.source.param} -> {f.sink.kind} in {f.sink.function} guarded={f.guarded}" for f in flows)
        out = llm("Write a two-sentence threat model summary for a security reviewer.",
                  f"Project {repo_dir.name}. Flows:\n{facts}", '{"summary": "string"}')
        return str(out.get("summary") or text)
    except Exception:
        return text


def build(repo_dir: Path, llm: Callable | None = None) -> ThreatModel:
    repo_dir = Path(repo_dir)
    texts = [(rel, p.read_text(errors="replace")) for p, rel in _source_files(repo_dir)]
    flows = [f for rel, text in texts for f in analyze(text, rel)]
    kinds = sorted({f.sink.kind for f in flows})
    entries = sorted({k for _, text in texts for k in entry_kinds(text)})
    boundaries = [ENTRY[k] for k in entries] or [ENTRY["mcp"]]
    boundaries += [BOUNDARY[k] for k in kinds if k in BOUNDARY]
    questions = list(dict.fromkeys(_question(f) for f in flows if not f.guarded))
    review = agents.review(repo_dir, texts, flows, llm) if llm else None
    # agent questions are "[agent] fn(): ..." so the detector only packs them for fn, and only once its gate opens
    return ThreatModel(summary=_summary(flows, repo_dir, llm), assets=[ASSET[k] for k in kinds if k in ASSET],
                       trust_boundaries=boundaries, flows=flows, questions=questions + (review.questions if review else []),
                       agent=review)


def _key(f: Flow) -> tuple:
    return (f.sink.file, f.sink.function, f.sink.kind, f.sink.line, f.sink.code, f.source.param)


def merge(model: ThreatModel, flows: list[Flow]) -> list[int]:
    """Learn flows the model has not seen (with their screening questions); return every flow's index."""
    seen = {_key(f): i for i, f in enumerate(model.flows)}
    out = []
    for f in flows:
        i = seen.get(_key(f))
        if i is None:
            i = seen[_key(f)] = len(model.flows)
            model.flows.append(f)
            if not f.guarded and _question(f) not in model.questions:
                model.questions.append(_question(f))
        out.append(i)
    return out


def relearn(model: ThreatModel, file: str, function: str, flows: list[Flow]) -> list[int]:
    """Replace every flow whose sink lies in `function`, from its freshly saved source: an edit can move
    a sink to another line or delete its guard, and the model must not keep the stale version."""
    model.flows = [f for f in model.flows if not (f.sink.file == file and f.sink.function == function)]
    return merge(model, flows)


def save(model: ThreatModel, repo_dir: Path) -> Path:
    out = Path(repo_dir) / ".reva" / "threatmodel.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(model.model_dump_json(indent=2, exclude_none=True))   # agent=None is left out of the file
    return out


def load(repo_dir: Path) -> ThreatModel | None:
    p = Path(repo_dir) / ".reva" / "threatmodel.json"
    return ThreatModel.model_validate_json(p.read_text()) if p.exists() else None
