"""Shared data contracts. Every module speaks these types; keep them small."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Status = Literal["suspected", "validating", "confirmed", "rejected", "patched"]


class Source(BaseModel):
    """Untrusted entry point, e.g. an MCP tool argument chosen by an LLM."""
    function: str
    param: str
    file: str
    line: int


class Sink(BaseModel):
    """Security-sensitive operation, e.g. filesystem path use or a git CLI call."""
    kind: Literal["path", "git_arg", "exec", "write", "sql", "http", "deserialize"]
    function: str
    file: str
    line: int
    code: str


class Flow(BaseModel):
    """Untrusted source reaching a sink; `guarded` = a recognised check lies on the path."""
    source: Source
    sink: Sink
    guarded: bool
    guards: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)  # function names along the flow


class Candidate(BaseModel):
    """An entry point or sink the agent believes the AST missed. Unverified: it never opens the gate."""
    role: Literal["entry", "sink"]
    kind: str
    file: str
    function: str
    reason: str
    decision: Literal["", "accepted", "dismissed"] = ""   # a reviewer's call; recorded, never opens the gate


class AgentReview(BaseModel):
    """Everything agent-derived lives here, apart from the deterministic model. Nothing in it is proven."""
    provenance: Literal["agent"] = "agent"
    assets: list[str]
    trust_boundaries: list[str]
    questions: list[str]
    candidates: list[Candidate]


class ThreatModel(BaseModel):
    summary: str
    assets: list[str]
    trust_boundaries: list[str]
    flows: list[Flow]
    questions: list[str]  # project-specific screening questions derived from the model
    agent: AgentReview | None = None  # optional agent review; None = purely deterministic model


class SemgrepHit(BaseModel):
    """One Semgrep registry rule firing inside a changed function: corroboration, never proof."""
    check_id: str
    line: int
    message: str
    severity: str
    cwe: str = ""


class Finding(BaseModel):
    id: str
    title: str
    file: str
    function: str
    line: int
    cwe: str
    status: Status = "suspected"
    confidence: float = 0.0       # detector probability, 0..1
    impact: int = 0               # 1..5, set after validation
    likelihood: int = 0           # 1..5, set after validation
    evidence: str = ""            # sandbox output proving exploitation
    exploit: str = ""             # script that reproduces it
    patch: str = ""               # unified diff
    validation: str = ""          # the same exploit re-run against the patched copy
    resolution: Literal["", "applied", "dismissed"] = ""   # what the developer did with it
    reasoning: str = ""
    semgrep: list[str] = Field(default_factory=list)   # Semgrep rule ids that corroborated this finding
