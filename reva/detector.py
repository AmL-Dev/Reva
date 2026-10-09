"""Real-time detector: static gate, context pack, one LLM call, deterministic calibration."""
from __future__ import annotations

import ast
import hashlib
import re
import time
from dataclasses import dataclass

from . import analytics, llm, semgrep
from .types import Finding, Flow, SemgrepHit, ThreatModel

THRESHOLD = 0.5
BASE_UNGUARDED = 0.55      # an unguarded source->sink flow exists
SIBLING_BONUS = 0.2        # same sink kind is guarded elsewhere in the codebase
SEMGREP_BONUS = 0.1        # a Semgrep Guardian rule fires inside the function, on top of an unguarded flow
LLM_WEIGHT = 0.6           # weight of the LLM probability vs static evidence
USE_LLM = True             # reva/corpus.py clears this to build volume from static evidence alone
PRIOR_WEIGHT = 0.15        # share of the static score taken from the measured hit rate of this shape
PRIOR_MIN_SAMPLES = 20     # proven labels required before that measurement is trusted at all

GENERIC_QUESTIONS = [
    "Can an attacker-controlled argument reach the sensitive operation without any validation?",
    "Could the argument be interpreted as a command-line option or escape the intended directory?",
    "Is the missing check one that comparable code in this codebase already performs?",
]
CWE_BY_SINK = {"path": "CWE-22", "write": "CWE-22", "git_arg": "CWE-88", "exec": "CWE-78",
               "sql": "CWE-89", "http": "CWE-918", "deserialize": "CWE-502"}
SYSTEM = (
    "You are a precise application-security reviewer screening one changed function. "
    "Each question is phrased so that 'yes' means a vulnerability exists. Be skeptical: if a guard "
    "on the path neutralises the issue, answer no with a low probability."
)
SCHEMA = '{"answers":[{"question":str,"answer":"yes"|"no","justification":str(one line),"probability":float 0..1}]}'


@dataclass
class Change:
    file: str
    function: str
    old_code: str
    new_code: str
    source: str


def _flows(change: Change, tm: ThreatModel) -> tuple[list[Flow], list[Flow]]:
    from .dataflow import analyze, flows_for_function

    all_flows = analyze(change.source, change.file)
    return flows_for_function(all_flows, change.function), all_flows + tm.flows


def discover(change: Change) -> list[Flow]:
    """Flows the changed function owns, computed from the source as just saved."""
    from .dataflow import analyze, flows_for_function

    return flows_for_function(analyze(change.source, change.file), change.function)


def _sibling_guards(kind: str, function: str, pool: list[Flow]) -> list[str]:
    seen = {g for f in pool if f.guarded and f.sink.kind == kind and f.sink.function != function for g in f.guards}
    return sorted(seen)


def _callers(change: Change) -> list[str]:
    pat = re.compile(rf"\b{re.escape(change.function)}\(")
    lines = change.source.splitlines()
    return [f"{i}: {ln.strip()}" for i, ln in enumerate(lines, 1) if pat.search(ln) and not ln.lstrip().startswith(("def ", "async def "))][:5]


def _span(change: Change) -> tuple[int, int]:
    """Line range of the changed function in the file as saved; (0, 0) when it cannot be located."""
    try:
        tree = ast.parse(change.source)
    except SyntaxError:
        return 0, 0
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == change.function:
            return n.lineno, n.end_lineno or n.lineno
    return 0, 0


def _semgrep(change: Change) -> list[SemgrepHit]:
    start, end = _span(change)
    return semgrep.in_lines(semgrep.scan(change.file, change.source), start, end) if start else []


def _questions(tm: ThreatModel, function: str) -> list[str]:
    own = [q for q in tm.questions if function in q or "()" not in q]
    return own[:6] + GENERIC_QUESTIONS


def _context(change: Change, tm: ThreatModel, flows: list[Flow], guards: list[str], questions: list[str],
             hits: list[SemgrepHit]) -> str:
    flow_lines = [f"- {f.source.param} -> {f.sink.kind} `{f.sink.code}` (line {f.sink.line}) via {' > '.join(f.path) or f.sink.function}" for f in flows]
    hit_lines = [f"- {h.check_id} (line {h.line}, {h.severity}{', ' + h.cwe if h.cwe else ''}): {h.message[:220]}" for h in hits]
    return "\n".join([
        f"THREAT MODEL: {tm.summary}",
        "TRUST BOUNDARIES: " + "; ".join(tm.trust_boundaries),
        f"FILE: {change.file}  FUNCTION: {change.function}",
        "UNGUARDED FLOWS:\n" + "\n".join(flow_lines),
        "GUARDS USED ELSEWHERE FOR THIS SINK KIND: " + (", ".join(guards) or "none"),
        f"SEMGREP {semgrep.CONFIG} RULES INSIDE THIS FUNCTION (pattern matches, not proof; judge them "
        "against the threat model above):\n" + ("\n".join(hit_lines) or "none fired"),
        "CALLERS:\n" + ("\n".join(_callers(change)) or "none found"),
        f"OLD CODE:\n{change.old_code or '(new function)'}",
        f"NEW CODE:\n{change.new_code}",
        "QUESTIONS:\n" + "\n".join(f"{i}. {q}" for i, q in enumerate(questions, 1)),
    ])


def vulnerability_probability(answer: dict) -> float:
    """P(a vulnerability exists) from one answer.

    `probability` is the model's confidence in *its own answer*, not in the vulnerability. Every
    question is phrased so that "yes" means vulnerable, so a confident "no" is evidence AGAINST and
    must be inverted: `{"answer": "no", "probability": 0.8}` means an 80% belief that the code is
    safe, i.e. 0.2 here. Reading it as 0.8 is how a correct "no" used to raise the score.
    Anything that is not an explicit "yes" is read as "no", which can only make Reva quieter.
    """
    p = min(1.0, max(0.0, float(answer["probability"])))
    return p if str(answer.get("answer", "")).strip().lower() == "yes" else 1.0 - p


def _llm_probability(prompt: str) -> tuple[float, str] | None:
    if not USE_LLM or not llm.available():
        return None
    try:
        answers = llm.complete_json(SYSTEM, prompt, SCHEMA).get("answers", [])
        probs = [vulnerability_probability(a) for a in answers]
    except (RuntimeError, KeyError, TypeError, ValueError):
        return None
    if not probs:
        return None
    notes = " | ".join(f"{a.get('answer')}: {a.get('justification', '')}" for a in answers if a.get("answer") == "yes")
    return sum(probs) / len(probs), notes


def blend_prior(static: float, prior: analytics.Prior | None) -> float:
    """Take PRIOR_WEIGHT of the static score from the measured hit rate of this shape.

    A convex combination of two values in [0, 1], so it cannot leave [0, 1] and cannot move the
    score by more than PRIOR_WEIGHT. Below PRIOR_MIN_SAMPLES proven labels it returns `static`
    unchanged, which is why a near-empty table scores exactly like the hand-tuned constants.
    """
    if prior is None or prior.samples < PRIOR_MIN_SAMPLES:
        return static
    return (1 - PRIOR_WEIGHT) * static + PRIOR_WEIGHT * prior.rate


def calibrate(unguarded: bool, sibling_guarded: bool, p_llm: float | None, semgrep_hit: bool = False,
              prior: analytics.Prior | None = None) -> float:
    """Semgrep and the prior only ever adjust an unguarded flow: whatever they say, a guarded flow
    stays at 0.0. Neither can raise a finding of its own."""
    if not unguarded:
        return 0.0
    static = min(1.0, BASE_UNGUARDED + (SIBLING_BONUS if sibling_guarded else 0.0)
                 + (SEMGREP_BONUS if semgrep_hit else 0.0))
    static = blend_prior(static, prior)
    return round(static if p_llm is None else (1 - LLM_WEIGHT) * static + LLM_WEIGHT * p_llm, 3)


def _reasoning(group: list[Flow], kind: str, guards: list[str], rules: list[str],
               notes: str, prior: analytics.Prior | None) -> str:
    out = f"Unguarded flow {group[0].source.param} -> {kind} sink `{group[0].sink.code}`."
    if guards:
        out += f" Sibling code guards this sink kind with: {', '.join(guards)}."
    if rules:
        out += f" Semgrep {semgrep.CONFIG} corroborates: {', '.join(rules)}."
    if prior and prior.samples >= PRIOR_MIN_SAMPLES:
        out += (f" Calibration memory: {prior.rate:.0%} of {prior.samples} proven screenings of this "
                f"shape{' with ' + prior.rule if prior.rule else ''} were confirmed.")
    if notes:
        out += f" LLM: {notes}"
    return out


def _screen_kind(change: Change, tm: ThreatModel, group: list[Flow], pool: list[Flow],
                 hits: list[SemgrepHit], rules: list[str], timings: dict) -> Finding | None:
    """One sink kind. The prior is read before the LLM call, so it can withhold one."""
    kind = group[0].sink.kind
    guards = _sibling_guards(kind, change.function, pool)
    cwe = CWE_BY_SINK[kind]
    fid = hashlib.sha1(f"{change.file}:{change.function}:{cwe}".encode()).hexdigest()[:10]
    t = time.perf_counter()
    prior = analytics.prior(kind, False, rules)
    timings["prior_ms"] = (time.perf_counter() - t) * 1000
    args = (True, bool(guards), None, bool(hits), prior)
    verdict = None
    if calibrate(*args) >= THRESHOLD:        # a shape this memory has never confirmed buys no LLM call
        t = time.perf_counter()
        verdict = _llm_probability(_context(change, tm, group, guards, _questions(tm, change.function), hits))
        timings["llm_ms"] = (time.perf_counter() - t) * 1000
    p_llm = verdict[0] if verdict else None
    confidence = calibrate(True, bool(guards), p_llm, bool(hits), prior)
    escalated = confidence >= THRESHOLD
    timings["total_ms"] = sum(timings.values())
    analytics.log_screening(change.file, change.function, kind, False, guards, rules, p_llm,
                            confidence, escalated, prior, timings, fid if escalated else "")
    if not escalated:
        return None
    return Finding(id=fid, confidence=confidence, semgrep=rules, cwe=cwe,
                   title=f"{cwe}: unvalidated {group[0].source.param} reaches {kind} sink in {change.function}",
                   file=change.file, function=change.function, line=group[0].sink.line,
                   reasoning=_reasoning(group, kind, guards, rules, verdict[1] if verdict else "", prior))


def screen(change: Change, tm: ThreatModel) -> list[Finding]:
    t = time.perf_counter()
    mine, pool = _flows(change, tm)
    unguarded = [f for f in mine if not f.guarded]
    gate_ms = (time.perf_counter() - t) * 1000
    if not unguarded:
        # the gate: no unguarded flow, no finding and no Semgrep subprocess, whatever Semgrep would say.
        analytics.log_screening(change.file, change.function, mine[0].sink.kind if mine else "",
                                True, sorted({g for f in mine for g in f.guards}), [], None, 0.0,
                                False, None, {"gate_ms": gate_ms, "total_ms": gate_ms})
        return []
    t = time.perf_counter()
    hits = _semgrep(change)
    semgrep_ms = (time.perf_counter() - t) * 1000
    rules = sorted({h.check_id for h in hits})
    found = [_screen_kind(change, tm, [f for f in unguarded if f.sink.kind == kind], pool, hits, rules,
                          {"gate_ms": gate_ms, "semgrep_ms": semgrep_ms})
             for kind in dict.fromkeys(f.sink.kind for f in unguarded)]
    return [f for f in found if f is not None]
