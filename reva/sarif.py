"""SARIF 2.1.0 export, so proven findings load into GitHub code scanning, IDE SARIF viewers and CI gates.

Only proven findings are exported (status confirmed or patched): the export keeps the same promise as the UI.
A verified patch is attached as a SARIF `fix`; the sandbox evidence and exploit travel in `properties`.
"""
from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .types import Finding, Flow, ThreatModel

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/AmL-Dev/Reva"
EXPORTED = ("confirmed", "patched")
NAMES = {"CWE-22": "Path traversal", "CWE-78": "Command injection", "CWE-88": "Argument injection",
         "CWE-89": "SQL injection", "CWE-502": "Unsafe deserialization", "CWE-918": "Server-side request forgery"}
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")


def _version() -> str:
    try:
        return version("reva")
    except PackageNotFoundError:
        return "0.0.0"


def _rule(cwe: str) -> dict:
    num = cwe.split("-")[-1]
    name = NAMES.get(cwe, cwe)
    return {"id": f"reva/{cwe}", "name": name.title().replace(" ", "").replace("-", ""),
            "shortDescription": {"text": f"{name} ({cwe})"},
            "fullDescription": {"text": f"Untrusted input reaches a sensitive operation ({cwe}); "
                                        "reported only after Reva exploited it in a sandbox."},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{num}.html",
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", f"external/cwe/cwe-{num}"], "precision": "very-high"}}


def _severity(f: Finding) -> str:
    """GitHub's `security-severity`: 0-10. Risk is impact x likelihood on 1..25."""
    return f"{min(10.0, max(1.0, f.impact * f.likelihood / 2.5)):.1f}" if f.impact else "7.0"


def _location(file: str, line: int, message: str = "") -> dict:
    loc = {"physicalLocation": {"artifactLocation": {"uri": file, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": max(1, line)}}}
    if message:
        loc["message"] = {"text": message}
    return loc


def _flow_for(f: Finding, tm: ThreatModel | None) -> Flow | None:
    param = (re.search(r"unvalidated (\S+) reaches", f.title) or [None, None])[1]
    for fl in tm.flows if tm else ():
        if fl.sink.function == f.function and fl.sink.file == f.file and (param is None or fl.source.param == param):
            return fl
    return None


def _code_flow(fl: Flow) -> dict:
    steps = [_location(fl.source.file, fl.source.line, f"untrusted input `{fl.source.param}` enters {fl.source.function}()"),
             _location(fl.sink.file, fl.sink.line, f"reaches {fl.sink.kind} sink `{fl.sink.code}`")]
    return {"threadFlows": [{"locations": [{"location": s} for s in steps]}]}


def _replacements(diff: str) -> list[dict]:
    """Each unified-diff hunk becomes one whole-line replacement of the original file."""
    out, lines, i = [], diff.splitlines(), 0
    while i < len(lines):
        m = HUNK.match(lines[i])
        i += 1
        if not m:
            continue
        start, count = int(m[1]), int(m[2] if m[2] is not None else 1)
        new = []
        while i < len(lines) and not lines[i].startswith("@@"):
            if lines[i][:1] in (" ", "+"):
                new.append(lines[i][1:])
            i += 1
        first = start if count else start + 1          # a pure insertion hunk names the line before it
        out.append({"deletedRegion": {"startLine": first, "startColumn": 1, "endLine": first + count, "endColumn": 1},
                    "insertedContent": {"text": "".join(line + "\n" for line in new)}})
    return out


def _result(f: Finding, tm: ThreatModel | None) -> dict:
    proof = f.evidence.split(" -- ")[0].strip()
    res = {"ruleId": f"reva/{f.cwe}", "level": "error",
           "message": {"text": f"{f.title}. Proven in a sandbox: {proof}" if proof else f.title},
           "locations": [_location(f.file, f.line)],
           "partialFingerprints": {"revaFindingId/v1": f.id},
           "properties": {"security-severity": _severity(f), "status": f.status, "confidence": f.confidence,
                          "impact": f.impact, "likelihood": f.likelihood, "exploit": f.exploit,
                          "evidence": f.evidence, "fixVerified": f.status == "patched", "validation": f.validation,
                          "resolution": f.resolution, "semgrep": f.semgrep}}
    if fl := _flow_for(f, tm):
        res["codeFlows"] = [_code_flow(fl)]
    if f.patch and (reps := _replacements(f.patch)):
        what = "Verified fix: the same exploit no longer reproduces" if f.status == "patched" else "Proposed fix (not verified)"
        res["fixes"] = [{"description": {"text": what},
                         "artifactChanges": [{"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                                              "replacements": reps}]}]
    return res


def build(findings: list[Finding], repo: str | Path | None = None, tm: ThreatModel | None = None) -> dict:
    proven = [f for f in findings if f.status in EXPORTED]
    cwes = sorted({f.cwe for f in proven})
    run = {"tool": {"driver": {"name": "Reva", "version": _version(), "informationUri": INFO_URI,
                               "rules": [_rule(c) for c in cwes]}},
           "results": [_result(f, tm) | {"ruleIndex": cwes.index(f.cwe)} for f in proven],
           "columnKind": "unicodeCodePoints"}
    if repo:
        run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": Path(repo).resolve().as_uri() + "/"}}
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
