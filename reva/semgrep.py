"""Semgrep Guardian registry scan of one saved file: corroborating evidence, never a gate of its own.

Every failure path (binary absent, registry unreachable, timeout, unparseable JSON) returns [] so the
pipeline behaves exactly as it did before Semgrep existed. Results are cached per (file, content hash):
a scan costs ~10s, and one saved file is screened once per changed function.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .types import SemgrepHit

CONFIG = "p/guardian-default"   # Semgrep Guardian's public pack: usable from the CLI with no login
TIMEOUT = 20.0
CACHE_MAX = 64
CWE_ID = re.compile(r"CWE-\d+")
_cache: dict[tuple[str, str], list[SemgrepHit]] = {}


def enabled() -> bool:
    return os.environ.get("REVA_SEMGREP", "1").lower() not in {"0", "off", "false", "no"}


def _timeout() -> float:
    try:
        return float(os.environ.get("REVA_SEMGREP_TIMEOUT", TIMEOUT))
    except ValueError:
        return TIMEOUT


def binary() -> str | None:
    """The venv's semgrep first: Reva may be started by absolute path, with its bin dir off PATH."""
    local = Path(sys.executable).with_name("semgrep")
    return str(local) if local.exists() else shutil.which("semgrep")


def _cwe(metadata: dict) -> str:
    found = CWE_ID.search(json.dumps(metadata.get("cwe", "")))
    return found.group(0) if found else ""


def parse(report: dict) -> list[SemgrepHit]:
    """Map semgrep's `results[]` to SemgrepHit, skipping anything missing a rule id or a line."""
    hits = []
    for r in report.get("results") or []:
        extra = r.get("extra") or {}
        line = int((r.get("start") or {}).get("line") or 0)
        if not r.get("check_id") or line < 1:
            continue
        hits.append(SemgrepHit(check_id=str(r["check_id"]), line=line,
                               message=" ".join(str(extra.get("message", "")).split()),
                               severity=str(extra.get("severity", "")),
                               cwe=_cwe(extra.get("metadata") or {})))
    return sorted(hits, key=lambda h: (h.line, h.check_id))


def _run(exe: str, target: Path, report: Path) -> list[SemgrepHit]:
    """--no-git-ignore: the saved file lives in a temp dir, which semgrep would otherwise skip."""
    subprocess.run([exe, "scan", "--config", CONFIG, "--no-git-ignore", "--metrics=off",
                    "--disable-version-check", "--quiet", "--json", f"--json-output={report}", str(target)],
                   capture_output=True, timeout=_timeout(), check=False)
    return parse(json.loads(report.read_text()))


def _scan(file: str, content: str) -> list[SemgrepHit]:
    exe = binary()
    if exe is None:
        return []
    try:
        with tempfile.TemporaryDirectory(prefix="reva-semgrep-") as tmp:
            target = Path(tmp) / Path(file).name
            target.write_text(content)
            return _run(exe, target, Path(tmp) / "report.json")
    except (OSError, ValueError, TypeError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def scan(file: str, content: str) -> list[SemgrepHit]:
    """Hits for the file's exact saved content. Failures cache as [] so a dead registry costs one timeout."""
    key = (file, hashlib.sha1(content.encode()).hexdigest())
    if key not in _cache:
        if len(_cache) >= CACHE_MAX:
            _cache.clear()
        _cache[key] = _scan(file, content) if enabled() else []
    return _cache[key]


def in_lines(hits: list[SemgrepHit], start: int, end: int) -> list[SemgrepHit]:
    return [h for h in hits if start <= h.line <= end]
