"""Bulk screening over many repositories, to ground the calibration memory in real volume.

Lives in the package rather than demo/ because it must run the production gate, the production
screening path and the production sandbox: a demo script would have to re-wire all three, and a
corpus built from a re-wiring would not calibrate the thing that actually runs.

A finding is only labelled `confirmed`/`rejected` when a sandbox probe could really execute against
the repository. Everywhere else the label is `suspected`, which the prior rollup excludes - a
corpus must not teach the detector from proofs that were never run.
"""
from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from . import analytics, detector, llm, server, threatmodel, validate

log = logging.getLogger("reva.corpus")


def repos(paths: list[str], subdirs: bool) -> list[Path]:
    roots = [Path(p).resolve() for p in paths]
    if subdirs:
        roots = [d for r in roots for d in sorted(r.iterdir()) if d.is_dir() and not d.name.startswith(".")]
    return [r for r in roots if r.is_dir()]


def _label(finding, root: Path, provable: bool) -> str:
    """Only a probe written for *this* function proves anything. The CWE fallback would run some
    other function's exploit and call the result a label, which is how a corpus poisons itself."""
    if not provable or (finding.cwe, finding.function) not in validate.PROBES:
        return "suspected"
    return validate.validate(finding, root).status


def screen_repo(root: Path, use_llm: bool, prove: bool) -> tuple[int, int, int]:
    """Screen every function in `root`. Returns (screenings, escalations, proven labels)."""
    analytics.set_repo(root.name)
    tm = threatmodel.build(root, llm.complete_json if use_llm else None)
    provable = prove and validate.find_server_dir(root) is not None
    rows = flagged = proven = 0
    for p in server.py_files(root):
        text = p.read_text(errors="replace")
        for name, src in server.functions_of(text).items():
            change = detector.Change(p.relative_to(root).as_posix(), name, "", src, text)
            rows += 1
            try:
                findings = detector.screen(change, tm)
            except Exception:
                log.debug("screening failed for %s:%s", change.file, name)
                continue
            for f in findings:
                flagged += 1
                label = _label(f, root, provable)
                analytics.log_outcome(f.id, label)
                proven += label in ("confirmed", "rejected")
    return rows, flagged, proven


def run(paths: list[str], subdirs: bool = False, use_llm: bool = False, prove: bool = True) -> dict:
    detector.USE_LLM = use_llm
    if not analytics.start():
        raise SystemExit("reva corpus: no ClickHouse configured (set REVA_CLICKHOUSE_HOST)")
    if not analytics.wait_ready():
        raise SystemExit("reva corpus: ClickHouse unreachable; nothing would be written")
    totals = {"repos": 0, "screenings": 0, "escalations": 0, "proven": 0}
    started = time.perf_counter()
    for root in repos(paths, subdirs):
        t = time.perf_counter()
        rows, flagged, proven = screen_repo(root, use_llm, prove)
        print(f"{root.name}: {rows} screened, {flagged} flagged, {proven} proven "
              f"({rows / max(time.perf_counter() - t, 1e-6) * 60:.0f} rows/min)", flush=True)
        totals["repos"] += 1
        for k, v in (("screenings", rows), ("escalations", flagged), ("proven", proven)):
            totals[k] += v
    totals["seconds"] = round(time.perf_counter() - started, 1)
    totals["rows_per_min"] = round(totals["screenings"] / max(totals["seconds"], 1e-6) * 60)
    analytics.close()
    return totals


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="reva corpus", description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", help="repository paths, or directories of checkouts with --subdirs")
    ap.add_argument("--subdirs", action="store_true", help="treat each immediate subdirectory as a repo")
    ap.add_argument("--llm", action="store_true", help="also make the LLM call (slow, costs tokens)")
    ap.add_argument("--no-prove", action="store_true", help="skip the sandbox; every label is 'suspected'")
    args = ap.parse_args(argv)
    totals = run(args.paths, args.subdirs, args.llm, not args.no_prove)
    print(f"\n{totals['repos']} repos  {totals['screenings']} screenings  {totals['escalations']} escalations  "
          f"{totals['proven']} proven labels  in {totals['seconds']}s  ({totals['rows_per_min']} rows/min)")


if __name__ == "__main__":
    main()
