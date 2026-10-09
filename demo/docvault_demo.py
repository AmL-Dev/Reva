"""The 60-second DocVault demo: stage a clean target, then play the coding agent in a terminal.

    python demo/docvault_demo.py stage        # fresh stage/docvault, latent issue already fixed
    reva init stage/docvault                  # threat model (+ agent review when the LLM is configured)
    reva watch stage/docvault                 # UI on http://127.0.0.1:8765
    python demo/docvault_demo.py agent        # backlog item 2 in two saves (add --tickets 2,4 for the SSRF too)

The agent is scripted: it replays one naive implementation of "full-text search" so every take is identical.
Everything Reva does in response (screening, sandbox proof, patch, re-test) is the real pipeline.
"""
import argparse
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "targets" / "docvault"
STAGE = ROOT / "stage" / "docvault"
REPORTS = STAGE / "docvault" / "routers" / "reports.py"
ADMIN = STAGE / "docvault" / "routers" / "admin.py"

PARAM_OLD = "    owner: str | None = Query(default=None, max_length=200),\n"
PARAM_NEW = PARAM_OLD + "    q: str | None = Query(default=None, max_length=200),\n"
FILTER_AT = "        params.append(owner)\n"
FILTER = FILTER_AT + "    if q:\n        where.append(f\"reports.title LIKE '%{q}%'\")\n"
INTEGRATIONS = STAGE / "docvault" / "routers" / "integrations.py"
LOGO_OLD = """    try:
        source = validate_logo_url(body.url)
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Redirects are not followed: the allowlist check above applies to the URL we
    # were given, and an allowlisted host must not be able to bounce us onto a
    # host that is not allowlisted. The CDN's object paths are already final.
    with httpx.Client(timeout=OUTBOUND_TIMEOUT, follow_redirects=False) as client:
        try:
            response = client.get(source)"""
LOGO_NEW = """    # Design pastes short links that redirect to the CDN, so the host we are given
    # is not the CDN host: follow the redirects and fetch whatever they point to.
    with httpx.Client(timeout=OUTBOUND_TIMEOUT, follow_redirects=True) as client:
        try:
            response = client.get(body.url)"""

# ticket -> (task, [(narration, file, old, new, note)]): every step is one save
TICKETS = {
    2: ("Backlog #2: full-text search over reports (title, partial words, one query param).", [
        ("Adding a `q` query parameter to GET /reports.", REPORTS, PARAM_OLD, PARAM_NEW, "+1 line"),
        ("Matching partial words in the title with LIKE.", REPORTS, FILTER_AT, FILTER, "+2 lines")]),
    4: ("Backlog #4: import a team logo from a URL; Design's short links redirect.", [
        ("Short links redirect off the allowlisted host: following redirects, fetching the URL as given.",
         INTEGRATIONS, LOGO_OLD, LOGO_NEW, "+3 -9 lines")]),
}
LATENT_OLD = "    target = DIAGNOSTICS_ROOT / name\n"
LATENT_NEW = "    target = ensure_within(DIAGNOSTICS_ROOT, name)\n"

DIM, BOLD, PURPLE, GREEN, RESET = "\033[2m", "\033[1m", "\033[38;5;141m", "\033[32m", "\033[0m"


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if old not in text:
        sys.exit(f"{path.relative_to(ROOT)} is not in the expected state; run `stage` again")
    path.write_text(text.replace(old, new, 1))


def stage(_args) -> None:
    shutil.rmtree(STAGE, ignore_errors=True)
    shutil.copytree(SOURCE, STAGE, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".reva", "var"))
    replace_once(ADMIN, LATENT_OLD, LATENT_NEW)   # the demo opens on an all-guarded threat model
    print(f"staged {STAGE.relative_to(ROOT)}\nnext: reva init {STAGE.relative_to(ROOT)} && reva watch {STAGE.relative_to(ROOT)}")


def say(text: str, pace: float, style: str = "") -> None:
    sys.stdout.write(style)
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(0.012 * pace)
    print(RESET if style else "")


def agent(args) -> None:
    pace = 0.0 if args.fast else 1.0

    def pause(seconds: float) -> None:
        time.sleep(seconds * pace)

    for n, ticket in enumerate(int(t) for t in args.tickets.split(",")):
        task, steps = TICKETS[ticket]
        if n:
            time.sleep(args.gap)
        print(f"{PURPLE}>{RESET} {BOLD}{task}{RESET}\n")
        pause(1.2)
        for i, (say_, path, old, new, note) in enumerate(steps):
            if i:
                time.sleep(args.gap)  # never scaled: two saves closer than the watcher's debounce arrive as one
            say(say_, pace)
            replace_once(path, old, new)
            print(f"  {GREEN}saved{RESET} {path.relative_to(STAGE)}  {DIM}({note}){RESET}")
        pause(1.0)
        say("Done.\n", pace)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stage", help="fresh stage/docvault with the latent read_diagnostic issue fixed").set_defaults(fn=stage)
    a = sub.add_parser("agent", help="play the coding agent: one save per step of each ticket")
    a.add_argument("--tickets", default="2", help="comma-separated backlog items to implement, e.g. 2,4")
    a.add_argument("--gap", type=float, default=6.0, help="seconds between the two saves")
    a.add_argument("--fast", action="store_true", help="no typing effect or pauses")
    a.set_defaults(fn=agent)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
