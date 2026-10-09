"""Play the coding agent: stream the original function bodies back into target/ as small saved edits."""
import argparse
import ast
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "target" / "src" / "mcp_server_git" / "server.py"
STEPS = sorted((ROOT / "demo" / "steps").glob("*.py"))


def put_function(text: str, new: str) -> str:
    """Replace the top-level function named like `new`, or insert it before `async def serve`."""
    name = ast.parse(new).body[0].name
    lines = text.splitlines(True)
    body = ast.parse(text).body
    old = next((n for n in body if isinstance(n, ast.FunctionDef) and n.name == name), None)
    if old:
        return "".join(lines[:old.lineno - 1]) + new + "".join(lines[old.end_lineno:])
    anchor = next(n for n in body if isinstance(n, ast.AsyncFunctionDef) and n.name == "serve")
    return "".join(lines[:anchor.lineno - 1]) + new + "\n\n" + "".join(lines[anchor.lineno - 1:])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=4.0, help="seconds between saved edits")
    ap.add_argument("--step", type=int, help="apply only step N (1-based) and exit")
    args = ap.parse_args()
    chosen = [STEPS[args.step - 1]] if args.step else STEPS
    for i, step in enumerate(chosen):
        FILE.write_text(put_function(FILE.read_text(), step.read_text()))
        print(f"saved {step.name}", flush=True)
        if i < len(chosen) - 1:
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
