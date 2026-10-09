"""Build the demo target: vulnerable mcp_server_git at d9c4547 with git_diff/git_checkout stubbed out.

The original bodies (and a few partial drafts) are written to demo/steps/ for replay.py to stream back in.
"""
import argparse
import ast
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLONE = str(ROOT / ".cache" / "servers")
UPSTREAM = "https://github.com/modelcontextprotocol/servers"
COMMIT = "d9c4547"
FILE = "mcp_server_git/server.py"
STUB = "    raise NotImplementedError\n"

DIFF_HEAD = "def git_diff(repo: git.Repo, target: str, context_lines: int = DEFAULT_CONTEXT_LINES) -> str:\n"
# Partial drafts of git_diff, ending in the original body (appended from the clone).
DRAFTS = {
    "01_git_diff_args.py": DIFF_HEAD + '    args = [f"--unified={context_lines}"]\n    raise NotImplementedError\n',
    "02_git_diff_target.py": DIFF_HEAD + '    args = [f"--unified={context_lines}"]\n    args.append(target)\n    raise NotImplementedError\n',
}
CONTROL = '''def git_tag_list(repo: git.Repo, pattern: str | None = None) -> str:
    if pattern is not None and (not pattern.isprintable() or pattern.startswith("-")):
        raise ValueError(f"Invalid pattern: {pattern!r}")
    tags = sorted(t.name for t in repo.tags)
    if pattern:
        tags = [t for t in tags if pattern in t]
    return "\\n".join(tags)
'''


def func_span(src: str, name: str) -> tuple[int, int]:
    node = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return node.lineno - 1, node.end_lineno


def stub_function(src: str, name: str) -> tuple[str, str]:
    a, b = func_span(src, name)
    lines = src.splitlines(True)
    original = "".join(lines[a:b])
    return "".join(lines[:a + 1] + [STUB] + lines[b:]), original


def archive(clone: str) -> bytes:
    """`git archive` of src/git at COMMIT, cloning upstream on first run."""
    if not Path(clone, ".git").exists() and clone == CLONE:
        Path(clone).parent.mkdir(parents=True, exist_ok=True)
        if subprocess.run(["git", "clone", "--filter=blob:none", UPSTREAM, clone]).returncode != 0:
            raise SystemExit(f"could not clone {UPSTREAM} into {clone}.\n"
                             f"Clone it by hand and pass it: python demo/make_snapshot.py --clone /path/to/servers")
    got = subprocess.run(["git", "-C", clone, "archive", COMMIT, "src/git"], capture_output=True)
    if got.returncode != 0:
        raise SystemExit(f"{clone} is not a clone of {UPSTREAM} at {COMMIT}: {got.stderr.decode().strip()}\n"
                         f"Pass a good one: python demo/make_snapshot.py --clone /path/to/servers")
    return got.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clone", default=CLONE, help=f"clone of {UPSTREAM} (cloned into {CLONE} if absent)")
    ap.add_argument("--out", default=str(ROOT / "target"))
    args = ap.parse_args()
    tar = archive(args.clone)
    out = Path(args.out)
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subprocess.run(["tar", "-x", "--strip-components=2", "-C", str(out)], input=tar, check=True)

    path = out / "src" / FILE
    src = path.read_text()
    steps = ROOT / "demo" / "steps"
    shutil.rmtree(steps, ignore_errors=True)
    steps.mkdir()
    for name, fname in (("git_diff", "03_git_diff.py"), ("git_checkout", "04_git_checkout.py")):
        src, original = stub_function(src, name)
        (steps / fname).write_text(original)
    for fname, body in DRAFTS.items():
        (steps / fname).write_text(body)
    (steps / "05_control_git_tag_list.py").write_text(CONTROL)
    path.write_text(src)
    print(f"snapshot at {out}, steps in {steps}")


if __name__ == "__main__":
    main()
