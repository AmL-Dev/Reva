"""Offline stand-ins for the analysis modules, so the UI/server can be demoed without an LLM.

Usage: python demo/fake.py watch target
"""
import sys
import time
import types
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from reva.types import Finding, Flow, Sink, Source, ThreatModel  # noqa: E402

F = "src/mcp_server_git/server.py"


def _flow(fn, param, kind, line, code, guarded=False, path=()):
    return Flow(source=Source(function="call_tool", param=param, file=F, line=349),
                sink=Sink(kind=kind, function=fn, file=F, line=line, code=code),
                guarded=guarded, path=["call_tool", *path, fn])


TM = ThreatModel(
    summary="MCP git server: tool args are attacker-controlled; boundary is --repository.",
    assets=["files outside the repository"], trust_boundaries=["--repository"], questions=[],
    flows=[_flow("git_diff", "target", "git_arg", 119, "repo.git.diff(..., target)"),
           _flow("git_checkout", "branch_name", "git_arg", 182, "repo.git.checkout(branch_name)"),
           _flow("git_status", "repo_path", "path", 110, "git.Repo(repo_path)", path=("validate_repo_path",), guarded=True),
           _flow("git_log", "repo_path", "path", 137, "git.Repo(repo_path)")])

Change = namedtuple("Change", "file function old_code new_code source")

# function -> (line, param, sink call, exploit, evidence)
BUGS = {
    "git_diff": (119, "target", "repo.git.diff(f'--unified={context_lines}', target)",
                 "call(git_diff, {'target': '--output=/tmp/canary'})",
                 "canary file created outside repository: /tmp/canary (0 bytes)"),
    "git_checkout": (182, "branch_name", "repo.git.checkout(branch_name)",
                     "call(git_checkout, {'branch_name': '--pathspec-from-file=/tmp/canary_secret.txt'})",
                     "outside file leaked: error: pathspec 'REVA-CANARY-LEAK' did not match any file(s) known to git"),
}


def discover(change):
    """Flows the saved function owns: visible as soon as its tainted argument is written."""
    return [f for f in TM.flows if f.sink.function == change.function and f.source.param in change.new_code]


def merge(tm, flows):
    return [tm.flows.index(f) for f in flows]


def screen(change, tm):
    bug = BUGS.get(change.function)
    if bug is None or bug[1] not in change.new_code or "NotImplementedError" in change.new_code or "args.append" in change.new_code:
        return []
    line, param, sink, _, _ = bug
    return [Finding(id=f"F-{change.function}", title=f"Argument injection via {change.function} {param}",
                    file=change.file, function=change.function, line=line, cwe="CWE-88", confidence=0.91,
                    reasoning=f"`{param}` is passed to git unvalidated in `{sink}`; a leading '-' becomes an option.")]


def validate(finding, target_dir):
    time.sleep(1.5)
    _, _, _, exploit, evidence = BUGS[finding.function]
    return finding.model_copy(update=dict(status="confirmed", impact=4, likelihood=4,
                                          exploit=exploit, evidence=evidence))


def propose(finding, source):
    time.sleep(1)
    line, param, sink, _, _ = BUGS[finding.function]
    return (f"--- a/{finding.file}\n+++ b/{finding.file}\n@@ -{line},1 +{line},3 @@\n"
            f"-    return {sink}\n"
            f"+    if {param}.startswith(\"-\"):\n"
            f"+        raise git.exc.BadName(f\"Invalid {param}: cannot start with '-'\")\n"
            f"+    return {sink}\n")


def verify(finding, target_dir, diff):
    time.sleep(1)
    _, param, _, _, _ = BUGS[finding.function]
    return finding.model_copy(update=dict(
        patch=diff, status="patched",
        validation=f"after patch: fix holds, exploit no longer reproduces: BadName: Invalid {param}: cannot start with '-'"))


def install() -> None:
    for name, attrs in dict(
        threatmodel=dict(build=lambda repo, llm=None: TM, load=lambda repo: TM, save=lambda tm, repo: None,
                         merge=merge),
        detector=dict(screen=screen, discover=discover, Change=Change),
        validate=dict(validate=validate),
        patch=dict(propose=propose, verify=verify),
    ).items():
        mod = types.ModuleType(f"reva.{name}")
        mod.__dict__.update(attrs)
        sys.modules[f"reva.{name}"] = mod


if __name__ == "__main__":
    install()
    from reva import cli
    cli.main(sys.argv[1:])
