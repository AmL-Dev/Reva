"""Patch proposal (deterministic templates, LLM fallback) and verification by re-running the exploit."""
from __future__ import annotations

import ast
import difflib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import llm
from .dataflow import (
    HTTP_LIBS,
    HTTP_METHODS,
    SQL_METHODS,
    URLOPEN,
    _fname,
    _is_exec,
    _names,
    _recv_name,
    _url_args,
    analyze,
    flows_for_function,
)
from .types import Finding
from .validate import probe_for, run_exploit

TEMPLATE_CWES = ("CWE-22", "CWE-88", "CWE-78", "CWE-89", "CWE-918")

VALIDATE_REPO_PATH = '''def validate_repo_path(repo_path: Path, allowed_repository: Path | None) -> None:
    """Validate that repo_path is within the allowed repository path."""
    if allowed_repository is None:
        return
    try:
        resolved_repo = repo_path.resolve()
        resolved_allowed = allowed_repository.resolve()
    except (OSError, RuntimeError):
        raise ValueError(f"Invalid path: {repo_path}")
    try:
        resolved_repo.relative_to(resolved_allowed)
    except ValueError:
        raise ValueError(
            f"Repository path '{repo_path}' is outside the allowed repository '{allowed_repository}'"
        )


'''
REPO_PATH_LINE = re.compile(r"^( *)repo_path = Path\(arguments\[\"repo_path\"\]\)\n", re.M)
FUNC_DEF = r"^def {name}\(repo[^,)]*, (\w+): str[^)]*\) *(?:->[^:]+)?:\n"


def _fix_path_containment(source: str) -> str | None:
    if "validate_repo_path" in source or not REPO_PATH_LINE.search(source) or "\nasync def serve" not in source:
        return None
    source = source.replace("\nasync def serve", "\n" + VALIDATE_REPO_PATH + "async def serve", 1)
    return REPO_PATH_LINE.sub(lambda m: f"{m.group(0)}{m.group(1)}validate_repo_path(repo_path, repository)\n", source, count=1)


def _fix_flag_injection(source: str, function: str) -> str | None:
    m = re.search(FUNC_DEF.format(name=re.escape(function)), source, re.M)
    if not m or f'{m.group(1)}.startswith("-")' in source:
        return None
    param = m.group(1)
    guard = (
        f'    if {param}.startswith("-"):\n'
        f'        raise git.exc.BadName(f"Invalid {param}: \'{{{param}}}\' - cannot start with \'-\'")\n'
        f"    repo.rev_parse({param})\n"
    )
    return source[: m.end()] + guard + source[m.end():]


CHECKED_URL = '''def checked_url(url: str) -> str:
    """Only fetch http(s) URLs whose host is in the ALLOWED_URL_HOSTS allowlist (empty = none)."""
    import os
    from urllib.parse import urlparse

    allowed = {h.strip() for h in os.environ.get("ALLOWED_URL_HOSTS", "").split(",") if h.strip()}
    parts = urlparse(str(url))
    if parts.scheme not in ("http", "https") or parts.hostname not in allowed:
        raise ValueError(f"outbound URL is not allowlisted: {url}")
    return url


'''
CONTAINED_PATH = '''def contained_path(base, name):
    """Join and resolve, then require the result to stay inside `base`.

    Nested names are still allowed; only an escape from the base directory is refused.
    """
    import os
    from pathlib import Path

    root = os.path.realpath(str(base))
    target = os.path.realpath(os.path.join(root, str(name).lstrip("/\\\\")))
    if target != root and not target.startswith(root + os.sep):
        raise ValueError(f"path escapes {base}: {name}")
    return Path(target)


'''


def _func(source: str, function: str):
    tree = ast.parse(source)
    return next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == function), None)


def _find_call(source: str, function: str, pred) -> ast.Call | None:
    """The first matching call in the function's body; decorators are not part of its behaviour."""
    scope = _func(source, function)
    body = scope.body if scope else ast.parse(source).body
    return next((c for s in body for c in ast.walk(s) if isinstance(c, ast.Call) and pred(c)), None)


def _insert_before(source: str, function: str, block: str) -> str | None:
    """Put a helper definition immediately above the vulnerable function."""
    fn = _func(source, function)
    if fn is None or block.split("(")[0] in source:
        return None
    line = min([d.lineno for d in fn.decorator_list] or [fn.lineno])
    lines = source.splitlines(True)
    return "".join(lines[:line - 1]) + block + "".join(lines[line - 1:])


def _ensure_import(source: str, module: str) -> str:
    if re.search(rf"^import {module}\b", source, re.M):
        return source
    body = ast.parse(source).body
    last = max((n.end_lineno for n in body if isinstance(n, (ast.Import, ast.ImportFrom))), default=0)
    lines = source.splitlines(True)
    return "".join(lines[:last]) + f"import {module}\n" + "".join(lines[last:])


def _sql_parts(e: ast.AST) -> list:
    """The query as a flat list of constant text and interpolated expressions."""
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return [e.value]
    if isinstance(e, ast.JoinedStr):
        return [p.value for p in e.values]      # Constant.value is text, FormattedValue.value is the expression
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
        return _sql_parts(e.left) + _sql_parts(e.right)
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Mod):
        return _split_in(_sql_parts(e.left), r"%s|%d|%\(\w+\)s", e.right)
    if isinstance(e, ast.Call) and _fname(e.func) == "format":
        return _split_in(_sql_parts(e.func.value), r"\{[^{}]*\}", ast.Tuple(elts=list(e.args)))
    return [e]


def _split_in(parts: list, pattern: str, values: ast.AST) -> list:
    text = "".join(p for p in parts if isinstance(p, str))
    vals = list(values.elts) if isinstance(values, (ast.Tuple, ast.List)) else [values]
    chunks = re.split(pattern, text)
    out = []
    for i, c in enumerate(chunks):
        out.append(c)
        if i < len(chunks) - 1:
            out.append(vals[i] if i < len(vals) else ast.Constant(value=""))
    return out


def _parameterise(parts: list) -> tuple[str, list[str]]:
    """Turn interpolated query text into placeholders, dropping the quotes that wrapped each value."""
    text, args, strip = "", [], ""
    for p in parts:
        if isinstance(p, str):
            text, strip = text + (p[1:] if strip and p.startswith(strip) else p), ""
        else:
            if text[-1:] in ("'", '"'):
                strip, text = text[-1], text[:-1]
            text += "?"
            args.append(ast.unparse(p))
    return text, args


def _fix_sql_injection(source: str, function: str) -> str | None:
    call = _find_call(source, function, lambda c: _fname(c.func) in SQL_METHODS and len(c.args) == 1)
    if call is None:
        return None
    text, args = _parameterise(_sql_parts(call.args[0]))
    old = ast.get_source_segment(source, call)
    if not args or not old:
        return None
    seq = ", ".join(args) + ("," if len(args) == 1 else "")
    return source.replace(old, f"{ast.unparse(call.func)}({text!r}, ({seq}))", 1)


def _bound_list(call: ast.Call) -> str | None:
    """The list the query's parameters come from: `execute(sql, params)` or `execute(sql, (*params, limit))`."""
    if len(call.args) < 2:
        return None
    a = call.args[1]
    if isinstance(a, ast.Name):
        return a.id
    stars = [e.value.id for e in getattr(a, "elts", ()) if isinstance(e, ast.Starred) and isinstance(e.value, ast.Name)]
    return stars[0] if len(stars) == 1 else None


def _fix_sql_fragment(source: str, function: str) -> str | None:
    """`where.append(f"title LIKE '%{q}%'")` -> `where.append("title LIKE ?")` + `params.append(f"%{q}%")`:
    each quoted region holding interpolated values becomes one placeholder, bound in the query's own list."""
    fn = _func(source, function)
    run = _find_call(source, function, lambda c: _fname(c.func) in SQL_METHODS and len(c.args) == 2)
    params = _bound_list(run) if run else None
    if fn is None or params is None:
        return None
    for stmt in ast.walk(fn):
        c = getattr(stmt, "value", None)
        if not (isinstance(stmt, ast.Expr) and isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                and c.func.attr == "append" and len(c.args) == 1 and isinstance(c.args[0], ast.JoinedStr)):
            continue
        text, values = "", []
        for v in c.args[0].values:
            if isinstance(v, ast.Constant):
                text += str(v.value).replace("\x00", "")
            else:
                text += f"\x00{len(values)}\x00"
                values.append(ast.get_source_segment(source, v.value) or ast.unparse(v.value))
        if not values:
            continue
        binds = []

        def bind(m):
            binds.append("f" + repr(re.sub(r"\x00(\d+)\x00", lambda k: "{" + values[int(k[1])] + "}", m[1])))
            return "?"
        sql = re.sub(r"'([^']*\x00\d+\x00[^']*)'", bind, text)
        if "\x00" in sql:               # a value outside quotes is an identifier: a placeholder cannot fix it
            return None
        old = ast.get_source_segment(source, stmt)
        pad = " " * stmt.col_offset
        new = f"{ast.unparse(c.func)}({sql!r})" + "".join(f"\n{pad}{params}.append({b})" for b in binds)
        return source.replace(old, new, 1)
    return None


def _unguarded(source: str, file: str, function: str, kind: str) -> bool:
    """Reva only patches what it flagged: a sink the analysis already finds guarded is left alone."""
    flows = [f for f in flows_for_function(analyze(source, file), function) if f.sink.kind == kind]
    return any(not f.guarded for f in flows)


def _fix_ssrf(source: str, function: str, file: str) -> str | None:
    if not _unguarded(source, file, function, "http"):
        return None

    def outbound(c):
        return bool(_url_args(c)) and (_fname(c.func) in URLOPEN
                                       or (_fname(c.func) in HTTP_METHODS and _recv_name(c.func).lower() in HTTP_LIBS))

    call = _find_call(source, function, outbound)
    url = _url_args(call)[0] if call else None
    old = ast.get_source_segment(source, url) if url is not None else None
    if not old or "checked_url" in source:
        return None
    whole = ast.get_source_segment(source, call)
    own = _project_url_check(source)              # the codebase's own validator beats a generic one
    fixed = source.replace(whole, whole.replace(old, f"{own or 'checked_url'}({old})", 1), 1)
    return fixed if own else _insert_before(fixed, function, CHECKED_URL)


URL_CHECK = re.compile(r"^(validate|check|verify|ensure)_\w*url\w*$")


def _project_url_check(source: str) -> str | None:
    """A module-level URL validator the file already defines or imports, e.g. `validate_logo_url`."""
    tree = ast.parse(source)
    defined = [n.name for n in tree.body if isinstance(n, ast.FunctionDef) and URL_CHECK.match(n.name)]
    imported = [a.asname or a.name for n in tree.body if isinstance(n, ast.ImportFrom) for a in n.names
                if URL_CHECK.match(a.asname or a.name)]
    return (defined + imported or [None])[0]


def _fix_command_injection(source: str, function: str) -> str | None:
    call = _find_call(source, function, lambda c: _is_exec(c.func) and c.args
                      and isinstance(c.args[0], ast.JoinedStr))
    if call is None or "shlex.quote" in source:
        return None
    old = ast.get_source_segment(source, call.args[0])
    quoted = ast.JoinedStr(values=[
        p if isinstance(p, ast.Constant) else
        ast.FormattedValue(value=_wrap(_wrap(p.value, None, "str"), "shlex", "quote"), conversion=-1, format_spec=None)
        for p in call.args[0].values])
    new = ast.unparse(ast.fix_missing_locations(quoted))
    return _ensure_import(source.replace(old, new, 1), "shlex") if old else None


def _wrap(node: ast.AST, module: str | None, attr: str) -> ast.Call:
    func = (ast.Attribute(value=ast.Name(id=module, ctx=ast.Load()), attr=attr, ctx=ast.Load())
            if module else ast.Name(id=attr, ctx=ast.Load()))
    return ast.Call(func=func, args=[node], keywords=[])


def _join_parts(node: ast.AST) -> tuple[ast.AST | None, ast.AST | None]:
    """(base, untrusted part) of `base / name` or os.path.join(base, name)."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return node.left, node.right
    if isinstance(node, ast.Call) and _fname(node.func) == "join" and len(node.args) == 2:
        return node.args[0], node.args[1]
    return None, None


def _fix_path_traversal(source: str, function: str, file: str) -> str | None:
    """Contain the join that builds the path from untrusted input, keeping nested names working."""
    taint = {f.source.param.split(".")[0] for f in flows_for_function(analyze(source, file), function)
             if f.sink.kind == "path" and not f.guarded}
    fn = _func(source, function)
    if not taint or fn is None or "contained_path" in source:
        return None
    for node in ast.walk(fn):
        base, user = _join_parts(node)
        if base is None or not _names(user) & taint or _names(base) & taint:
            continue
        old = ast.get_source_segment(source, node)
        if not old:
            continue
        new = f"contained_path({ast.unparse(base)}, {ast.unparse(user)})"
        return _insert_before(source.replace(old, new, 1), function, CONTAINED_PATH)
    return None


def _llm_fix(finding: Finding, source: str) -> str | None:
    if not llm.available():
        return None
    try:
        out = llm.complete_json(
            "You fix security bugs minimally. Return the complete corrected file.",
            f"{finding.cwe} in function {finding.function} of {finding.file}: {finding.title}\n{finding.reasoning}\n\n{source}",
            '{"fixed_source": str}',
        )
    except RuntimeError:
        return None
    fixed = out.get("fixed_source")
    return fixed if isinstance(fixed, str) else None


def propose(finding: Finding, source: str) -> str:
    """Unified diff (a/ b/ prefixed paths relative to the target root) or '' if no fix is available."""
    fixed = None
    if finding.cwe == "CWE-22":
        fixed = _fix_path_containment(source) or _fix_path_traversal(source, finding.function, finding.file)
    elif finding.cwe == "CWE-88":
        fixed = _fix_flag_injection(source, finding.function)
    elif finding.cwe == "CWE-89":
        fixed = _fix_sql_injection(source, finding.function) or _fix_sql_fragment(source, finding.function)
    elif finding.cwe == "CWE-918":
        fixed = _fix_ssrf(source, finding.function, finding.file)
    elif finding.cwe == "CWE-78":
        fixed = _fix_command_injection(source, finding.function)
    if fixed is None and finding.cwe not in TEMPLATE_CWES:
        fixed = _llm_fix(finding, source)
    if fixed is None or fixed == source:
        return ""
    name = finding.file.lstrip("/")
    return "".join(difflib.unified_diff(source.splitlines(True), fixed.splitlines(True), f"a/{name}", f"b/{name}"))


def verify(finding: Finding, target_dir: str | Path, diff: str) -> Finding:
    """Apply `diff` to a temp copy of target_dir and re-run this finding's own probe; 'patched' if it no longer reproduces."""
    update = {"patch": diff}
    probe = finding.exploit or probe_for(finding.cwe, finding.function)
    if probe and diff:
        with tempfile.TemporaryDirectory(prefix="reva-patch-") as tmp:
            copy = Path(tmp) / "target"
            shutil.copytree(target_dir, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            applied = subprocess.run(["patch", "-p1", "-d", str(copy)], input=diff, text=True, capture_output=True)
            if applied.returncode != 0:
                update["validation"] = f"patch did not apply: {applied.stdout}{applied.stderr}"[-500:]
            else:
                reproduced, output, ran = run_exploit(probe, copy, function=finding.function)
                verdict = ("exploit still reproduces" if reproduced else
                           "fix holds, exploit no longer reproduces" if ran else "exploit could not be re-run")
                update["validation"] = f"after patch: {verdict}: {output}"
                if ran and not reproduced:
                    update["status"] = "patched"
    return finding.model_copy(update=update)
