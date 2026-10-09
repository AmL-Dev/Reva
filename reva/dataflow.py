"""Stdlib-ast taint analysis from untrusted input (MCP tool arguments, HTTP request data) to
path, git, exec, SQL, outbound-HTTP and deserialization sinks."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .types import Flow, Sink, Source

GUARD_NAME = re.compile(r"valid|sanit|verify|ensure|check_path|check_url|allowed", re.I)
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "mkdir", "iterdir", "rmdir"}
EXEC_CALLS = {"system", "popen", "run", "call", "check_call", "check_output", "Popen", "exec", "eval",
              "getoutput", "getstatusoutput", "create_subprocess_shell"}
EXEC_MODULES = {"os", "subprocess", "commands", "asyncio"}
CONTAINMENT = {"relative_to", "is_relative_to", "commonpath"}
PATH_SANITIZERS = {"secure_filename", "safe_join", "basename"}
NORMALIZERS = {"realpath", "abspath", "normpath", "resolve"}

ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "route", "api_route", "websocket"}
REQUEST_ATTRS = {"args", "form", "json", "headers", "files", "cookies", "query_params", "path_params",
                 "data", "values", "GET", "POST", "body", "stream"}
REQUEST_OBJECTS = {"request", "req", "flask_request"}
SKIP_PARAMS = {"self", "cls", "request", "req", "websocket", "response", "background_tasks", "db", "session"}
DEPENDS = {"Depends", "Security"}

SQL_METHODS = {"execute", "executemany", "executescript", "exec_driver_sql", "execute_fetchall"}
SQL_KEYWORD = re.compile(r"\b(select|insert\s+into|update|delete\s+from|replace\s+into|drop|alter|union)\b", re.I)
PLACEHOLDER = re.compile(r"\?|%s|%\(\w+\)s|:\w+")
SQL_PARAM_KW = {"parameters", "params", "vars", "args", "seq_of_parameters"}

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "stream"}
HTTP_LIBS = {"requests", "httpx", "aiohttp", "urllib3", "session", "client", "http_client", "httpsession"}
HTTP_CTORS = {"Session", "Client", "AsyncClient", "ClientSession", "PoolManager"}
URLOPEN = {"urlopen", "urlretrieve"}
URL_ARG_KW = {"url", "uri", "full_url", "target_url"}
URL_PARTS = {"scheme", "netloc", "hostname", "host", "port"}
URL_PARSERS = {"urlparse", "urlsplit"}

DESERIALIZE = {"pickle": {"loads", "load"}, "dill": {"loads", "load"}, "cPickle": {"loads", "load"},
               "marshal": {"loads", "load"}, "yaml": {"load"}, "jsonpickle": {"decode"}, "shelve": {"open"}}


@dataclass
class _Guard:
    line: int
    names: set[str]
    kind: str  # a sink kind, or "*" for a named helper that guards whatever it is applied to
    label: str


@dataclass
class _Ctx:
    funcs: dict[str, ast.AST]
    file: str
    source: str
    flows: dict = field(default_factory=dict)
    seen: set = field(default_factory=set)


def _fname(f: ast.AST) -> str:
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _recv_name(f: ast.AST) -> str:
    return _fname(f.value) if isinstance(f, ast.Attribute) else ""


def _const_text(node: ast.AST) -> str:
    return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _is_args(node: ast.AST, root: str) -> bool:
    return isinstance(node, ast.Name) and node.id == root


def _arg_key(node: ast.AST, root: str) -> tuple[str, int] | None:
    """Return (param, line) for arguments["x"] / arguments.get("x")."""
    if isinstance(node, ast.Subscript) and _is_args(node.value, root):
        k = node.slice
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
          and _is_args(node.func.value, root) and node.args):
        k = node.args[0]
    else:
        return None
    return (k.value, node.lineno) if isinstance(k, ast.Constant) and isinstance(k.value, str) else None


def _is_req_attr(node: ast.AST) -> bool:
    """`request.args`, `req.form`, `flask.request.headers`: a bag of attacker-controlled request data."""
    return (isinstance(node, ast.Attribute) and node.attr in REQUEST_ATTRS
            and _fname(node.value).lower() in REQUEST_OBJECTS)


def _req_key(node: ast.AST) -> tuple[str, int] | None:
    """Return (label, line) for request.args["x"] / request.form.get("x") / request.json."""
    if isinstance(node, ast.Subscript) and _is_req_attr(node.value):
        bag, k = node.value, node.slice
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist")
          and _is_req_attr(node.func.value) and node.args):
        bag, k = node.func.value, node.args[0]
    elif _is_req_attr(node):
        return f"request.{node.attr}", node.lineno
    else:
        return None
    if isinstance(k, ast.Constant) and isinstance(k.value, str):
        return k.value, node.lineno
    return f"request.{bag.attr}", node.lineno


def _sources(node: ast.AST, root: str | None):
    """Yield (label, line) for every untrusted read in `node`; the outermost match wins, so
    request.args["name"] is one source called "name" and not also one called "request.args"."""
    stack = [node]
    while stack:
        n = stack.pop()
        hit = (_arg_key(n, root) if root else None) or _req_key(n)
        if hit:
            yield hit
        else:
            stack.extend(ast.iter_child_nodes(n))


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _field_of(node: ast.AST, name: str) -> str:
    """`body.url` names the source better than `body` when one field of a request model is read."""
    called = {id(c.func) for c in ast.walk(node) if isinstance(c, ast.Call)}
    attrs = {c.attr for c in ast.walk(node) if isinstance(c, ast.Attribute) and id(c) not in called
             and isinstance(c.value, ast.Name) and c.value.id == name}
    return f"{name}.{attrs.pop()}" if len(attrs) == 1 else name


def _is_repo_ctor(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name)) and (
        getattr(node.func, "attr", getattr(node.func, "id", "")) == "Repo")


def _url_args(n: ast.Call) -> list[ast.AST]:
    return [*n.args[:1], *(k.value for k in n.keywords if k.arg in URL_ARG_KW)]


def _is_deserialize(f: ast.AST) -> bool:
    return _fname(f) in DESERIALIZE.get(_recv_name(f), set())


def _is_exec(f: ast.AST) -> bool:
    if isinstance(f, ast.Name):
        return f.id in {"exec", "eval"}
    return isinstance(f, ast.Attribute) and f.attr in EXEC_CALLS and _recv_name(f) in EXEC_MODULES


def _parameterised(n: ast.Call) -> bool:
    """execute(sql, params) where the query carries placeholders: the value is bound, never pasted in."""
    bound = len(n.args) > 1 or any(k.arg in SQL_PARAM_KW for k in n.keywords)
    return bound and bool(PLACEHOLDER.search(_const_text(n.args[0])))


def _argv_list(n: ast.Call) -> bool:
    """subprocess.run(["git", "log", x]) with shell unset/False: x is one argv slot, not shell text."""
    shell = next((k.value for k in n.keywords if k.arg == "shell"), None)
    if isinstance(shell, ast.Constant) and shell.value:
        return False
    a = n.args[0] if n.args else None
    return isinstance(a, (ast.List, ast.Tuple)) and bool(a.elts) and isinstance(a.elts[0], ast.Constant)


def _quoted(n: ast.Call) -> bool:
    """shlex.quote(x) inside the command text: the value cannot break out of its shell word."""
    return bool(n.args) and any(
        isinstance(c, ast.Call) and (_recv_name(c.func) == "shlex"
                                     or (_recv_name(c.func) == "" and _fname(c.func) == "quote"))
        and _fname(c.func) in ("quote", "join") for c in ast.walk(n.args[0]))


def _safe_loader(n: ast.Call) -> bool:
    return any(k.arg in ("Loader", "loader") and "safe" in (_fname(k.value) or _const_text(k.value)).lower()
               for k in n.keywords)


def _allowlist(c: ast.Compare) -> bool:
    return any(isinstance(x, (ast.Set, ast.List, ast.Tuple, ast.Dict))
               or (isinstance(x, ast.Name) and x.id.isupper()) for x in c.comparators)


def _url_check(test: ast.AST) -> str | None:
    """A scheme/host check or an allowlist comparison standing between the input and the request."""
    for c in ast.walk(test):
        if isinstance(c, ast.Call) and _fname(c.func) in URL_PARSERS:
            return "URL scheme/host validation"
        if isinstance(c, ast.Attribute) and c.attr in URL_PARTS:
            return "URL scheme/host validation"
        if (isinstance(c, ast.Call) and _fname(c.func) == "startswith" and c.args
                and str(getattr(c.args[0], "value", "")).startswith(("http://", "https://"))):
            return "URL prefix allowlist"
        if isinstance(c, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in c.ops) and _allowlist(c):
            return "URL host allowlist"
    return None


MUTATORS = {"append", "extend", "insert", "add", "update", "appendleft"}   # taint flows into the receiver


class _Func:
    """Taint state of one function body."""

    def __init__(self, fn, root: str | None, params: dict[str, set[str]], inherited: dict[str, list[tuple[str, str]]]):
        self.fn, self.root = fn, root
        self.env: dict[str, set[str]] = {p: set(l) for p, l in params.items()}
        self.origin: dict[str, set[str]] = {}
        self.src_lines: dict[str, int] = {}
        self.flag_pref: dict[str, bool] = {}   # name -> every tainted binding is a ("-flag", value) sequence
        self.sqlish: set[str] = set()          # names bound to text that reads like a SQL statement
        self.clients: set[str] = set()         # names bound to an HTTP client object
        self.normalized: set[str] = set()      # names bound to a realpath/resolve of something
        self.guards = [_Guard(0, {p}, k, g) for p, gs in inherited.items() for k, g in gs]
        self.nodes = sorted((n for n in self._body_nodes() if hasattr(n, "lineno")), key=lambda n: (n.lineno, n.col_offset))
        self._propagate()
        self._collect_guards()

    def _body_nodes(self):
        stack = list(self.fn.body)
        while stack:
            n = stack.pop()
            yield n
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                stack.extend(ast.iter_child_nodes(n))

    def labels(self, node: ast.AST) -> set[str]:
        out: set[str] = set()
        for lab, line in _sources(node, self.root):
            out.add(lab)
            self.src_lines.setdefault(lab, line)
        for n in _names(node):
            out |= self.env.get(n, set())
        if _is_repo_ctor(node):
            return set()
        return {_field_of(node, l) if self.env.get(l) == {l} else l for l in out}

    def _classify_binding(self, name: str, value: ast.AST) -> None:
        if SQL_KEYWORD.search(_const_text(value)):
            self.sqlish.add(name)
        for c in ast.walk(value):
            if isinstance(c, ast.Call) and _fname(c.func) in HTTP_CTORS:
                self.clients.add(name)
            if isinstance(c, ast.Call) and _fname(c.func) in NORMALIZERS:
                self.normalized.add(name)

    def _propagate(self) -> None:
        for _ in range(2):
            for n in self.nodes:
                if isinstance(n, ast.Assign):
                    targets, value = n.targets, n.value
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    targets, value = [n.target], n.value
                elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in MUTATORS
                      and isinstance(n.func.value, ast.Name) and n.args):
                    targets = [n.func.value]                                              # parts.append(x)
                    value = n.args[0] if n.func.attr == "extend" else ast.Tuple(elts=n.args, ctx=ast.Load())
                else:
                    continue
                lab = self.labels(value)
                for t in targets:
                    for name in _names(t):
                        self.env.setdefault(name, set()).update(lab)
                        self.origin.setdefault(name, set()).update(_names(value))
                        self._classify_binding(name, value)
                        if lab:
                            self.flag_pref[name] = self.flag_pref.get(name, True) and _flag_seq(value)

    def _closure(self, name: str) -> set[str]:
        out, todo = set(), [name]
        while todo:
            x = todo.pop()
            if x not in out:
                out.add(x)
                todo.extend(self.origin.get(x, ()))
        return out

    def _if_guard(self, n: ast.If) -> None:
        for c in ast.walk(n.test):
            if (isinstance(c, ast.Call) and _fname(c.func) == "startswith" and c.args
                    and isinstance(c.args[0], ast.Constant) and str(c.args[0].value).startswith("-")):
                self.guards.append(_Guard(n.lineno, _names(c.func.value), "git_arg", "startswith('-') rejection"))
            elif (isinstance(c, ast.Call) and _fname(c.func) == "startswith"
                  and (_names(c.func.value) & self.normalized or _normalizer_call(c.func.value))):
                self.guards.append(_Guard(n.lineno, self._spread(_names(c.func.value)), "path",
                                          "realpath + startswith containment"))
        url = _url_check(n.test)
        if url:
            self.guards.append(_Guard(n.lineno, self._spread(_names(n.test)), "http", url))

    def _spread(self, names: set[str]) -> set[str]:
        return set().union(*(self._closure(x) for x in names)) if names else set()

    def _collect_guards(self) -> None:
        for n in self.nodes:
            if isinstance(n, ast.If):
                self._if_guard(n)
            if not isinstance(n, ast.Call):
                continue
            fname, argn = _fname(n.func), set().union(*(_names(a) for a in n.args)) if n.args else set()
            if fname == "rev_parse":
                self.guards.append(_Guard(n.lineno, argn, "git_arg", "rev_parse validation"))
            elif fname in CONTAINMENT:
                recv = _names(n.func.value) if isinstance(n.func, ast.Attribute) else set()
                self.guards.append(_Guard(n.lineno, self._spread(recv), "path", "relative_to containment"))
            elif fname in PATH_SANITIZERS and argn:
                self.guards.append(_Guard(n.lineno, argn, "path", f"{fname} sanitiser"))
            elif GUARD_NAME.search(fname) and argn:
                self.guards.append(_Guard(n.lineno, argn, "*", fname))

    def guards_for(self, kind: str, names: set[str], line: int) -> list[str]:
        return sorted({g.label for g in self.guards
                       if g.kind in (kind, "*") and g.line < line and g.names & names})

    def inherited(self, arg: ast.AST, line: int) -> list[tuple[str, str]]:
        """Guards a helper call carries with it; the argument's origins count, exactly as at a sink,
        so `run(ensure_within(base, name))` does not lose the guard at the helper boundary."""
        names = self._spread(_names(arg))
        return [(g.kind, g.label) for g in self.guards if g.line < line and g.names & names]

    def flag_bound(self, e: ast.AST) -> bool:
        """`*contains_sha` where contains_sha is only ever ("--contains", value): git reads the value as the flag's operand."""
        names = _names(e)
        return bool(names) and all(self.flag_pref.get(n) for n in names)

    def _is_sql(self, n: ast.Call) -> bool:
        return (_fname(n.func) in SQL_METHODS and bool(n.args)
                and bool(SQL_KEYWORD.search(_const_text(n.args[0])) or _names(n.args[0]) & self.sqlish))

    def _is_http(self, n: ast.Call) -> bool:
        f = n.func
        if _fname(f) in URLOPEN:
            return True
        if not (isinstance(f, ast.Attribute) and f.attr in HTTP_METHODS):
            return False
        v = f.value
        if isinstance(v, ast.Call):
            return _fname(v.func) in HTTP_CTORS
        return _fname(v).lower() in HTTP_LIBS or _fname(v) in self.clients or _fname(v) in HTTP_CTORS

    def _classify(self, n: ast.Call) -> tuple[str, list[ast.AST], list[str]] | None:
        """(sink kind, tainted expressions, guards visible at the call itself)."""
        f, exprs = n.func, [*n.args, *(k.value for k in n.keywords)]
        if _is_repo_ctor(n) and exprs:
            return "path", exprs[:1], []
        if isinstance(f, ast.Name) and f.id == "open" and exprs:
            return "path", exprs[:1], []
        if isinstance(f, ast.Attribute) and f.attr in PATH_METHODS and not isinstance(f.value, ast.Constant):
            return "path", [f.value], []
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute) and f.value.attr == "git":
            return "git_arg", [e for e in exprs if not _prefixed(e) and not self.flag_bound(e)], []
        if self._is_sql(n):
            return "sql", n.args[:1], ["parameterised query"] if _parameterised(n) else []
        if self._is_http(n):
            return "http", _url_args(n), []
        if _is_deserialize(f):
            return "deserialize", n.args[:1], ["yaml SafeLoader"] if _safe_loader(n) else []
        if _is_exec(f):
            local = ["argv list (shell=False)"] if _argv_list(n) else []
            return "exec", exprs, local + (["shlex.quote"] if _quoted(n) else [])
        return None

    def sinks(self):
        """Yield (kind, node, tainted-expr-nodes, call-site guards) for sinks in this body."""
        for n in self.nodes:
            hit = self._classify(n) if isinstance(n, ast.Call) else None
            if hit:
                wrapped = [_fname(e.func) for e in hit[1]           # sink(validate_url(x)): checked at the call itself
                           if isinstance(e, ast.Call) and (GUARD_NAME.search(_fname(e.func)) or _fname(e.func) in PATH_SANITIZERS)]
                yield hit[0], n, hit[1], hit[2] + [w for w in wrapped if w not in hit[2]]


def _normalizer_call(e: ast.AST) -> bool:
    return any(isinstance(c, ast.Call) and _fname(c.func) in NORMALIZERS for c in ast.walk(e))


def _prefixed(e: ast.AST) -> bool:
    """f"-U{x}": a constant flag prefix means the value cannot start a new option."""
    return (isinstance(e, ast.JoinedStr) and bool(e.values) and isinstance(e.values[0], ast.Constant)
            and str(e.values[0].value).startswith("-"))


def _flag_seq(e: ast.AST) -> bool:
    """("--contains", value): the constant flag ahead of the value makes git parse it as that flag's operand."""
    return (isinstance(e, (ast.Tuple, ast.List)) and len(e.elts) > 1 and isinstance(e.elts[0], ast.Constant)
            and str(e.elts[0].value).startswith("-"))


def _walk(ctx: _Ctx, fn, root: str | None, params: dict[str, set[str]], inh, chain: list[str], src: dict) -> None:
    key = (fn.name, tuple(sorted((p, tuple(sorted(l))) for p, l in params.items())))
    if key in ctx.seen or len(chain) > 6:
        return
    ctx.seen.add(key)
    st = _Func(fn, root, params, inh)
    for kind, call, exprs, local in st.sinks():
        names = set().union(*(_names(e) for e in exprs)) if exprs else set()
        labs = set().union(*(st.labels(e) for e in exprs)) if exprs else set()
        for lab in labs:
            at = src.get(lab) or src.get(lab.split(".")[0])
            line = at[2] if at else st.src_lines.get(lab, call.lineno)
            root_lab = lab.split(".")[0]          # a guard on one input must not cover another input of the same sink
            mine = {x for x in st._spread(names) if x == root_lab or {lab, root_lab} & st.env.get(x, set())}
            guards = sorted(set(st.guards_for(kind, mine or st._spread(names), call.lineno)) | set(local))
            code = ast.get_source_segment(ctx.source, call) or ast.unparse(call)
            flow = Flow(source=Source(function=chain[0], param=lab, file=ctx.file, line=line),
                        sink=Sink(kind=kind, function=fn.name, file=ctx.file, line=call.lineno, code=code.splitlines()[0]),
                        guarded=bool(guards), guards=guards, path=list(chain))
            ctx.flows[(flow.source.param, flow.sink.line, kind)] = flow
    for call in (n for n in st.nodes if isinstance(n, ast.Call)):
        callee = ctx.funcs.get(call.func.id) if isinstance(call.func, ast.Name) else None
        if callee is None or callee is fn:
            continue
        pnames = [a.arg for a in callee.args.args]
        bound = list(zip(pnames, call.args)) + [(k.arg, k.value) for k in call.keywords if k.arg]
        sub = {p: st.labels(a) for p, a in bound}
        sub = {p: l for p, l in sub.items() if l}
        if sub:
            inh2 = {p: st.inherited(a, call.lineno) for p, a in bound if p in sub}
            src2 = {l: src.get(l) or (fn.name, l, st.src_lines.get(l, call.lineno)) for l in set().union(*sub.values())}
            _walk(ctx, callee, None, sub, inh2, [*chain, callee.name], src2)


def _mcp_handlers(funcs: dict) -> list:
    out = [n for n in funcs.values() if any(
        isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "call_tool" for d in n.decorator_list)]
    return out or ([funcs["call_tool"]] if "call_tool" in funcs else [])


def _is_route(d: ast.AST) -> bool:
    """A decorator naming an HTTP method and a path: @app.get("/x"), @router.post(path="/x"), and
    @router.get("") as used with APIRouter(prefix="/reports")."""
    if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_METHODS):
        return False
    paths = [*d.args[:1], *(k.value for k in d.keywords if k.arg == "path")]
    return bool(paths) and isinstance(paths[0], ast.Constant) and isinstance(paths[0].value, str) and (
        paths[0].value == "" or paths[0].value.startswith("/"))


def _dep_params(fn) -> set[str]:
    args = [*fn.args.posonlyargs, *fn.args.args]
    pairs = list(zip(args[len(args) - len(fn.args.defaults):], fn.args.defaults))
    pairs += list(zip(fn.args.kwonlyargs, fn.args.kw_defaults))
    return {a.arg for a, d in pairs if isinstance(d, ast.Call) and _fname(d.func) in DEPENDS}


def _handler_params(fn) -> dict[str, tuple[set[str], int]]:
    """Route parameters are untrusted: path and query params, request bodies, uploaded files."""
    skip = SKIP_PARAMS | _dep_params(fn)
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    return {a.arg: ({a.arg}, a.lineno) for a in args
            if a.arg not in skip and (_fname(a.annotation) if a.annotation else "") not in ("Request", "WebSocket")}


def _entry_points(funcs: dict) -> list:
    """Route handlers, plus any function that reads request data directly (Flask-style views)."""
    routes = [n for n in funcs.values() if any(_is_route(d) for d in n.decorator_list)]
    reads = [n for n in funcs.values() if n not in routes and any(_req_key(x) for x in ast.walk(n))]
    return routes + reads


def entry_kinds(source: str) -> set[str]:
    """Which untrusted entry points this file has: "mcp" tool handlers and/or "http" route handlers."""
    try:
        funcs = {n.name: n for n in ast.walk(ast.parse(source))
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    except SyntaxError:
        return set()
    return ({"mcp"} if _mcp_handlers(funcs) else set()) | ({"http"} if _entry_points(funcs) else set())


def analyze(source: str, file: str) -> list[Flow]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    ctx = _Ctx(funcs=funcs, file=file, source=source)
    for h in _mcp_handlers(funcs):
        params = [a.arg for a in h.args.args]
        _walk(ctx, h, params[1] if len(params) > 1 else None, {}, {}, [h.name], {})
    for h in _entry_points(funcs):
        bound = _handler_params(h)
        _walk(ctx, h, None, {p: labs for p, (labs, _) in bound.items()}, {}, [h.name],
              {p: (h.name, p, line) for p, (_, line) in bound.items()})
    return sorted(ctx.flows.values(), key=lambda f: (f.sink.line, f.source.param))


def flows_for_function(flows: list[Flow], function_name: str) -> list[Flow]:
    """Flows whose sink lies in `function_name`: a dispatcher that only forwards args owns no finding."""
    return [f for f in flows if f.sink.function == function_name]
