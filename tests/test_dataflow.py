from pathlib import Path

from reva.dataflow import analyze, flows_for_function

FIX = Path(__file__).parent / "fixtures"


def flows(name):
    return analyze((FIX / name).read_text(), name)


def pick(fl, kind, param, fn=None):
    return [f for f in fl if f.sink.kind == kind and f.source.param == param and (fn is None or f.sink.function == fn)]


def test_vulnerable_path_flow_unguarded():
    (f,) = pick(flows("server_vulnerable.py"), "path", "repo_path")
    assert not f.guarded and f.path == ["call_tool"] and "Repo" in f.sink.code


def test_vulnerable_diff_arg_flow_unguarded():
    (f,) = pick(flows("server_vulnerable.py"), "git_arg", "target", "git_diff")
    assert not f.guarded and f.path == ["call_tool", "git_diff"]


def test_fixed_flows_guarded():
    fl = flows("server_fixed.py")
    (p,) = pick(fl, "path", "repo_path")
    assert p.guarded and p.guards == ["validate_repo_path"]
    (d,) = pick(fl, "git_arg", "target", "git_diff")
    assert d.guarded and "startswith('-') rejection" in d.guards and "rev_parse validation" in d.guards


def test_diff_only_fix_leaves_path_unguarded():
    fl = flows("server_fixed2.py")
    assert pick(fl, "git_arg", "target", "git_diff")[0].guarded
    assert not pick(fl, "path", "repo_path")[0].guarded


def test_constant_flag_prefix_not_a_sink():
    assert not pick(flows("server_vulnerable.py"), "git_arg", "context_lines")


def test_flag_prefixed_tuple_not_a_sink():
    """git_branch passes ("--contains", contains): git reads the value as that flag's operand, not a new option."""
    fl = flows("server_vulnerable.py")
    assert not pick(fl, "git_arg", "contains")
    assert not pick(fl, "git_arg", "not_contains")


def test_flows_for_function():
    fl = flows("server_vulnerable.py")
    assert any(not f.guarded for f in flows_for_function(fl, "git_diff"))
    assert flows_for_function(fl, "git_status") == []


def test_dispatcher_owns_only_its_own_sink():
    """call_tool forwards target to git_diff; only its own git.Repo(repo_path) sink is attributed to it."""
    fl = flows_for_function(flows("server_vulnerable.py"), "call_tool")
    assert [(f.sink.kind, f.source.param) for f in fl] == [("path", "repo_path")]


def test_syntax_error_and_non_handler():
    assert analyze("def (:", "x.py") == []
    assert analyze("def f(a):\n    open(a)\n", "x.py") == []


def test_exec_sink_and_helper_taint():
    src = (
        "@server.call_tool()\nasync def call_tool(name, arguments):\n"
        "    cmd = arguments['cmd']\n    run(cmd)\n"
        "def run(c):\n    subprocess.run(c, shell=True)\n"
    )
    (f,) = analyze(src, "x.py")
    assert f.sink.kind == "exec" and not f.guarded and f.path == ["call_tool", "run"]


WEB = FIX / "webvuln" / "app" / "main.py"
WEB_FIXED = FIX / "webfixed" / "app" / "main.py"


def route(body, sig="name: str"):
    return analyze(f'@app.get("/r")\ndef handler({sig}):\n' + body, "w.py")


def kinds(fl):
    return sorted((f.sink.kind, f.source.param, f.guarded) for f in fl)


# ---- new sinks -------------------------------------------------------------------------------

def test_sql_sink_for_every_interpolation_style():
    bodies = {
        "fstring": '    cur.execute(f"SELECT * FROM t WHERE o = \'{name}\'")\n',
        "percent": '    cur.execute("SELECT * FROM t WHERE o = \'%s\'" % name)\n',
        "format": '    cur.execute("SELECT * FROM t WHERE o = \'{}\'".format(name))\n',
        "concat": '    cur.execute("SELECT * FROM t WHERE o = \'" + name + "\'")\n',
        "indirect": '    q = f"SELECT * FROM t WHERE o = \'{name}\'"\n    cur.execute(q)\n',
    }
    for style, body in bodies.items():
        assert kinds(route(body)) == [("sql", "name", False)], style


def test_parameterised_sql_is_not_a_flow_at_all():
    """The whole point: a bound value never becomes part of the statement, so there is nothing to screen."""
    assert route('    cur.execute("SELECT * FROM t WHERE o = ?", (name,))\n') == []
    assert route('    cur.execute("SELECT * FROM t WHERE o = %s", [name])\n') == []
    assert route('    q = "SELECT * FROM t WHERE o = :o"\n    cur.execute(q, {"o": name})\n') == []
    assert route('    cur.executemany("INSERT INTO t VALUES (?)", [(name,)])\n') == []


def test_execute_without_sql_text_is_not_a_sql_sink():
    assert route("    workflow.execute(name)\n") == []


def test_http_sink_for_every_client_shape():
    bodies = {
        "requests": "    requests.get(name)\n",
        "httpx": "    httpx.post(name, json={})\n",
        "urlopen": "    urllib.request.urlopen(name)\n",
        "kwarg": "    requests.request('GET', url=name)\n",
        "session_var": "    s = requests.Session()\n    s.get(name)\n",
        "aiohttp": "    aiohttp.ClientSession().get(name)\n",
    }
    for style, body in bodies.items():
        assert kinds(route(body)) == [("http", "name", False)], style


def test_dict_get_is_not_an_http_sink():
    assert route("    cfg.get(name)\n") == []


def test_deserialize_sink_and_safe_loader_guard():
    assert kinds(route("    pickle.loads(name)\n")) == [("deserialize", "name", False)]
    assert kinds(route("    yaml.load(name)\n")) == [("deserialize", "name", False)]
    assert kinds(route("    yaml.load(name, Loader=yaml.SafeLoader)\n")) == [("deserialize", "name", True)]
    assert route("    yaml.safe_load(name)\n") == []


# ---- new sources -----------------------------------------------------------------------------

def test_route_path_and_query_parameters_are_sources():
    src = '@app.get("/r/{rid}")\ndef handler(rid: str, q: str = ""):\n    open(rid)\n    requests.get(q)\n'
    assert kinds(analyze(src, "w.py")) == [("http", "q", False), ("path", "rid", False)]


def test_pydantic_body_field_is_named_as_the_source():
    src = '@app.post("/r")\ndef handler(body: ImportRequest):\n    requests.get(body.url)\n'
    (f,) = analyze(src, "w.py")
    assert f.source.param == "body.url" and f.sink.kind == "http"


def test_uploaded_filename_is_a_source():
    src = '@app.post("/r")\ndef handler(upload: UploadFile):\n    open(upload.filename, "wb")\n'
    (f,) = analyze(src, "w.py")
    assert f.source.param == "upload.filename" and f.sink.kind == "path"


def test_request_bags_are_sources_with_the_key_as_the_name():
    src = ('@app.get("/r")\ndef handler(request: Request):\n'
           '    a = request.query_params["one"]\n    b = request.form.get("two")\n'
           '    c = request.headers["three"]\n    open(a)\n    open(b)\n    open(c)\n')
    assert [f.source.param for f in analyze(src, "w.py")] == ["one", "two", "three"]


def test_request_body_without_a_key_is_named_after_the_bag():
    src = '@app.post("/r")\nasync def handler(request: Request):\n    body = await request.json()\n    open(body)\n'
    (f,) = analyze(src, "w.py")
    assert f.source.param == "request.json"


def test_request_object_alone_is_not_a_source_but_its_data_is():
    """A Request parameter is plumbing; only the attacker-controlled bags hanging off it are sources."""
    src = '@app.get("/r")\ndef handler(request: Request):\n    log(request)\n    open(request.args["f"])\n'
    assert [f.source.param for f in analyze(src, "w.py")] == ["f"]


def test_depends_injected_parameters_are_not_sources():
    src = '@app.get("/r")\ndef handler(user: User = Depends(current_user)):\n    open(user)\n'
    assert analyze(src, "w.py") == []


def test_function_reading_request_data_is_an_entry_point_without_a_decorator():
    """Flask views registered with add_url_rule carry no recognisable decorator."""
    src = 'def legacy_view():\n    cur.execute("SELECT * FROM t WHERE o = \'%s\'" % request.args["o"])\n'
    (f,) = analyze(src, "w.py")
    assert f.sink.kind == "sql" and f.source.param == "o" and not f.guarded


# ---- guards ----------------------------------------------------------------------------------

def test_placeholder_plus_params_guards_a_mixed_statement():
    """f-string SQL *and* bound values: only the interpolated part is a flow, and it reads as guarded."""
    body = '    cur.execute(f"SELECT * FROM {TABLE} WHERE o = ?", (name,))\n'
    fl = route(body, "name: str, TABLE: str")
    assert kinds(fl) == [("sql", "TABLE", True)]
    assert pick(fl, "sql", "TABLE")[0].guards == ["parameterised query"]


def test_taint_only_in_the_sql_params_is_the_guard_working_not_a_finding():
    assert route('    cur.execute("SELECT * FROM t WHERE o = ?", (name,))\n') == []
    assert route('    cur.execute(f"SELECT * FROM {TABLE} WHERE o = ?", (name,))\n', "name: str") == []


def test_taint_in_an_http_payload_is_not_ssrf():
    """Only the destination makes a request an SSRF; the body is just data being sent."""
    assert route('    httpx.post(ENDPOINT, json={"q": name})\n') == []
    assert route("    requests.post(ENDPOINT, data=name)\n") == []
    assert kinds(route('    httpx.post(name, json={"q": "x"})\n')) == [("http", "name", False)]


def test_client_construction_is_not_the_sink_the_request_is():
    body = "    c = httpx.Client(base_url=BASE, timeout=5)\n    c.get(name)\n"
    (f,) = route(body)
    assert f.sink.kind == "http" and "c.get(name)" in f.sink.code


def test_realpath_plus_startswith_containment_guards_a_path():
    body = ('    real = os.path.realpath(os.path.join(BASE, name))\n'
            '    if not real.startswith(BASE):\n        raise ValueError(name)\n'
            '    open(real)\n')
    (f,) = route(body)
    assert f.guarded and f.guards == ["realpath + startswith containment"]


def test_resolve_plus_is_relative_to_guards_a_path():
    body = ('    p = (BASE / name).resolve()\n'
            '    if not p.is_relative_to(BASE):\n        raise ValueError(name)\n'
            '    return p.read_text()\n')
    (f,) = route(body)
    assert f.guarded and f.guards == ["relative_to containment"]


def test_url_scheme_and_host_validation_guards_an_outbound_request():
    body = ('    parts = urlparse(name)\n'
            '    if parts.scheme not in ("http", "https") or parts.hostname not in ALLOWED:\n'
            '        raise ValueError(name)\n'
            '    requests.get(name)\n')
    (f,) = route(body)
    assert f.guarded and f.guards and f.sink.kind == "http"


def test_url_prefix_allowlist_guards_an_outbound_request():
    body = ('    if not name.startswith("https://reports.internal/"):\n        raise ValueError(name)\n'
            '    requests.get(name)\n')
    (f,) = route(body)
    assert f.guarded and f.guards == ["URL prefix allowlist"]


def test_argv_list_is_guarded_and_shell_string_is_not():
    (listed,) = route('    subprocess.run(["cat", name], check=True)\n')
    assert listed.guarded and listed.guards == ["argv list (shell=False)"]
    (shelled,) = route('    subprocess.run(f"cat {name}", shell=True)\n')
    assert not shelled.guarded
    (both,) = route('    subprocess.run(["sh", "-c", name], shell=True)\n')
    assert not both.guarded


def test_shlex_quote_guards_a_shell_string():
    (f,) = route('    subprocess.run(f"cat {shlex.quote(name)}", shell=True)\n')
    assert f.guarded and f.guards == ["shlex.quote"]


def test_helper_module_guard_is_credited_by_name_for_every_sink_kind():
    """The check lives in a shared module, so only the call to it is visible here."""
    cases = {
        "sql": '    safe = validate_identifier(name)\n    cur.execute(f"SELECT * FROM t WHERE o = \'{safe}\'")\n',
        "http": "    safe = validated_url(name)\n    requests.get(safe)\n",
        "path": "    safe = validated_path(BASE, name)\n    open(safe)\n",
        "exec": '    safe = ensure_token(name)\n    subprocess.run(f"cat {safe}", shell=True)\n',
    }
    for kind, body in cases.items():
        (f,) = route(body)
        assert f.sink.kind == kind and f.guarded and len(f.guards) == 1, kind


# ---- the fixture app -------------------------------------------------------------------------

def test_vulnerable_web_app_flows():
    assert kinds(analyze(WEB.read_text(), "app/main.py")) == [
        ("deserialize", "blob", False), ("exec", "fmt", False), ("exec", "name", False),
        ("http", "body.url", False), ("path", "name", False),
        ("sql", "owner", False), ("sql", "owner", False)]


def test_hardened_web_app_has_no_unguarded_flow():
    fl = analyze(WEB_FIXED.read_text(), "app/main.py")
    assert fl and all(f.guarded and f.guards for f in fl)
    assert not [f for f in fl if f.sink.kind == "sql"]          # parameterised: no flow to guard


def test_collection_route_under_a_router_prefix_is_an_entry_point():
    """APIRouter(prefix="/reports") + @router.get(""): the commonest FastAPI collection shape."""
    src = 'router = APIRouter(prefix="/reports")\n\n\n@router.get("")\ndef listing(owner: str):\n    open(owner)\n'
    (f,) = analyze(src, "w.py")
    assert f.sink.kind == "path" and f.source.param == "owner"
    kw = '@router.get(path="/x")\ndef h(owner: str):\n    open(owner)\n'
    assert len(analyze(kw, "w.py")) == 1
    assert analyze('@cache.get(key)\ndef h(owner: str):\n    open(owner)\n', "w.py") == []


def test_guard_survives_a_helper_call_boundary():
    """The guard is recorded against the names it was applied to; the helper argument only names the result."""
    src = ('@app.get("/x")\ndef handler(team_id: str, stored_name: str):\n'
           '    source = ensure_within(team_dir(team_id), stored_name)\n'
           '    run_tool([BINARY, str(source)], source.parent)\n\n'
           'def run_tool(argv, cwd):\n    subprocess.run(argv, cwd=cwd, shell=True)\n')
    flows = analyze(src, "w.py")
    assert flows and all(f.guarded and "ensure_within" in f.guards for f in flows)


def test_guard_name_match_is_kind_agnostic():
    """Before guards became kind-agnostic no exec or http flow could ever be marked guarded."""
    exec_src = ('@app.get("/x")\ndef handler(tool: str):\n    safe = validate_tool_argument(tool)\n'
                '    subprocess.run(f"run {safe}", shell=True)\n')
    http_src = ('@app.post("/y")\ndef handler(logo: str):\n    safe = validate_logo_url(logo)\n'
                '    requests.get(safe)\n')
    (e,) = analyze(exec_src, "w.py")
    (h,) = analyze(http_src, "w.py")
    assert (e.sink.kind, e.guards) == ("exec", ["validate_tool_argument"])
    assert (h.sink.kind, h.guards) == ("http", ["validate_logo_url"])
