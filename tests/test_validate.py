from pathlib import Path

import pytest

from reva import llm
from reva.patch import propose, verify
from reva.types import Finding
from reva.validate import probe_for, validate

FIX = Path(__file__).parent / "fixtures"
VULN, FIXED = FIX / "vuln", FIX / "fixed"


def finding(cwe, function):
    return Finding(id="t", title="t", file="mcp_server_git/server.py", function=function, line=1, cwe=cwe)


def test_llm_unreachable_endpoint(monkeypatch):
    monkeypatch.setenv("REVA_BASE_URL", "http://127.0.0.1:9/v1")
    assert not llm.available()
    with pytest.raises(RuntimeError):
        llm.complete_json("s", "u")


def test_last_json_object_from_reasoning():
    assert llm._last_json_object('thinking {"a": 1} then {"b": {"c": 2}} done') == {"b": {"c": 2}}
    assert llm._last_json_object("none") is None


CASES = [("CWE-22", "call_tool"), ("CWE-88", "git_diff"), ("CWE-88", "git_checkout")]


def test_probe_is_selected_per_sink_function():
    assert "git_checkout" in probe_for("CWE-88", "git_checkout")
    assert "git_diff" in probe_for("CWE-88", "git_diff")
    assert probe_for("CWE-88", "git_checkout") != probe_for("CWE-88", "git_diff")
    assert probe_for("CWE-22", "git_log") == probe_for("CWE-22", "call_tool")
    assert probe_for("CWE-88", "git_branch") is None and probe_for("CWE-502", "restore_session") is None


@pytest.mark.parametrize("cwe,function", CASES)
def test_exploit_confirms_on_vulnerable_and_is_rejected_on_fixed(cwe, function):
    hit = validate(finding(cwe, function), VULN)
    assert hit.status == "confirmed" and hit.impact >= 4 and hit.likelihood >= 1
    assert "reproduced" not in hit.evidence and hit.exploit
    miss = validate(finding(cwe, function), FIXED)
    assert miss.status == "rejected" and miss.impact == 0


def test_unprovable_finding_stays_unproven():
    f = validate(finding("CWE-502", "restore_session"), VULN)
    assert f.status == "suspected" and f.impact == 0 and f.likelihood == 0
    assert "unproven" in f.evidence and not f.exploit


def test_web_probe_on_a_target_without_an_app_proves_nothing():
    """A probe that cannot be set up demonstrates nothing, so the finding may not be 'rejected'."""
    f = validate(finding("CWE-89", "search_reports"), VULN)
    assert f.status == "suspected" and f.impact == 0 and not f.exploit
    assert "unproven" in f.evidence and "nothing was demonstrated" in f.evidence


@pytest.mark.parametrize("cwe,function", CASES)
def test_patch_proposed_and_verified(cwe, function):
    source = (VULN / "mcp_server_git/server.py").read_text()
    diff = propose(finding(cwe, function), source)
    assert diff.startswith("--- a/mcp_server_git/server.py")
    patched = verify(validate(finding(cwe, function), VULN), VULN, diff)
    assert patched.status == "patched" and patched.patch == diff
    assert "fix holds" in patched.validation


def test_no_patch_for_already_fixed_source():
    source = (FIXED / "mcp_server_git/server.py").read_text()
    assert propose(finding("CWE-22", "call_tool"), source) == ""
    assert propose(finding("CWE-88", "git_diff"), source) == ""
    assert propose(finding("CWE-88", "git_checkout"), source) == ""


def test_bad_patch_does_not_mark_patched():
    f = verify(finding("CWE-22", "call_tool").model_copy(update={"status": "confirmed"}), VULN, "--- a/nope\n+++ b/nope\n@@ -1 +1 @@\n-x\n+y\n")
    assert f.status == "confirmed" and "did not apply" in f.validation


WEB_VULN, WEB_FIXED = FIX / "webvuln", FIX / "webfixed"
WEB_CASES = [("CWE-89", "search_reports"), ("CWE-89", "legacy_search"), ("CWE-918", "import_document"),
             ("CWE-78", "export_document"), ("CWE-22", "read_document")]


def web_finding(cwe, function):
    return Finding(id="t", title="t", file="app/main.py", function=function, line=1, cwe=cwe)


@pytest.mark.parametrize("cwe,function", WEB_CASES)
def test_web_probe_confirms_on_vulnerable_app_and_is_rejected_on_hardened_app(cwe, function):
    hit = validate(web_finding(cwe, function), WEB_VULN)
    assert hit.status == "confirmed" and hit.impact >= 4 and hit.likelihood >= 1 and hit.exploit
    miss = validate(web_finding(cwe, function), WEB_FIXED)
    assert miss.status == "rejected" and miss.impact == 0


def test_sql_probe_proves_unintended_data_access_not_a_syntax_error():
    hit = validate(web_finding("CWE-89", "search_reports"), WEB_VULN)
    assert "REVA-CANARY-SQL" in hit.evidence and "control request" in hit.evidence


def test_ssrf_probe_proves_a_fetch_of_the_sandbox_canary_server():
    hit = validate(web_finding("CWE-918", "import_document"), WEB_VULN)
    assert "127.0.0.1" in hit.evidence and "canary server" in hit.evidence


def test_command_injection_probe_proves_a_canary_outside_the_app_directory():
    hit = validate(web_finding("CWE-78", "export_document"), WEB_VULN)
    assert "canary_cmd.txt" in hit.evidence and "outside the application directory" in hit.evidence


def test_web_path_probe_proves_a_read_outside_the_document_directory():
    hit = validate(web_finding("CWE-22", "read_document"), WEB_VULN)
    assert "canary_secret.txt" in hit.evidence and "../" in hit.evidence


@pytest.mark.parametrize("cwe,function", WEB_CASES)
def test_web_patch_proposed_and_the_same_probe_confirms_the_fix(cwe, function):
    source = (WEB_VULN / "app/main.py").read_text()
    diff = propose(web_finding(cwe, function), source)
    assert diff.startswith("--- a/app/main.py")
    hit = validate(web_finding(cwe, function), WEB_VULN)
    patched = verify(hit, WEB_VULN, diff)
    assert patched.status == "patched" and "fix holds" in patched.validation
    assert patched.exploit == hit.exploit        # the same probe, re-run against the patched copy


def test_sql_patch_binds_the_value_instead_of_pasting_it():
    source = (WEB_VULN / "app/main.py").read_text()
    diff = propose(web_finding("CWE-89", "search_reports"), source)
    assert "+    cur.execute('SELECT id, title, body FROM reports WHERE owner = ?', (owner,))" in diff


def test_no_web_patch_for_already_hardened_source():
    source = (WEB_FIXED / "app/main.py").read_text()
    for cwe, function in WEB_CASES:
        assert propose(web_finding(cwe, function), source) == "", f"{cwe} {function}"


def test_path_patch_contains_the_join_and_keeps_nested_names_working():
    """`base / name` becomes a contained join, so a dated subdirectory still resolves."""
    source = ("DOCS = Path('docs')\n\n\n@app.get('/d')\ndef read_dump(name: str):\n"
              "    target = DOCS / name\n    return target.read_text()\n")
    diff = propose(web_finding("CWE-22", "read_dump"), source)
    assert "+    target = contained_path(DOCS, name)" in diff
    assert "def contained_path(base, name):" in diff
    assert "basename" not in diff


def test_no_path_patch_when_the_join_is_already_contained():
    source = ("DOCS = Path('docs')\n\n\n@app.get('/d')\ndef read_dump(name: str):\n"
              "    target = ensure_within(DOCS, name)\n    return target.read_text()\n")
    assert propose(web_finding("CWE-22", "read_dump"), source) == ""
