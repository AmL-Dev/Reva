import os
import socket
import time
import types

import pytest

from reva import analytics, detector
from reva.analytics import Prior
from reva.detector import Change, screen
from reva.types import Flow, Sink, Source, ThreatModel

TEST_HOST = os.environ.get("REVA_TEST_CLICKHOUSE_HOST", "127.0.0.1")
TEST_PORT = int(os.environ.get("REVA_TEST_CLICKHOUSE_PORT", "8123"))


def local_clickhouse() -> bool:
    try:
        with socket.create_connection((TEST_HOST, TEST_PORT), timeout=0.3):
            return True
    except OSError:
        return False


needs_clickhouse = pytest.mark.skipif(not local_clickhouse(),
                                      reason=f"no ClickHouse on {TEST_HOST}:{TEST_PORT}")


def flow(function, kind="path", guarded=False, guards=()):
    return Flow(source=Source(function=function, param="repo_path", file="s.py", line=1),
                sink=Sink(kind=kind, function=function, file="s.py", line=5, code="git.Repo(repo_path)"),
                guarded=guarded, guards=list(guards), path=[function])


def tm(*flows):
    return ThreatModel(summary="s", assets=[], trust_boundaries=["--repository"],
                       flows=list(flows), questions=["q?"])


@pytest.fixture
def fake_dataflow(monkeypatch):
    def install(flows):
        mod = types.SimpleNamespace(
            analyze=lambda source, file: flows,
            flows_for_function=lambda fl, name: [f for f in fl if f.sink.function == name])
        monkeypatch.setitem(__import__("sys").modules, "reva.dataflow", mod)
        monkeypatch.setattr(detector.llm, "available", lambda: False)
    return install


def change(function="call_tool"):
    return Change(file="s.py", function=function, old_code="",
                  new_code=f"def {function}(repo_path): ...", source="x = 1\n")


# -- the pipeline is unchanged without a ClickHouse ------------------------------------------

def test_unconfigured_clickhouse_changes_nothing(fake_dataflow):
    fake_dataflow([flow("call_tool")])
    assert not analytics.enabled()
    [f] = screen(change(), tm())
    assert f.confidence == detector.BASE_UNGUARDED and analytics.prior("path", False, []) is None


def test_unreachable_clickhouse_never_raises(monkeypatch, fake_dataflow):
    monkeypatch.setenv("REVA_CLICKHOUSE", "1")
    monkeypatch.setenv("REVA_CLICKHOUSE_HOST", "127.0.0.1")
    monkeypatch.setenv("REVA_CLICKHOUSE_PORT", "1")       # nothing listens there
    monkeypatch.setenv("REVA_CLICKHOUSE_SECURE", "0")
    analytics.start("t")
    analytics.wait_ready(20)
    assert not analytics.enabled() and analytics.prior("path", False, []) is None
    analytics.log_screening("s.py", "f", "path", False, [], [], None, 0.6, True, None, {}, "fid")
    analytics.log_outcome("fid", "confirmed")
    assert analytics.query("SELECT 1") == []
    fake_dataflow([flow("call_tool")])
    [f] = screen(change(), tm())
    assert f.confidence == detector.BASE_UNGUARDED            # byte-identical to no ClickHouse at all


def test_password_comes_from_a_file(monkeypatch, tmp_path):
    secret = tmp_path / "pw"
    secret.write_text("hunter2\n")
    monkeypatch.setenv("REVA_CLICKHOUSE", "1")
    monkeypatch.setenv("REVA_CLICKHOUSE_HOST", "example.invalid")
    monkeypatch.setenv("REVA_CLICKHOUSE_PASSWORD_FILE", str(secret))
    cfg = analytics.config()
    assert cfg.password == "hunter2" and cfg.port == 8443 and cfg.secure and cfg.database == "reva"
    monkeypatch.setenv("REVA_CLICKHOUSE_PASSWORD_FILE", str(tmp_path / "missing"))
    assert analytics.config().password == ""                  # unreadable file is not fatal


def test_disable_switch_wins_over_a_host(monkeypatch):
    monkeypatch.setenv("REVA_CLICKHOUSE_HOST", "example.invalid")
    monkeypatch.setenv("REVA_CLICKHOUSE", "0")
    assert analytics.config() is None


# -- the guardrails -------------------------------------------------------------------------

def test_a_guarded_flow_stays_at_zero_whatever_the_prior_says():
    for rate in (0.0, 0.5, 1.0):
        assert detector.calibrate(False, True, 1.0, True, Prior(rate, 10_000, "r")) == 0.0


def test_the_prior_cannot_raise_a_finding_on_its_own(fake_dataflow, monkeypatch):
    fake_dataflow([flow("safe_tool", guarded=True, guards=["validate_repo_path"])])
    monkeypatch.setattr(analytics, "prior", lambda *a: Prior(1.0, 10_000, "r"))
    assert screen(change("safe_tool"), tm()) == []


def test_the_prior_is_bounded_by_prior_weight():
    for static in (0.55, 0.75, 0.85, 1.0):
        for rate in (0.0, 0.1, 0.5, 0.9, 1.0):
            moved = detector.blend_prior(static, Prior(rate, detector.PRIOR_MIN_SAMPLES, ""))
            assert abs(moved - static) <= detector.PRIOR_WEIGHT + 1e-9
            assert 0.0 <= moved <= 1.0


def test_below_the_minimum_sample_count_the_constants_are_untouched():
    for n in range(detector.PRIOR_MIN_SAMPLES):
        assert detector.calibrate(True, False, None, False, Prior(0.0, n, "r")) == detector.BASE_UNGUARDED
        assert detector.calibrate(True, True, 0.9, True, Prior(1.0, n, "r")) == \
            detector.calibrate(True, True, 0.9, True, None)


def test_at_the_minimum_sample_count_the_prior_starts_to_move_the_score():
    cold = detector.calibrate(True, False, None, False, Prior(0.0, detector.PRIOR_MIN_SAMPLES, "r"))
    hot = detector.calibrate(True, False, None, False, Prior(1.0, detector.PRIOR_MIN_SAMPLES, "r"))
    assert cold < detector.BASE_UNGUARDED < hot
    assert hot - cold == pytest.approx(detector.PRIOR_WEIGHT, abs=1e-3)


def test_an_empirically_cold_shape_buys_no_llm_call(fake_dataflow, monkeypatch):
    """The point of the integration: the prior decides whether the expensive call happens."""
    fake_dataflow([flow("call_tool")])
    calls = []
    monkeypatch.setattr(detector.llm, "available", lambda: True)
    monkeypatch.setattr(detector.llm, "complete_json",
                        lambda *a, **k: calls.append(1) or {"answers": [{"question": "q", "answer": "yes",
                                                                         "justification": "j", "probability": 0.95}]})
    monkeypatch.setattr(analytics, "prior", lambda *a: Prior(0.0, 500, "rule"))
    assert screen(change(), tm()) == [] and calls == []
    monkeypatch.setattr(analytics, "prior", lambda *a: Prior(0.9, 500, "rule"))
    assert len(screen(change(), tm())) == 1 and len(calls) == 1


def test_a_confirmed_shape_shows_up_in_the_reasoning(fake_dataflow, monkeypatch):
    fake_dataflow([flow("call_tool")])
    monkeypatch.setattr(analytics, "prior", lambda *a: Prior(0.8, 40, "python.lang.x"))
    [f] = screen(change(), tm())
    assert "80% of 40 proven screenings" in f.reasoning and "python.lang.x" in f.reasoning


def test_best_bucket_prefers_a_rule_over_the_unconditional_one():
    rows = [("", 10, 100), ("python.lang.x", 9, 10)]
    assert analytics._best(rows) == Prior(0.9, 10, "python.lang.x")
    assert analytics._best([("", 10, 100)]) == Prior(0.1, 100, "")
    assert analytics._best([("", 0, 0)]) is None


def test_schema_statements_retarget_the_database():
    stmts = analytics._statements(analytics.SCHEMA_SQL.read_text(), "other")
    assert stmts[0] == "CREATE DATABASE IF NOT EXISTS other"
    assert all("--" not in s for s in stmts) and len(stmts) == 5
    assert any("ReplacingMergeTree(version)" in s for s in stmts)
    assert any("MATERIALIZED VIEW IF NOT EXISTS other.prior_mv" in s for s in stmts)


# -- against a real server -------------------------------------------------------------------

@needs_clickhouse
def test_rows_round_trip_through_clickhouse(monkeypatch):
    db = f"reva_test_{int(time.time() * 1000)}"
    monkeypatch.setenv("REVA_CLICKHOUSE", "1")
    monkeypatch.setenv("REVA_CLICKHOUSE_HOST", TEST_HOST)
    monkeypatch.setenv("REVA_CLICKHOUSE_PORT", str(TEST_PORT))
    monkeypatch.setenv("REVA_CLICKHOUSE_SECURE", "0")
    monkeypatch.setenv("REVA_CLICKHOUSE_DATABASE", db)
    analytics.start("unit")
    assert analytics.wait_ready(30)
    timings = {"gate_ms": 1.0, "semgrep_ms": 2.0, "llm_ms": 3.0, "prior_ms": 0.5, "total_ms": 6.5}
    for i in range(25):
        analytics.log_screening("s.py", f"f{i}", "git_arg", False, ["g"], ["rule.a"], 0.9, 0.74,
                                True, None, timings, f"fid{i}")
        analytics.log_outcome(f"fid{i}", "confirmed" if i % 5 else "rejected")
    analytics.log_screening("s.py", "quiet", "path", True, ["is_relative_to"], [], None, 0.0,
                            False, None, {"gate_ms": 0.2, "total_ms": 0.2})
    analytics.close()                                     # nothing may be lost at shutdown
    analytics.start("unit")
    assert analytics.wait_ready(30)
    [(rows, labelled, quiet)] = analytics.query(
        "SELECT count(), countIf(outcome != ''), countIf(sink_kind = '') FROM {db}.screenings FINAL")
    assert (rows, labelled, quiet) == (26, 25, 0)
    assert analytics.query("SELECT count() FROM {db}.verdicts") == [(25,)]
    p = analytics.prior("git_arg", False, ["rule.a"])
    assert p.samples == 25 and p.rate == pytest.approx(20 / 25) and p.rule == "rule.a"
    assert analytics.latency_percentiles()["p50"] > 0
    analytics.query("DROP DATABASE IF EXISTS {db}")
