"""The offline demo (`python demo/fake.py watch target`) must speak the same contracts as reva/server.py."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))
import fake  # noqa: E402

from reva import server  # noqa: E402
from reva.detector import Change as RealChange  # noqa: E402
from reva.types import Finding  # noqa: E402

BODY = "def git_diff(repo, target, context_lines=3):\n    return repo.git.diff(target)\n"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(fake.time, "sleep", lambda _: None)


def change(function, new_code):
    return fake.Change(fake.F, function, "", new_code, new_code)


def test_fake_change_matches_the_real_change():
    assert list(fake.Change._fields) == list(RealChange.__dataclass_fields__)
    assert server.unified(change("git_diff", BODY)).startswith(f"--- a/{fake.F}")


def test_fake_screen_only_fires_on_the_finished_body():
    tm = fake.TM
    assert fake.screen(change("git_diff", BODY), tm) and not fake.screen(change("git_status", BODY), tm)
    assert not fake.screen(change("git_diff", "def git_diff(repo, target):\n    raise NotImplementedError\n"), tm)


def test_fake_discover_indexes_into_the_fake_threat_model():
    flows = fake.discover(change("git_diff", BODY))
    assert [f.sink.function for f in flows] == ["git_diff"]
    assert fake.merge(fake.TM, flows) == [0]
    assert fake.discover(change("git_tag_list", "def git_tag_list(repo, pattern=None): ...")) == []


def test_install_registers_every_entry_point_server_calls():
    names = ("reva.threatmodel", "reva.detector", "reva.validate", "reva.patch")
    saved = {n: sys.modules.get(n) for n in names}
    try:
        fake.install()
        tmod, det, val, pat = (sys.modules[n] for n in names)
        assert tmod.load("target") is fake.TM and tmod.build(Path("target"), None) is fake.TM
        assert tmod.save(fake.TM, Path("target")) is None
        assert (det.Change, det.screen, det.discover, tmod.merge, val.validate, pat.propose, pat.verify) == (
            fake.Change, fake.screen, fake.discover, fake.merge, fake.validate, fake.propose, fake.verify)
    finally:
        for n, mod in saved.items():
            if mod is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = mod


@pytest.mark.parametrize("function", ["git_diff", "git_checkout"])
def test_fake_pipeline_ends_in_a_patched_finding(function):
    param = fake.BUGS[function][1]
    [f] = fake.screen(change(function, f"def {function}(repo, {param}):\n    pass\n"), fake.TM)
    f = fake.validate(f, "target")
    assert f.status == "confirmed" and f.evidence and f.exploit
    diff = fake.propose(f, "source")
    out = fake.verify(f, "target", diff)
    assert isinstance(out, Finding) and out.status == "patched" and out.patch == diff
