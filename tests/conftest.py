import os

import pytest

from reva import analytics, semgrep


@pytest.fixture(autouse=True)
def offline_semgrep(monkeypatch):
    """No test shells out to semgrep or its registry; tests/test_semgrep.py installs its own hits."""
    semgrep._cache.clear()
    monkeypatch.setattr(semgrep, "_scan", lambda file, content: [])


@pytest.fixture(autouse=True)
def offline_clickhouse(monkeypatch):
    """No test reaches a ClickHouse: the calibration memory is unconfigured unless a test says otherwise."""
    for key in [k for k in os.environ if k.startswith("REVA_CLICKHOUSE")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("REVA_CLICKHOUSE", "0")
    analytics.reset()
    yield
    analytics.reset()
