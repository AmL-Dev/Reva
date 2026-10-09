from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Point every configurable path at a temp dir and reload the package."""
    monkeypatch.setenv("DOCVAULT_STORAGE", str(tmp_path / "storage"))
    monkeypatch.setenv("DOCVAULT_EXPORTS", str(tmp_path / "exports"))
    monkeypatch.setenv("DOCVAULT_DB", str(tmp_path / "docvault.db"))
    monkeypatch.setenv("DOCVAULT_LOG", str(tmp_path / "docvault.log"))
    monkeypatch.setenv("DOCVAULT_OUTBOUND_HOSTS", "hooks.internal.example.com,cdn.internal.example.com")
    for name in [m for m in list(sys.modules) if m == "docvault" or m.startswith("docvault.")]:
        del sys.modules[name]
    config = importlib.import_module("docvault.config")
    config.ensure_dirs()
    return config


@pytest.fixture()
def client(env):
    from fastapi.testclient import TestClient

    from docvault.app import create_app
    from docvault.seed import seed

    seed(env.DB_PATH, reset=True)
    with TestClient(create_app(env.DB_PATH)) as c:
        yield c


@pytest.fixture()
def admin_key() -> str:
    return "dv_admin_platform_8f21"


@pytest.fixture()
def member_key() -> str:
    return "dv_member_platform_41ab"


@pytest.fixture()
def other_team_key() -> str:
    return "dv_admin_finance_77cd"


@pytest.fixture(autouse=True)
def _diagnostics_env(monkeypatch, tmp_path):
    monkeypatch.setenv("DOCVAULT_DIAGNOSTICS", str(tmp_path / "diagnostics"))
