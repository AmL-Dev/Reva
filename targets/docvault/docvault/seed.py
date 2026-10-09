"""Create the database and fill it with a small amount of realistic data.

    python -m docvault.seed              # uses DOCVAULT_DB
    python -m docvault.seed --reset      # drop the file first
"""
from __future__ import annotations

import argparse
from pathlib import Path

import json

from . import db
from .config import DIAGNOSTICS_ROOT, ensure_dirs, DB_PATH

TEAMS = [
    (1, "platform", "Platform Engineering", "https://hooks.internal.example.com/platform", None),
    (2, "finance", "Finance Operations", "https://hooks.internal.example.com/finance", None),
]

USERS = [
    (1, "dana@example.com", "Dana Okafor", "dv_admin_platform_8f21", "admin", 1),
    (2, "sam@example.com", "Sam Ito", "dv_member_platform_41ab", "member", 1),
    (3, "rhea@example.com", "Rhea Bakshi", "dv_admin_finance_77cd", "admin", 2),
    (4, "lee@example.com", "Lee Harmon", "dv_member_finance_9e03", "member", 2),
]

REPORTS = [
    (1, "Q3 platform availability", "99.94% across all regions; two partial incidents.", "published", 1, 1),
    (2, "Storage cost review", "Object storage grew 18% quarter on quarter.", "review", 2, 1),
    (3, "Incident 2411 postmortem", "Cache stampede after a config rollout.", "draft", 2, 1),
    (4, "FY close checklist", "Owner sign-off for each ledger.", "published", 3, 2),
    (5, "Vendor renewal summary", "Six renewals due before January.", "draft", 4, 2),
]


def _seed_diagnostics() -> None:
    """Stand in for the nightly diagnostics job."""
    day = DIAGNOSTICS_ROOT / "2026-10-08"
    day.mkdir(parents=True, exist_ok=True)
    (day / "queues.json").write_text(json.dumps({"ingest": 0, "convert": 2, "webhooks": 0}, indent=2))
    (day / "storage.json").write_text(json.dumps({"teams": 2, "documents": 0}, indent=2))


def seed(path: Path | str | None = None, reset: bool = False) -> Path:
    target = Path(path or DB_PATH)
    ensure_dirs()
    _seed_diagnostics()
    if reset and target.exists():
        target.unlink()
    conn = db.connect(target)
    try:
        db.init_schema(conn)
        db.execute_many(conn, "INSERT OR REPLACE INTO teams (id, slug, name, webhook_url, logo_path) VALUES (?, ?, ?, ?, ?)", TEAMS)
        db.execute_many(conn, "INSERT OR REPLACE INTO users (id, email, name, api_key, role, team_id) VALUES (?, ?, ?, ?, ?, ?)", USERS)
        db.execute_many(conn, "INSERT OR REPLACE INTO reports (id, title, summary, status, owner_id, team_id) VALUES (?, ?, ?, ?, ?, ?)", REPORTS)
        db.execute_many(conn, "INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)",
                        [("dana@example.com", "seed", "initial data loaded")])
    finally:
        conn.close()
    return target


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed the DocVault database")
    ap.add_argument("--db", default=None)
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    print(f"seeded {seed(args.db, args.reset)}")


if __name__ == "__main__":
    main()
