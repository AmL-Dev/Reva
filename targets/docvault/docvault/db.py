"""SQLite access.

House rules for anything in this package that talks to the database:

1. Values are **bound parameters**. Build the SQL as a module-level constant or a
   local string made only of literals, and pass every request-supplied value in
   the ``params`` tuple. :func:`query` and :func:`execute` refuse to run without
   one so that the habit is hard to break by accident.
2. Identifiers (``ORDER BY`` columns, table names) cannot be bound, so they come
   from :func:`security.validate_sort_column` against a per-endpoint allowlist.
3. ``WHERE x IN (...)`` uses :func:`placeholders` to build the right number of
   ``?`` marks from the length of the list -- never from its contents.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable, Sequence

from .config import DB_PATH

SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    """One connection per request.

    ``check_same_thread=False`` is needed because a sync dependency is resolved
    on Starlette's threadpool while an ``async def`` endpoint body runs on the
    event loop; the connection is never shared between requests, so there is no
    concurrent use of a single handle.
    """
    conn = sqlite3.connect(str(path or DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_FILE.read_text())
    conn.commit()


def placeholders(values: Sequence[Any]) -> str:
    """``?, ?, ?`` for a list of three. Derived from the length, never the values."""
    return ", ".join("?" for _ in values)


def query(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
    """Run a SELECT with bound parameters and return every row.

    The preferred entry point for reads. ``params`` is positional and required
    in spirit: a query that needs no values passes ``()`` explicitly.
    """
    if not isinstance(params, (tuple, list, dict)):
        raise TypeError("params must be a sequence or mapping of bound values")
    cur = conn.execute(sql, params)
    try:
        return cur.fetchall()
    finally:
        cur.close()


def query_one(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
    rows = query(conn, sql, params)
    return rows[0] if rows else None


def execute(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> int:
    """Run an INSERT/UPDATE/DELETE with bound parameters; return the row id."""
    if not isinstance(params, (tuple, list, dict)):
        raise TypeError("params must be a sequence or mapping of bound values")
    cur = conn.execute(sql, params)
    conn.commit()
    try:
        return int(cur.lastrowid or 0)
    finally:
        cur.close()


def execute_many(conn: sqlite3.Connection, sql: str, rows: Iterable[Sequence[Any]]) -> None:
    conn.executemany(sql, list(rows))
    conn.commit()
