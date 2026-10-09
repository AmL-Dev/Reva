"""ClickHouse calibration memory: every screening is a row, every sandbox proof is a label.

Entirely optional and never on the critical path. Unconfigured, unreachable, slow or erroring,
every entry point here returns the neutral value (`None`, `{}`) and the pipeline behaves exactly
as it did before this module existed. Writes are queued and flushed by one worker thread; the
only hot-path read is `prior()`, bounded by QUERY_TIMEOUT and cached for PRIOR_TTL.
"""
from __future__ import annotations

import atexit
import logging
import os
import queue
import re
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("reva.analytics")

SCHEMA_SQL = Path(__file__).with_name("schema.sql")
QUERY_TIMEOUT = 0.25     # hard budget for the hot-path prior lookup
CONNECT_TIMEOUT = 20     # worker thread only; a ClickHouse Cloud service resumes from idle in ~25s
STARTUP_TIMEOUT = 180    # worker thread only: DDL and inserts, never the hot path
PRIOR_TTL = 30.0         # seconds a prior is reused from memory; the rollup moves slowly
FLUSH_INTERVAL = 0.5
QUEUE_MAX = 20000
PENDING_MAX = 4096
CACHE_MAX = 1024
# The default flipped between server versions; silent insert lag is worse than a slower insert.
INSERT_SETTINGS = {"async_insert": 1, "wait_for_async_insert": 1}

SCREENING_COLUMNS = ["screening_id", "ts", "repo", "file", "function", "sink_kind", "guarded",
                     "guards", "semgrep_rules", "p_llm", "confidence", "escalated", "prior_rate",
                     "prior_n", "gate_ms", "prior_ms", "semgrep_ms", "llm_ms", "total_ms",
                     "outcome", "finding_id", "version"]
VERDICT_COLUMNS = ["ts", "screening_id", "finding_id", "repo", "sink_kind", "guarded",
                   "semgrep_rules", "outcome", "confidence", "validate_ms"]

PRIOR_SQL = ("SELECT rule, sum(confirmed) AS hits, sum(total) AS n FROM {db}.prior_rollup "
             "WHERE sink_kind = {{k:String}} AND guarded = {{g:UInt8}} AND rule IN {{rules:Array(String)}} "
             "GROUP BY rule")


@dataclass(frozen=True)
class Prior:
    """Empirical outcome of past screenings of one shape. `rate` = confirmed / proven."""
    rate: float
    samples: int
    rule: str


def _flag(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default).lower() not in {"0", "off", "false", "no"}


@dataclass
class Config:
    host: str
    port: int
    user: str
    password: str
    database: str
    secure: bool


def config() -> Config | None:
    """Read REVA_CLICKHOUSE_* from the environment. None means "not configured", which is normal."""
    host = os.environ.get("REVA_CLICKHOUSE_HOST", "").strip()
    if not host or not _flag("REVA_CLICKHOUSE"):
        return None
    return Config(host=host, port=int(os.environ.get("REVA_CLICKHOUSE_PORT", "8443") or 8443),
                  user=os.environ.get("REVA_CLICKHOUSE_USER", "default"),
                  password=_password(), database=os.environ.get("REVA_CLICKHOUSE_DATABASE", "reva"),
                  secure=_flag("REVA_CLICKHOUSE_SECURE"))


def _password() -> str:
    """REVA_CLICKHOUSE_PASSWORD, or the contents of the file named by REVA_CLICKHOUSE_PASSWORD_FILE."""
    path = os.environ.get("REVA_CLICKHOUSE_PASSWORD_FILE", "").strip()
    if path:
        try:
            return Path(path).read_text().strip()
        except OSError as exc:
            log.warning("reva: cannot read REVA_CLICKHOUSE_PASSWORD_FILE %s (%s)", path, exc.strerror)
    return os.environ.get("REVA_CLICKHOUSE_PASSWORD", "")


class _Memory:
    """Owns the connection, the write queue and the worker. One instance per process."""

    def __init__(self) -> None:
        self.cfg: Config | None = None
        self.repo = ""
        self.q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self.latencies: deque[float] = deque(maxlen=512)
        self.down = False
        self._wclient = None     # inserts and DDL, worker thread only
        self._qclient = None     # reads, query-pool thread only: an insert can never block a prior
        self._worker: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="reva-ch-query")
        self._cache: dict[tuple, tuple[float, Prior | None]] = {}
        self._pending: dict[str, list] = {}
        self._ready = threading.Event()

    def start(self) -> bool:
        if self._worker is not None:
            return not self.down
        self.cfg = config()
        if self.cfg is None:
            self.down = True
            return False
        self._worker = threading.Thread(target=self._run, name="reva-clickhouse", daemon=True)
        self._worker.start()
        atexit.register(self.close)
        return True

    def _open(self):
        """Generous timeouts: an idle ClickHouse Cloud service takes ~25s to resume, and this runs
        on the worker thread. The hot path is bounded by QUERY_TIMEOUT instead, never by these."""
        import clickhouse_connect

        c = self.cfg
        return clickhouse_connect.get_client(
            host=c.host, port=c.port, username=c.user, password=c.password, secure=c.secure,
            connect_timeout=CONNECT_TIMEOUT, send_receive_timeout=STARTUP_TIMEOUT, client_name="reva",
            settings={"max_execution_time": STARTUP_TIMEOUT})

    def _connect(self) -> None:
        self._wclient = self._open()
        for stmt in _statements(SCHEMA_SQL.read_text(), self.cfg.database):
            self._wclient.command(stmt)
        self._wclient.database = self.cfg.database
        reader = self._open()
        reader.database = self.cfg.database
        self._qclient = reader

    def _run(self) -> None:
        try:
            self._connect()
        except Exception as exc:   # unreachable, bad credentials, missing driver: degrade silently
            self.down = True
            log.warning("reva: ClickHouse unavailable (%s: %s); calibration memory disabled",
                        type(exc).__name__, exc)
            self._ready.set()
            return
        log.info("reva: ClickHouse calibration memory at %s:%s/%s", self.cfg.host, self.cfg.port, self.cfg.database)
        self._ready.set()
        stop = False
        while not stop:
            items, stop = self._drain()
            self._insert(items)

    def _drain(self) -> tuple[list, bool]:
        """Block up to FLUSH_INTERVAL for work, then sweep the queue. The None sentinel means stop,
        and is only ever read after everything queued before it has been swept into `items`."""
        items: list = []
        try:
            items.append(self.q.get(timeout=FLUSH_INTERVAL))
        except queue.Empty:
            return items, False
        while items[-1] is not None:
            try:
                items.append(self.q.get_nowait())
            except queue.Empty:
                return items, False
        return items[:-1], True

    def _insert(self, items: list) -> None:
        if not items or self._wclient is None:
            return
        for table, columns in (("screenings", SCREENING_COLUMNS), ("verdicts", VERDICT_COLUMNS)):
            rows = [r for t, r in items if t == table]
            if not rows:
                continue
            try:
                self._wclient.insert(table, rows, column_names=columns, settings=INSERT_SETTINGS)
            except Exception as exc:
                log.warning("reva: ClickHouse insert of %d %s rows failed (%s)", len(rows), table, exc)

    def close(self) -> None:
        """Flush everything queued, then stop. Called at exit and by the server lifespan."""
        if self._worker is None or not self._worker.is_alive():
            return
        with suppress(queue.Full):
            self.q.put(None, timeout=1)
        self._worker.join(timeout=10)

    def put(self, table: str, row: list) -> None:
        if self.down or self._worker is None:
            return
        try:
            self.q.put_nowait((table, row))
        except queue.Full:
            pass

    def remember(self, finding_id: str, row: list) -> None:
        if len(self._pending) >= PENDING_MAX:
            self._pending.clear()
        self._pending[finding_id] = row

    def take(self, finding_id: str) -> list | None:
        return self._pending.pop(finding_id, None)

    def prior(self, sink_kind: str, guarded: bool, rules: list[str]) -> Prior | None:
        if self.down or self._qclient is None:
            return None
        key = (sink_kind, guarded, tuple(sorted(rules)))
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < PRIOR_TTL:
            return hit[1]
        started = time.perf_counter()
        try:
            rows = self._pool.submit(self._query_prior, sink_kind, guarded, rules).result(QUERY_TIMEOUT)
        except Exception as exc:
            log.debug("reva: prior lookup skipped (%s)", type(exc).__name__)
            return hit[1] if hit else None   # a stale prior beats none; the bound makes it safe
        self.latencies.append((time.perf_counter() - started) * 1000)
        best = _best(rows)
        if len(self._cache) >= CACHE_MAX:
            self._cache.clear()
        self._cache[key] = (time.monotonic(), best)
        return best

    def _query_prior(self, sink_kind: str, guarded: bool, rules: list[str]):
        return self._qclient.query(
            PRIOR_SQL.format(db=self.cfg.database),
            parameters={"k": sink_kind, "g": int(guarded), "rules": [""] + sorted(set(rules))},
        ).result_rows

    def query(self, sql: str, timeout: float = 2.0):
        """Ad-hoc read for the UI panel. [] on anything going wrong."""
        if self.down or self._qclient is None:
            return []
        try:
            return self._pool.submit(self._run_query, sql).result(timeout)
        except Exception:
            return []

    def _run_query(self, sql: str):
        return self._qclient.query(sql.format(db=self.cfg.database)).result_rows


def _statements(ddl: str, database: str) -> list[str]:
    """schema.sql, comments stripped, split into idempotent statements and retargeted at `database`."""
    body = "\n".join(line.split("--")[0] for line in ddl.splitlines())
    body = re.sub(r"\breva\b", database, body)   # comments are gone, so every bare `reva` is the database
    return [s.strip() for s in body.split(";") if s.strip()]


def _best(rows) -> Prior | None:
    """Prefer the most specific bucket that has any data: a firing rule over the '' bucket."""
    buckets = [Prior(rate=int(h) / int(n), samples=int(n), rule=str(r)) for r, h, n in rows if int(n) > 0]
    if not buckets:
        return None
    return max(buckets, key=lambda b: (b.rule != "", b.samples))


_mem = _Memory()


def start(repo: str = "") -> bool:
    _mem.repo = repo
    return _mem.start()


def set_repo(repo: str) -> None:
    """Which repository the rows written from now on belong to. `corpus.py` moves between many."""
    _mem.repo = repo


def close() -> None:
    _mem.close()


def enabled() -> bool:
    return not _mem.down and _mem._qclient is not None


def wait_ready(timeout: float = 10.0) -> bool:
    """Block until the worker has finished its first connection attempt. For scripts and tests."""
    return _mem._ready.wait(timeout) and enabled()


def reset() -> None:
    """Drop all process state. Tests call this; nothing else should."""
    global _mem
    _mem.close()
    _mem = _Memory()


def prior(sink_kind: str, guarded: bool, rules: list[str]) -> Prior | None:
    return _mem.prior(sink_kind, guarded, rules)


def query(sql: str, timeout: float = 2.0) -> list:
    """`{db}` in `sql` is the configured database. [] when there is no ClickHouse or it errors."""
    return _mem.query(sql, timeout)


def latency_percentiles() -> dict:
    xs = sorted(_mem.latencies)
    if not xs:
        return {}
    return {"n": len(xs), "p50": round(xs[len(xs) // 2], 2),
            "p99": round(xs[min(len(xs) - 1, int(len(xs) * 0.99))], 2),
            "max": round(xs[-1], 2)}


def log_screening(file: str, function: str, sink_kind: str, guarded: bool,
                  guards: list[str], rules: list[str], p_llm: float | None, confidence: float,
                  escalated: bool, prior_: Prior | None, timings: dict, finding_id: str = "") -> None:
    """Queue one screening row. Returns immediately; nothing here touches the network."""
    if _mem.down or _mem._worker is None:
        return
    row = [uuid.uuid4(), datetime.now(timezone.utc).replace(tzinfo=None), _mem.repo, file, function,
           sink_kind, int(guarded), list(guards), list(rules),
           -1.0 if p_llm is None else float(p_llm), float(confidence), int(escalated),
           -1.0 if prior_ is None else prior_.rate, 0 if prior_ is None else prior_.samples,
           *(float(timings.get(k, 0.0)) for k in ("gate_ms", "prior_ms", "semgrep_ms", "llm_ms", "total_ms")),
           "", finding_id, 1]
    _mem.put("screenings", row)
    if finding_id:
        _mem.remember(finding_id, row)


def log_outcome(finding_id: str, outcome: str, validate_ms: float = 0.0) -> None:
    """Attach a proven label: re-insert the screening row with its outcome, and record the verdict."""
    row = _mem.take(finding_id)
    if row is None:
        return
    labelled = list(row)
    labelled[SCREENING_COLUMNS.index("outcome")] = outcome
    labelled[SCREENING_COLUMNS.index("version")] = 2
    _mem.put("screenings", labelled)
    _mem.put("verdicts", [row[1], row[0], finding_id, row[2], row[5], row[6], row[8],
                          outcome, row[10], float(validate_ms)])
