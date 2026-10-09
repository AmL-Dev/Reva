"""In-memory event log, findings and counters, with asyncio pub/sub for SSE."""
from __future__ import annotations

import asyncio
import time
from collections import deque

from .types import Finding, ThreatModel

COUNTERS = ("screened", "flagged", "confirmed", "quiet")
# screened/quiet count screenings, one per saved function; flagged/confirmed count distinct findings.


class Store:
    def __init__(self) -> None:
        self.events: deque[dict] = deque(maxlen=500)
        self.findings: dict[str, Finding] = {}
        self.counters = dict.fromkeys(COUNTERS, 0)
        self.marked: dict[str, set[str]] = {}
        self.threat_model: ThreatModel | None = None
        self._seq = 0
        self._subs: set[asyncio.Queue] = set()

    def publish(self, type: str, **data) -> dict:
        self._seq += 1
        event = {"id": self._seq, "type": type, "ts": time.time(), "data": data}
        self.events.append(event)
        for q in self._subs:
            q.put_nowait(event)
        return event

    def bump(self, name: str, n: int = 1) -> None:
        self.counters[name] += n
        self.publish("counters", **self.counters)

    def mark(self, name: str, key: str) -> None:
        """Count one distinct finding once, however many later passes rediscover it."""
        seen = self.marked.setdefault(name, set())
        if key not in seen:
            seen.add(key)
            self.bump(name)

    def set_threat_model(self, tm: ThreatModel) -> None:
        self.threat_model = tm
        self.publish("threatmodel", **tm.model_dump())

    def upsert(self, finding: Finding) -> None:
        self.findings[finding.id] = finding
        self.publish("finding", **finding.model_dump())

    def snapshot(self) -> dict:
        return {
            "threat_model": self.threat_model.model_dump() if self.threat_model else None,
            "findings": [f.model_dump() for f in self.findings.values()],
            "counters": self.counters,
            "events": list(self.events)[-200:],
            "last_id": self._seq,
        }

    async def subscribe(self, after: int = 0):
        """Yield events with id > after, then live ones. Subscribes before replaying so nothing is missed."""
        q: asyncio.Queue = asyncio.Queue()
        self._subs.add(q)
        try:
            last = after
            for e in [e for e in self.events if e["id"] > after]:
                last = e["id"]
                yield e
            while True:
                e = await q.get()
                if e["id"] > last:
                    last = e["id"]
                    yield e
        finally:
            self._subs.discard(q)
