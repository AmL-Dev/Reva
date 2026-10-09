"""Record a live `reva watch` run and write docs/replay.html: the real event stream, replayable with no server.

Start `reva watch target --port <port>`, open nothing, then run this; it plays demo/replay.py and captures every
server-sent event with its arrival time into a standalone copy of ui/index.html.
"""
import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


def listen(base: str, after: int, out: list) -> None:
    req = urllib.request.Request(f"{base}/api/events?after={after}", headers={"Accept": "text/event-stream"})
    t0 = time.monotonic()
    with urllib.request.urlopen(req) as r:
        for raw in r:
            line = raw.decode("utf-8", "replace")
            if line.startswith("data: "):
                out.append({"t": round(time.monotonic() - t0, 3), "ev": json.loads(line[6:])})


def build(state: dict, events: list) -> str:
    lead = events[0]["t"] - 0.4 if events else 0
    events = [{"t": round(e["t"] - lead, 3), "ev": e["ev"]} for e in events]
    driver = (ROOT / "demo" / "replay_driver.js").read_text()
    driver = driver.replace("__REVA_STATE__", json.dumps(state)).replace("__REVA_EVENTS__", json.dumps(events))
    return (ROOT / "ui" / "index.html").read_text().replace("</head>", f"<script>\n{driver}\n</script>\n</head>", 1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--delay", type=float, default=8.0, help="seconds between the agent's saves")
    ap.add_argument("--settle", type=float, default=180.0, help="stop once no event has arrived for this long")
    ap.add_argument("--max-wait", type=float, default=1800.0, help="give up waiting for the pipeline after this long")
    ap.add_argument("--out", default=str(ROOT / "docs" / "replay.html"))
    args = ap.parse_args()
    base = f"http://127.0.0.1:{args.port}"
    state, events = get(f"{base}/api/state"), []
    threading.Thread(target=listen, args=(base, state["last_id"], events), daemon=True).start()
    time.sleep(1)
    subprocess.run([sys.executable, str(ROOT / "demo" / "replay.py"), "--delay", str(args.delay)], check=True)
    end, seen, quiet = time.monotonic() + args.max_wait, len(events), time.monotonic()
    while time.monotonic() < end and time.monotonic() - quiet < args.settle:
        time.sleep(2)
        if len(events) != seen:
            seen, quiet = len(events), time.monotonic()
    html = build(state, list(events))
    Path(args.out).write_text(html)
    print(f"{len(events)} events, {len(html) // 1024} KiB -> {args.out}")


if __name__ == "__main__":
    main()
