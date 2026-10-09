"""reva init | scan | watch | corpus."""
from __future__ import annotations

import argparse
import asyncio
import errno
import socket

PORT = 8765


def claim_port(host: str, port: int, repo: str) -> None:
    """Fail with an actionable message instead of uvicorn's bare 'address already in use'."""
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
            raise SystemExit(
                f"reva: port {port} is already in use on {host} - another `reva watch` is probably still running.\n"
                f"      Stop that process, or start this one on a free port:\n"
                f"          reva watch {repo} --port {port + 1}"
            ) from exc


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="reva", description="Real-time vulnerability review for agent-written code")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, help_ in (("init", "build the threat model"), ("scan", "full scan of every function"),
                        ("watch", f"watch the repo and serve the UI on :{PORT}")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("repo")
    corpus = sub.add_parser("corpus", help="bulk-screen many repos into the calibration memory")
    corpus.add_argument("rest", nargs=argparse.REMAINDER)
    sub.choices["scan"].add_argument("--sarif", metavar="FILE", help="also write proven findings as SARIF 2.1.0")
    sub.choices["watch"].add_argument("--port", type=int, default=PORT)
    sub.choices["watch"].add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv)
    if args.cmd == "corpus":
        from .corpus import main as corpus_main

        return corpus_main(args.rest)
    if args.cmd == "watch":
        claim_port(args.host, args.port, args.repo)

    from . import server

    server.configure(args.repo, watch=args.cmd == "watch")
    if args.cmd == "watch":
        import uvicorn
        uvicorn.run(server.app, host=args.host, port=args.port, log_level="warning")
    elif args.cmd == "init":
        asyncio.run(server.ensure_threat_model(rebuild=True))
        print(server.store.threat_model.summary)
    else:
        asyncio.run(report_scan(server, args.sarif))


async def report_scan(server, sarif_path: str | None = None) -> None:
    await server.full_scan()
    if sarif_path:
        import json

        from . import sarif

        doc = sarif.build(list(server.store.findings.values()), server.repo, server.store.threat_model)
        with open(sarif_path, "w") as fh:
            json.dump(doc, fh, indent=2)
        print(f"wrote {len(doc['runs'][0]['results'])} proven finding(s) to {sarif_path}")
    c = server.store.counters
    print(f"screened {c['screened']}  flagged {c['flagged']}  confirmed {c['confirmed']}  quiet {c['quiet']}")
    for f in server.store.findings.values():
        print(f"[{f.status}] {f.file}:{f.line} {f.function} {f.cwe} {f.title}")


if __name__ == "__main__":
    main()
