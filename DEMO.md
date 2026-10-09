# Reva demo runbook: DocVault

One screen recording: an editor, a terminal playing the coding agent, and the Reva UI in a browser (dark theme).
The agent is scripted (`demo/docvault_demo.py agent`) so every take is identical. Everything Reva does after
the save is the real pipeline: static gate, Semgrep, LLM screening, sandbox exploit, patch, re-test.

This page is the short live version (one ticket, about a minute). The 3-minute pitch that cuts between the slides and two
tickets is scripted in `docs/DEMO_SCRIPT.md`, and recorded end to end by `demo/record_demo.py` (see the bottom of this page).
The Git MCP server runbook is in `docs/DEMO-git-mcp-server.md`.

## Pre-flight (5 minutes)

```bash
source .venv/bin/activate
# LLM (AkashML) and, optionally, ClickHouse: export the REVA_* variables as in README.md
python -c "from reva import llm; print('llm:', llm.available())"     # must print True for the agent review

python demo/docvault_demo.py stage     # fresh stage/docvault; the latent read_diagnostic issue is already fixed
reva init stage/docvault               # expect "11 flow(s) ... 0 without a recognised guard"
reva watch stage/docvault              # http://127.0.0.1:8765
```

Browser: open `http://127.0.0.1:8765` full screen. Check that the header reads `docvault · watching`, the Issues tab says
"Watching for changes", and the Threat model tab lists 11 guarded paths (plus agent suggestions if the LLM was on at init).

Re-run `stage` + `init` before **every** take: the agent's edits only apply to a fresh copy.

## The 60 seconds

| Time | On screen | Do | Say |
| --- | --- | --- | --- |
| 0:00 | Editor: `stage/docvault/BACKLOG.md`, item 2 | — | "DocVault: a real FastAPI app. The ticket: add search to reports." |
| 0:08 | Reva, **Threat model** tab | click the tab | "Reva has mapped every path from user input to a database, file or network call. All guarded." |
| 0:16 | Terminal next to Reva (**Issues** tab) | `python demo/docvault_demo.py agent` | "A coding agent picks up the ticket." |
| 0:22 | First save: Activity shows `list_reports()` → **No issue** | — | "Most saves are clean, and Reva stays silent." |
| 0:28 | Second save: banner "Checking a possible SQL injection…" | **speed up the recording** through the LLM screening (≈40–55 s; label it "+45 s") | "This one puts the search text straight into SQL." |
| 0:35 | Card fills in: **Exploited in a sandbox**, then **Fix written**, then **Fix verified** | open "View diff" | "It doesn't guess: it leaked a planted row through `q`, wrote a two-line fix, and re-ran the same exploit to prove the fix holds." |
| 0:50 | Click **Apply fix** | — | "One click and it's in the code, before the pull request even exists." |
| 0:55 | Card moves to Resolved; Activity: **No issue** | — | "Reva: every alert proven, every fix verified." |

Measured on this machine with the LLM off: the save is flagged in 3.4 s, proven in 2.7 s, and the fix verified 2.4 s later.
With the LLM on, only the flagging step grows.

## If something goes wrong

- **Nothing happens after the agent saves:** the stage copy was not fresh (`replace_once` exits with "not in the expected
  state"). Re-run `stage` and `init`, then restart `reva watch`.
- **The two saves collapse into one row:** keep `--gap` at 6 s or more (default 6).
- **The LLM is down:** Reva still flags the change from the static gate and Semgrep, and the sandbox proof is unchanged. The
  threat model just has no agent suggestions.
- **Export:** "Export SARIF" in the header downloads the proven findings as SARIF 2.1.0
  (`reva scan stage/docvault --sarif out.sarif` does the same from the CLI).

## Recording the 3-minute video

`demo/record_demo.py` plays `docs/DEMO_SCRIPT.md` by itself: it stages DocVault, starts a real `reva watch`, and records one
1920×1080 page that cuts between slide images and the live view (the UI beside the agent's terminal), clicking through the
UI as the script says. Before each cut back to the live view it waits for Reva's actual result, so a slow model lengthens a
slide rather than faking a result.

```bash
pip install -e '.[demo]' && playwright install chromium     # ffmpeg must be on PATH, or set FFMPEG
python demo/record_demo.py --slides <dir of cover.png, problem.png, ...> --out reva-demo.mp4
```

The slide images are exports of the pitch deck at 1920×1080, named by slide id (`cover`, `problem`, `augment`, `workflow`,
`detectx`, `validate`, `close`). Captions are off unless `--captions` is passed. Export the `REVA_*` variables first if the
recording should include the LLM screening and the calibration memory.
