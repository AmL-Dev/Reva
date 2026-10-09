# Reva demo runbook (3 minutes)

Two terminals and a browser. Terminal A runs Reva, terminal B plays the coding agent, the browser is on screen the whole time.
All commands are run from the bundle root — the directory holding this file.

> Before presenting, run the whole thing once, start to finish, and trust the counters your own dry run shows.
> If you cannot run it live, `python demo/record.py` captures a run into a standalone replay page, and
> `python demo/fake.py watch target` serves the UI from canned analysis.

## Pre-flight

Do these in order. Budget five minutes; the threat-model build and the first LLM call are the slow parts.

1. **Environment.**
   ```bash
   python3 -m venv .venv && source .venv/bin/activate && pip install -e . -q
   command -v git patch        # both must resolve: the sandbox and patch verification shell out
   ```
2. **LLM endpoint answers.** Set `REVA_BASE_URL`, `REVA_API_KEY`, `REVA_MODEL` (defaults:
   `http://localhost:19060/v1`, `meta-models/Muse-Glimmer-30B`), then confirm:
   ```bash
   python -c "from reva import llm; print('endpoint:', llm.available())"
   python -c "from reva import llm; print(llm.complete_json('Reply in JSON.','say ok','{\"ok\":true}'))"
   ```
   `True` plus a JSON object back means the fast path will work. If either fails, go to **Recovery / LLM endpoint down** —
   the demo still runs, and decide which fallback you are using *before* you start.
3. **Build or reset the target snapshot.** `target/` is disposable and git-ignored; rebuilding it is the reset button.
   ```bash
   python demo/make_snapshot.py            # add --clone <path-to-modelcontextprotocol/servers> to use your own clone
   ```
   This wipes `target/`, re-extracts `src/git` at commit `d9c4547`, stubs out `git_diff` and `git_checkout`, and regenerates
   `demo/steps/`. The upstream server is not shipped in this bundle: on the first run `make_snapshot.py` clones
   `https://github.com/modelcontextprotocol/servers` into `.cache/servers` (`--filter=blob:none`, a few seconds), so the
   first run needs network. Later runs reuse that clone and need none.
4. **Confirm it is clean.** Two stubs, nothing else:
   ```bash
   grep -n "NotImplementedError" target/src/mcp_server_git/server.py   # expect exactly 2 lines
   ```
   If you see more or fewer, or the file already contains `return repo.git.diff(`, the snapshot is dirty — re-run step 3.
5. **Build the threat model up front**, so `reva watch` starts instantly on stage:
   ```bash
   reva init target        # prints the one-paragraph summary; writes target/.reva/threatmodel.json
   ```
6. **Terminal A — start Reva and leave it running.**
   ```bash
   reva watch target       # serves http://127.0.0.1:8765, port 8765
   ```
7. **Browser.** Open `http://127.0.0.1:8765` and check: header says connected, counters are at zero, the centre graph already
   shows entry points → functions → sinks with red (unguarded) edges, the left pane says it is waiting for the agent, the right
   pane says silence means nothing provable. Put the window full-screen at a font size the back row can read.
8. **Terminal B — stage the first command but do not run it.** Type `python demo/replay.py --step 1` and stop.

Steps must be played **in order from a fresh snapshot**: each step writes a function body, and replaying one that is already
in place produces no change, so Reva correctly says nothing and the beat falls flat.

## The beats

### 1 — Pitch and threat model (0:00, no command)
**Say:** "Coding agents write code faster than any human can review it. Reva reviews at the same speed, and only speaks up
when it can prove it. This is Anthropic's Git MCP server, pre-fix — every input to it is chosen by a language model."
**Screen:** the centre graph. Point at a red path: a tool argument reaching a git command-line sink with no guard on it. That
graph came from data-flow analysis, not from a model's opinion.

### 2 — The agent starts writing; Reva says nothing (0:25)
```bash
python demo/replay.py --step 1
python demo/replay.py --step 2
```
**Say:** "The agent is writing `git_diff` and saving as it goes. Reva screens both saves and stays quiet — the static gate sees
no unguarded flow to a sink yet, so it never even calls the model."
**Screen:** two rows in the left pane with their diffs, marked quiet / "nothing to say". The quiet counter goes up; findings
stay empty.

### 3 — The real body lands, and Reva proves it (0:50 — the centre of the demo)
```bash
python demo/replay.py --step 3
```
**Say:** "Now the finished body passes `target` straight into git. Reva flags it, then escalates: it runs an exploit in a
sandbox that calls the tool with `target=--output=<canary outside the repo>`, and the canary gets written. That is not a
warning, that is a demonstration."
**Screen:** the `git_diff` node lights up, a card appears in the right pane and walks `suspected` → `validating` →
`confirmed` — impact 5, likelihood 4, risk 20/25 — then `patched`. Open the card's **Sandbox evidence** and **Patch diff**
panels: the patch adds a leading-`-` rejection and a `rev_parse` check, and the same exploit was re-run against the patched
copy and no longer reproduces.

### 4 — The second bug, same machinery (1:40)
```bash
python demo/replay.py --step 4
```
**Say:** "`git_checkout` has the same shape, and goes the same way — flagged, proven, patched. No new rule was written for it."
**Screen:** a second card confirming and patching; the flagged and confirmed counters tick to two.

### 5 — The control edit: nothing fires (2:00)
```bash
python demo/replay.py --step 5
```
**Say:** "This edit, `git_tag_list`, validates its input — it rejects a leading dash. Reva screens it and has nothing to say.
That silence is the product: a reviewer that cries wolf gets switched off."
**Screen:** one more quiet row in the left pane, the quiet counter ticking up, and the right pane unchanged at two findings.

### 6 — Full scan on demand (2:20)
Click **Full scan** in the header (or, from terminal B, `curl -s -X POST http://127.0.0.1:8765/api/scan`).
**Say:** "The same pipeline runs repo-wide whenever you ask. Forty-three functions, forty-one of them silent — and it finds the
second class of bug that is still in here: a tool-supplied repository path that is never checked to stay inside the directory
the server was started with."
**Screen:** the counters climbing to roughly 43 screened / 41 quiet, and the path-containment finding (`CWE-22`) confirmed with
its own sandbox evidence — a repo outside the boundary being read. This beat takes the longest; keep talking over it.

### 7 — Close (2:50)
**Say:** "Two true positives, both proven by execution, no false positives on the forty-one other functions, and a patch that
was re-tested against the exploit. Reva only speaks when it can prove it."

## Recovery

**LLM endpoint down.** Two options, in order of preference.

1. *Static-only live mode* — real analysis, real sandbox proofs, no LLM. Point Reva at a dead endpoint and run the demo
   exactly as written:
   ```bash
   REVA_BASE_URL=http://127.0.0.1:1 reva init target && REVA_BASE_URL=http://127.0.0.1:1 reva watch target
   ```
   Everything still works: the drafts stay quiet (static gate), `git_diff` and `git_checkout` are flagged on static evidence
   alone, the sandbox proof and patch verification are unchanged, and the control edit still produces nothing. Differences to
   narrate: confidence reads around 55% (static evidence only, no LLM term in the blend) instead of the higher live score, and
   the threat-model summary is the plain generated sentence rather than written prose.
2. *Offline canned mode* — `python demo/fake.py watch target`, same UI with pre-written analysis and no LLM at all:
   ```bash
   python demo/make_snapshot.py && python demo/fake.py watch target   # then, in terminal B, python demo/replay.py
   ```
   It reaches 5 screened / 2 flagged / 2 confirmed / 3 quiet with both findings `patched`. `tests/test_fake_demo.py` pins its
   stub signatures to the contracts `reva/server.py` calls, so drift fails the suite rather than the demo — but dry-run it
   anyway, and say out loud that this mode is canned.

3. *A single file, nothing installed* — record one beforehand with `python demo/record.py` (it writes `docs/replay.html`):
   the real UI replaying a recorded live run, with play/pause and a speed control, and no server, python, network or LLM.

**Port 8765 in use.**
```bash
ss -ltnp | grep 8765          # find the holder (usually a Reva left running from a dry run)
reva watch target --port 8866 # then open http://127.0.0.1:8866
```
Kill the old process rather than moving ports if you can — the audience sees the URL.

**Target snapshot dirty** (a step produced no reaction, or `grep NotImplementedError` does not show exactly two hits):
```bash
python demo/make_snapshot.py && reva init target
```
Restart `reva watch target` afterwards, because the watcher takes its function snapshot at startup. If `make_snapshot.py`
fails because its default clone path is gone, clone the upstream repo once and pass it in:
```bash
git clone --filter=blob:none https://github.com/modelcontextprotocol/servers /tmp/servers
python demo/make_snapshot.py --clone /tmp/servers
```

**A beat does not fire at all.** Check terminal A for a traceback (the watcher logs and keeps going), confirm the step actually
changed the file (`git diff` does not help here — `target/` is untracked; use the `grep` check), and if in doubt reset the
snapshot and replay from step 1. Do not re-run a step twice hoping for a reaction: identical text is not a change, and Reva is
right to be quiet.
