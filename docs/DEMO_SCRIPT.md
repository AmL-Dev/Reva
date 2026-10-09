# Reva — 3-minute demo script (slides ⇄ live)

**Story:** it's Friday afternoon. A coding agent is clearing the DocVault backlog, one ticket after another, with nobody
watching. Reva catches two real vulnerabilities as they're written, one SQL injection and one SSRF. It proves each one,
fixes it, re-tests the fix, and stays silent about everything else.

**Rhythm:** each LLM screening takes roughly 40–55 s of real wall time. We never wait on screen. Every time Reva starts
working, we cut to the slide that explains the step it's running, and cut back once the result has landed. Nothing in the
recording needs speeding up.

**Screens:** the deck (full screen), and the live setup: Reva UI (dark, about 2/3 of the screen) beside a terminal where the
agent runs (about 1/3). Each cut is one keystroke (window switch).

**Target length:** 3:00, about 420 spoken words.

---

## Act 1 — Why (slides, 0:00–1:00)

| Time | Screen | Action | Say |
|---|---|---|---|
| 0:00 | **SLIDE cover** | — | "This is Reva: security at the speed of your coding agent. Real-time vulnerability analysis and patching for AI-written code, built on Semgrep." |
| 0:08 | **SLIDE problem** | — | "A defect found after release costs about twenty-five times what it costs at review. That's a survey of sixty-eight studies. What changed is the left side: an agent writes a feature in minutes, and review still takes days. More and more bugs are now born on the expensive end of this chart." |
| 0:28 | **SLIDE augment** | — | "We build on Semgrep. Guardian gives broad coverage on every save. Reva adds two things: triage grounded in a threat model of *your* project, and an escalation pipeline that proves a finding is real, then ships a fix that's been tested." |
| 0:43 | **SLIDE workflow** | — | "The loop: the agent saves, Reva checks the save against the threat model. If something looks wrong, Reva exploits it in a sandbox, writes a patch, and re-runs the exploit against the patch. If it can't prove it, you never hear about it. Let me show you." |

## Act 2 — Watch it work (live ⇄ slides, 1:00–2:40)

| Time | Screen | Action | Say |
|---|---|---|---|
| 1:00 | **LIVE** · Reva, **Threat model → Graph** | — | "This is DocVault, a real FastAPI app. Reva mapped every path from user input to a database, a file or the network: eleven of them, all guarded. Built once, versioned with the repo." |
| 1:10 | **LIVE** · terminal | run `python demo/docvault_demo.py agent` (tickets 2 and 4 queued) | "Now we give the agent two tickets from the backlog and walk away." |
| 1:15 | **LIVE** · Reva Activity rail | first save → **No issue** | "Most saves are clean, and Reva stays silent. No alert fatigue." |
| 1:22 | **LIVE** · banner *"Checking a possible SQL injection in list_reports()"* | second save lands | "This one adds search, and pastes the search text straight into SQL. Reva noticed. While it works, here's how it decided." |
| 1:28 | **SLIDE detectx** | — | "The new function, the path from `q` to the database, Semgrep's results, and project-specific questions all go into one pass through our model on AkashML. It answers each question with a probability. Static evidence is already 0.75 here: an open path, and every sibling function binds its values. The model has to agree at 0.34 or more for the change to go to the sandbox." |
| 1:48 | **LIVE** · Issues: card filled in | open **View diff** | "Exploited: a planted canary row came back that the query should never return. Then a two-line fix, binding the search term as a parameter, and the same exploit re-run against it: blocked." |
| 2:00 | **LIVE** · terminal + banner *"Checking a possible server-side request forgery in import_logo()"* | (agent is on ticket 4) | "Meanwhile the agent moved on: importing logos from a short link. To follow redirects, it dropped the URL allowlist." |
| 2:06 | **SLIDE validate** | — | "That's the step that makes Reva different. A finding only counts if a canary fires: a leaked row, a file that appears, or, here, a request that hits our canary server. If it doesn't fire, the finding is dropped. And a fix only ships after the same exploit fails against it." |
| 2:22 | **LIVE** · second card: *SSRF in import_logo()*, server hit → fix → verified | click **Apply fix** on both cards | "There it is: the server called our canary. Fixed, verified. One click each, and the fixes are in the code before a pull request even exists." |
| 2:32 | **LIVE** · Threat model graph: red edges turn green, boxes say **fixed** | click **Export SARIF** | "The threat model updates as the code changes. Everything exports as SARIF, straight into GitHub code scanning." |

## Act 3 — Land it (slides, 2:40–3:00)

| Time | Screen | Action | Say |
|---|---|---|---|
| 2:40 | **SLIDE close** | — | "Across twenty-five repositories, thirty-four thousand functions, less than a fifth of one percent ever reached a model. And every alert we raised came with an exploit that ran. Agents won't slow down, so review has to happen where the code is written." |
| 2:58 | **SLIDE close** | stop talking | — |

**Cut from the 3-minute run:** `threat`, `detect` and `example`. They overlap with the live demo. Keep `example` as the
fallback if the live setup fails: it shows the same SQL injection beat from a recorded run.

---

## Before recording

- Both beats run on the real pipeline: SQL injection (ticket 2, `list_reports`) and SSRF (ticket 4, `import_logo`) are each
  flagged, proven, fixed and verified, and unmodified DocVault rejects both probes (`tests/test_search_beat.py`).
- `demo/docvault_demo.py agent --tickets 2,4` plays both tickets; `demo/record_demo.py` records the whole script.
- Export the `REVA_*` variables (LLM, ClickHouse) before recording, so slide 7's claims match what runs. Without them the
  static gate and the sandbox still produce every result on screen, and the model's p₁–p₄ stay unmeasured.
- Deck order for this run: cover → problem → augment → workflow → *(live)* → detectx → *(live)* → validate → *(live)* → close.

**Facts to keep straight:** no 0-day was found; both bugs are written into our own demo app by the scripted agent. The agent
is scripted so every take is identical. Everything Reva does after each save is the real pipeline.
