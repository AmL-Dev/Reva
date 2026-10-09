"""Record the 3-minute pitch video (docs/DEMO_SCRIPT.md): slides interleaved with a live Reva run on DocVault.

    python demo/record_demo.py --slides <dir of slide PNGs> --out reva-demo.mp4

Needs Playwright (`pip install playwright && playwright install chromium`). It stages a fresh DocVault copy, starts a
real `reva watch` on it, and records one 1920x1080 page that cuts between slide images and the live view (Reva's UI
beside the agent's terminal). The agent's saves are the scripted edits in demo/docvault_demo.py; everything Reva shows
is the real pipeline reacting to them. Before each cut back to the live view the recorder waits for Reva's actual
result, so a slow LLM lengthens a slide instead of faking a result. The REVA_* environment is passed through.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))
import docvault_demo as dv  # noqa: E402

PORT = 8790
UI = f"http://127.0.0.1:{PORT}"
W, H, TERM_W = 1920, 1080, 560
PREROLL = 12      # seconds held on the cover before the script's clock starts; trimmed on export
LENGTH = 180      # the script's length: export keeps the last LENGTH seconds

STUDIO = """<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
html,body{margin:0;width:%(W)spx;height:%(H)spx;overflow:hidden;background:#0B0F14;font-family:'IBM Plex Sans',sans-serif}
.layer{position:absolute;inset:0;opacity:0;transition:opacity .45s ease}
.layer{pointer-events:none}.layer.on{opacity:1;pointer-events:auto}
#slide img{width:100%%;height:100%%;display:block}
#live{display:grid;grid-template-columns:1fr %(TW)spx}
#ui{width:100%%;height:100%%;border:0;background:#0e1014}
#term{background:#090b0e;border-left:1px solid #262b33;display:flex;flex-direction:column;min-height:0}
#term .bar{display:flex;align-items:center;gap:8px;padding:14px 18px;border-bottom:1px solid #1d2229;color:#7a828e;font:500 15px 'IBM Plex Sans'}
#term .bar i{width:11px;height:11px;border-radius:50%%;background:#2a3038}
#term .bar b{margin-left:8px;color:#a7aeb9;font-weight:500}
#out{flex:1;overflow:hidden;padding:18px 20px;font:15.5px/1.6 'JetBrains Mono',monospace;color:#c9d1d9;white-space:pre-wrap}
#out .p{color:#b9a6fb;font-weight:600}#out .t{color:#e6e8eb;font-weight:600}#out .d{color:#7a828e}
#out .s{color:#3fbf86}#out .w{color:#e5a93d}
#cap{pointer-events:none;position:absolute;left:50%%;bottom:42px;transform:translateX(-50%%);max-width:1480px;padding:16px 28px;border-radius:14px;
  background:rgba(9,11,14,.9);border:1px solid #2a3038;color:#e8edf2;font:500 28px/1.4 'IBM Plex Sans';text-align:center;
  opacity:0;transition:opacity .35s}
#cap.on{opacity:1}
#tag{pointer-events:none;margin-left:auto;padding:4px 10px;border-radius:8px;background:rgba(139,108,246,.16);
  color:#c4b5fd;font:600 15px 'IBM Plex Sans';letter-spacing:.3px;opacity:0;transition:opacity .35s}
#tag.on{opacity:1}
#cursor{position:absolute;left:-40px;top:-40px;width:26px;height:26px;margin:-13px 0 0 -13px;border-radius:50%%;
  background:rgba(255,255,255,.22);border:2px solid #fff;box-shadow:0 2px 10px rgba(0,0,0,.5);
  transition:left .7s cubic-bezier(.2,.7,.2,1),top .7s cubic-bezier(.2,.7,.2,1),transform .15s;z-index:9;pointer-events:none}
#cursor.down{transform:scale(.7)}
#cursor.off{opacity:0}
#tick{position:absolute;right:0;bottom:0;width:2px;height:2px;background:#0B0F14;animation:tk .08s steps(2) infinite;z-index:10}
@keyframes tk{50%%{background:#0C1015}}
</style></head><body>
<div id="live" class="layer"><iframe id="ui" src="%(UI)s"></iframe>
  <div id="term"><div class="bar"><i></i><i></i><i></i><b>coding agent &middot; ~/docvault</b><span id="tag">LIVE &middot; real Reva pipeline</span></div><div id="out"></div></div></div>
<div id="slide" class="layer on"><img id="img"></div>
<div id="cap"></div><div id="cursor" class="off"></div><div id="tick"></div>
</body></html>"""


def state() -> dict:
    with urllib.request.urlopen(f"{UI}/api/state", timeout=5) as r:
        return json.load(r)


def wait_for(pred, timeout=240.0, what=""):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if pred(state()):
                return
        except OSError:
            pass
        time.sleep(0.4)
    raise SystemExit(f"timed out waiting for {what}")


def finding(st, function, status):
    return any(f["function"] == function and f["status"] in status for f in st["findings"])


class Director:
    def __init__(self, page, slides: Path, captions: bool = False):
        self.page, self.slides, self.t0, self.captions = page, slides, time.monotonic(), captions

    def at(self, t: float) -> None:
        """Hold until `t` seconds into the video: the schedule only ever stretches, it never skips."""
        left = t - (time.monotonic() - self.t0)
        if left > 0:
            self.page.wait_for_timeout(left * 1000)

    def caption(self, text: str = "") -> None:
        if not self.captions:
            return
        self.page.evaluate("t => { const c = document.getElementById('cap'); "
                           "c.textContent = t; c.classList.toggle('on', !!t); }", text)

    def slide(self, name: str, text: str = "") -> None:
        self.page.evaluate("""src => { document.getElementById('img').src = src;
            document.getElementById('slide').classList.add('on'); document.getElementById('tag').classList.remove('on');
            document.getElementById('cursor').classList.add('off'); }""",
                           (self.slides / f"{name}.png").as_uri())
        self.caption(text)

    def live(self, text: str = "") -> None:
        self.page.evaluate("""() => { document.getElementById('live').classList.add('on');
            document.getElementById('slide').classList.remove('on'); document.getElementById('tag').classList.add('on'); }""")
        self.caption(text)

    def term(self, text: str, cls: str = "", typed: bool = False) -> None:
        self.page.evaluate("""([t, c, typed]) => new Promise(done => {
            const out = document.getElementById('out'), s = document.createElement('span');
            if (c) s.className = c; out.appendChild(s); out.appendChild(document.createTextNode('\\n'));
            if (!typed) { s.textContent = t; return done(); }
            let i = 0; const tick = () => { s.textContent = t.slice(0, ++i); i < t.length ? setTimeout(tick, 14) : done(); }; tick(); })""",
                           [text, cls, typed])

    def click(self, locator, pause: float = 0.5) -> None:
        locator.scroll_into_view_if_needed()
        box = locator.bounding_box()
        x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
        self.page.evaluate("([x, y]) => { const c = document.getElementById('cursor'); c.classList.remove('off'); "
                           "c.style.left = x + 'px'; c.style.top = y + 'px'; }", [x, y])
        self.page.wait_for_timeout(800)
        self.page.evaluate("() => document.getElementById('cursor').classList.add('down')")
        locator.click()
        self.page.wait_for_timeout(160)
        self.page.evaluate("() => document.getElementById('cursor').classList.remove('down')")
        self.page.wait_for_timeout(pause * 1000)

    def save(self, ticket: int, step: int) -> None:
        say, path, old, new, note = dv.TICKETS[ticket][1][step]
        self.term(say, typed=True)
        dv.replace_once(path, old, new)
        self.term(f"  saved {path.relative_to(dv.STAGE)}  ({note})", "s")


def run(slides: Path, out: Path, captions: bool = False) -> None:
    subprocess.run([str(ROOT / ".venv" / "bin" / "python"), str(ROOT / "demo" / "docvault_demo.py"), "stage"], check=True)
    env = {**os.environ}
    subprocess.run([str(ROOT / ".venv" / "bin" / "reva"), "init", str(dv.STAGE)], check=True, env=env, stdout=subprocess.DEVNULL)
    server = subprocess.Popen([str(ROOT / ".venv" / "bin" / "reva"), "watch", str(dv.STAGE), "--port", str(PORT)],
                              env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        wait_for(lambda s: s.get("threat_model"), 60, "reva watch")
        work = Path(tempfile.mkdtemp(prefix="reva-rec-"))
        studio = work / "studio.html"
        studio.write_text(STUDIO % {"W": W, "H": H, "TW": TERM_W, "UI": UI})
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(work),
                                      record_video_size={"width": W, "height": H})
            ctx.add_init_script("try { localStorage.setItem('reva.modelView', 'graph') } catch (e) {}")
            page = ctx.new_page()
            page.goto(studio.as_uri(), wait_until="networkidle")
            ui = page.frame_locator("#ui")
            ui.locator("#h1").wait_for()
            d = Director(page, slides, captions)
            d.slide("cover", "Reva: security at the speed of your coding agent.")
            page.wait_for_timeout(PREROLL * 1000)   # the recorder drops its first seconds: start the clock after them
            d.t0 = time.monotonic()
            script(d, ui)
            page.wait_for_timeout(800)
            video = page.video
            ctx.close()
            browser.close()
            raw = Path(video.path())
            export(raw, out)
    finally:
        server.terminate()
        server.wait(10)


def export(raw: Path, out: Path) -> None:
    """Keep the last LENGTH seconds (the pre-roll and the recorder's dropped start fall away); mp4 if asked."""
    ffmpeg = os.environ.get("FFMPEG", "ffmpeg")
    probe = subprocess.run([ffmpeg, "-hide_banner", "-i", str(raw)], capture_output=True, text=True).stderr
    h, m, sec = (probe.split("Duration: ")[1].split(",")[0]).split(":")
    head = max(0.0, int(h) * 3600 + int(m) * 60 + float(sec) - LENGTH)
    codec = ["-c:v", "libx264", "-preset", "slow", "-crf", "20", "-pix_fmt", "yuv420p", "-movflags", "+faststart"] \
        if out.suffix == ".mp4" else ["-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "30"]
    subprocess.run([ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-ss", f"{head:.2f}", "-i", str(raw),
                    *codec, "-an", str(out)], check=True)
    print(f"wrote {out} (trimmed {head:.1f}s of pre-roll)")


def script(d: Director, ui) -> None:
    # Act 1: why (slides); the cover is already up from the pre-roll
    d.at(8)
    d.slide("problem", "A defect found after release costs ~25× what it costs at review. Agents now write features in minutes.")
    d.at(28)
    d.slide("augment", "Built on Semgrep. Reva adds triage grounded in a threat model, "
                       "and proves every finding before it ships a fix.")
    d.at(43)
    d.slide("workflow", "Agent saves → detect → prove in a sandbox → patch → re-run the exploit. Silent unless proven.")
    d.at(60)

    # Act 2: watch it work (live <-> slides)
    d.live("DocVault, a real FastAPI app. Reva mapped every path from user input to a database, file or network call.")
    d.click(ui.locator('nav button[data-tab="model"]'), 0.3)
    d.click(ui.locator('[data-view="graph"]'), 0.3)
    d.at(70)
    d.click(ui.locator('nav button[data-tab="issues"]'), 0.2)
    d.caption("A coding agent picks up two backlog tickets. Nobody is watching it.")
    task, _ = dv.TICKETS[2]
    d.term("> " + task, "t", typed=True)
    d.term("  reading docvault/routers/reports.py", "d")
    d.at(75)
    d.save(2, 0)
    wait_for(lambda s: s["counters"]["quiet"] >= 1, 60, "first save to be screened")
    d.caption("Most saves are clean, and Reva stays silent. No alert fatigue.")
    d.at(82)
    d.save(2, 1)
    wait_for(lambda s: finding(s, "list_reports", ("validating", "confirmed", "patched")), 120, "the SQL injection to be flagged")
    d.caption("This save pastes the search text straight into SQL. Reva noticed.")
    d.at(88)
    d.slide("detectx", "How it decided: an open path q → SQL, sibling code that binds its values, and four screening questions.")
    d.at(108)
    wait_for(lambda s: finding(s, "list_reports", ("patched",)), 240, "the SQL injection fix to be verified")
    d.live("Exploited in a sandbox: a planted canary row leaked through q. Two-line fix. Same exploit re-run: blocked.")
    d.click(ui.locator("button.link", has_text="View diff").first, 0.2)
    d.term("  done.", "d")
    d.at(120)
    task, _ = dv.TICKETS[4]
    d.term("")
    d.term("> " + task, "t", typed=True)
    d.save(4, 0)
    d.caption("Next ticket: logo import from a short link. To follow redirects, the agent dropped the URL allowlist.")
    wait_for(lambda s: finding(s, "import_logo", ("validating", "confirmed", "patched")), 120, "the SSRF to be flagged")
    d.at(126)
    d.slide("validate", "A finding only counts if a canary fires: a leaked row, a created file, or a hit on our canary server.")
    d.at(142)
    wait_for(lambda s: finding(s, "import_logo", ("patched",)), 240, "the SSRF fix to be verified")
    d.live("The server called our canary. Fixed with the project's own URL validator, and verified.")
    d.page.wait_for_timeout(2500)
    d.caption("One click each: the verified fixes go into the code before a pull request exists.")
    for _ in range(2):
        d.click(ui.locator('[data-act="apply"]').first, 1.2)
    d.at(152)
    d.click(ui.locator('nav button[data-tab="model"]'), 0.2)
    d.caption("The threat model follows the code: both paths are fixed. Findings export as SARIF for GitHub code scanning.")
    d.at(160)

    # Act 3: land it (slide)
    d.slide("close", "Agents won't slow down. Review has to happen where the code is written.")
    d.at(179)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slides", type=Path, required=True, help="directory of <slide id>.png at 1920x1080")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "reva-demo.mp4",
                    help=".mp4 or .webm (needs ffmpeg; set FFMPEG to point at one)")
    ap.add_argument("--captions", action="store_true", help="burn the script's lines in as captions")
    a = ap.parse_args()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    run(a.slides.resolve(), a.out.resolve(), a.captions)
