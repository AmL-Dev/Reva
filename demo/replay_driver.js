/* Generated into docs/replay.html by demo/record.py: replays a recorded run with no server, network or LLM.
   Stands in for /api/state and /api/events so the page below is the unmodified live UI. */
(() => {
const STATE = __REVA_STATE__, EVENTS = __REVA_EVENTS__;
const TOTAL = EVENTS.length ? EVENTS[EVENTS.length - 1].t : 0;
const SPEEDS = [1, 2, 4, 8, 16, 32];
const subs = {};
let at = 0, vt = 0, speed = SPEEDS.find(s => TOTAL / s <= 120) ?? 32, playing = true, last = 0;

window.fetch = async (url, opts) => opts?.method === "POST"
  ? {ok: false, status: 409, json: async () => ({detail: "recorded replay: actions are disabled"})}
  : {ok: true, status: 200, json: async () => STATE};
window.EventSource = class {
  constructor() { this.readyState = 1; setTimeout(() => this.onopen?.(), 60); }
  addEventListener(type, fn) { (subs[type] ??= []).push(fn); }
  close() {}
};

const STYLE = `<style>
#rp{display:flex;align-items:center;gap:14px;padding:7px 18px;background:var(--panel2);
  border-bottom:1px solid var(--line2);font-size:12px;letter-spacing:1px;color:var(--mut);flex-wrap:wrap}
#rp .tag2{color:var(--pur);border:1px solid var(--pur);background:var(--purbg);border-radius:4px;
  padding:3px 9px;text-transform:uppercase;font-weight:700}
#rp button{font:600 12px/1 var(--mono);padding:6px 12px;border-radius:5px;border:1px solid var(--line2);
  background:var(--panel);color:var(--fg);letter-spacing:1px}
#rp button:hover{border-color:var(--cyn);color:var(--cyn)}
#rp .bar{flex:1 1 180px;height:6px;min-width:120px;border-radius:3px;background:var(--line);overflow:hidden}
#rp .bar i{display:block;height:100%;width:0;background:var(--cyn)}
#rp-time{color:var(--fg);font-variant-numeric:tabular-nums}
#rp select{font:12px var(--mono);background:var(--panel);color:var(--fg);border:1px solid var(--line2);
  border-radius:5px;padding:5px 6px}
</style>`;
const mmss = s => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
const q = s => document.querySelector(s);

function paint() {
  q("#rp-fill").style.width = `${TOTAL ? (100 * vt / TOTAL).toFixed(2) : 100}%`;
  q("#rp-time").textContent = `${mmss(vt)} / ${mmss(TOTAL)}`;
  q("#scan").disabled = true;
  q("#scan").title = "recorded replay — run reva watch for a live full scan";
}
function frame(now) {
  if (last && playing) vt = Math.min(TOTAL, vt + (now - last) / 1000 * speed);
  last = now;
  while (at < EVENTS.length && EVENTS[at].t <= vt) {
    const ev = EVENTS[at++].ev;
    for (const fn of subs[ev.type] || []) fn({data: JSON.stringify(ev)});
  }
  paint();
  if (at < EVENTS.length) requestAnimationFrame(frame);
  else { playing = false; q("#rp-play").textContent = "▶ REPLAY ENDED"; q("#rp-play").disabled = true; }
}
function mount() {
  document.head.insertAdjacentHTML("beforeend", STYLE);
  const el = document.createElement("div");
  el.id = "rp";
  el.innerHTML = `<span class="tag2">recorded replay</span>
    <button id="rp-play">⏸ PAUSE</button>
    <div class="bar"><i id="rp-fill"></i></div><span id="rp-time">0:00 / 0:00</span>
    <label>speed <select id="rp-speed">${SPEEDS.map(s =>
      `<option value="${s}"${s === speed ? " selected" : ""}>${s}x</option>`).join("")}</select></label>
    <button id="rp-again">↺ RESTART</button>`;
  q("header").after(el);
  q("#rp-play").onclick = () => {
    playing = !playing;
    q("#rp-play").textContent = playing ? "⏸ PAUSE" : "▶ PLAY";
  };
  q("#rp-speed").onchange = e => { speed = Number(e.target.value); };
  q("#rp-again").onclick = () => location.reload();
  document.title = "Reva — recorded replay";
  requestAnimationFrame(frame);
}
document.addEventListener("DOMContentLoaded", mount);
})();
