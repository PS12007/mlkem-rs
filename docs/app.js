// mlkem-rs site: live WebAssembly demo + charts drawn from data.json
// (generated from results/ by scripts/site_data.py). No libraries.

document.documentElement.classList.add("js");
const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const C = { ink: css("--ink"), ink2: css("--ink-2"), ink3: css("--ink-3"), rule: css("--rule"),
  leak: css("--leak"), note: css("--note"), paper: css("--paper"), paper2: css("--paper-2") };

// ------------------------------------------------------------------ reveal
const io = new IntersectionObserver((es) => es.forEach((e) => {
  if (e.isIntersecting) { e.target.classList.add("seen"); e.target.dispatchEvent(new Event("seen")); io.unobserve(e.target); }
}), { threshold: 0.12 });
document.querySelectorAll(".sec").forEach((s) => io.observe(s));

// ------------------------------------------------------------------ tooltip
const tip = $("tip");
function showTip(html, ev) {
  tip.innerHTML = html; tip.style.opacity = 1;
  const x = Math.min(ev.clientX + 14, innerWidth - tip.offsetWidth - 10);
  const y = ev.clientY + 16 + tip.offsetHeight > innerHeight ? ev.clientY - tip.offsetHeight - 12 : ev.clientY + 16;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const hideTip = () => { tip.style.opacity = 0; };

// ------------------------------------------------------------------ wasm
let K = null; // { x, mem, alloc, view }
let nodeDecaps = null; // µs, from results/wasm/bench-cpu2.txt via data.json
async function loadWasm() {
  const resp = await fetch("mlkem_wasm.wasm");
  const bytes = await resp.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes);
  const x = instance.exports, mem = x.memory;
  const base = x.__heap_base.value;
  let top = base;
  const alloc = (n) => {
    const p = top; top += (n + 15) & ~15;
    const need = top - mem.buffer.byteLength;
    if (need > 0) mem.grow(Math.ceil(need / 65536));
    return p;
  };
  const view = (p, n) => new Uint8Array(mem.buffer, p, n);
  const L = { ek: x.mlkem_768_ek_len(), dk: x.mlkem_768_dk_len(), ct: x.mlkem_768_ct_len() };
  // fixed buffers for the whole session
  const B = { d: alloc(32), z: alloc(32), m: alloc(32), ek: alloc(L.ek), dk: alloc(L.dk),
    ct: alloc(L.ct), ct2: alloc(L.ct), kb: alloc(32), ka: alloc(32),
    // separate buffers for FIG. 1, so "new key" never touches the demo's keys
    sd: alloc(32), sz: alloc(32), sek: alloc(L.ek), sdk: alloc(L.dk) };
  return { x, mem, alloc, view, L, B };
}
const rand = (p, n) => crypto.getRandomValues(K.view(p, n));
const copy = (p, n) => K.view(p, n).slice();
const hex = (u8, max = 64) => {
  let s = "";
  for (let i = 0; i < Math.min(u8.length, max); i++) s += u8[i].toString(16).padStart(2, "0");
  return u8.length > max ? s + ` <span class="dim">… +${u8.length - max} B</span>` : s;
};

// ------------------------------------------------------------------ FIG 1: lattice
const cvs = $("lattice"), ctx = cvs.getContext("2d");
const dpr = Math.min(2, window.devicePixelRatio || 1);
const W = 960, H = 400;
cvs.width = W * dpr; cvs.height = H * dpr; ctx.scale(dpr, dpr);
const PITCH = 19, CELL = 16, BLOCK = 16 * PITCH, GAP = (W - 3 * BLOCK) / 2;
const RHO_Y = 16 * PITCH + 62, RHO_PITCH = W / 32;
let coeffs = null, rho = null, genAt = 0, animStart = 0;

function decodeEk(ek) {
  const c = new Uint16Array(768);
  for (let i = 0, j = 0; i < 768; i += 2, j += 3) {
    c[i] = ek[j] | ((ek[j + 1] & 0x0f) << 8);
    c[i + 1] = (ek[j + 1] >> 4) | (ek[j + 2] << 4);
  }
  return c;
}
function cellXY(i) {
  const poly = Math.floor(i / 256), k = i % 256;
  return [poly * (BLOCK + GAP) + (k % 16) * PITCH, Math.floor(k / 16) * PITCH];
}
function drawLattice(now) {
  const t = reduceMotion ? 1e9 : now - animStart;
  ctx.clearRect(0, 0, W, H);
  ctx.font = "15px 'Martian Mono', monospace";
  ctx.fillStyle = C.ink3;
  for (let p = 0; p < 3; p++) ctx.fillText(`t̂[${p}]  256 × mod 3329`, p * (BLOCK + GAP), 16 * PITCH + 22);
  ctx.fillText("ρ  32 bytes: seed of the public matrix Â", 0, RHO_Y - 10);
  let pending = false;
  for (let i = 0; i < 768; i++) {
    const [x, y] = cellXY(i);
    // diagonal sweep: cells appear by (row + column) across all three blocks
    const delay = ((i % 256) % 16 + Math.floor((i % 256) / 16)) * 18 + Math.floor(i / 256) * 90;
    const a = Math.max(0, Math.min(1, (t - delay) / 260));
    if (a < 1) pending = true;
    ctx.fillStyle = C.paper2;
    ctx.fillRect(x, y, CELL, CELL);
    if (a > 0) {
      ctx.globalAlpha = a * (0.06 + 0.94 * (coeffs[i] / 3328));
      ctx.fillStyle = C.ink;
      ctx.fillRect(x, y, CELL, CELL);
      ctx.globalAlpha = 1;
    }
  }
  for (let i = 0; i < 32; i++) {
    const a = Math.max(0, Math.min(1, (t - 700 - i * 14) / 240));
    if (a < 1) pending = true;
    const x = i * RHO_PITCH;
    ctx.fillStyle = C.paper2; ctx.fillRect(x + 1, RHO_Y, RHO_PITCH - 3, 18);
    ctx.globalAlpha = a * (0.12 + 0.88 * rho[i] / 255);
    ctx.fillStyle = C.leak; ctx.fillRect(x + 1, RHO_Y, RHO_PITCH - 3, 18);
    ctx.globalAlpha = 1;
  }
  if (hoverIdx != null && hoverIdx < 768) {
    const [x, y] = cellXY(hoverIdx);
    ctx.strokeStyle = C.leak; ctx.lineWidth = 2; ctx.strokeRect(x - 1, y - 1, CELL + 2, CELL + 2);
  }
  if (pending) requestAnimationFrame(drawLattice);
}
let hoverIdx = null;
cvs.addEventListener("mousemove", (e) => {
  if (!coeffs) return;
  const r = cvs.getBoundingClientRect();
  const mx = (e.clientX - r.left) * (W / r.width), my = (e.clientY - r.top) * (H / r.height);
  let idx = null, text = "hover a cell →";
  if (my >= RHO_Y && my <= RHO_Y + 18) {
    const i = Math.floor(mx / RHO_PITCH);
    if (i >= 0 && i < 32) text = `ρ[${i}] = 0x${rho[i].toString(16).padStart(2, "0")}`;
  } else {
    const poly = Math.floor(mx / (BLOCK + GAP)), lx = mx - poly * (BLOCK + GAP);
    const col = Math.floor(lx / PITCH), row = Math.floor(my / PITCH);
    if (poly >= 0 && poly < 3 && col < 16 && row < 16 && lx < BLOCK) {
      idx = poly * 256 + row * 16 + col;
      text = `t̂[${poly}][${row * 16 + col}] = ${coeffs[idx]}  (mod 3329)`;
    }
  }
  $("hover-readout").textContent = text;
  if (idx !== hoverIdx) { hoverIdx = idx; drawLattice(1e9); }
});
cvs.addEventListener("mouseleave", () => { hoverIdx = null; $("hover-readout").textContent = "hover a cell →"; drawLattice(1e9); });

function newSpecimen() {
  const { x, B, L } = K;
  rand(B.sd, 32); rand(B.sz, 32);
  x.mlkem_768_keygen(B.sd, B.sz, B.sek, B.sdk);
  const ek = copy(B.sek, L.ek);
  coeffs = decodeEk(ek); rho = ek.slice(1152, 1184);
  genAt = performance.now(); animStart = performance.now();
  requestAnimationFrame(drawLattice);
}
setInterval(() => {
  if (!genAt) return;
  const s = Math.round((performance.now() - genAt) / 1000);
  $("gen-age").textContent = s < 2 ? "just now" : `${s} seconds ago`;
}, 1000);

// ------------------------------------------------------------------ §1 handshake
const st = { ek: null, ct: null };
const ms = (a, b) => `${(b - a).toFixed(2)} ms`;
const times = {};
function setKeyState(cls) {
  for (const id of ["h-ka", "h-kb"]) {
    const f = $(id).parentElement;
    f.classList.remove("match", "mismatch");
    // on a mismatch only Alice's key is "wrong": Bob's is what she should have got
    if (cls === "match" || (cls === "mismatch" && id === "h-ka")) f.classList.add(cls);
  }
}
function timingNote() {
  const parts = Object.entries(times).map(([k, v]) => `${k} ${v}`);
  $("timing-note").textContent = parts.length
    ? `In your browser: ${parts.join(" · ")}. (Browsers round their clocks on purpose, so treat these as rough. §6 has careful numbers.)`
    : "";
}
$("b-keygen").onclick = () => {
  const { x, B, L } = K;
  rand(B.d, 32); rand(B.z, 32);
  const t0 = performance.now();
  x.mlkem_768_keygen(B.d, B.z, B.ek, B.dk);
  times.KeyGen = ms(t0, performance.now());
  st.ek = copy(B.ek, L.ek);
  $("h-ek").innerHTML = hex(st.ek);
  $("h-dk").innerHTML = hex(copy(B.dk, L.dk), 24);
  for (const id of ["h-ct", "h-ka", "h-kb"]) $(id).textContent = "—";
  setKeyState(null); $("verdict").innerHTML = "";
  $("p-ek").classList.remove("on"); void $("p-ek").offsetWidth; $("p-ek").classList.add("on");
  $("p-ct").classList.remove("on", "evil");
  $("b-keygen").classList.add("done"); $("b-encaps").disabled = false; $("b-decaps").disabled = true;
  delete times.Encaps; delete times.Decaps; timingNote();
  // the specimen follows the demo's key
  coeffs = decodeEk(st.ek); rho = st.ek.slice(1152, 1184); genAt = performance.now(); animStart = performance.now();
  requestAnimationFrame(drawLattice);
};
$("b-encaps").onclick = () => {
  const { x, B, L } = K;
  rand(B.m, 32);
  const t0 = performance.now();
  const r = x.mlkem_768_encaps(B.ek, B.m, B.ct, B.kb);
  times.Encaps = ms(t0, performance.now());
  if (r !== 0) { $("verdict").textContent = "Bob rejected the key (should never happen)."; return; }
  st.ct = copy(B.ct, L.ct);
  $("h-ct").innerHTML = hex(st.ct);
  $("h-kb").innerHTML = hex(copy(B.kb, 32), 32);
  $("h-ka").textContent = "—"; setKeyState(null); $("verdict").innerHTML = "";
  const p = $("p-ct"); p.classList.remove("on", "evil"); void p.offsetWidth; p.classList.add("on");
  $("b-encaps").classList.add("done"); $("b-decaps").disabled = false;
  delete times.Decaps; timingNote();
};
$("b-decaps").onclick = () => {
  const { x, B, L } = K;
  const c = st.ct.slice();
  let flipped = -1;
  if ($("tamper").checked) {
    flipped = Math.floor(Math.random() * 40); // within the visible bytes, so you can see it
    c[flipped] ^= 1 << Math.floor(Math.random() * 8);
    $("p-ct").classList.add("evil");
    // show the flipped byte
    let s = "";
    for (let i = 0; i < 64; i++) {
      const h = c[i].toString(16).padStart(2, "0");
      s += i === flipped ? `<span class="flip">${h}</span>` : h;
    }
    $("h-ct").innerHTML = s + ` <span class="dim">… +${c.length - 64} B</span>`;
  } else {
    $("p-ct").classList.remove("evil");
    $("h-ct").innerHTML = hex(st.ct);
  }
  K.view(B.ct2, L.ct).set(c);
  const t0 = performance.now();
  x.mlkem_768_decaps(B.dk, B.ct2, B.ka);
  times.Decaps = ms(t0, performance.now());
  const ka = copy(B.ka, 32), kb = copy(B.kb, 32);
  $("h-ka").innerHTML = hex(ka, 32);
  const same = ka.every((v, i) => v === kb[i]);
  setKeyState(same ? "match" : "mismatch");
  $("verdict").innerHTML = same
    ? `Same 32 bytes on both sides. <small>Eve saw ek and c, and still cannot compute this secret: doing so means solving a noisy lattice problem that is believed hard even for quantum computers.</small>`
    : `<span class="bad">One flipped bit, and Alice's key is unrelated to Bob's.</span> <small>That is <em>implicit rejection</em>: Alice re-encrypts, notices the ciphertext was altered, and silently returns a pseudorandom key derived from her secret z instead of an error, so Eve learns nothing from the reaction. And she does it in exactly the same time either way: the timing tests in §3 check that.</small>`;
  timingNote();
};
$("tamper").onchange = () => { if (!$("b-decaps").disabled) $("b-decaps").click(); };

// ------------------------------------------------------------------ data + charts
function el(name, attrs = {}, parent) {
  const e = document.createElementNS(SVGNS, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
}
const fmtT = (t) => (t >= 100 ? Math.round(t).toLocaleString("en-US") : t.toFixed(t < 10 ? 2 : 1));
const BUILD_LABEL = { normal: "normal build", kyberslash: "LEAKY: KyberSlash", "early-exit": "LEAKY: early-exit compare" };
function category(r) {
  if (r.target.startsWith("aa-")) return "ctrl";
  if (r.target === "keygen-d") return "pub";
  return r.build === "normal" ? "ok" : "leak";
}

function drawRuler(runs, host) {
  const Wd = 1000, rows = [["native", "P"], ["native", "E"], ["wasm", "P"], ["wasm", "E"]];
  const top = 34, rowH = 46, left = 150, right = 20, Ht = top + rows.length * rowH + 40;
  const lo = Math.log10(0.5), hi = Math.log10(50000);
  const X = (t) => left + ((Math.log10(Math.max(t, 0.5)) - lo) / (hi - lo)) * (Wd - left - right);
  const svg = el("svg", { viewBox: `0 0 ${Wd} ${Ht}` }, host);
  const yEnd = top + rows.length * rowH;
  // zones
  el("rect", { x: X(10), y: top - 8, width: X(50000) - X(10), height: yEnd - top + 8, fill: C.leak, opacity: 0.07 }, svg);
  el("rect", { x: X(4.5), y: top - 8, width: X(10) - X(4.5), height: yEnd - top + 8, fill: C.leak, opacity: 0.03 }, svg);
  const lbl = (x, text, anchor, color) => { const t = el("text", { x, y: top - 16, "font-size": 10, "text-anchor": anchor, fill: color }, svg); t.textContent = text; };
  lbl(X(0.5) + 2, "NOTHING DETECTED", "start", C.ink3);
  lbl(X(10) + 6, "LEAK →", "start", C.leak);
  for (const [v, txt] of [[4.5, "4.5"], [10, "10"]]) {
    el("line", { x1: X(v), x2: X(v), y1: top - 8, y2: yEnd, stroke: C.leak, "stroke-dasharray": "3 3", "stroke-width": 1 }, svg);
    const t = el("text", { x: X(v), y: yEnd + 30, "font-size": 10, "text-anchor": "middle", fill: C.leak }, svg); t.textContent = txt;
  }
  for (const v of [1, 100, 1000, 10000]) {
    el("line", { x1: X(v), x2: X(v), y1: yEnd, y2: yEnd + 6, stroke: C.ink }, svg);
    const t = el("text", { x: X(v), y: yEnd + 20, "font-size": 10, "text-anchor": "middle" }, svg);
    t.textContent = v.toLocaleString("en-US");
  }
  el("line", { x1: left, x2: Wd - right, y1: yEnd, y2: yEnd, stroke: C.ink }, svg);
  const axis = el("text", { x: Wd - right, y: yEnd + 34, "font-size": 10, "text-anchor": "end", fill: C.ink3 }, svg);
  axis.textContent = "max |t|  (log scale)";
  rows.forEach(([plat, core], ri) => {
    const y = top + ri * rowH + rowH / 2;
    el("line", { x1: left, x2: Wd - right, y1: y, y2: y, stroke: C.rule, "stroke-width": 1 }, svg);
    const t = el("text", { x: 0, y: y + 4, "font-size": 11, fill: C.ink }, svg);
    t.textContent = `${plat === "native" ? "native x86-64" : "WASM in V8"}`;
    const t2 = el("text", { x: 0, y: y + 18, "font-size": 9.5, fill: C.ink3 }, svg);
    t2.textContent = core === "P" ? "performance core" : "efficiency core";
    const rs = runs.filter((r) => r.platform === plat && r.core === core);
    rs.forEach((r, i) => {
      const cat = category(r);
      const jitter = ((i * 7) % 5 - 2) * 4.2;
      const g = el("g", { class: "mark", style: `transform: translate(${X(0.5)}px, ${y + jitter}px); transition: transform 0.9s cubic-bezier(.2,.7,.2,1) ${i * 40}ms`, "data-x": X(r.maxT), "data-y": y + jitter }, svg);
      const color = cat === "leak" ? C.leak : cat === "pub" ? C.note : C.ink;
      el("circle", { r: cat === "leak" || cat === "pub" ? 6 : 5, fill: cat === "ctrl" ? C.paper : color, stroke: color, "stroke-width": 1.6, opacity: 0.92 }, g);
      el("circle", { r: 12, fill: "transparent" }, g);
      g.addEventListener("mousemove", (e) => {
        showTip(`<b>${r.target}</b> · ${BUILD_LABEL[r.build]}<br>${plat === "native" ? "native" : "WASM/V8"}, cpu ${r.cpu} (${core}-core)<br>max |t| = <b>${fmtT(r.maxT)}</b><br><span style="opacity:.6">${r.source} @ ${r.commit}</span>`, e);
        $("ruler-readout").textContent = `${r.target} · ${BUILD_LABEL[r.build]} · ${core}-core · |t| = ${fmtT(r.maxT)}`;
      });
      g.addEventListener("mouseleave", hideTip);
    });
  });
  const place = () => svg.querySelectorAll(".mark").forEach((g) => { g.style.transform = `translate(${g.dataset.x}px, ${g.dataset.y}px)`; });
  if (reduceMotion) place(); else host.closest(".sec").addEventListener("seen", () => requestAnimationFrame(place), { once: true });
  if (host.closest(".sec").classList.contains("seen")) place();
}

function drawGrowth(runs, host) {
  const pick = [
    ["native", "kyberslash", "u-encode-zero", 20, C.leak, "KyberSlash, E-core"],
    ["native", "early-exit", "decaps-ct", 2, C.leak, "early-exit compare, P-core"],
    ["native", "normal", "keygen-d", 2, C.note, "KeyGen (public ρ)"],
    ["native", "normal", "decaps-ct", 2, C.ink, "Decaps, this crate"],
    ["native", "normal", "aa-decaps-ct", 2, C.ink3, "A/A control"],
  ];
  const Wd = 1000, Ht = 380, left = 64, right = 210, top = 20, bottom = 46;
  const xl = Math.log10(5e4), xh = Math.log10(1.2e7), yl = Math.log10(0.5), yh = Math.log10(60000);
  const X = (n) => left + ((Math.log10(n) - xl) / (xh - xl)) * (Wd - left - right);
  const Y = (t) => top + (1 - (Math.log10(Math.max(t, 0.5)) - yl) / (yh - yl)) * (Ht - top - bottom);
  const svg = el("svg", { viewBox: `0 0 ${Wd} ${Ht}` }, host);
  el("rect", { x: left, y: Y(60000), width: Wd - left - right, height: Y(10) - Y(60000), fill: C.leak, opacity: 0.06 }, svg);
  for (const v of [1, 4.5, 10, 100, 1000, 10000]) {
    const isT = v === 4.5 || v === 10;
    el("line", { x1: left, x2: Wd - right, y1: Y(v), y2: Y(v), stroke: isT ? C.leak : C.rule, "stroke-dasharray": isT ? "3 3" : "", "stroke-width": 1 }, svg);
    const t = el("text", { x: left - 8, y: Y(v) + 3, "font-size": 10, "text-anchor": "end", fill: isT ? C.leak : C.ink2 }, svg);
    t.textContent = v.toLocaleString("en-US");
  }
  for (const v of [1e5, 1e6, 1e7]) {
    el("line", { x1: X(v), x2: X(v), y1: Ht - bottom, y2: Ht - bottom + 6, stroke: C.ink }, svg);
    const t = el("text", { x: X(v), y: Ht - bottom + 20, "font-size": 10, "text-anchor": "middle" }, svg);
    t.textContent = v === 1e5 ? "100 k" : v === 1e6 ? "1 M" : "10 M";
  }
  el("line", { x1: left, x2: Wd - right, y1: Ht - bottom, y2: Ht - bottom, stroke: C.ink }, svg);
  const xa = el("text", { x: Wd - right, y: Ht - 8, "font-size": 10, "text-anchor": "end", fill: C.ink3 }, svg); xa.textContent = "measurements (log)";
  const ya = el("text", { x: left, y: top - 6, "font-size": 10, fill: C.ink3 }, svg); ya.textContent = "max |t| (log)";
  // √n guide through the early-exit curve's first point
  const ee = runs.find((r) => r.platform === "native" && r.build === "early-exit" && r.target === "decaps-ct" && r.cpu === 2);
  if (ee && ee.progress.length) {
    const [n0, t0] = ee.progress[0];
    const a = t0 / Math.sqrt(n0);
    el("line", { x1: X(5e4), y1: Y(a * Math.sqrt(5e4)), x2: X(1.2e7), y2: Y(a * Math.sqrt(1.2e7)), stroke: C.ink3, "stroke-dasharray": "1 4", "stroke-width": 1.2 }, svg);
    const g = el("text", { x: X(1.2e7) - 4, y: Y(a * Math.sqrt(1.2e7)) - 6, "font-size": 9.5, "text-anchor": "end", fill: C.ink3 }, svg); g.textContent = "∝ √n";
  }
  const labels = [];
  for (const [plat, build, target, cpu, color, name] of pick) {
    const r = runs.find((q) => q.platform === plat && q.build === build && q.target === target && q.cpu === cpu);
    if (!r || !r.progress.length) continue;
    const d = r.progress.map(([n, t], i) => `${i ? "L" : "M"}${X(n).toFixed(1)},${Y(t).toFixed(1)}`).join(" ");
    const path = el("path", { d, fill: "none", stroke: color, "stroke-width": color === C.ink3 ? 1.6 : 2.4, "stroke-linejoin": "round" }, svg);
    r.progress.forEach(([n, t]) => el("circle", { cx: X(n), cy: Y(t), r: 2.6, fill: color }, svg));
    const [ln, lt] = r.progress[r.progress.length - 1];
    labels.push({ y: Y(lt), x: X(ln), color, text: `${name}  ${fmtT(lt)}` });
    if (!reduceMotion) {
      const len = path.getTotalLength();
      path.style.strokeDasharray = len; path.style.strokeDashoffset = len;
      host.closest(".sec").addEventListener("seen", () => {
        path.style.transition = "stroke-dashoffset 1.6s cubic-bezier(.3,.6,.2,1)"; path.style.strokeDashoffset = 0;
      }, { once: true });
    }
  }
  // de-overlap end labels
  labels.sort((a, b) => a.y - b.y);
  for (let i = 1; i < labels.length; i++) if (labels[i].y - labels[i - 1].y < 15) labels[i].y = labels[i - 1].y + 15;
  for (const l of labels) {
    const t = el("text", { x: Wd - right + 12, y: l.y + 4, "font-size": 10.5, fill: l.color }, svg);
    t.textContent = l.text;
  }
}

function drawBars(bench, host) {
  const impls = [
    ["mlkem, native", (op) => find(bench.native, op, "mlkem"), C.ink],
    ["RustCrypto ml-kem (parsed key)", (op) => find(bench.native, op, "ml-kem"), C.ink3],
    ["RustCrypto ml-kem (key from bytes, like mlkem)", (op) => find(bench.native, op, "ml-kem/bytes"), C.rule],
    ["mlkem as WASM, V8 optimising", (op) => bench.wasm.find((r) => r.set === "ML-KEM-768" && r.op === op && r.tier === "default")?.us, C.note],
    ["mlkem as WASM, V8 baseline only", (op) => bench.wasm.find((r) => r.set === "ML-KEM-768" && r.op === op && r.tier === "liftoff")?.us, "#9fb2d9"],
  ];
  function find(rows, op, impl) { return rows.find((r) => r.set === "ML-KEM-768" && r.op === op && r.impl === impl)?.us; }
  const ops = ["KeyGen", "Encaps", "Decaps"];
  const Wd = 1000, left = 90, right = 70, barH = 13, gap = 3, groupGap = 26, top = 10;
  const rowsFor = (op) => impls.filter(([, get]) => get(op) != null);
  const groupHs = ops.map((op) => rowsFor(op).length * (barH + gap));
  const Ht = top + groupHs.reduce((a, b) => a + b, 0) + ops.length * groupGap + 30;
  const max = 340;
  const X = (v) => left + (v / max) * (Wd - left - right);
  const svg = el("svg", { viewBox: `0 0 ${Wd} ${Ht}` }, host);
  let y0 = top;
  ops.forEach((op, gi) => {
    const groupH = groupHs[gi];
    const t = el("text", { x: 0, y: y0 + groupH / 2 + 4, "font-size": 13, fill: C.ink }, svg); t.textContent = op;
    let row = 0;
    impls.forEach(([name, get, color], i) => {
      const v = get(op);
      if (v == null) return;
      const y = y0 + (row++) * (barH + gap);
      const r = el("rect", { x: left, y, width: X(v) - left, height: barH, fill: color }, svg);
      if (i === 2) r.setAttribute("stroke", C.ink3);
      const tv = el("text", { x: X(v) + 6, y: y + barH - 3, "font-size": 10, fill: C.ink2 }, svg);
      tv.textContent = `${v.toFixed(1)} µs`;
      r.addEventListener("mousemove", (e) => showTip(`<b>${op}</b> · ${name}<br>median ${v.toFixed(2)} µs`, e));
      r.addEventListener("mouseleave", hideTip);
    });
    y0 += groupH + groupGap;
  });
  for (const v of [0, 100, 200, 300]) {
    const t = el("text", { x: X(v), y: Ht - 6, "font-size": 10, "text-anchor": "middle", fill: C.ink3 }, svg); t.textContent = `${v} µs`;
    el("line", { x1: X(v), x2: X(v), y1: top - 4, y2: Ht - 20, stroke: C.rule, "stroke-dasharray": "2 4" }, svg);
  }
  // legend
  const lg = document.createElement("div");
  lg.className = "legend"; lg.style.margin = "14px 0 0";
  lg.innerHTML = impls.map(([n, , c], i) => `<span><i class="dot" style="border-radius:0;background:${c};${i === 2 ? `outline:1px solid ${C.ink3}` : ""}"></i>${n}</span>`).join("");
  host.appendChild(lg);
}

// ------------------------------------------------------------------ boot
(async () => {
  try {
    K = await loadWasm();
    newSpecimen();
    $("regen").onclick = newSpecimen;
  } catch (e) {
    $("hover-readout").textContent = "WebAssembly could not load here (open the page over http, not file://).";
    for (const id of ["b-keygen", "regen", "b-bench"]) $(id).disabled = true;
    console.error(e);
  }
  try {
    const data = await (await fetch("data.json")).json();
    nodeDecaps = data.bench.wasm.find((r) => r.set === "ML-KEM-768" && r.op === "Decaps" && r.tier === "default")?.us;
    drawRuler(data.dudect, $("ruler"));
    drawGrowth(data.dudect, $("growth"));
    drawBars(data.bench, $("bars"));
    const kc = data.bench.keccakNs;
    const base = data.bench.baseline.find((r) => r.set === "ML-KEM-768" && r.op === "Encaps" && r.impl === "mlkem")?.us;
    const now = data.bench.native.find((r) => r.set === "ML-KEM-768" && r.op === "Encaps" && r.impl === "mlkem")?.us;
    $("speed-note").innerHTML = `The hash permutation at the heart of it (Keccak-f[1600]) runs at ${kc.mlkem} ns here vs ${kc.rustcrypto} ns for RustCrypto's: a dead heat. Most of the remaining gap is glue code, plus work RustCrypto caches inside its key objects. One optimisation, squeezing hash output 8 bytes at a time instead of 1, took ML-KEM-768 Encaps from ${base.toFixed(1)} to ${now.toFixed(1)} µs. In WebAssembly, V8's optimising compiler gets within about 2.3× of native.`;
  } catch (e) {
    console.error(e);
  }
})();

// ------------------------------------------------------------------ your-browser benchmark
$("b-bench").onclick = async () => {
  if (!K) return;
  const out = $("bench-out"), btn = $("b-bench");
  btn.disabled = true; out.textContent = "running…";
  await new Promise((r) => setTimeout(r, 30));
  const { x, B, L } = K;
  rand(B.d, 32); rand(B.z, 32); rand(B.m, 32);
  x.mlkem_768_keygen(B.d, B.z, B.ek, B.dk);
  x.mlkem_768_encaps(B.ek, B.m, B.ct, B.kb);
  for (let i = 0; i < 300; i++) x.mlkem_768_decaps(B.dk, B.ct, B.ka); // warm-up: let V8 optimise
  // browsers round performance.now(), so time batches and divide
  const per = [];
  for (let b = 0; b < 15; b++) {
    const t0 = performance.now();
    for (let i = 0; i < 40; i++) x.mlkem_768_decaps(B.dk, B.ct, B.ka);
    per.push(((performance.now() - t0) / 40) * 1000);
  }
  per.sort((a, b) => a - b);
  const med = per[Math.floor(per.length / 2)];
  out.textContent = `your browser: ${med.toFixed(0)} µs per Decaps (median of 15 batches × 40) ${nodeDecaps ? ` · my laptop in Node: ${nodeDecaps.toFixed(0)} µs` : ""}`;
  btn.disabled = false;
};
