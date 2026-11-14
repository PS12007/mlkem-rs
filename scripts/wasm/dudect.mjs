// dudect-style timing-leak test of the WebAssembly build, in Node: the same
// method as crates/dudect (LEARNING.md 5.1, 5.6), so that what is measured
// is the machine code V8 actually generated from our .wasm.
//
//   - classes: 0 = one FIXED input, 1 = a fresh RANDOM input;
//   - batches of 1000: all classes and inputs generated first, then the
//     whole batch copied once more with a single memcpy (TypedArray.set),
//     then a timed loop with no class-dependent code;
//   - "aa-" targets are A/A controls: the random input is still generated,
//     but the fixed one is used, so only the data differs from the real test;
//   - Welch's t-test, uncropped and at 100 dudect percentile crops; the
//     maximum |t| is reported. < 4.5 nothing detected, >= 10 leak.
//
// Targets: decaps-ct (ML-KEM-768 Decaps; class 0 a valid ciphertext,
// class 1 random bytes) and u-encode-zero (ByteEncode_11(Compress_11(u)),
// needs the `probes` feature; class 0 u = 0, class 1 random u).
//
// Usage: node scripts/wasm/dudect.mjs mlkem_wasm.wasm TARGET [n]
// CPU pinning is done by the caller (scripts/wasm-dudect.ps1).

import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const [wasmPath, targetArg, nArg] = process.argv.slice(2);
if (!wasmPath || !targetArg) {
  console.error("usage: node scripts/wasm/dudect.mjs mlkem_wasm.wasm TARGET [n]");
  process.exit(2);
}
const n = Number(nArg ?? 200000);
const aa = targetArg.startsWith("aa-");
const target = targetArg.replace(/^aa-/, "");
const BATCH = 1000;

const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath));
const x = instance.exports, mem = x.memory;
let top = x.__heap_base.value;
function alloc(len) {
  const p = top;
  top += (len + 15) & ~15;
  const need = top - mem.buffer.byteLength;
  if (need > 0) mem.grow(Math.ceil(need / 65536));
  return p;
}
const bytes = (p, len) => new Uint8Array(mem.buffer, p, len);
const randomFill = (u8) => {
  for (let o = 0; o < u8.length; o += 65536) webcrypto.getRandomValues(u8.subarray(o, o + 65536));
};

// ---- targets: input size, fixed input, random-input generator, operation
function makeTarget() {
  if (target === "decaps-ct") {
    const [ekLen, dkLen, ctLen] = [x.mlkem_768_ek_len(), x.mlkem_768_dk_len(), x.mlkem_768_ct_len()];
    const d = alloc(32), z = alloc(32), m = alloc(32);
    for (const p of [d, z, m]) randomFill(bytes(p, 32));
    const ek = alloc(ekLen), dk = alloc(dkLen), c = alloc(ctLen), k = alloc(32);
    x.mlkem_768_keygen(d, z, ek, dk);
    if (x.mlkem_768_encaps(ek, m, c, k) !== 0) throw new Error("ek rejected");
    const fixed = bytes(c, ctLen).slice();
    const decaps = x.mlkem_768_decaps;
    return {
      desc: "ML-KEM-768 Decaps, one fixed key. class 0: one fixed VALID ciphertext; class 1: random bytes (implicit rejection)",
      size: ctLen, fixed,
      random: (u8) => randomFill(u8),
      op: (p) => decaps(dk, p, k),
    };
  }
  if (target === "u-encode-zero") {
    if (!x.mlkem_probe_u_encode_d11) throw new Error("u-encode-zero needs a build with --features probes");
    const out = alloc(352);
    const probe = x.mlkem_probe_u_encode_d11;
    return {
      desc: "ByteEncode_11(Compress_11(u)), the KyberSlash1 site. class 0: u = 0; class 1: random u in [0, q)",
      size: 512, fixed: new Uint8Array(512),
      random: (u8) => {
        const c = new Uint16Array(u8.buffer, u8.byteOffset, 256);
        webcrypto.getRandomValues(c);
        for (let i = 0; i < 256; i++) c[i] %= 3329; // bias ~2^-4, irrelevant here
      },
      op: (p) => probe(p, out),
    };
  }
  throw new Error(`unknown target ${targetArg}; one of decaps-ct, u-encode-zero (optionally aa-)`);
}

const t = makeTarget();
const prep = alloc(BATCH * t.size), timed = alloc(BATCH * t.size);
const scratch = new Uint8Array(t.size);
const classes = new Uint8Array(BATCH), out = new Float64Array(BATCH);
const now = () => process.hrtime.bigint();

function batch(count) {
  webcrypto.getRandomValues(classes);
  const P = bytes(prep, count * t.size);
  for (let i = 0; i < count; i++) {
    classes[i] &= 1;
    const slot = P.subarray(i * t.size, (i + 1) * t.size);
    if (classes[i] === 0) {
      slot.set(t.fixed);
    } else {
      t.random(scratch); // A/A: same work, then the fixed input is used
      slot.set(aa ? t.fixed : scratch);
    }
  }
  bytes(timed, count * t.size).set(P); // one class-independent copy
  for (let i = 0; i < count; i++) {
    const p = timed + i * t.size;
    const t0 = now();
    t.op(p);
    const t1 = now();
    out[i] = Number(t1 - t0);
  }
}
function run(total, sink) {
  for (let left = total; left > 0; left -= BATCH) {
    const c = Math.min(left, BATCH);
    batch(c);
    for (let i = 0; i < c; i++) sink(classes[i], out[i]);
  }
}

// ---- Welch's t-test with dudect crops (crates/dudect/src/stats.rs)
class Welch {
  n = [0, 0]; mean = [0, 0]; m2 = [0, 0];
  push(c, v) {
    this.n[c]++;
    const d = v - this.mean[c];
    this.mean[c] += d / this.n[c];
    this.m2[c] += d * (v - this.mean[c]);
  }
  t() {
    if (this.n[0] < 2 || this.n[1] < 2) return 0;
    const v0 = this.m2[0] / (this.n[0] - 1), v1 = this.m2[1] / (this.n[1] - 1);
    const se = Math.sqrt(v0 / this.n[0] + v1 / this.n[1]);
    return se === 0 ? 0 : (this.mean[0] - this.mean[1]) / se;
  }
}

const warm = Math.min(Math.max(Math.floor(n / 100), 1000), 20000);
run(warm, () => {}); // warm-up: caches, predictors, and V8 tier-up to TurboFan
const cal = [];
run(warm, (_, v) => cal.push(v));
cal.sort((a, b) => a - b);
const tests = [{ name: "uncropped", thr: Infinity, w: new Welch() }];
for (let k = 0; k < 100; k++) {
  const p = 1 - Math.pow(0.5, (10 * (k + 1)) / 100);
  tests.push({ name: `below p${(p * 100).toFixed(4)}`, thr: cal[Math.round((cal.length - 1) * p)], w: new Welch() });
}
const start = Date.now();
let i = 0;
const maxT = () => tests.reduce((b, x) => (Math.abs(x.w.t()) > Math.abs(b.w.t()) ? x : b));
run(n, (c, v) => {
  for (const s of tests) if (v < s.thr) s.w.push(c, v);
  if (++i % Math.max(1, Math.floor(n / 10)) === 0) {
    const b = maxT();
    console.log(`progress n=${String(i).padStart(9)}  max|t| = ${Math.abs(b.w.t()).toFixed(2).padStart(8)}  (${b.name})  elapsed ${Math.round((Date.now() - start) / 1000)} s`);
  }
});

const u = tests[0].w;
const best = maxT(), tmax = Math.abs(best.w.t());
console.log("");
console.log(`# mlkem WebAssembly dudect (Node ${process.version}, V8 ${process.versions.v8})`);
console.log(`target:        ${targetArg}${aa ? "  (A/A CONTROL: both classes receive identical data)" : ""}`);
console.log(`description:   ${t.desc}`);
console.log(`v8 flags:      ${process.execArgv.join(" ") || "(none: default tiering)"}`);
console.log(`timer:         process.hrtime.bigint() (QueryPerformanceCounter on Windows)`);
console.log(`measurements:  ${n} (+ ${warm} warm-up + ${warm} calibration)`);
console.log(`uncropped means: class 0 = ${u.mean[0].toFixed(1)} ns, class 1 = ${u.mean[1].toFixed(1)} ns (n0 ${u.n[0]}, n1 ${u.n[1]})`);
console.log(`max |t| = ${tmax.toFixed(2)} (${best.name})`);
console.log(`verdict: ${tmax < 4.5 ? "no leak detected (max |t| < 4.5)" : tmax < 10 ? "POSSIBLE LEAK (4.5 <= max |t| < 10): re-run with more measurements" : "LEAK (max |t| >= 10): timing depends on the input class"}`);
