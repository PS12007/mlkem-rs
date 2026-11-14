// Times KeyGen, Encaps and Decaps of the WebAssembly build of mlkem in Node,
// with the same method as crates/bench (LEARNING.md 6.2): 64 random inputs
// cycled, every call timed on its own, 1 warm-up round discarded, then
// `rounds` rounds of `samples` calls; median, 5th and 95th percentile.
//
// Usage: node [V8 flags] scripts/wasm/bench.mjs mlkem_wasm.wasm [rounds] [samples]
// e.g. `node --liftoff-only ...` to time V8's baseline compiler only, or
// `node --no-liftoff ...` for its optimising compiler (TurboFan) only.
// CPU pinning is done by the caller (scripts/wasm-bench.ps1).

import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const [wasmPath, roundsArg, samplesArg] = process.argv.slice(2);
const rounds = Number(roundsArg ?? 20), samples = Number(samplesArg ?? 500);
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath));
const x = instance.exports, mem = x.memory;
const INPUTS = 64;

let top = x.__heap_base.value;
function alloc(n) {
  const p = top;
  top += (n + 15) & ~15;
  const need = top - mem.buffer.byteLength;
  if (need > 0) mem.grow(Math.ceil(need / 65536));
  return p;
}
const rand32 = () => {
  const p = alloc(32);
  webcrypto.getRandomValues(new Uint8Array(mem.buffer, p, 32));
  return p;
};

// Timer: process.hrtime.bigint() (nanoseconds; on Windows it is backed by
// QueryPerformanceCounter, 100 ns resolution, which is under 0.5% of the
// fastest operation timed here).
const now = () => process.hrtime.bigint();

function measure(fn) {
  const t = [];
  for (let round = 0; round <= rounds; round++) {
    for (let s = 0; s < samples; s++) {
      const i = (round * samples + s) % INPUTS;
      const t0 = now();
      fn(i);
      const t1 = now();
      if (round > 0) t.push(Number(t1 - t0) / 1000);
    }
  }
  t.sort((a, b) => a - b);
  const pct = (p) => t[Math.round((t.length - 1) * p)];
  return { med: pct(0.5), p5: pct(0.05), p95: pct(0.95), n: t.length };
}

console.log("# mlkem WebAssembly benchmark (Node)");
console.log(`node:     ${process.version}, V8 ${process.versions.v8}`);
console.log(`v8 flags: ${process.execArgv.join(" ") || "(none: default tiering)"}`);
console.log(`method:   ${INPUTS} random inputs; ${rounds} rounds x ${samples} calls after 1 warm-up round`);
console.log("");
console.log(`${"param set".padEnd(12)} ${"op".padEnd(7)} ${"median us".padStart(10)} ${"p5 us".padStart(10)} ${"p95 us".padStart(10)} ${"ops/s".padStart(10)} ${"n".padStart(8)}`);

for (const p of ["512", "768", "1024"]) {
  const f = (s) => x[`mlkem_${p}_${s}`];
  const [ekLen, dkLen, ctLen] = [f("ek_len")(), f("dk_len")(), f("ct_len")()];
  const inp = [...Array(INPUTS)].map(() => {
    const d = rand32(), z = rand32(), m = rand32();
    const ek = alloc(ekLen), dk = alloc(dkLen), c = alloc(ctLen), k = alloc(32);
    f("keygen")(d, z, ek, dk);
    if (f("encaps")(ek, m, c, k) !== 0) throw new Error("ek rejected");
    return { d, z, m, ek, dk, c, k };
  });
  const outEk = alloc(ekLen), outDk = alloc(dkLen), outC = alloc(ctLen), outK = alloc(32);
  // Sanity: Decaps must return Encaps' key.
  for (const t of inp) {
    f("decaps")(t.dk, t.c, outK);
    const a = new Uint8Array(mem.buffer, outK, 32), b = new Uint8Array(mem.buffer, t.k, 32);
    if (!a.every((v, j) => v === b[j])) throw new Error("decaps mismatch");
  }
  const keygen = f("keygen"), encaps = f("encaps"), decaps = f("decaps");
  const ops = {
    KeyGen: (i) => keygen(inp[i].d, inp[i].z, outEk, outDk),
    Encaps: (i) => encaps(inp[i].ek, inp[i].m, outC, outK),
    Decaps: (i) => decaps(inp[i].dk, inp[i].c, outK),
  };
  for (const [op, fn] of Object.entries(ops)) {
    const r = measure(fn);
    console.log(`${("ML-KEM-" + p).padEnd(12)} ${op.padEnd(7)} ${r.med.toFixed(2).padStart(10)} ${r.p5.toFixed(2).padStart(10)} ${r.p95.toFixed(2).padStart(10)} ${(1e6 / r.med).toFixed(0).padStart(10)} ${String(r.n).padStart(8)}`);
  }
}
