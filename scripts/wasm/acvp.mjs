// Runs every NIST ACVP test vector (vectors/acvp/) against the WebAssembly
// build of mlkem, in Node, the same checks as crates/mlkem/tests/acvp.rs.
// No npm packages: only Node's built-in fs and WebAssembly.
//
// Usage: node scripts/wasm/acvp.mjs path/to/mlkem_wasm.wasm
// Exit code 1 on any mismatch or wrong case count.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node scripts/wasm/acvp.mjs mlkem_wasm.wasm");
  process.exit(2);
}

const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath));
const x = instance.exports;
const mem = x.memory;

// Bump allocator over memory the module does not use (above __heap_base).
// Reset before each test case.
const heapBase = x.__heap_base.value;
let top = heapBase;
function alloc(n) {
  const p = top;
  top += (n + 15) & ~15;
  const need = top - mem.buffer.byteLength;
  if (need > 0) mem.grow(Math.ceil(need / 65536));
  return p;
}
function put(bytes) {
  const p = alloc(bytes.length);
  new Uint8Array(mem.buffer, p, bytes.length).set(bytes);
  return p;
}
const get = (p, n) => Buffer.from(new Uint8Array(mem.buffer, p, n));
const hex = (s) => Buffer.from(s, "hex");

const SETS = { "ML-KEM-512": "512", "ML-KEM-768": "768", "ML-KEM-1024": "1024" };
function kem(name) {
  const p = SETS[name];
  if (!p) throw new Error(`unknown parameter set ${name}`);
  const f = (s) => x[`mlkem_${p}_${s}`];
  return {
    ekLen: f("ek_len")(), dkLen: f("dk_len")(), ctLen: f("ct_len")(),
    keygen: f("keygen"), encaps: f("encaps"), decaps: f("decaps"),
    ekCheck: f("ek_check"), dkCheck: f("dk_check"),
  };
}

let failures = 0;
function check(ok, what) {
  if (!ok) {
    failures++;
    console.log(`FAIL ${what}`);
  }
}
const load = (f) => JSON.parse(readFileSync(join(root, "vectors", "acvp", f), "utf8"));

// KeyGen_internal(d, z) must give exactly ek and dk.
let nKeygen = 0;
for (const g of load("keyGen-internalProjection.json").testGroups) {
  const k = kem(g.parameterSet);
  for (const t of g.tests) {
    top = heapBase;
    const ek = alloc(k.ekLen), dk = alloc(k.dkLen);
    k.keygen(put(hex(t.d)), put(hex(t.z)), ek, dk);
    check(get(ek, k.ekLen).equals(hex(t.ek)), `keyGen tcId ${t.tcId}: ek`);
    check(get(dk, k.dkLen).equals(hex(t.dk)), `keyGen tcId ${t.tcId}: dk`);
    nKeygen++;
  }
}

const counts = {};
for (const g of load("encapDecap-internalProjection.json").testGroups) {
  const k = kem(g.parameterSet);
  for (const t of g.tests) {
    top = heapBase;
    const id = `${g.function} tcId ${t.tcId}`;
    switch (g.function) {
      case "encapsulation": {
        const c = alloc(k.ctLen), key = alloc(32);
        const r = k.encaps(put(hex(t.ek)), put(hex(t.m)), c, key);
        check(r === 0, `${id}: valid ek rejected`);
        check(get(c, k.ctLen).equals(hex(t.c)), `${id}: c`);
        check(get(key, 32).equals(hex(t.k)), `${id}: k`);
        break;
      }
      case "decapsulation": {
        const key = alloc(32);
        const r = k.decaps(put(hex(t.dk)), put(hex(t.c)), key);
        check(r === 0, `${id}: valid dk rejected`);
        check(get(key, 32).equals(hex(t.k)), `${id} (${t.reason})`);
        break;
      }
      case "encapsulationKeyCheck":
        check((k.ekCheck(put(hex(t.ek))) === 0) === t.testPassed, `${id} (${t.reason})`);
        break;
      case "decapsulationKeyCheck":
        check((k.dkCheck(put(hex(t.dk))) === 0) === t.testPassed, `${id} (${t.reason})`);
        break;
      default:
        throw new Error(`unknown function ${g.function}`);
    }
    counts[g.function] = (counts[g.function] ?? 0) + 1;
  }
}

const expected = {
  encapsulation: 75, decapsulation: 30, encapsulationKeyCheck: 30, decapsulationKeyCheck: 30,
};
check(nKeygen === 75, `keyGen count ${nKeygen}, expected 75`);
for (const [f, n] of Object.entries(expected)) {
  check(counts[f] === n, `${f} count ${counts[f]}, expected ${n}`);
}
const total = nKeygen + Object.values(counts).reduce((a, b) => a + b, 0);
console.log(`node ${process.version}, ${wasmPath}`);
console.log(`keyGen: ${nKeygen} cases; ` +
  Object.entries(counts).map(([f, n]) => `${f}: ${n}`).join("; "));
console.log(failures === 0 ? `PASS: all ${total} ACVP cases` : `FAIL: ${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
