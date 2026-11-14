# mlkem-rs

> **Warning: educational code. Not audited. Do not use in production.**
> This is a learning implementation of ML-KEM. No one has reviewed it for
> security. Its constant-time behaviour has been checked only on the
> machines described in this README. For real systems, use a maintained,
> audited library.

A from-scratch Rust implementation of ML-KEM (NIST FIPS 203, the
standardised post-quantum key-encapsulation mechanism, formerly Kyber),
plus a statistical timing-leak tester (dudect method). It targets Windows
with the MSVC toolchain, and WebAssembly.

The library (`crates/mlkem`) has no runtime dependencies: field arithmetic,
NTT, Keccak/SHA-3 and the KEM are all written by hand. It passes all 240
NIST ACVP test vectors and is cross-checked byte for byte against
RustCrypto's `ml-kem`.

| crate | what it is |
|---|---|
| `crates/mlkem` | the library: ML-KEM-512/768/1024 |
| `crates/dudect` | `mlkem-dudect`, the timing-leak tester (Windows, x86-64) |
| `crates/bench` | `mlkem-bench`, benchmarks against RustCrypto's `ml-kem` |
| `crates/wasm` | `mlkem-wasm`, the library as a WebAssembly module |

Status: all seven planned phases are done. See [LEARNING.md](LEARNING.md)
for what each phase covers and why.

## Reference

- FIPS 203 (August 2024): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  Code comments cite its section and algorithm numbers, e.g. "Alg 9 (§4.3)".

## Building

Requires Rust stable with the MSVC toolchain (`x86_64-pc-windows-msvc`)
and the Visual Studio C++ build tools.

```
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```

## Reproducing the results

Every number in this README comes from a script in `scripts/` whose raw
output, with date, commit and compiler, is committed under `results/`.
Run them with `powershell -ExecutionPolicy Bypass -File scripts\<name>`.

| result | script | output | time |
|---|---|---|---|
| constant-time assembly check, x86-64 (CI) | `asm-check.ps1` | `results/asm-check.txt`, `results/asm/` | a few min |
| constant-time instruction check, WASM (CI) | `wasm-check.ps1` | `results/wasm-check.txt` | ~1 min |
| 100 000-case property tests | `extended-proptest.ps1` | `results/extended-proptest.txt` | ~4 min |
| timing-leak tests, native | `dudect.ps1` | `results/dudect/` | ~30 min |
| timing-leak tests, WASM in Node | `wasm-dudect.ps1` | `results/wasm/dudect/` | ~7 min |
| benchmarks vs `ml-kem` | `bench.ps1` | `results/bench/` | ~1 min |
| WASM benchmarks in Node | `wasm-bench.ps1` | `results/wasm/bench-cpu*.txt` | ~2 min |

The timing scripts pin to logical CPUs 2 (a P-core) and 20 (an E-core) of
an i7-14700HX; pass `-Cpus` for another machine.

## Timing-leak test (dudect)

`crates/dudect` measures whether running time depends on input data
(Welch's t-test, fixed vs random inputs, dudect percentile crops; method and
caveats in [LEARNING.md phase 5](LEARNING.md)). Each target runs next to an
A/A control that cannot leak. Measured on an Intel i7-14700HX, one P-core
(cpu 2) and one E-core (cpu 20); max |t| < 4.5 means nothing detected and
≥ 10 means a leak. Raw output is in `results/dudect/`, and the table in
`results/dudect/summary.txt`, produced by `scripts/dudect.ps1`.

| build / target | P-core | E-core |
|---|---|---|
| normal: ct-eq, encode targets, Decaps, Encaps (7 targets) | 1.3 – 2.9 | 1.2 – 1.8 |
| normal: A/A controls | 1.9 – 3.0 | 1.9 – 3.6 |
| normal: KeyGen, fixed vs random d | 4480 | 2500 |
| leaky-early-exit: Decaps, valid vs random ciphertext | 660 | 202 |
| leaky-kyberslash: Compress_11 (`div` on secret) | 2.6 | 19857 |
| leaky-kyberslash: Compress_1 (`div` on secret) | 1.2 – 3.0 | 1.8 – 2.4 |

KeyGen's dependence is on ρ, which is public (rejection sampling of the
matrix, as FIPS 203 specifies). The leaky rows are deliberately broken
builds (Cargo features) that show the tester can detect a leak. It found
the `div` leak only on the E-core, and the d = 1 variant on neither core.
A pass does not prove constant time; it means no difference was found with
10⁶–10⁷ measurements on this machine.

## Performance

`crates/bench` compares this crate with RustCrypto's `ml-kem` 0.3.3. Both
get the same inputs, outputs are checked byte-identical before timing,
and the result is the median of 10 000 calls. Method in
[LEARNING.md phase 6](LEARNING.md); raw output in `results/bench/`, from
`scripts/bench.ps1`. Medians in µs, i7-14700HX P-core (cpu 2), rustc
1.99.1, release build, no `target-cpu=native`:

| | KeyGen | Encaps | Decaps |
|---|---|---|---|
| ML-KEM-512, this crate | 25.7 | 31.1 | 40.0 |
| ML-KEM-512, ml-kem (parsed key) | 21.8 | 21.6 | 27.8 |
| ML-KEM-512, ml-kem (key from bytes) | | 24.4 | 31.2 |
| ML-KEM-768, this crate | 42.1 | 49.2 | 60.5 |
| ML-KEM-768, ml-kem (parsed key) | 38.8 | 38.7 | 47.5 |
| ML-KEM-768, ml-kem (key from bytes) | | 43.1 | 52.4 |
| ML-KEM-1024, this crate | 65.3 | 73.3 | 87.8 |
| ML-KEM-1024, ml-kem (parsed key) | 62.7 | 62.3 | 73.7 |
| ML-KEM-1024, ml-kem (key from bytes) | | 68.1 | 80.3 |

This crate stores keys as bytes and redoes the decoding and H(ek) on every
call; `ml-kem` caches them in its key objects. The "key from bytes" rows
time `ml-kem` doing that work too, and they are the closer comparison:
this crate is 8–28% slower than they are. Its Keccak-f[1600] is as fast as
RustCrypto's `keccak` crate (350 vs 352 ns). The E-core shows the same ratios.

## WebAssembly

`crates/wasm` builds a 58 KB `no_std` module with a plain C ABI (no
wasm-bindgen), so JavaScript can call it directly. See
[LEARNING.md phase 7](LEARNING.md).

```
cargo build --release -p mlkem-wasm --target wasm32-unknown-unknown
node scripts/wasm/acvp.mjs target/wasm32-unknown-unknown/release/mlkem_wasm.wasm
```

- **Correct:** all 240 NIST ACVP cases pass in Node 24 (run in CI).
- **Constant-time instructions:** `scripts/wasm-check.ps1` applies the x86
  rules to the WASM output at every optimisation level, and requires that a
  deliberately leaky build is caught (run in CI). Note: LLVM keeps
  `x / constant` as a real `i32.div_u` for WASM, where x86 gets a multiply.
- **Timing, measured on V8's machine code** (`scripts/wasm-dudect.ps1`): the
  normal build shows no leak on either core (max |t| 0.9–2.8, A/A controls
  included). The leaky early-exit build is caught on both cores (|t| 46, 57),
  and the leaky KyberSlash build only on the E-core (|t| 713), as natively.
- **Speed:** ML-KEM-768 KeyGen / Encaps / Decaps take 95 / 113 / 147 µs on
  the P-core under V8's normal tiering (2.3–2.4× native), and 236 / 279 /
  321 µs under its baseline compiler only.

The module exports FIPS 203's `_internal` functions, so the caller must
supply the random seeds from `crypto.getRandomValues`.

## Limitations

- **Not audited**, and not reviewed by anyone but its author.
- **Constant time is checked only for x86-64 Windows (MSVC) and wasm32
  release builds**: statically at every optimisation level
  (`scripts/asm-check.ps1`, `scripts/wasm-check.ps1`, both run in CI), and
  by measurement on one CPU model (natively, and in Node/V8 for WASM).
  Debug builds add branches on secret data (overflow checks,
  `debug_assert!`). ARM and other WASM engines are unchecked.
- **The timing tests are statistical.** They can miss leaks that are smaller
  than what 10⁶–10⁷ samples resolve, or that show up only on other CPUs.
  This laptop did not reveal KyberSlash on d = 1 dividends at all.
- **Zeroisation is best effort**: copies the compiler makes (spills, moved
  values) are not wiped.
- **Portable scalar code only**: no AVX2 or NEON, so it is slower than
  optimised libraries.
- **The `*_internal` functions** (deterministic KeyGen and Encaps) are
  public for testing, which FIPS 203 §6 advises against offering to
  applications.

## License

MIT, see [LICENSE](LICENSE).
