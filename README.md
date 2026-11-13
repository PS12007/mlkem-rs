# mlkem-rs

> **Warning: educational code. Not audited. Do not use in production.**
> This is a learning implementation of ML-KEM. No one has reviewed it for
> security. Its constant-time behaviour has been checked only on the
> machines described in this README. For real systems, use a maintained,
> audited library.

A from-scratch Rust implementation of ML-KEM (NIST FIPS 203, the
standardised post-quantum key-encapsulation mechanism, formerly Kyber),
plus a statistical timing-leak tester (dudect method). It targets Windows
with the MSVC toolchain.

Status: work in progress, built in phases. See [LEARNING.md](LEARNING.md)
for what each phase covers and why.

## Reference

- FIPS 203 (August 2024): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  Code comments cite its section and algorithm numbers, e.g. "Alg 9 (§4.3)".

## Building

Requires Rust stable with the MSVC toolchain (`x86_64-pc-windows-msvc`)
and the Visual Studio C++ build tools.

```
cargo test
cargo clippy --all-targets -- -D warnings
```

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
| normal: ct-eq, encode targets, Decaps, Encaps (8 targets) | 1.5 – 2.7 | 1.5 – 2.6 |
| normal: A/A controls | 1.4 – 1.7 | 1.8 – 2.3 |
| normal: KeyGen, fixed vs random d | 4519 | 3921 |
| leaky-early-exit: Decaps, valid vs random ciphertext | 660 | 202 |
| leaky-kyberslash: Compress_11 (`div` on secret) | 2.6 | 19857 |
| leaky-kyberslash: Compress_1 (`div` on secret) | 1.2 – 3.0 | 1.8 – 2.4 |

KeyGen's dependence is on ρ, which is public (rejection sampling of the
matrix, as FIPS 203 specifies). The leaky rows are deliberately broken
builds (Cargo features) that show the tester can detect a leak. It found
the `div` leak only on the E-core, and the d = 1 variant on neither core.
A pass does not prove constant time; it means no difference was found with
10⁶–10⁷ measurements on this machine.

## License

MIT, see [LICENSE](LICENSE).
