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

## License

MIT, see [LICENSE](LICENSE).
