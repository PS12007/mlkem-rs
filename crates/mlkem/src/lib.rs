//! An educational, from-scratch implementation of ML-KEM (NIST FIPS 203).
//!
//! **Not audited. Do not use in production.**
//!
//! Module map (FIPS 203 section in brackets):
//! - [`params`]: constants and parameter sets (§8)
//! - `ct`: constant-time masks, comparison and selection
//! - `field`: arithmetic mod q with Barrett and Montgomery reduction
//! - `poly`: polynomials in R_q = Z_q[X]/(X^256+1) (§2.3)
//! - `ntt`: NTT, inverse NTT, multiplication in T_q (§4.3, Alg 9–12)
//! - `encode`: Compress/Decompress, ByteEncode/ByteDecode (§4.2.1, Alg 3–6)
//! - `sample`: SampleNTT and SamplePolyCBD (§4.2.2, Alg 7–8)
//! - `hash`: Keccak-f[1600], SHA3-256/512, SHAKE128/256 (FIPS 202), and
//!   the H, J, G, PRF, XOF wrappers (§4.1)
//! - `spec` (tests only): literal pseudocode transcriptions used as oracles

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// The building blocks come before the KEM that uses them (phase 3).
// Until then the non-test build would warn that they are unused.
// TODO(phase 3): remove this allow.
#![allow(dead_code)]

mod ct;
mod encode;
mod field;
mod hash;
mod ntt;
pub mod params;
mod poly;
mod sample;
#[cfg(test)]
mod spec;
