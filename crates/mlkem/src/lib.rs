//! An educational, from-scratch implementation of ML-KEM (NIST FIPS 203).
//!
//! **Not audited. Do not use in production.**
//!
//! Module map (FIPS 203 section in brackets):
//! - [`params`]: constants and parameter sets (§8)
//! - `ct`: constant-time masks, comparison and selection
//! - `field`: arithmetic mod q with Barrett and Montgomery reduction

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// The building blocks come before the KEM that uses them (phase 3).
// Until then the non-test build would warn that they are unused.
// TODO(phase 3): remove this allow.
#![allow(dead_code)]

mod ct;
mod field;
pub mod params;
