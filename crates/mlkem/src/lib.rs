//! An educational, from-scratch implementation of ML-KEM (NIST FIPS 203).
//!
//! **Not audited. Do not use in production.**
//!
//! Module map (FIPS 203 section in brackets):
//! - [`params`]: constants and parameter sets (§8)

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod params;
