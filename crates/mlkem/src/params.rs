//! Constants shared by every ML-KEM parameter set (FIPS 203 §8).
//!
//! The per-parameter-set values (k, η1, η2, du, dv from Table 2) are added in
//! phase 3, when K-PKE starts using them.

/// n = 256: every polynomial has 256 coefficients (FIPS 203 §8).
pub const N: usize = 256;

/// q = 3329 = 13·2^8 + 1, the prime modulus (FIPS 203 §8).
///
/// q is prime, and 256 divides q − 1 = 3328 = 13·256. That is why Z_q has a
/// primitive 256-th root of unity (ζ = 17), which is what makes the NTT work.
pub const Q: i16 = 3329;
