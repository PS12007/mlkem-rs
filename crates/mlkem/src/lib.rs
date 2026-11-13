//! An educational, from-scratch implementation of ML-KEM (NIST FIPS 203).
//!
//! **Not audited. Do not use in production.**
//!
//! ```
//! # #[cfg(windows)] {
//! use mlkem::{ml_kem_768, OsRng};
//!
//! // Alice generates a key pair and publishes `ek`.
//! let (ek, dk) = ml_kem_768::generate(&mut OsRng).unwrap();
//! // Bob encapsulates: he gets a ciphertext to send and his copy of the key.
//! let (ct, key_bob) = ek.encapsulate(&mut OsRng).unwrap();
//! // Alice decapsulates the ciphertext and gets the same key.
//! let key_alice = dk.decapsulate(&ct);
//! assert_eq!(key_alice, key_bob);
//! # }
//! ```
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
//! - `kpke`: K-PKE KeyGen / Encrypt / Decrypt (§5, Alg 13–15)
//! - `kem`: ML-KEM internal algorithms and input checks (§6, §7)
//! - [`ml_kem_512`], [`ml_kem_768`], [`ml_kem_1024`]: the public API (§7)
//! - `spec` (tests only): literal pseudocode transcriptions used as oracles

#![cfg_attr(not(test), no_std)]
// `deny`, not `forbid`, so that exactly one module (`rng`, the Windows RNG
// call) can opt out with `#[allow(unsafe_code)]`. Everything else is safe.
#![deny(unsafe_code)]

mod ct;
mod encode;
mod field;
mod hash;
#[cfg(feature = "hazmat")]
pub mod hazmat;
mod kem;
mod kpke;
mod ntt;
pub mod params;
mod poly;
mod rng;
mod sample;
#[cfg(test)]
mod spec;

#[cfg(windows)]
pub use rng::OsRng;
pub use rng::RandomSource;

use core::fmt;

/// Everything that can go wrong in the public API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrong length (FIPS 203 §7.2/§7.3 "type check") for the named object.
    InvalidLength,
    /// The encapsulation key failed the modulus check (§7.2): some encoded
    /// coefficient is ≥ q.
    InvalidEncapsulationKey,
    /// The decapsulation key failed the hash check (§7.3): the stored H(ek)
    /// does not match the stored ek.
    InvalidDecapsulationKey,
    /// The random source failed (Alg 19 line 4, Alg 20 line 3).
    RandomnessFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "input has the wrong length for this parameter set",
            Error::InvalidEncapsulationKey => "encapsulation key failed the modulus check",
            Error::InvalidDecapsulationKey => "decapsulation key failed the hash check",
            Error::RandomnessFailure => "random number generation failed",
        })
    }
}

impl core::error::Error for Error {}

/// Best-effort wipe of secret bytes. Writing zeros and then passing the
/// buffer through `black_box` makes it much harder for the optimiser to drop
/// the writes as "dead" (nothing reads them afterwards). It is *not* a
/// guarantee: copies made earlier (moves, registers, the stack of called
/// functions) are not wiped. See Limits in README.md.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(buf);
}

/// The 32-byte shared secret K (FIPS 203 Table 3).
///
/// Equality is constant time, `Debug` does not print the bytes, and the
/// bytes are wiped (best effort) on drop.
#[derive(Clone)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        ct::ct_eq_bytes(&self.0, &other.0) == 0xFF
    }
}
impl Eq for SharedSecret {}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(..)")
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Generates the typed API for one parameter set: fixed-size key and
/// ciphertext types, with the FIPS 203 §7 input checks built into their
/// constructors, so an unchecked key cannot reach Encaps/Decaps.
macro_rules! parameter_set {
    ($module:ident, $params:path, $doc:literal) => {
        #[doc = $doc]
        pub mod $module {
            use crate::{Error, RandomSource, SharedSecret, kem, params::Params, wipe};
            use core::fmt;

            pub const PARAMS: Params = $params;
            /// Encapsulation key length in bytes (FIPS 203 Table 3).
            pub const EK_LEN: usize = PARAMS.ek_len();
            /// Decapsulation key length in bytes (FIPS 203 Table 3).
            pub const DK_LEN: usize = PARAMS.dk_len();
            /// Ciphertext length in bytes (FIPS 203 Table 3).
            pub const CT_LEN: usize = PARAMS.ct_len();

            /// A *checked* encapsulation key (the public key).
            #[derive(Clone, PartialEq, Eq, Debug)]
            pub struct EncapsulationKey([u8; EK_LEN]);

            /// A *checked* decapsulation key (the secret key). Its bytes are
            /// wiped (best effort) on drop and never printed by `Debug`.
            #[derive(Clone)]
            pub struct DecapsulationKey([u8; DK_LEN]);

            /// A ciphertext. Any byte string of the right length is a valid
            /// ciphertext: tampered ones are handled by implicit rejection.
            #[derive(Clone, PartialEq, Eq, Debug)]
            pub struct Ciphertext([u8; CT_LEN]);

            /// Algorithm 19 ML-KEM.KeyGen().
            pub fn generate(
                rng: &mut impl RandomSource,
            ) -> Result<(EncapsulationKey, DecapsulationKey), Error> {
                let mut dz = [0u8; 64]; // lines 1–2: d, z ← 32 random bytes each
                rng.fill_bytes(&mut dz)?; // lines 3–5: report RNG failure
                let (d, z) = dz.split_at(32);
                let keys = generate_internal(d.try_into().unwrap(), z.try_into().unwrap());
                wipe(&mut dz);
                Ok(keys)
            }

            /// Algorithm 16 ML-KEM.KeyGen_internal(d, z): deterministic.
            ///
            /// **For testing only.** FIPS 203 §6 says the internal functions
            /// should not be offered to applications, and the seeds must come
            /// from an approved RNG. It is public here so the official test
            /// vectors and the timing harness can call it.
            pub fn generate_internal(
                d: &[u8; 32],
                z: &[u8; 32],
            ) -> (EncapsulationKey, DecapsulationKey) {
                let mut ek = [0u8; EK_LEN];
                let mut dk = [0u8; DK_LEN];
                kem::keygen_internal(&PARAMS, d, z, &mut ek, &mut dk);
                (EncapsulationKey(ek), DecapsulationKey(dk))
            }

            impl EncapsulationKey {
                /// Encapsulation key check (§7.2). The array type is the type
                /// check; this function performs the modulus check.
                pub fn from_bytes(bytes: &[u8; EK_LEN]) -> Result<Self, Error> {
                    if kem::ek_check(&PARAMS, bytes) {
                        Ok(Self(*bytes))
                    } else {
                        Err(Error::InvalidEncapsulationKey)
                    }
                }

                pub fn as_bytes(&self) -> &[u8; EK_LEN] {
                    &self.0
                }

                /// Algorithm 20 ML-KEM.Encaps(ek).
                pub fn encapsulate(
                    &self,
                    rng: &mut impl RandomSource,
                ) -> Result<(Ciphertext, SharedSecret), Error> {
                    let mut m = [0u8; 32]; // line 1: m ← 32 random bytes
                    rng.fill_bytes(&mut m)?; // lines 2–4: report RNG failure
                    let out = self.encapsulate_internal(&m);
                    wipe(&mut m);
                    Ok(out)
                }

                /// Algorithm 17 ML-KEM.Encaps_internal(ek, m): deterministic.
                /// **For testing only** (see [`generate_internal`]).
                pub fn encapsulate_internal(&self, m: &[u8; 32]) -> (Ciphertext, SharedSecret) {
                    let mut c = [0u8; CT_LEN];
                    let k = kem::encaps_internal(&PARAMS, &self.0, m, &mut c);
                    (Ciphertext(c), SharedSecret(k))
                }
            }

            impl TryFrom<&[u8]> for EncapsulationKey {
                type Error = Error;
                /// Type check (length) followed by the modulus check (§7.2).
                fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                    let arr: &[u8; EK_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
                    Self::from_bytes(arr)
                }
            }

            impl DecapsulationKey {
                /// Decapsulation key check (§7.3, items 2 and 3). The array
                /// type is the type check; this performs the hash check.
                pub fn from_bytes(bytes: &[u8; DK_LEN]) -> Result<Self, Error> {
                    if kem::dk_check(&PARAMS, bytes) {
                        Ok(Self(*bytes))
                    } else {
                        Err(Error::InvalidDecapsulationKey)
                    }
                }

                /// The secret key bytes. Handle with care.
                pub fn as_bytes(&self) -> &[u8; DK_LEN] {
                    &self.0
                }

                /// The encapsulation key stored inside dk (dk[384k : 768k + 32]).
                pub fn encapsulation_key(&self) -> EncapsulationKey {
                    let start = PARAMS.dk_pke_len();
                    EncapsulationKey(self.0[start..start + EK_LEN].try_into().unwrap())
                }

                /// Algorithm 21 ML-KEM.Decaps(dk, c) (which is just
                /// Decaps_internal, Alg 18). Never fails: a tampered
                /// ciphertext gives a pseudorandom key (implicit rejection).
                pub fn decapsulate(&self, c: &Ciphertext) -> SharedSecret {
                    SharedSecret(kem::decaps_internal(&PARAMS, &self.0, &c.0))
                }
            }

            impl TryFrom<&[u8]> for DecapsulationKey {
                type Error = Error;
                fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                    let arr: &[u8; DK_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
                    Self::from_bytes(arr)
                }
            }

            impl fmt::Debug for DecapsulationKey {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(concat!(stringify!($module), "::DecapsulationKey(..)"))
                }
            }

            impl Drop for DecapsulationKey {
                fn drop(&mut self) {
                    wipe(&mut self.0);
                }
            }

            impl Ciphertext {
                pub fn from_bytes(bytes: &[u8; CT_LEN]) -> Self {
                    Self(*bytes)
                }
                pub fn as_bytes(&self) -> &[u8; CT_LEN] {
                    &self.0
                }
            }

            impl TryFrom<&[u8]> for Ciphertext {
                type Error = Error;
                /// Ciphertext type check (§7.3 item 1): length only.
                fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                    let arr: &[u8; CT_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
                    Ok(Self(*arr))
                }
            }
        }
    };
}

parameter_set!(
    ml_kem_512,
    crate::params::ML_KEM_512,
    "ML-KEM-512 (k = 2): NIST security category 1."
);
parameter_set!(
    ml_kem_768,
    crate::params::ML_KEM_768,
    "ML-KEM-768 (k = 3): NIST security category 3. The usual default."
);
parameter_set!(
    ml_kem_1024,
    crate::params::ML_KEM_1024,
    "ML-KEM-1024 (k = 4): NIST security category 5."
);
