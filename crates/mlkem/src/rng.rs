//! Randomness for ML-KEM.KeyGen (Alg 19) and ML-KEM.Encaps (Alg 20).
//!
//! FIPS 203 §3.3 requires an approved random bit generator. On Windows the
//! system's is `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`,
//! which uses the OS's CTR_DRBG (an SP 800-90A design).
//!
//! This module holds the **only `unsafe` code in the crate**: one call to
//! a Windows function through the C calling convention. Rust cannot check
//! what foreign code does, so every foreign call is `unsafe`. The crate root
//! says `#![deny(unsafe_code)]`, and only this module opts out.

use crate::Error;

/// Where KeyGen and Encaps get their random bytes. Implement this to plug in
/// any CSPRNG (tests use a deterministic one; the browser demo will use
/// `crypto.getRandomValues`).
pub trait RandomSource {
    /// Fill `dest` entirely with random bytes, or return
    /// [`Error::RandomnessFailure`]. FIPS 203 Alg 19 lines 3–4 and Alg 20
    /// lines 2–3 require failure to be reported, not ignored.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error>;
}

/// The operating system's random number generator (Windows only for now).
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use core::ffi::c_void;

    /// Use the system-preferred RNG; then the algorithm handle must be NULL.
    pub(super) const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        /// NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm,
        ///   PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
        /// Returns 0 (STATUS_SUCCESS) on success.
        pub(super) fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            len: u32,
            flags: u32,
        ) -> i32;
    }

    pub(super) fn fill(dest: &mut [u8]) -> bool {
        // ULONG is 32 bits, so very large buffers go in pieces.
        for chunk in dest.chunks_mut(u32::MAX as usize) {
            // SAFETY: the pointer and length describe a live, writable slice
            // (`chunk`) that nothing else borrows during the call; the
            // length fits in a u32 by construction; a NULL algorithm handle
            // is what the documentation requires with this flag.
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(windows)]
impl RandomSource for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        if windows::fill(dest) {
            Ok(())
        } else {
            Err(Error::RandomnessFailure)
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn os_rng_produces_varying_output() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        OsRng.fill_bytes(&mut a).unwrap();
        OsRng.fill_bytes(&mut b).unwrap();
        assert_ne!(a, b); // fails with probability 2^-512
        assert_ne!(a, [0u8; 64]);
    }
}
