//! mlkem-wasm: the mlkem crate compiled to WebAssembly, with a plain C-style
//! ABI that JavaScript can call directly (`WebAssembly.instantiate`), so no
//! wasm-bindgen and no extra dependencies.
//!
//! **Not audited. Educational only.** Constant-time behaviour in WASM also
//! depends on the engine that compiles it to machine code; see LEARNING.md
//! phase 7.
//!
//! ABI. Every export takes pointers into the module's linear memory, where
//! the caller has placed the inputs and reserved room for the outputs. This
//! crate has no allocator, so a caller may use any memory at or above the
//! exported global `__heap_base` (growing memory if needed). Sizes are fixed
//! per parameter set (FIPS 203 Table 3) and given by the `*_len` exports.
//!
//! For each parameter set P in {512, 768, 1024}:
//!   mlkem_P_keygen(d, z, ek_out, dk_out)        KeyGen_internal (Alg 16)
//!   mlkem_P_encaps(ek, m, c_out, k_out) -> i32  §7.2 check, Encaps_internal (Alg 17)
//!   mlkem_P_decaps(dk, c, k_out) -> i32         §7.3 checks, Decaps (Alg 21)
//!   mlkem_P_ek_check(ek) -> i32, mlkem_P_dk_check(dk) -> i32
//!   mlkem_P_ek_len(), _dk_len(), _ct_len() -> i32
//! Return values: 0 = ok / key accepted, 1 = key rejected.
//!
//! Randomness: there is no RNG in a bare WASM module. KeyGen and Encaps take
//! their random seeds (d, z, m) from the caller, who must get them from a
//! cryptographic RNG (`crypto.getRandomValues` in JavaScript). That is
//! FIPS 203's `_internal` interface, which §6 says applications should not
//! be offered directly: a real binding would draw the seeds itself.

#![cfg_attr(target_arch = "wasm32", no_std)]

// A bare WASM module has no OS to report a panic to: trap. (The library
// only panics on broken internal invariants; lengths are fixed here.)
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

/// Turns a caller-supplied pointer into a fixed-size array reference.
///
/// # Safety
/// The caller (JavaScript) must pass a pointer to N valid bytes of linear
/// memory, not overlapping any output buffer of the same call. Everything
/// unsafe in this crate goes through these two functions.
#[allow(unsafe_code)]
unsafe fn arr<'a, const N: usize>(p: *const u8) -> &'a [u8; N] {
    // SAFETY: guaranteed by the caller, see above. u8 has alignment 1.
    unsafe { &*(p as *const [u8; N]) }
}

/// # Safety
/// As [`arr`], for an output buffer of N writable bytes.
#[allow(unsafe_code)]
unsafe fn arr_mut<'a, const N: usize>(p: *mut u8) -> &'a mut [u8; N] {
    // SAFETY: guaranteed by the caller, see `arr`.
    unsafe { &mut *(p as *mut [u8; N]) }
}

macro_rules! exports {
    ($m:ident, $keygen:ident, $encaps:ident, $decaps:ident, $ekc:ident, $dkc:ident,
     $ekl:ident, $dkl:ident, $ctl:ident) => {
        mod $m {
            use super::{arr, arr_mut};
            use mlkem::$m::{
                CT_LEN, Ciphertext, DK_LEN, DecapsulationKey, EK_LEN, EncapsulationKey,
                generate_internal,
            };

            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub extern "C" fn $ekl() -> i32 {
                EK_LEN as i32
            }
            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub extern "C" fn $dkl() -> i32 {
                DK_LEN as i32
            }
            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub extern "C" fn $ctl() -> i32 {
                CT_LEN as i32
            }

            /// # Safety
            /// See the crate ABI: d, z are 32 bytes; ek_out, dk_out are
            /// EK_LEN and DK_LEN writable bytes.
            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $keygen(
                d: *const u8,
                z: *const u8,
                ek_out: *mut u8,
                dk_out: *mut u8,
            ) {
                // SAFETY: the caller follows the ABI documented above.
                let (d, z) = unsafe { (arr::<32>(d), arr::<32>(z)) };
                let (ek, dk) = generate_internal(d, z);
                // SAFETY: as above.
                unsafe {
                    arr_mut::<EK_LEN>(ek_out).copy_from_slice(ek.as_bytes());
                    arr_mut::<DK_LEN>(dk_out).copy_from_slice(dk.as_bytes());
                }
            }

            /// # Safety
            /// ek is EK_LEN bytes, m is 32; c_out is CT_LEN, k_out 32 writable bytes.
            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $encaps(
                ek: *const u8,
                m: *const u8,
                c_out: *mut u8,
                k_out: *mut u8,
            ) -> i32 {
                // SAFETY: the caller follows the ABI documented above.
                let (ek, m) = unsafe { (arr::<EK_LEN>(ek), arr::<32>(m)) };
                let Ok(ek) = EncapsulationKey::from_bytes(ek) else {
                    return 1;
                };
                let (c, k) = ek.encapsulate_internal(m);
                // SAFETY: as above.
                unsafe {
                    arr_mut::<CT_LEN>(c_out).copy_from_slice(c.as_bytes());
                    arr_mut::<32>(k_out).copy_from_slice(k.as_bytes());
                }
                0
            }

            /// # Safety
            /// dk is DK_LEN bytes, c is CT_LEN; k_out is 32 writable bytes.
            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $decaps(dk: *const u8, c: *const u8, k_out: *mut u8) -> i32 {
                // SAFETY: the caller follows the ABI documented above.
                let (dk, c) = unsafe { (arr::<DK_LEN>(dk), arr::<CT_LEN>(c)) };
                let Ok(dk) = DecapsulationKey::from_bytes(dk) else {
                    return 1;
                };
                let k = dk.decapsulate(&Ciphertext::from_bytes(c));
                // SAFETY: as above.
                unsafe { arr_mut::<32>(k_out).copy_from_slice(k.as_bytes()) };
                0
            }

            /// # Safety
            /// ek is EK_LEN bytes.
            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $ekc(ek: *const u8) -> i32 {
                // SAFETY: the caller follows the ABI documented above.
                let ek = unsafe { arr::<EK_LEN>(ek) };
                i32::from(EncapsulationKey::from_bytes(ek).is_err())
            }

            /// # Safety
            /// dk is DK_LEN bytes.
            #[allow(unsafe_code)]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $dkc(dk: *const u8) -> i32 {
                // SAFETY: the caller follows the ABI documented above.
                let dk = unsafe { arr::<DK_LEN>(dk) };
                i32::from(DecapsulationKey::from_bytes(dk).is_err())
            }
        }
    };
}

exports!(
    ml_kem_512,
    mlkem_512_keygen,
    mlkem_512_encaps,
    mlkem_512_decaps,
    mlkem_512_ek_check,
    mlkem_512_dk_check,
    mlkem_512_ek_len,
    mlkem_512_dk_len,
    mlkem_512_ct_len
);
exports!(
    ml_kem_768,
    mlkem_768_keygen,
    mlkem_768_encaps,
    mlkem_768_decaps,
    mlkem_768_ek_check,
    mlkem_768_dk_check,
    mlkem_768_ek_len,
    mlkem_768_dk_len,
    mlkem_768_ct_len
);
exports!(
    ml_kem_1024,
    mlkem_1024_keygen,
    mlkem_1024_encaps,
    mlkem_1024_decaps,
    mlkem_1024_ek_check,
    mlkem_1024_dk_check,
    mlkem_1024_ek_len,
    mlkem_1024_dk_len,
    mlkem_1024_ct_len
);
