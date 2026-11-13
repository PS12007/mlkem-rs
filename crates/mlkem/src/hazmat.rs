//! Internal building blocks, exposed only with the `hazmat` feature.
//!
//! **Not an API for applications.** This exists for two tools:
//! - the assembly check (`scripts/asm-check.ps1`, phase 4), which needs each
//!   secret-handling function as its own symbol so its machine code can be
//!   read and scanned;
//! - the timing-leak harness (`crates/dudect`, phase 5), which times these
//!   functions directly.
//!
//! Every wrapper is `#[inline(never)]`, so the compiler emits it as a
//! separate function instead of folding it into its caller. Variable
//! parameters such as d and η are fixed per wrapper (`compress_d1`,
//! `cbd_eta2`, …), because that is how they appear in real use: the
//! compiler sees them as constants and specialises the code.
//!
//! Caveat: a function compiled on its own can differ slightly from the same
//! function inlined into a caller. That is why `decaps_768` (the whole
//! decapsulation, with everything inlined) is checked too.

use crate::params::{ML_KEM_768, N};
use crate::poly::Poly;
use crate::{ct, encode, field, hash, kem, ntt, sample};

// ---- field arithmetic (field.rs) ----
#[inline(never)]
pub fn barrett_reduce(a: i16) -> i16 {
    field::barrett_reduce(a)
}
#[inline(never)]
pub fn montgomery_reduce(a: i32) -> i16 {
    field::montgomery_reduce(a)
}
#[inline(never)]
pub fn fqmul(a: i16, b: i16) -> i16 {
    field::fqmul(a, b)
}
#[inline(never)]
pub fn to_canonical(a: i16) -> u16 {
    field::to_canonical(a)
}
#[inline(never)]
pub fn csubq(a: i16) -> i16 {
    field::csubq(a)
}

// ---- compression (encode.rs); d values used by ML-KEM ----
#[inline(never)]
pub fn compress_d1(x: u16) -> u16 {
    encode::compress(x, 1)
}
#[inline(never)]
pub fn compress_d4(x: u16) -> u16 {
    encode::compress(x, 4)
}
#[inline(never)]
pub fn compress_d5(x: u16) -> u16 {
    encode::compress(x, 5)
}
#[inline(never)]
pub fn compress_d10(x: u16) -> u16 {
    encode::compress(x, 10)
}
#[inline(never)]
pub fn compress_d11(x: u16) -> u16 {
    encode::compress(x, 11)
}
#[inline(never)]
pub fn decompress_d1(y: u16) -> u16 {
    encode::decompress(y, 1)
}

/// K-PKE.Decrypt line 7: ByteEncode_1(Compress_1(w)). The KyberSlash2 site.
#[inline(never)]
pub fn message_encode(w: &[i16; N]) -> [u8; 32] {
    let mut m = [0u8; 32];
    encode::poly_compress_encode(&Poly { coeffs: *w }, 1, &mut m);
    m
}

/// K-PKE.Encrypt line 22 for one polynomial of u at ML-KEM-1024's du = 11:
/// ByteEncode_11(Compress_11(u)). The KyberSlash1 site (larger dividends
/// than d = 1: up to 2^11·q).
#[inline(never)]
pub fn u_encode_d11(u: &[i16; N]) -> [u8; 352] {
    let mut out = [0u8; 352];
    encode::poly_compress_encode(&Poly { coeffs: *u }, 11, &mut out);
    out
}

/// ByteDecode_12 of one secret-key polynomial (reduces mod q branch-free).
#[inline(never)]
pub fn decode12(b: &[u8; 384]) -> [i16; N] {
    encode::poly_decode12(b).coeffs
}

// ---- sampling (sample.rs) ----
#[inline(never)]
pub fn cbd_eta2(b: &[u8; 128]) -> [i16; N] {
    sample::sample_poly_cbd(2, b).coeffs
}
#[inline(never)]
pub fn cbd_eta3(b: &[u8; 192]) -> [i16; N] {
    sample::sample_poly_cbd(3, b).coeffs
}

// ---- NTT (ntt.rs) ----
#[inline(never)]
pub fn ntt(f: &mut [i16; N]) {
    let mut p = Poly { coeffs: *f };
    ntt::ntt(&mut p);
    *f = p.coeffs;
}
#[inline(never)]
pub fn ntt_inverse(f: &mut [i16; N]) {
    let mut p = Poly { coeffs: *f };
    ntt::ntt_inverse(&mut p);
    *f = p.coeffs;
}
#[inline(never)]
pub fn multiply_ntts(f: &[i16; N], g: &[i16; N]) -> [i16; N] {
    ntt::multiply_ntts(&Poly { coeffs: *f }, &Poly { coeffs: *g }).coeffs
}

// ---- constant-time helpers (ct.rs) ----
#[inline(never)]
pub fn is_zero_mask(x: u32) -> u32 {
    ct::is_zero_mask_u32(x)
}
#[inline(never)]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    ct::ct_eq_bytes(a, b)
}
/// The FO re-encryption comparison at ML-KEM-768 ciphertext size.
#[inline(never)]
pub fn ct_eq_1088(a: &[u8; 1088], b: &[u8; 1088]) -> u8 {
    ct::ct_eq_bytes(a, b)
}
#[inline(never)]
pub fn ct_select_32(out: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32], mask: u8) {
    ct::ct_select_bytes(out, a, b, mask)
}

// ---- Keccak (hash/keccak.rs) ----
#[inline(never)]
pub fn keccak_f1600(state: &mut [u64; 25]) {
    hash::keccak::f1600(state)
}

// ---- whole algorithms ----
/// ML-KEM-768 Decaps_internal (Alg 18), everything inlined into one symbol.
#[inline(never)]
pub fn decaps_768(dk: &[u8; 2400], c: &[u8; 1088]) -> [u8; 32] {
    kem::decaps_internal(&ML_KEM_768, dk, c)
}
